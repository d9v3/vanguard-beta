//! Wi-Fi : la protection du réseau où l'on est connecté, et le faux point d'accès (« jumeau maléfique ») qui copie
//! son nom. Un jumeau se montre souvent sans mot de passe, pour attirer les appareils et voir passer leur trafic :
//! même nom que le vrai réseau, protection plus faible. Un répéteur protégé comme le réseau principal n'alerte pas.

use super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::affichable;
use crate::{tr, trf};

pub(crate) mod elements;
#[cfg(target_os = "linux")]
pub(crate) mod networkmanager;
pub(crate) mod nl80211;
pub(crate) mod profils;
pub(crate) mod wlanapi;

/// Nom d'un réseau que macOS 14 cache sans l'autorisation de localisation : sa protection se lit encore, mais il ne
/// se compare pas aux autres.
pub(super) const CACHE: &str = "<redacted>";

/// Un réseau Wi-Fi visible d'ici.
#[derive(Debug, PartialEq)]
pub(crate) struct Visible {
    pub ssid: String,
    /// Protection telle que le système la nomme (« WPA2 », « WPA2-Personal », « Open », « Ouvert »…).
    pub securite: String,
    /// Le réseau où l'on est connecté.
    pub actif: bool,
}

/// Force d'une protection : 0 ouverte, 1 faible (WEP, WPA, chiffrée sans mot de passe), 2 WPA2, 3 WPA3 ou entreprise
/// (802.1X). Ce qui ne nomme aucune protection connue (« -- », « Open », « Ouvert », « None ») est ouvert, dans
/// toutes les langues.
pub(crate) fn force(securite: &str) -> u8 {
    let s = securite.to_ascii_uppercase();
    if ["WPA3", "SAE", "802.1X", "ENTERPRISE", "ENTREPRISE"]
        .iter()
        .any(|m| s.contains(m))
    {
        3
    } else if s.contains("WPA2") {
        2
    } else {
        // 1 : WEP, WPA, ou chiffré sans mot de passe ; 0 : ouvert.
        u8::from(["WEP", "WPA", "OWE", "ENHANCED OPEN"].iter().any(|m| s.contains(m)))
    }
}

/// Protection du réseau où l'on est connecté. `admin` : commandes pour ouvrir l'administration de la box.
pub(crate) fn securite(ssid: &str, libelle: &str, admin: &[&str]) -> Constat {
    let routeur = tr!(
        "Ouvrir l'admin du routeur > Wi-Fi > Sécurité : choisir « WPA2/WPA3 » ou « WPA3 »",
        "Open the router admin > Wi-Fi > Security: choose “WPA2/WPA3” or “WPA3”"
    );
    // Ouvert ou sans mot de passe : souvent un réseau public, que la box ne permet pas de régler.
    let public = tr!(
        "Sur un réseau public (café, hôtel) : « vanguard wifi-public on » ferme l'ordinateur à ce réseau ; chez vous, ouvrir l'admin du routeur > Wi-Fi > Sécurité : choisir « WPA2/WPA3 » ou « WPA3 »",
        "On a public network (café, hotel): “vanguard public-wifi on” closes the computer to this network; at home, open the router admin > Wi-Fi > Security: choose “WPA2/WPA3” or “WPA3”"
    );
    match force(libelle) {
        3 => ok("Wi-Fi", trf!("« {ssid} » en {libelle}.", "“{ssid}” uses {libelle}.")),
        2 => alerte(
            "Wi-Fi",
            Niveau::Info,
            trf!(
                "« {ssid} » en {libelle}. WPA3 serait mieux si le routeur le permet.",
                "“{ssid}” uses {libelle}. WPA3 would be better if the router allows it."
            ),
        )
        .manuel(routeur, admin),
        // Chiffré, mais sans mot de passe : n'importe qui peut s'y connecter, ou l'imiter.
        1 if libelle.to_ascii_uppercase().contains("OWE") || libelle.to_ascii_uppercase().contains("ENHANCED") => {
            alerte(
                "Wi-Fi",
                Niveau::Moyen,
                trf!(
                    "« {ssid} » est chiffré mais sans mot de passe ({libelle}) : n'importe qui peut s'y connecter.",
                    "“{ssid}” is encrypted but has no password ({libelle}): anyone can join it."
                ),
            )
            .manuel(public, admin)
        }
        1 => alerte(
            "Wi-Fi",
            Niveau::Eleve,
            trf!(
                "« {ssid} » utilise {libelle}, cassable en minutes.",
                "“{ssid}” uses {libelle}, crackable in minutes."
            ),
        )
        .manuel(routeur, admin),
        _ => alerte(
            "Wi-Fi",
            Niveau::Eleve,
            trf!(
                "« {ssid} » est un réseau ouvert : le trafic non chiffré est visible.",
                "“{ssid}” is an open network: unencrypted traffic is visible."
            ),
        )
        .manuel(public, admin),
    }
}

/// Réseaux ouverts enregistrés qui se reconnectent tout seuls : n'importe qui peut créer un faux réseau du même nom
/// (« Wi-Fi gratuit », celui d'un hôtel) et l'ordinateur s'y joint sans rien demander. `noms` à montrer, une commande
/// par réseau pour couper la reconnexion.
pub(crate) fn ouverts_automatiques(noms: &[String], commandes: &[String]) -> Option<Constat> {
    if noms.is_empty() {
        return None;
    }
    let montres: Vec<String> = noms.iter().map(|n| format!("« {} »", affichable(n))).collect();
    let liste = crate::ui::resume(&montres, 3, ", ");
    let commandes: Vec<&str> = commandes.iter().map(String::as_str).collect();
    Some(
        alerte(
            "Wi-Fi",
            Niveau::Moyen,
            trf!(
                "Réseaux ouverts qui se reconnectent tout seuls : {liste}. N'importe qui peut créer un faux réseau du même nom, et l'ordinateur s'y joint sans rien demander.",
                "Open networks that reconnect by themselves: {liste}. Anyone can set up a fake network with the same name, and the computer joins it without asking."
            ),
        )
        .corriger(
            tr!(
                "Ne plus s'y reconnecter tout seul (ils restent enregistrés, à choisir soi-même)",
                "Stop reconnecting to them automatically (they stay saved, to pick by hand)"
            ),
            &commandes,
        ),
    )
}

/// Les réseaux ouverts qui se reconnectent seuls, d'après les profils enregistrés lus nativement : le même jugement
/// pour le bilan et l'audit du réseau, qui le faisaient chacun à sa façon. Une commande qui reprend une valeur sans
/// forme sûre (un nom choisi par n'importe qui) est montrée, jamais lancée d'office.
pub(crate) fn ouverts_des_profils(profils: &[profils::ProfilEnregistre]) -> Option<Constat> {
    let ouverts: Vec<&profils::ProfilEnregistre> = profils.iter().filter(|p| p.ouvert && p.automatique).collect();
    let noms: Vec<String> = ouverts.iter().map(|p| p.nom.clone()).collect();
    let commandes: Vec<String> = ouverts.iter().map(|p| p.commande.clone()).collect();
    let mut c = ouverts_automatiques(&noms, &commandes)?;
    if let Some(k) = &mut c.correctif
        && !ouverts.iter().all(|p| p.commande_sure)
    {
        k.automatique = false;
    }
    Some(c)
}

/// Les réseaux visibles d'une lecture native (nl80211, wlanapi), pour le bilan : leur protection lue dans les
/// balises, nommée comme les systèmes la nomment (`Protection::libelle`), sauf pour le réseau connecté quand le
/// système dit la protection négociée. Le réseau connecté est la borne que le système dit active, ou celle de la
/// connexion. Vide : la lecture n'a vu aucune borne (Windows 11 sans
/// l'autorisation de localisation), et l'appelant demande alors au système.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn visibles_de(lecture: &Lecture) -> Vec<Visible> {
    // Sans BSSID (le balayage ne montre plus la borne associée), le nom seul ne dit pas laquelle des bornes de ce nom
    // est la vraie. Si leurs protections diffèrent, l'une peut être un jumeau ouvert : la marquer « connectée »
    // dirait « ton Wi-Fi est ouvert », ou cacherait le jumeau. Rien n'est alors marqué, et l'appelant demande au
    // système (nmcli), qui sait laquelle est active. Même protection partout (un réseau maillé) : peu importe.
    let ambigu = lecture.connexion.as_ref().is_some_and(|c| {
        c.bssid.is_empty() && {
            let mut protections = lecture
                .balises
                .iter()
                .filter(|b| b.borne.ssid == c.ssid)
                .map(|b| b.protection.libelle());
            protections.next().is_some_and(|p| protections.any(|x| x != p))
        }
    });
    lecture
        .balises
        .iter()
        .filter(|b| !b.borne.ssid.is_empty())
        .map(|b| {
            let connectee = lecture.connexion.as_ref().is_some_and(|c| {
                c.ssid == b.borne.ssid
                    && if c.bssid.is_empty() {
                        !ambigu
                    } else {
                        c.bssid.eq_ignore_ascii_case(&b.borne.bssid)
                    }
            });
            let actif = b.borne.actif || connectee;
            let securite = match &lecture.connexion {
                Some(c) if actif && c.ssid == b.borne.ssid && !c.securite.is_empty() => c.securite.clone(),
                _ => b.protection.libelle().to_string(),
            };
            Visible {
                ssid: b.borne.ssid.clone(),
                securite,
                actif,
            }
        })
        .collect()
}

/// Un réseau qui porte le nom de celui où l'on est connecté, ouvert ou à la protection cassable, alors que le vrai
/// est en WPA2 ou mieux : la signature d'un jumeau maléfique.
pub(super) fn jumeau(visibles: &[Visible]) -> Option<Constat> {
    let actif = visibles.iter().find(|v| v.actif)?;
    if force(&actif.securite) < 2 || actif.ssid == CACHE {
        return None;
    }
    let faible = visibles
        .iter()
        .find(|v| !v.actif && v.ssid == actif.ssid && force(&v.securite) <= 1)?;
    let ssid = &actif.ssid;
    let protection = if force(&faible.securite) == 0 {
        tr!("sans mot de passe", "without a password").to_string()
    } else {
        trf!("en {}", "using {}", faible.securite)
    };
    Some(
        alerte(
            "Wi-Fi",
            Niveau::Moyen,
            trf!(
                "Un autre réseau « {ssid} », {protection}, est visible d'ici : un faux point d'accès (« jumeau maléfique ») copie souvent le nom d'un vrai réseau pour attirer les appareils et voir passer leur trafic.",
                "Another “{ssid}” network, {protection}, is visible from here: a fake access point (“evil twin”) often copies a real network's name to lure devices and see their traffic."
            ),
        )
        .manuel(
            tr!(
                "Ne vous y connectez pas, et refusez si un appareil propose de le rejoindre. Si c'est un de vos appareils (vieux répéteur, réseau invité), donnez-lui un autre nom ou un mot de passe",
                "Do not connect to it, and decline if a device offers to join it. If it is one of your devices (old repeater, guest network), give it another name or a password"
            ),
            &[],
        ),
    )
}

/// Un réseau de `system_profiler SPAirPortDataType` : son nom, s'il est le réseau connecté, ses lignes de détail.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct BlocMac<'a> {
    nom: String,
    actif: bool,
    details: Vec<&'a str>,
}

/// Sous « Current Network Information: » (le réseau connecté) et « Other Local Wi-Fi Networks: », un nom par réseau
/// puis ses détails (« Security: WPA2 Personal », « Channel: 36 (5GHz, 80MHz) »…), plus en retrait.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn blocs_system_profiler(sortie: &str) -> Vec<BlocMac<'_>> {
    let mut blocs: Vec<BlocMac> = Vec::new();
    let mut section: Option<(usize, bool)> = None;
    let mut retrait_nom: Option<usize> = None;
    for ligne in sortie.lines() {
        let l = ligne.trim();
        if l.is_empty() {
            continue;
        }
        let retrait = ligne.len() - ligne.trim_start().len();
        if section.is_some_and(|(r, _)| retrait <= r) {
            section = None;
        }
        if l == "Current Network Information:" || l == "Other Local Wi-Fi Networks:" {
            section = Some((retrait, l.starts_with("Current")));
            retrait_nom = None;
            continue;
        }
        let Some((_, actif)) = section else {
            continue;
        };
        if retrait == *retrait_nom.get_or_insert(retrait) {
            blocs.push(BlocMac {
                nom: affichable(l.trim_end_matches(':')),
                actif,
                details: Vec::new(),
            });
        } else if let Some(b) = blocs.last_mut() {
            b.details.push(l);
        }
    }
    blocs.retain(|b| !b.nom.is_empty());
    blocs
}

/// `system_profiler SPAirPortDataType` : la protection de chaque réseau (« Security: WPA2 Personal »).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn lire_system_profiler(sortie: &str) -> Vec<Visible> {
    blocs_system_profiler(sortie)
        .into_iter()
        .map(|b| Visible {
            securite: b
                .details
                .iter()
                .find_map(|d| d.strip_prefix("Security:"))
                .map(|s| affichable(s.trim()))
                .unwrap_or_default(),
            ssid: b.nom,
            actif: b.actif,
        })
        .collect()
}

/// Bande de fréquences d'un réseau Wi-Fi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Bande {
    G24,
    G5,
    G6,
}

impl Bande {
    /// D'après la fréquence, en MHz.
    pub(crate) fn de_frequence(mhz: u32) -> Option<Bande> {
        match mhz {
            2400..=2500 => Some(Bande::G24),
            4900..=5899 => Some(Bande::G5),
            5925..=7125 => Some(Bande::G6),
            _ => None,
        }
    }

    /// D'après le canal seul, quand le système ne dit pas la bande (Windows 10) : 1 à 14 en 2,4 GHz, au-delà en
    /// 5 GHz. Ces systèmes-là ne connaissent pas le 6 GHz, qui réutilise les petits numéros.
    pub(crate) fn de_canal(canal: u16) -> Option<Bande> {
        match canal {
            1..=14 => Some(Bande::G24),
            32..=177 => Some(Bande::G5),
            _ => None,
        }
    }

    /// D'après un texte du système : « 2.4 GHz », « 2,4 GHz », « 5 GHz », « 2GHz » (macOS)…
    pub(crate) fn de_texte(t: &str) -> Option<Bande> {
        let t: String = t
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        if t.starts_with("2.4") || t.starts_with("2,4") || t.starts_with("2ghz") {
            Some(Bande::G24)
        } else if t.starts_with('5') {
            Some(Bande::G5)
        } else if t.starts_with('6') {
            Some(Bande::G6)
        } else {
            None
        }
    }

    pub(crate) fn libelle(self) -> &'static str {
        match self {
            Bande::G24 => tr!("2,4 GHz", "2.4 GHz"),
            Bande::G5 => "5 GHz",
            Bande::G6 => "6 GHz",
        }
    }
}

/// Canal d'une fréquence en MHz : 2412 → 1 (2484 → 14), 5180 → 36, 5955 → 1 (6 GHz).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn canal_de_frequence(mhz: u32) -> Option<u16> {
    let canal = match Bande::de_frequence(mhz)? {
        Bande::G24 if mhz == 2484 => 14,
        Bande::G24 => mhz.checked_sub(2407)? / 5,
        Bande::G5 => mhz.checked_sub(5000)? / 5,
        Bande::G6 => mhz.checked_sub(5950)? / 5,
    };
    u16::try_from(canal).ok()
}

/// Puissance reçue en dBm vers le pourcentage que montrent les systèmes : −100 dBm → 0 %, −50 dBm et mieux → 100 %.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn pourcentage(dbm: i32) -> u8 {
    u8::try_from(dbm.saturating_add(100).saturating_mul(2).clamp(0, 100)).unwrap_or(0)
}

/// Un réseau Wi-Fi entendu d'ici sur un canal : une borne. Un même réseau peut en avoir plusieurs (2,4 et 5 GHz,
/// répéteurs).
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Borne {
    /// Nom du réseau ; vide s'il est caché.
    pub ssid: String,
    /// Adresse de l'émetteur (BSSID), « aa:bb:cc:dd:ee:ff » ; vide si l'outil ne la donne pas.
    pub bssid: String,
    pub bande: Bande,
    pub canal: u16,
    /// Force du signal reçu, de 0 à 100 %.
    pub signal: Option<u8>,
    /// La borne de la connexion actuelle.
    pub actif: bool,
}

/// Une borne et ce que ses balises annoncent : chiffrements acceptés, WPS. Lue nativement (nl80211, wlanapi).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Balise {
    pub borne: Borne,
    pub protection: elements::Protection,
    pub wps: Option<elements::Wps>,
}

/// Le réseau où l'on est connecté, d'après le système.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Connexion {
    pub ssid: String,
    /// L'émetteur de la connexion ; vide si le système ne le dit pas.
    pub bssid: String,
    /// Qualité du signal de la connexion, de 0 à 100 %, quand le système la donne.
    pub qualite: Option<u8>,
    pub canal: Option<u16>,
    pub bande: Option<Bande>,
    /// La protection négociée, nommée comme `Protection::libelle` ; vide si le système ne la dit pas (nl80211). Une
    /// borne WPA2/WPA3 annonce les deux, mais une carte sans WPA3 s'y connecte en WPA2 : c'est le lien qui compte.
    pub securite: String,
}

/// Au-delà, en secondes, la liste des voisins ne dit plus qui émet maintenant : un jumeau allumé depuis, ou un voisin
/// qui a changé de canal, n'y serait pas.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const VOISINS_RECENTS: u64 = 600;

/// Ce que vaut la liste des bornes voisines d'une lecture : ce qui manque d'une liste vieille ou vide ne se compte
/// pas comme absent (pas de jumeau, canal libre), il est dit non vérifié. Seul Linux dit l'âge de sa liste.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Voisins {
    /// Le système ne dit pas l'âge de sa liste (Windows, qui la tient lui-même à jour) : prise telle quelle.
    #[default]
    NonJuges,
    Recents,
    Anciens {
        minutes: u64,
    },
    /// Le noyau n'a plus aucune borne voisine : il les oublie 30 s après une recherche.
    Oublies,
    /// NetworkManager n'a encore fait aucune recherche depuis son démarrage.
    JamaisCherches,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Voisins {
    /// D'après l'âge de la dernière recherche, en secondes.
    pub(crate) fn selon_age(secondes: u64) -> Voisins {
        if secondes <= VOISINS_RECENTS {
            Voisins::Recents
        } else {
            Voisins::Anciens { minutes: secondes / 60 }
        }
    }
}

/// Ce qu'une lecture native a vu : les bornes du dernier balayage, et la connexion en cours.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Lecture {
    pub balises: Vec<Balise>,
    pub connexion: Option<Connexion>,
    /// Une réserve du système sur la liste (Windows : l'autorisation de localisation).
    pub note: Option<&'static str>,
    pub voisins: Voisins,
}

// macOS lit encore son Wi-Fi par system_profiler, sans lecture native : ni bilan ni réserve.
#[cfg_attr(target_os = "macos", allow(dead_code))]
impl Lecture {
    /// Pourquoi la liste des voisins ne suffit pas à conclure (jumeau absent, canal libre) ; `None` : elle suffit.
    pub(crate) fn reserve_voisins(&self) -> Option<String> {
        if let Some(n) = self.note {
            return Some(n.to_string());
        }
        match self.voisins {
            Voisins::NonJuges | Voisins::Recents => None,
            Voisins::Anciens { minutes } => Some(trf!(
                "la liste des réseaux voisins date de {minutes} min",
                "the list of nearby networks is {minutes} min old"
            )),
            Voisins::Oublies => Some(
                tr!(
                    "le système ne garde les réseaux voisins que 30 s après une recherche, et aucune n'est récente",
                    "the system keeps nearby networks only 30 s after a search, and none is recent"
                )
                .to_string(),
            ),
            Voisins::JamaisCherches => Some(
                tr!(
                    "NetworkManager n'a encore cherché aucun réseau",
                    "NetworkManager has not searched for networks yet"
                )
                .to_string(),
            ),
        }
    }
}

/// Le Wi-Fi de Linux : NetworkManager d'abord, qui garde les bornes de ses dernières recherches ; sans lui (iwd,
/// systemd-networkd), sans carte qu'il gère, sans connexion qu'il voie ou si le bus refuse, le dernier balayage
/// gardé par le noyau.
#[cfg(target_os = "linux")]
pub(crate) fn lecture_linux() -> Result<Lecture, &'static str> {
    match networkmanager::lire() {
        Ok(Some(l)) if l.connexion.is_some() => Ok(l),
        // NetworkManager ne voit aucune connexion : sa carte peut être « non gérée » (wpa_supplicant ou iwd lancés à
        // part), et il la publie quand même, vide. Le noyau dit alors si elle est associée.
        Ok(Some(l)) => match nl80211::lire() {
            Ok(noyau) if noyau.connexion.is_some() => Ok(noyau),
            _ => Ok(l),
        },
        Ok(None) | Err(_) => nl80211::lire(),
    }
}

/// La protection du réseau connecté : celle que le système dit négociée (Windows), sinon celle de la borne qu'il dit
/// active ou du BSSID de la connexion, enfin celle du réseau connecté selon `visibles_de` (une seule protection pour
/// ce nom). `None` : la borne n'est pas dans la liste, ou plusieurs du même nom diffèrent (l'une peut être un jumeau).
/// `visibles` : `visibles_de(l)`.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn protection_connectee(l: &Lecture, visibles: &[Visible]) -> Option<String> {
    let c = l.connexion.as_ref()?;
    if !c.securite.is_empty() {
        return Some(c.securite.clone());
    }
    let active = l
        .balises
        .iter()
        .find(|b| b.borne.actif || (!c.bssid.is_empty() && c.bssid.eq_ignore_ascii_case(&b.borne.bssid)));
    if let Some(b) = active {
        return Some(b.protection.libelle().to_string());
    }
    visibles
        .iter()
        .find(|v| v.actif && v.ssid == c.ssid)
        .map(|v| v.securite.clone())
}

/// WIN-WIF-001 et LNX-WIF-001 : la protection du réseau connecté, puis un jumeau parmi les voisins. Sans connexion,
/// rien à juger, sauf si le système a refusé de dire laquelle (la note). Une liste de voisins trop vieille ne prouve
/// pas l'absence de jumeau : c'est dit non vérifié. La borne de la connexion n'est jamais devinée parmi plusieurs du
/// même nom aux protections différentes (l'une peut être le jumeau) : la protection est alors dite non vérifiée.
/// `admin` : commandes pour ouvrir l'administration de la box.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(super) fn bilan(l: &Lecture, admin: &[&str]) -> Vec<Constat> {
    let Some(c) = &l.connexion else {
        return l
            .note
            .map(|n| {
                vec![impossible(
                    "Wi-Fi",
                    &trf!("réseau connecté : {n}", "connected network: {n}"),
                )]
            })
            .unwrap_or_default();
    };
    let nom = if c.ssid.is_empty() {
        tr!("réseau caché", "hidden network").to_string()
    } else {
        c.ssid.clone()
    };
    let mut visibles = visibles_de(l);
    let libelle = protection_connectee(l, &visibles);
    let Some(libelle) = libelle else {
        let homonymes = !c.ssid.is_empty() && l.balises.iter().any(|b| b.borne.ssid == c.ssid);
        return vec![impossible(
            "Wi-Fi",
            &if homonymes {
                trf!(
                    "protection du Wi-Fi « {nom} » : plusieurs bornes de ce nom n'ont pas la même protection, et le système ne dit pas laquelle est la vôtre (l'une peut être un faux réseau)",
                    "protection of Wi-Fi “{nom}”: several access points with this name differ in protection, and the system does not say which one is yours (one may be a fake network)"
                )
            } else {
                trf!(
                    "protection du Wi-Fi « {nom} » : le dernier balayage ne montre pas sa borne",
                    "protection of Wi-Fi “{nom}”: the last scan does not show its access point"
                )
            },
        )];
    };
    let mut constats = vec![securite(&nom, &libelle, admin)];
    // Un réseau caché n'a pas de nom à copier : aucun jumeau à chercher.
    if c.ssid.is_empty() {
        return constats;
    }
    if let Some(r) = l.reserve_voisins() {
        constats.push(impossible(
            "Wi-Fi",
            &trf!(
                "faux réseau du même nom (jumeau) : non cherché, {r}",
                "same-name fake network (evil twin): not looked for, {r}"
            ),
        ));
        return constats;
    }
    // La borne de la connexion absente de la liste (Windows sans la localisation, borne pas encore balayée) : le
    // réseau connecté, avec sa protection, sert de référence au jumeau.
    if !visibles.iter().any(|v| v.actif) {
        visibles.insert(
            0,
            Visible {
                ssid: c.ssid.clone(),
                securite: libelle,
                actif: true,
            },
        );
    }
    constats.extend(jumeau(&visibles));
    constats
}

/// `system_profiler SPAirPortDataType` : « Channel: 36 (5GHz, 80MHz) » et, pour le réseau connecté (et parfois les
/// autres), « Signal / Noise: -50 dBm / -90 dBm ».
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn bornes_system_profiler(sortie: &str) -> Vec<Borne> {
    blocs_system_profiler(sortie)
        .into_iter()
        .filter_map(|b| {
            let (canal, reste) = b
                .details
                .iter()
                .find_map(|d| d.strip_prefix("Channel:"))?
                .trim()
                .split_once(' ')?;
            let canal: u16 = canal.parse().ok()?;
            let bande = Bande::de_texte(reste.trim_start_matches('('))?;
            let signal = b
                .details
                .iter()
                .find_map(|d| d.strip_prefix("Signal / Noise:"))
                .and_then(|s| s.split_whitespace().next()?.parse::<i32>().ok())
                .map(pourcentage);
            Some(Borne {
                ssid: if b.nom == CACHE { String::new() } else { b.nom },
                bssid: String::new(),
                bande,
                canal,
                signal,
                actif: b.actif,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une lecture native donne au bilan les mêmes réseaux que nmcli : la protection lue dans les balises, et le
    /// réseau connecté reconnu par la borne active ou par la connexion.
    #[test]
    fn visibles_d_une_lecture_native() {
        let balise = |ssid: &str, bssid: &str, actif, protection| Balise {
            borne: Borne {
                ssid: ssid.into(),
                bssid: bssid.into(),
                bande: Bande::G5,
                canal: 36,
                signal: Some(70),
                actif,
            },
            protection,
            wps: None,
        };
        let wpa2 = elements::Protection {
            chiffree: true,
            rsn: true,
            aes: true,
            psk: true,
            ..elements::Protection::default()
        };
        let mut l = Lecture {
            balises: vec![
                balise("Salon", "00:11:22:aa:bb:01", false, wpa2),
                balise("Salon", "00:11:22:aa:bb:02", false, elements::Protection::default()),
                balise("", "00:11:22:aa:bb:03", false, wpa2),
            ],
            connexion: Some(Connexion {
                ssid: "Salon".into(),
                bssid: "00:11:22:AA:BB:01".into(),
                ..Connexion::default()
            }),
            ..Lecture::default()
        };
        let v = visibles_de(&l);
        assert_eq!(v.len(), 2, "le réseau caché est écarté");
        assert!(v[0].actif && !v[1].actif);
        assert_eq!(force(&v[0].securite), 2);
        assert_eq!(force(&v[1].securite), 0);
        // Le jumeau ouvert du réseau connecté se voit comme avec nmcli.
        assert!(jumeau(&v).is_some());
        // La protection négociée l'emporte sur celle de la balise : une borne WPA2/WPA3 où la carte s'est connectée
        // en WPA2.
        let mut mixte = wpa2;
        mixte.sae = true;
        let negociee = |securite: &str| Lecture {
            balises: vec![balise("Salon", "00:11:22:aa:bb:01", false, mixte)],
            connexion: Some(Connexion {
                ssid: "Salon".into(),
                bssid: "00:11:22:aa:bb:01".into(),
                securite: securite.into(),
                ..Connexion::default()
            }),
            ..Lecture::default()
        };
        assert_eq!(force(&visibles_de(&negociee("")).swap_remove(0).securite), 3);
        let v = visibles_de(&negociee("WPA2"));
        assert!(v[0].actif);
        assert_eq!(force(&v[0].securite), 2);
        assert_eq!(securite("Salon", &v[0].securite, &[]).probleme, Some(Niveau::Info));
        // Sans BSSID, deux bornes du même nom aux protections différentes : on ne sait pas laquelle est la vraie,
        // aucune n'est connectée (l'appelant demande au système), et le jumeau ouvert ne passe pas pour elle.
        l.connexion = Some(Connexion {
            ssid: "Salon".into(),
            bssid: String::new(),
            ..Connexion::default()
        });
        assert!(visibles_de(&l).iter().all(|v| !v.actif));
        // Une seule borne de ce nom, ou deux à la même protection (réseau maillé) : celle de la connexion.
        let ouverte = l.balises.remove(1);
        let v = visibles_de(&l);
        assert!(v[0].actif && v[0].ssid == "Salon");
        l.balises.push(balise("Salon", "00:11:22:aa:bb:04", false, wpa2));
        assert!(visibles_de(&l).iter().filter(|v| v.ssid == "Salon").all(|v| v.actif));
        l.balises.push(ouverte);
        assert!(visibles_de(&l).iter().all(|v| !v.actif));
        // Sans connexion ni borne active : rien de connecté, l'appelant demande au système.
        l.connexion = None;
        assert!(visibles_de(&l).iter().all(|v| !v.actif));
    }

    #[test]
    fn ouverts_des_profils_lus() {
        let profil = |nom: &str, ouvert, automatique, sure| profils::ProfilEnregistre {
            nom: nom.into(),
            automatique,
            ouvert,
            commande: format!("couper {nom}"),
            commande_sure: sure,
        };
        assert!(
            ouverts_des_profils(&[profil("Salon", false, true, true), profil("Café", true, false, true)]).is_none()
        );
        let c = ouverts_des_profils(&[profil("Café", true, true, true)]).unwrap();
        assert!(c.correctif.as_ref().is_some_and(|k| k.automatique));
        // Une commande sans forme sûre : montrée, pas lancée d'office.
        let c = ouverts_des_profils(&[profil("Café", true, true, true), profil("Gare", true, true, false)]).unwrap();
        assert!(c.correctif.as_ref().is_some_and(|k| !k.automatique));
    }

    #[test]
    fn ouverts_qui_se_reconnectent() {
        assert!(ouverts_automatiques(&[], &[]).is_none());
        let noms = ["Hôtel".to_string(), "Gare\x1b[2K".to_string()];
        let c = ouverts_automatiques(&noms, &["a".into(), "b".into()]).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("« Hôtel »") && !c.message.contains('\x1b'));
        let k = c.correctif.unwrap();
        assert!(k.automatique && k.commandes == ["a", "b"]);
    }

    fn visible(ssid: &str, securite: &str, actif: bool) -> Visible {
        Visible {
            ssid: ssid.into(),
            securite: securite.into(),
            actif,
        }
    }

    #[test]
    fn force_des_protections() {
        for (protection, attendue) in [
            ("--", 0),
            ("Open", 0),
            ("Ouvert", 0),
            ("None", 0),
            ("WEP", 1),
            ("WPA1", 1),
            ("OWE", 1),
            ("WPA1 WPA2", 2),
            ("WPA2-Personal", 2),
            ("WPA2 - Personnel", 2),
            ("WPA2/WPA3 Personal", 3),
            ("WPA3", 3),
            ("WPA2 802.1X", 3),
            ("WPA2-Enterprise", 3),
            ("WPA2 - Entreprise", 3),
        ] {
            assert_eq!(force(protection), attendue, "{protection}");
        }
    }

    #[test]
    fn jumeau_ouvert_repere() {
        let reseaux = [
            visible("Salon", "WPA2", true),
            visible("Salon", "WPA2 WPA3", false),
            visible("Voisin", "--", false),
        ];
        // Un répéteur protégé, un voisin ouvert : rien.
        assert!(jumeau(&reseaux).is_none());
        let reseaux = [visible("Salon", "WPA2", true), visible("Salon", "--", false)];
        let c = jumeau(&reseaux).expect("jumeau ouvert");
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("sans mot de passe"));
        // Le réseau connecté est lui-même ouvert : c'est sa propre alerte, pas celle d'un jumeau.
        assert!(jumeau(&[visible("Salon", "--", true), visible("Salon", "--", false)]).is_none());
    }

    #[test]
    fn reseaux_de_system_profiler() {
        let sortie = "Wi-Fi:

      Software Versions:
          CoreWLAN: 16.0 (1657)
      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4387)
          Status: Connected
          Current Network Information:
            Salon:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 80MHz)
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -50 dBm / -90 dBm
          Other Local Wi-Fi Networks:
            Salon:
              PHY Mode: 802.11n
              Network Type: Infrastructure
              Security: None
            <redacted>:
              Security: WPA2 Personal
        awdl0:
          MAC Address: 12:34:56:78:9a:bc
";
        let reseaux = lire_system_profiler(sortie);
        assert_eq!(
            reseaux,
            [
                visible("Salon", "WPA2 Personal", true),
                visible("Salon", "None", false),
                visible(CACHE, "WPA2 Personal", false),
            ]
        );
        assert!(jumeau(&reseaux).is_some());
        // Noms cachés par macOS : rien ne se compare.
        assert!(jumeau(&[visible(CACHE, "WPA2 Personal", true), visible(CACHE, "None", false)]).is_none());
    }

    fn borne(ssid: &str, bande: Bande, canal: u16, signal: Option<u8>, actif: bool) -> Borne {
        Borne {
            ssid: ssid.into(),
            bssid: String::new(),
            bande,
            canal,
            signal,
            actif,
        }
    }

    #[test]
    fn bandes_canaux_et_signal() {
        for (mhz, canal) in [(2412, 1), (2437, 6), (2484, 14), (5180, 36), (5745, 149), (5955, 1)] {
            assert_eq!(canal_de_frequence(mhz), Some(canal), "{mhz}");
        }
        assert_eq!(Bande::de_frequence(5955), Some(Bande::G6));
        assert_eq!(canal_de_frequence(900), None);
        assert_eq!(Bande::de_canal(11), Some(Bande::G24));
        assert_eq!(Bande::de_canal(36), Some(Bande::G5));
        assert_eq!(Bande::de_canal(0), None);
        for (texte, bande) in [
            ("2.4 GHz", Bande::G24),
            ("2,4 GHz", Bande::G24),
            ("2GHz, 20MHz)", Bande::G24),
            ("5 GHz", Bande::G5),
            ("5GHz, 80MHz)", Bande::G5),
            ("6 GHz", Bande::G6),
        ] {
            assert_eq!(Bande::de_texte(texte), Some(bande), "{texte}");
        }
        assert_eq!(pourcentage(-45), 100);
        assert_eq!(pourcentage(-75), 50);
        assert_eq!(pourcentage(-110), 0);
        assert_eq!(pourcentage(i32::MIN), 0);
    }

    /// Un nom de réseau, choisi par n'importe qui à portée de Wi-Fi : séquence OSC 52 (presse-papier), effacement de la
    /// ligne, retour chariot, retournement bidi. Lu par chaque outil, il arrive inoffensif, « � » à la place de chaque
    /// caractère piégé ; la protection aussi.
    const PIEGE: &str = "Salon\x1b]52;c;ZWNobyBQSVJBVEU=\x07\x1b[2K\rFaux\u{202e}";
    const VU: &str = "Salon�]52;c;ZWNobyBQSVJBVEU=��[2K�Faux�";

    #[test]
    fn noms_de_reseaux_pieges_rendus_inoffensifs() {
        let profiler = format!(
            "Wi-Fi:\n      Interfaces:\n        en0:\n          Current Network Information:\n            \
             {PIEGE}:\n              Channel: 36 (5GHz, 80MHz)\n              Security: WPA2\x1b[8m\n\
             \x20         Other Local Wi-Fi Networks:\n            {PIEGE}:\n              Security: None\n"
        );
        let v = lire_system_profiler(&profiler);
        assert_eq!(v, [visible(VU, "WPA2�[8m", true), visible(VU, "None", false)]);
        assert!(jumeau(&v).is_some_and(|c| !crate::ui::contient_un_piege(&c.message)));
        assert_eq!(bornes_system_profiler(&profiler)[0].ssid, VU);
        // Les messages de l'audit Wi-Fi ne portent plus rien qui pilote le terminal.
        let c = securite(&v[0].ssid, &v[0].securite, &[]);
        assert!(!crate::ui::contient_un_piege(&c.message), "{}", c.message);
    }

    fn balise(ssid: &str, mac: u8, protection: elements::Protection, actif: bool) -> Balise {
        Balise {
            borne: Borne {
                bssid: format!("02:00:00:aa:bb:{mac:02x}"),
                ..borne(ssid, Bande::G5, 36, Some(70), actif)
            },
            protection,
            wps: None,
        }
    }

    fn wpa2() -> elements::Protection {
        elements::Protection {
            chiffree: true,
            rsn: true,
            aes: true,
            psk: true,
            ..elements::Protection::default()
        }
    }

    fn connecte(ssid: &str) -> Connexion {
        Connexion {
            ssid: ssid.into(),
            bssid: "02:00:00:aa:bb:01".into(),
            ..Connexion::default()
        }
    }

    /// Le bilan du Wi-Fi de la machine : la protection, puis le jumeau ; tout ce qui ne se conclut pas d'une liste
    /// douteuse est dit non vérifié, jamais compté comme sain.
    #[test]
    fn bilan_du_wifi() {
        let ouvert = elements::Protection::default();
        let mut l = Lecture {
            balises: vec![balise("Salon", 1, wpa2(), true), balise("Salon", 2, ouvert, false)],
            connexion: Some(connecte("Salon")),
            voisins: Voisins::Recents,
            ..Lecture::default()
        };
        let c = bilan(&l, &[]);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].probleme, Some(Niveau::Info));
        assert!(c[0].verifie && c[0].message.contains("WPA2"));
        assert_eq!(c[1].probleme, Some(Niveau::Moyen));
        assert!(c[1].message.contains("sans mot de passe") || c[1].message.contains("without a password"));
        // Une liste de voisins trop vieille, oubliée ou jamais faite : la protection se juge, le jumeau est non
        // cherché.
        for voisins in [
            Voisins::Anciens { minutes: 25 },
            Voisins::Oublies,
            Voisins::JamaisCherches,
        ] {
            l.voisins = voisins;
            let c = bilan(&l, &[]);
            assert_eq!(c.len(), 2, "{voisins:?}");
            assert!(c[0].verifie);
            assert!(!c[1].verifie && (c[1].message.contains("jumeau") || c[1].message.contains("evil twin")));
        }
        // La protection de l'association (Windows) l'emporte, même sans aucune borne lue (localisation refusée) ;
        // le jumeau est alors non cherché, avec la raison de Windows.
        let l = Lecture {
            connexion: Some(Connexion {
                securite: "WPA3".into(),
                ..connecte("Salon")
            }),
            note: Some("localisation"),
            ..Lecture::default()
        };
        let c = bilan(&l, &[]);
        assert_eq!(c.len(), 2);
        assert!(c[0].verifie && c[0].probleme.is_none());
        assert!(!c[1].verifie && c[1].message.contains("localisation"));
        // Pas de connexion, mais Windows refuse de dire laquelle : non vérifié ; sans raison, rien à dire.
        let l = Lecture {
            note: Some("localisation"),
            ..Lecture::default()
        };
        let c = bilan(&l, &[]);
        assert_eq!(c.len(), 1);
        assert!(!c[0].verifie && c[0].message.contains("localisation"));
        assert!(bilan(&Lecture::default(), &[]).is_empty());
        // Connecté, mais la borne n'est pas dans le balayage : la protection n'est pas devinée.
        let l = Lecture {
            balises: vec![balise("Voisin", 3, wpa2(), false)],
            connexion: Some(connecte("Salon")),
            voisins: Voisins::Recents,
            ..Lecture::default()
        };
        let c = bilan(&l, &[]);
        assert!(!c[0].verifie && c[0].message.contains("Salon"));
        assert_eq!(c.len(), 1);
        // Un réseau caché : sa protection, la plus forte borne de la liste à défaut d'active, et aucun jumeau.
        let l = Lecture {
            balises: vec![balise("", 1, wpa2(), true), balise("", 2, ouvert, false)],
            connexion: Some(connecte("")),
            voisins: Voisins::Oublies,
            ..Lecture::default()
        };
        let c = bilan(&l, &[]);
        assert_eq!(c.len(), 1);
        assert!(c[0].message.contains("réseau caché") || c[0].message.contains("hidden network"));
        // Sans borne active ni BSSID, une seule borne de ce nom : la sienne.
        let mut l = Lecture {
            balises: vec![balise("Salon", 5, wpa2(), false)],
            connexion: Some(Connexion {
                bssid: String::new(),
                ..connecte("Salon")
            }),
            voisins: Voisins::Recents,
            ..Lecture::default()
        };
        let c = bilan(&l, &[]);
        assert!(c[0].verifie && c[0].message.contains("WPA2"));
        // Deux bornes de ce nom, l'une ouverte : laquelle est la vôtre n'est pas devinée (ni « ouvert », ni le jumeau
        // pris pour le vrai réseau).
        let mut faible = balise("Salon", 4, ouvert, false);
        faible.borne.signal = Some(10);
        l.balises.insert(0, faible);
        let c = bilan(&l, &[]);
        assert_eq!(c.len(), 1);
        assert!(!c[0].verifie && c[0].probleme == Some(Niveau::Info), "{}", c[0].message);
        // La borne du BSSID de la connexion, même sans drapeau « active » : elle seule donne la protection, et
        // l'autre est le jumeau.
        l.balises[1].borne.bssid = "02:00:00:AA:BB:01".into();
        l.connexion = Some(connecte("Salon"));
        let c = bilan(&l, &[]);
        assert_eq!(c.len(), 2);
        assert!(c[0].verifie && c[0].message.contains("WPA2"));
        assert_eq!(c[1].probleme, Some(Niveau::Moyen));
    }

    #[test]
    fn reserve_des_voisins() {
        let mut l = Lecture::default();
        assert_eq!(l.reserve_voisins(), None);
        l.voisins = Voisins::Recents;
        assert_eq!(l.reserve_voisins(), None);
        l.voisins = Voisins::selon_age(VOISINS_RECENTS + 60);
        assert_eq!(l.voisins, Voisins::Anciens { minutes: 11 });
        assert!(l.reserve_voisins().is_some_and(|r| r.contains("11 min")));
        assert_eq!(Voisins::selon_age(VOISINS_RECENTS), Voisins::Recents);
        // La note du système passe avant.
        l.note = Some("localisation");
        assert_eq!(l.reserve_voisins().as_deref(), Some("localisation"));
    }

    #[test]
    fn bornes_de_system_profiler() {
        let sortie = "Wi-Fi:
      Interfaces:
        en0:
          Current Network Information:
            Salon:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 80MHz)
              Security: WPA2 Personal
              Signal / Noise: -50 dBm / -90 dBm
          Other Local Wi-Fi Networks:
            Voisin:
              Channel: 6 (2GHz, 20MHz)
              Security: WPA2 Personal
            <redacted>:
              Channel: 149 (5GHz, 80MHz)
              Signal / Noise: -70 dBm / -92 dBm
";
        assert_eq!(
            bornes_system_profiler(sortie),
            [
                borne("Salon", Bande::G5, 36, Some(100), true),
                borne("Voisin", Bande::G24, 6, None, false),
                borne("", Bande::G5, 149, Some(60), false),
            ]
        );
        // La lecture des protections, elle, est la même qu'avant.
        assert_eq!(lire_system_profiler(sortie).len(), 3);
    }
}

/// Propriétés des lectures, sur des sorties tirées au hasard : aucune ne plante, quoi qu'écrive l'outil ou l'appareil
/// d'en face ; un nom lu ne porte jamais de quoi piloter le terminal ; une sortie bien formée redonne ses valeurs.
#[cfg(test)]
mod proprietes {
    use super::*;
    use proptest::prelude::*;

    /// Une sortie d'outil quelconque : des lignes de n'importe quels caractères, deux-points, tabulations,
    /// séquences d'échappement et écritures bidirectionnelles compris.
    fn sortie() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                any::<String>(),
                "[ -~\\t\u{1b}\u{202e}\u{200b}é:%()\\[\\]]{0,60}",
                "(SSID|BSSID|Channel|Canal|Band|Signal|Authentication|freq|signal|BSS|Security|Channel) ?[0-9]* ?: ?[ -~]{0,30}",
            ],
            0..12,
        )
        .prop_map(|l| l.join("\n"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lectures_sans_plantage_ni_piege(t in sortie()) {
            let visibles = lire_system_profiler(&t);
            let bornes = bornes_system_profiler(&t);
            for v in &visibles {
                prop_assert!(!crate::ui::contient_un_piege(&v.ssid) && !crate::ui::contient_un_piege(&v.securite));
            }
            for b in &bornes {
                prop_assert!(!crate::ui::contient_un_piege(&b.ssid));
                prop_assert!(b.signal.is_none_or(|s| s <= 100));
            }
            let _ = jumeau(&visibles);
        }

        #[test]
        fn pourcentage_borne_et_croissant(a in any::<i32>(), b in any::<i32>()) {
            let (pa, pb) = (pourcentage(a), pourcentage(b));
            prop_assert!(pa <= 100 && pb <= 100);
            if a <= b {
                prop_assert!(pa <= pb);
            }
        }

        #[test]
        fn canaux_des_frequences(mhz in any::<u32>()) {
            // Un canal ne vient que d'une fréquence d'une bande connue ; toute autre fréquence n'en donne aucun, sans
            // plantage.
            if canal_de_frequence(mhz).is_some() {
                prop_assert!(Bande::de_frequence(mhz).is_some());
            }
        }
    }
}
