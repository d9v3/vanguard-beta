//! Domaine Wi-Fi de l'audit du réseau : cinq règles communes aux trois systèmes, sur ce que les balises des bornes
//! annoncent et ce que l'ordinateur garde en mémoire. COM-WIF-001 : le chiffrement du réseau connecté (TKIP, WPA de
//! 2003, WEP, ouvert) ; COM-WIF-002 : WPS allumé sur la box ; COM-WIF-003 : plusieurs émetteurs pour le même nom
//! (un jumeau possible, ou un répéteur) ; COM-WIF-004 : les réseaux ouverts qui se reconnectent seuls ;
//! COM-WIF-005 : les appareils inconnus du dernier scan. Tout est lu nativement (nl80211 sous Linux, wlanapi sous
//! Windows, les fichiers du système) ; ce qui ne se lit pas d'ici est dit « non vérifié », jamais compté sain. Les
//! constats sont purs (`constats`), l'acquisition à part (`entree`). Vanguard observe : il ne balaie pas, n'essaie
//! aucun mot de passe et ne touche pas à la box, qui se règle dans son administration.
//!
//! Références : NSA, Best Practices for Securing Your Home Network (CSI PP-23-0270, 2023) ; CERT/CC VU#723755
//! (WPS, 2011) ; ANSSI, Recommandations de sécurité relatives aux réseaux Wi-Fi ; IEEE 802.11-2012 (TKIP déprécié) ;
//! CCCS ITSAP.80.019.

use crate::machine::wifi::elements::Wps;
use crate::machine::wifi::profils::ProfilEnregistre;
use crate::machine::wifi::{self, Balise, Connexion, Lecture};
use crate::machine::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::affichable;
use crate::{tr, trf};

const CATEGORIE: &str = "Wi-Fi";
/// Les règles du domaine, dans l'ordre des constats.
const REGLES: [&str; 5] = [
    "COM-WIF-001",
    "COM-WIF-002",
    "COM-WIF-003",
    "COM-WIF-004",
    "COM-WIF-005",
];
/// Au-delà de ce nombre d'appareils inconnus d'un coup, quelqu'un a peut-être le mot de passe du Wi-Fi.
const INCONNUS_INQUIETANTS: usize = 3;
/// Noms de réseau laissés par défaut par les fabricants et les fournisseurs : deux voisins peuvent porter le même,
/// et plusieurs émetteurs pour ce nom ne disent rien.
const NOMS_PAR_DEFAUT: [&str; 44] = [
    "linksys",
    "netgear",
    "dlink",
    "d-link",
    "default",
    "asus",
    "tp-link",
    "tp_link",
    "belkin",
    "wireless",
    "wifi",
    "wlan",
    "home",
    "maison",
    "router",
    "routeur",
    "xfinitywifi",
    "attwifi",
    "bell",
    "videotron",
    "vidéotron",
    "telus",
    "rogers",
    "shaw",
    "cogeco",
    "freebox",
    "livebox",
    "bbox",
    "sfr",
    "orange",
    "2wire",
    "zyxel",
    "huawei",
    "tenda",
    "hitron",
    "arris",
    "sagemcom",
    "technicolor",
    "free wifi",
    "guest",
    "invité",
    "invite",
    "public",
    "open",
];

/// Ce que le domaine Wi-Fi examine. `entree()` remplit ce qui se lit nativement d'ici ; ce que le scan du réseau
/// apporte (appareils nouveaux, adresse de la box) vient de l'audit qui l'appelle (`avec_scan`).
pub struct Entree {
    /// Les bornes entendues d'ici, avec leurs éléments d'information ; `Err` : pourquoi elles ne se lisent pas.
    pub bornes: Result<Vec<Balise>, String>,
    /// Le réseau connecté ; `None` : pas connecté en Wi-Fi.
    pub connexion: Option<Connexion>,
    /// Une réserve du système sur la liste (Windows : l'autorisation de localisation).
    pub note: Option<&'static str>,
    /// Les réseaux enregistrés sur cet ordinateur ; `Err` : pourquoi ils ne se lisent pas.
    pub profils: Result<Vec<ProfilEnregistre>, String>,
    /// L'adresse MAC de la box (passerelle), pour reconnaître sa marque parmi les émetteurs.
    pub mac_box: Option<String>,
    /// Les appareils que le dernier scan a vus pour la première fois (leurs titres) ; `None` : pas de scan.
    pub nouveaux: Option<Vec<String>>,
}

impl Entree {
    /// Ce que le scan du réseau apporte : les titres des appareils nouveaux, et l'adresse MAC de la box.
    #[must_use]
    pub fn avec_scan(mut self, nouveaux: Vec<String>, mac_box: Option<String>) -> Entree {
        self.nouveaux = Some(nouveaux);
        if mac_box.is_some() {
            self.mac_box = mac_box;
        }
        self
    }
}

/// Lit ce qui se lit d'ici : les bornes et la connexion par le système, les réseaux enregistrés, la box sous Linux.
pub fn entree() -> Entree {
    let (bornes, connexion, note) = match lecture_native() {
        Ok(l) => (Ok(l.balises), l.connexion, l.note),
        Err(raison) => (Err(raison.to_string()), None, None),
    };
    Entree {
        bornes,
        connexion,
        note,
        profils: profils_natifs().map_err(str::to_string),
        mac_box: mac_box_native(),
        nouveaux: None,
    }
}

#[cfg(target_os = "linux")]
fn lecture_native() -> Result<Lecture, &'static str> {
    wifi::nl80211::lire()
}

#[cfg(windows)]
fn lecture_native() -> Result<Lecture, &'static str> {
    wifi::wlanapi::lire()
}

/// macOS ne donne ses balises qu'à CoreWLAN (Objective-C), hors de portée d'ici : non vérifié, dit tel quel. Le
/// bilan de la machine garde sa lecture de la protection par system_profiler.
#[cfg(target_os = "macos")]
fn lecture_native() -> Result<Lecture, &'static str> {
    Err(tr!(
        "les bornes Wi-Fi ne se lisent pas d'ici sur macOS (CoreWLAN) ; le bilan garde la protection du réseau",
        "Wi-Fi access points cannot be read from here on macOS (CoreWLAN); the check-up keeps the network's protection"
    ))
}

#[cfg(target_os = "linux")]
fn profils_natifs() -> Result<Vec<ProfilEnregistre>, &'static str> {
    wifi::profils::lire_linux()
}

#[cfg(windows)]
fn profils_natifs() -> Result<Vec<ProfilEnregistre>, &'static str> {
    wifi::wlanapi::profils()
}

#[cfg(target_os = "macos")]
fn profils_natifs() -> Result<Vec<ProfilEnregistre>, &'static str> {
    wifi::profils::lire_macos()
}

/// L'adresse MAC de la box : Linux la lit dans /proc (route par défaut, table ARP) ; ailleurs, elle vient du scan.
fn mac_box_native() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let ip = crate::reseau::scan::passerelle()?;
        crate::reseau::scan::table_arp().get(&ip).cloned()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Les cinq constats du domaine, chacun avec sa règle.
pub fn constats(e: &Entree) -> Vec<Constat> {
    let mut liste = vec![chiffrement(e), wps(e), emetteurs(e), ouverts(e), inconnus(e)];
    for (c, regle) in liste.iter_mut().zip(REGLES) {
        c.regle = regle;
    }
    liste
}

/// Le réseau connecté et ses bornes (même nom, ou l'émetteur de la connexion). `Err` : ce qui empêche de regarder,
/// déjà dit comme non vérifié pour `sujet`.
fn reseau<'a>(e: &'a Entree, sujet: &str) -> Result<(&'a Connexion, Vec<&'a Balise>), Box<Constat>> {
    let bornes = match &e.bornes {
        Ok(b) => b,
        Err(raison) => return Err(Box::new(impossible(CATEGORIE, &format!("{sujet} : {raison}")))),
    };
    let Some(c) = &e.connexion else {
        return Err(Box::new(impossible(
            CATEGORIE,
            &trf!(
                "{sujet} : pas connecté en Wi-Fi, le réseau local ne se voit pas d'ici",
                "{sujet}: not connected over Wi-Fi, the home network cannot be seen from here"
            ),
        )));
    };
    let siennes: Vec<&Balise> = bornes
        .iter()
        .filter(|b| (!c.ssid.is_empty() && b.borne.ssid == c.ssid) || (!c.bssid.is_empty() && b.borne.bssid == c.bssid))
        .collect();
    if siennes.is_empty() {
        let note = e.note.map(|n| format!(" ; {n}")).unwrap_or_default();
        return Err(Box::new(impossible(
            CATEGORIE,
            &trf!(
                "{sujet} : le dernier balayage du système ne montre pas le réseau connecté{note}",
                "{sujet}: the system's last scan does not show the connected network{note}"
            ),
        )));
    }
    Ok((c, siennes))
}

/// Le nom du réseau connecté, prêt à montrer : « Salon », ou « réseau caché ».
fn nom_du_reseau(c: &Connexion) -> String {
    if c.ssid.is_empty() {
        tr!("réseau caché", "hidden network").to_string()
    } else {
        affichable(&c.ssid)
    }
}

/// La borne de la connexion, sinon la première du réseau.
fn principale<'a>(bornes: &[&'a Balise]) -> &'a Balise {
    bornes.iter().find(|b| b.borne.actif).unwrap_or(&bornes[0])
}

/// COM-WIF-001 : le chiffrement du réseau connecté. TKIP encore accepté à côté d'AES : Moyen ; WPA de 2003, WEP
/// ou ouvert : les verdicts de `wifi::securite`, les mêmes que le bilan de la machine.
fn chiffrement(e: &Entree) -> Constat {
    let sujet = tr!("chiffrement du Wi-Fi", "Wi-Fi encryption");
    let (c, bornes) = match reseau(e, sujet) {
        Ok(r) => r,
        Err(k) => return *k,
    };
    let ssid = nom_du_reseau(c);
    let p = principale(&bornes).protection;
    let tkip = bornes.iter().any(|b| b.protection.tkip);
    if p.rsn && tkip {
        let seulement = !bornes.iter().any(|b| b.protection.aes);
        let message = if seulement {
            trf!(
                "Le Wi-Fi « {ssid} » n'accepte que le vieux chiffrement TKIP : il freine le réseau et affaiblit WPA2.",
                "Wi-Fi “{ssid}” only accepts the old TKIP encryption: it slows the network down and weakens WPA2."
            )
        } else {
            trf!(
                "Le Wi-Fi « {ssid} » accepte encore le vieux chiffrement TKIP : il freine le réseau et affaiblit WPA2.",
                "Wi-Fi “{ssid}” still accepts the old TKIP encryption: it slows the network down and weakens WPA2."
            )
        };
        return alerte(CATEGORIE, Niveau::Moyen, message).manuel(
            tr!(
                "Admin du routeur > Wi-Fi > Sécurité : WPA2-AES (CCMP) ou WPA3, sans TKIP ; un très vieil appareil qui ne connaît que TKIP devra être remplacé ou mis sur le réseau invité",
                "Router admin > Wi-Fi > Security: WPA2-AES (CCMP) or WPA3, without TKIP; a very old device that only knows TKIP will have to be replaced or moved to the guest network"
            ),
            &[],
        );
    }
    wifi::securite(&ssid, p.libelle(), &[])
}

/// COM-WIF-002 : WPS allumé sur la box, d'après l'élément WPS de ses balises. Moyen si la méthode PIN est offerte
/// (ou que la borne ne dit pas ses méthodes), Info si le bouton seul ou la méthode PIN verrouillée.
fn wps(e: &Entree) -> Constat {
    let sujet = tr!("WPS du routeur", "router WPS");
    let (c, bornes) = match reseau(e, sujet) {
        Ok(r) => r,
        Err(k) => return *k,
    };
    let nom = nom_du_reseau(c);
    let pin_possible = |w: Wps| !w.verrouille && w.pin() != Some(false);
    let Some((pire, w)) = bornes
        .iter()
        .filter_map(|b| b.wps.map(|w| (b, w)))
        .max_by_key(|(_, w)| pin_possible(*w))
    else {
        return ok(
            CATEGORIE,
            trf!(
                "Le routeur n'annonce pas WPS pour « {nom} » : rien à couper.",
                "The router does not advertise WPS for “{nom}”: nothing to turn off."
            ),
        );
    };
    let detail = if w.verrouille {
        tr!(
            "méthode PIN verrouillée après trop d'essais",
            "PIN method locked after too many attempts"
        )
    } else {
        match w.pin() {
            Some(true) => tr!("code PIN offert", "PIN code offered"),
            Some(false) if w.bouton() => tr!("bouton seulement", "button only"),
            Some(false) => tr!("ni PIN ni bouton annoncés", "neither PIN nor button advertised"),
            None => tr!("méthodes non dites", "methods not stated"),
        }
    };
    let qui = if bornes.len() > 1 {
        trf!(
            " (émetteur {}, {detail})",
            " (transmitter {}, {detail})",
            pire.borne.bssid
        )
    } else {
        format!(" ({detail})")
    };
    let niveau = if pin_possible(w) { Niveau::Moyen } else { Niveau::Info };
    alerte(
        CATEGORIE,
        niveau,
        trf!(
            "Votre routeur garde WPS allumé (le bouton ou le code PIN pour connecter un appareil){qui} : une faiblesse connue de ce mécanisme permet d'entrer sans le mot de passe du Wi-Fi.",
            "Your router keeps WPS on (the button or PIN code to join a device){qui}: a known weakness of this mechanism lets someone in without the Wi-Fi password."
        ),
    )
    .manuel(
        tr!(
            "Désactivez WPS dans le routeur (Wi-Fi > WPS) : les appareils déjà connectés le restent. Si l'émetteur nommé est un répéteur à vous, c'est lui qu'il faut régler",
            "Turn WPS off in the router (Wi-Fi > WPS): devices already connected stay connected. If the named transmitter is a repeater of yours, that is the one to set"
        ),
        &[],
    )
}

/// La marque d'un émetteur : son préfixe (les trois premiers octets, bit « local » effacé : les box dérivent souvent
/// l'adresse de leur seconde bande en posant ce bit) et le fabricant qu'il désigne.
struct Marque {
    prefixe: String,
    fabricant: Option<String>,
    /// Le bit « administré localement » était posé.
    locale: bool,
}

fn marque(mac: &str) -> Marque {
    let mut octets: Vec<String> = mac.split(':').map(str::to_string).collect();
    let locale = octets
        .first()
        .and_then(|o| u8::from_str_radix(o, 16).ok())
        .is_some_and(|o| o & 0x02 != 0);
    if let Some(premier) = octets.first_mut()
        && let Ok(o) = u8::from_str_radix(premier, 16)
    {
        *premier = format!("{:02x}", o & !0x02);
    }
    let normalisee = octets.join(":");
    Marque {
        prefixe: normalisee.chars().take(8).collect(),
        fabricant: crate::reseau::scan::fabricant(&normalisee),
        locale,
    }
}

/// Même préfixe, ou même fabricant (un routeur a parfois plusieurs blocs d'adresses).
fn meme_marque(a: &Marque, b: &Marque) -> bool {
    a.prefixe == b.prefixe || (a.fabricant.is_some() && a.fabricant == b.fabricant)
}

fn fabricant_affiche(m: &Marque) -> String {
    match (&m.fabricant, m.locale) {
        (Some(f), _) => f.clone(),
        (None, true) => tr!(
            "adresse locale : répéteur ou maillage ?",
            "local address: repeater or mesh?"
        )
        .to_string(),
        (None, false) => tr!("fabricant inconnu", "unknown maker").to_string(),
    }
}

fn nom_par_defaut(ssid: &str) -> bool {
    NOMS_PAR_DEFAUT.contains(&ssid.trim().to_lowercase().as_str())
}

/// COM-WIF-003 : plusieurs émetteurs pour le nom du réseau connecté. Normal quand tous sont de la marque de la box
/// (deux bandes, un répéteur) ; à vérifier (Moyen, jamais plus) quand l'un n'en est pas, ou protège moins bien que
/// la box : un répéteur d'une autre marque, un système maillé, ou un faux point d'accès. Info pour un nom par
/// défaut, que des voisins portent aussi.
fn emetteurs(e: &Entree) -> Constat {
    let sujet = tr!("émetteurs du réseau", "network transmitters");
    let (c, bornes) = match reseau(e, sujet) {
        Ok(r) => r,
        Err(k) => return *k,
    };
    let nom = nom_du_reseau(c);
    // Une adresse d'émetteur (BSSID) est celle d'une radio : la même entendue sur deux canaux, ou annonçant deux
    // protections, est la forme classique du jumeau malveillant, qui recopie l'adresse de la box. Compter les
    // adresses seules la faisait passer pour « un seul émetteur : votre routeur ».
    let adresse = |b: &Balise| b.borne.bssid.to_ascii_lowercase();
    let jumeau = bornes.iter().find_map(|a| {
        let autre = bornes.iter().find(|b| {
            !a.borne.bssid.is_empty()
                && adresse(a) == adresse(b)
                && (a.borne.canal != b.borne.canal || a.protection != b.protection)
        })?;
        Some((*a, *autre))
    });
    if let Some((a, b)) = jumeau {
        // Le suspect : celui qui n'est pas la connexion, ou le moins protégé.
        let (vrai, copie) = if b.borne.actif || (!a.borne.actif && a.protection.force() < b.protection.force()) {
            (b, a)
        } else {
            (a, b)
        };
        let bssid = affichable(&copie.borne.bssid);
        let (canal_vrai, canal_copie) = (vrai.borne.canal, copie.borne.canal);
        return alerte(
            CATEGORIE,
            Niveau::Moyen,
            trf!(
                "La même adresse d'émetteur ({bssid}) diffuse « {nom} » deux fois : canal {canal_vrai} ({}) et canal {canal_copie} ({}). Une radio n'a qu'une adresse : possible faux point d'accès qui copie l'adresse de votre box, sauf si elle vient de changer de canal.",
                "The same transmitter address ({bssid}) broadcasts “{nom}” twice: channel {canal_vrai} ({}) and channel {canal_copie} ({}). A radio has a single address: possibly a fake access point copying your router's address, unless it just changed channel.",
                vrai.protection.libelle(),
                copie.protection.libelle()
            ),
        )
        .manuel(
            tr!(
                "Relancez l'analyse dans quelques minutes : si les deux restent, changez le mot de passe du Wi-Fi, ne vous connectez pas à ce nom quand le Wi-Fi propose un réseau ouvert, et prévenez vos proches",
                "Run the scan again in a few minutes: if both remain, change the Wi-Fi password, do not connect to this name when Wi-Fi offers an open network, and tell your family"
            ),
            &[],
        );
    }
    let mut adresses: Vec<(String, u16)> = bornes
        .iter()
        .filter(|b| !b.borne.bssid.is_empty())
        .map(|b| (adresse(b), b.borne.canal))
        .collect();
    adresses.sort_unstable();
    adresses.dedup();
    let n = adresses.len();
    if n <= 1 {
        return ok(
            CATEGORIE,
            trf!(
                "Un seul émetteur diffuse « {nom} » : votre routeur.",
                "A single transmitter broadcasts “{nom}”: your router."
            ),
        );
    }
    if nom_par_defaut(&c.ssid) {
        return alerte(
            CATEGORIE,
            Niveau::Info,
            trf!(
                "{n} émetteurs diffusent « {nom} », un nom par défaut que des voisins portent sans doute aussi : vos appareils peuvent confondre leur routeur et le vôtre.",
                "{n} transmitters broadcast “{nom}”, a default name neighbors probably use too: your devices may mix up their router and yours."
            ),
        )
        .manuel(
            tr!(
                "Donnez à votre réseau un nom bien à vous dans l'admin du routeur (Wi-Fi > nom du réseau), puis reconnectez vos appareils",
                "Give your network a name of your own in the router admin (Wi-Fi > network name), then reconnect your devices"
            ),
            &[],
        );
    }
    // La référence : la box si son adresse est connue, sinon l'émetteur de la connexion.
    let (reference, de_la_box) = match e.mac_box.as_deref().filter(|m| !m.is_empty()) {
        Some(m) => (m, true),
        None if !c.bssid.is_empty() => (c.bssid.as_str(), false),
        None => (adresses[0].0.as_str(), false),
    };
    let marque_reference = marque(reference);
    let force_connectee = principale(&bornes).protection.force();
    let etranger = |b: &Balise| !b.borne.bssid.is_empty() && !meme_marque(&marque(&b.borne.bssid), &marque_reference);
    let plus_faible = |b: &Balise| b.protection.force() < force_connectee;
    let Some(suspect) = bornes.iter().copied().find(|b| etranger(b) || plus_faible(b)) else {
        return ok(
            CATEGORIE,
            trf!(
                "{n} émetteurs diffusent « {nom} », tous de la marque de votre routeur (2,4 et 5 GHz, répéteur) : normal.",
                "{n} transmitters broadcast “{nom}”, all of your router's brand (2.4 and 5 GHz, repeater): normal."
            ),
        );
    };
    let bssid = &suspect.borne.bssid;
    let fabricant = fabricant_affiche(&marque(bssid));
    let message = if etranger(suspect) {
        let faible = if plus_faible(suspect) {
            trf!(
                " et il protège moins bien ({})",
                " and it is less protected ({})",
                suspect.protection.libelle()
            )
        } else {
            String::new()
        };
        if de_la_box {
            trf!(
                "{n} émetteurs diffusent « {nom} » ; l'un d'eux ({bssid}, {fabricant}) n'est pas de la marque de votre routeur{faible} : un répéteur à vous, ou un faux point d'accès qui copie votre réseau.",
                "{n} transmitters broadcast “{nom}”; one of them ({bssid}, {fabricant}) is not your router's brand{faible}: a repeater of yours, or a fake access point copying your network."
            )
        } else {
            trf!(
                "{n} émetteurs diffusent « {nom} » ; l'un d'eux ({bssid}, {fabricant}) n'est pas de la marque de celui où vous êtes connecté{faible} : un répéteur à vous, ou un faux point d'accès qui copie votre réseau.",
                "{n} transmitters broadcast “{nom}”; one of them ({bssid}, {fabricant}) is not the brand of the one you are connected to{faible}: a repeater of yours, or a fake access point copying your network."
            )
        }
    } else {
        trf!(
            "{n} émetteurs diffusent « {nom} » ; l'un d'eux ({bssid}, {fabricant}) protège moins bien ({}) que celui où vous êtes connecté : un vieux répéteur à vous, ou un faux point d'accès qui copie votre réseau.",
            "{n} transmitters broadcast “{nom}”; one of them ({bssid}, {fabricant}) is less protected ({}) than the one you are connected to: an old repeater of yours, or a fake access point copying your network.",
            suspect.protection.libelle()
        )
    };
    alerte(CATEGORIE, Niveau::Moyen, message).manuel(
        tr!(
            "Si ce n'est pas un répéteur ou un système maillé à vous, changez le mot de passe du Wi-Fi et prévenez vos proches de ne pas se connecter à ce nom hors de chez vous",
            "If it is not a repeater or a mesh system of yours, change the Wi-Fi password and tell your family not to connect to this name away from home"
        ),
        &[],
    )
}

fn accord_enregistres(n: usize) -> String {
    match n {
        1 => tr!("1 réseau enregistré", "1 saved network").to_string(),
        n => trf!("{n} réseaux enregistrés", "{n} saved networks"),
    }
}

/// COM-WIF-004 : les réseaux ouverts enregistrés qui se reconnectent seuls, avec les textes du bilan. La correction
/// est lancée quand chaque commande a une forme sûre (NetworkManager, par UUID), montrée sinon.
fn ouverts(e: &Entree) -> Constat {
    let sujet = tr!("réseaux enregistrés", "saved networks");
    let profils = match &e.profils {
        Ok(p) => p,
        Err(raison) => return impossible(CATEGORIE, &format!("{sujet} : {raison}")),
    };
    match wifi::ouverts_des_profils(profils) {
        Some(c) => c,
        None => ok(
            CATEGORIE,
            trf!(
                "Aucun réseau ouvert enregistré ne se reconnecte tout seul ({}).",
                "No saved open network reconnects by itself ({}).",
                accord_enregistres(profils.len())
            ),
        ),
    }
}

/// COM-WIF-005 : les appareils que le dernier scan a vus pour la première fois. Info jusqu'à trois (un nouvel
/// appareil à soi), Moyen au-delà : quelqu'un a peut-être le mot de passe du Wi-Fi. Aucune sonde : le scan a déjà
/// tout vu, et les noter comme connus se fait dans le carnet.
fn inconnus(e: &Entree) -> Constat {
    let sujet = tr!("appareils inconnus", "unknown devices");
    let Some(nouveaux) = &e.nouveaux else {
        return impossible(
            CATEGORIE,
            &trf!(
                "{sujet} : pas de scan du réseau dans cette passe",
                "{sujet}: no network scan in this pass"
            ),
        );
    };
    let n = nouveaux.len();
    if n == 0 {
        return ok(
            CATEGORIE,
            tr!(
                "Aucun appareil inconnu sur le réseau : tous ceux vus au scan étaient déjà dans le carnet.",
                "No unknown device on the network: all those seen by the scan were already in the device book."
            ),
        );
    }
    let montres: Vec<String> = nouveaux.iter().map(|t| format!("« {} »", affichable(t))).collect();
    let liste = crate::ui::resume(&montres, 3, ", ");
    if n > INCONNUS_INQUIETANTS {
        return alerte(
            CATEGORIE,
            Niveau::Moyen,
            trf!(
                "{n} appareils inconnus sont apparus d'un coup sur le réseau : {liste}. Quelqu'un a peut-être le mot de passe du Wi-Fi.",
                "{n} unknown devices appeared at once on the network: {liste}. Someone may have the Wi-Fi password."
            ),
        )
        .manuel(
            tr!(
                "Si vous ne les reconnaissez pas, changez le mot de passe du Wi-Fi dans le routeur et reconnectez vos appareils ; ceux que vous reconnaissez, notez-les dans le carnet du scan",
                "If you do not recognize them, change the Wi-Fi password in the router and reconnect your devices; note those you recognize in the scan's device book"
            ),
            &[],
        );
    }
    let message = if n == 1 {
        trf!(
            "Un appareil inconnu sur le réseau : {liste}. Un nouvel appareil à vous, ou quelqu'un qui a le mot de passe du Wi-Fi.",
            "One unknown device on the network: {liste}. A new device of yours, or someone who has the Wi-Fi password."
        )
    } else {
        trf!(
            "{n} appareils inconnus sur le réseau : {liste}. De nouveaux appareils à vous, ou quelqu'un qui a le mot de passe du Wi-Fi.",
            "{n} unknown devices on the network: {liste}. New devices of yours, or someone who has the Wi-Fi password."
        )
    };
    alerte(CATEGORIE, Niveau::Info, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::wifi::elements::Protection;
    use crate::machine::wifi::{Bande, Borne};

    fn wpa2() -> Protection {
        Protection {
            chiffree: true,
            rsn: true,
            aes: true,
            psk: true,
            ..Protection::default()
        }
    }

    fn balise(ssid: &str, bssid: &str, canal: u16, actif: bool, protection: Protection, wps: Option<Wps>) -> Balise {
        Balise {
            borne: Borne {
                ssid: ssid.into(),
                bssid: bssid.into(),
                bande: Bande::de_canal(canal).unwrap(),
                canal,
                signal: Some(70),
                actif,
            },
            protection,
            wps,
        }
    }

    fn connexion(ssid: &str, bssid: &str) -> Connexion {
        Connexion {
            ssid: ssid.into(),
            bssid: bssid.into(),
            ..Connexion::default()
        }
    }

    fn entree(bornes: Vec<Balise>, connexion: Option<Connexion>) -> Entree {
        Entree {
            bornes: Ok(bornes),
            connexion,
            note: None,
            profils: Ok(Vec::new()),
            mac_box: None,
            nouveaux: None,
        }
    }

    fn salon() -> Entree {
        entree(
            vec![
                balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
                balise("Voisin", "00:11:33:aa:bb:02", 6, false, wpa2(), None),
            ],
            Some(connexion("Salon", "00:11:22:aa:bb:01")),
        )
    }

    #[test]
    fn cinq_regles_dans_l_ordre() {
        let c = constats(&salon());
        assert_eq!(c.iter().map(|c| c.regle).collect::<Vec<_>>(), REGLES);
        assert!(c.iter().all(|c| c.categorie == "Wi-Fi"));
        // WPA2-AES sans WPS, un seul émetteur, aucun profil, pas de scan : rien d'alarmant.
        assert!(c[0].verifie && c[0].probleme <= Some(Niveau::Info));
        assert!(c[1].verifie && c[1].probleme.is_none());
        assert!(c[2].verifie && c[2].probleme.is_none());
        assert!(c[3].verifie && c[3].probleme.is_none());
        assert!(!c[4].verifie);
    }

    #[test]
    fn sans_bornes_ni_connexion_non_verifie() {
        let mut e = salon();
        e.bornes = Err("pas de carte Wi-Fi sur cet ordinateur".into());
        let c = constats(&e);
        assert!(
            c[..3]
                .iter()
                .all(|c| !c.verifie && c.message.contains("pas de carte Wi-Fi"))
        );
        assert!(
            c[0].message.contains("chiffrement") && c[1].message.contains("WPS") && c[2].message.contains("émetteurs")
        );
        let mut e = salon();
        e.connexion = None;
        assert!(
            constats(&e)[..3]
                .iter()
                .all(|c| !c.verifie && c.message.contains("pas connecté"))
        );
        // Connecté, mais le balayage ne montre plus le réseau : non vérifié, avec la réserve du système.
        let mut e = salon();
        e.connexion = Some(connexion("Ailleurs", ""));
        e.note = Some("localisation");
        let c = constats(&e);
        assert!(!c[0].verifie && c[0].message.contains("localisation"));
        // La borne de la connexion suffit, même sans nom (réseau caché).
        let mut e = salon();
        e.connexion = Some(connexion("", "00:11:22:aa:bb:01"));
        let c = constats(&e);
        assert!(c[0].verifie && c[0].message.contains("réseau caché"));
    }

    #[test]
    fn chiffrement_du_reseau() {
        let tkip = Protection { tkip: true, ..wpa2() };
        let mut e = salon();
        e.bornes = Ok(vec![
            balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
            balise("Salon", "00:11:22:aa:bb:02", 6, false, tkip, None),
        ]);
        let c = &constats(&e)[0];
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("accepte encore") && c.message.contains("TKIP"));
        assert!(c.correctif.as_ref().is_some_and(|k| !k.automatique));
        let seulement = Protection { aes: false, ..tkip };
        e.bornes = Ok(vec![balise("Salon", "00:11:22:aa:bb:01", 36, true, seulement, None)]);
        assert!(constats(&e)[0].message.contains("n'accepte que"));
        // WPA de 2003, WEP, ouvert : les verdicts du bilan.
        let wpa = Protection {
            chiffree: true,
            wpa: true,
            tkip: true,
            psk: true,
            ..Protection::default()
        };
        e.bornes = Ok(vec![balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa, None)]);
        let c = &constats(&e)[0];
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("WPA"));
        let wep = Protection {
            chiffree: true,
            ..Protection::default()
        };
        e.bornes = Ok(vec![balise("Salon", "00:11:22:aa:bb:01", 36, true, wep, None)]);
        assert!(constats(&e)[0].message.contains("WEP"));
        e.bornes = Ok(vec![balise(
            "Salon",
            "00:11:22:aa:bb:01",
            36,
            true,
            Protection::default(),
            None,
        )]);
        let c = &constats(&e)[0];
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("ouvert"));
        // WPA3 : rien à redire.
        let wpa3 = Protection {
            sae: true,
            psk: false,
            pmf: true,
            pmf_exigee: true,
            ..wpa2()
        };
        e.bornes = Ok(vec![balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa3, None)]);
        let c = &constats(&e)[0];
        assert!(c.probleme.is_none() && c.message.contains("WPA3"));
    }

    #[test]
    fn wps_de_la_box() {
        let configure = |methodes, verrouille| {
            Some(Wps {
                etat: 2,
                verrouille,
                registraire: false,
                methodes,
            })
        };
        let mut e = salon();
        e.bornes = Ok(vec![balise(
            "Salon",
            "00:11:22:aa:bb:01",
            36,
            true,
            wpa2(),
            configure(Some(0x2088), false),
        )]);
        let c = &constats(&e)[1];
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("WPS allumé") && c.message.contains("code PIN offert"));
        assert!(!c.message.contains("00:11:22"), "un seul émetteur : pas d'adresse");
        // Bouton seul, ou PIN verrouillé : Info. Méthodes non dites : Moyen.
        e.bornes = Ok(vec![balise(
            "Salon",
            "00:11:22:aa:bb:01",
            36,
            true,
            wpa2(),
            configure(Some(0x0080), false),
        )]);
        let c = &constats(&e)[1];
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("bouton seulement"));
        e.bornes = Ok(vec![balise(
            "Salon",
            "00:11:22:aa:bb:01",
            36,
            true,
            wpa2(),
            configure(Some(0x2088), true),
        )]);
        assert_eq!(constats(&e)[1].probleme, Some(Niveau::Info));
        e.bornes = Ok(vec![balise(
            "Salon",
            "00:11:22:aa:bb:01",
            36,
            true,
            wpa2(),
            configure(None, false),
        )]);
        let c = &constats(&e)[1];
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("méthodes non dites"));
        // Deux émetteurs, un seul avec WPS : le pire est nommé.
        e.bornes = Ok(vec![
            balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
            balise(
                "Salon",
                "00:11:22:aa:bb:02",
                6,
                false,
                wpa2(),
                configure(Some(0x0004), false),
            ),
        ]);
        let c = &constats(&e)[1];
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("00:11:22:aa:bb:02"));
        // Un voisin avec WPS ne compte pas.
        e.bornes = Ok(vec![
            balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
            balise(
                "Voisin",
                "00:11:33:aa:bb:02",
                6,
                false,
                wpa2(),
                configure(Some(0x0004), false),
            ),
        ]);
        assert!(constats(&e)[1].probleme.is_none());
    }

    #[test]
    fn emetteurs_du_reseau() {
        let mut e = salon();
        // Deux bandes de la même box (le bit local posé sur la seconde) : normal.
        e.bornes = Ok(vec![
            balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
            balise("Salon", "02:11:22:aa:bb:02", 6, false, wpa2(), None),
        ]);
        e.mac_box = Some("00:11:22:aa:bb:00".into());
        let c = &constats(&e)[2];
        assert!(c.probleme.is_none() && c.message.contains("2 émetteurs"));
        // Une autre marque : à vérifier, Moyen, jamais plus.
        e.bornes = Ok(vec![
            balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
            balise("Salon", "00:11:33:aa:bb:02", 6, false, wpa2(), None),
        ]);
        let c = &constats(&e)[2];
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("00:11:33:aa:bb:02") && c.message.contains("marque de votre routeur"));
        assert!(c.correctif.as_ref().is_some_and(|k| !k.automatique));
        // Sans l'adresse de la box : comparé à l'émetteur de la connexion.
        e.mac_box = None;
        let c = &constats(&e)[2];
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("où vous êtes connecté"));
        // Même marque, mais ouvert : un jumeau possible.
        e.bornes = Ok(vec![
            balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
            balise("Salon", "00:11:22:aa:bb:02", 6, false, Protection::default(), None),
        ]);
        let c = &constats(&e)[2];
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("protège moins bien") && c.message.contains("ouvert"));
        // Un nom par défaut : Info seulement.
        e.bornes = Ok(vec![
            balise("linksys", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
            balise("linksys", "00:11:33:aa:bb:02", 6, false, wpa2(), None),
        ]);
        e.connexion = Some(connexion("linksys", "00:11:22:aa:bb:01"));
        let c = &constats(&e)[2];
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("nom par défaut"));
        assert!(nom_par_defaut(" NETGEAR ") && !nom_par_defaut("NETGEAR42"));
    }

    /// La preuve de la campagne d'attaque n° 3 : un jumeau qui recopie l'adresse de la box sur un autre canal, sans
    /// chiffrement. Les adresses dédoublonnées seules en faisaient « un seul émetteur : votre routeur ».
    #[test]
    fn jumeau_qui_copie_l_adresse_de_la_box() {
        let mut e = salon();
        e.mac_box = Some("00:11:22:aa:bb:00".into());
        e.bornes = Ok(vec![
            balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
            balise("Salon", "00:11:22:AA:BB:01", 6, false, Protection::default(), None),
        ]);
        let c = &constats(&e)[2];
        assert_eq!(c.probleme, Some(Niveau::Moyen), "{}", c.message);
        assert!(
            c.message.contains("canal 6") && c.message.contains("copie l'adresse"),
            "{}",
            c.message
        );
        assert!(c.correctif.as_ref().is_some_and(|k| !k.automatique));
        // Même canal, deux protections : aussi.
        e.bornes = Ok(vec![
            balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
            balise("Salon", "00:11:22:aa:bb:01", 36, false, Protection::default(), None),
        ]);
        assert_eq!(constats(&e)[2].probleme, Some(Niveau::Moyen));
        // La même borne entendue deux fois à l'identique : un seul émetteur.
        e.bornes = Ok(vec![
            balise("Salon", "00:11:22:aa:bb:01", 36, true, wpa2(), None),
            balise("Salon", "00:11:22:aa:bb:01", 36, false, wpa2(), None),
        ]);
        let c = &constats(&e)[2];
        assert!(
            c.probleme.is_none() && c.message.contains("Un seul émetteur"),
            "{}",
            c.message
        );
    }

    #[test]
    fn marques() {
        let a = marque("02:11:22:aa:bb:01");
        assert_eq!(a.prefixe, "00:11:22");
        assert!(a.locale);
        let b = marque("00:11:22:cc:dd:ee");
        assert!(!b.locale && meme_marque(&a, &b));
        assert!(!meme_marque(&a, &marque("00:11:33:cc:dd:ee")));
        assert!(fabricant_affiche(&a).contains(tr!("répéteur", "repeater")) || a.fabricant.is_some());
        assert_eq!(
            fabricant_affiche(&Marque {
                prefixe: String::new(),
                fabricant: None,
                locale: false
            }),
            "fabricant inconnu"
        );
        assert_eq!(
            fabricant_affiche(&Marque {
                prefixe: String::new(),
                fabricant: Some("Acme".into()),
                locale: true
            }),
            "Acme"
        );
        assert_eq!(marque("").prefixe, "");
    }

    #[test]
    fn reseaux_ouverts_enregistres() {
        let profil = |nom: &str, ouvert, automatique, sure| ProfilEnregistre {
            nom: nom.into(),
            automatique,
            ouvert,
            commande: format!("couper {nom}"),
            commande_sure: sure,
        };
        let mut e = salon();
        e.profils = Err("réservé à l'administrateur".into());
        let c = &constats(&e)[3];
        assert!(!c.verifie && c.message.contains("réservé à l'administrateur"));
        e.profils = Ok(vec![
            profil("Salon", false, true, true),
            profil("Hôtel", true, false, true),
        ]);
        let c = &constats(&e)[3];
        assert!(c.probleme.is_none() && c.message.contains("2 réseaux enregistrés"));
        e.profils = Ok(vec![profil("Salon", false, true, true)]);
        assert!(constats(&e)[3].message.contains("1 réseau enregistré"));
        // Deux réseaux ouverts automatiques, commandes sûres : correction lancée.
        e.profils = Ok(vec![
            profil("Hôtel", true, true, true),
            profil("Gare", true, true, true),
        ]);
        let c = &constats(&e)[3];
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("« Hôtel »") && c.message.contains("« Gare »"));
        let k = c.correctif.as_ref().unwrap();
        assert!(k.automatique && k.commandes == ["couper Hôtel", "couper Gare"]);
        // Une commande qui reprend un nom : montrée seulement.
        e.profils = Ok(vec![profil("Hôtel", true, true, false)]);
        assert!(constats(&e)[3].correctif.as_ref().is_some_and(|k| !k.automatique));
    }

    #[test]
    fn appareils_inconnus() {
        let mut e = salon();
        assert!(!constats(&e)[4].verifie);
        e = e.avec_scan(Vec::new(), Some("00:11:22:aa:bb:00".into()));
        assert_eq!(e.mac_box.as_deref(), Some("00:11:22:aa:bb:00"));
        let c = &constats(&e)[4];
        assert!(c.verifie && c.probleme.is_none());
        e.nouveaux = Some(vec!["Téléphone".into()]);
        let c = &constats(&e)[4];
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.starts_with("Un appareil inconnu") && c.message.contains("« Téléphone »"));
        e.nouveaux = Some(vec!["a".into(), "b".into(), "c".into()]);
        assert_eq!(constats(&e)[4].probleme, Some(Niveau::Info));
        e.nouveaux = Some((1..=5).map(|i| format!("appareil {i}")).collect());
        let c = &constats(&e)[4];
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("5 appareils") && c.message.contains("(et 2 autre(s))"));
        assert!(c.correctif.as_ref().is_some_and(|k| !k.automatique));
        // L'adresse de la box déjà connue n'est pas effacée par un scan qui ne la donne pas.
        let e = e.avec_scan(Vec::new(), None);
        assert_eq!(e.mac_box.as_deref(), Some("00:11:22:aa:bb:00"));
    }

    #[test]
    fn messages_sans_piege() {
        let piege = "Salon\x1b[2K\rFaux";
        let mut e = entree(
            vec![
                balise(
                    piege,
                    "00:11:22:aa:bb:01",
                    36,
                    true,
                    Protection::default(),
                    Some(Wps::default()),
                ),
                balise(piege, "00:11:33:aa:bb:02", 6, false, wpa2(), None),
            ],
            Some(connexion(piege, "00:11:22:aa:bb:01")),
        );
        e.nouveaux = Some(vec![piege.into(); 5]);
        e.profils = Ok(vec![ProfilEnregistre {
            nom: piege.into(),
            automatique: true,
            ouvert: true,
            commande: String::new(),
            commande_sure: false,
        }]);
        for c in constats(&e) {
            assert!(!crate::ui::contient_un_piege(&c.message), "{}", c.message);
        }
    }

    /// La vraie acquisition, sur cet ordinateur : elle finit vite, rend cinq constats aux messages inoffensifs, et
    /// dit « non vérifié » là où rien ne se lit (pas de carte, pas de droits, Wine). Rien de ce qui est lu n'est
    /// affiché.
    #[test]
    fn entree_reelle_et_rapide() {
        let debut = std::time::Instant::now();
        let e = entree_native_pour_test();
        let c = constats(&e);
        assert!(debut.elapsed() < std::time::Duration::from_secs(20));
        assert_eq!(c.len(), 5);
        assert!(c.iter().all(|c| !crate::ui::contient_un_piege(&c.message)));
        assert!(!c[4].verifie, "sans scan, les appareils inconnus restent non vérifiés");
    }

    fn entree_native_pour_test() -> Entree {
        super::entree()
    }

    /// `cargo test -- --ignored resume_de_l_audit --nocapture` : les cinq constats sur cet ordinateur, tels quels.
    #[test]
    #[ignore = "lecture de la machine, à lancer à la main"]
    fn resume_de_l_audit() {
        for c in constats(&entree_native_pour_test()) {
            let etat = if c.verifie {
                format!("{:?}", c.probleme)
            } else {
                "non vérifié".to_string()
            };
            println!("{} [{etat}] {}", c.regle, c.message);
            if let Some(k) = &c.correctif {
                println!("    → {} (auto : {}) {:?}", k.action, k.automatique, k.commandes);
            }
        }
    }
}
