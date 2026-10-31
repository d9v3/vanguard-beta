//! La liste d'indicateurs de logiciels espions de l'association Échap (<https://echap.eu.org>), sous licence CC-BY 4.0 :
//! pour chaque logiciel espion vendu au grand public (TheTruthSpy, mSpy, FlexiSpy…), ses noms, les sites où il se
//! vend et où se consulte ce qu'il a volé, et ses serveurs de commande. Téléchargée à l'usage depuis son dépôt, gardée
//! un jour comme les listes d'abuse.ch, jamais intégrée au programme (rien n'est redistribué ; la mention est faite à
//! l'écran et dans LICENCES-TIERCES.txt).
//!
//! Le fichier est du YAML. Aucune bibliothèque YAML n'est prise pour lui : un petit lecteur écrit ici lit le sous-ensemble
//! qu'Échap emploie (une suite d'entrées, des clés, des listes, une table « c2 »), borné en lignes, en entrées et en
//! valeurs, et refuse le reste. Les paquets Android et les certificats d'APK ne servent pas sur un ordinateur : lus,
//! puis jetés.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::{tr, trf};

const ADRESSE: &str = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml";
/// La liste change quelques fois par mois.
const FRAICHE: Duration = Duration::from_hours(24);
/// Au-delà, une copie qui n'a pas pu être rafraîchie ne sert plus : dit, jamais compté comme vérifié.
const TROP_VIEILLE: Duration = Duration::from_hours(60 * 24);
/// 95 Ko le 22 oct. 2026.
const TAILLE_MAX: u64 = 4 << 20;

/// Bornes du lecteur : une page piégée (ou un portail Wi-Fi) ne doit ni remplir la mémoire ni figer l'écran.
const LIGNES_MAX: usize = 200_000;
const LONGUEUR_MAX: usize = 1024;
const ENTREES_MAX: usize = 5_000;
const VALEURS_PAR_ENTREE: usize = 20_000;
const VALEURS_MAX: usize = 200_000;

/// Une liste plus petite que ça n'est pas celle d'Échap (149 entrées et 929 domaines le 22 oct. 2026) : jamais une
/// liste vide, donc « rien trouvé », à sa place.
const ENTREES_MIN: usize = 20;
const DOMAINES_MIN: usize = 50;

/// Des hébergeurs partagés par des millions de sites : jamais gardés comme indicateur (« github.com » est un hôte de
/// distribution de la liste), ni atteints par la recherche des sous-domaines. Seul un nom précis chez eux
/// (« x.firebaseio.com ») peut l'être.
const PLATEFORMES: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "appspot.com",
    "firebaseio.com",
    "firebaseapp.com",
    "s3.amazonaws.com",
    "amazonaws.com",
    "azurewebsites.net",
    "windows.net",
    "azurewebsites.windows.net",
    "herokuapp.com",
    "blogspot.com",
    "digitaloceanspaces.com",
    "wasabisys.com",
    "back4app.io",
    "google.com",
    "play.google.com",
    "drive.google.com",
    "dropbox.com",
];

/// Les domaines (et leurs sous-domaines) d'entrées écartées, jamais gardés ni comme serveur ni comme site : Traccar
/// est un projet libre de suivi GPS (sa documentation, demo.traccar.org), Bark un contrôle parental, WiseMo un bureau à
/// distance (renvoyé à « Mon ordinateur est-il contrôlé ? »), FindMyKids une localisation d'enfant qu'un parent règle depuis
/// son ordinateur (plan, § 1). Les visiter n'est pas un signe ; les domaines de Cerberus, eux, restent.
const DOMAINES_ECARTES: &[&str] = &["traccar.org", "bark.us", "wisemo.com", "findmykids.org"];

/// Le domaine d'une entrée écartée, ou l'un de ses sous-domaines.
fn ecarte(d: &str) -> bool {
    DOMAINES_ECARTES
        .iter()
        .any(|e| d == *e || d.strip_suffix(e).is_some_and(|r| r.ends_with('.')))
}

/// Des noms précis mais partagés, jamais gardés comme indicateur : la démo WebRTC publique de Google.
const NOMS_PARTAGES: &[&str] = &["apprtc.appspot.com"];

/// Un nom d'infrastructure partagée : les unités d'Azure App Service (« waws-prod-… »), vers lesquelles chaque
/// application *.azurewebsites.net hébergée là renvoie par CNAME (la mémoire DNS garde aussi ce nom-là), ou un nom
/// de `NOMS_PARTAGES`.
fn partage(d: &str) -> bool {
    d.starts_with("waws-prod-") || NOMS_PARTAGES.contains(&d)
}

/// Les adresses d'entrée de Cloudflare, partagées par des millions de sites : une adresse de la liste prise là
/// accuserait Steam, Discord ou pacman de parler à un logiciel espion. Plages publiées par Cloudflare
/// (<https://www.cloudflare.com/ips-v4> et <https://www.cloudflare.com/ips-v6>) : (adresse, longueur du préfixe).
const PLAGES_PARTAGEES: &[(&str, u8)] = &[
    ("173.245.48.0", 20),
    ("103.21.244.0", 22),
    ("103.22.200.0", 22),
    ("103.31.4.0", 22),
    ("141.101.64.0", 18),
    ("108.162.192.0", 18),
    ("190.93.240.0", 20),
    ("188.114.96.0", 20),
    ("197.234.240.0", 22),
    ("198.41.128.0", 17),
    ("162.158.0.0", 15),
    ("104.16.0.0", 13),
    ("104.24.0.0", 14),
    ("172.64.0.0", 13),
    ("131.0.72.0", 22),
    ("2400:cb00::", 32),
    ("2606:4700::", 32),
    ("2803:f800::", 32),
    ("2405:b500::", 32),
    ("2405:8100::", 32),
    ("2a06:98c0::", 29),
    ("2c0f:f248::", 32),
];

/// Une adresse d'un hébergeur partagé (`PLAGES_PARTAGEES`).
fn partagee(ip: IpAddr) -> bool {
    let dans = |reseau: u128, adresse: u128, bits: u8, total: u8| {
        let decalage = u32::from(total.saturating_sub(bits));
        reseau.checked_shr(decalage).unwrap_or(0) == adresse.checked_shr(decalage).unwrap_or(0)
    };
    PLAGES_PARTAGEES
        .iter()
        .any(|(reseau, bits)| match (reseau.parse::<IpAddr>(), ip.to_canonical()) {
            (Ok(IpAddr::V4(r)), IpAddr::V4(a)) => dans(u32::from(r).into(), u32::from(a).into(), *bits, 32),
            (Ok(IpAddr::V6(r)), IpAddr::V6(a)) => dans(u128::from(r), u128::from(a), *bits, 128),
            _ => false,
        })
}

/// Noms d'entrées jamais comparés aux noms des programmes : mots courants (« Observer », « Dash »), projets libres ou
/// outils qui ne sont pas des logiciels espions sur un ordinateur (Traccar, Metasploit), applications de contrôle
/// parental ou de localisation de téléphone, logiciel de bureau à distance (WiseMo : renvoyé à « Mon ordinateur est-il
/// contrôlé ? ») et noms qui sont aussi ceux d'éléments ordinaires d'un système (« Screen Time » de macOS, « Mobile Backup »,
/// « System Framework »). Normalisés (minuscules, lettres et chiffres seulement). Tout nom de moins de 6 caractères
/// est écarté aussi.
const EXCLUS: &[&str] = &[
    "stalkerware",
    "observer",
    "dash",
    "juju",
    "bark",
    "cerberus",
    "metasploit",
    "traccar",
    "findmyphone",
    "findmykids",
    "androidlost",
    "wisemo",
    "screentime",
    "systemframework",
    "lockscreenprotector",
    "mobilebackup",
    "inmobi",
    "remotecommand",
    "remotesecurity",
    "autoforward",
    // Alias de SpyNote : Scream est aussi un pilote audio libre des machines virtuelles (programme « scream »).
    "scream",
    // Alias de Tracku : « Kurulum », c'est « installation » en turc (Kurulum.exe, un installateur).
    "kurulum",
];

/// Les entrées dont aucun nom, même un alias, n'est comparé aux programmes : leurs alias sont aussi trompeurs que leur
/// nom (Cerberus a « System Framework » et « Lock Screen Protector »).
const ENTREES_EXCLUES: &[&str] = &[
    "cerberus",
    "traccar",
    "metasploit",
    "bark",
    "wisemo",
    "findmykids",
    "findmyphone",
];

/// Une entrée de la liste, réduite à ce qui sert sur un ordinateur.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Entree {
    pub nom: String,
    pub noms: Vec<String>,
    pub sites: Vec<String>,
    pub distribution: Vec<String>,
    pub domaines: Vec<String>,
    pub ips: Vec<String>,
}

/// Les indicateurs utilisables : chaque domaine, adresse ou nom renvoie au nom de son entrée (« TheTruthSpy »).
#[derive(Debug, Default)]
pub(crate) struct Indicateurs {
    serveurs: HashMap<String, String>,
    /// Adresses : (entrée, serveur de commande ; sinon hôte de distribution).
    ips: HashMap<IpAddr, (String, bool)>,
    sites: HashMap<String, String>,
    produits: HashMap<String, String>,
    pub entrees: usize,
}

/// Ce que la liste a donné pour un nom ou une adresse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Genre {
    /// Serveur de commande : le logiciel espion y envoie ce qu'il a volé, ou en reçoit ses ordres.
    Serveur,
    /// Site de vente, tableau de bord ou hôte de téléchargement.
    Site,
}

impl Indicateurs {
    /// Une adresse IP sur la liste. Une adresse IPv4 vue par une prise IPv6 (« ::ffff:192.0.2.1 ») est comparée sous
    /// sa forme IPv4, celle de la liste.
    pub(crate) fn ip(&self, ip: IpAddr) -> Option<(&str, Genre)> {
        self.ips
            .get(&ip.to_canonical())
            .map(|(nom, serveur)| (nom.as_str(), if *serveur { Genre::Serveur } else { Genre::Site }))
    }

    /// Un nom demandé par l'ordinateur : serveur de commande (le nom même ou l'un de ses sous-domaines, comme pour
    /// ThreatFox), sinon site (le nom même, avec ou sans « www. » : un sous-domaine d'un site de vente est souvent
    /// celui d'un autre service, hébergé ailleurs).
    pub(crate) fn nom(&self, nom: &str) -> Option<(&str, Genre)> {
        let nom = nom.trim_end_matches('.').to_lowercase();
        let serveur = std::iter::successors(Some(nom.as_str()), |n| n.split_once('.').map(|(_, reste)| reste))
            .filter(|n| n.contains('.') && !PLATEFORMES.contains(n))
            .find_map(|n| self.serveurs.get(n));
        if let Some(entree) = serveur {
            return Some((entree, Genre::Serveur));
        }
        let sans_www = nom.strip_prefix("www.").unwrap_or(&nom);
        [nom.as_str(), sans_www, &format!("www.{sans_www}")]
            .iter()
            .find_map(|n| self.sites.get(*n))
            .map(|entree| (entree.as_str(), Genre::Site))
    }

    /// Le nom d'un programme (installé, processus, service), s'il est exactement le nom d'un logiciel espion de la
    /// liste, en ignorant la casse, les espaces, tirets, points et l'extension « .exe » ou « .app ». Jamais par une
    /// partie du nom : « Observer » ou « Dash » sont des mots courants, et la liste nomme surtout des applications de
    /// téléphone.
    pub(crate) fn produit(&self, programme: &str) -> Option<&str> {
        let n = normaliser(programme);
        if n.len() < 6 || EXCLUS.contains(&n.as_str()) {
            return None;
        }
        self.produits.get(&n).map(String::as_str)
    }
}

/// Minuscules, lettres et chiffres seulement, sans l'extension d'un programme.
fn normaliser(nom: &str) -> String {
    let bas = nom.trim().to_lowercase();
    let sans = [".exe", ".app"]
        .iter()
        .find_map(|e| bas.strip_suffix(e))
        .unwrap_or(&bas);
    sans.chars().filter(|c| c.is_alphanumeric()).collect()
}

// ───────────────────────────── Le lecteur YAML ─────────────────────────────

/// Une valeur sans guillemets appariés autour.
fn sans_guillemets(v: &str) -> &str {
    for g in ['"', '\''] {
        if let Some(dedans) = v.strip_prefix(g).and_then(|r| r.strip_suffix(g))
            && v.len() >= 2
        {
            return dedans;
        }
    }
    v
}

/// La ligne sans son commentaire : « # » en tête, ou « # » précédé d'un blanc hors guillemets.
fn sans_commentaire(ligne: &str) -> &str {
    if ligne.starts_with('#') {
        return "";
    }
    let mut guillemet = None;
    let mut avant = ' ';
    for (i, c) in ligne.char_indices() {
        match guillemet {
            Some(g) if c == g => guillemet = None,
            None if c == '"' || c == '\'' => guillemet = Some(c),
            None if c == '#' && avant.is_whitespace() => return &ligne[..i],
            _ => {}
        }
        avant = c;
    }
    ligne
}

/// « clé: valeur », « clé : valeur » ou « clé: » ; `None` si la ligne n'en est pas une.
fn cle_valeur(texte: &str) -> Option<(&str, &str)> {
    let (cle, valeur) = texte.split_once(':')?;
    let cle = cle.trim_end();
    if cle.is_empty() || !cle.bytes().all(|o| o.is_ascii_alphanumeric() || o == b'_') {
        return None;
    }
    // « clé:valeur » sans blanc n'est pas une clé en YAML (une adresse « a:b ») ; Échap n'en écrit pas.
    if !valeur.is_empty() && !valeur.starts_with(' ') {
        return None;
    }
    Some((cle, valeur.trim()))
}

/// Une valeur scalaire utilisable : `None` pour ce que ce lecteur ne lit pas (bloc « | », « > », ancre, alias, liste
/// ou table sur une ligne) — compté comme ignoré, jamais deviné.
fn scalaire(valeur: &str) -> Option<&str> {
    if valeur.starts_with(['|', '>', '&', '*', '{', '[']) {
        return None;
    }
    Some(sans_guillemets(valeur).trim())
}

/// La liste lue : ses entrées, et le nombre de lignes ou valeurs ignorées (format que ce lecteur ne lit pas).
#[derive(Debug, Default)]
pub(super) struct Lecture {
    pub entrees: Vec<Entree>,
    pub ignorees: usize,
}

/// Lit le sous-ensemble YAML d'ioc.yaml. `None` : au-delà des bornes (lignes, entrées, valeurs).
pub(super) fn lire_yaml(texte: &str) -> Option<Lecture> {
    let mut lecture = Lecture::default();
    let mut courante: Option<Entree> = None;
    // Les clés ouvertes de l'entrée en cours : (retrait, nom).
    let mut pile: Vec<(usize, String)> = Vec::new();
    let (mut valeurs_entree, mut valeurs) = (0usize, 0usize);
    for (n, ligne) in texte.split('\n').enumerate() {
        if n >= LIGNES_MAX {
            return None;
        }
        let ligne = ligne.strip_suffix('\r').unwrap_or(ligne);
        // Une ligne trop longue est ignorée, mais si elle commence une entrée, la limite reste : sans elle, les clés
        // qui suivent iraient à l'entrée d'avant (ses serveurs montrés comme ceux d'un autre logiciel).
        let longue = ligne.len() > LONGUEUR_MAX;
        if longue && !(ligne == "-" || ligne.starts_with("- ")) {
            lecture.ignorees = lecture.ignorees.saturating_add(1);
            continue;
        }
        let retrait = ligne.bytes().take_while(|&o| o == b' ').count();
        let reste = &ligne[retrait..];
        if reste.starts_with('\t') {
            lecture.ignorees = lecture.ignorees.saturating_add(1);
            continue;
        }
        let reste = sans_commentaire(reste).trim_end();
        if reste.is_empty() {
            continue;
        }
        // Une nouvelle entrée : « - » en colonne 0 ; le reste de la ligne est sa première clé.
        let (retrait, reste) = if retrait == 0 && (reste == "-" || reste.starts_with("- ")) {
            if let Some(e) = courante.take() {
                lecture.entrees.push(e);
            }
            if lecture.entrees.len() >= ENTREES_MAX {
                return None;
            }
            courante = Some(Entree::default());
            pile.clear();
            valeurs_entree = 0;
            if longue {
                // Une entrée sans nom : ses valeurs sont lues puis jetées (`indicateurs_de` saute les sans-nom).
                lecture.ignorees = lecture.ignorees.saturating_add(1);
                continue;
            }
            let r = reste[1..].trim_start();
            if r.is_empty() {
                continue;
            }
            (2, r)
        } else {
            (retrait, reste)
        };
        let Some(entree) = courante.as_mut() else {
            // Avant la première entrée : pas la liste d'Échap (un portail Wi-Fi, une page HTML).
            lecture.ignorees = lecture.ignorees.saturating_add(1);
            continue;
        };
        let (chemin, valeur) = if reste == "-" || reste.starts_with("- ") {
            // Un élément de liste : toujours une valeur, jamais une table (une expression régulière contient « : »),
            // rattachée à la dernière clé ouverte de retrait inférieur ou égal.
            while pile.last().is_some_and(|(r, _)| *r > retrait) {
                pile.pop();
            }
            let chemin: Vec<&str> = pile.iter().map(|(_, c)| c.as_str()).collect();
            (chemin.join("/"), reste[1..].trim_start())
        } else if let Some((cle, valeur)) = cle_valeur(reste) {
            while pile.last().is_some_and(|(r, _)| *r >= retrait) {
                pile.pop();
            }
            if valeur.is_empty() {
                pile.push((retrait, cle.to_string()));
                continue;
            }
            let mut chemin: Vec<&str> = pile.iter().map(|(_, c)| c.as_str()).collect();
            chemin.push(cle);
            (chemin.join("/"), valeur)
        } else {
            lecture.ignorees = lecture.ignorees.saturating_add(1);
            continue;
        };
        let Some(valeur) = scalaire(valeur) else {
            lecture.ignorees = lecture.ignorees.saturating_add(1);
            continue;
        };
        let liste = match chemin.as_str() {
            "name" => None,
            "names" => Some(&mut entree.noms),
            "websites" => Some(&mut entree.sites),
            "distribution" => Some(&mut entree.distribution),
            "c2/domains" => Some(&mut entree.domaines),
            "c2/ips" | "c2/ip" => Some(&mut entree.ips),
            // Paquets, certificats, type… : lus puis jetés.
            _ => continue,
        };
        if valeur.is_empty() {
            continue;
        }
        // Compteurs bornés juste après (VALEURS_PAR_ENTREE, VALEURS_MAX).
        valeurs_entree = valeurs_entree.saturating_add(1);
        valeurs = valeurs.saturating_add(1);
        if valeurs_entree > VALEURS_PAR_ENTREE || valeurs > VALEURS_MAX {
            return None;
        }
        match liste {
            Some(l) => l.push(valeur.to_string()),
            None => entree.nom = valeur.to_string(),
        }
    }
    if let Some(e) = courante {
        lecture.entrees.push(e);
    }
    (lecture.entrees.len() <= ENTREES_MAX).then_some(lecture)
}

// ───────────────────────────── Validation ─────────────────────────────

/// Un nom de domaine utilisable, en minuscules : au moins deux étiquettes de lettres, chiffres, « - » (« _ » toléré,
/// vu chez les hébergeurs), sans tiret au bord, 253 caractères au plus ; jamais une adresse IP écrite en nom.
fn domaine(nom: &str) -> Option<String> {
    let nom = nom.trim().trim_end_matches('.').to_ascii_lowercase();
    if nom.len() > 253 || !nom.is_ascii() || nom.parse::<IpAddr>().is_ok() {
        return None;
    }
    let etiquettes: Vec<&str> = nom.split('.').collect();
    let bonnes = etiquettes.iter().all(|e| {
        (1..=63).contains(&e.len())
            && !e.starts_with('-')
            && !e.ends_with('-')
            && e.bytes().all(|o| o.is_ascii_alphanumeric() || o == b'-' || o == b'_')
    });
    let tld_lettres = etiquettes
        .last()
        .is_some_and(|t| t.bytes().any(|o| o.is_ascii_alphabetic()));
    (etiquettes.len() >= 2 && bonnes && tld_lettres).then_some(nom)
}

/// Une adresse IP sur Internet (jamais une adresse privée, locale ou réservée, qui désignerait un appareil de la maison),
/// hors des hébergeurs partagés.
fn adresse(texte: &str) -> Option<IpAddr> {
    let ip = texte.trim().parse::<IpAddr>().ok()?.to_canonical();
    (crate::socle::adresses::sur_internet(ip) && !partagee(ip)).then_some(ip)
}

/// L'hôte d'une ligne de distribution : une adresse (« <https://github.com/x/y> ») ou un nom nu ; schéma, chemin,
/// compte (« user@ ») et port retirés.
fn hote(ligne: &str) -> &str {
    let sans_schema = ligne.split_once("://").map_or(ligne, |(_, r)| r);
    let autorite = sans_schema.split(['/', '?', '#']).next().unwrap_or_default();
    let autorite = autorite.rsplit_once('@').map_or(autorite, |(_, r)| r);
    if let Some(v6) = autorite.strip_prefix('[') {
        return v6.split(']').next().unwrap_or_default();
    }
    match autorite.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|o| o.is_ascii_digit()) => h,
        _ => autorite,
    }
}

/// Les indicateurs d'une liste lue ; `None` si elle est trop petite pour être celle d'Échap.
pub(super) fn indicateurs_de(entrees: &[Entree]) -> Option<Indicateurs> {
    let mut ind = Indicateurs {
        entrees: entrees.len(),
        ..Indicateurs::default()
    };
    for e in entrees {
        let nom = crate::ui::affichable(e.nom.trim());
        if nom.is_empty() {
            continue;
        }
        for d in e.domaines.iter().filter_map(|d| domaine(d)) {
            if !PLATEFORMES.contains(&d.as_str()) && !ecarte(&d) && !partage(&d) {
                ind.serveurs.entry(d).or_insert_with(|| nom.clone());
            }
        }
        for ip in e.ips.iter().filter_map(|i| adresse(i)) {
            ind.ips.insert(ip, (nom.clone(), true));
        }
        for h in e
            .sites
            .iter()
            .map(String::as_str)
            .chain(e.distribution.iter().map(|d| hote(d)))
        {
            if let Some(ip) = adresse(h) {
                ind.ips.entry(ip).or_insert_with(|| (nom.clone(), false));
            } else if let Some(d) = domaine(h)
                && !PLATEFORMES.contains(&d.as_str())
                && !ecarte(&d)
                && !partage(&d)
            {
                ind.sites.entry(d).or_insert_with(|| nom.clone());
            }
        }
        if ENTREES_EXCLUES.contains(&normaliser(&e.nom).as_str()) {
            continue;
        }
        for n in std::iter::once(&e.nom).chain(&e.noms) {
            let cle = normaliser(n);
            if cle.len() >= 6 && !EXCLUS.contains(&cle.as_str()) {
                ind.produits.entry(cle).or_insert_with(|| nom.clone());
            }
        }
    }
    (ind.entrees >= ENTREES_MIN && ind.serveurs.len() >= DOMAINES_MIN).then_some(ind)
}

// ───────────────────────────── Téléchargement ─────────────────────────────

/// La liste, et l'âge de la copie qui sert. `telecharger` : la rafraîchir si elle a plus d'un jour (sauf hors ligne) ;
/// sinon, la copie gardée seulement, jamais de réseau (le bilan), et pas au-delà de `age_max`. `Err` : pourquoi elle
/// ne sert pas, prêt à suivre « liste d'Échap non vérifiée : ».
pub(crate) fn indicateurs(telecharger: bool, age_max: Duration) -> Result<(Indicateurs, Duration), String> {
    let (octets, age) = if telecharger && !crate::parametres::hors_ligne() {
        use crate::protection::abuse_ch::Echec;
        // Validée avant de remplacer la copie : une page de blocage reçue avec un 200 ne l'efface pas.
        crate::socle::cache::liste(demande(), ("echap", "ioc.yaml"), FRAICHE, |o| du_fichier(o).is_some())
            .resultat(false)
            .map_err(|e| match e {
                Echec::Reponse(code) => trf!("GitHub a répondu {code}", "GitHub answered {code}"),
                Echec::SansReponse => tr!("pas d'Internet ?", "no Internet?").to_string(),
                autre => autre.raison(),
            })?
    } else {
        copie_gardee()
            .map_err(|r| {
                trf!(
                    "{} (vanguard logiciels-espions la retélécharge)",
                    "{} (vanguard spyware downloads it again)",
                    r.texte()
                )
            })?
            .ok_or_else(|| {
                if telecharger {
                    tr!(
                        "hors ligne demandé, et aucune copie gardée",
                        "offline mode requested, and no saved copy"
                    )
                } else {
                    tr!(
                        "aucune copie récente (vanguard logiciels-espions la télécharge)",
                        "no recent copy (vanguard spyware downloads it)"
                    )
                }
                .to_string()
            })?
    };
    if age > age_max {
        return Err(if telecharger {
            tr!(
                "copie de plus de 60 jours, rafraîchissement impossible",
                "copy more than 60 days old, could not refresh it"
            )
            .to_string()
        } else {
            trf!(
                "copie de plus de {} jours (vanguard logiciels-espions la rafraîchit)",
                "copy more than {} days old (vanguard spyware refreshes it)",
                age_max.as_secs() / 86_400
            )
        });
    }
    let illisible = || {
        tr!(
            "liste illisible (page d'un portail Wi-Fi ?)",
            "list unreadable (a Wi-Fi portal page?)"
        )
        .to_string()
    };
    let texte = std::str::from_utf8(&octets).map_err(|_| illisible())?;
    let lecture = lire_yaml(texte).ok_or_else(illisible)?;
    let ind = indicateurs_de(&lecture.entrees).ok_or_else(illisible)?;
    Ok((ind, age))
}

/// La demande de la liste : la même pour le programme et pour les canaris de la veille de nuit (`canaris`).
pub(crate) fn demande() -> crate::http::Demande<'static> {
    crate::http::Demande {
        taille_max: TAILLE_MAX,
        meme_hote: true,
        ..crate::http::Demande::get(ADRESSE, Duration::from_secs(30))
    }
}

/// Les indicateurs d'un fichier reçu, s'il se lit en entier comme la liste d'Échap.
fn du_fichier(octets: &[u8]) -> Option<Indicateurs> {
    indicateurs_de(&lire_yaml(std::str::from_utf8(octets).ok()?)?.entrees)
}

/// Les comptes d'un fichier reçu (entrées, serveurs, adresses, sites), par le même lecteur que le programme : les
/// canaris de la veille de nuit les comparent d'un jour à l'autre. `None` : le programme refuserait ce fichier.
#[cfg(test)]
pub(crate) fn comptes(octets: &[u8]) -> Option<[usize; 4]> {
    du_fichier(octets).map(|i| [i.entrees, i.serveurs.len(), i.ips.len(), i.sites.len()])
}

/// La copie gardée par un téléchargement d'avant, et son âge d'après son sceau (`socle::cache::gardee`) ; `Err` : la
/// raison de son refus (changée hors de Vanguard, datée dans le futur…), jamais une liste crue.
fn copie_gardee() -> Result<Option<(Vec<u8>, Duration)>, crate::socle::cache::Refus> {
    crate::socle::cache::gardee(("echap", "ioc.yaml"), crate::socle::cache::LISTE_MAX)
}

/// L'âge par défaut au-delà duquel `vanguard logiciels-espions` ne se sert plus d'une copie.
pub(crate) const AGE_ECRAN: Duration = TROP_VIEILLE;

#[cfg(test)]
mod tests {
    use super::*;

    /// Un extrait inventé qui reproduit chaque irrégularité relevée dans le vrai fichier, et celles qu'il pourrait
    /// avoir un jour.
    const EXTRAIT: &str = "\
# un commentaire en tête\r
- name: EspionUn\r
  names:\r
  - Espion Un\r
  - 'EspionPro'\r
  type: stalkerware\r
  packages:\r
  - com.example.espion\r
  certificate_cname_re:\r
  - ^Kids\\WSafety\\W[0-9]{2}:[0-9]{2}$\r
  websites:\r
    - vendeur.example\r
    - \"www.tableau.example\"\r
  distribution:\r
  - https://github.com/alice/espion/releases\r
  - telechargement.example:8080\r
  - 203.0.113.9\r
  c2:\r
    ips:\r
      - 203.0.113.7\r
    domains:\r
    - c2.example.com  # c2.example.com/donnees.apk\r
    - EXAMPLE.org\r
- name : EspionDeux
  c2:
    ip:
    - 198.51.100.4
    domains:
    - autre.example.net
\t- tabulation.example
  notes: |
    texte en bloc
  websites:
  - [a, b]
";

    #[test]
    fn extrait_aux_irregularites_lu() {
        let l = lire_yaml(EXTRAIT).unwrap();
        assert_eq!(l.entrees.len(), 2);
        let un = &l.entrees[0];
        assert_eq!(un.nom, "EspionUn");
        assert_eq!(un.noms, ["Espion Un", "EspionPro"]);
        assert_eq!(un.sites, ["vendeur.example", "www.tableau.example"]);
        assert_eq!(
            un.distribution,
            [
                "https://github.com/alice/espion/releases",
                "telechargement.example:8080",
                "203.0.113.9"
            ]
        );
        assert_eq!(un.ips, ["203.0.113.7"]);
        assert_eq!(un.domaines, ["c2.example.com", "EXAMPLE.org"]);
        let deux = &l.entrees[1];
        assert_eq!(deux.nom, "EspionDeux");
        assert_eq!(deux.ips, ["198.51.100.4"]);
        assert_eq!(deux.domaines, ["autre.example.net"]);
        // La tabulation, le bloc « | » (sa ligne de texte n'est pas une clé) et la liste sur une ligne : ignorés.
        assert_eq!(l.ignorees, 4);
        assert_eq!(deux.sites, Vec::<String>::new());
        // Une ligne de 2 000 octets : ignorée, comptée.
        let longue = format!("- name: X\n  websites:\n  - {}.example\n", "a".repeat(2000));
        assert_eq!(lire_yaml(&longue).unwrap().ignorees, 1);
        // Un « - name: » trop long commence quand même une entrée : ses serveurs ne vont pas à celle d'avant.
        let texte = format!(
            "- name: A\n  c2:\n    domains:\n    - a.example.com\n- name: {}\n  c2:\n    domains:\n    - b.example.org\n",
            "B".repeat(2000)
        );
        let l = lire_yaml(&texte).unwrap();
        assert_eq!(l.entrees[0].domaines, ["a.example.com"]);
        assert_eq!(l.entrees.len(), 2);
        assert_eq!(l.entrees[1].nom, "");
        assert_eq!(l.ignorees, 1);
    }

    #[test]
    fn bornes_et_pages_qui_ne_sont_pas_la_liste() {
        let trop = "- name: E\n".repeat(ENTREES_MAX + 1);
        assert!(lire_yaml(&trop).is_none());
        // Un portail Wi-Fi : rien d'une entrée.
        let html = "<!DOCTYPE html>\n<html><body>Connectez-vous : Wi-Fi gratuit</body></html>\n";
        let l = lire_yaml(html).unwrap();
        assert_eq!(l.entrees, Vec::<Entree>::new());
        assert!(indicateurs_de(&l.entrees).is_none());
        // Une liste trop courte n'est jamais prise pour la vraie.
        let courte = lire_yaml(EXTRAIT).unwrap();
        assert!(indicateurs_de(&courte.entrees).is_none());
    }

    /// Assez d'entrées inventées pour passer les seuils, plus celles de l'extrait.
    fn indicateurs_inventes() -> Indicateurs {
        let mut entrees = lire_yaml(EXTRAIT).unwrap().entrees;
        for i in 0..ENTREES_MIN {
            entrees.push(Entree {
                nom: format!("Remplissage{i}"),
                domaines: (0..3).map(|j| format!("r{i}-{j}.example.com")).collect(),
                ..Entree::default()
            });
        }
        entrees.push(Entree {
            nom: "Cerberus".into(),
            noms: vec!["System Framework".into()],
            domaines: vec!["firebaseio.com".into(), "projet-123.firebaseio.com".into()],
            sites: vec!["github.com".into(), "s3.amazonaws.com".into()],
            ..Entree::default()
        });
        entrees.push(Entree {
            nom: "Observer".into(),
            ..Entree::default()
        });
        // Des alias qui sont des noms ordinaires, comme dans le vrai fichier.
        entrees.push(Entree {
            nom: "EspionTrois".into(),
            noms: vec!["Kurulum".into(), "Scream".into()],
            // Deux adresses d'entrée de Cloudflare, partagées par des millions de sites.
            ips: vec![
                "104.26.14.56".into(),
                "172.67.73.2".into(),
                "2606:4700::6810:e38".into(),
            ],
            ..Entree::default()
        });
        // L'infrastructure partagée d'Azure et la démo WebRTC de Google : ni serveur ni site.
        entrees.push(Entree {
            nom: "EspionQuatre".into(),
            domaines: vec![
                "waws-prod-xyz-1.sip.azurewebsites.windows.net".into(),
                "waws-prod-xyz-1-ab12.eastus.cloudapp.azure.com".into(),
            ],
            sites: vec!["apprtc.appspot.com".into()],
            ..Entree::default()
        });
        // Les entrées écartées gardent des domaines dans la liste : ni serveur ni site.
        for (nom, domaines, sites) in [
            ("Traccar", "traccar.org", "demo.traccar.org"),
            ("bark", "www.bark.us", "bark.us"),
            ("WiseMo", "mycloud.wisemo.com", "www.wisemo.com"),
            ("FindMyKids", "api.findmykids.org", "findmykids.org"),
        ] {
            entrees.push(Entree {
                nom: nom.into(),
                domaines: vec![domaines.into()],
                sites: vec![sites.into()],
                ..Entree::default()
            });
        }
        indicateurs_de(&entrees).unwrap()
    }

    #[test]
    fn validation_des_noms_et_adresses() {
        assert_eq!(domaine("EXAMPLE.com").as_deref(), Some("example.com"));
        assert_eq!(domaine("x_y.example.com.").as_deref(), Some("x_y.example.com"));
        for refuse in [
            "a..example.com",
            "-a.example.com",
            "a-.example.com",
            "example",
            "192.0.2.1",
            "1.2.3.4.5",
            "é.example",
            &format!("{}.example", "a.".repeat(126)),
        ] {
            assert_eq!(domaine(refuse), None, "{refuse}");
        }
        assert_eq!(adresse("10.0.0.1"), None);
        assert_eq!(adresse("192.168.1.1"), None);
        assert_eq!(adresse("127.0.0.1"), None);
        assert_eq!(adresse("203.0.113.7"), Some("203.0.113.7".parse().unwrap()));
        assert_eq!(
            hote("https://alice@telechargement.example:8443/a?b#c"),
            "telechargement.example"
        );
        assert_eq!(hote("telechargement.example:8080"), "telechargement.example");
        assert_eq!(hote("http://[2001:db8::1]:80/x"), "2001:db8::1");
        assert_eq!(hote("nu.example"), "nu.example");
        let ind = indicateurs_inventes();
        // Les plateformes ne sont jamais gardées, ni comme serveur ni comme site.
        for p in ["github.com", "firebaseio.com", "s3.amazonaws.com"] {
            assert_eq!(ind.nom(p), None, "{p}");
        }
        assert_eq!(ind.nom("autre.firebaseio.com"), None);
        for p in [
            "waws-prod-xyz-1.sip.azurewebsites.windows.net",
            "waws-prod-xyz-1-ab12.eastus.cloudapp.azure.com",
            "apprtc.appspot.com",
        ] {
            assert_eq!(ind.nom(p), None, "{p}");
        }
        assert_eq!(ind.nom("projet-123.firebaseio.com"), Some(("Cerberus", Genre::Serveur)));
        // Un hôte de distribution sous forme d'adresse : site, pas serveur.
        assert_eq!(ind.ip("203.0.113.9".parse().unwrap()), Some(("EspionUn", Genre::Site)));
        assert_eq!(ind.nom("telechargement.example"), Some(("EspionUn", Genre::Site)));
        assert_eq!(ind.nom("example.org"), Some(("EspionUn", Genre::Serveur)));
    }

    #[test]
    fn correspondances() {
        let ind = indicateurs_inventes();
        assert_eq!(ind.nom("x.c2.example.com"), Some(("EspionUn", Genre::Serveur)));
        assert_eq!(ind.nom("C2.Example.Com."), Some(("EspionUn", Genre::Serveur)));
        assert_eq!(ind.nom("c2.example.com.evil.example"), None);
        assert_eq!(ind.nom("example.com"), None);
        assert_eq!(ind.nom("www.vendeur.example"), Some(("EspionUn", Genre::Site)));
        assert_eq!(ind.nom("tableau.example"), Some(("EspionUn", Genre::Site)));
        assert_eq!(ind.nom("api.vendeur.example"), None);
        assert_eq!(
            ind.ip("::ffff:203.0.113.7".parse().unwrap()),
            Some(("EspionUn", Genre::Serveur))
        );
        assert_eq!(ind.ip("203.0.113.8".parse().unwrap()), None);
        // Produits : égalité du nom normalisé seulement.
        assert_eq!(ind.produit("Espion Un"), Some("EspionUn"));
        assert_eq!(ind.produit("espion-un.exe"), Some("EspionUn"));
        assert_eq!(ind.produit("EspionPro.app"), Some("EspionUn"));
        assert_eq!(ind.produit("EspionUnPlus"), None);
        assert_eq!(ind.produit("Mon EspionUn"), None);
        // Les noms exclus, et tous ceux d'une entrée exclue, jamais.
        assert_eq!(ind.produit("Observer"), None);
        assert_eq!(ind.produit("System Framework"), None);
        assert_eq!(ind.produit("Cerberus"), None);
        // « Kurulum » (« installation » en turc) et « Scream » (pilote audio libre) : des noms ordinaires.
        for nom in ["Kurulum.exe", "Scream", "scream.exe"] {
            assert_eq!(ind.produit(nom), None, "{nom}");
        }
        // Les domaines des entrées écartées, et leurs sous-domaines : rien.
        for nom in [
            "traccar.org",
            "demo.traccar.org",
            "www.bark.us",
            "bark.us",
            "mycloud.wisemo.com",
            "www.wisemo.com",
            "api.findmykids.org",
            "findmykids.org",
        ] {
            assert_eq!(ind.nom(nom), None, "{nom}");
        }
        // Les adresses de Cloudflare ne désignent aucun serveur ; une adresse ordinaire, si.
        for ip in ["104.26.14.56", "172.67.73.2", "2606:4700::6810:e38"] {
            assert_eq!(ind.ip(ip.parse().unwrap()), None, "{ip}");
        }
        assert_eq!(
            ind.ip("203.0.113.7".parse().unwrap()),
            Some(("EspionUn", Genre::Serveur))
        );
    }

    /// Le vrai fichier d'Échap, quand `VANGUARD_ESSAI_ECHAP` donne le chemin d'une copie (téléchargée à la main :
    /// les tests ne vont pas sur Internet). Sans elle, rien à vérifier ici.
    #[test]
    fn vrai_fichier_d_echap() {
        let Some(chemin) = std::env::var_os("VANGUARD_ESSAI_ECHAP") else {
            return crate::essais::saute("VANGUARD_ESSAI_ECHAP non donné");
        };
        let texte = std::fs::read_to_string(chemin).unwrap();
        let l = lire_yaml(&texte).unwrap();
        assert_eq!(l.ignorees, 0);
        assert!(l.entrees.len() >= 140, "{}", l.entrees.len());
        let ind = indicateurs_de(&l.entrees).unwrap();
        assert!(ind.serveurs.len() >= 900, "{}", ind.serveurs.len());
        // 57 le 23 oct. 2026, les adresses de Cloudflare retirées.
        assert!(ind.ips.len() >= 50, "{}", ind.ips.len());
        assert!(ind.sites.len() >= 600, "{}", ind.sites.len());
        // Les pièges relevés le 22 oct. 2026 : jamais un produit reconnu par un mot courant ou un alias trompeur.
        for nom in [
            "Observer",
            "Dash",
            "System Framework",
            "Screen Time",
            "Traccar",
            "WiseMo",
            "Kurulum.exe",
            "Scream",
            "scream.exe",
        ] {
            assert_eq!(ind.produit(nom), None, "{nom}");
        }
        for nom in [
            "traccar.org",
            "demo.traccar.org",
            "mycloud.wisemo.com",
            "api.findmykids.org",
            "www.bark.us",
        ] {
            assert_eq!(ind.nom(nom), None, "{nom}");
        }
        assert!(!ind.serveurs.contains_key("traccar.org"));
        for ip in ["104.26.14.56", "172.67.73.2"] {
            assert_eq!(ind.ip(ip.parse().unwrap()), None, "{ip}");
        }
        assert_eq!(ind.produit("pcTattletale"), Some("pcTattletale"));
        assert_eq!(ind.nom("github.com"), None);
    }
}
