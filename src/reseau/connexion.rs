//! Test de connexion pour le jeu : latence (ping), gigue, pertes vers la box et vers Internet, débit, et
//! bufferbloat (le lag qui arrive dès que quelqu'un télécharge ou envoie un fichier sur le réseau).
//! La latence se mesure par le temps d'établissement d'une connexion TCP : sans droits admin, sur tout système.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::risk::Niveau;
use crate::ui::*;

mod resultat;

/// Serveur de référence sur Internet (Cloudflare, présent dans presque toutes les villes).
const INTERNET: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
const TELECHARGEMENT: &str = "https://speed.cloudflare.com/__down?bytes=25000000";
const ENVOI: &str = "https://speed.cloudflare.com/__up";
/// Volume maximal d'un test de débit, dans chaque sens.
const PLAFOND: u64 = 500_000_000;

/// Une série de mesures : temps en millisecondes, `None` pour un paquet perdu (pas de réponse en 1 s).
struct Serie(Vec<Option<f64>>);

impl Serie {
    fn recus(&self) -> Vec<f64> {
        self.0.iter().flatten().copied().collect()
    }

    fn mediane(&self) -> Option<f64> {
        let mut t = self.recus();
        if t.is_empty() {
            return None;
        }
        t.sort_by(f64::total_cmp);
        Some(t[t.len() / 2])
    }

    /// Gigue : écart moyen entre deux mesures successives.
    fn gigue(&self) -> f64 {
        let t = self.recus();
        if t.len() < 2 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let n = (t.len() - 1) as f64;
        t.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / n
    }

    fn pertes(&self) -> f64 {
        if self.0.is_empty() {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let p = self.0.iter().filter(|m| m.is_none()).count() as f64 * 100.0 / self.0.len() as f64;
        p
    }
}

/// Temps d'établissement d'une connexion TCP. Un refus (« port fermé ») répond aussi vite qu'une acceptation :
/// il compte comme une réponse.
async fn sonder(cible: SocketAddr) -> Option<f64> {
    let debut = Instant::now();
    match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(cible)).await {
        Ok(Ok(_)) => Some(debut.elapsed().as_secs_f64() * 1000.0),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(debut.elapsed().as_secs_f64() * 1000.0),
        _ => None,
    }
}

async fn serie(cible: SocketAddr, nombre: usize, arret: Option<&AtomicBool>) -> Serie {
    let mut mesures = Vec::new();
    for _ in 0..nombre {
        if arret.is_some_and(|a| a.load(Ordering::Relaxed)) {
            break;
        }
        let debut = Instant::now();
        mesures.push(sonder(cible).await);
        tokio::time::sleep(Duration::from_millis(200).saturating_sub(debut.elapsed())).await;
    }
    Serie(mesures)
}

/// Port de la box qui répond (même par un refus) : web, HTTPS ou DNS.
async fn port_de_la_box(ip: Ipv4Addr) -> Option<SocketAddr> {
    for port in [80, 443, 53] {
        let cible = SocketAddr::new(IpAddr::V4(ip), port);
        if sonder(cible).await.is_some() {
            return Some(cible);
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq)]
enum Sens {
    Reception,
    Envoi,
}

/// Ce qu'un envoi porte : assez pour que la mesure ne soit pas que des débuts de connexion, assez peu pour qu'un envoi
/// en cours à la fin des 8 s ne compte pas pour rien.
const MORCEAU_ENVOYE: usize = 2_000_000;

/// Charge la connexion dans un sens pendant `duree` (4 transferts à la fois, 500 Mo au plus) et rend le débit en
/// Mbit/s. La réception se compte au fil de l'eau ; l'envoi, par morceaux reçus par le serveur. `None` : aucun
/// transfert n'a abouti (pas d'Internet).
fn charger(sens: Sens, duree: Duration, arret: &Arc<AtomicBool>) -> Option<f64> {
    let octets = Arc::new(AtomicU64::new(0));
    let debut = Instant::now();
    let fin = debut + duree;
    let travailleurs: Vec<_> = (0..4)
        .map(|_| {
            let (octets, arret) = (Arc::clone(&octets), Arc::clone(arret));
            std::thread::spawn(move || {
                while !arret.load(Ordering::Relaxed) && Instant::now() < fin && octets.load(Ordering::Relaxed) < PLAFOND
                {
                    let abouti = match sens {
                        Sens::Reception => crate::http::recevoir_en_comptant(TELECHARGEMENT, fin, &octets, &arret),
                        Sens::Envoi => {
                            let demande = crate::http::Demande {
                                corps: Some(vec![0u8; MORCEAU_ENVOYE]),
                                ..crate::http::Demande::get(ENVOI, fin.saturating_duration_since(Instant::now()))
                            };
                            let recu = crate::http::envoyer(demande).is_some_and(|r| r.code == 200);
                            if recu {
                                octets.fetch_add(MORCEAU_ENVOYE as u64, Ordering::Relaxed);
                            }
                            recu
                        }
                    };
                    if !abouti {
                        break;
                    }
                }
            })
        })
        .collect();
    for t in travailleurs {
        let _ = t.join();
    }
    arret.store(true, Ordering::Relaxed);
    let total = octets.load(Ordering::Relaxed);
    #[allow(clippy::cast_precision_loss)]
    let mbits = total as f64 * 8.0 / debut.elapsed().as_secs_f64() / 1_000_000.0;
    (total > 0).then_some(mbits)
}

/// Latence pendant que la connexion est chargée dans un sens, et débit obtenu.
async fn sous_charge(sens: Sens) -> (Serie, Option<f64>) {
    let arret = Arc::new(AtomicBool::new(false));
    let charge = {
        let arret = Arc::clone(&arret);
        tokio::task::spawn_blocking(move || charger(sens, Duration::from_secs(8), &arret))
    };
    // Une seconde pour que les transferts prennent leur vitesse, puis des mesures jusqu'à la fin.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mesures = serie(INTERNET, 35, Some(&arret)).await;
    arret.store(true, Ordering::Relaxed);
    (mesures, charge.await.ok().flatten())
}

/// Au repos : le routeur (le port qui répond, s'il y en a un) et Internet.
struct Repos {
    boite: Option<SocketAddr>,
    serie_box: Option<Serie>,
    internet: Serie,
}

async fn mesurer_repos() -> Repos {
    let boite = match crate::reseau::scan::passerelle() {
        Some(ip) => port_de_la_box(ip).await,
        None => None,
    };
    let serie_box = match boite {
        Some(cible) => Some(serie(cible, 20, None).await),
        None => None,
    };
    let internet = serie(INTERNET, 20, None).await;
    Repos {
        boite,
        serie_box,
        internet,
    }
}

/// Sous charge : la latence pendant un téléchargement puis pendant un envoi, et les débits obtenus.
struct Charge {
    en_reception: Serie,
    debit_bas: Option<f64>,
    en_envoi: Serie,
    debit_haut: Option<f64>,
}

async fn mesurer_charge() -> Charge {
    let (en_reception, debit_bas) = sous_charge(Sens::Reception).await;
    let (en_envoi, debit_haut) = sous_charge(Sens::Envoi).await;
    Charge {
        en_reception,
        debit_bas,
        en_envoi,
        debit_haut,
    }
}

impl Charge {
    /// La hausse de latence sous charge (bufferbloat) par rapport à la latence au repos ; `None` : aucune mesure
    /// sous charge n'a abouti.
    fn hausse(&self, repos: f64) -> Option<f64> {
        [self.en_reception.mediane(), self.en_envoi.mediane()]
            .into_iter()
            .flatten()
            .map(|m| (m - repos).max(0.0))
            .reduce(f64::max)
    }
}

/// Ce qu'a relevé un test : ce que l'écran montre et que `--json` juge, le même pour les deux.
struct Releve {
    repos: Repos,
    /// `None` : Internet n'a pas répondu au repos, le test s'est arrêté là.
    charge: Option<Charge>,
    /// Les habitudes de ce réseau, d'avant ce test.
    habituel: Option<Habitudes>,
}

/// Le test entier, sans rien afficher (`--json`) : les mêmes mesures que l'écran, dans le même ordre, et le test
/// noté dans l'historique comme à l'écran.
async fn relever() -> Releve {
    let repos = mesurer_repos().await;
    let Some(repos_ms) = repos.internet.mediane() else {
        return Releve {
            repos,
            charge: None,
            habituel: None,
        };
    };
    let charge = mesurer_charge().await;
    let habituel = noter(repos_ms, &repos.internet, &charge);
    Releve {
        repos,
        charge: Some(charge),
        habituel,
    }
}

/// Les habitudes du réseau où l'on est (d'avant ce test), puis ce test gardé dans l'historique.
fn noter(repos_ms: f64, internet: &Serie, charge: &Charge) -> Option<Habitudes> {
    let reseau = reseau_actuel();
    let habituel = habitudes(&historique(), reseau.as_deref());
    enregistrer(Resultat {
        date: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        internet_ms: repos_ms,
        gigue_ms: internet.gigue(),
        pertes: internet.pertes(),
        descendant: charge.debit_bas,
        montant: charge.debit_haut,
        hausse_ms: charge.hausse(repos_ms),
        reseau,
    });
    habituel
}

/// Résultat d'un test, gardé sur cet ordinateur pour le rapport HTML.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Resultat {
    /// « AAAA-MM-JJ HH:MM ».
    pub date: String,
    pub internet_ms: f64,
    pub gigue_ms: f64,
    pub pertes: f64,
    pub descendant: Option<f64>,
    pub montant: Option<f64>,
    /// Hausse de latence sous charge (bufferbloat), en ms.
    pub hausse_ms: Option<f64>,
    /// Le réseau du test : adresse MAC de la box. Un portable fait des tests à la maison, au café, chez un ami : on ne
    /// compare qu'à ceux du même réseau. Absent des tests d'avant la 0.52 : ils ne servent plus de référence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reseau: Option<String>,
}

/// Le réseau où l'on est : adresse MAC de la box (la table ARP la connaît, le test vient de la joindre).
fn reseau_actuel() -> Option<String> {
    let box_ = crate::reseau::scan::passerelle()?;
    crate::reseau::scan::table_arp().get(&box_).cloned()
}

/// Habitudes du réseau où l'on est (pour « Ce que Vanguard a appris »).
pub fn habitudes_ici() -> Option<Habitudes> {
    habitudes(&historique(), reseau_actuel().as_deref())
}

/// Nombre de tests gardés.
const GARDES: usize = 50;

fn fichier() -> std::path::PathBuf {
    crate::socle::dossier_local().join("connexion.json")
}

/// Tests précédents, du plus ancien au plus récent.
pub fn historique() -> Vec<Resultat> {
    crate::socle::lire_texte_ordinaire(&fichier(), 16 << 20)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn enregistrer(r: Resultat) {
    let mut tous = historique();
    tous.push(r);
    let surplus = tous.len().saturating_sub(GARDES);
    tous.drain(..surplus);
    if let Ok(texte) = serde_json::to_string(&tous) {
        let _ = std::fs::create_dir_all(crate::socle::dossier_local());
        let _ = std::fs::write(fichier(), texte);
    }
}

/// Ce qui est habituel ici : médianes des derniers tests (au moins 3), pour comparer le test du jour.
#[derive(Debug, PartialEq)]
pub struct Habitudes {
    pub tests: usize,
    pub ping_ms: f64,
    pub descendant: Option<f64>,
    pub montant: Option<f64>,
}

fn mediane(mut valeurs: Vec<f64>) -> Option<f64> {
    valeurs.sort_by(f64::total_cmp);
    valeurs.get(valeurs.len() / 2).copied()
}

/// Habitudes d'après les 10 derniers tests, s'il y en a au moins 3 (un seul test peut tomber un mauvais soir).
pub fn habitudes(precedents: &[Resultat], reseau: Option<&str>) -> Option<Habitudes> {
    let reseau = reseau?;
    let memes: Vec<&Resultat> = precedents
        .iter()
        .filter(|r| r.reseau.as_deref() == Some(reseau))
        .collect();
    let derniers = &memes[memes.len().saturating_sub(10)..];
    if derniers.len() < 3 {
        return None;
    }
    Some(Habitudes {
        tests: derniers.len(),
        ping_ms: mediane(derniers.iter().map(|r| r.internet_ms).collect())?,
        descendant: mediane(derniers.iter().filter_map(|r| r.descendant).collect()),
        montant: mediane(derniers.iter().filter_map(|r| r.montant).collect()),
    })
}

/// Ping nettement plus haut que d'habitude : de moitié, et d'au moins 10 ms (5 ms de plus sur 8 ms, c'est rien).
fn ping_degrade(h: &Habitudes, ping: f64) -> bool {
    ping > h.ping_ms * 1.5 && ping - h.ping_ms >= 10.0
}

/// Débit nettement plus bas que d'habitude : sous 70 %.
fn debit_degrade(habituel: Option<f64>, mesure: Option<f64>) -> bool {
    matches!((habituel, mesure), (Some(h), Some(m)) if m < h * 0.7)
}

/// Note du bufferbloat d'après la hausse de latence sous charge (barème de Waveform).
pub fn note_bufferbloat(hausse: f64) -> (&'static str, Niveau) {
    match hausse {
        h if h <= 5.0 => ("A+", Niveau::Info),
        h if h <= 30.0 => ("A", Niveau::Info),
        h if h <= 60.0 => ("B", Niveau::Moyen),
        h if h <= 200.0 => ("C", Niveau::Eleve),
        h if h <= 400.0 => ("D", Niveau::Critique),
        _ => ("F", Niveau::Critique),
    }
}

/// Couleur d'une latence pour le jeu : vert sous 30 ms, jaune sous 60, orange sous 100, rouge au-delà.
fn couleur_ping(ms: f64) -> &'static str {
    match ms {
        m if m < 30.0 => VERT,
        m if m < 60.0 => couleur(Niveau::Moyen),
        m if m < 100.0 => couleur(Niveau::Eleve),
        _ => couleur(Niveau::Critique),
    }
}

fn couleur_gigue(ms: f64) -> &'static str {
    match ms {
        m if m < 5.0 => VERT,
        m if m < 10.0 => couleur(Niveau::Moyen),
        _ => couleur(Niveau::Eleve),
    }
}

fn couleur_pertes(p: f64) -> &'static str {
    match p {
        p if p <= 0.0 => VERT,
        p if p <= 1.0 => couleur(Niveau::Moyen),
        _ => couleur(Niveau::Critique),
    }
}

/// Une mesure : nom, latence colorée, gigue et pertes.
fn ligne(nom: &str, s: &Serie) {
    let nom = ajuster(nom, 27);
    match s.mediane() {
        Some(m) => trp!(
            "  {nom} {}{m:>5.0} ms{RESET}   {DISCRET}gigue{RESET} {}{:>4.1} ms{RESET}   {DISCRET}pertes{RESET} {}{:>3.0} %{RESET}",
            "  {nom} {}{m:>5.0} ms{RESET}   {DISCRET}jitter{RESET} {}{:>4.1} ms{RESET}   {DISCRET}loss{RESET} {}{:>3.0}%{RESET}",
            couleur_ping(m),
            couleur_gigue(s.gigue()),
            s.gigue(),
            couleur_pertes(s.pertes()),
            s.pertes()
        ),
        None => trp!(
            "  {nom} {}pas de réponse{RESET}",
            "  {nom} {}no response{RESET}",
            couleur(Niveau::Critique)
        ),
    }
}

/// Barre de débit sur une échelle logarithmique : 1 Mbit/s = vide, 1 Gbit/s = pleine.
fn barre_debit(mbits: f64) -> String {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let pleines = ((mbits.max(1.0).log10() / 3.0 * 10.0).round() as usize).min(10);
    let c = match mbits {
        d if d >= 50.0 => VERT,
        d if d >= 15.0 => couleur(Niveau::Moyen),
        _ => couleur(Niveau::Eleve),
    };
    format!("{c}{}{DISCRET}{}{RESET}", "▰".repeat(pleines), "▱".repeat(10 - pleines))
}

/// Une ligne du verdict : coche ou croix, critère, valeur, explication.
fn verdict(bon: bool, critere: &str, valeur: &str, explication: &str) {
    let marque = if bon {
        format!("{VERT}✔{RESET}")
    } else {
        format!("{}✖{RESET}", couleur(Niveau::Eleve))
    };
    println!(
        "  {marque} {GRAS}{}{RESET}{} {DISCRET}{explication}{RESET}",
        ajuster(critere, 12),
        ajuster(valeur, 14)
    );
}

/// La liaison avec le routeur est-elle instable (gigue, latence ou pertes) ? `None` : pas mesurable. Une box qui
/// répond plus lentement qu'Internet ne l'est pas (routeur virtuel d'une VM, page web de la box lente).
fn liaison_instable(box_: Option<&Serie>, internet: &Serie) -> Option<bool> {
    let b = box_?;
    let (m, i) = b.mediane().zip(internet.mediane())?;
    (m < i).then(|| b.gigue() > 5.0 || m > 5.0 || b.pertes() > 0.0)
}

/// La connexion est-elle nettement moins bonne que d'habitude (ping ou débit) ?
fn moins_bonne_que_d_habitude(h: &Habitudes, repos: f64, charge: &Charge) -> bool {
    ping_degrade(h, repos)
        || debit_degrade(h.descendant, charge.debit_bas)
        || debit_degrade(h.montant, charge.debit_haut)
}

/// Conseils pour le jeu, du plus important au moins important.
fn conseils(box_: Option<&Serie>, internet: &Serie, hausse: Option<f64>) -> Vec<String> {
    let mut c = Vec::new();
    if internet.pertes() > 1.0 {
        c.push(tr!(
            "Des paquets se perdent : en jeu, ça donne des saccades et des « téléportations ». Redémarrez le routeur ; si ça reste, appelez votre fournisseur.",
            "Packets are being lost: in game, that means stutter and “teleporting”. Restart the router; if it persists, call your provider."
        ).to_string());
    }
    if liaison_instable(box_, internet) == Some(true) {
        c.push(
            tr!(
                "La liaison avec le routeur est instable (souvent le Wi-Fi) : un câble Ethernet règle presque toujours ça.",
                "The link to the router is unstable (often Wi-Fi): an Ethernet cable almost always fixes it."
            )
            .to_string(),
        );
    }
    if let Some(h) = hausse
        && h > 30.0
    {
        c.push(trf!(
            "Le ping grimpe de {h:.0} ms dès que la connexion est occupée : activez la QoS « SQM » / « Smart Queue » de votre routeur, ou limitez les téléchargements pendant les parties.",
            "Ping rises by {h:.0} ms as soon as the connection is busy: turn on “SQM” / “Smart Queue” QoS on your router, or limit downloads while playing."
        ));
    }
    if internet.gigue() > 10.0 {
        c.push(
            tr!(
                "Le ping varie beaucoup (gigue) : fermez les téléchargements et le streaming en arrière-plan.",
                "Ping varies a lot (jitter): close background downloads and streaming."
            )
            .to_string(),
        );
    }
    c
}

pub async fn tester() {
    println!();
    cadre(
        &format!(
            "{ACCENT}{}{RESET}",
            tr!("CONNEXION POUR LE JEU", "CONNECTION FOR GAMING")
        ),
        &format!(
            "{GRIS}{}{RESET}",
            tr!("environ 25 s · Cloudflare", "about 25 s · Cloudflare")
        ),
    );
    trp!(
        "  {DISCRET}Le test de débit télécharge et envoie quelques centaines de Mo au plus.{RESET}",
        "  {DISCRET}The speed test downloads and uploads a few hundred MB at most.{RESET}"
    );
    section(tr!("AU REPOS", "AT REST"));
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let mesures_repos = mesurer_repos().await;
    if let (Some(cible), Some(s)) = (mesures_repos.boite, &mesures_repos.serie_box) {
        ligne(&trf!("Routeur ({})", "Router ({})", cible.ip()), s);
    }
    ligne("Internet (Cloudflare)", &mesures_repos.internet);
    let Some(repos) = mesures_repos.internet.mediane() else {
        trp!(
            "\n  {}✖ Internet ne répond pas : test arrêté.{RESET}",
            "\n  {}✖ Internet does not answer: test stopped.{RESET}",
            couleur(Niveau::Critique)
        );
        let releve = Releve {
            repos: mesures_repos,
            charge: None,
            habituel: None,
        };
        crate::modele::resultat::verser(&resultat::resultat(Some(&releve), debut));
        return;
    };
    section(tr!("SOUS CHARGE", "UNDER LOAD"));
    trp!(
        "  {DISCRET}Téléchargement puis envoi, 8 secondes chacun…{RESET}",
        "  {DISCRET}Download then upload, 8 seconds each…{RESET}"
    );
    let charge = mesurer_charge().await;
    let Charge {
        en_reception,
        debit_bas,
        en_envoi,
        debit_haut,
    } = &charge;
    let (debit_bas, debit_haut) = (*debit_bas, *debit_haut);
    ligne(tr!("Pendant un téléchargement", "During a download"), en_reception);
    ligne(tr!("Pendant un envoi", "During an upload"), en_envoi);

    section(tr!("DÉBIT", "SPEED"));
    for (nom, d) in [
        (tr!("↓ Réception", "↓ Download"), debit_bas),
        (tr!("↑ Envoi", "↑ Upload"), debit_haut),
    ] {
        match d {
            Some(d) => println!(
                "  {} {GRAS}{d:>5.0}{RESET} Mbit/s   {}",
                ajuster(nom, 14),
                barre_debit(d)
            ),
            None => trp!("  {} ?", "  {} ?", ajuster(nom, 14)),
        }
    }
    let hausse = charge.hausse(repos);
    let internet = &mesures_repos.internet;
    // Apprendre la normale : le test du jour comparé aux habitudes de cette connexion (puis gardé avec elles).
    let habituel = noter(repos, internet, &charge);
    if let Some(h) = &habituel {
        section(tr!("PAR RAPPORT À D'HABITUDE", "COMPARED WITH USUAL"));
        let moins_bon = couleur(Niveau::Moyen);
        let ping = if ping_degrade(h, repos) { moins_bon } else { "" };
        trp!(
            "  {} {ping}{repos:>5.0}{RESET} ms       d'habitude {:.0} ms",
            "  {} {ping}{repos:>5.0}{RESET} ms       usually {:.0} ms",
            ajuster("Ping", 14),
            h.ping_ms
        );
        for (nom, habituel, mesure) in [
            (tr!("↓ Réception", "↓ Download"), h.descendant, debit_bas),
            (tr!("↑ Envoi", "↑ Upload"), h.montant, debit_haut),
        ] {
            if let (Some(hab), Some(m)) = (habituel, mesure) {
                let teinte = if debit_degrade(habituel, mesure) { moins_bon } else { "" };
                trp!(
                    "  {} {teinte}{m:>5.0}{RESET} Mbit/s   d'habitude {hab:.0}",
                    "  {} {teinte}{m:>5.0}{RESET} Mbit/s   usually {hab:.0}",
                    ajuster(nom, 14)
                );
            }
        }
        trp!(
            "  {GRIS}d'après vos {} derniers tests{RESET}",
            "  {GRIS}from your last {} tests{RESET}",
            h.tests
        );
    }
    section(tr!("VERDICT POUR LE JEU", "VERDICT FOR GAMING"));
    let (gigue, pertes) = (internet.gigue(), internet.pertes());
    verdict(
        repos < 60.0,
        "Ping",
        &format!("{repos:.0} ms"),
        match repos {
            r if r < 30.0 => tr!("excellent (moins de 30 ms)", "excellent (under 30 ms)"),
            r if r < 60.0 => tr!("bon (moins de 60 ms)", "good (under 60 ms)"),
            _ => tr!("élevé : retard visible en jeu", "high: visible lag in game"),
        },
    );
    verdict(
        gigue < 10.0,
        tr!("Gigue", "Jitter"),
        &format!("{} ms", crate::langue::decimal(gigue, 1)),
        if gigue < 10.0 {
            tr!("stable", "stable")
        } else {
            tr!("instable : saccades", "unstable: stutter")
        },
    );
    verdict(
        pertes <= 1.0,
        tr!("Pertes", "Loss"),
        &format!("{pertes:.0} %"),
        if pertes == 0.0 {
            tr!("aucune", "none")
        } else {
            tr!("paquets perdus", "packets lost")
        },
    );
    if let Some(h) = hausse {
        let (note, niveau) = note_bufferbloat(h);
        verdict(
            h <= 30.0,
            "Bufferbloat",
            &format!("{}{note}{RESET} (+{h:.0} ms)", couleur(niveau)),
            if h <= 30.0 {
                tr!(
                    "le ping tient quand la connexion est occupée",
                    "ping holds when the connection is busy"
                )
            } else {
                tr!(
                    "le ping monte quand quelqu'un télécharge",
                    "ping rises when someone downloads"
                )
            },
        );
    }
    let mut conseils = conseils(mesures_repos.serie_box.as_ref(), internet, hausse);
    if let Some(h) = &habituel
        && moins_bonne_que_d_habitude(h, repos, &charge)
    {
        conseils.push(
            tr!(
                "Votre connexion est nettement moins bonne que d'habitude : quelqu'un envoie ou télécharge peut-être en ce moment ; sinon, redémarrez le routeur, et si ça dure, appelez votre fournisseur.",
                "Your connection is clearly worse than usual: someone may be uploading or downloading right now; otherwise, restart the router, and if it lasts, call your provider."
            )
            .to_string(),
        );
    }
    println!();
    if conseils.is_empty() {
        trp!(
            "  {VERT}✔ Connexion excellente pour le jeu.{RESET}",
            "  {VERT}✔ Excellent connection for gaming.{RESET}"
        );
    }
    for c in conseils {
        for (i, l) in envelopper(&c, LARGEUR - 6).iter().enumerate() {
            println!("  {} {l}", if i == 0 { ampoule() } else { "  " });
        }
    }
    let releve = Releve {
        repos: mesures_repos,
        charge: Some(charge),
        habituel,
    };
    crate::modele::resultat::verser(&resultat::resultat(Some(&releve), debut));
}

/// `vanguard test-connexion --json` : les mêmes mesures que l'écran, sans rien demander ni afficher d'autre que le
/// JSON, jugées en résultat et versées comme à l'écran. Hors ligne (VANGUARD_HORS_LIGNE, Paramètres), rien ne part :
/// tout est dit non vérifié.
pub async fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let releve = if crate::parametres::hors_ligne() {
        None
    } else {
        Some(relever().await)
    };
    let r = resultat::resultat(releve.as_ref(), debut);
    crate::modele::resultat::verser(&r);
    println!("{}", crate::modele::resultat::json(&r));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statistiques() {
        let s = Serie(vec![Some(10.0), Some(12.0), None, Some(11.0), Some(30.0)]);
        assert_eq!(s.mediane(), Some(12.0));
        assert!((s.pertes() - 20.0).abs() < 1e-9);
        // Écarts successifs : 2, 1, 19 → 22 / 3.
        assert!((s.gigue() - 22.0 / 3.0).abs() < 1e-9);
        assert_eq!(Serie(vec![None]).mediane(), None);
        assert_eq!(note_bufferbloat(3.0).0, "A+");
        assert_eq!(note_bufferbloat(45.0).0, "B");
        assert_eq!(note_bufferbloat(900.0).0, "F");
    }

    #[test]
    fn habitudes_de_la_connexion() {
        let sur = |reseau: Option<&str>, ping: f64, bas: f64| Resultat {
            date: String::new(),
            internet_ms: ping,
            gigue_ms: 1.0,
            pertes: 0.0,
            descendant: Some(bas),
            montant: Some(30.0),
            hausse_ms: None,
            reseau: reseau.map(str::to_string),
        };
        let test = |ping: f64, bas: f64| sur(Some("box"), ping, bas);
        let ici = Some("box");
        assert_eq!(habitudes(&[test(18.0, 98.0), test(20.0, 100.0)], ici), None);
        // Les tests d'un autre réseau (le café) ou d'avant la 0.52 (sans réseau) ne comptent pas.
        let autres = [
            sur(Some("cafe"), 90.0, 5.0),
            sur(None, 90.0, 5.0),
            test(18.0, 98.0),
            test(20.0, 100.0),
        ];
        assert_eq!(habitudes(&autres, ici), None);
        assert_eq!(
            habitudes(&[test(18.0, 98.0), test(18.0, 98.0), test(18.0, 98.0)], None),
            None
        );
        let h = habitudes(&[test(18.0, 98.0), test(20.0, 100.0), test(60.0, 40.0)], ici).unwrap();
        // Médianes : un mauvais soir ne fait pas l'habitude.
        assert_eq!((h.ping_ms, h.descendant), (20.0, Some(98.0)));
        assert!(ping_degrade(&h, 61.0) && !ping_degrade(&h, 25.0));
        // Sur une connexion très rapide, quelques ms de plus ne comptent pas.
        let rapide = Habitudes {
            tests: 3,
            ping_ms: 4.0,
            descendant: None,
            montant: None,
        };
        assert!(!ping_degrade(&rapide, 9.0));
        assert!(debit_degrade(Some(98.0), Some(66.0)) && !debit_degrade(Some(98.0), Some(80.0)));
        assert!(!debit_degrade(None, Some(10.0)));
    }

    #[test]
    fn conseils_pour_le_jeu() {
        let stable = Serie(vec![Some(1.0); 10]);
        let internet = Serie(vec![Some(12.0); 10]);
        assert_eq!(conseils(Some(&stable), &internet, Some(3.0)), Vec::<String>::new());
        let wifi = Serie(vec![Some(2.0), Some(15.0), Some(3.0), Some(40.0)]);
        let perdu = Serie(vec![Some(30.0), None, Some(30.0)]);
        assert_eq!(conseils(Some(&wifi), &perdu, Some(120.0)).len(), 3);
        // Box plus lente qu'Internet (routeur virtuel d'une VM) : pas de conseil de câble.
        let virtuelle = Serie(vec![Some(20.0), Some(35.0), Some(8.0)]);
        assert_eq!(
            conseils(Some(&virtuelle), &Serie(vec![Some(18.0); 3]), Some(3.0)),
            Vec::<String>::new()
        );
    }
}
