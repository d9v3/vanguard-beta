//! Tableau de bord : une page locale, un seul fichier sans aucune ressource externe ni script, qui montre l'état de la
//! surveillance horaire, le dernier bilan, la protection, les alertes (par gravité sur 30 jours, puis jour par jour),
//! les appareils apparus sur le réseau, les connexions vers des serveurs de botnets et toutes les fonctions du menu.
//! Rien n'est envoyé : la page est écrite dans le dossier de Vanguard de cet ordinateur.
//!
//! Chaque alerte est notée au moment d'être notifiée, dans le journal commun des événements (`modele::journal`). Une
//! notification disparaît en quelques secondes ; sans ce journal, une alerte de la nuit était perdue. L'ancien journal
//! des alertes (surveillance-alertes.jsonl) n'est plus écrit, mais il est encore lu : une version d'avant, lancée
//! depuis la clé, peut y écrire.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::fmt::Write;
use std::path::{Path, PathBuf};

use chrono::NaiveDateTime;

use crate::rapport::{base64, esc};
use crate::reseau::{self, FicheAppareil, date_fr};
use crate::{tr, trf, trp, trw};

/// Format des dates du journal : trié comme du texte, il l'est aussi dans le temps.
const FORMAT_DATE: &str = "%Y-%m-%d %H:%M:%S";
/// Le journal garde au plus les 500 dernières alertes des 90 derniers jours : quelques centaines de Ko au pire,
/// même si un appareil bavard déclenche une alerte à chaque passe.
const ALERTES_GARDEES: usize = 500;
const JOURS_GARDES: i64 = 90;
/// Un appareil apparu depuis moins de 30 jours est « nouveau » sur le tableau.
const JOURS_NOUVEAUX: i64 = 30;
/// Jours du graphique et de l'anneau des alertes : un mois se lit d'un coup d'œil.
const JOURS_GRAPHIQUE: i64 = 30;
/// Longueurs gardées d'une alerte : un nom d'appareil choisi par n'importe qui ne doit pas gonfler le journal.
const TITRE_MAX: usize = 200;
const TEXTE_MAX: usize = 1000;

/// Ce qui a déclenché une alerte : il donne sa couleur et son étiquette sur le tableau.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Genre {
    Machine,
    Fichiers,
    Telechargement,
    Botnet,
    Passerelle,
    Empoisonneur,
    Appareil,
    Port,
    /// Le Wi-Fi moins protégé qu'au passage d'avant (ouvert, TKIP, WPS apparu) : l'audit du réseau.
    WiFi,
    /// Une menace bloquée par la protection active, ou qu'elle n'a pas pu bloquer (protection/blocage).
    Blocage,
    /// Un programme ou une connexion brève vus par le veilleur (Linux), entre deux passes de la surveillance.
    Veilleur,
    /// Un rançongiciel repéré en direct par le veilleur (rafale de chiffrement, piège touché, copies effacées).
    Rancongiciel,
    /// Une alerte des journaux de Windows (règles `EVT-`, `vanguard journaux-windows`).
    Evenements,
    Autre,
}

/// La famille des alertes des journaux de Windows, telle que le journal des événements la garde.
pub(crate) const FAMILLE_EVENEMENTS: &str = "evenements";

impl Genre {
    const TOUS: [Genre; 14] = [
        Genre::Machine,
        Genre::Fichiers,
        Genre::Telechargement,
        Genre::Botnet,
        Genre::Passerelle,
        Genre::Empoisonneur,
        Genre::Appareil,
        Genre::Port,
        Genre::WiFi,
        Genre::Blocage,
        Genre::Veilleur,
        Genre::Rancongiciel,
        Genre::Evenements,
        Genre::Autre,
    ];

    /// Le nom gardé dans le journal : stable, jamais traduit.
    fn nom(self) -> &'static str {
        match self {
            Genre::Machine => "machine",
            Genre::Fichiers => "fichiers",
            Genre::Telechargement => "telechargement",
            Genre::Botnet => "botnet",
            Genre::Passerelle => "passerelle",
            Genre::Empoisonneur => "empoisonneur",
            Genre::Appareil => "appareil",
            Genre::Port => "port",
            Genre::WiFi => "wifi",
            Genre::Blocage => "blocage",
            Genre::Veilleur => "veilleur",
            Genre::Rancongiciel => "rancongiciel",
            Genre::Evenements => FAMILLE_EVENEMENTS,
            Genre::Autre => "autre",
        }
    }

    /// Un nom inconnu (journal d'une version plus récente) reste montré, sans couleur particulière.
    fn de(nom: &str) -> Genre {
        Genre::TOUS.into_iter().find(|g| g.nom() == nom).unwrap_or(Genre::Autre)
    }

    fn libelle(self) -> &'static str {
        match self {
            Genre::Machine => tr!("MACHINE", "MACHINE"),
            Genre::Fichiers => tr!("FICHIERS", "FILES"),
            Genre::Telechargement => tr!("TÉLÉCHARGEMENT", "DOWNLOAD"),
            Genre::Botnet => tr!("BOTNET", "BOTNET"),
            Genre::Passerelle => tr!("BOX", "ROUTER"),
            Genre::Empoisonneur => tr!("EMPOISONNEUR", "POISONER"),
            Genre::Appareil => tr!("APPAREIL", "DEVICE"),
            Genre::Port => tr!("PORT", "PORT"),
            Genre::WiFi => tr!("WI-FI", "WI-FI"),
            Genre::Blocage => tr!("BLOCAGE", "BLOCKING"),
            Genre::Veilleur => tr!("VEILLEUR", "WATCHER"),
            Genre::Rancongiciel => tr!("RANÇONGICIEL", "RANSOMWARE"),
            Genre::Evenements => tr!("JOURNAUX WINDOWS", "WINDOWS LOGS"),
            Genre::Autre => tr!("AUTRE", "OTHER"),
        }
    }

    /// La classe de couleur du rapport HTML : rouge pour ce qui trahit une attaque en cours.
    fn classe(self) -> &'static str {
        match self {
            Genre::Botnet | Genre::Passerelle | Genre::Empoisonneur | Genre::Blocage | Genre::Rancongiciel => {
                "critique"
            }
            Genre::Appareil | Genre::Port | Genre::Fichiers | Genre::WiFi | Genre::Veilleur | Genre::Evenements => {
                "eleve"
            }
            Genre::Machine | Genre::Telechargement => "moyen",
            Genre::Autre => "info",
        }
    }
}

/// La classe de couleur d'une gravité.
fn classe_de(n: crate::risk::Niveau) -> &'static str {
    match n {
        crate::risk::Niveau::Critique => "critique",
        crate::risk::Niveau::Eleve => "eleve",
        crate::risk::Niveau::Moyen => "moyen",
        crate::risk::Niveau::Info => "info",
    }
}

/// Une alerte notifiée par la surveillance, une ligne JSON du journal.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Alerte {
    /// « AAAA-MM-JJ HH:MM:SS », heure de cet ordinateur.
    pub date: String,
    pub genre: String,
    pub titre: String,
    pub texte: String,
    /// Ce dont parle l'alerte, stable et jamais traduit (« veilleur|… », « blocage|connexion:203.0.113.7 ») : on
    /// peut la déclarer normale (`protection::normales`), et les traces d'incident relient par elle l'alerte, la
    /// preuve et le blocage. Absente des alertes d'avant la 0.86 et de celles qui ne se reconnaissent pas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cle: Option<String>,
    /// La gravité portée par l'événement (une faille KEV est critique) ; absente de l'ancien journal : celle du
    /// genre.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gravite: Option<crate::risk::Niveau>,
}

fn fichier_journal() -> PathBuf {
    crate::socle::dossier_local().join("surveillance-alertes.jsonl")
}

fn fichier_reseau() -> PathBuf {
    crate::socle::dossier_local().join("surveillance-reseau-non-verifie.txt")
}

fn fichier_page() -> PathBuf {
    crate::socle::dossier_local().join("tableau.html")
}

/// Les `max` premiers caractères (jamais au milieu d'un caractère), suivis de « … » s'il y en avait plus.
fn tronquer(texte: &str, max: usize) -> String {
    match texte.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &texte[..i]),
        None => texte.to_string(),
    }
}

/// Ajoute une alerte au journal, au moment où la surveillance la notifie. Un échec d'écriture ne doit pas empêcher
/// la notification : il va au journal des erreurs, en silence.
pub(crate) fn noter_alerte(genre: Genre, titre: &str, texte: &str) {
    noter_alerte_cle(genre, None, titre, texte);
}

/// Comme `noter_alerte`, avec la clé de ce dont parle l'alerte.
pub(crate) fn noter_alerte_cle(genre: Genre, cle: Option<&str>, titre: &str, texte: &str) {
    noter_alerte_liee(genre, cle, None, titre, texte);
}

/// Comme `noter_alerte_cle`, avec l'événement qui l'a causée (le blocage dont elle prévient). Elle va au journal
/// commun des événements (`modele::journal`), en ajout seul et chaîné, et plus à surveillance-alertes.jsonl, qui
/// reste lu : une seule écriture, deux lectures, jamais d'alerte en double. Rend l'identifiant de l'événement.
pub(crate) fn noter_alerte_liee(
    genre: Genre,
    cle: Option<&str>,
    cause: Option<&str>,
    titre: &str,
    texte: &str,
) -> Option<String> {
    use crate::modele::evenement::{Evenement, Source};
    let source = match genre {
        Genre::Veilleur | Genre::Rancongiciel => Source::Veilleur,
        Genre::Blocage => Source::Blocage,
        _ => Source::Surveillance,
    };
    let ev = Evenement::alerte(
        source,
        genre.nom(),
        &tronquer(titre, TITRE_MAX),
        &tronquer(texte, TEXTE_MAX),
    )
    .gravite(gravite(genre, texte))
    .cle(cle)
    .cause(cause);
    crate::modele::journal::noter(ev)
}

/// La gravité d'une alerte, portée par son événement : celle de son genre, sauf une faille du catalogue KEV de la
/// CISA (activement exploitée), critique même si elle arrive par l'alerte de la machine.
fn gravite(genre: Genre, texte: &str) -> crate::risk::Niveau {
    use crate::risk::Niveau;
    if genre == Genre::Machine && texte.contains("KEV") {
        return Niveau::Critique;
    }
    match genre.classe() {
        "critique" => Niveau::Critique,
        "eleve" => Niveau::Eleve,
        "moyen" => Niveau::Moyen,
        _ => Niveau::Info,
    }
}

/// Ajoute une alerte à l'ancien journal (surveillance-alertes.jsonl) : les essais qui en préparent un comme une
/// version d'avant l'écrivait.
#[cfg(test)]
fn ajouter(fichier: &Path, alerte: Alerte, maintenant: NaiveDateTime) -> std::io::Result<()> {
    let mut alertes = lire_journal(fichier);
    alertes.push(alerte);
    let texte: String = borner(alertes, maintenant)
        .iter()
        .filter_map(|a| serde_json::to_string(a).ok())
        .map(|ligne| ligne + "\n")
        .collect();
    crate::socle::ecrire_atomique(fichier, texte)
}

/// `t` moins `jours` jours, écrit dans `format`. Vide hors des dates de chrono, que l'horloge n'atteint pas : une
/// limite vide laisse tout passer, rien n'est retiré.
fn jours_avant(t: NaiveDateTime, jours: i64, format: &str) -> String {
    t.checked_sub_signed(chrono::Duration::days(jours))
        .map(|d| d.format(format).to_string())
        .unwrap_or_default()
}

/// Les alertes de moins de 90 jours, les 500 plus récentes au plus.
fn borner(mut alertes: Vec<Alerte>, maintenant: NaiveDateTime) -> Vec<Alerte> {
    let limite = jours_avant(maintenant, JOURS_GARDES, FORMAT_DATE);
    alertes.retain(|a| a.date >= limite);
    let trop = alertes.len().saturating_sub(ALERTES_GARDEES);
    alertes.drain(..trop);
    alertes
}

/// Le journal tel qu'il est sur le disque. Une ligne illisible ou mal datée (fichier abîmé, retouché à la main) est
/// laissée de côté : le reste du journal sert quand même. Les textes sont rendus inoffensifs pour le terminal comme
/// pour la page, qui les échappe en plus.
fn lire_journal(fichier: &Path) -> Vec<Alerte> {
    // Un simple fichier, borné : un tube à sa place figeait la passe de la surveillance qui y note ses alertes.
    let Ok(texte) = crate::socle::lire_texte_ordinaire(fichier, 64 << 20) else {
        return Vec::new();
    };
    alertes_du_texte(&texte)
}

/// Les alertes d'un journal déjà lu (les traces d'incident le lisent elles-mêmes, sans suivre de lien ni attendre
/// sur un tube), textes rendus inoffensifs.
pub(crate) fn alertes_du_texte(texte: &str) -> Vec<Alerte> {
    texte
        .trim_start_matches('\u{feff}')
        .lines()
        .filter_map(|ligne| serde_json::from_str::<Alerte>(ligne).ok())
        .filter(|a| NaiveDateTime::parse_from_str(&a.date, FORMAT_DATE).is_ok())
        .map(|a| Alerte {
            titre: crate::ui::affichable(&a.titre),
            texte: crate::ui::affichable(&a.texte),
            ..a
        })
        .collect()
}

/// Les alertes du journal des événements, en alertes du tableau, textes rendus inoffensifs. Un journal falsifié
/// donne quand même ses alertes (on ne cache pas une alerte), mais il est dit par `vanguard evenements`, les traces
/// et le bilan (COM-ETA-001, chaîne relue).
pub(crate) fn alertes_des_evenements(evenements: &[crate::modele::evenement::Evenement]) -> Vec<Alerte> {
    crate::modele::journal::alertes(evenements)
        .filter_map(|(e, famille, titre, texte)| {
            Some(Alerte {
                date: e.date_locale()?,
                genre: famille.to_string(),
                titre: crate::ui::affichable(titre),
                texte: crate::ui::affichable(texte),
                cle: e.cle.clone(),
                gravite: e.gravite,
            })
        })
        .collect()
}

/// Les alertes de l'ancien journal et du journal des événements réunies, dans l'ordre du temps : une version d'avant
/// lancée depuis la clé écrit encore l'ancien.
pub(crate) fn reunir(mut anciennes: Vec<Alerte>, nouvelles: Vec<Alerte>) -> Vec<Alerte> {
    anciennes.extend(nouvelles);
    anciennes.sort_by(|a, b| a.date.cmp(&b.date));
    anciennes
}

/// Les alertes des deux journaux, de la plus ancienne à la plus récente, textes rendus inoffensifs : pour le tableau
/// et pour déclarer une alerte normale.
pub(crate) fn alertes() -> Vec<Alerte> {
    let lu = crate::modele::journal::lire();
    reunir(lire_journal(&fichier_journal()), alertes_des_evenements(&lu.evenements))
}

/// Le genre d'une alerte du journal, tel qu'il s'affiche (« VEILLEUR », « BOTNET »).
pub(crate) fn libelle_genre(nom: &str) -> &'static str {
    Genre::de(nom).libelle()
}

/// Le nom stable d'un genre, tel que le journal le garde.
pub(crate) fn nom_genre(g: Genre) -> &'static str {
    g.nom()
}

/// Noté au début de chaque passe de la surveillance : le tableau dit quand elle a tourné pour la dernière fois.
pub(crate) fn noter_passe() {
    // Une mise à jour se lit dans le journal des événements à la première passe qui suit, pas à la prochaine alerte.
    crate::modele::journal::noter_version();
    let maintenant = chrono::Local::now().format(FORMAT_DATE).to_string();
    // Scellée : forgée par un autre programme du compte, elle disait la surveillance passée il y a cinq minutes alors
    // qu'elle était coupée.
    let _ = crate::sceau::ecrire(crate::sceau::SURVEILLANCE_PASSE, maintenant);
}

/// Le scan du réseau de cette passe n'a pas pu se faire (`Some(raison)`), ou il s'est fait (`None`). La passe est
/// notée dès son début : sans cette note, une passe sans réseau passerait sur le tableau pour une passe saine.
pub(crate) fn noter_reseau(non_verifie: Option<&str>) {
    ecrire_reseau(&fichier_reseau(), non_verifie, chrono::Local::now().naive_local());
}

/// La note dans `fichier` : sa date puis sa raison, une ligne chacune ; retirée quand le scan s'est fait.
fn ecrire_reseau(fichier: &Path, non_verifie: Option<&str>, maintenant: NaiveDateTime) {
    match non_verifie {
        Some(raison) => {
            let texte = format!(
                "{}\n{}\n",
                maintenant.format(FORMAT_DATE),
                tronquer(&raison.replace('\n', " "), TEXTE_MAX)
            );
            if let Err(e) = crate::socle::ecrire_atomique(fichier, texte) {
                crate::journal::erreur(crate::compte_rendu::Contexte::ScanReseauNonVerifie, &e.to_string());
            }
        }
        None => {
            let _ = std::fs::remove_file(fichier);
        }
    }
}

/// La note relue : (date, raison) ; une note abîmée ou mal datée est laissée de côté, comme une ligne du journal.
fn lire_reseau(fichier: &Path) -> Option<(String, String)> {
    let texte = crate::socle::lire_texte_ordinaire(fichier, 64 << 10).ok()?;
    let (date, raison) = texte.split_once('\n')?;
    let date = date.trim();
    NaiveDateTime::parse_from_str(date, FORMAT_DATE).ok()?;
    Some((date.to_string(), crate::ui::affichable(raison.trim())))
}

/// La dernière passe : notée par `noter_passe`, sinon (passes d'avant le tableau) la date de l'état de la machine,
/// que chaque passe réécrit. Une note qui ne peut pas être crue (changée, effacée, acceptée telle quelle hors de
/// Vanguard) ne dit aucune passe : jamais une passe récente inventée.
fn derniere_passe() -> Option<String> {
    derniere_passe_lue(crate::sceau::juge(crate::sceau::SURVEILLANCE_PASSE))
}

fn derniere_passe_lue(lu: crate::sceau::Juge) -> Option<String> {
    use crate::sceau::Juge;
    let notee = match lu {
        Juge::Cru(o) => Some(String::from_utf8_lossy(&o).trim().to_string())
            .filter(|t| NaiveDateTime::parse_from_str(t, FORMAT_DATE).is_ok()),
        Juge::Absent => None,
        Juge::Douteux(..) | Juge::Illisible(_) => return None,
    };
    notee.or_else(|| {
        let date = std::fs::metadata(crate::socle::dossier_local().join("surveillance-machine.json"))
            .and_then(|m| m.modified())
            .ok()?;
        Some(
            chrono::DateTime::<chrono::Local>::from(date)
                .format(FORMAT_DATE)
                .to_string(),
        )
    })
}

/// Tout ce que la page montre, réuni d'abord : la page elle-même se teste sur des données inventées.
pub(crate) struct Donnees {
    pub maintenant: NaiveDateTime,
    pub active: bool,
    pub derniere_passe: Option<String>,
    pub alertes: Vec<Alerte>,
    pub appareils: Vec<FicheAppareil>,
    /// Les connexions vers un serveur de commande vues à la dernière passe qui a pu lire les connexions.
    pub botnets_en_cours: Vec<String>,
    /// Quand elles ont été vues (la date du fichier) : la passe suivante ne le réécrit pas si la lecture des
    /// connexions échoue, et une liste d'il y a trois jours n'est plus « encore vue ».
    pub botnets_vus: Option<NaiveDateTime>,
    /// La protection en temps réel coupée, avec son échéance (« jusqu'à 17:30 ») : la minuterie est là, mais aucune
    /// passe ne se fait.
    pub temps_reel_coupe: Option<String>,
    /// Le dernier scan du réseau qui n'a pas pu se faire (date, raison) ; `None` dès qu'un scan s'est fait.
    pub reseau_non_verifie: Option<(String, String)>,
    /// Le dernier bilan de sécurité de l'historique ; aucun : `None`.
    pub bilan: Option<DernierBilan>,
    /// L'état de la chaîne des bilans (« Historique intact : … », « ⚠ Historique modifié… ») ; aucun bilan : `None`.
    pub historique: Option<String>,
    /// Le temps réel des fichiers en une phrase : le veilleur sous Linux, Defender sous Windows.
    pub fichiers: String,
    /// L'état du veilleur (Linux seulement : ailleurs il n'existe pas).
    pub veilleur: Option<String>,
    /// L'état court de la protection active (« protection active », « désactivé »…).
    pub blocage: String,
    /// Les fichiers en quarantaine.
    pub quarantaine: usize,
    /// Les fonctions du menu, rangées comme lui : le menu est dans main.rs, qui les passe.
    pub fonctions: Vec<Rubrique>,
}

/// Le dernier bilan de sécurité, tel que l'historique le garde.
pub(crate) struct DernierBilan {
    /// « AAAA-MM-JJ HH:MM ».
    pub date: String,
    /// La note de la machine sur 100 ; `None` : l'audit n'était pas fiable, rien n'est noté.
    pub machine: Option<u32>,
    pub reseau: Option<u32>,
    /// Les problèmes moyens ou plus graves trouvés.
    pub problemes: usize,
}

/// Une fonction du menu : sa place (« 6.1 »), son titre, sa précision, et la commande qui fait la même chose (aucune :
/// le menu seulement, ou la même que la ligne d'avant).
pub(crate) struct Fonction {
    pub place: String,
    pub titre: String,
    pub precision: String,
    pub commande: Option<String>,
}

/// Une rubrique du menu et ses fonctions, dans l'ordre de l'écran.
pub(crate) struct Rubrique {
    pub titre: String,
    pub resume: String,
    pub fonctions: Vec<Fonction>,
}

/// Au-delà, les connexions vues ne sont plus dites en cours : la surveillance repasse chaque heure.
const BOTNETS_RECENTS_HEURES: i64 = 2;

/// L'état du veilleur, en lisant ses fichiers : rien n'est lancé.
#[cfg(target_os = "linux")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "sous Windows, il n'y a pas de veilleur : `None`"
)]
fn veilleur() -> Option<String> {
    Some(crate::machine::linux::veilleur::precision().to_string())
}

#[cfg(not(target_os = "linux"))]
fn veilleur() -> Option<String> {
    None
}

fn collecter(fonctions: Vec<Rubrique>) -> Donnees {
    let fichier_botnets = crate::protection::sortantes::fichier_botnets();
    // Lu sous son sceau, comme la surveillance qui l'écrit : jamais un tube ou un lien suivi.
    let botnets = match crate::sceau::lire(crate::sceau::BOTNETS) {
        crate::sceau::Lecture::Intact(o)
        | crate::sceau::Lecture::Adopte(o)
        | crate::sceau::Lecture::Falsifie(Some(o)) => String::from_utf8_lossy(&o).into_owned(),
        _ => String::new(),
    };
    let botnets_en_cours = botnets
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(crate::ui::affichable)
        .collect();
    let botnets_vus = std::fs::symlink_metadata(&fichier_botnets)
        .and_then(|m| m.modified())
        .ok()
        .map(|t| chrono::DateTime::<chrono::Local>::from(t).naive_local());
    Donnees {
        maintenant: chrono::Local::now().naive_local(),
        active: reseau::surveillance::active(),
        derniere_passe: derniere_passe(),
        alertes: borner(alertes(), chrono::Local::now().naive_local()),
        appareils: reseau::appareils_connus(),
        botnets_en_cours,
        botnets_vus,
        temps_reel_coupe: crate::protection::temps_reel::coupure().map(|c| crate::protection::temps_reel::echeance(&c)),
        reseau_non_verifie: lire_reseau(&fichier_reseau()),
        bilan: crate::historique::charger().last().map(|b| DernierBilan {
            date: crate::ui::affichable(&b.date),
            machine: b.machine,
            reseau: b.reseau,
            problemes: b.problemes.len(),
        }),
        historique: crate::historique::etat_chaine(),
        fichiers: crate::protection::etat_antivirus::temps_reel(),
        veilleur: veilleur(),
        blocage: crate::protection::blocage::etat_court().to_string(),
        quarantaine: crate::protection::quarantaine::nombre(),
        fonctions,
    }
}

/// « 2026-10-20 14:05:33 » → « 20/10/2026 à 14:05 » (en anglais : « 2026-10-20 14:05 »).
fn quand(date: &str) -> String {
    match NaiveDateTime::parse_from_str(date, FORMAT_DATE) {
        Ok(d) => d.format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M")).to_string(),
        Err(_) => date.to_string(),
    }
}

/// Le jour d'une date du journal, « AAAA-MM-JJ » (les dates lues ont été vérifiées : le découpage est sûr).
fn jour(date: &str) -> &str {
    date.get(..10).unwrap_or(date)
}

/// Les appareils apparus depuis 30 jours, les plus récents en tête. Ceux du premier scan d'un réseau n'en sont pas :
/// ils étaient déjà là quand Vanguard l'a découvert.
fn nouveaux(appareils: &[FicheAppareil], maintenant: NaiveDateTime) -> Vec<&FicheAppareil> {
    let limite = jours_avant(maintenant, JOURS_NOUVEAUX, "%Y-%m-%d");
    let mut debut: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for a in appareils {
        if let Some(p) = a.premier_vu.as_deref() {
            let d = debut.entry(a.reseau.as_str()).or_insert(p);
            *d = (*d).min(p);
        }
    }
    let mut liste: Vec<&FicheAppareil> = appareils
        .iter()
        .filter(|a| {
            a.premier_vu
                .as_deref()
                .is_some_and(|p| p >= limite.as_str() && debut.get(a.reseau.as_str()).is_some_and(|d| p > *d))
        })
        .collect();
    liste.sort_by(|a, b| b.premier_vu.cmp(&a.premier_vu).then(a.ip.cmp(&b.ip)));
    liste
}

/// Le nom montré d'un appareil : son surnom en gras d'abord, puis son nom et son fabricant.
fn nom_appareil(a: &FicheAppareil) -> String {
    let description = if a.description.is_empty() && a.surnom.is_none() {
        format!("<span class=meta>{}</span>", tr!("appareil inconnu", "unknown device"))
    } else {
        esc(&a.description)
    };
    match a.surnom.as_deref() {
        Some(s) if a.description.is_empty() => format!("<strong>{}</strong>", esc(s)),
        Some(s) => format!("<strong>{}</strong> · {description}", esc(s)),
        None => description,
    }
}

fn nom_reseau(a: &FicheAppareil) -> String {
    match (a.nom_reseau.as_deref(), a.reseau.as_str()) {
        (Some(n), _) => esc(n),
        (None, "") => tr!("réseau inconnu", "unknown network").to_string(),
        (None, id) => esc(id),
    }
}

/// Une table d'appareils : première apparition, dernière fois vu, nom, adresse, identifiant, réseau.
fn table_appareils(appareils: &[&FicheAppareil]) -> String {
    let mut h = String::from(tr!(
        "<table><tr class=entete><td>Apparu le</td><td>Vu le</td><td>Appareil</td><td>Adresse</td><td>MAC</td><td>Réseau</td></tr>",
        "<table><tr class=entete><td>First seen</td><td>Last seen</td><td>Device</td><td>Address</td><td>MAC</td><td>Network</td></tr>"
    ));
    let date = |d: Option<&String>| d.map_or_else(|| "?".to_string(), |d| esc(&date_fr(d)));
    for a in appareils {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
            date(a.premier_vu.as_ref()),
            date(a.dernier_vu.as_ref()),
            nom_appareil(a),
            a.ip,
            esc(&a.id),
            nom_reseau(a)
        );
    }
    h += "</table>";
    h
}

/// Les couleurs de la page : lime sur noir pur, ou sur un fond clair. Les mêmes noms dans les deux thèmes : le reste
/// de la feuille ne connaît qu'eux.
const SOMBRE: &str = "--fond:#000;--surface:#0d0d0d;--surface-2:#171717;--encre:#f4f4ef;--doux:#a8a8a0;--discret:#77776f;\
--trait:#1c1c1c;--accent:#d4f36b;--accent-doux:rgba(217,245,110,.10);--vif:#d9f56e;--sur-vif:#0c0e04;\
--sur-vif-doux:rgba(12,14,4,.66);--grave:#ff5c5c;--moyen:#f5b83d;--gris:#4a4a46;--ombre:none;color-scheme:dark";
const CLAIR: &str = "--fond:#f2f3ec;--surface:#fff;--surface-2:#f1f2ea;--encre:#0f1108;--doux:#4a4d40;--discret:#63675a;\
--trait:#e2e4da;--accent:#4d6b00;--accent-doux:rgba(77,107,0,.10);--vif:#d9f56e;--sur-vif:#0c0e04;\
--sur-vif-doux:rgba(12,14,4,.66);--grave:#c62828;--moyen:#b45309;--gris:#b5b8ad;--ombre:0 1px 2px rgba(0,0,0,.06);\
color-scheme:light";

/// La feuille de style du tableau. Sans script (la CSP l'interdit, et c'est voulu) : le bouton clair/sombre est une
/// case à cocher que la feuille lit (`:has`) ; cochée, elle inverse le thème du système. Le choix ne se garde pas
/// d'une ouverture à l'autre : il faudrait un script.
fn feuille() -> String {
    format!(
        ":root{{{SOMBRE}}}@media (prefers-color-scheme:light){{:root{{{CLAIR}}}:root:has(#bascule:checked){{{SOMBRE}}}}}\
         @media (prefers-color-scheme:dark){{:root:has(#bascule:checked){{{CLAIR}}}}}{CSS_TABLEAU}"
    )
}

/// La mise en page : menu à gauche, cartes arrondies, chiffres en grand, la carte « en ordre » en lime.
const CSS_TABLEAU: &str = "
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:16px}
body{margin:0;background:var(--fond);color:var(--encre);font:15px/1.55 system-ui,'Segoe UI',sans-serif}
a{color:var(--accent)}.bascule{position:absolute;opacity:0;width:1px;height:1px}
.cadre{display:grid;grid-template-columns:232px minmax(0,1fr);min-height:100vh}
.cote{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:4px;padding:22px 14px;border-right:1px solid var(--trait);background:var(--fond)}
.marque{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:.12em;font-size:14px;margin:0 8px 22px}
.logo{width:26px;height:26px;background-size:contain;flex:none}
.cote a{display:block;padding:9px 12px;border-radius:10px;color:var(--doux);text-decoration:none;font-size:14px}
.cote a:hover{background:var(--surface-2);color:var(--encre)}.cote a.actif{background:var(--vif);color:var(--sur-vif);font-weight:600}
.theme{margin-top:auto;display:flex;align-items:center;gap:8px;padding:9px 12px;border:1px solid var(--trait);border-radius:999px;cursor:pointer;color:var(--doux);font-size:13px;user-select:none}
.theme:hover{color:var(--encre)}.lune{width:12px;height:12px;border-radius:50%;border:1.5px solid currentColor;background:linear-gradient(90deg,currentColor 50%,transparent 50%);flex:none}#bascule:focus-visible~.cadre .theme{outline:2px solid var(--accent);outline-offset:2px}
main{padding:28px 36px 64px;max-width:1180px;width:100%}
.haut{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:22px}
h1{font-size:36px;line-height:1.1;margin:0 0 6px;font-weight:700;letter-spacing:-.02em}h1 em{font-style:normal;color:var(--accent)}
h2{font-size:22px;margin:40px 0 14px;font-weight:650}.sous{color:var(--doux);margin:0}
.bouton{display:inline-block;background:var(--vif);color:var(--sur-vif);text-decoration:none;font-weight:600;padding:11px 20px;border-radius:999px}
.bouton:hover{filter:brightness(1.06)}
.grille{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;align-items:stretch;margin-bottom:14px}
.carte{background:var(--surface);border:1px solid var(--trait);border-radius:18px;padding:18px 20px;margin:0 0 14px;box-shadow:var(--ombre)}
.grille .carte{margin:0}.carte h3{font-size:18px;font-weight:600;margin:0 0 12px;display:flex;align-items:center;gap:8px}
.carte.vif{background:var(--vif);border-color:var(--vif);color:var(--sur-vif)}
.carte.vif .meta,.carte.vif .fix,.carte.vif .etiq{color:var(--sur-vif-doux)}.carte.vif code{background:rgba(12,14,4,.10)}
.point{width:9px;height:9px;border-radius:50%;flex:none;display:inline-block;background:var(--moyen)}
.point.bon{background:var(--accent)}.carte.vif .point.bon{background:var(--sur-vif)}.point.grave{background:var(--grave)}.point.gris{background:var(--gris)}
.tuiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin:0 0 14px}
.tuile{background:var(--surface);border:1px solid var(--trait);border-radius:18px;padding:16px 18px;box-shadow:var(--ombre)}
.tuile .n{font-size:40px;font-weight:700;line-height:1;letter-spacing:-.02em}.etiq{color:var(--doux);font-size:13px;margin-top:6px}
.note{display:flex;align-items:center;gap:16px}.note .n{font-size:28px;font-weight:700;line-height:1}
.lettre{flex:none;width:64px;height:64px;border-radius:16px;display:grid;place-items:center;font-size:34px;font-weight:800;background:var(--surface-2)}
.carte.vif .lettre{background:var(--sur-vif);color:var(--vif)}
.duo{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.anneau{width:124px;height:124px;border-radius:50%;display:grid;place-items:center;flex:none}
.anneau span{width:88px;height:88px;border-radius:50%;background:var(--surface);display:grid;place-content:center;text-align:center;font-size:26px;font-weight:700;line-height:1.1}
.anneau small{display:block;font-size:11px;font-weight:400;color:var(--doux)}
.legende{list-style:none;margin:0;padding:0;font-size:13px;color:var(--doux);flex:1;min-width:150px}
.legende li{display:flex;align-items:center;gap:8px;padding:2px 0}.legende b{color:var(--encre);margin-left:auto;padding-left:12px}
.graphe{display:flex;align-items:flex-end;gap:4px;height:150px;padding-top:6px}
.col{flex:1;height:100%;display:flex;flex-direction:column;justify-content:flex-end;gap:2px;min-width:0}
.col i{display:block;border-radius:4px;min-height:3px}.col i.vide{background:var(--surface-2);height:3px}
.axe{display:flex;justify-content:space-between;color:var(--discret);font-size:12px;margin-top:8px}
.critique-c{background:var(--grave)}.eleve-c{background:var(--moyen)}.moyen-c{background:color-mix(in srgb,var(--moyen) 50%,transparent)}.info-c{background:var(--gris)}
.badge{font-size:11px;font-weight:700;letter-spacing:.04em;padding:3px 9px;border-radius:999px;white-space:nowrap;background:var(--gris);color:var(--encre)}
.badge.ok{background:var(--vif);color:var(--sur-vif)}.carte.vif .badge.ok{background:var(--sur-vif);color:var(--vif)}
.badge.critique{background:var(--grave);color:#fff}.badge.eleve{background:var(--moyen);color:#1a1200}
.badge.moyen{background:transparent;color:var(--moyen);box-shadow:inset 0 0 0 1px var(--moyen)}.badge.info{background:var(--surface-2);color:var(--doux)}
.carte.vif .badge.moyen{color:var(--sur-vif);box-shadow:inset 0 0 0 1px var(--sur-vif)}
.ligne{display:flex;gap:12px;align-items:baseline;padding:9px 0;border-top:1px solid var(--trait)}.jour+.ligne,.ligne:first-child{border-top:0}
.etats .ligne{justify-content:space-between}.etats .ligne b{text-align:right}
.cat{font-weight:600}.meta{color:var(--doux);font-size:13px}.fix{color:var(--doux);font-size:13px;margin-top:6px}.jour{font-weight:650;margin:0 0 6px}
code{font:12.5px ui-monospace,monospace;background:var(--surface-2);padding:2px 6px;border-radius:6px;overflow-wrap:break-word;user-select:all}
table{width:100%;border-collapse:separate;border-spacing:0 6px;font-size:14px}
td{padding:9px 10px;background:var(--surface-2);vertical-align:top}td:first-child{border-radius:10px 0 0 10px}td:last-child{border-radius:0 10px 10px 0}
.entete td{background:transparent;color:var(--discret);font-size:12px;padding:0 10px}
details summary{cursor:pointer;font-weight:600}ul{margin:8px 0 0;padding-left:20px}
.fonctions{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px;align-items:start}
.fonctions details{background:var(--surface);border:1px solid var(--trait);border-radius:18px;padding:16px 18px;box-shadow:var(--ombre)}
.fonctions summary{font-size:17px}.fonctions summary small{color:var(--doux);font-weight:400;font-size:13px;margin-left:6px}
.fonction{display:grid;grid-template-columns:52px 1fr;gap:2px 12px;padding:10px 0;border-top:1px solid var(--trait)}
.fonction>*{grid-column:2}.fonction>.place{grid-column:1;grid-row:1/span 3}summary+.fonction{border-top:0;margin-top:8px}
.place{font:600 12px ui-monospace,monospace;background:var(--accent-doux);color:var(--accent);padding:3px 8px;border-radius:999px;height:fit-content;text-align:center}
.pied{color:var(--discret);font-size:13px;margin-top:36px}
@media (max-width:760px){.cadre{display:block}.cote{height:auto;flex-direction:row;align-items:center;overflow-x:auto;padding:10px 12px;border-right:0;border-bottom:1px solid var(--trait);z-index:1}
.marque{margin:0 10px 0 0}.theme{margin:0 0 0 auto;white-space:nowrap}.cote a{white-space:nowrap}main{padding:20px 16px 48px}h1{font-size:28px}.ligne{flex-wrap:wrap}}
";

/// Le comment l'activer, dit partout où la surveillance manque.
fn comment_activer() -> &'static str {
    tr!(
        "Pour l'activer : menu « Réseau et Internet » › « Surveillance toutes les heures », ou <code>vanguard surveillance on</code>. Elle scanne alors le réseau toutes les heures, sans rien changer, et notifie un nouvel appareil, un port dangereux nouvellement ouvert, un routeur usurpé, un port que le routeur ouvre vers Internet, un DNS ou un Wi-Fi qui changent, ou un programme qui parle à un serveur de botnet ; chaque alerte est gardée ici.",
        "To turn it on: menu “Network and Internet” › “Hourly monitoring”, or <code>vanguard monitor on</code>. It then scans the network every hour, changing nothing, and notifies a new device, a dangerous newly opened port, an impersonated router, a port the router opens to the Internet, a DNS or Wi-Fi that changes, or a program talking to a botnet server; each alert is kept here."
    )
}

/// La carte de l'état de la surveillance, en tête de page.
fn etat(d: &Donnees) -> String {
    let passe = d
        .derniere_passe
        .as_deref()
        .map(|p| trf!("dernière passe le {}", "last run on {}", esc(&quand(p))));
    let en_ordre =
        d.active && d.derniere_passe.is_some() && d.temps_reel_coupe.is_none() && d.reseau_non_verifie.is_none();
    let mut h = format!(
        "<div class=\"carte{}\"><h3><span class=\"point {}\"></span>{}</h3>",
        if en_ordre { " vif" } else { "" },
        if en_ordre { "bon" } else { "" },
        tr!("Surveillance du réseau", "Network monitoring")
    );
    match (d.active, passe, d.temps_reel_coupe.as_deref()) {
        (true, passe, Some(quand)) => {
            let _ = trw!(
                h,
                "<span class=\"badge moyen\">EN PAUSE</span> Surveillance toutes les heures en pause : la protection en temps réel de Vanguard est coupée ({}), aucune passe ne se fait et rien n'est notifié{}.<div class=fix>Pour la remettre : <code>vanguard parametres temps-reel oui</code>.</div>",
                "<span class=\"badge moyen\">PAUSED</span> Hourly monitoring paused: Vanguard's real-time protection is off ({}), no run happens and nothing is notified{}.<div class=fix>To turn it back on: <code>vanguard settings real-time yes</code>.</div>",
                esc(quand),
                passe.map(|p| format!(" ({p})")).unwrap_or_default()
            );
        }
        (true, Some(p), None) => {
            let _ = trw!(
                h,
                "<span class=\"badge ok\">ACTIVE</span> Surveillance toutes les heures : {p}.",
                "<span class=\"badge ok\">ON</span> Hourly monitoring: {p}."
            );
        }
        (true, None, None) => {
            h += tr!(
                "<span class=\"badge ok\">ACTIVE</span> Surveillance toutes les heures : pas encore de passe, la première vient dans l'heure (5 minutes après le démarrage de l'ordinateur).",
                "<span class=\"badge ok\">ON</span> Hourly monitoring: no run yet, the first one comes within the hour (5 minutes after the computer starts)."
            );
        }
        (false, passe, _) => {
            let _ = trw!(
                h,
                "<span class=\"badge moyen\">COUPÉE</span> La surveillance horaire n'est pas active{} : rien de nouveau n'est noté.<div class=fix>{}</div>",
                "<span class=\"badge moyen\">OFF</span> Hourly monitoring is not on{}: nothing new is recorded.<div class=fix>{}</div>",
                passe.map(|p| format!(" ({p})")).unwrap_or_default(),
                comment_activer()
            );
        }
    }
    // Le scan du réseau qui n'a pas pu se faire : dit à côté de la dernière passe, qui sinon passerait pour saine.
    if let Some((date, raison)) = &d.reseau_non_verifie {
        let _ = trw!(
            h,
            "<div class=fix><span class=\"badge moyen\">NON VÉRIFIÉ</span> Réseau non scanné à la passe du {} : {}. Les contrôles de cet ordinateur ont été faits ; le scan reprend à la passe suivante.</div>",
            "<div class=fix><span class=\"badge moyen\">NOT CHECKED</span> Network not scanned at the run on {}: {}. This computer's checks were done; the scan resumes at the next run.</div>",
            esc(&quand(date)),
            esc(raison)
        );
    }
    h += "</div>";
    h
}

/// Rien à montrer du tout : ni surveillance, ni passe, ni alerte, ni appareil. La page l'explique au lieu d'être vide.
fn page_vide(d: &Donnees) -> bool {
    !d.active && d.derniere_passe.is_none() && d.alertes.is_empty() && d.appareils.is_empty()
}

fn tuiles(d: &Donnees, nouveaux: usize, suspectes: usize) -> String {
    let depuis = |jours: i64| {
        let limite = jours_avant(d.maintenant, jours, FORMAT_DATE);
        d.alertes.iter().filter(|a| a.date >= limite).count()
    };
    let tuile = |n: usize, etiquette: &str| {
        format!("<div class=tuile><div class=n>{n}</div><div class=etiq>{etiquette}</div></div>")
    };
    [
        tuile(depuis(1), tr!("alertes en 24 heures", "alerts in 24 hours")),
        tuile(depuis(7), tr!("alertes en 7 jours", "alerts in 7 days")),
        tuile(
            nouveaux,
            tr!("nouveaux appareils en 30 jours", "new devices in 30 days"),
        ),
        tuile(
            suspectes,
            tr!("connexions suspectes en 90 jours", "suspicious connections in 90 days"),
        ),
    ]
    .into_iter()
    .fold(String::from("<div class=tuiles>"), |h, t| h + &t)
        + "</div>"
}

/// Les alertes jour par jour : les 14 derniers jours en barres, puis chaque jour qui en a, le plus récent en tête.
fn alertes_par_jour(d: &Donnees) -> String {
    let mut h = String::from(tr!("<h2>Alertes par jour</h2>", "<h2>Alerts by day</h2>"));
    if d.alertes.is_empty() {
        h += tr!(
            "<div class=carte>Aucune alerte notée ces 90 derniers jours.</div>",
            "<div class=carte>No alert recorded in the last 90 days.</div>"
        );
        return h;
    }
    let mut par_jour: std::collections::BTreeMap<&str, Vec<&Alerte>> = std::collections::BTreeMap::new();
    for a in &d.alertes {
        par_jour.entry(jour(&a.date)).or_default().push(a);
    }
    for (j, alertes) in par_jour.iter().rev() {
        let _ = write!(
            h,
            "<div class=carte><p class=jour>{} — {}</p>",
            esc(&date_fr(j)),
            trf!("{} alerte(s)", "{} alert(s)", alertes.len())
        );
        // Dans la journée aussi, la plus récente en haut.
        for a in alertes.iter().rev() {
            let genre = Genre::de(&a.genre);
            let heure = a.date.get(11..16).unwrap_or("");
            let _ = write!(
                h,
                "<div class=ligne><span class=meta>{}</span><span class=\"badge {}\">{}</span><div><span class=cat>{}</span> {}</div></div>",
                esc(heure),
                classe_alerte(a),
                genre.libelle(),
                esc(&a.titre),
                esc(&a.texte)
            );
        }
        h += "</div>";
    }
    h
}

fn appareils(d: &Donnees, nouveaux: &[&FicheAppareil]) -> String {
    let mut h = String::from(tr!(
        "<h2>Nouveaux appareils (30 derniers jours)</h2><div class=carte>",
        "<h2>New devices (last 30 days)</h2><div class=carte>"
    ));
    if d.appareils.is_empty() {
        h += tr!(
            "Aucun appareil connu : lancez un scan du réseau (menu « Réseau et Internet » › « Appareils du réseau » › « Scan du réseau », ou <code>vanguard appareils</code>) pour que Vanguard apprenne ceux de votre réseau.",
            "No known device: run a network scan (menu “Network and Internet” › “Devices on the network” › “Network scan”, or <code>vanguard devices</code>) so Vanguard learns your home's devices."
        );
    } else if nouveaux.is_empty() {
        h += tr!(
            "Aucun appareil apparu ces 30 derniers jours.",
            "No device appeared in the last 30 days."
        );
    } else {
        h += &table_appareils(nouveaux);
    }
    if !d.appareils.is_empty() {
        h += tr!(
            "<div class=meta>Ceux du premier scan d'un réseau n'y sont pas : ils étaient déjà là. Un surnom (menu « Nommer un appareil » ou <code>vanguard nommer &lt;ip&gt; &lt;surnom&gt;</code>) s'affiche en gras.</div>",
            "<div class=meta>Those of a network's first scan are not listed: they were already there. A nickname (menu “Name a device” or <code>vanguard name &lt;ip&gt; &lt;nickname&gt;</code>) is shown in bold.</div>"
        );
    }
    h += "</div>";
    if !d.appareils.is_empty() {
        let mut tous: Vec<&FicheAppareil> = d.appareils.iter().collect();
        tous.sort_by(|a, b| a.reseau.cmp(&b.reseau).then(a.ip.cmp(&b.ip)));
        let _ = trw!(
            h,
            "<div class=carte><details><summary>Tous les appareils connus ({})</summary>{}</details></div>",
            "<div class=carte><details><summary>All known devices ({})</summary>{}</details></div>",
            tous.len(),
            table_appareils(&tous)
        );
    }
    h
}

fn connexions_suspectes(d: &Donnees, vues: &[&Alerte]) -> String {
    let mut h = String::from(tr!(
        "<h2>Connexions suspectes</h2><div class=carte>",
        "<h2>Suspicious connections</h2><div class=carte>"
    ));
    if d.botnets_en_cours.is_empty() && vues.is_empty() {
        h += tr!(
            "Aucun programme de cet ordinateur n'a été vu parler à un serveur de commande de botnet connu (listes Feodo Tracker et ThreatFox d'abuse.ch).",
            "No program on this computer was seen talking to a known botnet command server (abuse.ch's Feodo Tracker and ThreatFox lists)."
        );
    }
    if !d.botnets_en_cours.is_empty() {
        // Vues il y a moins de deux heures : la dernière passe les a revues. Plus vieilles (surveillance coupée,
        // connexions illisibles depuis) : la date, sans « encore ».
        let recentes = d
            .botnets_vus
            .is_some_and(|v| d.maintenant.signed_duration_since(v) <= chrono::Duration::hours(BOTNETS_RECENTS_HEURES));
        let vues = d
            .botnets_vus
            .map(|v| quand(&v.format(FORMAT_DATE).to_string()))
            .unwrap_or_default();
        let _ = if recentes {
            trw!(
                h,
                "<p class=jour>Encore vues à la dernière passe (le {})</p><ul>",
                "<p class=jour>Still seen at the last run ({})</p><ul>",
                esc(&vues)
            )
        } else {
            trw!(
                h,
                "<p class=jour>Vues le {} ; rien de plus récent : la surveillance n'a pas pu revérifier depuis</p><ul>",
                "<p class=jour>Seen on {}; nothing more recent: monitoring could not check again since</p><ul>",
                esc(&vues)
            )
        };
        for c in &d.botnets_en_cours {
            let _ = write!(h, "<li><span class=\"badge critique\">BOTNET</span> {}</li>", esc(c));
        }
        h += tr!(
            "</ul><div class=fix>Ouvrez « Après une infection » dans Vanguard (<code>vanguard depanner infection</code>) : coupez Internet d'abord.</div>",
            "</ul><div class=fix>Open “After an infection” in Vanguard (<code>vanguard troubleshoot infection</code>): cut the Internet first.</div>"
        );
    }
    if !vues.is_empty() {
        h += tr!("<p class=jour>Signalées</p>", "<p class=jour>Reported</p>");
        for a in vues.iter().rev() {
            let _ = write!(
                h,
                "<div class=ligne><span class=meta>{}</span><div>{}</div></div>",
                esc(&quand(&a.date)),
                esc(&a.texte)
            );
        }
    }
    h += "</div>";
    h
}

/// La classe de gravité d'une alerte : celle portée par l'événement, sinon celle de son genre.
fn classe_alerte(a: &Alerte) -> &'static str {
    a.gravite.map_or(Genre::de(&a.genre).classe(), classe_de)
}

/// Les quatre gravités, de la plus grave à la moins grave, avec leur nom dans la légende.
fn gravites() -> [(&'static str, &'static str); 4] {
    [
        ("critique", tr!("graves", "critical")),
        ("eleve", tr!("élevées", "high")),
        ("moyen", tr!("moyennes", "medium")),
        ("info", tr!("pour information", "for information")),
    ]
}

/// Les alertes des `JOURS_GRAPHIQUE` derniers jours, comptées par gravité (dans l'ordre de `gravites`).
fn par_gravite<'a>(alertes: impl Iterator<Item = &'a Alerte>) -> [usize; 4] {
    let mut n = [0usize; 4];
    for a in alertes {
        let classe = classe_alerte(a);
        if let Some(i) = gravites().iter().position(|(c, _)| *c == classe)
            && let Some(compte) = n.get_mut(i)
        {
            *compte = compte.saturating_add(1);
        }
    }
    n
}

/// `n` sur `total` en pourcentage entier (0 si le total est nul).
fn pourcent(n: usize, total: usize) -> usize {
    n.saturating_mul(100).checked_div(total).unwrap_or(0)
}

/// La carte du dernier bilan : sa note en lettre, son score, ses problèmes ; en lime seulement si tout est en ordre.
fn carte_bilan(d: &Donnees) -> String {
    let titre = tr!("Dernier bilan", "Last check");
    let Some(b) = &d.bilan else {
        return format!(
            "<div class=carte><h3><span class=\"point gris\"></span>{titre}</h3><p class=meta>{}</p></div>",
            tr!(
                "Aucun bilan encore. Lancez « Bilan de sécurité complet » (1 au menu) ou <code>vanguard bilan</code>.",
                "No check yet. Run “Full security check” (1 in the menu) or <code>vanguard check</code>."
            )
        );
    };
    // Un historique retouché après coup ne laisse pas la carte se dire en ordre.
    let historique_sain = d.historique.as_deref().is_none_or(|h| !h.starts_with('⚠'));
    let en_ordre = b.machine.is_some_and(|m| m >= 75) && b.problemes == 0 && historique_sain;
    let (lettre, score) = match b.machine {
        Some(m) => (crate::risk::note(m), format!("{m}/100")),
        None => ("?", tr!("non vérifié", "not verified").to_string()),
    };
    let quand = NaiveDateTime::parse_from_str(&b.date, "%Y-%m-%d %H:%M").map_or_else(
        |_| b.date.clone(),
        |t| t.format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M")).to_string(),
    );
    let mut h = format!(
        "<div class=\"carte{}\"><h3><span class=\"point {}\"></span>{titre}</h3><div class=note><div class=lettre>{lettre}</div><div><div class=n>{}</div><div class=etiq>{}</div></div></div>",
        if en_ordre { " vif" } else { "" },
        if en_ordre { "bon" } else { "" },
        esc(&score),
        trf!("cet ordinateur, le {}", "this computer, on {}", esc(&quand))
    );
    if b.machine.is_none() {
        h += tr!(
            "<div class=fix>L'audit n'a pas pu se faire en entier : aucune note n'est donnée plutôt qu'une note fausse.</div>",
            "<div class=fix>The audit could not run in full: no grade is given rather than a wrong one.</div>"
        );
    }
    if let Some(r) = b.reseau {
        let _ = trw!(
            h,
            "<div class=fix>Réseau : {} ({r}/100)</div>",
            "<div class=fix>Network: {} ({r}/100)</div>",
            crate::risk::note(r)
        );
    }
    if b.problemes > 0 {
        let _ = trw!(
            h,
            "<div class=fix>{} problème(s) à corriger : <code>vanguard corriger</code></div>",
            "<div class=fix>{} problem(s) to fix: <code>vanguard fix</code></div>",
            b.problemes
        );
    }
    if let Some(avis) = &d.historique {
        let _ = write!(h, "<div class=meta>{}</div>", esc(avis));
    }
    h += "</div>";
    h
}

/// L'anneau des alertes des 30 derniers jours, par gravité : de vraies alertes du journal, jamais un chiffre inventé.
fn carte_anneau(d: &Donnees) -> String {
    let limite = jours_avant(d.maintenant, JOURS_GRAPHIQUE, FORMAT_DATE);
    let n = par_gravite(d.alertes.iter().filter(|a| a.date >= limite));
    let total: usize = n.iter().sum();
    let fond = if total == 0 {
        "var(--surface-2)".to_string()
    } else {
        let mut fait = 0usize;
        let mut arcs = Vec::new();
        for ((classe, _), compte) in gravites().iter().zip(n) {
            let debut = pourcent(fait, total);
            fait = fait.saturating_add(compte);
            let fin = pourcent(fait, total);
            let couleur = match *classe {
                "critique" => "var(--grave)",
                "eleve" => "var(--moyen)",
                "moyen" => "color-mix(in srgb,var(--moyen) 50%,transparent)",
                _ => "var(--gris)",
            };
            arcs.push(format!("{couleur} {debut}% {fin}%"));
        }
        format!("conic-gradient({})", arcs.join(","))
    };
    let mut h = format!(
        "<div class=carte><h3><span class=\"point {}\"></span>{}</h3><div class=duo><div class=anneau style=\"background:{fond}\"><span>{total}<small>{}</small></span></div><ul class=legende>",
        if n.first().is_some_and(|c| *c > 0) {
            "grave"
        } else if total > 0 {
            ""
        } else {
            "bon"
        },
        tr!("Alertes sur 30 jours", "Alerts over 30 days"),
        tr!("alertes", "alerts")
    );
    for ((classe, nom), compte) in gravites().iter().zip(n) {
        let _ = write!(
            h,
            "<li><span class=\"point {classe}-c\"></span>{nom}<b>{compte}</b></li>"
        );
    }
    h += "</ul></div></div>";
    h
}

/// La carte de la protection : le temps réel des fichiers, le veilleur, la protection active et la quarantaine, lus
/// tels qu'ils sont ; ce qui n'a pas pu être lu le dit.
fn carte_protection(d: &Donnees) -> String {
    let pause = d.temps_reel_coupe.is_some();
    let mut h = format!(
        "<div class=carte><h3><span class=\"point {}\"></span>{}</h3><p class=meta>{}</p><div class=etats>",
        if pause { "" } else { "gris" },
        tr!("Protection", "Protection"),
        esc(&d.fichiers)
    );
    let ligne = |h: &mut String, nom: &str, valeur: &str| {
        let _ = write!(h, "<div class=ligne><span>{nom}</span><b>{}</b></div>", esc(valeur));
    };
    if let Some(quand) = &d.temps_reel_coupe {
        ligne(
            &mut h,
            tr!("Temps réel", "Real-time"),
            &trf!("en pause {}", "paused {}", quand),
        );
    }
    if let Some(v) = &d.veilleur {
        ligne(&mut h, tr!("Veilleur", "Watcher"), v);
    }
    ligne(&mut h, tr!("Protection active", "Active protection"), &d.blocage);
    ligne(
        &mut h,
        tr!("Quarantaine", "Quarantine"),
        &trf!("{} fichier(s)", "{} file(s)", d.quarantaine),
    );
    h += "</div></div>";
    h
}

/// Les alertes des 30 derniers jours, une colonne par jour, empilées par gravité (la plus grave en bas).
fn graphique(d: &Donnees) -> String {
    let jours: Vec<String> = (0..JOURS_GRAPHIQUE)
        .rev()
        .map(|i| jours_avant(d.maintenant, i, "%Y-%m-%d"))
        .collect();
    let comptes: Vec<[usize; 4]> = jours
        .iter()
        .map(|j| par_gravite(d.alertes.iter().filter(|a| jour(&a.date) == j.as_str())))
        .collect();
    let plus = comptes
        .iter()
        .map(|c| c.iter().sum::<usize>())
        .max()
        .unwrap_or(0)
        .max(1);
    let mut h = format!(
        "<div class=carte><h3>{}</h3><div class=graphe>",
        tr!("Alertes des 30 derniers jours", "Alerts of the last 30 days")
    );
    for (j, c) in jours.iter().zip(&comptes) {
        let total: usize = c.iter().sum();
        let _ = write!(
            h,
            "<div class=col title=\"{}\">",
            esc(&trf!("{} : {} alerte(s)", "{}: {} alert(s)", date_fr(j), total))
        );
        if total == 0 {
            h += "<i class=vide></i>";
        }
        // De haut en bas : information, moyennes, élevées, graves (la plus grave posée en bas de la colonne).
        for ((classe, _), compte) in gravites().iter().zip(c).rev() {
            if *compte > 0 {
                let _ = write!(
                    h,
                    "<i class={classe}-c style=\"height:{}%\"></i>",
                    compte.saturating_mul(100).div_ceil(plus)
                );
            }
        }
        h += "</div>";
    }
    let premier = jours.first().map(|j| date_fr(j)).unwrap_or_default();
    let _ = write!(
        h,
        "</div><div class=axe><span>{premier}</span><span>{}</span></div><ul class=legende style=\"display:flex;gap:16px;flex-wrap:wrap;margin-top:10px\">",
        tr!("aujourd'hui", "today")
    );
    for (classe, nom) in gravites() {
        let _ = write!(h, "<li><span class=\"point {classe}-c\"></span>{nom}</li>");
    }
    h += "</ul></div>";
    h
}

/// Toutes les fonctions du menu, rubrique par rubrique : la place à taper dans le menu, et la commande, qu'un clic
/// sélectionne en entier pour la copier (sans script, la page ne peut rien lancer elle-même).
fn toutes_les_fonctions(fonctions: &[Rubrique]) -> String {
    if fonctions.is_empty() {
        return String::new();
    }
    let mut h = String::from(tr!(
        "<section id=fonctions><h2>Toutes les fonctions</h2><p class=meta>Le menu de Vanguard, rubrique par rubrique : tapez le numéro dans le menu (<code>vanguard</code>), ou la commande dans un terminal ; un clic sur une commande la sélectionne, prête à copier.</p><div class=fonctions>",
        "<section id=fonctions><h2>All features</h2><p class=meta>Vanguard's menu, section by section: type the number in the menu (<code>vanguard</code>), or the command in a terminal; one click on a command selects it, ready to copy.</p><div class=fonctions>"
    ));
    for (i, r) in fonctions.iter().enumerate() {
        let _ = write!(
            h,
            "<details{}><summary>{} <small>{} · {}</small></summary>",
            if i == 0 { " open" } else { "" },
            esc(&r.titre),
            esc(&r.resume),
            r.fonctions.len()
        );
        for f in &r.fonctions {
            let _ = write!(
                h,
                "<div class=fonction><span class=place>{}</span><span class=cat>{}</span><span class=meta>{}</span>{}</div>",
                esc(&f.place),
                esc(&f.titre),
                esc(&f.precision),
                f.commande
                    .as_deref()
                    .map(|c| format!("<code>{}</code>", esc(c)))
                    .unwrap_or_default()
            );
        }
        h += "</details>";
    }
    h += "</div></section>";
    h
}

/// Le menu de gauche : des ancres vers les sections de la page, et le bouton clair/sombre (l'étiquette de la case).
fn navigation(complete: bool, logo: &str) -> String {
    let mut h = format!(
        "<nav class=cote><div class=marque><span class=logo style=\"background-image:url(data:image/png;base64,{logo})\"></span>VANGUARD</div><a class=actif href=#apercu>{}</a>",
        tr!("Vue d'ensemble", "Overview")
    );
    if complete {
        for (ancre, nom) in [
            ("alertes", tr!("Alertes", "Alerts")),
            ("appareils", tr!("Appareils", "Devices")),
            ("connexions", tr!("Connexions", "Connections")),
        ] {
            let _ = write!(h, "<a href=#{ancre}>{nom}</a>");
        }
    }
    let _ = write!(
        h,
        "<a href=#fonctions>{}</a><label class=theme for=bascule><span class=lune></span>{}</label></nav>",
        tr!("Toutes les fonctions", "All features"),
        tr!("Clair / sombre", "Light / dark")
    );
    h
}

/// Ce que le navigateur a le droit de charger dans la page : rien, sauf sa feuille de style écrite dedans et son
/// icône en data:. Deuxième barrière derrière l'échappement (`esc`) : une section qui l'oublierait un jour ne
/// pourrait toujours pas faire tourner un script ni appeler Internet.
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:";

/// La page entière, à partir des données réunies.
pub(crate) fn html(d: &Donnees) -> String {
    let mut h = String::new();
    let date = d.maintenant.format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M"));
    let logo = base64(include_bytes!("../../assets/icones/vanguard-32.png"));
    let feuille = feuille();
    let vide = page_vide(d);
    let _ = trw!(
        h,
        "<!doctype html><html lang=fr><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">\
         <title>Tableau de bord Vanguard</title><link rel=icon href=\"data:image/png;base64,{logo}\"><style>{feuille}</style></head><body>\
         <input type=checkbox id=bascule class=bascule aria-label=\"Thème clair ou sombre\"><div class=cadre>{}<main>\
         <header class=haut id=apercu><div><h1>Tableau de bord <em>Vanguard</em></h1><p class=sous>Généré par Vanguard le {date}. Rien n'est envoyé : cette page est écrite sur cet ordinateur.</p></div>{}</header>",
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">\
         <title>Vanguard dashboard</title><link rel=icon href=\"data:image/png;base64,{logo}\"><style>{feuille}</style></head><body>\
         <input type=checkbox id=bascule class=bascule aria-label=\"Light or dark theme\"><div class=cadre>{}<main>\
         <header class=haut id=apercu><div><h1>Vanguard <em>dashboard</em></h1><p class=sous>Generated by Vanguard on {date}. Nothing is sent: this page is written on this computer.</p></div>{}</header>",
        navigation(!vide, &logo),
        if vide {
            ""
        } else {
            tr!(
                "<a class=bouton href=#alertes>Voir les alertes</a>",
                "<a class=bouton href=#alertes>See the alerts</a>"
            )
        }
    );
    if vide {
        let _ = trw!(
            h,
            "<div class=carte><span class=\"badge moyen\">COUPÉE</span> Rien à montrer pour l'instant : la surveillance horaire n'a jamais tourné sur cet ordinateur, et aucun appareil n'est encore connu.<div class=fix>{}</div><div class=fix>Pour voir tout de suite les appareils de votre réseau : menu « Réseau et Internet » › « Appareils du réseau » › « Scan du réseau », ou <code>vanguard appareils</code>.</div></div>",
            "<div class=carte><span class=\"badge moyen\">OFF</span> Nothing to show yet: hourly monitoring has never run on this computer, and no device is known yet.<div class=fix>{}</div><div class=fix>To see your home's devices right away: menu “Network and Internet” › “Devices on the network” › “Network scan”, or <code>vanguard devices</code>.</div></div>",
            comment_activer()
        );
        let _ = write!(h, "<div class=grille>{}{}</div>", carte_bilan(d), carte_protection(d));
        h += &toutes_les_fonctions(&d.fonctions);
        h += "</main></div></body></html>";
        return h;
    }
    h += &etat(d);
    let nouveaux = nouveaux(&d.appareils, d.maintenant);
    let vues: Vec<&Alerte> = d
        .alertes
        .iter()
        .filter(|a| Genre::de(&a.genre) == Genre::Botnet)
        .collect();
    let _ = write!(
        h,
        "<div class=grille>{}{}{}</div>",
        carte_bilan(d),
        carte_anneau(d),
        carte_protection(d)
    );
    h += &tuiles(d, nouveaux.len(), vues.len());
    h += &graphique(d);
    let _ = write!(
        h,
        "<section id=alertes>{}</section><section id=appareils>{}</section><section id=connexions>{}</section>",
        alertes_par_jour(d),
        appareils(d, &nouveaux),
        connexions_suspectes(d, &vues)
    );
    h += &toutes_les_fonctions(&d.fonctions);
    let _ = trw!(
        h,
        "<p class=pied>Les alertes sont gardées {JOURS_GARDES} jours ({ALERTES_GARDEES} au plus) dans le dossier de Vanguard de cet ordinateur. Pour remettre la page à jour : <code>vanguard tableau-de-bord</code>.</p>",
        "<p class=pied>Alerts are kept {JOURS_GARDES} days ({ALERTES_GARDEES} at most) in this computer's Vanguard folder. To refresh the page: <code>vanguard dashboard</code>.</p>"
    );
    h += "</main></div></body></html>";
    h
}

/// Écrit la page dans le dossier de Vanguard de cet ordinateur (jamais sur la clé : elle dit ce qui a été vu ici).
/// `fonctions` : celles du menu, que main.rs range.
pub fn generer(fonctions: Vec<Rubrique>) -> std::io::Result<PathBuf> {
    let chemin = fichier_page();
    crate::socle::ecrire_atomique(&chemin, html(&collecter(fonctions)))?;
    Ok(chemin)
}

/// La commande et le menu : la page écrite, puis ouverte dans le navigateur sauf avec `sans_ouvrir` (sans affichage
/// graphique, par SSH, ou pour l'essayer).
pub fn ouvrir(sans_ouvrir: bool, fonctions: Vec<Rubrique>) {
    match generer(fonctions) {
        Ok(p) => {
            trp!("  Tableau de bord : {}", "  Dashboard: {}", p.display());
            if !sans_ouvrir {
                crate::machine::ouvrir(&p.display().to_string());
            }
        }
        Err(e) => trp!(
            "  Impossible d'écrire le tableau de bord : {e}",
            "  Could not write the dashboard: {e}"
        ),
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// S2c : une dernière passe forgée (ou effacée) ne fait jamais dire au tableau que la surveillance vient de passer.
    #[test]
    fn passe_forgee_jamais_dite() {
        use crate::sceau::{Doute, Juge};
        let notee = b"2026-10-25 10:00:00".to_vec();
        assert_eq!(
            derniere_passe_lue(Juge::Cru(notee.clone())).as_deref(),
            Some("2026-10-25 10:00:00")
        );
        assert_eq!(
            derniere_passe_lue(Juge::Douteux(Doute::HorsVanguard, Some(notee.clone()))),
            None
        );
        assert_eq!(derniere_passe_lue(Juge::Douteux(Doute::Adopte, Some(notee))), None);
        assert_eq!(derniere_passe_lue(Juge::Douteux(Doute::HorsVanguard, None)), None);
        assert!(crate::modele::inventaire::scelles().any(|n| n == crate::sceau::SURVEILLANCE_PASSE));
    }

    fn date(texte: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(texte, FORMAT_DATE).unwrap()
    }

    fn une_alerte(date: &str, genre: Genre, titre: &str, texte: &str) -> Alerte {
        Alerte {
            date: date.into(),
            genre: genre.nom().into(),
            titre: titre.into(),
            texte: texte.into(),
            cle: None,
            gravite: None,
        }
    }

    fn appareil(id: &str, ip: &str, premier: &str, surnom: Option<&str>, description: &str) -> FicheAppareil {
        FicheAppareil {
            reseau: "3c:22:fb:00:00:01".into(),
            nom_reseau: Some("Salon".into()),
            id: id.into(),
            ip: ip.parse().unwrap(),
            surnom: surnom.map(str::to_string),
            description: description.into(),
            premier_vu: Some(premier.into()),
            dernier_vu: Some("2026-10-20".into()),
        }
    }

    fn donnees() -> Donnees {
        Donnees {
            maintenant: date("2026-10-20 14:50:00"),
            active: true,
            derniere_passe: Some("2026-10-20 14:00:00".into()),
            alertes: vec![
                une_alerte(
                    "2026-10-19 03:00:00",
                    Genre::Appareil,
                    "Nouvel appareil sur votre réseau",
                    "10.0.0.66 — <script>alert(1)</script> 3c:22:fb:00:00:66",
                ),
                une_alerte(
                    "2026-10-20 14:00:00",
                    Genre::Botnet,
                    "Vanguard : programme relié à un botnet",
                    "outil → 192.0.2.7:443 (Emotet, ThreatFox) : un serveur de commande connu.",
                ),
            ],
            appareils: vec![
                appareil(
                    "3c:22:fb:00:00:10",
                    "10.0.0.10",
                    "2026-09-01",
                    Some("imprimante HP"),
                    "HP",
                ),
                appareil(
                    "3c:22:fb:00:00:66",
                    "10.0.0.66",
                    "2026-10-19",
                    None,
                    "<img src=x onerror=alert(2)>",
                ),
                appareil(
                    "3c:22:fb:00:00:20",
                    "10.0.0.20",
                    "2026-10-18",
                    Some("<b>tablette</b>"),
                    "",
                ),
            ],
            botnets_en_cours: vec!["<svg onload=alert(3)> → 192.0.2.7:443".into()],
            botnets_vus: Some(date("2026-10-20 14:00:00")),
            temps_reel_coupe: None,
            reseau_non_verifie: None,
            bilan: Some(DernierBilan {
                date: "2026-10-20 09:12".into(),
                machine: Some(82),
                reseau: Some(64),
                problemes: 2,
            }),
            historique: Some("Historique intact : 3 bilans chaînés par leur empreinte.".into()),
            fichiers: "Temps réel des fichiers : 12 fichiers examinés, <i>aucun</i> danger.".into(),
            veilleur: Some("allumé".into()),
            blocage: "protection active".into(),
            quarantaine: 1,
            fonctions: vec![Rubrique {
                titre: "4 · Cet ordinateur".into(),
                resume: "failles, mises à jour".into(),
                fonctions: vec![
                    Fonction {
                        place: "4.1".into(),
                        titre: "Failles connues".into(),
                        precision: "<u>piège</u>".into(),
                        commande: Some("vanguard failles".into()),
                    },
                    Fonction {
                        place: "4.2".into(),
                        titre: "Variante".into(),
                        precision: "même écran".into(),
                        commande: None,
                    },
                ],
            }],
        }
    }

    #[test]
    fn page_sur_des_donnees_inventees() {
        let page = html(&donnees());
        assert!(page.contains("ACTIVE") && page.contains("20/10/2026 à 14:00"));
        // Deux jours d'alertes, le plus récent en tête.
        assert!(page.find("20/10/2026 — 1 alerte").unwrap() < page.find("19/10/2026 — 1 alerte").unwrap());
        // Le premier scan du réseau (1er septembre) n'est pas une nouveauté ; les deux suivants le sont.
        let nouveaux = &page[page.find("<h2>Nouveaux").unwrap()..page.find("Tous les appareils connus").unwrap()];
        assert!(nouveaux.contains("10.0.0.66") && nouveaux.contains("10.0.0.20"));
        assert!(!nouveaux.contains("10.0.0.10"));
        // Le surnom donné par « nommer » est montré.
        assert!(page.contains("<strong>imprimante HP</strong> · HP"));
        assert!(page.contains("Emotet") && page.contains("Encore vues à la dernière passe (le 20/10/2026 à 14:00)"));
        // Aucune ressource externe : la page se suffit (logo compris), et sa politique de sécurité (CSP) interdit
        // tout script et tout appel vers l'extérieur, même si une section oubliait d'échapper un nom.
        for externe in ["http://", "https://", "<script", "<img", "<link rel=stylesheet"] {
            assert!(!page.contains(externe), "{externe}");
        }
        let entete = &page[..page.find("<title>").unwrap()];
        assert!(entete.contains(&format!(
            "<meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">"
        )));
        assert!(CSP.starts_with("default-src 'none'") && !CSP.contains("script-src"));
    }

    /// Des connexions vues il y a trois jours ne sont plus « encore vues » : la surveillance a été coupée, ou la
    /// lecture des connexions échoue depuis ; la page dit la date, sans laisser croire qu'elles durent.
    #[test]
    fn connexions_vues_datees() {
        let vieilles = Donnees {
            botnets_vus: Some(date("2026-10-17 09:00:00")),
            ..donnees()
        };
        let page = html(&vieilles);
        assert!(!page.contains("Encore vues"));
        assert!(page.contains("Vues le 17/10/2026 à 09:00") && page.contains("Emotet"));
        let sans_date = Donnees {
            botnets_vus: None,
            ..donnees()
        };
        assert!(!html(&sans_date).contains("Encore vues"));
    }

    #[test]
    fn un_nom_piege_ne_devient_pas_du_code() {
        // Un appareil choisit son nom ; un programme, son nom de fichier : ils restent du texte dans la page.
        let page = html(&donnees());
        for piege in ["<script>alert", "<img src=x", "<svg onload", "<b>tablette</b>"] {
            assert!(!page.contains(piege), "{piege}");
        }
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(page.contains("<strong>&lt;b&gt;tablette&lt;/b&gt;</strong>"));
    }

    #[test]
    fn page_vide_expliquee() {
        let vide = Donnees {
            maintenant: date("2026-10-20 14:50:00"),
            active: false,
            derniere_passe: None,
            alertes: vec![],
            appareils: vec![],
            botnets_en_cours: vec![],
            botnets_vus: None,
            temps_reel_coupe: None,
            reseau_non_verifie: None,
            bilan: None,
            historique: None,
            fichiers: "Temps réel des fichiers : arrêté.".into(),
            veilleur: None,
            blocage: "désactivé".into(),
            quarantaine: 0,
            fonctions: vec![],
        };
        let page = html(&vide);
        assert!(page.contains("Rien à montrer pour l'instant") && page.contains("vanguard surveillance on"));
        assert!(page.contains("vanguard appareils") && page.ends_with("</main></div></body></html>"));
        // Coupée mais avec un historique : l'historique reste, et la façon de la réactiver est dite.
        let coupee = Donnees {
            active: false,
            ..donnees()
        };
        let page = html(&coupee);
        assert!(page.contains("COUPÉE") && page.contains("vanguard surveillance on"));
        assert!(page.contains("Nouvel appareil sur votre réseau"));
        // Active mais la protection en temps réel coupée : en pause, pas « ACTIVE », et la façon de la remettre.
        let en_pause = Donnees {
            temps_reel_coupe: Some("jusqu'à reprise".into()),
            ..donnees()
        };
        let page = html(&en_pause);
        assert!(page.contains("EN PAUSE") && !page.contains("badge ok"), "{page}");
        assert!(page.contains("jusqu'à reprise") && page.contains("vanguard parametres temps-reel oui"));
        assert!(
            page.contains("20/10/2026 à 14:00"),
            "la dernière vraie passe reste dite"
        );
        // Active, sans alerte ni appareil : chaque section le dit au lieu d'être vide.
        let calme = Donnees {
            alertes: vec![],
            appareils: vec![],
            botnets_en_cours: vec![],
            ..donnees()
        };
        let page = html(&calme);
        assert!(page.contains("Aucune alerte notée") && page.contains("Aucun appareil connu"));
        assert!(page.contains("Aucun programme de cet ordinateur"));
        assert!(page.contains("Aucun bilan encore") || calme.bilan.is_some());
    }

    /// Les cartes de la vue d'ensemble : de vraies données passées telles quelles, échappées, et le thème sans script.
    #[test]
    fn vue_d_ensemble_et_fonctions() {
        let page = html(&donnees());
        // Le bilan : 82/100 donne B ; deux problèmes empêchent la carte d'être dite en ordre (pas de lime).
        assert!(page.contains("<div class=lettre>B</div>") && page.contains("82/100"));
        assert!(page.contains("2 problème(s) à corriger") && page.contains("Réseau : C (64/100)"));
        let bilan = &page[page.find("Dernier bilan").unwrap() - 60..page.find("Dernier bilan").unwrap()];
        assert!(!bilan.contains("vif"), "{bilan}");
        // L'anneau compte les deux alertes du mois : une grave (botnet), une élevée (appareil).
        assert!(page.contains("<span>2<small>alertes</small></span>"), "anneau");
        assert!(page.contains("conic-gradient(var(--grave) 0% 50%,var(--moyen) 50% 100%"));
        // La protection, telle que lue ; un texte venu d'ailleurs reste du texte.
        assert!(page.contains("&lt;i&gt;aucun&lt;/i&gt;") && !page.contains("<i>aucun"));
        assert!(page.contains("1 fichier(s)") && page.contains("protection active"));
        // Les fonctions du menu, avec leur place et leur commande, échappées elles aussi.
        assert!(page.contains("<section id=fonctions>") && page.contains("<span class=place>4.1</span>"));
        assert!(page.contains("<code>vanguard failles</code>") && page.contains("&lt;u&gt;piège&lt;/u&gt;"));
        // Le graphique : 30 colonnes, une par jour.
        assert_eq!(page.matches("<div class=col ").count(), 30);
        // Le menu de gauche mène aux sections qui existent, et le bouton des alertes aussi.
        for ancre in ["apercu", "alertes", "appareils", "connexions", "fonctions"] {
            assert!(page.contains(&format!("href=#{ancre}")), "{ancre}");
            assert!(page.contains(&format!("id={ancre}")), "{ancre}");
        }
        // Clair/sombre : une case lue par la feuille, sans aucun script.
        assert!(page.contains("<input type=checkbox id=bascule") && page.contains(":root:has(#bascule:checked)"));
        assert!(page.contains("<label class=theme for=bascule>"));
        // La surveillance active et passée, sans scan raté : sa carte est dite en ordre (lime).
        assert!(page.contains("<div class=\"carte vif\"><h3><span class=\"point bon\"></span>Surveillance du réseau"));
        // Un historique retouché empêche le bilan de se dire en ordre, même parfait.
        let parfait = Donnees {
            bilan: Some(DernierBilan {
                date: "2026-10-20 09:12".into(),
                machine: Some(95),
                reseau: None,
                problemes: 0,
            }),
            ..donnees()
        };
        assert!(html(&parfait).contains("<div class=\"carte vif\"><h3><span class=\"point bon\"></span>Dernier bilan"));
        let retouche = Donnees {
            historique: Some("⚠ Historique modifié après coup".into()),
            ..parfait
        };
        assert!(!html(&retouche).contains("point bon\"></span>Dernier bilan"));
        // Sans note fiable : « non vérifié », jamais une lettre.
        let sans_note = Donnees {
            bilan: Some(DernierBilan {
                date: "2026-10-20 09:12".into(),
                machine: None,
                reseau: None,
                problemes: 0,
            }),
            ..donnees()
        };
        let page = html(&sans_note);
        assert!(page.contains("<div class=lettre>?</div>") && page.contains("non vérifié"));
    }

    /// Un scan du réseau qui n'a pas pu se faire : noté avec sa date et sa raison, dit sur la page à côté de la
    /// dernière passe, retiré dès qu'un scan s'est fait.
    #[test]
    fn scan_du_reseau_non_verifie() {
        assert!(!html(&donnees()).contains("NON VÉRIFIÉ") && !html(&donnees()).contains("NOT CHECKED"));
        let dossier = crate::socle::dossier_local().join("tableau-reseau");
        let _ = std::fs::remove_dir_all(&dossier);
        let fichier = dossier.join("surveillance-reseau-non-verifie.txt");
        assert_eq!(lire_reseau(&fichier), None);
        ecrire_reseau(
            &fichier,
            Some("pas de réseau\n<b>piège</b>"),
            date("2026-10-20 14:37:05"),
        );
        let note = lire_reseau(&fichier).expect("note relue");
        assert_eq!(
            note,
            ("2026-10-20 14:37:05".into(), "pas de réseau <b>piège</b>".into())
        );
        let page = html(&Donnees {
            reseau_non_verifie: Some(note),
            ..donnees()
        });
        assert!(page.contains("NON VÉRIFIÉ") || page.contains("NOT CHECKED"), "{page}");
        assert!(page.contains("20/10/2026 à 14:37") || page.contains("2026-10-20 14:37"));
        assert!(page.contains("&lt;b&gt;piège&lt;/b&gt;") && !page.contains("<b>piège"));
        // Toujours active : la surveillance n'est pas dite en panne, seul ce scan l'est.
        assert!(page.contains("badge ok"));
        ecrire_reseau(&fichier, None, date("2026-10-20 15:00:10"));
        assert!(!fichier.exists() && lire_reseau(&fichier).is_none());
        // Une note abîmée (sans date lisible) n'est pas montrée.
        std::fs::write(&fichier, "hier\nx\n").unwrap();
        assert_eq!(lire_reseau(&fichier), None);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    #[test]
    fn journal_borne_en_nombre_et_en_age() {
        let dossier = crate::socle::dossier_local().join("tableau-journal");
        let _ = std::fs::remove_dir_all(&dossier);
        let fichier = dossier.join("surveillance-alertes.jsonl");
        let maintenant = date("2026-10-20 14:50:00");
        // Une alerte notée en juillet, puis 510 en octobre : celle de juillet a plus de 90 jours, et des 510 il
        // reste les 500 plus récentes.
        let juillet = date("2026-07-01 10:00:00");
        ajouter(
            &fichier,
            une_alerte("2026-07-01 10:00:00", Genre::Port, "vieux", "x"),
            juillet,
        )
        .unwrap();
        assert_eq!(lire_journal(&fichier).len(), 1);
        for i in 0..510 {
            let d = (maintenant - chrono::Duration::minutes(510 - i))
                .format(FORMAT_DATE)
                .to_string();
            ajouter(
                &fichier,
                une_alerte(&d, Genre::Appareil, "neuf", &i.to_string()),
                maintenant,
            )
            .unwrap();
        }
        let gardees = lire_journal(&fichier);
        assert_eq!(gardees.len(), ALERTES_GARDEES);
        assert!(gardees.iter().all(|a| a.titre == "neuf"));
        assert_eq!(gardees.first().unwrap().texte, "10");
        assert_eq!(gardees.last().unwrap().texte, "509");
        // Une ligne abîmée ou mal datée est laissée de côté, le reste se lit ; le prochain ajout la retire.
        let mut texte = std::fs::read_to_string(&fichier).unwrap();
        texte += "{pas du json\n{\"date\":\"<script>\",\"genre\":\"port\",\"titre\":\"t\",\"texte\":\"x\"}\n";
        std::fs::write(&fichier, texte).unwrap();
        assert_eq!(lire_journal(&fichier).len(), ALERTES_GARDEES);
        // Aucun fichier temporaire laissé à côté (écriture atomique), ni le verrou pris pendant l'ajout.
        let fichiers = std::fs::read_dir(&dossier).unwrap().count();
        assert_eq!(fichiers, 1);
    }

    #[test]
    fn alerte_tronquee_et_genres_stables() {
        assert_eq!(tronquer("abc", 5), "abc");
        assert_eq!(tronquer("éléphant", 3), "élé…");
        for g in Genre::TOUS {
            assert_eq!(Genre::de(g.nom()), g);
        }
        // Un genre inconnu (journal d'une version plus récente) reste montré.
        assert_eq!(Genre::de("nouveau-genre"), Genre::Autre);
    }
}
