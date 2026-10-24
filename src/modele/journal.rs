//! Le journal commun des événements : `evenements/AAAA-MM.jsonl` dans le dossier de données de cet ordinateur
//! (jamais sur la clé), une ligne par événement, écrit en ajout seul. Les alertes, les preuves relevées, les gestes
//! (blocages, quarantaines, corrections), leurs annulations, les alertes déclarées normales et les passages de
//! version y vont ; le tableau de bord et les traces d'incident le lisent.
//!
//! Pourquoi en ajout seul et chaîné : l'ancien journal des alertes était relu puis réécrit en entier (500 lignes au
//! plus), si bien qu'une rafale effaçait la preuve de ce qui la précédait, et rien ne disait qu'une ligne avait été
//! retirée. Ici, chaque ligne porte l'empreinte BLAKE3 des octets exacts de la ligne d'avant (jamais relue par serde,
//! qui pourrait réordonner) ; la tête (`evenements.tete` : dernière empreinte, nombre de lignes, empreinte de chaque
//! mois clos) est scellée par `sceau`. Une ligne changée, retirée, déplacée ou ajoutée, une fin tronquée, un mois
//! remplacé : la lecture le voit. Le premier `precedent` d'un mois est la dernière empreinte du mois d'avant (ancre
//! de rotation) ; quand les plus vieux mois partent (13 mois, 20 Mo au plus), la tête retient l'ancre du plus ancien
//! gardé.
//!
//! Comme les sceaux : barrière, pas coffre. BLAKE3 sans clé secrète, quelqu'un qui a les droits du compte peut tout
//! recalculer ; ce qu'on gagne, c'est qu'un programme qui retire sa ligne sans connaître ce mécanisme se voit.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::evenement::{Evenement, Genre, Source};
use crate::risk::Niveau;
use crate::{tr, trf};

/// Le sous-dossier des segments mensuels.
pub(crate) const DOSSIER: &str = "evenements";
/// La tête scellée du journal.
pub(crate) const TETE: &str = "evenements.tete";
/// Le verrou des écritures : la surveillance, le veilleur et le menu écrivent chacun.
const VERROU: &str = "evenements.verrou";
/// Mois gardés : un an entier, plus le mois en cours.
const MOIS_GARDES: i32 = 13;
/// Taille gardée en tout : on garde les décisions, pas la télémétrie ; au-delà, les plus vieux mois partent.
const OCTETS_GARDES: u64 = 20 << 20;
/// Un segment plus gros n'est pas lu (un fichier mis à sa place pour faire durer la lecture).
const SEGMENT_MAX: u64 = 2 * OCTETS_GARDES;

/// Ce que la lecture prend en tout, au plus. L'élagage (`garder`) ne tourne qu'à l'écriture : sans borne, un dépôt de
/// centaines de segments faisait tout charger au lecteur, jusqu'à le faire tomber faute de mémoire au moment même
/// où il fallait montrer l'incident. Un vrai journal tient en 13 mois et 20 Mo ; au-delà, les plus récents sont lus
/// et ce qui est écarté est dit (`Lecture::Incomplet`).
#[derive(Clone, Copy, Debug)]
struct Bornes {
    mois: usize,
    octets: u64,
    evenements: usize,
}

const BORNES: Bornes = Bornes {
    // Le mois en cours en plus : une horloge sautée en avant peut en laisser un de plus.
    mois: MOIS_GARDES as usize + 1,
    octets: SEGMENT_MAX,
    evenements: 200_000,
};

/// Ce que la tête retient d'un mois clos.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Clos {
    lignes: u64,
    /// L'empreinte du segment entier, tel qu'il était à sa clôture.
    empreinte: String,
}

/// La tête du journal, scellée.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
struct Tete {
    /// La version de Vanguard qui a écrit en dernier : une autre version note son passage.
    version: String,
    /// Le segment en cours (« 2026-10 »).
    segment: String,
    /// Ses lignes, et l'empreinte de la dernière.
    lignes: u64,
    derniere: String,
    /// Le `precedent` attendu de la première ligne du plus ancien segment gardé (vide : le tout premier).
    #[serde(default)]
    ancre: String,
    #[serde(default)]
    clos: BTreeMap<String, Clos>,
    /// Ce qu'une écriture va ajouter, scellé AVANT l'ajout : un arrêt entre l'ajout et la tête qui le suit laisse une
    /// fin que seule cette annonce couvre. Sans elle, une fin en plus de la tête n'est pas de Vanguard : un programme
    /// du compte qui ajoutait ses lignes sans toucher la tête les voyait reprises comme les nôtres à l'écriture
    /// suivante, puis lues « intactes ».
    #[serde(default, skip_serializing_if = "Option::is_none")]
    annonce: Option<Annonce>,
}

/// La fin qu'une écriture annonce avant d'ajouter ses lignes : le segment, son nombre de lignes et l'empreinte de sa
/// dernière ligne une fois l'ajout fait, et le mois que l'écriture clôt (changement de mois) tel qu'il était.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Annonce {
    segment: String,
    lignes: u64,
    derniere: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    clos: Option<(String, Clos)>,
}

/// La fin trouvée sur le disque, d'après la tête : la sienne, celle qu'elle annonçait (arrêt entre l'ajout et la
/// tête), ou une autre.
#[derive(Debug, PartialEq, Eq)]
enum Fin {
    DeLaTete,
    Annoncee,
    Autre,
}

/// Juge la fin du dernier segment (`dernier`, ses lignes, l'empreinte de la dernière) d'après la tête. Égalité
/// exacte, nombre de lignes compris : une ligne de plus que la tête, même chaînée sur sa dernière, est une autre fin.
fn fin_trouvee(t: &Tete, dernier: Option<&str>, lignes: usize, derniere: Option<&str>) -> Fin {
    let pareil = |segment: &str, n: u64, fin: &str| {
        dernier.unwrap_or_default() == segment && lignes as u64 == n && derniere.unwrap_or_default() == fin
    };
    if pareil(&t.segment, t.lignes, &t.derniere) {
        Fin::DeLaTete
    } else if t
        .annonce
        .as_ref()
        .is_some_and(|a| pareil(&a.segment, a.lignes, &a.derniere))
    {
        Fin::Annoncee
    } else {
        Fin::Autre
    }
}

/// Ce que vaut le journal relu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lecture {
    /// Rien d'écrit encore.
    Vide,
    /// Chaîne et tête scellée d'accord.
    Intact,
    /// D'accord, mais la tête a été scellée telle quelle au premier usage des sceaux (`sceau::Lecture::Adopte`).
    Adopte,
    /// Pas falsifié, mais pas entier : fin écrite sans sa tête (arrêt pendant l'écriture), lignes illisibles,
    /// rupture notée plus tôt, sceaux refaits. La raison suit.
    Incomplet(String),
    /// Changé hors de Vanguard : où. Ce qu'on en lit n'est jamais tenu pour vérifié.
    Falsifie(String),
}

impl Lecture {
    /// Le code stable, pour le JSON.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Lecture::Vide => "vide",
            Lecture::Intact => "intact",
            Lecture::Adopte => "adopte",
            Lecture::Incomplet(_) => "incomplet",
            Lecture::Falsifie(_) => "falsifie",
        }
    }

    /// Le pire des deux.
    fn pire(self, autre: Lecture) -> Lecture {
        let rang = |l: &Lecture| match l {
            Lecture::Vide | Lecture::Intact => 0,
            Lecture::Adopte => 1,
            Lecture::Incomplet(_) => 2,
            Lecture::Falsifie(_) => 3,
        };
        if rang(&autre) > rang(&self) { autre } else { self }
    }
}

/// Le journal relu : ce qu'il vaut, ses événements lisibles (du plus ancien au plus récent), et le nombre de lignes
/// qui ne se lisent pas.
#[derive(Debug)]
pub(crate) struct Lu {
    pub lecture: Lecture,
    pub evenements: Vec<Evenement>,
    pub illisibles: usize,
    /// Les événements à partir de ce rang sont tenus pour vérifiés (`verifies`) : écrits sous une tête crue, après la
    /// dernière rupture notée.
    pub verifies_des: usize,
}

impl Lu {
    /// Ce que la lecture garantit écrit par Vanguard : tout, d'un journal intact ; ce qui suit la dernière rupture,
    /// d'un journal rompu puis repris ; rien, d'un journal falsifié ou dont la tête n'est pas crue. Ce qui décide de
    /// taire quelque chose (une alerte déjà notée) ne se fonde que là-dessus.
    pub(crate) fn verifies(&self) -> &[Evenement] {
        self.evenements.get(self.verifies_des..).unwrap_or_default()
    }
}

/// L'empreinte des octets exacts d'une ligne, sans son retour à la ligne.
pub(crate) fn empreinte_ligne(octets: &[u8]) -> String {
    let mut h = blake3::Hasher::new_derive_key("vanguard evenement 1");
    h.update(octets);
    h.finalize().to_hex().to_string()
}

fn empreinte_segment(octets: &[u8]) -> String {
    let mut h = blake3::Hasher::new_derive_key("vanguard segment 1");
    h.update(octets);
    h.finalize().to_hex().to_string()
}

/// Les lignes d'un segment, octets exacts. Une fin sans retour à la ligne (arrêt pendant l'écriture) est une ligne.
fn lignes(octets: &[u8]) -> Vec<&[u8]> {
    if octets.is_empty() {
        return Vec::new();
    }
    let corps = octets.strip_suffix(b"\n").unwrap_or(octets);
    corps.split(|&o| o == b'\n').collect()
}

/// Le `precedent` d'une ligne, sans relire le reste (`None` : la ligne ne se lit pas).
fn precedent_de(ligne: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Chainon {
        precedent: String,
    }
    serde_json::from_slice::<Chainon>(ligne).ok().map(|c| c.precedent)
}

/// « 2026-10.jsonl » → « 2026-10 ».
fn nom_de_segment(nom: &str) -> Option<&str> {
    let mois = nom.strip_suffix(".jsonl")?;
    let o = mois.as_bytes();
    (o.len() == 7 && o[4] == b'-' && o.iter().enumerate().all(|(i, c)| i == 4 || c.is_ascii_digit())).then_some(mois)
}

/// Les segments présents, du plus ancien au plus récent : (mois, chemin).
fn segments(rep: &Path) -> Vec<(String, PathBuf)> {
    let mut s: Vec<(String, PathBuf)> = std::fs::read_dir(rep)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let nom = e.file_name().to_string_lossy().into_owned();
            Some((nom_de_segment(&nom)?.to_string(), e.path()))
        })
        .collect();
    s.sort();
    s
}

/// Les segments lus, les mois écartés, les mois posés après le plafond.
type Partage = (Vec<(String, PathBuf)>, Vec<String>, Vec<String>);

/// Les segments à lire sous `bornes`, du plus ancien au plus récent, les mois écartés et ceux posés après
/// `plafond` : on part du mois du journal (l'incident en cours est là), et dès qu'un mois dépasse le nombre ou les
/// octets permis, lui et tous les plus anciens sont écartés, pour que ce qui est lu reste d'un seul tenant. Le plus
/// récent est toujours lu (sa propre limite, `SEGMENT_MAX`, tient à la lecture). La taille vient du lien lui-même,
/// jamais de sa cible. Les mois après `plafond` ne comptent pas dans les bornes : sinon, des fichiers posés aux
/// noms de 2099 les remplissaient, et le vrai mois en cours n'était plus lu.
fn segments_bornes(presents: Vec<(String, PathBuf)>, bornes: Bornes, plafond: &str) -> Partage {
    let mut lus = Vec::new();
    let mut ecartes = Vec::new();
    let mut posterieurs = Vec::new();
    let mut total: u64 = 0;
    for (mois, chemin) in presents.into_iter().rev() {
        if mois.as_str() > plafond {
            posterieurs.push(mois);
            continue;
        }
        let taille = std::fs::symlink_metadata(&chemin).map_or(0, |m| m.len());
        let dedans = lus.is_empty() || (lus.len() < bornes.mois && total.saturating_add(taille) <= bornes.octets);
        if dedans && ecartes.is_empty() {
            total = total.saturating_add(taille);
            lus.push((mois, chemin));
        } else {
            ecartes.push(mois);
        }
    }
    lus.reverse();
    ecartes.reverse();
    posterieurs.reverse();
    (lus, ecartes, posterieurs)
}

/// Ce que dit une lecture des mois posés après le mois du journal, non lus.
fn dire_posterieurs(posterieurs: &[String]) -> Option<String> {
    let (a, b) = (posterieurs.first()?, posterieurs.last()?);
    let n = posterieurs.len();
    Some(format!(
        "{n} mois posés après le mois du journal, non lus, de {a} à {b} / {n} month(s) placed after the log's \
         month, not read, {a} to {b}"
    ))
}

/// Le mois de l'horloge (UTC, comme les segments).
fn mois_de(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m").to_string()
}

/// Le plafond des lectures qui ne jugent pas la tête (traces en administrateur) : le mois de l'horloge, ou celui de
/// la tête lue telle quelle s'il est plus tard (une horloge sautée en avant a pu y écrire). Non jugée, la tête peut
/// mentir ; mais qui la change peut aussi bien retirer les segments, et ces lectures ne disent rien d'intact.
fn plafond_brut(dossier: &Path) -> String {
    let tete = crate::socle::lire_ordinaire(&dossier.join(TETE), 1 << 20)
        .ok()
        .and_then(|o| serde_json::from_slice::<Tete>(&o).ok())
        .map(|t| t.segment)
        .filter(|m| nom_de_segment(&format!("{m}.jsonl")).is_some());
    let horloge = mois_de(chrono::Utc::now());
    tete.map_or_else(|| horloge.clone(), |t| t.max(horloge.clone()))
}

/// Ce que dit une lecture bornée : les mois écartés (le plus ancien et le plus récent) et les événements laissés.
fn dire_ecartes(ecartes: &[String], laisses: usize) -> Option<String> {
    let mut morceaux = Vec::new();
    if let (Some(a), Some(b)) = (ecartes.first(), ecartes.last()) {
        morceaux.push(format!(
            "{} mois non lus, de {a} à {b} (lecture bornée) / {} month(s) not read, {a} to {b} (bounded read)",
            ecartes.len(),
            ecartes.len()
        ));
    }
    if laisses > 0 {
        morceaux.push(format!(
            "{laisses} événement(s) les plus anciens laissés (lecture bornée) / {laisses} oldest event(s) left out \
             (bounded read)"
        ));
    }
    (!morceaux.is_empty()).then(|| morceaux.join(" ; "))
}

/// Ajoute un événement aux plus récents gardés : au-delà de la borne, le plus ancien part, ce qui garde la mémoire
/// bornée sans perdre les derniers.
fn garder_recent(
    evenements: &mut std::collections::VecDeque<Evenement>,
    e: Evenement,
    max: usize,
    laisses: &mut usize,
) {
    if evenements.len() >= max {
        evenements.pop_front();
        *laisses += 1;
    }
    evenements.push_back(e);
}

/// Le mois le plus ancien gardé, `MOIS_GARDES` avant `mois` compris (« 2026-10 » → « 2025-10 »).
fn plus_ancien_garde(mois: &str) -> String {
    let annee: i32 = mois.get(..4).and_then(|a| a.parse().ok()).unwrap_or(0);
    let m: i32 = mois.get(5..).and_then(|a| a.parse().ok()).unwrap_or(1);
    let total = annee * 12 + (m - 1) - (MOIS_GARDES - 1);
    format!("{:04}-{:02}", total.div_euclid(12), total.rem_euclid(12) + 1)
}

/// Le mois d'après (« 2026-12 » → « 2027-01 »).
fn mois_suivant(mois: &str) -> String {
    let annee: i32 = mois.get(..4).and_then(|a| a.parse().ok()).unwrap_or(0);
    let m: i32 = mois.get(5..).and_then(|a| a.parse().ok()).unwrap_or(1);
    let total = annee * 12 + m;
    format!("{:04}-{:02}", total.div_euclid(12), total.rem_euclid(12) + 1)
}

/// La tête telle que les sceaux la rendent.
enum TeteLue {
    Absente,
    /// Lue ; `true` : scellée telle quelle au premier usage des sceaux.
    Lue(Box<Tete>, bool),
    /// Changée hors de Vanguard.
    Falsifiee,
    /// Ni crue ni prouvée changée : sceaux refaits, illisible. La raison suit.
    Douteuse(String),
}

fn tete_lue(dossier: &Path) -> TeteLue {
    use crate::sceau::Lecture as L;
    let lire = |o: &[u8], adoptee| {
        serde_json::from_slice(o).map_or_else(
            |e: serde_json::Error| TeteLue::Douteuse(e.to_string()),
            |t| TeteLue::Lue(Box::new(t), adoptee),
        )
    };
    match crate::sceau::lire_dans(dossier, TETE) {
        L::Absent => TeteLue::Absente,
        L::Intact(o) => lire(&o, false),
        L::Adopte(o) => lire(&o, true),
        L::Falsifie(_) => TeteLue::Falsifiee,
        L::Inconnu => TeteLue::Douteuse("sceaux refaits / seals rebuilt".into()),
        L::Illisible(e) => TeteLue::Douteuse(e),
    }
}

const TETE_FALSIFIEE: &str = "tête changée hors de Vanguard / head changed outside Vanguard";

/// Ajoute un segment à la fin d'un fichier, sans suivre de lien, réservé à son compte.
fn ajouter(chemin: &Path, octets: &[u8]) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = o.open(chemin)?;
    if !f.metadata()?.file_type().is_file() {
        return Err(std::io::Error::other("pas un simple fichier / not a plain file"));
    }
    // Un seul write : deux écrivains sous le verrou ne s'entrelacent pas, et sans verrou (pris ailleurs depuis plus
    // de 10 s) une ligne reste entière.
    f.write_all(octets)?;
    f.sync_data()
}

/// Note un événement dans le journal de `dossier`, daté par lui-même ; `maintenant` choisit le segment. Rend son
/// identifiant. Une fin qui n'est pas celle que la tête attendait est d'abord notée (`Rupture`), une autre version
/// que la dernière aussi (`Version`).
pub(crate) fn noter_dans(
    dossier: &Path,
    ev: Evenement,
    maintenant: chrono::DateTime<chrono::Utc>,
) -> std::io::Result<String> {
    let id = ev.id.clone();
    ecrire_dans(dossier, Some(ev), maintenant).map(|()| id)
}

// Les essais arrêtent l'écriture juste après l'ajout, comme un arrêt net du programme (`arret_entre_ajout_…`).
#[cfg(test)]
thread_local! {
    static ARRET_APRES_AJOUT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// L'écriture elle-même ; sans événement, seuls une rupture et un passage de version s'écrivent, s'il y en a.
fn ecrire_dans(
    dossier: &Path,
    ev: Option<Evenement>,
    maintenant: chrono::DateTime<chrono::Utc>,
) -> std::io::Result<()> {
    if !crate::socle::ecriture_sure(dossier) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "dossier d'un autre compte / another account's folder",
        ));
    }
    // Pendant un autotest, seul son propre événement d'essai s'écrit (`autotest::lecture_seule`).
    if crate::autotest::lecture_seule::active() && ev.as_ref().is_none_or(|e| !e.essai) {
        return Err(crate::autotest::lecture_seule::refus());
    }
    let _verrou = crate::socle::Verrou::prendre_nomme(dossier, VERROU);
    let rep = dossier.join(DOSSIER);
    std::fs::create_dir_all(&rep)?;
    let lue = tete_lue(dossier);
    // Les mois après celui de l'horloge (ou de la tête, si une horloge sautée en avant y a écrit) ne sont pas
    // suivis : un fichier posé au nom de 2099 ferait écrire là, et partir les vrais mois de la lecture bornée.
    let plafond = match &lue {
        TeteLue::Lue(t, _) => {
            let annonce = t.annonce.as_ref().map(|a| a.segment.clone()).unwrap_or_default();
            t.segment.clone().max(annonce).max(mois_de(maintenant))
        }
        _ => mois_de(maintenant),
    };
    let presents: Vec<(String, PathBuf)> = segments(&rep).into_iter().filter(|(m, _)| *m <= plafond).collect();
    let (dernier, octets) = match presents.last() {
        Some((m, chemin)) => (Some(m.clone()), crate::socle::lire_ordinaire(chemin, SEGMENT_MAX)?),
        None => (None, Vec::new()),
    };
    // Une horloge remise en arrière n'ouvre jamais un mois avant le dernier : la chaîne suit l'ordre des mois.
    let mois = match &dernier {
        Some(d) if *d > maintenant.format("%Y-%m").to_string() => d.clone(),
        _ => maintenant.format("%Y-%m").to_string(),
    };
    let reelles = lignes(&octets);
    let fin_reelle = reelles.last().map(|l| empreinte_ligne(l));

    let mut rupture = None;
    let mut tete = match lue {
        TeteLue::Lue(mut t, _) => {
            // Ce qui est là est jugé avant d'écrire : seule la fin de la tête, ou celle qu'elle annonçait, est de
            // Vanguard. Toute autre (des lignes ajoutées sans toucher la tête, une fin retirée) est une rupture
            // notée, et la tête repart du disque sans rien adopter en silence.
            match fin_trouvee(&t, dernier.as_deref(), reelles.len(), fin_reelle.as_deref()) {
                Fin::DeLaTete => {}
                Fin::Annoncee => {
                    // Un arrêt entre l'ajout et la tête : l'ajout annoncé est le nôtre, la tête le rattrape (et le
                    // mois qu'il closait, s'il est bien tel qu'annoncé).
                    let a = t
                        .annonce
                        .clone()
                        .unwrap_or_else(|| unreachable!("fin annoncée sans annonce"));
                    if let Some((m, c)) = a.clos {
                        let pareil = presents.iter().find(|(p, _)| *p == m).is_some_and(|(_, chemin)| {
                            crate::socle::lire_ordinaire(chemin, SEGMENT_MAX).is_ok_and(|o| {
                                empreinte_segment(&o) == c.empreinte && lignes(&o).len() as u64 == c.lignes
                            })
                        });
                        if pareil {
                            t.clos.insert(m, c);
                        } else {
                            rupture = Some((
                                format!("{m} : mois clos annoncé / announced closed month"),
                                format!("{} segment(s)", presents.len()),
                            ));
                        }
                    }
                    t.segment = a.segment;
                    t.lignes = a.lignes;
                    t.derniere = a.derniere;
                }
                Fin::Autre => {
                    rupture = Some((
                        format!("{} #{} {}", t.segment, t.lignes, t.derniere),
                        format!(
                            "{} #{} {}",
                            dernier.as_deref().unwrap_or("-"),
                            reelles.len(),
                            fin_reelle.as_deref().unwrap_or("-")
                        ),
                    ));
                }
            }
            t.annonce = None;
            *t
        }
        TeteLue::Absente if presents.is_empty() => Tete::default(),
        TeteLue::Absente => {
            rupture = Some((
                "tête absente / head missing".into(),
                format!("{} segment(s)", presents.len()),
            ));
            Tete::default()
        }
        TeteLue::Falsifiee => {
            rupture = Some((TETE_FALSIFIEE.into(), format!("{} segment(s)", presents.len())));
            Tete::default()
        }
        TeteLue::Douteuse(raison) => {
            rupture = Some((raison, format!("{} segment(s)", presents.len())));
            Tete::default()
        }
    };
    if rupture.is_some() {
        // La tête repart de ce qui est sur le disque : la rupture, elle, reste écrite.
        tete.clos.clear();
        for (m, chemin) in presents.iter().take(presents.len().saturating_sub(1)) {
            if let Ok(o) = crate::socle::lire_ordinaire(chemin, SEGMENT_MAX) {
                tete.clos.insert(
                    m.clone(),
                    Clos {
                        lignes: lignes(&o).len() as u64,
                        empreinte: empreinte_segment(&o),
                    },
                );
            }
        }
        tete.ancre = presents
            .first()
            .and_then(|(_, c)| crate::socle::lire_ordinaire(c, SEGMENT_MAX).ok())
            .and_then(|o| lignes(&o).first().and_then(|l| precedent_de(l)))
            .unwrap_or_default();
    }

    let mut a_ecrire = Vec::new();
    if let Some((attendu, trouve)) = rupture {
        a_ecrire.push(Evenement::nouveau(Source::Vanguard, Genre::Rupture { attendu, trouve }).gravite(Niveau::Eleve));
    }
    let version = env!("CARGO_PKG_VERSION");
    if tete.version != version {
        a_ecrire.push(Evenement::nouveau(
            Source::Vanguard,
            Genre::Version {
                de: Some(tete.version.clone()).filter(|v| !v.is_empty()),
                vers: version.to_string(),
            },
        ));
    }
    a_ecrire.extend(ev);
    if a_ecrire.is_empty() {
        return Ok(());
    }

    // La tête telle que le disque est avant l'ajout (après une rupture, celle refaite du disque) : c'est elle qui
    // porte l'annonce.
    tete.segment = dernier.clone().unwrap_or_default();
    tete.lignes = reelles.len() as u64;
    tete.derniere = fin_reelle.clone().unwrap_or_default();
    // Rotation : le mois d'avant est clos, et sa dernière empreinte devient l'ancre du nouveau.
    let mut n_courant = reelles.len() as u64;
    let mut prefixe_retour = !octets.is_empty() && !octets.ends_with(b"\n");
    let mut clos_ici = None;
    if let Some(d) = &dernier
        && *d != mois
    {
        clos_ici = Some((
            d.clone(),
            Clos {
                lignes: reelles.len() as u64,
                empreinte: empreinte_segment(&octets),
            },
        ));
        n_courant = 0;
        prefixe_retour = false;
    }
    let mut precedent = fin_reelle.unwrap_or_else(|| tete.ancre.clone());
    let mut a_ajouter = Vec::new();
    if prefixe_retour {
        a_ajouter.push(b'\n');
    }
    for mut e in a_ecrire {
        e.precedent = precedent;
        let ligne = serde_json::to_vec(&e).map_err(std::io::Error::other)?;
        precedent = empreinte_ligne(&ligne);
        a_ajouter.extend_from_slice(&ligne);
        a_ajouter.push(b'\n');
        n_courant += 1;
    }
    // Le mois en cours n'est jamais élagué : sans cette borne, un segment au-delà de ce que la lecture accepte ne
    // se relirait plus, et tout le mois (ses alertes comprises) disparaîtrait des lectures. Le refus, lui, va au
    // journal des erreurs par `noter`.
    let deja = if n_courant == 0 { 0 } else { octets.len() as u64 };
    if deja + a_ajouter.len() as u64 > SEGMENT_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            "journal du mois plein / month's log full",
        ));
    }
    // En deux temps : la fin à venir d'abord, scellée dans la tête, puis l'ajout, puis la tête qui le couvre.
    tete.annonce = Some(Annonce {
        segment: mois.clone(),
        lignes: n_courant,
        derniere: precedent.clone(),
        clos: clos_ici.clone(),
    });
    crate::sceau::ecrire_dans(
        dossier,
        TETE,
        &serde_json::to_vec(&tete).map_err(std::io::Error::other)?,
    )?;
    ajouter(&rep.join(format!("{mois}.jsonl")), &a_ajouter)?;
    #[cfg(test)]
    if ARRET_APRES_AJOUT.with(std::cell::Cell::get) {
        return Ok(());
    }
    tete.annonce = None;
    if let Some((m, c)) = clos_ici {
        tete.clos.insert(m, c);
    }
    tete.version = version.to_string();
    tete.segment.clone_from(&mois);
    tete.lignes = n_courant;
    tete.derniere = precedent;
    garder(&rep, &mois, &maintenant.format("%Y-%m").to_string(), &mut tete);
    crate::sceau::ecrire_dans(
        dossier,
        TETE,
        &serde_json::to_vec(&tete).map_err(std::io::Error::other)?,
    )
}

/// Retire les mois de plus de 13 mois, puis les plus vieux tant que le tout dépasse 20 Mo (jamais le mois en cours),
/// et retient l'ancre du plus ancien gardé. `courant` : le mois de l'horloge, jamais après `mois`.
fn garder(rep: &Path, mois: &str, courant: &str, tete: &mut Tete) {
    // Les mois posés après celui qu'on écrit ne sont ni comptés ni retirés : un faux de 40 Mo au nom de 2099 ferait
    // sinon partir tous les vrais mois d'avant, pour la limite de taille.
    let mut presents: Vec<(String, PathBuf, u64)> = segments(rep)
        .into_iter()
        .filter(|(m, _)| m.as_str() <= mois)
        .map(|(m, c)| {
            let t = std::fs::metadata(&c).map_or(0, |x| x.len());
            (m, c, t)
        })
        .collect();
    // L'âge ne se compte ni depuis le nom du segment (un fichier vide posé au nom de 9999-12 viderait tout), ni
    // au-delà du mois qui suit le dernier mois clos : une horloge sautée une fois en avant (pile de la carte mère,
    // NTP faux) ne vide pas l'historique d'un coup. Un vrai passage du temps les fait partir à l'écriture du mois
    // suivant ; la limite de taille, elle, tient toujours.
    let repere = presents
        .iter()
        .rev()
        .find(|p| p.0.as_str() < mois)
        .map(|p| mois_suivant(&p.0))
        .filter(|s| s.as_str() < mois)
        .unwrap_or_else(|| mois.to_string());
    let limite = plus_ancien_garde(repere.as_str().min(courant));
    let mut total: u64 = presents.iter().map(|p| p.2).sum();
    let mut retire = false;
    while let Some((m, c, t)) = presents.first().cloned() {
        if m == mois || (m >= limite && total <= OCTETS_GARDES) {
            break;
        }
        if std::fs::remove_file(&c).is_err() {
            break;
        }
        tete.clos.remove(&m);
        total = total.saturating_sub(t);
        presents.remove(0);
        retire = true;
    }
    if retire {
        tete.ancre = presents
            .first()
            .and_then(|(_, c, _)| crate::socle::lire_ordinaire(c, SEGMENT_MAX).ok())
            .and_then(|o| lignes(&o).first().and_then(|l| precedent_de(l)))
            .unwrap_or_default();
    }
}

/// Relit le journal de `dossier` et juge sa chaîne, sa tête et ses mois clos.
pub(crate) fn lire_dans(dossier: &Path) -> Lu {
    lire_borne(dossier, BORNES)
}

fn lire_borne(dossier: &Path, bornes: Bornes) -> Lu {
    let presents = segments(&dossier.join(DOSSIER));
    let lue = tete_lue(dossier);
    let tete_crue = matches!(lue, TeteLue::Lue(_, false));
    let (mut lecture, tete) = match lue {
        TeteLue::Absente if presents.is_empty() => {
            return Lu {
                lecture: Lecture::Vide,
                evenements: Vec::new(),
                illisibles: 0,
                verifies_des: 0,
            };
        }
        TeteLue::Absente => (Lecture::Falsifie("tête absente / head missing".into()), None),
        TeteLue::Falsifiee => (Lecture::Falsifie(TETE_FALSIFIEE.into()), None),
        TeteLue::Douteuse(r) => (Lecture::Incomplet(r), None),
        TeteLue::Lue(t, true) => (Lecture::Adopte, Some(t)),
        TeteLue::Lue(t, false) => (Lecture::Intact, Some(t)),
    };
    // Avec une tête crue, rien ne s'écrit après son mois : ce qui y est posé n'est pas de Vanguard.
    // Le mois qu'elle annonçait aussi (un arrêt entre l'ajout et la tête, au changement de mois).
    let plafond = match &tete {
        Some(t) if !t.segment.is_empty() => t
            .annonce
            .as_ref()
            .map_or_else(|| t.segment.clone(), |a| a.segment.clone().max(t.segment.clone())),
        _ => mois_de(chrono::Utc::now()),
    };
    let (presents, ecartes, posterieurs) = segments_bornes(presents, bornes, &plafond);
    let (evenements, illisibles, chaine, laisses) = relire(&presents, &ecartes, tete.as_deref(), bornes.evenements);
    lecture = lecture.pire(chaine);
    if let Some(r) = dire_posterieurs(&posterieurs) {
        lecture = lecture.pire(if tete.is_some() {
            Lecture::Falsifie(r)
        } else {
            Lecture::Incomplet(r)
        });
    }
    if let Some(r) = dire_ecartes(&ecartes, laisses) {
        lecture = lecture.pire(Lecture::Incomplet(r));
    }
    if illisibles > 0 {
        lecture = lecture.pire(Lecture::Incomplet(format!(
            "{illisibles} ligne(s) illisible(s) / unreadable line(s)"
        )));
    }
    let derniere_rupture = evenements.iter().rposition(|e| matches!(e.quoi, Genre::Rupture { .. }));
    if let Some(r) = derniere_rupture.map(|i| &evenements[i]) {
        lecture = lecture.pire(Lecture::Incomplet(format!(
            "rupture notée le / break recorded on {}",
            r.date_locale().unwrap_or_default()
        )));
    }
    let verifies_des = if tete_crue && !matches!(lecture, Lecture::Falsifie(_)) {
        derniere_rupture.map_or(0, |i| i + 1)
    } else {
        evenements.len()
    };
    Lu {
        lecture,
        evenements,
        illisibles,
        verifies_des,
    }
}

/// Les événements des segments (les `max` plus récents), le jugement de leur chaîne d'après la tête (`None` : sans
/// tête, seule la chaîne entre les lignes se juge) et le nombre d'événements laissés. `ecartes` : les mois présents
/// mais non lus (`segments_bornes`), qui ne sont pas « retirés », et devant lesquels l'ancre ne se juge pas.
fn relire(
    presents: &[(String, PathBuf)],
    ecartes: &[String],
    tete: Option<&Tete>,
    max: usize,
) -> (Vec<Evenement>, usize, Lecture, usize) {
    let mut lecture = Lecture::Intact;
    let mut evenements = std::collections::VecDeque::new();
    let mut laisses = 0;
    let mut illisibles = 0;
    let mut precedente: Option<String> = tete.filter(|_| ecartes.is_empty()).map(|t| t.ancre.clone());
    let dernier = presents.len().saturating_sub(1);
    if let Some(t) = tete {
        for m in t.clos.keys() {
            if !presents.iter().any(|(p, _)| p == m) && !ecartes.contains(m) {
                lecture = lecture.pire(Lecture::Falsifie(format!("{m} : mois retiré / month removed")));
            }
        }
    }
    for (i, (mois, chemin)) in presents.iter().enumerate() {
        let octets = match crate::socle::lire_ordinaire(chemin, SEGMENT_MAX) {
            Ok(o) => o,
            Err(e) => {
                lecture = lecture.pire(Lecture::Incomplet(format!("{mois} : {e}")));
                precedente = None;
                continue;
            }
        };
        let ls = lignes(&octets);
        if !octets.is_empty() && !octets.ends_with(b"\n") {
            lecture = lecture.pire(Lecture::Incomplet(format!(
                "{mois} : dernière ligne coupée / last line cut"
            )));
        }
        for (j, l) in ls.iter().enumerate() {
            match (precedent_de(l), &precedente) {
                (Some(p), Some(attendu)) if p != *attendu => {
                    lecture = lecture.pire(Lecture::Falsifie(format!(
                        "{mois} ligne/line {} : chaîne rompue / chain broken",
                        j + 1
                    )));
                }
                _ => {}
            }
            match serde_json::from_slice::<Evenement>(l) {
                Ok(e) => garder_recent(&mut evenements, e, max, &mut laisses),
                Err(_) => illisibles += 1,
            }
            precedente = Some(empreinte_ligne(l));
        }
        let Some(t) = tete else { continue };
        // Le mois qu'une écriture annoncée closait (arrêt entre l'ajout et la tête) : retenu tel qu'annoncé.
        let clos_annonce = t
            .annonce
            .as_ref()
            .and_then(|a| a.clos.as_ref())
            .filter(|(m, _)| m == mois)
            .map(|(_, c)| c);
        if i < dernier {
            match t.clos.get(mois).or(clos_annonce) {
                Some(c) if c.empreinte == empreinte_segment(&octets) && c.lignes == ls.len() as u64 => {}
                Some(_) => {
                    lecture = lecture.pire(Lecture::Falsifie(format!(
                        "{mois} : mois clos changé / closed month changed"
                    )));
                }
                None => {
                    lecture = lecture.pire(Lecture::Falsifie(format!(
                        "{mois} : mois inconnu de la tête / month unknown to the head"
                    )));
                }
            }
        } else {
            let fin = ls.last().map(|l| empreinte_ligne(l));
            match fin_trouvee(t, Some(mois), ls.len(), fin.as_deref()) {
                Fin::DeLaTete => {}
                // Annoncée et scellée avant l'ajout : de Vanguard, mais sa tête n'a pas suivi.
                Fin::Annoncee => {
                    lecture = lecture.pire(Lecture::Incomplet(
                        "fin écrite sans sa tête (arrêt pendant l'écriture ?) / end written without its head".into(),
                    ));
                }
                Fin::Autre if *mois != t.segment && t.annonce.as_ref().is_none_or(|a| a.segment != *mois) => {
                    lecture = lecture.pire(Lecture::Falsifie(format!(
                        "{mois} : pas le mois de la tête / not the head's month"
                    )));
                }
                // Des lignes en plus de la tête, même chaînées sur sa dernière : jamais annoncées, donc pas de
                // Vanguard ; une fin retirée ou changée aussi.
                Fin::Autre => {
                    lecture = lecture.pire(Lecture::Falsifie(format!(
                        "{mois} : fin différente de la tête (lignes ajoutées, retirées ou changées) / end differs from the head (lines added, removed or changed)"
                    )));
                }
            }
        }
    }
    (evenements.into(), illisibles, lecture, laisses)
}

/// Les événements de `dossier` sans juger la tête : ce que lisent les traces en administrateur dans le dossier d'un
/// compte, où juger écrirait les sceaux (`sceau::lire_dans` peut les adopter). Chaque segment est lu borné, sans
/// suivre de lien, et le tout aussi (`BORNES`) ; un segment illisible ou une lecture bornée est dit dans `manques`.
pub(crate) fn lire_sans_juger(dossier: &Path) -> (Vec<Evenement>, Vec<String>) {
    lire_sans_juger_borne(dossier, BORNES)
}

fn lire_sans_juger_borne(dossier: &Path, bornes: Bornes) -> (Vec<Evenement>, Vec<String>) {
    let mut evenements = std::collections::VecDeque::new();
    let mut laisses = 0;
    let mut manques = Vec::new();
    let (lus, ecartes, posterieurs) = segments_bornes(segments(&dossier.join(DOSSIER)), bornes, &plafond_brut(dossier));
    for (mois, chemin) in lus {
        match crate::socle::lire_ordinaire(&chemin, SEGMENT_MAX) {
            Ok(o) => {
                for e in lignes(&o)
                    .into_iter()
                    .filter_map(|l| serde_json::from_slice::<Evenement>(l).ok())
                {
                    garder_recent(&mut evenements, e, bornes.evenements, &mut laisses);
                }
            }
            Err(e) => manques.push(format!("{DOSSIER}/{mois}.jsonl : {e}")),
        }
    }
    manques.extend(dire_ecartes(&ecartes, laisses));
    manques.extend(dire_posterieurs(&posterieurs));
    (evenements.into(), manques)
}

/// Les fichiers du journal sous le dossier de données (« evenements/2026-10.jsonl », la tête), pour les recopier
/// tels quels.
pub(crate) fn fichiers(dossier: &Path) -> Vec<String> {
    // Bornés comme la lecture : les traces n'en recopient pas plus qu'elles n'en liraient.
    let mut f: Vec<String> = segments_bornes(segments(&dossier.join(DOSSIER)), BORNES, &plafond_brut(dossier))
        .0
        .into_iter()
        .map(|(mois, _)| format!("{DOSSIER}/{mois}.jsonl"))
        .collect();
    f.push(TETE.to_string());
    f
}

/// Note un événement dans le journal de cet ordinateur. Un échec ne retient jamais ce qui l'a causé (l'alerte est
/// notifiée, le geste fait) : il va au journal des erreurs. Rend l'identifiant noté.
pub(crate) fn noter(ev: Evenement) -> Option<String> {
    let dossier = crate::socle::dossier_local();
    // En administrateur dans le dossier d'un compte (sudo -E), rien n'est écrit, exprès (comme les sceaux) : ce
    // n'est pas une panne à rapporter.
    if !crate::socle::ecriture_sure(&dossier) {
        return None;
    }
    match noter_dans(&dossier, ev, chrono::Utc::now()) {
        Ok(id) => Some(id),
        Err(e) => {
            super::Echec::io("evenements/noter", &e).journaliser();
            None
        }
    }
}

/// Ce que le bilan dit du journal (règle COM-ETA-001) : la tête scellée peut être intacte alors qu'une ligne a été
/// retirée au milieu ; seul le journal relu le voit, et le tableau, lui, montre les alertes qui restent sans rien
/// dire.
pub(crate) fn constat() -> Option<crate::machine::Constat> {
    let lu = lire();
    constat_de(&lu.lecture).or_else(|| constat_de_rupture(&lu.evenements, chrono::Utc::now()))
}

/// Une rupture se dit au bilan un mois : la tête est repartie du disque, et ce qui la précède (des lignes ajoutées,
/// retirées ou changées hors de Vanguard, ou une écriture coupée net) n'est pas vérifié. Sans cela, le « falsifié »
/// d'avant la rupture devenait un simple « incomplet » dès l'écriture suivante, sans plus rien dire.
const RUPTURE_DITE_JOURS: i64 = 30;

fn constat_de_rupture(
    evenements: &[Evenement],
    maintenant: chrono::DateTime<chrono::Utc>,
) -> Option<crate::machine::Constat> {
    let limite = (maintenant - chrono::Duration::days(RUPTURE_DITE_JOURS))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    // Jamais après maintenant : une rupture datée de l'avenir (horloge avancée) ne tiendrait l'alerte que plus longtemps.
    let apres = maintenant.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let r = evenements
        .iter()
        .rev()
        .find(|e| matches!(e.quoi, Genre::Rupture { .. }) && e.quand >= limite && e.quand <= apres)?;
    let quand = r.date_locale().unwrap_or_default();
    Some(
        crate::machine::alerte(
            crate::sceau::CAT,
            Niveau::Eleve,
            trf!(
                "Le journal des événements a été rompu le {quand} : sa fin n'était pas celle que Vanguard avait écrite (lignes ajoutées, retirées ou changées hors de Vanguard, ou écriture coupée net). Ce qui précède la rupture n'est pas tenu pour vérifié.",
                "The event log was broken on {quand}: its end was not the one Vanguard had written (lines added, removed or changed outside Vanguard, or a write cut short). What comes before the break is not taken as verified."
            ),
        )
        .manuel(
            tr!(
                "« vanguard evenements » montre la rupture ; regardez ce qui tourne sous votre compte (Protection › Qui parle à Internet ?)",
                "“vanguard events” shows the break; look at what runs under your account (Protection › Who talks to the Internet?)"
            ),
            &[],
        ),
    )
}

fn constat_de(l: &Lecture) -> Option<crate::machine::Constat> {
    let Lecture::Falsifie(r) = l else { return None };
    Some(
        crate::machine::alerte(
            crate::sceau::CAT,
            Niveau::Eleve,
            trf!(
                "Le journal des événements a été changé hors de Vanguard ({}) : ses alertes ne sont pas tenues pour vérifiées. Un programme qui tourne sous votre compte a pu retirer celles qui le gênaient.",
                "The event log was changed outside Vanguard ({}): its alerts are not taken as verified. A program running under your account may have removed the ones in its way.",
                crate::ui::affichable(r)
            ),
        )
        .manuel(
            tr!(
                "« vanguard evenements » dit où ; regardez ce qui tourne sous votre compte (Protection › Qui parle à Internet ?)",
                "“vanguard events” says where; look at what runs under your account (Protection › Who talks to the Internet?)"
            ),
            &[],
        ),
    )
}

/// Le journal de cet ordinateur, jugé.
pub(crate) fn lire() -> Lu {
    lire_dans(&crate::socle::dossier_local())
}

/// Note le passage de version s'il y en a un, sans autre événement : appelé au début de chaque passe de la
/// surveillance, pour qu'une mise à jour se lise à son heure et non à la prochaine alerte.
pub(crate) fn noter_version() {
    let dossier = crate::socle::dossier_local();
    if !crate::socle::ecriture_sure(&dossier) {
        return;
    }
    if let TeteLue::Lue(t, _) = tete_lue(&dossier)
        && t.version == env!("CARGO_PKG_VERSION")
    {
        return;
    }
    if let Err(e) = ecrire_dans(&dossier, None, chrono::Utc::now()) {
        super::Echec::io("evenements/version", &e).journaliser();
    }
}

/// Le plus récent événement de moins de `fenetre` qui répond à `filtre` : la cause d'un geste (l'alerte qui parle
/// du même objet), l'Action d'une alerte de blocage. Seulement le mois en cours et le précédent, jamais un mois
/// d'après celui de l'horloge ni un événement daté après maintenant : un segment posé au nom de 2099 reliait sinon un
/// geste à une fausse cause, et la vraie n'était plus trouvée.
pub(crate) fn dernier(filtre: impl Fn(&Evenement) -> bool, fenetre: chrono::Duration) -> Option<String> {
    dernier_dans(&crate::socle::dossier_local(), filtre, fenetre, chrono::Utc::now())
}

fn dernier_dans(
    dossier: &Path,
    filtre: impl Fn(&Evenement) -> bool,
    fenetre: chrono::Duration,
    maintenant: chrono::DateTime<chrono::Utc>,
) -> Option<String> {
    let limite = (maintenant - fenetre).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let apres = maintenant.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let plafond = mois_de(maintenant);
    let presents = segments(&dossier.join(DOSSIER));
    presents
        .iter()
        .rev()
        .filter(|(mois, _)| *mois <= plafond)
        .take(2)
        .find_map(|(_, chemin)| {
            let o = crate::socle::lire_ordinaire(chemin, SEGMENT_MAX).ok()?;
            lignes(&o)
                .into_iter()
                .rev()
                .filter_map(|l| serde_json::from_slice::<Evenement>(l).ok())
                .filter(|e| e.quand <= apres)
                .take_while(|e| e.quand >= limite)
                .find(|e| !e.essai && filtre(e))
                .map(|e| e.id)
        })
}

/// Le fil d'un incident : l'événement `id`, ce qui l'a causé en remontant, et ce qu'il a causé, dans l'ordre du
/// journal.
pub(crate) fn incident<'a>(evenements: &'a [Evenement], id: &str) -> Vec<&'a Evenement> {
    let par_id: BTreeMap<&str, &Evenement> = evenements.iter().map(|e| (e.id.as_str(), e)).collect();
    // La racine : on remonte les causes (borné, un cycle écrit à la main ne fige rien).
    let mut racine = id;
    for _ in 0..64 {
        match par_id.get(racine).and_then(|e| e.cause.as_deref()) {
            Some(c) if par_id.contains_key(c) => racine = c,
            _ => break,
        }
    }
    let mut dans: std::collections::BTreeSet<&str> = [racine].into();
    // Les descendants : un passage dans l'ordre suffit, une cause est toujours écrite avant ce qu'elle cause.
    for e in evenements {
        if e.cause.as_deref().is_some_and(|c| dans.contains(c)) {
            dans.insert(&e.id);
        }
    }
    evenements.iter().filter(|e| dans.contains(e.id.as_str())).collect()
}

/// Les alertes du journal, de la plus ancienne à la plus récente : (événement, famille, titre, texte). Les essais
/// n'en sont pas.
pub(crate) fn alertes(evenements: &[Evenement]) -> impl Iterator<Item = (&Evenement, &str, &str, &str)> {
    evenements.iter().filter(|e| !e.essai).filter_map(|e| match &e.quoi {
        Genre::Alerte { famille, titre, texte } => Some((e, famille.as_str(), titre.as_str(), texte.as_str())),
        _ => None,
    })
}

/// Les gestes encore en place : une Action réussie qu'aucune Annulation ne vise.
#[cfg_attr(not(test), allow(dead_code))] // le lot 6 (anti-rançongiciel) s'en servira pour ce qu'il a posé
pub(crate) fn en_place(evenements: &[Evenement]) -> Vec<&Evenement> {
    let annules: std::collections::BTreeSet<&str> = evenements
        .iter()
        .filter(|e| matches!(e.quoi, Genre::Annulation { .. }))
        .filter_map(|e| e.cause.as_deref())
        .collect();
    evenements
        .iter()
        .filter(|e| matches!(e.quoi, Genre::Action { reussi: true, .. }) && !annules.contains(e.id.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn le(texte: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(texte)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    /// Un dossier neuf à chaque appel, jamais celui d'un essai d'avant. Le dossier jetable des tests est sous le
    /// dossier temporaire, que d'autres tests parcourent en même temps (sous Windows, `nettoyer` en mesure la taille :
    /// une poignée par dossier et par fichier). Sous Wine, effacer un fichier ou un dossier ouvert ailleurs ne fait que
    /// le marquer « à effacer » : il reste là, illisible, jusqu'à la dernière poignée. Le même nom repris d'un cas de
    /// proptest au suivant gardait alors la tête du cas d'avant, illisible : la première écriture notait une rupture,
    /// et le journal neuf se lisait « Incomplet ».
    fn dossier(nom: &str) -> PathBuf {
        static ESSAIS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = ESSAIS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = crate::socle::dossier_local().join(format!("essai-journal-{nom}-{n}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // Rien d'avant : un reste se dit ici, pas plus loin comme une rupture du journal.
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "{} pas vide", d.display());
        d
    }

    fn alerte(n: usize, quand: &str) -> Evenement {
        Evenement::le(
            Source::Surveillance,
            Genre::Alerte {
                famille: "port".into(),
                titre: format!("alerte {n}"),
                texte: "x".into(),
            },
            le(quand),
        )
        .cle(Some(&format!("port|{n}")))
    }

    fn remplir(d: &Path, n: usize, quand: &str) {
        for i in 0..n {
            noter_dans(d, alerte(i, quand), le(quand)).unwrap();
        }
    }

    fn segment(d: &Path, mois: &str) -> PathBuf {
        d.join(DOSSIER).join(format!("{mois}.jsonl"))
    }

    #[test]
    fn vide_puis_intact() {
        let d = dossier("intact");
        assert_eq!(lire_dans(&d).lecture, Lecture::Vide);
        remplir(&d, 3, "2026-10-23T10:00:00Z");
        let lu = lire_dans(&d);
        assert_eq!(lu.lecture, Lecture::Intact, "{lu:?}");
        // Le passage de version est noté avant le premier événement, une fois.
        assert_eq!(lu.evenements.len(), 4);
        assert!(matches!(&lu.evenements[0].quoi, Genre::Version { de: None, .. }));
        assert_eq!(alertes(&lu.evenements).count(), 3);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(segment(&d, "2026-10")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une autre version qui écrit : son passage est noté, avec la version d'avant.
    #[test]
    fn passage_de_version_note() {
        let d = dossier("version");
        remplir(&d, 1, "2026-10-23T10:00:00Z");
        let mut t: Tete = match crate::sceau::lire_dans(&d, TETE) {
            crate::sceau::Lecture::Intact(o) => serde_json::from_slice(&o).unwrap(),
            autre => panic!("{autre:?}"),
        };
        t.version = "0.1.0".into();
        crate::sceau::ecrire_dans(&d, TETE, &serde_json::to_vec(&t).unwrap()).unwrap();
        remplir(&d, 1, "2026-10-23T11:00:00Z");
        let lu = lire_dans(&d);
        assert_eq!(lu.lecture, Lecture::Intact);
        let versions: Vec<_> = lu
            .evenements
            .iter()
            .filter_map(|e| match &e.quoi {
                Genre::Version { de, .. } => Some(de.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(versions, vec![None, Some("0.1.0".to_string())]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La rotation : le mois clos est scellé dans la tête, le premier `precedent` du mois suivant est la dernière
    /// empreinte du mois clos ; plus de 13 mois, le plus vieux part et l'ancre suit.
    #[test]
    fn rotation_et_garde() {
        let d = dossier("rotation");
        remplir(&d, 2, "2025-08-15T10:00:00Z");
        remplir(&d, 2, "2025-09-15T10:00:00Z");
        let aout = std::fs::read(segment(&d, "2025-08")).unwrap();
        let sept = std::fs::read(segment(&d, "2025-09")).unwrap();
        let derniere_aout = empreinte_ligne(lignes(&aout).last().unwrap());
        assert_eq!(precedent_de(lignes(&sept)[0]).unwrap(), derniere_aout);
        assert_eq!(lire_dans(&d).lecture, Lecture::Intact);
        // Octobre puis novembre 2026 : août 2025 a plus de 13 mois, septembre aussi.
        remplir(&d, 1, "2026-10-01T10:00:00Z");
        // Un an sans écriture : les vieux mois ne partent qu'à l'écriture du mois suivant (une horloge sautée en
        // avant ne vide rien d'un coup).
        assert!(segment(&d, "2025-08").exists());
        remplir(&d, 1, "2026-11-01T10:00:00Z");
        assert!(!segment(&d, "2025-08").exists() && !segment(&d, "2025-09").exists());
        assert_eq!(lire_dans(&d).lecture, Lecture::Intact);
        assert_eq!(plus_ancien_garde("2026-10"), "2025-10");
        assert_eq!(plus_ancien_garde("2026-01"), "2025-01");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une horloge remise en arrière : on continue le dernier mois, la chaîne reste dans l'ordre.
    #[test]
    fn horloge_en_arriere() {
        let d = dossier("horloge");
        remplir(&d, 1, "2026-11-02T10:00:00Z");
        remplir(&d, 1, "2026-10-30T10:00:00Z");
        assert!(!segment(&d, "2026-10").exists());
        assert_eq!(lire_dans(&d).lecture, Lecture::Intact);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un fichier vide posé au nom d'un mois lointain par un programme qui ne connaît pas la chaîne : la rupture
    /// est notée, mais les vrais mois restent sur le disque (l'âge ne se compte pas depuis ce nom).
    #[test]
    fn mois_futur_pose_ne_vide_pas_l_historique() {
        let d = dossier("futur");
        remplir(&d, 1, "2025-12-15T10:00:00Z");
        remplir(&d, 1, "2026-10-01T10:00:00Z");
        std::fs::write(segment(&d, "9999-12"), b"").unwrap();
        remplir(&d, 1, "2026-10-23T10:00:00Z");
        assert!(segment(&d, "2025-12").exists() && segment(&d, "2026-10").exists());
        let lu = lire_dans(&d);
        assert_ne!(lu.lecture, Lecture::Intact);
        assert_eq!(alertes(&lu.evenements).count(), 3);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une horloge sautée une fois en avant (pile de la carte mère, NTP faux) : l'historique ne part pas d'un coup.
    #[test]
    fn horloge_en_avance_ne_purge_pas() {
        let d = dossier("avance");
        remplir(&d, 2, "2025-12-15T10:00:00Z");
        remplir(&d, 2, "2026-10-01T10:00:00Z");
        remplir(&d, 1, "2030-01-15T10:00:00Z");
        let mois: Vec<String> = segments(&d.join(DOSSIER)).into_iter().map(|(m, _)| m).collect();
        assert_eq!(mois, ["2025-12", "2026-10", "2030-01"]);
        let lu = lire_dans(&d);
        assert_eq!(lu.lecture, Lecture::Intact, "{lu:?}");
        assert_eq!(alertes(&lu.evenements).count(), 5);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un segment en cours qui atteindrait la taille au-delà de laquelle il ne se relit plus : l'écriture est
    /// refusée (et dite par `noter`), le mois reste lisible en entier.
    #[test]
    fn segment_plein_refuse_sans_cacher_le_mois() {
        let d = dossier("plein");
        let q = "2026-10-23T10:00:00Z";
        let gros = Evenement::le(
            Source::Surveillance,
            Genre::Alerte {
                famille: "port".into(),
                titre: "alerte 0".into(),
                texte: "x".repeat(usize::try_from(SEGMENT_MAX).unwrap() - 4096),
            },
            le(q),
        );
        noter_dans(&d, gros, le(q)).unwrap();
        let mut suivante = alerte(1, q);
        if let Genre::Alerte { texte, .. } = &mut suivante.quoi {
            *texte = "x".repeat(8192);
        }
        assert!(noter_dans(&d, suivante, le(q)).is_err());
        let lu = lire_dans(&d);
        assert_eq!(lu.lecture, Lecture::Intact, "{:?}", lu.lecture);
        assert_eq!(alertes(&lu.evenements).count(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Des centaines de segments déposés à côté du journal : la lecture ne charge que les mois les plus récents
    /// permis, garde le mois en cours, et dit ce qu'elle n'a pas lu, au lieu de tout charger jusqu'à tomber.
    #[test]
    fn lecture_bornee_en_tout() {
        let d = dossier("borne");
        remplir(&d, 1, "2026-10-23T10:00:00Z");
        let ligne = serde_json::to_string(&alerte(7, "2000-01-01T00:00:00Z")).unwrap() + "\n";
        for i in 0..300 {
            let mois = format!("{:04}-{:02}", 2000 + i / 12, i % 12 + 1);
            std::fs::write(segment(&d, &mois), &ligne).unwrap();
        }
        let lu = lire_dans(&d);
        assert!(lu.evenements.len() <= 2 * BORNES.mois, "{}", lu.evenements.len());
        assert!(alertes(&lu.evenements).any(|(_, _, t, _)| t == "alerte 0"));
        assert_ne!(lu.lecture, Lecture::Intact);
        let (evenements, manques) = lire_sans_juger(&d);
        assert!(evenements.len() <= 2 * BORNES.mois, "{}", evenements.len());
        assert!(manques.iter().any(|m| m.contains("non lus")), "{manques:?}");
        assert!(fichiers(&d).len() <= BORNES.mois + 1);
        // Le nombre d'événements et les octets aussi : les plus récents restent, l'écart est dit.
        let d2 = dossier("borne-evenements");
        remplir(&d2, 2, "2026-09-23T10:00:00Z");
        remplir(&d2, 5, "2026-10-23T10:00:00Z");
        let peu = Bornes {
            evenements: 3,
            ..BORNES
        };
        let lu = lire_borne(&d2, peu);
        assert_eq!(lu.evenements.len(), 3);
        assert!(alertes(&lu.evenements).any(|(_, _, t, _)| t == "alerte 4"));
        assert!(
            matches!(&lu.lecture, Lecture::Incomplet(r) if r.contains("laissés")),
            "{:?}",
            lu.lecture
        );
        let octets = std::fs::metadata(segment(&d2, "2026-10")).unwrap().len();
        let lu = lire_borne(&d2, Bornes { octets, ..BORNES });
        assert!(
            matches!(&lu.lecture, Lecture::Incomplet(r) if r.contains("2026-09")),
            "{:?}",
            lu.lecture
        );
        assert_eq!(alertes(&lu.evenements).count(), 5);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&d2);
    }

    /// Des mois « futurs » déposés à côté du journal (petits et nombreux, ou un seul presque à la taille permise) :
    /// sans plafond, ils remplissaient les bornes de la lecture et le vrai mois en cours, celui de l'incident,
    /// n'était plus lu ni recopié dans les traces.
    #[test]
    fn mois_futurs_deposes_ne_cachent_pas_le_mois_en_cours() {
        let futurs: Vec<String> = (0..14)
            .map(|i| format!("{:04}-{:02}", 2099 + i / 12, i % 12 + 1))
            .collect();
        for (nom, gros) in [("futurs-nombreux", false), ("futur-gros", true)] {
            let d = dossier(nom);
            remplir(&d, 1, "2026-09-23T10:00:00Z");
            remplir(&d, 3, "2026-10-23T10:00:00Z");
            if gros {
                // Creux : la taille seule compte pour les bornes, rien n'est écrit sur le disque.
                std::fs::File::create(segment(&d, "2099-01"))
                    .unwrap()
                    .set_len(SEGMENT_MAX - 64)
                    .unwrap();
            } else {
                for m in &futurs {
                    std::fs::write(segment(&d, m), b"").unwrap();
                }
            }
            let verifier = |d: &Path| {
                let lu = lire_dans(d);
                assert_eq!(alertes(&lu.evenements).count(), 4, "{nom} : {lu:?}");
                assert!(
                    matches!(&lu.lecture, Lecture::Falsifie(r) if r.contains("2099-01")),
                    "{nom} : {:?}",
                    lu.lecture
                );
                let (evenements, manques) = lire_sans_juger(d);
                assert_eq!(alertes(&evenements).count(), 4, "{nom}");
                assert!(manques.iter().any(|m| m.contains("2099-01")), "{nom} : {manques:?}");
                let f = fichiers(d);
                assert!(f.contains(&format!("{DOSSIER}/2026-10.jsonl")), "{nom} : {f:?}");
                assert!(!f.iter().any(|x| x.contains("2099-")), "{nom} : {f:?}");
            };
            verifier(&d);
            // Une écriture après le dépôt ne suit pas les faux mois : elle reste dans le mois en cours, et
            // l'élagage ne compte pas leur taille (un faux de 40 Mo aurait fait partir les vrais mois).
            remplir(&d, 1, "2026-10-23T11:00:00Z");
            assert!(segment(&d, "2026-09").exists(), "{nom}");
            let lu = lire_dans(&d);
            assert_eq!(alertes(&lu.evenements).count(), 5, "{nom} : {lu:?}");
            assert!(
                matches!(&lu.lecture, Lecture::Falsifie(r) if r.contains("2099-01")),
                "{nom}"
            );
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// Une ligne retirée au milieu sans toucher la tête : la tête scellée reste intacte, seul le journal relu le
    /// voit ; le bilan doit le dire.
    #[test]
    fn chaine_rompue_dite_au_bilan() {
        let d = dossier("bilan");
        remplir(&d, 3, "2026-10-23T10:00:00Z");
        let s = segment(&d, "2026-10");
        let o = std::fs::read(&s).unwrap();
        let mut ls = lignes(&o);
        ls.remove(1);
        let sans: Vec<u8> = ls.iter().flat_map(|l| l.iter().copied().chain(*b"\n")).collect();
        std::fs::write(&s, sans).unwrap();
        assert!(matches!(
            crate::sceau::lire_dans(&d, TETE),
            crate::sceau::Lecture::Intact(_)
        ));
        let lu = lire_dans(&d);
        assert!(matches!(lu.lecture, Lecture::Falsifie(_)), "{:?}", lu.lecture);
        assert!(constat_de(&lu.lecture).is_some());
        assert!(constat_de(&Lecture::Intact).is_none());
        assert!(constat_de(&Lecture::Vide).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une fin retirée puis une nouvelle écriture : la rupture est notée dans le journal, qui ne s'en remet pas en
    /// silence.
    #[test]
    fn rupture_notee_a_l_ecriture() {
        let d = dossier("rupture");
        remplir(&d, 3, "2026-10-23T10:00:00Z");
        let s = segment(&d, "2026-10");
        let o = std::fs::read(&s).unwrap();
        let ls = lignes(&o);
        let tronque: Vec<u8> = ls[..ls.len() - 1]
            .iter()
            .flat_map(|l| l.iter().copied().chain(*b"\n"))
            .collect();
        std::fs::write(&s, tronque).unwrap();
        assert!(matches!(lire_dans(&d).lecture, Lecture::Falsifie(_)));
        remplir(&d, 1, "2026-10-23T11:00:00Z");
        let lu = lire_dans(&d);
        assert!(
            matches!(&lu.lecture, Lecture::Incomplet(r) if r.contains("rupture")),
            "{:?}",
            lu.lecture
        );
        assert!(lu.evenements.iter().any(|e| matches!(e.quoi, Genre::Rupture { .. })));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Des lignes ajoutées à la fin par un autre programme, chaînées sur la vraie dernière, sans toucher la tête ni
    /// les sceaux : falsifié tout de suite (jamais « incomplet » sans alerte), puis, à l'écriture suivante, une rupture
    /// notée et dite au bilan, jamais une reprise en silence qui se relirait « intacte ». La déduplication ne s'y fie
    /// pas : la ligne forgée n'est pas parmi les événements vérifiés.
    #[test]
    fn lignes_ajoutees_a_la_fin_jamais_adoptees() {
        let d = dossier("ajout-fin");
        remplir(&d, 2, "2026-10-23T10:00:00Z");
        let s = segment(&d, "2026-10");
        let o = std::fs::read(&s).unwrap();
        let mut forgee = alerte(99, "2026-10-23T10:30:00Z");
        forgee.precedent = empreinte_ligne(lignes(&o).last().unwrap());
        let mut ligne = serde_json::to_vec(&forgee).unwrap();
        ligne.push(b'\n');
        ajouter(&s, &ligne).unwrap();
        let lu = lire_dans(&d);
        assert!(matches!(lu.lecture, Lecture::Falsifie(_)), "{:?}", lu.lecture);
        assert!(constat_de(&lu.lecture).is_some());
        assert_eq!(lu.verifies(), &[] as &[Evenement]);
        // Une écriture ordinaire : la rupture est notée, rien n'est repris comme de Vanguard.
        remplir(&d, 1, "2026-10-23T11:00:00Z");
        let lu = lire_dans(&d);
        assert_ne!(lu.lecture, Lecture::Intact, "{:?}", lu.lecture);
        assert!(lu.evenements.iter().any(|e| matches!(e.quoi, Genre::Rupture { .. })));
        // La rupture est datée par l'horloge : dite un mois après, jamais avant elle.
        let quand = lu
            .evenements
            .iter()
            .find(|e| matches!(e.quoi, Genre::Rupture { .. }))
            .map(|e| le(&e.quand))
            .unwrap();
        assert!(constat_de_rupture(&lu.evenements, quand + chrono::Duration::days(1)).is_some());
        assert!(constat_de_rupture(&lu.evenements, quand + chrono::Duration::days(60)).is_none());
        assert!(constat_de_rupture(&lu.evenements, quand - chrono::Duration::days(1)).is_none());
        assert!(
            !alertes(lu.verifies()).any(|(e, ..)| e.cle.as_deref() == Some("port|99")),
            "la ligne forgée passe pour vérifiée"
        );
        assert_eq!(
            alertes(lu.verifies()).count(),
            1,
            "l'alerte d'après la rupture est vérifiée"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un arrêt entre l'ajout et la tête qui le suit : la fin est celle que la tête annonçait, scellée avant l'ajout.
    /// Elle est de Vanguard : lue « incomplète » sans alerte, reprise sans rupture à l'écriture suivante, y compris
    /// quand cette écriture ouvrait un nouveau mois.
    #[test]
    fn arret_entre_ajout_et_tete_repris_sans_rupture() {
        for (avant, apres) in [
            ("2026-10-23T10:00:00Z", "2026-10-23T11:00:00Z"),
            ("2026-09-30T10:00:00Z", "2026-10-01T10:00:00Z"),
        ] {
            let d = dossier("annonce");
            remplir(&d, 2, avant);
            // L'écriture annoncée, scellée, puis l'ajout ; la tête finale manque : arrêt juste après l'ajout, dans la
            // vraie écriture (l'annonce est celle qu'elle a scellée).
            ARRET_APRES_AJOUT.with(|a| a.set(true));
            let r = noter_dans(&d, alerte(7, apres), le(apres));
            ARRET_APRES_AJOUT.with(|a| a.set(false));
            r.unwrap();
            assert!(
                matches!(tete_lue(&d), TeteLue::Lue(t, _) if t.annonce.is_some()),
                "l'annonce n'est pas dans la tête"
            );
            let lu = lire_dans(&d);
            assert!(
                matches!(&lu.lecture, Lecture::Incomplet(r) if r.contains("sans sa tête")),
                "{avant} : {:?}",
                lu.lecture
            );
            assert!(constat_de(&lu.lecture).is_none());
            remplir(&d, 1, apres);
            let lu = lire_dans(&d);
            assert_eq!(lu.lecture, Lecture::Intact, "{avant} : {:?}", lu.evenements);
            assert_eq!(lu.verifies().len(), lu.evenements.len());
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// Une ligne coupée par un arrêt : elle reste dans la chaîne, illisible ; la ligne suivante commence sur une
    /// nouvelle ligne. Rien ne l'annonçait telle quelle : c'est une rupture, notée.
    #[test]
    fn ligne_coupee_reste_dans_la_chaine() {
        let d = dossier("coupee");
        remplir(&d, 1, "2026-10-23T10:00:00Z");
        let s = segment(&d, "2026-10");
        ajouter(&s, b"{\"v\":1,\"id\":\"coup").unwrap();
        remplir(&d, 1, "2026-10-23T11:00:00Z");
        let lu = lire_dans(&d);
        assert_eq!(lu.illisibles, 1);
        assert_eq!(alertes(&lu.evenements).count(), 2);
        // Une ligne illisible : le journal n'est pas entier, jamais dit intact.
        assert!(matches!(lu.lecture, Lecture::Incomplet(_)), "{:?}", lu.lecture);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// T14 : détection → preuve → blocage → annulation, reliés par `cause` ; le fil se remonte de n'importe lequel.
    #[test]
    #[allow(clippy::many_single_char_names)] // a, p, b : l'alerte, la preuve, le blocage, lus dans l'ordre du fil
    fn fil_d_un_incident() {
        let d = dossier("incident");
        let q = "2026-10-23T10:00:00Z";
        let a = noter_dans(&d, alerte(1, q).cle(Some("botnet|203.0.113.7:443")), le(q)).unwrap();
        let p = noter_dans(
            &d,
            Evenement::le(
                Source::Blocage,
                Genre::Preuve {
                    releve: crate::protection::preuve::Preuve::default(),
                },
                le(q),
            )
            .cause(Some(&a)),
            le(q),
        )
        .unwrap();
        let b = noter_dans(
            &d,
            Evenement::action(Source::Blocage, "bloqué", true, &[]).cause(Some(&p)),
            le(q),
        )
        .unwrap();
        let autre = noter_dans(&d, alerte(2, q), le(q)).unwrap();
        let lu = lire_dans(&d);
        assert_eq!(en_place(&lu.evenements).len(), 1);
        noter_dans(
            &d,
            Evenement::le(
                Source::Utilisateur,
                Genre::Annulation {
                    objet: "b1".into(),
                    supprime: false,
                },
                le(q),
            )
            .cause(Some(&b)),
            le(q),
        )
        .unwrap();
        let lu = lire_dans(&d);
        assert_eq!(en_place(&lu.evenements), Vec::<&Evenement>::new());
        for depart in [&a, &p, &b] {
            let fil: Vec<&str> = incident(&lu.evenements, depart)
                .iter()
                .map(|e| e.quoi.sorte())
                .collect();
            assert_eq!(fil, ["alerte", "preuve", "action", "annulation"]);
        }
        assert_eq!(incident(&lu.evenements, &autre).len(), 1);
        // Chaque Action a une cause qui est une Preuve ; chaque Annulation pointe une Action.
        let par_id: BTreeMap<&str, &Evenement> = lu.evenements.iter().map(|e| (e.id.as_str(), e)).collect();
        for e in &lu.evenements {
            let cause = e.cause.as_deref().and_then(|c| par_id.get(c));
            match e.quoi {
                Genre::Action { .. } => assert!(matches!(cause.map(|c| &c.quoi), Some(Genre::Preuve { .. }))),
                Genre::Annulation { .. } => assert!(matches!(cause.map(|c| &c.quoi), Some(Genre::Action { .. }))),
                _ => {}
            }
        }
        // La cause d'un geste se retrouve par ce dont parle l'alerte, dans la fenêtre seulement.
        let trouve = dernier_dans(
            &d,
            |e| e.cle.as_deref() == Some("botnet|203.0.113.7:443"),
            chrono::Duration::hours(1),
            le("2026-10-23T10:30:00Z"),
        );
        assert_eq!(trouve.as_deref(), Some(a.as_str()));
        let trop_tard = dernier_dans(
            &d,
            |e| e.cle.as_deref() == Some("botnet|203.0.113.7:443"),
            chrono::Duration::hours(1),
            le("2026-10-23T12:00:00Z"),
        );
        assert_eq!(trop_tard, None);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Des segments posés aux noms de 2099 et 2098, avec une fausse cause datée de l'avenir : `dernier` ne les lit
    /// pas, et retrouve toujours la vraie cause, du mois de l'horloge.
    #[test]
    fn dernier_ignore_les_mois_d_apres_l_horloge() {
        let d = dossier("dernier-futur");
        let vraie = noter_dans(&d, alerte(1, "2026-10-23T10:00:00Z"), le("2026-10-23T10:00:00Z")).unwrap();
        for mois in ["2098-01", "2099-12"] {
            let mut f = alerte(1, "2099-12-31T10:00:00Z");
            f.id = format!("forge-{mois}");
            let mut l = serde_json::to_vec(&f).unwrap();
            l.push(b'\n');
            ajouter(&segment(&d, mois), &l).unwrap();
        }
        // Une ligne datée de l'avenir dans le vrai mois, aussi.
        let mut f = alerte(1, "2026-10-30T10:00:00Z");
        f.id = "forge-avenir".into();
        let mut l = serde_json::to_vec(&f).unwrap();
        l.push(b'\n');
        ajouter(&segment(&d, "2026-10"), &l).unwrap();
        let trouve = dernier_dans(
            &d,
            |e| e.cle.as_deref() == Some("port|1"),
            chrono::Duration::hours(1),
            le("2026-10-23T10:30:00Z"),
        );
        assert_eq!(trouve.as_deref(), Some(vraie.as_str()));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une mutation du journal sur le disque.
    #[derive(Debug, Clone)]
    enum Mutation {
        Octet(usize, u8),
        Retirer(usize),
        Permuter(usize, usize),
        Inserer(usize),
        Tronquer(usize),
        MoisClos(usize, u8),
        RetirerMoisClos,
    }

    fn mutation() -> impl Strategy<Value = Mutation> {
        prop_oneof![
            (any::<usize>(), 1u8..=255).prop_map(|(i, x)| Mutation::Octet(i, x)),
            any::<usize>().prop_map(Mutation::Retirer),
            (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Mutation::Permuter(a, b)),
            any::<usize>().prop_map(Mutation::Inserer),
            (1usize..200).prop_map(Mutation::Tronquer),
            (any::<usize>(), 1u8..=255).prop_map(|(i, x)| Mutation::MoisClos(i, x)),
            Just(Mutation::RetirerMoisClos),
        ]
    }

    /// Applique une mutation ; `false` si elle ne change rien (deux lignes identiques permutées, par exemple).
    #[allow(clippy::many_single_char_names)] // les indices tirés par proptest, comme dans `Mutation`
    fn muter(d: &Path, m: &Mutation) -> bool {
        let courant = segment(d, "2026-10");
        let clos = segment(d, "2026-09");
        let o = std::fs::read(&courant).unwrap();
        let mut ls: Vec<Vec<u8>> = lignes(&o).into_iter().map(<[u8]>::to_vec).collect();
        let n = ls.len();
        let ecrire = |ls: &[Vec<u8>]| {
            let t: Vec<u8> = ls.iter().flat_map(|l| l.iter().copied().chain(*b"\n")).collect();
            std::fs::write(&courant, &t).unwrap();
            t != o
        };
        match *m {
            Mutation::Octet(i, x) => {
                let mut t = o.clone();
                let i = i % t.len();
                t[i] ^= x;
                std::fs::write(&courant, &t).unwrap();
                true
            }
            Mutation::Retirer(i) => {
                ls.remove(i % n);
                ecrire(&ls)
            }
            Mutation::Permuter(a, b) => {
                ls.swap(a % n, b % n);
                ecrire(&ls)
            }
            Mutation::Inserer(i) => {
                let copie = ls[i % n].clone();
                ls.insert(i % (n + 1), copie);
                ecrire(&ls)
            }
            Mutation::Tronquer(k) => {
                let k = k.min(o.len());
                std::fs::write(&courant, &o[..o.len() - k]).unwrap();
                true
            }
            Mutation::MoisClos(i, x) => {
                let mut t = std::fs::read(&clos).unwrap();
                let i = i % t.len();
                t[i] ^= x;
                std::fs::write(&clos, &t).unwrap();
                true
            }
            Mutation::RetirerMoisClos => {
                std::fs::remove_file(&clos).unwrap();
                true
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        /// T8 : un octet changé, une ligne retirée, permutée ou dupliquée, une fin tronquée, un mois clos changé ou
        /// retiré : jamais `Intact`.
        #[test]
        fn aucune_falsification_silencieuse(m in mutation()) {
            let d = dossier("mutation");
            remplir(&d, 2, "2026-09-30T10:00:00Z");
            remplir(&d, 4, "2026-10-01T10:00:00Z");
            let neuf = lire_dans(&d);
            // Une rupture dit ce que la tête attendait et ce qui a été trouvé : la cause se lit dans l'échec même.
            let ruptures: Vec<&Genre> =
                neuf.evenements.iter().map(|e| &e.quoi).filter(|q| matches!(q, Genre::Rupture { .. })).collect();
            prop_assert_eq!(neuf.lecture, Lecture::Intact, "{:?}", ruptures);
            if muter(&d, &m) {
                let lu = lire_dans(&d).lecture;
                prop_assert!(lu != Lecture::Intact, "{:?} → {:?}", m, lu);
            }
            let _ = std::fs::remove_dir_all(&d);
        }
    }
}
