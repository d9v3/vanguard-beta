//! L'autodiagnostic de Vanguard (`vanguard autotest`, et une fois par semaine avec la surveillance) : Vanguard vérifie
//! ses propres lectures sur cet ordinateur. Rien n'est changé, rien n'est envoyé.
//!
//! Pourquoi : Vanguard lit presque tout en Rust natif (base de pacman, unités systemd, prises réseau, registre de
//! Windows…). Une lecture native peut se tromper sans bruit, à la mise à jour d'un format, et la règle dirait « sain »
//! sur une donnée mal lue. Les tests qui comparent ces lectures aux outils du système ne tournent que sur l'ordinateur
//! de l'auteur ; l'autotest les fait tourner là où Vanguard travaille vraiment, et mesure ce qui ralentit.
//!
//! Ce qu'il fait : chaque règle du bilan sous garde et délai, en lecture seule vérifiée (`lecture_seule` : interrupteur
//! et empreintes avant/après), des invariants sur chaque constat, les lectures croisées (`croisees`), le verdict du
//! journal des mesures (`mesures`). Hors ligne par défaut ; `--internet` le permet à la main. Ce qui ne va pas va au
//! journal des erreurs, sans aucune valeur lue sur la machine : identifiants, nombres, genres d'écart.

pub(crate) mod croisees;
pub(crate) mod lecture_seule;
pub(crate) mod mesures;

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::machine::Constat;
use crate::modele::{Etat, Raison};
use crate::risk::Niveau;
use crate::ui::*;
use croisees::{Comparaison, Croisee};

/// L'identifiant de l'autotest (`modele::registre::OUTILS`).
pub(crate) const OUTIL: &str = "AUT-VAN-001";
/// La date du dernier autotest et ses lectures contredites, scellées.
pub(crate) const DERNIER: &str = "autotest/dernier.json";
/// La catégorie de ses constats.
const CAT: &str = "Autodiagnostic";
/// L'hebdomadaire ne repasse pas avant.
const SEMAINE: i64 = 7;
/// Une lecture contredite le dit aux constats sains de ses règles pendant au plus ce temps.
const CONTREDITE_JOURS: i64 = 30;
/// Un « différent » est relu après ce temps avant d'être noté : une mise à jour de pacman pendant l'essai change la
/// liste entre les deux lectures, comme le second essai des canaris de la nuit.
const RELECTURE: Duration = if cfg!(test) {
    Duration::from_millis(10)
} else {
    Duration::from_secs(3)
};
/// Une passe de la surveillance commencée depuis moins longtemps peut tourner encore.
const PASSE_EN_COURS: Duration = Duration::from_mins(30);

/// Les options de `vanguard autotest`.
#[allow(clippy::struct_excessive_bools)] // les quatre options de la ligne de commande
pub(crate) struct Options {
    pub json: bool,
    pub internet: bool,
    pub detail: bool,
    pub une_par_une: bool,
}

/// Une règle qui ne tient pas un invariant du modèle commun.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
struct Invariant {
    regle: String,
    /// « sans-regle », « etat-incoherent », « message-vide ».
    genre: &'static str,
}

/// Ce que les règles ont rendu.
#[derive(Serialize, Default, Debug)]
struct Regles {
    essayees: usize,
    /// Pas lancées : celles des mises à jour, qui vont sur Internet, sans `--internet` (le bilan horaire les essaie).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hors_ligne: Vec<&'static str>,
    ont_repondu: usize,
    plantees: Vec<&'static str>,
    hors_delai: Vec<&'static str>,
    muettes: Vec<&'static str>,
    /// Des « non vérifié » sans raison typée (règles pas encore migrées) : dit, pas une faute.
    sans_raison_typee: usize,
    invariants: Vec<Invariant>,
    /// La durée de chaque règle pendant l'essai (ms) ; vide pour l'hebdomadaire, qui reprend le bilan de la passe.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    durees_ms: BTreeMap<&'static str, u64>,
}

/// Une lecture croisée, telle qu'elle s'écrit : aucune valeur, seulement des nombres et des codes.
#[derive(Serialize, Debug)]
struct CroiseeEcrite {
    id: &'static str,
    outil: &'static str,
    verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    en_plus: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    en_moins: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    differents: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    genre: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raison: Option<&'static str>,
    regles: &'static [&'static str],
}

/// La preuve de « rien changé ».
#[derive(Serialize, Debug, Default)]
struct Preuve {
    /// « rien-change », « change », « non-concluante » (la surveillance a tourné pendant l'essai), « bornee » (trop
    /// gros pour tout lire), « non-prise » (l'hebdomadaire : la surveillance écrit légitimement pendant sa passe).
    verdict: &'static str,
    /// Les fichiers changés, par leur nom de l'inventaire (« autre » pour un nom hors inventaire : il pourrait venir
    /// de l'extérieur).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fichiers: Vec<String>,
    /// Le nombre de fichiers changés (plusieurs peuvent porter le même nom de l'inventaire), pour le journal.
    #[serde(skip)]
    nombre: usize,
}

/// Le rapport d'un autotest : ce qui s'écrit en `--json`, sans aucune valeur lue sur la machine (la veille de nuit
/// peut le confier à une IA en ligne).
#[derive(Serialize, Debug)]
pub(crate) struct Rapport {
    outil: &'static str,
    schema: u16,
    version: &'static str,
    systeme: &'static str,
    debut: String,
    duree_ms: u64,
    hebdomadaire: bool,
    hors_ligne: bool,
    regles: Regles,
    croisees: Vec<CroiseeEcrite>,
    preuve: Preuve,
    mesures: mesures::Verdict,
    /// « sain », « ecart », « non-verifie ».
    verdict: &'static str,
    /// 0 tout bon, 1 écart ou plantage, 2 rien de fautif mais du non vérifié.
    code: i32,
}

/// La date du dernier autotest et les lectures qu'il a vues contredites.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
struct Dernier {
    /// « AAAA-MM-JJTHH:MM:SSZ ».
    quand: String,
    verdict: String,
    #[serde(default)]
    contredites: Vec<Contredite>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Contredite {
    croisee: String,
    outil: String,
    regles: Vec<String>,
    /// L'essai qui l'a vue : une contradiction que l'essai suivant n'a pas tranchée (lecture sautée) est gardée avec
    /// sa date. Vide dans les anciens fichiers : la date du dernier essai.
    #[serde(default)]
    quand: String,
}

fn systeme() -> &'static str {
    match crate::machine::regles::Os::actuel() {
        crate::machine::regles::Os::Windows => "windows",
        crate::machine::regles::Os::MacOs => "macos",
        _ => "linux",
    }
}

/// Ce que les règles ont rendu, et les invariants du modèle commun sur chaque constat.
fn juger_regles(constats: &[Constat], durees: &[(&'static str, Duration)], sautees: &[&'static str]) -> Regles {
    let regles: Vec<_> = crate::machine::regles::regles(crate::machine::regles::Os::actuel())
        .into_iter()
        .filter(|r| !sautees.contains(&r.id))
        .collect();
    let mut r = Regles {
        essayees: regles.len(),
        hors_ligne: sautees.to_vec(),
        durees_ms: durees
            .iter()
            .map(|(id, d)| (*id, u64::try_from(d.as_millis()).unwrap_or(u64::MAX)))
            .collect(),
        ..Regles::default()
    };
    for regle in &regles {
        let siens = constats.iter().filter(|c| c.regle == regle.id);
        let raison = |x: &Raison| {
            siens
                .clone()
                .any(|c| matches!(c.etat(), Etat::NonVerifie(ref y) if y == x))
        };
        if raison(&Raison::Panique) {
            r.plantees.push(regle.id);
        } else if raison(&Raison::Delai) {
            r.hors_delai.push(regle.id);
        } else if raison(&Raison::Muette) {
            r.muettes.push(regle.id);
        } else {
            r.ont_repondu += 1;
        }
    }
    for c in constats {
        let genre = if c.regle.is_empty() {
            Some("sans-regle")
        } else if !c.coherent() {
            Some("etat-incoherent")
        } else if c.message.trim().is_empty() {
            Some("message-vide")
        } else {
            None
        };
        if let Some(genre) = genre {
            let inv = Invariant {
                regle: c.regle.to_string(),
                genre,
            };
            if !r.invariants.contains(&inv) {
                r.invariants.push(inv);
            }
        }
        if matches!(c.etat(), Etat::NonVerifie(Raison::NonPrecisee)) {
            r.sans_raison_typee += 1;
        }
    }
    r
}

/// Une lecture croisée, relue une fois si elle diverge ; une comparaison qui plante est sautée, dite.
fn comparer_relu(c: &Croisee, relire: Duration) -> Comparaison {
    let une = || crate::journal::rattraper(c.comparer).unwrap_or(Comparaison::Saute(Raison::Panique));
    let premiere = une();
    if matches!(premiere, Comparaison::Different { .. }) {
        std::thread::sleep(relire);
        return une();
    }
    premiere
}

/// Toutes les lectures croisées de ce système, en même temps (chacune attend surtout son outil).
fn croiser() -> Vec<(&'static Croisee, Comparaison)> {
    let toutes = croisees::croisees();
    std::thread::scope(|s| {
        let fils: Vec<_> = toutes
            .into_iter()
            .map(|c| s.spawn(move || (c, comparer_relu(c, RELECTURE))))
            .collect();
        fils.into_iter().filter_map(|f| f.join().ok()).collect()
    })
}

fn ecrire_croisee(c: &'static Croisee, r: &Comparaison) -> CroiseeEcrite {
    let mut e = CroiseeEcrite {
        id: c.id,
        outil: c.outil,
        verdict: r.code(),
        n: None,
        en_plus: None,
        en_moins: None,
        differents: None,
        genre: None,
        raison: None,
        regles: c.regles,
    };
    match r {
        Comparaison::Pareil { n } => e.n = Some(*n),
        Comparaison::Different {
            en_plus,
            en_moins,
            differents,
            genre,
        } => {
            e.en_plus = Some(en_plus.len());
            e.en_moins = Some(en_moins.len());
            e.differents = Some(differents.len());
            e.genre = Some(genre.code());
        }
        Comparaison::Saute(raison) => e.raison = Some(raison.code()),
        Comparaison::SansObjet(_) => {}
    }
    e
}

/// Les dossiers de Vanguard dont l'empreinte se prend : celui de cet ordinateur, et celui de la clé s'il est autre.
fn dossiers() -> Vec<std::path::PathBuf> {
    let local = crate::socle::dossier_local();
    let donnees = crate::reseau::dossier_donnees();
    if donnees == local {
        vec![local]
    } else {
        vec![local, donnees]
    }
}

/// Le moment de la dernière passe de la surveillance, d'après son fichier (`reseau::tableau`).
fn passe() -> (Option<Vec<u8>>, Option<std::time::SystemTime>) {
    let chemin = crate::socle::dossier_local().join("surveillance-passe.txt");
    let contenu = crate::socle::lire_ordinaire(&chemin, 4096).ok();
    let quand = std::fs::symlink_metadata(&chemin).and_then(|m| m.modified()).ok();
    (contenu, quand)
}

/// Le nom d'un fichier changé, tel qu'il peut sortir de l'écran : son nom s'il est inventorié (par lui-même ou son
/// premier dossier), sinon « autre » (un nom hors inventaire pourrait venir de l'extérieur).
fn nom_inventorie(relatif: &str) -> String {
    let premier = relatif.split('/').next().unwrap_or_default();
    crate::modele::inventaire::INVENTAIRE
        .iter()
        .find(|f| f.nom == relatif || f.nom == premier)
        .map_or_else(|| "autre".to_string(), |f| f.nom.to_string())
}

/// Juge la preuve : rien changé, changé, ou non concluante quand la surveillance a pu tourner pendant l'essai.
fn juger_preuve(
    ecarts: &[(String, lecture_seule::Changement)],
    bornee: bool,
    passe_avant: &(Option<Vec<u8>>, Option<std::time::SystemTime>),
    passe_apres: &(Option<Vec<u8>>, Option<std::time::SystemTime>),
    debut: std::time::SystemTime,
) -> Preuve {
    let surveillance = passe_avant.0 != passe_apres.0
        || passe_avant
            .1
            .and_then(|q| debut.duration_since(q).ok())
            .is_some_and(|d| d < PASSE_EN_COURS);
    let verdict = if ecarts.is_empty() && !bornee {
        "rien-change"
    } else if ecarts.is_empty() {
        "bornee"
    } else if surveillance {
        "non-concluante"
    } else {
        "change"
    };
    let mut fichiers: Vec<String> = ecarts.iter().map(|(n, _)| nom_inventorie(n)).collect();
    // Triés d'abord : dedup ne retire que les doublons voisins.
    fichiers.sort();
    fichiers.dedup();
    Preuve {
        verdict,
        fichiers,
        nombre: ecarts.len(),
    }
}

/// Le code de sortie et le verdict d'un rapport.
fn code_de(r: &Rapport) -> (i32, &'static str) {
    let faute = !r.regles.plantees.is_empty()
        || !r.regles.invariants.is_empty()
        || r.croisees.iter().any(|c| c.verdict == "different")
        || r.preuve.verdict == "change";
    let manque = !r.regles.hors_delai.is_empty()
        || !r.regles.muettes.is_empty()
        || r.croisees.iter().any(|c| c.verdict == "saute")
        || r.croisees.is_empty()
        || matches!(r.preuve.verdict, "non-concluante" | "bornee")
        // Moins de 5 semaines de mesures : la section le dit « non vérifié », le verdict ne peut pas dire « sain ».
        || r.mesures.verdict == "pas-assez";
    if faute {
        (1, "ecart")
    } else if manque {
        (2, "non-verifie")
    } else {
        (0, "sain")
    }
}

/// Le rapport, d'après ce qui a été vu.
fn rapport(
    debut: (chrono::DateTime<chrono::Utc>, std::time::Instant),
    hebdomadaire: bool,
    regles: Regles,
    croisees: &[(&'static Croisee, Comparaison)],
    preuve: Preuve,
) -> Rapport {
    let mut r = Rapport {
        outil: OUTIL,
        schema: 1,
        version: env!("CARGO_PKG_VERSION"),
        systeme: systeme(),
        debut: debut.0.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        duree_ms: u64::try_from(debut.1.elapsed().as_millis()).unwrap_or(u64::MAX),
        hebdomadaire,
        hors_ligne: crate::parametres::hors_ligne(),
        regles,
        croisees: croisees.iter().map(|(c, x)| ecrire_croisee(c, x)).collect(),
        preuve,
        mesures: mesures::verdict(),
        verdict: "",
        code: 0,
    };
    (r.code, r.verdict) = code_de(&r);
    r
}

// ---------------------------------------------------------------------------------------------------------------
// Textes

fn texte_regles(r: &Regles) -> String {
    trf!(
        "{} règles essayées : {} ont répondu, {} plantée(s), {} hors délai, {} sans réponse.",
        "{} rules tried: {} answered, {} crashed, {} timed out, {} returned nothing.",
        r.essayees,
        r.ont_repondu,
        r.plantees.len(),
        r.hors_delai.len(),
        r.muettes.len()
    )
}

fn texte_croisee(c: &Croisee, r: &Comparaison) -> String {
    match r {
        Comparaison::Pareil { n } => trf!(
            "{} et la lecture de Vanguard disent la même chose ({n} éléments).",
            "{} and Vanguard's reading agree ({n} items).",
            c.outil
        ),
        Comparaison::Different {
            en_plus,
            en_moins,
            differents,
            genre,
        } => trf!(
            "{} et la lecture de Vanguard ne disent pas la même chose ({} en plus, {} en moins, {} différent(s) : {}). Les règles {} peuvent se tromper ici : l'écart est noté pour être corrigé.",
            "{} and Vanguard's reading disagree ({} more, {} fewer, {} different: {}). Rules {} may be wrong here: the gap is logged to be fixed.",
            c.outil,
            en_plus.len(),
            en_moins.len(),
            differents.len(),
            genre.code(),
            c.regles.join(", ")
        ),
        Comparaison::SansObjet(pourquoi) => trf!("Sans objet : {pourquoi}.", "Not applicable: {pourquoi}."),
        Comparaison::Saute(raison) => trf!("Non vérifié : {}.", "Not checked: {}.", raison.texte()),
    }
}

fn texte_preuve(p: &Preuve) -> String {
    match p.verdict {
        "rien-change" => tr!(
            "Rien n'a changé dans le dossier de Vanguard pendant l'essai (vérifié par empreintes).",
            "Nothing changed in Vanguard's folder during the test (checked by fingerprints)."
        )
        .to_string(),
        "change" => trf!(
            "Attention : pendant l'essai, {} a changé. L'autotest ne devait rien écrire : c'est un défaut de Vanguard, noté.",
            "Warning: during the test, {} changed. The self-test must not write anything: this is a Vanguard bug, logged.",
            p.fichiers.join(", ")
        ),
        "non-concluante" => tr!(
            "Preuve non concluante : la surveillance horaire a tourné pendant l'essai et écrit dans le même dossier. Relancez l'autotest plus tard pour la preuve.",
            "Inconclusive proof: the hourly monitoring ran during the test and wrote to the same folder. Run the self-test again later for the proof."
        )
        .to_string(),
        "bornee" => tr!(
            "Preuve incomplète : le dossier de Vanguard est trop gros pour être lu en entier ; rien de changé dans ce qui a été lu.",
            "Incomplete proof: Vanguard's folder is too big to be read in full; nothing changed in what was read."
        )
        .to_string(),
        _ => tr!(
            "Pas d'empreintes pour l'autotest de la semaine : la surveillance écrit pendant sa passe.",
            "No fingerprints for the weekly self-test: the monitoring writes during its pass."
        )
        .to_string(),
    }
}

/// Le constat de chaque partie, pour le résultat gardé (`examens/AUT-VAN-001.json`) : textes sans valeur lue.
fn constats_du_rapport(r: &Rapport, croisees: &[(&'static Croisee, Comparaison)]) -> Vec<Constat> {
    use crate::machine::{alerte, impossible_par, ok, sans_objet};
    let mut v = Vec::new();
    let regles = texte_regles(&r.regles);
    let mut c = if !r.regles.plantees.is_empty() || !r.regles.invariants.is_empty() {
        alerte(CAT, Niveau::Moyen, regles)
    } else if !r.regles.hors_delai.is_empty() {
        impossible_par(CAT, Raison::Delai, regles)
    } else if !r.regles.muettes.is_empty() {
        impossible_par(CAT, Raison::Muette, regles)
    } else {
        ok(CAT, regles)
    };
    c.regle = OUTIL;
    v.push(c);
    for (croisee, x) in croisees {
        let texte = texte_croisee(croisee, &sans_valeurs(x));
        let mut c = match x {
            Comparaison::Pareil { .. } => ok(CAT, texte),
            Comparaison::Different { .. } => alerte(CAT, Niveau::Moyen, texte),
            Comparaison::SansObjet(_) => sans_objet(CAT, crate::modele::Absence::Logiciel, texte),
            Comparaison::Saute(raison) => impossible_par(CAT, raison.clone(), texte),
        };
        c.regle = croisee.id;
        v.push(c);
    }
    let preuve = texte_preuve(&r.preuve);
    let mut c = match r.preuve.verdict {
        "rien-change" => ok(CAT, preuve),
        "change" => alerte(CAT, Niveau::Moyen, preuve),
        "non-prise" => sans_objet(CAT, crate::modele::Absence::Inactif, preuve),
        _ => impossible_par(CAT, Raison::Echoue(preuve.clone()), preuve),
    };
    c.regle = OUTIL;
    v.push(c);
    v
}

/// Une comparaison sans ses valeurs : ce qui va au résultat gardé et au JSON n'en a pas.
fn sans_valeurs(x: &Comparaison) -> Comparaison {
    match x {
        Comparaison::Different {
            en_plus,
            en_moins,
            differents,
            genre,
        } => Comparaison::Different {
            en_plus: vec![String::new(); en_plus.len()],
            en_moins: vec![String::new(); en_moins.len()],
            differents: vec![String::new(); differents.len()],
            genre: *genre,
        },
        autre => autre.clone(),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Ce qui s'écrit

/// Les entrées du journal des erreurs : identifiants, nombres, genres, jamais une valeur lue sur la machine.
fn entrees_du_journal(r: &Rapport) -> Vec<(String, String)> {
    let mut e = Vec::new();
    for c in r.croisees.iter().filter(|c| c.verdict == "different") {
        e.push((
            format!("autotest {}", c.id),
            format!(
                "[{}] {} en plus, {} en moins, {} différent(s) ; règles {}",
                c.genre.unwrap_or_default(),
                c.en_plus.unwrap_or_default(),
                c.en_moins.unwrap_or_default(),
                c.differents.unwrap_or_default(),
                c.regles.join(", ")
            ),
        ));
    }
    for id in &r.regles.plantees {
        e.push((
            format!("autotest {id}"),
            "[panique] règle plantée pendant l'autotest".into(),
        ));
    }
    for i in &r.regles.invariants {
        let id = if i.regle.is_empty() { "sans-regle" } else { &i.regle };
        e.push((format!("autotest {id}"), format!("[invariant] {}", i.genre)));
    }
    if r.preuve.verdict == "change" {
        e.push((
            format!("autotest {OUTIL}"),
            format!(
                "[ecriture] {} fichier(s) changé(s) pendant l'essai : {}",
                r.preuve.nombre,
                r.preuve.fichiers.join(", ")
            ),
        ));
    }
    for l in &r.mesures.lentes {
        e.push((
            format!("autotest {}", l.regle),
            format!(
                "[lente] médiane de la semaine {} ms, {} ms les 4 semaines d'avant",
                l.semaine_ms, l.avant_ms
            ),
        ));
    }
    for f in &r.mesures.frolent_le_delai {
        e.push((
            format!("autotest {}", f.regle),
            format!("[frole-delai] {} ms sur un délai de {} ms", f.max_ms, f.delai_ms),
        ));
    }
    e
}

/// Écrit le résultat : `examens/AUT-VAN-001.json` (scellé, un événement d'essai au journal), la date du dernier
/// autotest et ses lectures contredites (scellées), puis le journal des erreurs.
fn ecrire(
    r: &Rapport,
    croisees: &[(&'static Croisee, Comparaison)],
    debut: (chrono::DateTime<chrono::Utc>, std::time::Instant),
) {
    use crate::modele::resultat::{Couverture, Resultat};
    let constats = constats_du_rapport(r, croisees);
    let non_verifies: Vec<String> = constats
        .iter()
        .filter(|c| matches!(c.etat(), Etat::NonVerifie(_)))
        .map(|c| format!("{} : {}", c.regle, c.message))
        .collect();
    let verifies = constats.iter().filter(|c| c.verifie).count();
    let resultat = Resultat::nouveau(
        OUTIL,
        debut,
        &constats,
        Couverture {
            verifies: u32::try_from(verifies).unwrap_or(u32::MAX),
            non_verifies,
        },
    );
    let dernier = Dernier {
        quand: r.debut.clone(),
        verdict: r.verdict.to_string(),
        contredites: contredites(croisees, &r.debut, dernier()),
    };
    lecture_seule::ecrire_resultat(|| {
        crate::modele::resultat::verser(&resultat);
        if let Ok(o) = serde_json::to_vec_pretty(&dernier)
            && let Err(e) = crate::sceau::ecrire(DERNIER, o)
        {
            crate::modele::Echec::io("autotest/dernier", &e).journaliser();
        }
    });
    for (contexte, detail) in entrees_du_journal(r) {
        crate::journal::erreur(&contexte, &detail);
    }
}

/// Les lectures contredites par cet essai, plus celles du précédent qu'il n'a pas tranchées : une lecture sautée
/// (délai, outil absent) n'efface pas une contradiction, seul un « pareil » ou un nouvel écart la remplace.
fn contredites(croisees: &[(&'static Croisee, Comparaison)], quand: &str, avant: Option<Dernier>) -> Vec<Contredite> {
    let mut v: Vec<Contredite> = croisees
        .iter()
        .filter(|(_, x)| matches!(x, Comparaison::Different { .. }))
        .map(|(c, _)| Contredite {
            croisee: c.id.to_string(),
            outil: c.outil.to_string(),
            regles: c.regles.iter().map(|r| (*r).to_string()).collect(),
            quand: quand.to_string(),
        })
        .collect();
    let tranchees: Vec<&str> = croisees
        .iter()
        .filter(|(_, x)| matches!(x, Comparaison::Pareil { .. } | Comparaison::Different { .. }))
        .map(|(c, _)| c.id)
        .collect();
    if let Some(av) = avant {
        for mut x in av.contredites {
            if !tranchees.contains(&x.croisee.as_str()) {
                if x.quand.is_empty() {
                    x.quand.clone_from(&av.quand);
                }
                v.push(x);
            }
        }
    }
    v
}

/// Le dernier autotest relu, s'il est tel que Vanguard l'a écrit (un fichier changé hors de Vanguard ne vaut rien).
fn dernier() -> Option<Dernier> {
    match crate::sceau::lire(DERNIER) {
        crate::sceau::Lecture::Intact(o) | crate::sceau::Lecture::Adopte(o) => serde_json::from_slice(&o).ok(),
        _ => None,
    }
}

fn date(quand: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(quand)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}

/// Les constats sains des règles dont la lecture a été contredite au dernier autotest (depuis moins de 30 jours) le
/// disent ; leurs problèmes, non (une alerte ne devient pas moins sûre), et la note ne change pas.
pub(crate) fn annoter(constats: &mut [Constat]) {
    let Some(d) = dernier() else { return };
    annoter_selon(constats, &d, chrono::Utc::now());
}

fn annoter_selon(constats: &mut [Constat], d: &Dernier, maintenant: chrono::DateTime<chrono::Utc>) {
    // Chaque contradiction a sa date : une reprise d'un essai à l'autre ne vit jamais plus de 30 jours après
    // l'essai qui l'a vue.
    let vivantes: Vec<(&Contredite, String)> = d
        .contredites
        .iter()
        .filter_map(|x| {
            let q = date(if x.quand.is_empty() { &d.quand } else { &x.quand })?;
            (maintenant - q <= chrono::Duration::days(CONTREDITE_JOURS))
                .then(|| (x, q.with_timezone(&chrono::Local).format("%d/%m").to_string()))
        })
        .collect();
    for c in constats.iter_mut().filter(|c| c.etat() == Etat::Sain) {
        if let Some((x, jour)) = vivantes.iter().find(|(x, _)| x.regles.iter().any(|r| r == c.regle)) {
            c.message += &trf!(
                " (Lecture contredite par {} le {jour} : non vérifié à 100 %.)",
                " (Reading contradicted by {} on {jour}: not fully verified.)",
                crate::ui::affichable(&x.outil)
            );
        }
    }
}

/// La ligne du diagnostic : quand le dernier autotest a tourné, et ce qu'il a trouvé.
pub(crate) fn ligne_diagnostic() -> (String, Option<Niveau>) {
    let Some(d) = dernier() else {
        return (
            tr!("jamais fait (vanguard autotest)", "never run (vanguard autotest)").to_string(),
            None,
        );
    };
    let jours = date(&d.quand).map_or(0, |q| (chrono::Utc::now() - q).num_days().max(0));
    match d.verdict.as_str() {
        "sain" => (trf!("il y a {jours} j, sans écart", "{jours} d ago, no gap"), None),
        "ecart" => (
            trf!(
                "il y a {jours} j : écart trouvé (vanguard autotest)",
                "{jours} d ago: gap found (vanguard autotest)"
            ),
            Some(Niveau::Moyen),
        ),
        _ => (
            trf!(
                "il y a {jours} j, en partie non vérifié",
                "{jours} d ago, partly not checked"
            ),
            None,
        ),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Écran

fn afficher(r: &Rapport, croisees: &[(&'static Croisee, Comparaison)], detail: bool) {
    let icone = |bon: bool, manque: bool| {
        if bon {
            format!("{VERT}✔{RESET}")
        } else if manque {
            format!("{}ℹ{RESET}", couleur(Niveau::Info))
        } else {
            format!("{}✖{RESET}", couleur(Niveau::Moyen))
        }
    };
    titre(tr!("Autodiagnostic de Vanguard", "Vanguard self-test"));
    afficher_aligne(
        "  ",
        tr!(
            "Vanguard vérifie ses propres lectures sur cet ordinateur : rien n'est changé, rien n'est envoyé.",
            "Vanguard checks its own readings on this computer: nothing is changed, nothing is sent."
        ),
        2,
        GRIS,
    );
    if r.hors_ligne {
        afficher_aligne(
            "  ",
            &trf!(
                "Hors ligne : les {} règles des mises à jour ne sont pas lancées, et celles qui ont besoin d'Internet sont dites non vérifiées (« --internet » pour les essayer).",
                "Offline: the {} update rules are not run, and those that need the Internet are reported as not checked (“--internet” to try them).",
                r.regles.hors_ligne.len()
            ),
            2,
            GRIS,
        );
    }
    println!();
    let reg = &r.regles;
    let bon =
        reg.plantees.is_empty() && reg.invariants.is_empty() && reg.hors_delai.is_empty() && reg.muettes.is_empty();
    let manque = reg.plantees.is_empty() && reg.invariants.is_empty();
    afficher_aligne(&format!("  {} ", icone(bon, manque)), &texte_regles(reg), 4, "");
    for (liste, fr, en) in [
        (&reg.plantees, "plantées", "crashed"),
        (&reg.hors_delai, "hors délai", "timed out"),
        (&reg.muettes, "sans réponse", "returned nothing"),
    ] {
        if !liste.is_empty() {
            afficher_aligne(
                "    ",
                &format!(
                    "{} : {}",
                    if crate::langue::anglais() { en } else { fr },
                    liste.join(", ")
                ),
                4,
                GRIS,
            );
        }
    }
    for i in &reg.invariants {
        afficher_aligne(
            "    ",
            &trf!(
                "Invariant non tenu ({}) : {}",
                "Invariant broken ({}): {}",
                i.genre,
                i.regle
            ),
            4,
            GRIS,
        );
    }
    if reg.sans_raison_typee > 0 {
        afficher_aligne(
            "    ",
            &trf!(
                "{} non vérifié(s) sans raison typée (règles pas encore migrées).",
                "{} not-checked result(s) without a typed reason (rules not migrated yet).",
                reg.sans_raison_typee
            ),
            4,
            GRIS,
        );
    }
    section(tr!("Lectures croisées", "Cross-checks"));
    if croisees.is_empty() {
        let texte = if r.systeme == "macos" {
            tr!(
                "Aucune lecture croisée n'existe encore sous macOS : ce point n'est pas vérifié.",
                "No cross-check exists yet on macOS: this point is not checked."
            )
        } else {
            tr!(
                "Aucune lecture croisée ici : non vérifié.",
                "No cross-check here: not checked."
            )
        };
        afficher_aligne(&format!("  {} ", icone(false, true)), texte, 4, "");
    }
    for (c, x) in croisees {
        let (bon, manque) = match x {
            Comparaison::Pareil { .. } | Comparaison::SansObjet(_) => (true, false),
            Comparaison::Different { .. } => (false, false),
            Comparaison::Saute(_) => (false, true),
        };
        afficher_aligne(
            &format!("  {} {GRAS}{}{RESET} ", icone(bon, manque), c.id),
            &texte_croisee(c, x),
            16,
            "",
        );
        if detail
            && let Comparaison::Different {
                en_plus,
                en_moins,
                differents,
                ..
            } = x
        {
            for (liste, fr, en) in [
                (en_plus, "en plus chez Vanguard", "only in Vanguard's reading"),
                (en_moins, "en moins chez Vanguard", "missing from Vanguard's reading"),
                (differents, "différents", "different"),
            ] {
                if liste.is_empty() {
                    continue;
                }
                let montres: Vec<String> = liste.iter().take(20).map(|v| affichable(v)).collect();
                let reste = liste.len().saturating_sub(20);
                let suite = if reste > 0 {
                    trf!(" … et {reste} autres", " … and {reste} more")
                } else {
                    String::new()
                };
                afficher_aligne(
                    "      ",
                    &format!(
                        "{} : {}{suite}",
                        if crate::langue::anglais() { en } else { fr },
                        montres.join(", ")
                    ),
                    6,
                    GRIS,
                );
            }
        }
    }
    section(tr!("Rien changé ?", "Nothing changed?"));
    let p = &r.preuve;
    afficher_aligne(
        &format!("  {} ", icone(p.verdict == "rien-change", p.verdict != "change")),
        &texte_preuve(p),
        4,
        "",
    );
    section(tr!("Mesures", "Timings"));
    let m = &r.mesures;
    match m.verdict {
        "pas-assez" => afficher_aligne(
            &format!("  {} ", icone(false, true)),
            &trf!(
                "Pas assez de mesures pour juger une régression ({} jour(s), il en faut 35) : non vérifié.",
                "Not enough timings to judge a slowdown ({} day(s), 35 needed): not checked.",
                m.jours
            ),
            4,
            "",
        ),
        "sans-regression" => afficher_aligne(
            &format!("  {} ", icone(true, false)),
            tr!(
                "Aucune règle n'a ralenti cette semaine.",
                "No rule slowed down this week."
            ),
            4,
            "",
        ),
        _ => {}
    }
    for l in &m.lentes {
        afficher_aligne(
            &format!("  {} ", icone(false, true)),
            &trf!(
                "La règle {} prend {} s (d'habitude {} s) : notée pour le développement.",
                "Rule {} takes {} s (usually {} s): logged for development.",
                l.regle,
                l.semaine_ms / 1000,
                l.avant_ms / 1000
            ),
            4,
            "",
        );
    }
    for f in &m.frolent_le_delai {
        afficher_aligne(
            &format!("  {} ", icone(false, true)),
            &trf!(
                "La règle {} a pris {} s, plus de la moitié de son délai ({} s) : notée pour le développement.",
                "Rule {} took {} s, more than half its time limit ({} s): logged for development.",
                f.regle,
                f.max_ms / 1000,
                f.delai_ms / 1000
            ),
            4,
            "",
        );
    }
    println!();
    let verdict = match r.code {
        0 => format!(
            "{VERT}{}{RESET}",
            tr!(
                "Tout ce qui pouvait être vérifié l'a été, sans écart.",
                "Everything that could be checked was, with no gap."
            )
        ),
        1 => format!(
            "{}{}{RESET}",
            couleur(Niveau::Moyen),
            tr!(
                "Écart trouvé : noté au journal des erreurs pour être corrigé (aucune valeur de cet ordinateur n'y est écrite).",
                "Gap found: logged in the error log to be fixed (no value from this computer is written there)."
            )
        ),
        _ => tr!(
            "Rien de fautif, mais tout n'a pas pu être vérifié (voir ci-dessus).",
            "Nothing wrong, but not everything could be checked (see above)."
        )
        .to_string(),
    };
    afficher_aligne("  ", &verdict, 2, "");
}

// ---------------------------------------------------------------------------------------------------------------
// Lancements

/// Une règle qui va sur Internet : celles des mises à jour (« LNX-MAJ-001 »), au délai long pour la même raison.
fn va_sur_internet(id: &str) -> bool {
    id.get(4..7) == Some("MAJ")
}

/// « vanguard autotest » : rend le code de sortie (0 tout bon, 1 écart ou plantage, 2 du non vérifié).
pub(crate) fn executer(o: &Options) -> i32 {
    // Pas de root : lancé par sudo -E, le dossier serait celui d'un compte, et rien ne doit y être écrit en root (même
    // règle que les sceaux). Sous `unshare -r` aussi, où le compte se croit root.
    #[cfg(unix)]
    // SAFETY : geteuid n'a ni argument ni effet de bord.
    if unsafe { libc::geteuid() } == 0 {
        if o.json {
            println!(
                "{}",
                serde_json::json!({"outil": OUTIL, "verdict": "refuse", "raison": "root", "code": 2})
            );
        } else {
            trp!(
                "  ✖ L'autotest tourne avec les droits de votre compte, jamais en root : relancez-le sans sudo.",
                "  ✖ The self-test runs with your account's rights, never as root: run it again without sudo."
            );
        }
        return 2;
    }
    if !o.internet {
        crate::parametres::forcer_hors_ligne();
    }
    if !o.json {
        trp!(
            "  {DISCRET}Autodiagnostic : chaque règle du bilan, puis les lectures croisées (une minute ou deux)…{RESET}",
            "  {DISCRET}Self-test: every check rule, then the cross-checks (a minute or two)…{RESET}"
        );
    }
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let debut_systeme = std::time::SystemTime::now();
    let dossiers = dossiers();
    let passe_avant = passe();
    let avant: Vec<lecture_seule::Empreinte> = dossiers.iter().map(|d| lecture_seule::empreinte_dossier(d)).collect();
    // L'interrupteur reste posé jusqu'à la fin du processus (voir lecture_seule).
    lecture_seule::poser();
    // Sans --internet, les règles des mises à jour (domaine « MAJ ») ne sont pas lancées : elles interrogent Internet
    // (AUR, dépôts, Flatpak, Snap) sans toutes consulter le travail sans Internet. Elles sont dites, pas comptées.
    let sautees: Vec<&'static str> = crate::machine::regles::regles(crate::machine::regles::Os::actuel())
        .into_iter()
        .map(|r| r.id)
        .filter(|id| !o.internet && va_sur_internet(id))
        .collect();
    let (constats, durees) = crate::machine::essai_des_regles(o.une_par_une, |id| !sautees.contains(&id));
    let croisees = croiser();
    let apres: Vec<lecture_seule::Empreinte> = dossiers.iter().map(|d| lecture_seule::empreinte_dossier(d)).collect();
    let passe_apres = passe();
    let ecarts: Vec<(String, lecture_seule::Changement)> = avant
        .iter()
        .zip(&apres)
        .flat_map(|(a, b)| lecture_seule::ecarts(a, b))
        .collect();
    let bornee = avant.iter().chain(&apres).any(|e| e.bornee);
    let preuve = juger_preuve(&ecarts, bornee, &passe_avant, &passe_apres, debut_systeme);
    let r = rapport(
        debut,
        false,
        juger_regles(&constats, &durees, &sautees),
        &croisees,
        preuve,
    );
    ecrire(&r, &croisees, debut);
    if o.json {
        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
    } else {
        if o.detail && r.preuve.verdict == "change" {
            for (n, c) in &ecarts {
                afficher_aligne("    ", &format!("{} ({})", affichable(n), c.code()), 4, GRIS);
            }
        }
        afficher(&r, &croisees, o.detail);
    }
    r.code
}

/// L'autotest de la semaine, lancé en fond par la passe de la surveillance.
static HEBDOMADAIRE: std::sync::Mutex<Option<std::thread::JoinHandle<()>>> = std::sync::Mutex::new(None);

/// À la passe de la surveillance, une fois par semaine au plus : les lectures croisées, les invariants du bilan de
/// cette passe (déjà fait, rien relancé) et le verdict des mesures, dans un fil à part. Ni interrupteur ni empreintes
/// ici : la surveillance écrit légitimement pendant sa passe. Reporté pendant un jeu (GameMode, sous Linux) ; coupé
/// par le réglage « autotest » ; jamais de notification.
pub(crate) fn hebdomadaire_en_fond(constats: &[Constat]) {
    if !crate::parametres::autotest_hebdomadaire() || !du(dernier().as_ref(), chrono::Utc::now()) {
        return;
    }
    #[cfg(target_os = "linux")]
    if reporter(
        dernier().as_ref(),
        chrono::Utc::now(),
        crate::machine::linux::dbus::gamemode_actif(),
    ) {
        return;
    }
    let constats = constats.to_vec();
    let fil = std::thread::Builder::new()
        .name("autotest de la semaine".into())
        .spawn(move || hebdomadaire(&constats));
    if let Ok(fil) = fil {
        *HEBDOMADAIRE.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fil);
    }
}

/// Attend la fin de l'autotest de la semaine, s'il tourne : la passe ne finit pas avant lui.
pub(crate) fn attendre_hebdomadaire() {
    let fil = HEBDOMADAIRE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(f) = fil {
        let _ = f.join();
    }
}

/// Reporter l'autotest dû parce qu'un jeu tourne ? Seulement une semaine de plus : un programme qui ferait croire à
/// un jeu sans fin (ou un jeu jamais quitté) ne le repousse pas pour toujours ; au-delà de deux semaines depuis le
/// dernier, il est lancé quand même (en fond, sans notification, comme toujours). Sans dernier autotest lisible,
/// jamais reporté : rien ne dit depuis quand il attend.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn reporter(d: Option<&Dernier>, maintenant: chrono::DateTime<chrono::Utc>, jeu: Option<bool>) -> bool {
    jeu == Some(true)
        && d.and_then(|d| date(&d.quand))
            .is_some_and(|q| maintenant - q < chrono::Duration::days(2 * SEMAINE))
}

/// L'hebdomadaire est-il dû ? Oui sans dernier autotest lisible (absent, changé hors de Vanguard : une date forgée ne
/// le repousse pas), ou après 7 jours ; une date dans le futur ne le repousse pas non plus.
fn du(d: Option<&Dernier>, maintenant: chrono::DateTime<chrono::Utc>) -> bool {
    d.and_then(|d| date(&d.quand)).is_none_or(|q| {
        let ecart = maintenant - q;
        ecart >= chrono::Duration::days(SEMAINE) || ecart < chrono::Duration::zero()
    })
}

fn hebdomadaire(constats: &[Constat]) {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let croisees = croiser();
    let preuve = Preuve {
        verdict: "non-prise",
        fichiers: Vec::new(),
        nombre: 0,
    };
    let r = rapport(debut, true, juger_regles(constats, &[], &[]), &croisees, preuve);
    ecrire(&r, &croisees, debut);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{alerte, impossible_par, ok};

    /// Un jeu en cours (ou un faux GameMode) reporte l'autotest dû d'une semaine au plus ; sans dernier lisible, jamais.
    #[test]
    fn report_borne_pendant_un_jeu() {
        let maintenant = chrono::Utc::now();
        let il_y_a = |jours: i64| Dernier {
            quand: (maintenant - chrono::Duration::days(jours)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            verdict: "ok".into(),
            contredites: Vec::new(),
        };
        assert!(reporter(Some(&il_y_a(8)), maintenant, Some(true)));
        assert!(!reporter(Some(&il_y_a(8)), maintenant, Some(false)));
        assert!(!reporter(Some(&il_y_a(8)), maintenant, None));
        assert!(!reporter(Some(&il_y_a(15)), maintenant, Some(true)));
        assert!(!reporter(None, maintenant, Some(true)));
    }

    fn constat(regle: &'static str, c: Constat) -> Constat {
        Constat { regle, ..c }
    }

    /// Les règles comptées par leur raison ; les invariants vus (sans règle, incohérent, message vide).
    #[test]
    fn regles_et_invariants() {
        let regles = crate::machine::regles::regles(crate::machine::regles::Os::actuel());
        let (a, b, c) = (regles[0].id, regles[1].id, regles[2].id);
        let constats = vec![
            constat(
                a,
                impossible_par("Audit", Raison::Panique, "Impossible de vérifier (erreur interne)."),
            ),
            constat(b, impossible_par("Audit", Raison::Delai, "délai")),
            constat(c, ok("Pare-feu", "")),
            ok("Pare-feu", "sans règle"),
            constat(
                c,
                Constat {
                    verifie: false,
                    ..alerte("Pare-feu", Niveau::Critique, "trop fort")
                },
            ),
        ];
        let r = juger_regles(&constats, &[(a, Duration::from_millis(12))], &[]);
        assert_eq!(r.plantees, vec![a]);
        assert_eq!(r.hors_delai, vec![b]);
        assert_eq!(r.ont_repondu, regles.len() - 2);
        let genres: Vec<&str> = r.invariants.iter().map(|i| i.genre).collect();
        assert_eq!(genres, ["message-vide", "sans-regle", "etat-incoherent"]);
        assert_eq!(r.durees_ms[a], 12);
    }

    /// Changé hors surveillance : « change » ; avec une passe de la surveillance pendant l'essai : « non concluante »,
    /// jamais « change ».
    #[test]
    fn preuve_et_surveillance_en_meme_temps() {
        let maintenant = std::time::SystemTime::now();
        let vieille = maintenant - Duration::from_hours(3);
        let ecart = vec![("administrateurs.json".to_string(), lecture_seule::Changement::Change)];
        let calme = (Some(b"2026-10-23 08:00:00".to_vec()), Some(vieille));
        assert_eq!(
            juger_preuve(&[], false, &calme, &calme, maintenant).verdict,
            "rien-change"
        );
        let p = juger_preuve(&ecart, false, &calme, &calme, maintenant);
        assert_eq!(
            (p.verdict, p.fichiers.clone()),
            ("change", vec!["administrateurs.json".to_string()])
        );
        let nouvelle = (Some(b"2026-10-23 11:00:00".to_vec()), Some(maintenant));
        assert_eq!(
            juger_preuve(&ecart, false, &calme, &nouvelle, maintenant).verdict,
            "non-concluante"
        );
        let recente = (calme.0.clone(), Some(maintenant - Duration::from_secs(60)));
        assert_eq!(
            juger_preuve(&ecart, false, &recente, &recente, maintenant).verdict,
            "non-concluante"
        );
        assert_eq!(juger_preuve(&[], true, &calme, &calme, maintenant).verdict, "bornee");
        // Un nom hors inventaire ne sort pas tel quel.
        let p = juger_preuve(
            &[("alice-laptop.txt".to_string(), lecture_seule::Changement::Ajoute)],
            false,
            &calme,
            &calme,
            maintenant,
        );
        assert_eq!(p.fichiers, vec!["autre".to_string()]);
        // Trois fichiers, dont deux hors inventaire non voisins : deux noms, mais trois changés au journal.
        let p = juger_preuve(
            &[
                ("alice-a.txt".to_string(), lecture_seule::Changement::Ajoute),
                ("administrateurs.json".to_string(), lecture_seule::Changement::Change),
                ("bob-b.txt".to_string(), lecture_seule::Changement::Ajoute),
            ],
            false,
            &calme,
            &calme,
            maintenant,
        );
        assert_eq!(
            p.fichiers,
            vec!["administrateurs.json".to_string(), "autre".to_string()]
        );
        assert_eq!(p.nombre, 3);
    }

    fn croisee_d_essai() -> &'static Croisee {
        static C: Croisee = Croisee {
            id: "AUT-LNX-999",
            systeme: crate::machine::regles::Os::Linux,
            sujet: ("essai", "test"),
            outil: "pacman -Q",
            regles: &["LNX-MAJ-006"],
            comparer: || Comparaison::Pareil { n: 1 },
        };
        &C
    }

    /// Anonymat : un écart sur des noms piégés (nom d'ordinateur, courriel, SID) n'en laisse aucun dans le JSON, le
    /// résultat gardé ni le journal des erreurs : seulement des identifiants, des nombres et des genres.
    #[test]
    fn aucune_valeur_ne_sort() {
        // Le courriel est assemblé ici : écrit en clair, il ferait réagir le garde-fou de confidentialité du dépôt.
        let courriel = format!("alice{}example.com", '@');
        let pieges = ["alice-laptop", courriel.as_str(), "S-1-5-21-1-1-1-1001", "Salon-5G"];
        let x = croisees::comparer(
            pieges.iter().map(|p| ((*p).to_string(), "1.0".to_string())),
            [("bash".to_string(), "5.2".to_string())],
        );
        let c = croisee_d_essai();
        let croisees = vec![(c, x)];
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        let r = rapport(
            debut,
            false,
            Regles::default(),
            &croisees,
            Preuve {
                verdict: "rien-change",
                fichiers: Vec::new(),
                nombre: 0,
            },
        );
        assert_eq!(r.code, 1);
        let json = serde_json::to_string(&r).unwrap();
        let journal: String = entrees_du_journal(&r)
            .iter()
            .map(|(a, b)| [a.as_str(), " ", b.as_str(), "\n"].concat())
            .collect();
        let gardes: String = constats_du_rapport(&r, &croisees)
            .iter()
            .map(|c| c.message.clone())
            .collect();
        for p in pieges.iter().chain(&["bash", "5.2"]) {
            assert!(!json.contains(p), "{p} dans le JSON : {json}");
            assert!(!journal.contains(p), "{p} au journal : {journal}");
            assert!(!gardes.contains(p), "{p} dans le résultat : {gardes}");
        }
        assert!(journal.contains("autotest AUT-LNX-999") && journal.contains("[absent-natif] 4 en plus, 1 en moins"));
    }

    /// Le code de sortie : 0 tout bon, 1 écart, 2 du non vérifié ; une lecture sans objet ne compte pas.
    #[test]
    fn codes_de_sortie() {
        let c = croisee_d_essai();
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        let preuve = || Preuve {
            verdict: "rien-change",
            fichiers: Vec::new(),
            nombre: 0,
        };
        // Les mesures du vrai dossier local n'entrent pas dans le code attendu : assez de jours, sans régression.
        let assez = |mut r: Rapport| {
            r.mesures = mesures::Verdict {
                verdict: "sans-regression",
                jours: 35,
                lentes: Vec::new(),
                frolent_le_delai: Vec::new(),
            };
            r
        };
        let r = |x: Comparaison, p: Preuve| code_de(&assez(rapport(debut, false, Regles::default(), &[(c, x)], p))).0;
        assert_eq!(r(Comparaison::Pareil { n: 3 }, preuve()), 0);
        assert_eq!(r(Comparaison::SansObjet("dpkg absent".into()), preuve()), 0);
        assert_eq!(r(Comparaison::Saute(Raison::Absente("pacman".into())), preuve()), 2);
        assert_eq!(r(Comparaison::inattendue(), preuve()), 1);
        assert_eq!(
            r(
                Comparaison::Pareil { n: 3 },
                Preuve {
                    verdict: "non-concluante",
                    fichiers: Vec::new(),
                    nombre: 0,
                }
            ),
            2
        );
        assert_eq!(
            r(
                Comparaison::Pareil { n: 3 },
                Preuve {
                    verdict: "change",
                    fichiers: vec!["x".into()],
                    nombre: 1,
                }
            ),
            1
        );
        assert_eq!(
            code_de(&assez(rapport(debut, false, Regles::default(), &[], preuve()))).0,
            2,
            "aucune lecture : non vérifié"
        );
        let mut court = assez(rapport(
            debut,
            false,
            Regles::default(),
            &[(c, Comparaison::Pareil { n: 3 })],
            preuve(),
        ));
        court.mesures.verdict = "pas-assez";
        assert_eq!(
            code_de(&court),
            (2, "non-verifie"),
            "pas assez de mesures : non vérifié"
        );
    }

    /// L'hebdomadaire : pas avant 7 jours ; une date absente, illisible ou dans le futur le relance.
    #[test]
    fn hebdomadaire_pas_avant_sept_jours() {
        let maintenant = date("2026-10-23T10:00:00Z").unwrap();
        let d = |q: &str| Dernier {
            quand: q.into(),
            ..Dernier::default()
        };
        assert!(du(None, maintenant));
        assert!(!du(Some(&d("2026-10-20T10:00:00Z")), maintenant));
        assert!(du(Some(&d("2026-10-16T10:00:00Z")), maintenant));
        assert!(
            du(Some(&d("2099-01-01T00:00:00Z")), maintenant),
            "date forgée dans le futur"
        );
        assert!(du(Some(&d("abîmé")), maintenant));
    }

    /// Une date forgée hors de Vanguard (sceau qui ne correspond plus) n'est pas lue : l'hebdomadaire est relancé.
    #[test]
    fn dernier_forge_ignore() {
        let d = crate::socle::dossier_local().join("essai-autotest-dernier");
        let _ = std::fs::remove_dir_all(&d);
        let vrai = serde_json::to_vec(&Dernier {
            quand: "2026-10-22T10:00:00Z".into(),
            ..Dernier::default()
        })
        .unwrap();
        crate::sceau::ecrire_dans(&d, DERNIER, &vrai).unwrap();
        assert!(matches!(
            crate::sceau::lire_dans(&d, DERNIER),
            crate::sceau::Lecture::Intact(_)
        ));
        std::fs::write(
            d.join(DERNIER),
            b"{\"quand\":\"2099-01-01T00:00:00Z\",\"verdict\":\"sain\"}",
        )
        .unwrap();
        assert!(matches!(
            crate::sceau::lire_dans(&d, DERNIER),
            crate::sceau::Lecture::Falsifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une lecture contredite le dit aux constats sains de ses règles, jamais à leurs problèmes ; après 30 jours, plus.
    #[test]
    fn lecture_contredite_annoncee_aux_constats_sains() {
        let d = Dernier {
            quand: "2026-10-20T10:00:00Z".into(),
            verdict: "ecart".into(),
            contredites: vec![Contredite {
                croisee: "AUT-LNX-003".into(),
                outil: "pacman -Qmq".into(),
                regles: vec!["LNX-MAJ-006".into()],
                quand: String::new(),
            }],
        };
        let mut constats = vec![
            constat("LNX-MAJ-006", ok("Mises à jour", "Aucun paquet de l'AUR.")),
            constat(
                "LNX-MAJ-006",
                alerte("Mises à jour", Niveau::Moyen, "Paquet pas à jour."),
            ),
            constat("LNX-PFE-001", ok("Pare-feu", "Actif.")),
        ];
        annoter_selon(&mut constats, &d, date("2026-10-23T10:00:00Z").unwrap());
        assert!(constats[0].message.contains("pacman -Qmq"), "{}", constats[0].message);
        assert_eq!(constats[1].message, "Paquet pas à jour.");
        assert_eq!(constats[2].message, "Actif.");
        let mut vieux = vec![constat("LNX-MAJ-006", ok("Mises à jour", "Aucun."))];
        annoter_selon(&mut vieux, &d, date("2026-12-23T10:00:00Z").unwrap());
        assert_eq!(vieux[0].message, "Aucun.");
    }

    /// Une lecture sautée ne tranche rien : la contradiction de l'essai A reste, à sa date, jusqu'à un « pareil ».
    #[test]
    fn une_lecture_sautee_n_efface_pas_la_contradiction() {
        static PORTS: Croisee = Croisee {
            id: "AUT-LNX-006",
            systeme: crate::machine::regles::Os::Linux,
            sujet: ("ports en écoute", "listening ports"),
            outil: "ss -tlnpe / -ulnpe",
            regles: &["LNX-RES-001"],
            comparer: Comparaison::inattendue,
        };
        let essai = |x: Comparaison, quand: &str, avant: Option<Dernier>| Dernier {
            quand: quand.into(),
            verdict: String::new(),
            contredites: contredites(&[(&PORTS, x)], quand, avant),
        };
        let a = essai(Comparaison::inattendue(), "2026-10-01T10:00:00Z", None);
        let b = essai(
            Comparaison::Saute(crate::modele::Raison::Delai),
            "2026-10-08T10:00:00Z",
            Some(a),
        );
        assert_eq!(b.contredites.len(), 1);
        assert_eq!(b.contredites[0].quand, "2026-10-01T10:00:00Z");
        let sain = || vec![constat("LNX-RES-001", ok("Pare-feu", "Rien en écoute."))];
        let mut v = sain();
        annoter_selon(&mut v, &b, date("2026-10-09T10:00:00Z").unwrap());
        assert!(v[0].message.contains("ss -tlnpe"), "{}", v[0].message);
        // 30 jours après l'essai A, même repris par B : plus de mention.
        let mut v = sain();
        annoter_selon(&mut v, &b, date("2026-11-05T10:00:00Z").unwrap());
        assert_eq!(v[0].message, "Rien en écoute.");
        let c = essai(Comparaison::Pareil { n: 2 }, "2026-10-15T10:00:00Z", Some(b));
        assert_eq!(c.contredites, Vec::<Contredite>::new());
    }

    /// Règles « déjà vu » : un nouvel administrateur simulé (aucun n'est encore connu), un autotest (la règle relancée
    /// sous l'interrupteur), puis le bilan normal : l'alerte « nouvel administrateur » sort toujours, l'autotest n'a
    /// rien appris.
    #[cfg(unix)]
    #[test]
    fn l_autotest_n_apprend_jamais() {
        let fichier = crate::socle::dossier_local().join("administrateurs.json");
        crate::socle::ecrire_atomique(&fichier, b"{\"vus\":{}}").unwrap();
        lecture_seule::poser();
        let essai = crate::machine::auditer_seulement(|id| id == "COM-CPT-001");
        lecture_seule::relever_pour_le_test();
        assert_eq!(
            std::fs::read(&fichier).unwrap(),
            b"{\"vus\":{}}",
            "l'autotest a appris les administrateurs"
        );
        if !essai
            .constats
            .iter()
            .any(|c| c.probleme.is_some_and(|n| n > Niveau::Info))
        {
            return crate::essais::saute("aucun administrateur sur cet ordinateur : rien de nouveau à signaler");
        }
        let bilan = crate::machine::auditer_seulement(|id| id == "COM-CPT-001");
        assert!(
            bilan
                .constats
                .iter()
                .any(|c| c.probleme.is_some_and(|n| n > Niveau::Info)),
            "l'alerte du nouvel administrateur ne sort plus après l'autotest"
        );
    }
}
