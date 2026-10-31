//! Les clés VANGUARD que cet ordinateur connaît. Le témoin `vanguard.cle` dit qu'un volume est fait comme une clé,
//! pas que c'est la sienne : n'importe quelle clé reçue ou image disque ouverte le porte si quelqu'un l'y a posé, et
//! Vanguard lancé depuis sa copie locale (surveillance, entretien, raccourci) y écrirait la base des appareils, le
//! rapport et le diagnostic, et en lirait un carnet qui décide de « Nouvel appareil ». D'où une identité : au
//! déploiement, outils/deployer.sh tire une fois un jeton (`vanguard.jeton`, 32 caractères hexadécimaux) à la racine
//! de la clé et le recopie sur la partition des journaux ; cet ordinateur garde les jetons qu'il reconnaît dans
//! `cles-connues.json` (dossier de Vanguard). Une clé y entre quand Vanguard est lancé depuis elle (la personne l'a
//! branchée et lancée) ou quand son manifeste est écrit (déploiement, chez le propriétaire). Un volume au témoin
//! sans jeton connu n'est jamais lu ni écrit.
//!
//! Par jeton, l'ordinateur note aussi l'état du carnet des appareils tel que Vanguard l'y a écrit en dernier :
//! l'empreinte BLAKE3 du fichier et la présence de l'enveloppe de chiffrement. Un carnet qui a changé sans passer par
//! Vanguard (clé perdue puis revenue, copie remplacée) ou dont l'enveloppe a disparu n'est ni lu ni réécrit, et le
//! bilan le dit ; `vanguard manifeste --accepter` prend l'état actuel quand c'est voulu (copie restaurée). L'empreinte
//! n'est comparée que là où la clé est modifiable : c'est là que Vanguard l'écrit. Sur un ordinateur où la clé est en
//! lecture seule (celui d'un ami), chaque scan fait chez soi aurait sinon l'air d'une modification.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::machine::{Constat, alerte};
use crate::risk::Niveau;
use crate::ui::*;

/// Le jeton d'identité, à la racine de la clé et de sa partition des journaux.
pub const JETON: &str = "vanguard.jeton";
const FICHIER: &str = crate::sceau::CLES_CONNUES;
const FORMAT: &str = "vanguard-cles-connues";
const CAT: &str = "Clé USB";

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
struct CleConnue {
    /// « AAAA-MM-JJ HH:MM » de la reconnaissance.
    depuis: String,
    /// Empreinte BLAKE3 du carnet tel que Vanguard l'a écrit en dernier sur cette clé ; absente : pas de carnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    carnet: Option<String>,
    /// Le carnet y était protégé par une phrase (enveloppe présente).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    protege: bool,
}

#[derive(Serialize, Deserialize)]
struct Fichier {
    format: String,
    cles: BTreeMap<String, CleConnue>,
}

/// Pourquoi le carnet d'une clé connue n'est ni lu ni réécrit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refus {
    /// L'enveloppe de chiffrement a disparu : le carnet en clair qui la remplace n'est pas celui de Vanguard.
    ProtectionRetiree,
    /// Le carnet n'est plus celui que Vanguard a écrit en dernier ici.
    CarnetModifie,
}

impl Refus {
    pub(crate) fn texte(self) -> String {
        match self {
            Refus::ProtectionRetiree => tr!(
                "la protection du carnet de la clé a été retirée hors de Vanguard (enveloppe absente)",
                "the key record's protection was removed outside Vanguard (envelope missing)"
            ),
            Refus::CarnetModifie => tr!(
                "le carnet de la clé a été modifié hors de Vanguard",
                "the key's record was changed outside Vanguard"
            ),
        }
        .to_string()
    }
}

/// Le jeton d'un volume, en minuscules ; rien s'il manque ou s'il n'a pas la forme attendue : il devient une clé du
/// fichier des clés connues, et un fichier posé par n'importe qui ne doit pas y mettre n'importe quoi.
pub(crate) fn jeton_de(racine: &Path) -> Option<String> {
    // Lu sur un volume qui n'est peut-être pas une clé : seulement un fichier ordinaire, et 64 octets au plus (un
    // fichier spécial bloquerait le menu à chaque affichage, un fichier démesuré remplirait la mémoire).
    // Ouvert sans suivre de lien et sans attendre, jugé sur ce qui est ouvert (`socle::lire_ordinaire`).
    let octets = crate::socle::lire_ordinaire(&racine.join(JETON), 64).ok()?;
    jeton_valide(std::str::from_utf8(&octets).ok()?)
}

fn jeton_valide(texte: &str) -> Option<String> {
    let t = texte.trim();
    (t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit())).then(|| t.to_ascii_lowercase())
}

fn chemin(base: &Path) -> PathBuf {
    base.join(FICHIER)
}

/// Lire, changer, réécrire le fichier des clés connues : sans verrou, deux notes en même temps (deux fils, ou les
/// tests en parallèle) en perdaient une, et la clé perdue n'était plus reconnue. Les lectures le prennent aussi : sous
/// Windows, remplacer un fichier qu'un autre fil est en train de lire échoue.
static VERROU: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn verrou() -> std::sync::MutexGuard<'static, ()> {
    VERROU.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `lire_dans`, sous le verrou.
fn lire_verrouille(base: &Path) -> BTreeMap<String, CleConnue> {
    let _garde = verrou();
    lire_dans(base)
}

/// Relu sous son sceau : changé hors de Vanguard (un jeton inscrit d'avance ferait d'une clé piégée une clé
/// connue), effacé ou illisible, aucune clé n'y est connue (tout est redit, rien n'est lu ni écrit sur un volume) et
/// le bilan le dit ; la personne qui relance depuis sa clé la fait reconnaître de nouveau. Un fichier qui ne se lit
/// pas, ou changé, est mis de côté, jamais écrasé en silence : il nommait les clés de la personne.
fn lire_dans(base: &Path) -> BTreeMap<String, CleConnue> {
    use crate::sceau::Lecture;
    let fichier = chemin(base);
    let octets = match crate::sceau::lire_dans(base, FICHIER) {
        Lecture::Intact(o) => Some(o),
        Lecture::Adopte(o) if crate::sceau::repris_dans(base, FICHIER) => Some(o),
        Lecture::Adopte(_) | Lecture::Falsifie(Some(_)) => None,
        Lecture::Absent | Lecture::Inconnu | Lecture::Falsifie(None) | Lecture::Illisible(_) => {
            return BTreeMap::new();
        }
    };
    let lu = octets
        .and_then(|o| serde_json::from_str::<Fichier>(String::from_utf8_lossy(&o).trim_start_matches('\u{feff}')).ok());
    match lu {
        Some(f) if f.format == FORMAT => f.cles,
        _ => {
            let copie = fichier.with_extension(format!(
                "illisible-{}.json",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            ));
            // Jamais en administrateur dans le dossier d'un compte (`socle::ecriture_sure`).
            if crate::socle::ecriture_sure(base) {
                let _ = std::fs::rename(&fichier, &copie);
            }
            BTreeMap::new()
        }
    }
}

fn ecrire_dans(base: &Path, cles: &BTreeMap<String, CleConnue>) -> std::io::Result<()> {
    let f = Fichier {
        format: FORMAT.into(),
        cles: cles.clone(),
    };
    let texte = serde_json::to_string_pretty(&f).map_err(std::io::Error::other)?;
    crate::sceau::ecrire_dans(base, FICHIER, texte.as_bytes())
}

/// Les jetons que cet ordinateur reconnaît.
pub(crate) fn jetons() -> BTreeSet<String> {
    lire_verrouille(&crate::socle::dossier_local()).into_keys().collect()
}

/// Parmi `volumes` (ceux qui portent le témoin), la clé connue : deux clés connues branchées, la première dans l'ordre
/// des chemins (« /run/media/alice/VANGUARD » avant « …/VANGUARD1 »), la même à chaque lancement, l'autre n'est pas
/// regardée ; deux volumes à son jeton, aucun : une copie de la clé (identifiant de volume compris) ne doit rien lire
/// ni recevoir selon l'ordre des chemins (campagne d'attaque n° 4, C-B2). Seul le jeton de la première est cherché en
/// double : celui d'une seconde clé connue, qu'elle ne remplace pas, ne change rien à ce qui est choisi.
pub(crate) fn seule_connue(volumes: Vec<PathBuf>, jetons: &BTreeSet<String>) -> Option<PathBuf> {
    premiere_connue(volumes, jetons).and_then(|(cle, en_double)| (!en_double).then_some(cle))
}

/// Parmi `volumes`, une clé connue a-t-elle une copie à son jeton (la règle de `seule_connue`) ? Le dire autrement
/// qu'un volume inconnu : redéployer n'y changerait rien, c'est l'une des deux à débrancher.
pub(crate) fn en_double(volumes: Vec<PathBuf>, jetons: &BTreeSet<String>) -> bool {
    premiere_connue(volumes, jetons).is_some_and(|(_, en_double)| en_double)
}

/// La première clé connue dans l'ordre des chemins, et si un autre volume porte son jeton.
fn premiere_connue(volumes: Vec<PathBuf>, jetons: &BTreeSet<String>) -> Option<(PathBuf, bool)> {
    premiere_parmi_lus(volumes.into_iter().map(|d| (jeton_de(&d), d)).collect(), jetons)
}

/// `seule_connue` sur des jetons déjà lus (`jeton_de`) : le journal sous Windows les lit dans des fils bornés dans le
/// temps, un lecteur réseau qui cesse de répondre ne doit pas figer le programme ici.
#[cfg(any(windows, test))]
pub(crate) fn seule_parmi_lus(lus: Vec<(Option<String>, PathBuf)>, jetons: &BTreeSet<String>) -> Option<PathBuf> {
    premiere_parmi_lus(lus, jetons).and_then(|(cle, en_double)| (!en_double).then_some(cle))
}

fn premiere_parmi_lus(mut lus: Vec<(Option<String>, PathBuf)>, jetons: &BTreeSet<String>) -> Option<(PathBuf, bool)> {
    lus.sort_by(|a, b| a.1.cmp(&b.1));
    let mut cles = lus
        .into_iter()
        .filter_map(|(j, d)| j.filter(|j| jetons.contains(j)).map(|j| (d, j)));
    let (cle, jeton) = cles.next()?;
    let en_double = cles.any(|(_, j)| j == jeton);
    Some((cle, en_double))
}

/// Au-delà, ce n'est pas un carnet des appareils.
const CARNET_MAX: u64 = 256 << 20;

/// L'empreinte du carnet que Vanguard lirait : le chiffré quand l'enveloppe est là, sinon le clair.
fn empreinte_du_carnet(donnees: &Path) -> Option<String> {
    let fichier = if crate::chiffrement::protegee(donnees) {
        crate::chiffrement::CARNET_CHIFFRE
    } else {
        "appareils.json"
    };
    // Un simple fichier, borné : un tube ou un lien vers /dev/zero posé sur la clé ne fige ni ne remplit rien.
    let octets = crate::socle::lire_ordinaire(&donnees.join(fichier), CARNET_MAX).ok()?;
    Some(blake3::hash(&octets).to_hex().to_string())
}

/// Note dans `base` l'état actuel du carnet de la clé `racine` : reconnue si elle ne l'était pas, empreinte et
/// protection telles qu'elles sont. Rien sans jeton (clé pas encore redéployée : rien à reconnaître).
fn noter_dans(base: &Path, racine: &Path) -> bool {
    let _garde = verrou();
    let Some(jeton) = jeton_de(racine) else {
        return false;
    };
    let donnees = racine.join("donnees");
    let mut cles = lire_dans(base);
    let entree = cles.entry(jeton).or_insert_with(|| CleConnue {
        depuis: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        ..CleConnue::default()
    });
    entree.carnet = empreinte_du_carnet(&donnees);
    entree.protege = crate::chiffrement::protegee(&donnees);
    ecrire_dans(base, &cles).is_ok()
}

/// La clé que Vanguard vient d'écrire ou que la personne vient de brancher et de lancer : son état est la référence.
pub(crate) fn noter(racine: &Path) -> bool {
    noter_dans(&crate::socle::dossier_local(), racine)
}

/// Une clé déjà connue garde sa référence ; une nouvelle entre avec son état du moment (la confiance d'aujourd'hui :
/// la personne l'a branchée et lancée, ou la déploie).
fn reconnaitre_dans(base: &Path, racine: &Path) -> bool {
    match jeton_de(racine) {
        Some(j) if lire_verrouille(base).contains_key(&j) => true,
        Some(_) => noter_dans(base, racine),
        None => false,
    }
}

/// Au lancement : la clé d'où tourne le programme entre dans les clés connues. Avant toute lecture du carnet et
/// avant le premier mot du journal des erreurs, qui cherche la partition des journaux au jeton de cette clé.
pub fn reconnaitre_la_cle_du_programme() {
    if cfg!(test) {
        return;
    }
    if let Some(cle) = crate::reseau::cle_du_programme() {
        reconnaitre_dans(&crate::socle::dossier_local(), &cle);
    }
}

/// Le carnet de la clé `racine` peut-il être lu et réécrit ? `modifiable` : la clé s'écrit ici, l'empreinte compte.
fn verdict_dans(base: &Path, racine: &Path, modifiable: bool) -> Result<(), Refus> {
    // Sans jeton (clé d'avant le jeton, lancée depuis elle) ou pas encore notée : rien à comparer.
    let Some(connue) = jeton_de(racine).and_then(|j| lire_verrouille(base).remove(&j)) else {
        return Ok(());
    };
    let donnees = racine.join("donnees");
    if connue.protege && !crate::chiffrement::protegee(&donnees) {
        return Err(Refus::ProtectionRetiree);
    }
    if modifiable && connue.carnet != empreinte_du_carnet(&donnees) {
        return Err(Refus::CarnetModifie);
    }
    Ok(())
}

pub(crate) fn verdict(racine: &Path, modifiable: bool) -> Result<(), Refus> {
    verdict_dans(&crate::socle::dossier_local(), racine, modifiable)
}

/// « vanguard manifeste --accepter » : l'état actuel du carnet de la clé branchée devient la référence.
pub(crate) fn accepter() {
    let Some(cle) = crate::reseau::cle_usb() else {
        trp!("  Clé VANGUARD non branchée.", "  VANGUARD key not plugged in.");
        return;
    };
    if jeton_de(&cle).is_none() {
        trp!(
            "  Cette clé n'a pas de jeton (vanguard.jeton) : rien à accepter. Remettez-la à jour chez vous (outils/deployer.sh).",
            "  This key has no token (vanguard.jeton): nothing to accept. Update it at home (outils/deployer.sh)."
        );
        return;
    }
    if noter(&cle) {
        trp!(
            "  {VERT}✔{RESET} Carnet de la clé accepté tel qu'il est : il est de nouveau lu et réécrit.",
            "  {VERT}✔{RESET} Key record accepted as it is: it is read and written again."
        );
    } else {
        trp!(
            "  ✖ Clés connues non enregistrées sur cet ordinateur.",
            "  ✖ Known keys not saved on this computer."
        );
    }
}

/// Au bilan : la clé reconnue dont le carnet est refusé (niveau élevé), ou un volume au témoin sans jeton connu,
/// ignoré (information au premier usage : une clé à soi pas encore redéployée a le même air ; moyen dès que cet
/// ordinateur a déployé des clés, voir `constat_inconnue`).
pub fn constats() -> Vec<Constat> {
    // Pendant les tests, jamais la vraie clé branchée sur l'ordinateur de développement.
    if cfg!(test) {
        return Vec::new();
    }
    match crate::reseau::cle_usb() {
        Some(cle) => match verdict(&cle, crate::reseau::modifiable(&cle)) {
            Ok(()) => Vec::new(),
            Err(refus) => vec![constat_refus(refus)],
        },
        None if crate::reseau::cle_en_double() => vec![constat_en_double()],
        None if crate::reseau::volume_inconnu() => vec![constat_inconnue(
            crate::protection::manifeste::a_des_references(&crate::socle::dossier_local()),
        )],
        None => Vec::new(),
    }
}

fn constat_refus(refus: Refus) -> Constat {
    let pourquoi = refus.texte();
    // L'objet : le refus lui-même, sans langue ; accepter un carnet modifié ne tait pas une protection retirée.
    let objet = match refus {
        Refus::ProtectionRetiree => "protection-retiree",
        Refus::CarnetModifie => "carnet-modifie",
    };
    alerte(
        CAT,
        Niveau::Eleve,
        trf!(
            "Clé VANGUARD : {pourquoi}. Son carnet n'est ni lu ni réécrit, et le rapport reste sur cet ordinateur : un carnet préparé ferait passer un intrus pour un habitué du réseau.",
            "VANGUARD key: {pourquoi}. Its record is neither read nor rewritten, and the report stays on this computer: a prepared record would make an intruder look like a regular of the network."
        ),
    )
    .avec_objet(crate::modele::Objet::de("refus", objet))
    .manuel(
        tr!(
            "Si c'est voulu (copie restaurée, protection retirée ailleurs) : vanguard manifeste --accepter ; sinon, regardez ce qui a touché la clé avant de vous en resservir",
            "If intended (restored copy, protection removed elsewhere): vanguard manifeste --accepter; otherwise, find out what touched the key before using it again"
        ),
        &[],
    )
}

/// Deux volumes au jeton d'une même clé connue : une copie de la clé, l'original ou non, dont rien ne dit laquelle est
/// la vraie (campagne d'attaque n° 4, C-B2) ; aucune n'est lue ni écrite, et rien n'a été comparé.
fn constat_en_double() -> Constat {
    Constat {
        verifie: false,
        ..alerte(
            CAT,
            Niveau::Moyen,
            tr!(
                "Deux volumes branchés portent le jeton de la même clé VANGUARD : l'un est une copie de l'autre (identifiant de volume compris). Rien n'est lu ni écrit sur aucun, rien n'a été comparé.",
                "Two plugged-in volumes carry the token of the same VANGUARD key: one is a copy of the other (volume identifier included). Nothing is read from or written to either, nothing was compared."
            ),
        )
        .manuel(
            tr!(
                "Débranchez celle qui n'est pas votre clé ; ne lancez rien depuis elle",
                "Unplug the one that is not your key; do not run anything from it"
            ),
            &[],
        )
    }
}

/// Un volume au témoin sans jeton connu. Là où des clés ont déjà été déployées (`deja_deployees` : une référence
/// de manifeste existe), changer le jeton (un simple fichier texte) et le numéro de série d'une clé qui a voyagé
/// suffisait à la faire passer pour un volume étranger, en simple information : rien n'a été comparé, c'est un
/// avertissement moyen. Sans aucune clé déployée ici, c'est le premier usage : information.
fn constat_inconnue(deja_deployees: bool) -> Constat {
    if deja_deployees {
        return Constat {
            verifie: false,
            ..alerte(
                CAT,
                Niveau::Moyen,
                tr!(
                    "Un volume branché porte le témoin d'une clé VANGUARD sans jeton connu de cet ordinateur : autre clé que celles déployées ici, ou clé dont le jeton et l'identifiant de volume ont été changés. Rien n'a été comparé ni lu : ne lancez rien depuis elle avant de l'avoir redéployée.",
                    "A plugged-in volume carries a VANGUARD key marker without a token known to this computer: a key other than those deployed here, or a key whose token and volume identifier were changed. Nothing was compared or read: do not run anything from it before redeploying it."
                ),
            )
            .manuel(
                tr!(
                    "Redéployez-la avec outils/deployer.sh",
                    "Redeploy it with outils/deployer.sh"
                ),
                &[],
            )
        };
    }
    alerte(
        CAT,
        Niveau::Info,
        tr!(
            "Un volume branché porte le témoin d'une clé VANGUARD sans être connu de cet ordinateur : il est ignoré, rien n'y est lu ni écrit.",
            "A plugged-in volume carries a VANGUARD key marker without being known to this computer: it is ignored, nothing is read from or written to it."
        ),
    )
    .manuel(
        tr!(
            "Si c'est votre clé : lancez Vanguard depuis elle une fois, ou remettez-la à jour chez vous (outils/deployer.sh)",
            "If it is your key: run Vanguard from it once, or update it at home (outils/deployer.sh)"
        ),
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const JETON_A: &str = "0123456789abcdef0123456789abcdef";
    const JETON_B: &str = "fedcba9876543210fedcba9876543210";

    /// Un volume au témoin sans jeton connu : information au premier usage, moyen dès qu'une clé a été déployée ici
    /// (jeton et numéro de série changés ne ramènent plus une clé altérée à une information).
    #[test]
    fn volume_inconnu_la_ou_des_cles_sont_deployees() {
        let c = constat_inconnue(false);
        assert_eq!(c.probleme, Some(Niveau::Info));
        let c = constat_inconnue(true);
        assert_eq!((c.probleme, c.verifie), (Some(Niveau::Moyen), false));
        assert!(
            c.message.contains("jeton") || c.message.contains("token"),
            "{}",
            c.message
        );
    }

    /// Une copie de la clé : moyen, pas vérifié, et pas le conseil de redéployer.
    #[test]
    fn cle_en_double() {
        let c = constat_en_double();
        assert_eq!((c.probleme, c.verifie), (Some(Niveau::Moyen), false));
        let action = |c: &Constat| c.correctif.as_ref().map(|k| k.action.clone()).unwrap_or_default();
        let a = action(&c);
        assert!(a.contains("Débranchez") || a.contains("Unplug"), "{a}");
        // Le constat d'une clé inconnue, lui, conseille de redéployer : redéployer une copie ne la rendrait pas sûre.
        assert!(!a.contains("deployer.sh") && action(&constat_inconnue(true)).contains("deployer.sh"));
    }

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-cles-connues-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn fausse_cle(nom: &str, jeton: Option<&str>) -> PathBuf {
        let cle = jetable(nom);
        std::fs::create_dir_all(cle.join("donnees")).unwrap();
        std::fs::write(cle.join(crate::reseau::TEMOIN_CLE), "").unwrap();
        if let Some(j) = jeton {
            std::fs::write(cle.join(JETON), format!("{j}\n")).unwrap();
        }
        cle
    }

    /// Huit clés notées en même temps dans le même fichier : les huit y sont (une note perdue, et la clé n'était
    /// plus reconnue ; un fichier temporaire partagé, et la note échouait).
    #[test]
    fn notes_simultanees_toutes_gardees() {
        let base = jetable("simultanees");
        let cles: Vec<PathBuf> = (0..8)
            .map(|i| fausse_cle(&format!("simultanee-{i}"), Some(&format!("{i:032x}"))))
            .collect();
        std::thread::scope(|s| {
            for c in &cles {
                let base = &base;
                s.spawn(move || assert!(noter_dans(base, c)));
            }
        });
        assert_eq!(lire_dans(&base).len(), 8);
        for c in cles.iter().chain([&base]) {
            let _ = std::fs::remove_dir_all(c);
        }
    }

    #[test]
    fn jeton_bien_forme_seulement() {
        assert_eq!(
            jeton_valide(" 0123456789ABCDEF0123456789abcdef\n").as_deref(),
            Some(JETON_A)
        );
        assert!(jeton_valide("").is_none());
        assert!(jeton_valide("0123456789abcdef0123456789abcde").is_none());
        assert!(jeton_valide("0123456789abcdef0123456789abcdeg").is_none());
        assert!(jeton_valide("../../x").is_none());
    }

    /// Sur un volume quelconque, le jeton n'est lu que dans un petit fichier ordinaire : un dossier, un fichier
    /// démesuré ou (sous Unix) une file nommée ne bloquent ni ne remplissent rien.
    #[test]
    fn jeton_lu_seulement_dans_un_petit_fichier() {
        let racine = crate::socle::dossier_local().join("essai-jeton-borne");
        let _ = std::fs::remove_dir_all(&racine);
        std::fs::create_dir_all(&racine).unwrap();
        std::fs::write(racine.join(JETON), format!("{JETON_A}\n")).unwrap();
        assert_eq!(jeton_de(&racine).as_deref(), Some(JETON_A));
        std::fs::write(racine.join(JETON), format!("{JETON_A}{}", " ".repeat(10_000))).unwrap();
        assert!(jeton_de(&racine).is_none(), "au-delà de 64 octets, rien n'est pris");
        std::fs::remove_file(racine.join(JETON)).unwrap();
        std::fs::create_dir(racine.join(JETON)).unwrap();
        assert!(jeton_de(&racine).is_none());
        std::fs::remove_dir(racine.join(JETON)).unwrap();
        #[cfg(unix)]
        {
            crate::essais::tube_nomme(&racine.join(JETON)).unwrap();
            assert!(jeton_de(&racine).is_none(), "une file nommée ne bloque pas");
        }
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Un programme du compte inscrit d'avance le jeton d'une clé piégée dans cles-connues.json : le fichier n'est
    /// plus scellé, aucune clé n'y est connue (le jeton forgé non plus), et il est mis de côté.
    #[test]
    fn jeton_inscrit_d_avance_jamais_connu() {
        let base = jetable("forge");
        let a = fausse_cle("forge-a", Some(JETON_A));
        assert!(reconnaitre_dans(&base, &a));
        let mut texte = std::fs::read_to_string(chemin(&base)).unwrap();
        texte = texte.replacen(
            "\"cles\": {",
            &format!("\"cles\": {{\n    \"{JETON_B}\": {{\"depuis\": \"2026-01-01 10:00\"}},"),
            1,
        );
        std::fs::write(chemin(&base), texte).unwrap();
        let cles = lire_verrouille(&base);
        assert!(!cles.contains_key(JETON_B), "{cles:?}");
        assert!(cles.is_empty());
        // Le même jeton inscrit, puis sceaux.json effacé (son témoin resté) : accepté tel quel, jamais cru.
        assert!(reconnaitre_dans(&base, &a));
        let texte = std::fs::read_to_string(chemin(&base)).unwrap().replacen(
            "\"cles\": {",
            &format!("\"cles\": {{\n    \"{JETON_B}\": {{\"depuis\": \"2026-01-01 10:00\"}},"),
            1,
        );
        std::fs::write(chemin(&base), texte).unwrap();
        std::fs::remove_file(base.join("sceaux.json")).unwrap();
        assert!(!lire_verrouille(&base).contains_key(JETON_B));
        for d in [base, a] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn reconnaissance_et_fichier() {
        let base = jetable("base");
        let sans = fausse_cle("sans-jeton", None);
        let a = fausse_cle("a", Some(JETON_A));
        let b = fausse_cle("b", Some(JETON_B));
        assert!(!reconnaitre_dans(&base, &sans));
        assert!(reconnaitre_dans(&base, &a));
        assert!(reconnaitre_dans(&base, &b));
        let cles = lire_dans(&base);
        assert_eq!(cles.len(), 2);
        assert!(cles[JETON_A].carnet.is_none() && !cles[JETON_A].protege);
        let jetons: BTreeSet<String> = cles.keys().cloned().collect();
        // Deux clés connues : la première dans l'ordre des chemins ; sans jeton, aucune.
        assert_eq!(
            seule_connue(vec![b.clone(), sans.clone(), a.clone()], &jetons),
            Some(a.clone())
        );
        assert_eq!(seule_connue(vec![sans.clone()], &jetons), None);
        // Une copie de la première, jeton compris : aucune des deux, quel que soit l'ordre.
        let copie = fausse_cle("copie", Some(JETON_A));
        assert_eq!(seule_connue(vec![copie.clone(), a.clone(), b.clone()], &jetons), None);
        assert!(en_double(vec![copie.clone(), a.clone(), b.clone()], &jetons));
        assert!(!en_double(vec![a.clone(), b.clone(), sans.clone()], &jetons));
        let _ = std::fs::remove_dir_all(copie);
        // Jetons déjà lus (journal sous Windows) : la même règle, sans relire les volumes.
        let lu = |d: &PathBuf, j: Option<&str>| (j.map(str::to_owned), d.clone());
        let lus = vec![lu(&b, Some(JETON_B)), lu(&sans, None), lu(&a, Some(JETON_A))];
        assert_eq!(seule_parmi_lus(lus, &jetons), Some(a.clone()));
        let copie = PathBuf::from("/nulle-part/copie");
        let lus = vec![lu(&copie, Some(JETON_A)), lu(&a, Some(JETON_A))];
        assert_eq!(
            seule_parmi_lus(lus, &jetons),
            None,
            "la copie n'est pas lue sur le disque"
        );
        // Un fichier qui n'est pas le nôtre est mis de côté, pas écrasé.
        std::fs::write(chemin(&base), "{\"format\":\"autre\"}").unwrap();
        assert!(lire_dans(&base).is_empty());
        assert!(!chemin(&base).exists());
        assert!(
            std::fs::read_dir(&base)
                .unwrap()
                .flatten()
                .any(|e| { e.file_name().to_string_lossy().starts_with("cles-connues.illisible-") })
        );
        for d in [base, sans, a, b] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn carnet_modifie_hors_de_vanguard() {
        let base = jetable("verdict");
        let cle = fausse_cle("modifiee", Some(JETON_A));
        let carnet = cle.join("donnees").join("appareils.json");
        // Pas encore notée, ou sans jeton : rien à comparer.
        assert_eq!(verdict_dans(&base, &cle, true), Ok(()));
        std::fs::write(&carnet, "{\"reseaux\":{}}").unwrap();
        assert!(noter_dans(&base, &cle));
        assert_eq!(verdict_dans(&base, &cle, true), Ok(()));
        std::fs::write(&carnet, "{\"reseaux\":{\"x\":{\"appareils\":{}}}}").unwrap();
        assert_eq!(verdict_dans(&base, &cle, true), Err(Refus::CarnetModifie));
        // En lecture seule (ordinateur d'un ami), l'empreinte ne compte pas : chez soi, chaque scan la change.
        assert_eq!(verdict_dans(&base, &cle, false), Ok(()));
        // Carnet disparu : changé aussi.
        std::fs::write(&carnet, "{\"reseaux\":{}}").unwrap();
        assert!(noter_dans(&base, &cle));
        std::fs::remove_file(&carnet).unwrap();
        assert_eq!(verdict_dans(&base, &cle, true), Err(Refus::CarnetModifie));
        // Accepté tel quel : de nouveau bon.
        assert!(noter_dans(&base, &cle));
        assert_eq!(verdict_dans(&base, &cle, true), Ok(()));
        let sans = fausse_cle("sans", None);
        assert!(!noter_dans(&base, &sans));
        assert_eq!(verdict_dans(&base, &sans, true), Ok(()));
        for d in [base, cle, sans] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn enveloppe_retiree() {
        let base = jetable("enveloppe");
        let cle = fausse_cle("protegee", Some(JETON_A));
        let donnees = cle.join("donnees");
        std::fs::write(donnees.join("appareils.json"), "{\"reseaux\":{}}").unwrap();
        crate::chiffrement::proteger_dans(
            &donnees,
            &base.join("cle-donnees"),
            &base.join("local"),
            "phrase",
            (64, 1, 1),
        )
        .unwrap();
        assert!(noter_dans(&base, &cle));
        assert!(lire_dans(&base)[JETON_A].protege);
        assert_eq!(verdict_dans(&base, &cle, true), Ok(()));
        // Clé revenue sans enveloppe, avec un carnet en clair : refusée même en lecture seule.
        std::fs::remove_file(donnees.join(crate::chiffrement::ENVELOPPE)).unwrap();
        std::fs::write(donnees.join("appareils.json"), "{\"reseaux\":{}}").unwrap();
        assert_eq!(verdict_dans(&base, &cle, true), Err(Refus::ProtectionRetiree));
        assert_eq!(verdict_dans(&base, &cle, false), Err(Refus::ProtectionRetiree));
        // Protection ajoutée après la note : ce n'est pas un retrait.
        assert!(noter_dans(&base, &cle));
        crate::chiffrement::proteger_dans(
            &donnees,
            &base.join("cle-donnees"),
            &base.join("local"),
            "phrase",
            (64, 1, 1),
        )
        .unwrap();
        assert_eq!(verdict_dans(&base, &cle, false), Ok(()));
        for d in [base, cle] {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}
