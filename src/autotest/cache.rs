//! La mémoire cache des passages automatiques : le passage horaire de la surveillance reprend, un passage sur deux au
//! plus, le résultat de quelques vérifications lentes dont l'état change peu (`TABLE`), au lieu de les refaire. Rien
//! ne sort de l'ordinateur, rien ne passe par une IA.
//!
//! Les garde-fous, chacun tenu ici et essayé plus bas :
//! - **Seulement les passages automatiques.** Un bilan lancé par la personne vérifie tout à neuf, et vide la cache
//!   (`machine::audit`) ; seule `machine::auditer_automatique` (le passage horaire) s'en sert.
//! - **Une liste fermée.** Seules les règles de `TABLE` (mises à jour qui interrogent des serveurs, fichiers sensibles
//!   qui traînent) ; jamais ce qui peut changer d'une minute à l'autre ou trahir une attaque en cours (`EXCLUES`). Un
//!   résultat qui touche une catégorie que la surveillance notifie n'est jamais gardé
//!   (`reseau::surveillance::categorie_alertee`) : un résultat repris ne peut ni taire ni retarder une alerte.
//! - **Rien d'inventé.** Seul un résultat entièrement vérifié se garde ; il revient tel qu'il était (état, niveau,
//!   message, clé), sans sa correction, avec son âge à la fin du message (« vérifié il y a 40 min »). Un résultat non
//!   vérifié n'est jamais gardé : la règle se refait au passage suivant.
//! - **Un passage sur deux au plus, et une durée bornée.** Un résultat se reprend une seule fois : sa reprise est notée
//!   dans le fichier avant de servir (si elle ne s'écrit pas, tout se vérifie à neuf). Il faut aussi qu'il ait au
//!   plus la durée de sa règle (`TABLE`, raccourcie par l'auto-réglage) et qu'il ne soit pas daté dans l'avenir :
//!   reculer ou avancer l'horloge ne prolonge jamais rien.
//! - **Scellé, local.** `autotest/cache.json` sous le dossier de données (jamais sur la clé), scellé : un fichier
//!   douteux ou illisible est ignoré (tout se vérifie à neuf) et n'est pas réécrit tout seul, pour que le bilan le
//!   montre. Un fichier d'une autre version de Vanguard ou d'une autre langue est ignoré, puis remplacé. Il grossit
//!   jusqu'à 10 Mio, jamais au-delà (les entrées les plus vieilles partent d'abord) ; plus gros, il est ignoré sans
//!   être lu, puis refait (`TAILLE_MAX`).
//! - **Vidée** après une correction ou une mise à jour appliquée (`machine::lancer_chacune`), une annulation
//!   (`optimiser::annulables::defaire`), un bilan demandé, et par « annuler », « tout remettre » ou l'interrupteur de
//!   l'auto-réglage (`super::reglage`), qu'elle suit : coupé ou douteux, plus de cache.
//!
//! La note : un résultat repris compte ce qu'il comptait à sa date, ni plus ni moins. Un changement d'une règle gardée
//! se voit au passage suivant (vérifié à neuf), comparé au passage d'avant : la note et « note en baisse » sont
//! retardées d'un passage au plus, jamais baissées ni masquées par la cache.
//!
//! La cache se mesure elle-même dans `super::mesures` (des nombres par règle de `TABLE`, jamais un texte) : reprises,
//! vérifications à neuf, âge des résultats repris, temps gagné, et chaque vérification à neuf qui contredit le
//! résultat repris juste avant. Trop de contradictions : l'auto-réglage raccourcit la durée de la règle, dans les
//! bornes de `TABLE`, noté et annulable comme un délai (`super::reglage`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::machine::Constat;
use crate::machine::regles::Regle;
use crate::modele::{Absence, Objet, Precision};
use crate::risk::Niveau;

/// Le fichier, sous le dossier de données. Scellé : il décide de ce que le passage horaire ne refait pas.
pub(crate) const CACHE: &str = "autotest/cache.json";
/// La borne du fichier (10 Mio, voulue par l'auteur) : il grossit jusque-là, jamais au-delà (les entrées les plus
/// vieilles partent d'abord, `ecrire`) ; plus gros, il est ignoré sans être lu, puis refait (`regarder`). D'ordinaire,
/// quelques résultats font quelques Kio. `crate::sceau` lit ce fichier jusqu'à cette borne.
pub(crate) const TAILLE_MAX: u64 = 10 << 20;
/// Constats gardés au plus pour un résultat, et longueur d'un texte : au-delà, le résultat se refait.
const CONSTATS_MAX: usize = 100;
const TEXTE_MAX: usize = 8 << 10;
const CATEGORIE_MAX: usize = 80;
/// Catégories distinctes reprises au plus dans un processus (`categorie`).
const CATEGORIES_MAX: usize = 64;
/// Le pas d'un raccourci de durée par l'auto-réglage, en minutes.
pub(crate) const PAS_MIN: u16 = 15;

/// Une règle que le passage horaire peut reprendre : sa durée au plus (celle du code), le plancher où l'auto-réglage
/// peut la raccourcir, et pourquoi elle est là.
#[derive(Debug)]
pub(crate) struct EnCache {
    pub regle: &'static str,
    /// Minutes. Au plus 120 : avec la reprise unique, un résultat ne sert jamais au-delà de deux passages.
    pub duree_min: u16,
    /// Minutes. Sous 60 (le passage horaire), la règle ne se reprend plus en pratique.
    pub plancher_min: u16,
    pub raison: (&'static str, &'static str),
}

/// Les règles que le passage horaire peut reprendre. Lentes (des serveurs interrogés, un dossier personnel parcouru)
/// et d'un état qui change en heures, jamais en minutes ; aucune ne juge une défense ni une attaque en cours.
pub(crate) const TABLE: &[EnCache] = &[
    EnCache {
        regle: "LNX-MAJ-001",
        duree_min: 90,
        plancher_min: 45,
        raison: (
            "interroge les miroirs des paquets ; les mises à jour en attente changent quelques fois par jour",
            "queries the package mirrors; pending updates change a few times a day",
        ),
    },
    EnCache {
        regle: "LNX-MAJ-004",
        duree_min: 120,
        plancher_min: 45,
        raison: (
            "interroge Flatpak et le service des micrologiciels ; change rarement dans la journée",
            "queries Flatpak and the firmware service; rarely changes within a day",
        ),
    },
    EnCache {
        regle: "LNX-MAJ-006",
        duree_min: 120,
        plancher_min: 45,
        raison: (
            "interroge le serveur de l'AUR, la plus lente des mises à jour ; change rarement dans la journée",
            "queries the AUR server, the slowest of the update checks; rarely changes within a day",
        ),
    },
    EnCache {
        regle: "MAC-MAJ-002",
        duree_min: 120,
        plancher_min: 45,
        raison: (
            "softwareupdate interroge Apple (souvent des dizaines de secondes) ; change rarement dans la journée",
            "softwareupdate queries Apple (often tens of seconds); rarely changes within a day",
        ),
    },
    EnCache {
        regle: "MAC-MAJ-003",
        duree_min: 90,
        plancher_min: 45,
        raison: (
            "Homebrew interroge ses dépôts ; change quelques fois par jour",
            "Homebrew queries its repositories; changes a few times a day",
        ),
    },
    EnCache {
        regle: "MAC-MAJ-004",
        duree_min: 120,
        plancher_min: 45,
        raison: (
            "versions des logiciels comparées à celles publiées ; change rarement dans la journée",
            "software versions compared with the published ones; rarely changes within a day",
        ),
    },
    EnCache {
        regle: "WIN-MAJ-001",
        duree_min: 120,
        plancher_min: 45,
        raison: (
            "la recherche de Windows Update est la plus lente du bilan ; change rarement dans la journée",
            "the Windows Update search is the slowest of the check; rarely changes within a day",
        ),
    },
    EnCache {
        regle: "WIN-MAJ-002",
        duree_min: 90,
        plancher_min: 45,
        raison: (
            "winget interroge ses sources ; change quelques fois par jour",
            "winget queries its sources; changes a few times a day",
        ),
    },
    EnCache {
        regle: "COM-FIC-001",
        duree_min: 90,
        plancher_min: 45,
        raison: (
            "parcourt Téléchargements, Bureau et Documents (jusqu'à 5 s) ; un fichier oublié là y reste des jours",
            "walks Downloads, Desktop and Documents (up to 5 s); a file forgotten there stays for days",
        ),
    },
];

/// Les domaines de règles jamais gardés, et pourquoi : ce qui peut changer d'une minute à l'autre ou trahir une
/// attaque en cours. Une règle d'un de ces domaines ne peut pas entrer dans `TABLE` (essai `table_hors_des_exclues`).
pub(crate) const EXCLUES: &[(&str, &str, &str)] = &[
    ("PFE", "pare-feu", "firewall"),
    (
        "ANV",
        "antivirus et protection en temps réel",
        "antivirus and real-time protection",
    ),
    ("DIS", "connexions à distance", "remote connections"),
    ("SES", "sessions", "sessions"),
    ("SSH", "SSH et ses clés", "SSH and its keys"),
    ("RES", "ports en écoute et réseau", "listening ports and network"),
    ("PRG", "programmes en marche", "running programs"),
    (
        "PRS",
        "persistance et processus cachés",
        "persistence and hidden processes",
    ),
    ("NOY", "noyau et modules", "kernel and modules"),
    ("ESP", "logiciels espions", "spyware"),
    ("CPT", "comptes", "accounts"),
    ("PRV", "droits d'administrateur", "administrator rights"),
    ("CRT", "certificats racine", "root certificates"),
    ("DNS", "DNS", "DNS"),
    (
        "NAV",
        "navigateurs et navigation détournée",
        "browsers and hijacked browsing",
    ),
    (
        "LOG",
        "logiciels installés depuis le dernier bilan",
        "software installed since the last check",
    ),
    ("INT", "intégrité et fichiers-pièges", "integrity and decoy files"),
    ("JRN", "journaux effacés", "erased logs"),
    ("ETA", "état de Vanguard scellé", "Vanguard's sealed state"),
    ("SUR", "surveillance", "monitoring"),
    (
        "HEU",
        "heure de l'ordinateur (la cache en dépend)",
        "computer clock (the cache depends on it)",
    ),
    (
        "SAV",
        "sauvegardes (un rançongiciel les efface)",
        "backups (ransomware erases them)",
    ),
    ("CHF", "chiffrement du disque", "disk encryption"),
    ("DEM", "démarrage sécurisé", "secure boot"),
    ("SYS", "protections du système", "system protections"),
    ("PRF", "profils de configuration", "configuration profiles"),
    ("DUR", "durcissement (notifié)", "hardening (notified)"),
    (
        "AGT",
        "serveurs d'IA ouverts au réseau",
        "AI servers open to the network",
    ),
    ("CTN", "Docker exposé", "exposed Docker"),
    ("BLU", "Bluetooth", "Bluetooth"),
    ("WIF", "réseaux Wi-Fi", "Wi-Fi networks"),
    ("PAR", "partages ouverts", "open shares"),
    ("PUB", "mode Wi-Fi public", "public Wi-Fi mode"),
    ("CLE", "clé VANGUARD", "VANGUARD key"),
    (
        "HIS",
        "évolution depuis le dernier bilan",
        "changes since the last check",
    ),
    ("SRV", "services", "services"),
];

/// La ligne de `TABLE` d'une règle.
pub(crate) fn en_cache(regle: &str) -> Option<&'static EnCache> {
    TABLE.iter().find(|e| e.regle == regle)
}

/// La durée appliquée d'une règle de `TABLE`, en minutes : celle du code, ou celle que l'auto-réglage a raccourcie
/// (`raccourcies`), jamais hors de ses bornes.
pub(crate) fn duree_appliquee(regle: &str, raccourcies: &BTreeMap<String, u16>) -> Option<u16> {
    let e = en_cache(regle)?;
    Some(
        raccourcies
            .get(regle)
            .map_or(e.duree_min, |m| (*m).clamp(e.plancher_min, e.duree_min)),
    )
}

/// Ce que juge un constat gardé, à côté de sa règle.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum ObjetGarde {
    NonMigre,
    Seul,
    De(String),
}

/// Un constat gardé : seulement vérifié, sans sa correction.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Garde {
    categorie: String,
    probleme: Option<Niveau>,
    message: String,
    objet: ObjetGarde,
    /// L'absence d'un « sans objet » (`Absence::code`) ; rien pour un sain ou un problème.
    #[serde(default)]
    absence: Option<String>,
}

/// Le résultat gardé d'une règle.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entree {
    regle: String,
    /// La vérification, en secondes depuis 1970 (UTC).
    quand: i64,
    /// 0 : pas encore repris ; 1 : repris une fois, il ne sert plus.
    reprises: u8,
    constats: Vec<Garde>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Fichier {
    v: u16,
    /// La version de Vanguard qui l'a écrit : une autre l'ignore.
    version: String,
    /// « fr » ou « en » : les messages gardés sont dans cette langue.
    langue: String,
    entrees: Vec<Entree>,
}

fn langue() -> &'static str {
    if crate::langue::anglais() { "en" } else { "fr" }
}

fn absence_de(code: &str) -> Option<Absence> {
    [
        Absence::Materiel,
        Absence::Logiciel,
        Absence::Plateforme,
        Absence::Inactif,
    ]
    .into_iter()
    .find(|a| a.code() == code)
}

/// La catégorie d'un constat repris, au même `&'static str` que ses pareilles de ce processus : les catégories des
/// règles de `TABLE` sont peu nombreuses, chacune n'est gardée qu'une fois (64 au plus ; au-delà, rien n'est repris).
fn categorie(texte: &str) -> Option<&'static str> {
    static VUES: std::sync::Mutex<Vec<&'static str>> = std::sync::Mutex::new(Vec::new());
    let mut vues = VUES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(c) = vues.iter().find(|c| **c == texte) {
        return Some(c);
    }
    if texte.is_empty() || texte.len() > CATEGORIE_MAX || vues.len() >= CATEGORIES_MAX {
        return None;
    }
    let c: &'static str = Box::leak(texte.to_string().into_boxed_str());
    vues.push(c);
    Some(c)
}

/// Un constat gardable : vérifié, d'une catégorie que la surveillance ne notifie pas, sans précision qui le
/// contredise, de textes bornés.
fn garder(c: &Constat) -> Option<Garde> {
    if !c.verifie
        || crate::reseau::surveillance::categorie_alertee(c.categorie)
        || c.categorie.is_empty()
        || c.categorie.len() > CATEGORIE_MAX
        || c.message.len() > TEXTE_MAX
    {
        return None;
    }
    let absence = match &c.precision {
        Precision::Aucune => None,
        Precision::SansObjet(a) if c.probleme.is_none() => Some(a.code().to_string()),
        _ => return None,
    };
    let objet = match &c.objet {
        Objet::NonMigre => ObjetGarde::NonMigre,
        Objet::Seul => ObjetGarde::Seul,
        Objet::De(o) if o.len() <= TEXTE_MAX => ObjetGarde::De(o.clone()),
        Objet::De(_) => return None,
    };
    Some(Garde {
        categorie: c.categorie.to_string(),
        probleme: c.probleme,
        message: c.message.clone(),
        objet,
        absence,
    })
}

/// Le résultat d'une règle, s'il est gardable en entier : au moins un constat, tous gardables.
fn garder_tout(constats: &[&Constat]) -> Option<Vec<Garde>> {
    if constats.is_empty() || constats.len() > CONSTATS_MAX {
        return None;
    }
    constats.iter().map(|c| garder(c)).collect()
}

/// Un constat gardé, tel qu'il était : vérifié, même état, même niveau, même message, même clé ; sans correction.
fn reprendre(regle: &'static str, g: &Garde) -> Option<Constat> {
    if g.message.len() > TEXTE_MAX || crate::reseau::surveillance::categorie_alertee(&g.categorie) {
        return None;
    }
    let precision = match &g.absence {
        None => Precision::Aucune,
        Some(_) if g.probleme.is_some() => return None,
        Some(a) => Precision::SansObjet(absence_de(a)?),
    };
    let objet = match &g.objet {
        ObjetGarde::NonMigre => Objet::NonMigre,
        ObjetGarde::Seul => Objet::Seul,
        ObjetGarde::De(o) if !o.trim().is_empty() && o.len() <= TEXTE_MAX => Objet::De(o.clone()),
        ObjetGarde::De(_) => return None,
    };
    let c = Constat {
        categorie: categorie(&g.categorie)?,
        probleme: g.probleme,
        message: g.message.clone(),
        correctif: None,
        verifie: true,
        regle,
        objet,
        precision,
    };
    c.coherent().then_some(c)
}

/// Ce qui distingue l'état d'un résultat d'un autre, sans ses textes (un nombre de paquets qui bouge n'est pas un
/// autre état) : la clé de chaque constat (ou sa catégorie), son état et son niveau.
fn signature<'a>(
    constats: impl Iterator<Item = (&'a str, Option<String>, &'static str, Option<Niveau>)>,
) -> BTreeSet<(String, &'static str, Option<Niveau>)> {
    constats
        .map(|(categorie, cle, etat, niveau)| (cle.unwrap_or_else(|| categorie.to_string()), etat, niveau))
        .collect()
}

fn signature_des_gardes(
    regle: &'static str,
    gardes: &[Garde],
) -> Option<BTreeSet<(String, &'static str, Option<Niveau>)>> {
    let repris: Vec<Constat> = gardes.iter().map(|g| reprendre(regle, g)).collect::<Option<_>>()?;
    Some(signature_des_constats(&repris.iter().collect::<Vec<_>>()))
}

fn signature_des_constats(constats: &[&Constat]) -> BTreeSet<(String, &'static str, Option<Niveau>)> {
    signature(
        constats
            .iter()
            .map(|c| (c.categorie, c.cle().map(|k| k.to_string()), c.etat().code(), c.probleme)),
    )
}

/// Ce qui permet à un passage automatique de se servir de la cache.
#[derive(Clone, Debug)]
pub(crate) struct Permis {
    /// La durée raccourcie de chaque règle (`super::reglage`) ; `None` : l'auto-réglage est coupé ou douteux, pas de
    /// cache.
    pub raccourcies: Option<BTreeMap<String, u16>>,
    /// Faux quand l'autotest de la semaine reprend ce passage : il juge des lectures fraîches.
    pub reprendre: bool,
    /// Faux sous l'interrupteur de lecture seule de l'autotest.
    pub ecrire: bool,
}

impl Permis {
    fn actuel() -> Permis {
        Permis {
            raccourcies: super::reglage::pour_le_cache(),
            reprendre: !super::hebdomadaire_du(),
            ecrire: !super::lecture_seule::active(),
        }
    }
}

/// Un résultat repris par ce passage.
struct Repris {
    regle: &'static str,
    quand: i64,
    constats: Vec<Constat>,
}

/// Ce qu'un passage automatique fait de la cache : les résultats qu'il reprend (déjà notés repris dans le fichier),
/// et de quoi garder ceux qu'il vérifie à neuf.
pub(crate) struct Plan {
    dossier: PathBuf,
    /// Faux : rien ne s'écrit (coupé, douteux, lecture seule, écriture refusée).
    ecrire: bool,
    /// Le contenu du fichier au dernier regard (`None` : absent) : `terminer` n'écrit que s'il n'a pas changé depuis.
    vu: Regard,
    fichier: Fichier,
    repris: Vec<Repris>,
    /// Le début du passage : la date des résultats vérifiés à neuf (la plus ancienne possible, jamais flatteuse).
    debut: i64,
}

/// Ce que la cache a fait d'une règle de `TABLE` à ce passage, pour `super::mesures`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Evenement {
    /// Repris : son âge (s).
    Repris { regle: &'static str, age_s: u64 },
    /// Vérifiée à neuf.
    ANeuf { regle: &'static str },
    /// Vérifiée à neuf juste après une reprise : l'état a-t-il changé depuis le résultat repris ? (date du passage)
    Compare {
        regle: &'static str,
        ecart: bool,
        quand: i64,
    },
}

impl Plan {
    /// Un plan qui ne reprend ni n'écrit rien.
    fn inactif(dossier: &Path, debut: i64) -> Plan {
        Plan {
            dossier: dossier.to_path_buf(),
            ecrire: false,
            vu: Regard::Absent,
            fichier: Fichier::default(),
            repris: Vec::new(),
            debut,
        }
    }

    /// Le résultat repris de `regle`, avec son âge à la fin de chaque message ; `None` : elle se vérifie à neuf.
    pub(crate) fn constats_de(&self, regle: &str) -> Option<Vec<Constat>> {
        let r = self.repris.iter().find(|r| r.regle == regle)?;
        let age = u64::try_from(self.debut.saturating_sub(r.quand)).unwrap_or(0);
        let suffixe = age_dit(age);
        Some(
            r.constats
                .iter()
                .cloned()
                .map(|mut c| {
                    c.message = format!("{} ({suffixe})", c.message);
                    c
                })
                .collect(),
        )
    }

    /// Cette règle est-elle reprise à ce passage ?
    pub(crate) fn reprend(&self, regle: &str) -> bool {
        self.repris.iter().any(|r| r.regle == regle)
    }
}

/// « vérifié il y a 40 min ».
pub(crate) fn age_dit(age_s: u64) -> String {
    let minutes = age_s / 60;
    if minutes == 0 {
        crate::tr!("vérifié il y a moins d'une minute", "checked less than a minute ago").to_string()
    } else {
        crate::trf!("vérifié il y a {minutes} min", "checked {minutes} min ago")
    }
}

/// Le fichier, s'il est de cette version et de cette langue, dans ses bornes ; sinon, un fichier vide (il sera
/// remplacé).
fn lire_de(octets: &[u8]) -> Fichier {
    if u64::try_from(octets.len()).map_or(true, |n| n > TAILLE_MAX) {
        return Fichier::default();
    }
    serde_json::from_slice::<Fichier>(octets)
        .ok()
        .filter(|f| {
            f.v == 1
                && f.version == env!("CARGO_PKG_VERSION")
                && f.langue == langue()
                && f.entrees.len() <= TABLE.len()
                && f.entrees.iter().all(|e| e.constats.len() <= CONSTATS_MAX)
        })
        .unwrap_or_default()
}

/// Ce que donne le fichier au regard.
#[derive(Debug, PartialEq, Eq)]
enum Regard {
    Absent,
    Cru(Vec<u8>),
    /// Plus gros que la borne : ignoré sans être lu (ni jugé), puis refait. Sa taille, pour voir s'il a changé.
    TropGros(u64),
    /// Douteux ou illisible : ignoré, et jamais réécrit tout seul (le bilan le montre).
    Douteux,
}

impl Regard {
    /// Ce qu'il garde : vide s'il est absent, trop gros, d'une autre version ou langue ; `None` s'il est douteux.
    fn fichier(&self) -> Option<Fichier> {
        match self {
            Regard::Absent | Regard::TropGros(_) => Some(Fichier::default()),
            Regard::Cru(o) => Some(lire_de(o)),
            Regard::Douteux => None,
        }
    }
}

fn regarder(dossier: &Path) -> Regard {
    regarder_borne(dossier, TAILLE_MAX)
}

/// `regarder`, avec la borne en paramètre pour les essais. La taille se demande au système avant toute lecture : un
/// fichier plus gros que `max` n'est jamais ouvert. Un lien n'est pas suivi ici : le sceau le juge.
fn regarder_borne(dossier: &Path, max: u64) -> Regard {
    if let Ok(m) = std::fs::symlink_metadata(dossier.join(CACHE))
        && m.is_file()
        && m.len() > max
    {
        return Regard::TropGros(m.len());
    }
    match crate::sceau::juge_dans(dossier, CACHE) {
        crate::sceau::Juge::Absent => Regard::Absent,
        crate::sceau::Juge::Cru(o) => Regard::Cru(o),
        crate::sceau::Juge::Douteux(..) | crate::sceau::Juge::Illisible(_) => Regard::Douteux,
    }
}

fn ecrire(dossier: &Path, f: &mut Fichier) -> std::io::Result<Vec<u8>> {
    ecrire_borne(dossier, f, TAILLE_MAX)
}

/// Écrit `f`, jamais plus gros que `max` : au-delà, les entrées les plus vieilles partent d'abord (et de `f` aussi, pour
/// que ce qui reste en mémoire soit ce qui est écrit). Une entrée retirée se vérifie à neuf : rien ne se reprend de
/// plus. Même vide, trop gros : rien ne s'écrit.
fn ecrire_borne(dossier: &Path, f: &mut Fichier, max: u64) -> std::io::Result<Vec<u8>> {
    loop {
        let o = serde_json::to_vec(f).map_err(std::io::Error::other)?;
        if u64::try_from(o.len()).is_ok_and(|n| n <= max) {
            crate::sceau::ecrire_dans(dossier, CACHE, &o)?;
            return Ok(o);
        }
        let Some(i) = f
            .entrees
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.quand)
            .map(|(i, _)| i)
        else {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        };
        f.entrees.remove(i);
    }
}

/// Le plan du passage automatique qui commence (`debut`, en secondes depuis 1970) pour ces règles.
pub(crate) fn preparer(choisies: &[&'static Regle], debut: i64) -> Plan {
    preparer_dans(&crate::socle::dossier_local(), choisies, debut, &Permis::actuel())
}

fn preparer_dans(dossier: &Path, choisies: &[&'static Regle], debut: i64, permis: &Permis) -> Plan {
    let Some(raccourcies) = permis.raccourcies.as_ref().filter(|_| permis.ecrire) else {
        return Plan::inactif(dossier, debut);
    };
    let vu = regarder(dossier);
    let Some(mut fichier) = vu.fichier() else {
        return Plan::inactif(dossier, debut);
    };
    let mut repris = Vec::new();
    if permis.reprendre {
        for r in choisies {
            let Some(duree) = duree_appliquee(r.id, raccourcies) else {
                continue;
            };
            let Some(e) = fichier.entrees.iter_mut().find(|e| e.regle == r.id) else {
                continue;
            };
            let age = debut.saturating_sub(e.quand);
            // Daté dans l'avenir (horloge reculée) ou trop vieux (horloge avancée, passage manqué) : à neuf.
            if e.reprises != 0 || age < 0 || age > i64::from(duree) * 60 {
                continue;
            }
            let Some(constats) = e
                .constats
                .iter()
                .map(|g| reprendre(r.id, g))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            if constats.is_empty() {
                continue;
            }
            e.reprises = 1;
            repris.push(Repris {
                regle: r.id,
                quand: e.quand,
                constats,
            });
        }
    }
    let mut plan = Plan {
        dossier: dossier.to_path_buf(),
        ecrire: true,
        vu,
        fichier: Fichier {
            v: 1,
            version: env!("CARGO_PKG_VERSION").to_string(),
            langue: langue().to_string(),
            ..fichier
        },
        repris: Vec::new(),
        debut,
    };
    if repris.is_empty() {
        return plan;
    }
    // La reprise est notée avant de servir : un résultat ne sert jamais deux fois, même si le passage s'arrête net.
    match ecrire(dossier, &mut plan.fichier) {
        Ok(o) => {
            plan.vu = Regard::Cru(o);
            // Une entrée retirée pour la borne n'est plus notée reprise : elle ne sert pas.
            plan.repris = repris
                .into_iter()
                .filter(|x| {
                    plan.fichier
                        .entrees
                        .iter()
                        .any(|e| e.regle == x.regle && e.reprises == 1)
                })
                .collect();
            plan
        }
        Err(_) => Plan::inactif(dossier, debut),
    }
}

impl Plan {
    /// Après les règles : garde les résultats vérifiés à neuf des règles de `TABLE` (entièrement vérifiés, hors des
    /// catégories notifiées), oublie les autres, et rend ce que la cache a fait de chaque règle. N'écrit rien si le
    /// fichier a changé depuis `preparer` (vidé par une correction, un bilan demandé, l'auto-réglage).
    pub(crate) fn terminer(mut self, choisies: &[&'static Regle], constats: &[Constat]) -> Vec<Evenement> {
        if !self.ecrire {
            return Vec::new();
        }
        let mut evenements = Vec::new();
        let mut entrees = Vec::new();
        for r in choisies.iter().filter(|r| en_cache(r.id).is_some()) {
            if let Some(x) = self.repris.iter().find(|x| x.regle == r.id) {
                evenements.push(Evenement::Repris {
                    regle: r.id,
                    age_s: u64::try_from(self.debut.saturating_sub(x.quand)).unwrap_or(0),
                });
                if let Some(e) = self.fichier.entrees.iter().find(|e| e.regle == r.id) {
                    entrees.push(e.clone());
                }
                continue;
            }
            evenements.push(Evenement::ANeuf { regle: r.id });
            let siens: Vec<&Constat> = constats.iter().filter(|c| c.regle == r.id).collect();
            let gardes = garder_tout(&siens);
            // Repris au passage d'avant : la vérification à neuf dit si l'état avait changé (la durée est trop longue).
            if let Some(avant) = self.fichier.entrees.iter().find(|e| e.regle == r.id && e.reprises == 1)
                && siens.iter().all(|c| c.verifie)
                && !siens.is_empty()
                && let Some(sig_avant) = signature_des_gardes(r.id, &avant.constats)
            {
                evenements.push(Evenement::Compare {
                    regle: r.id,
                    ecart: sig_avant != signature_des_constats(&siens),
                    quand: self.debut,
                });
            }
            if let Some(constats) = gardes {
                entrees.push(Entree {
                    regle: r.id.to_string(),
                    quand: self.debut,
                    reprises: 0,
                    constats,
                });
            }
        }
        self.fichier.entrees = entrees;
        if regarder(&self.dossier) == self.vu {
            let _ = ecrire(&self.dossier, &mut self.fichier);
        }
        evenements
    }
}

/// Vide la cache : après une correction, une mise à jour, une annulation, un bilan demandé. Seulement un fichier cru :
/// un fichier douteux reste, pour que le bilan le montre (il n'est jamais repris).
pub(crate) fn oublier() {
    if let Err(e) = oublier_dans(&crate::socle::dossier_local(), false) {
        crate::modele::Echec::echoue("autotest/cache", e.to_string()).journaliser();
    }
}

/// Vide la cache de `dossier` ; `meme_douteux` : aussi un fichier douteux (un geste de la personne dans Paramètres).
pub(crate) fn oublier_dans(dossier: &Path, meme_douteux: bool) -> std::io::Result<()> {
    match regarder(dossier) {
        Regard::Cru(_) | Regard::TropGros(_) => crate::sceau::effacer_dans(dossier, CACHE),
        Regard::Douteux if meme_douteux => crate::sceau::effacer_dans(dossier, CACHE),
        Regard::Absent | Regard::Douteux => Ok(()),
    }
}

/// Ce que la cache fait sur cet ordinateur, pour Paramètres : chaque règle de `TABLE` de ce système, sa durée et sa
/// raison, ce qu'elle garde (avec son âge) et ses mesures ; puis ce qui n'est jamais repris.
pub(crate) fn lignes() -> Vec<String> {
    let os = crate::machine::regles::Os::actuel();
    let ids: Vec<&'static str> = crate::machine::regles::regles(os)
        .into_iter()
        .map(|r| r.id)
        .filter(|id| en_cache(id).is_some())
        .collect();
    lignes_dans(
        &crate::socle::dossier_local(),
        chrono::Utc::now().timestamp(),
        &ids,
        &super::mesures::lues().cache,
        &super::reglage::pour_le_cache().unwrap_or_default(),
    )
}

fn lignes_dans(
    dossier: &Path,
    maintenant: i64,
    ids: &[&str],
    mesures: &BTreeMap<String, super::mesures::Cache>,
    raccourcies: &BTreeMap<String, u16>,
) -> Vec<String> {
    let mut lignes = Vec::new();
    let vu = regarder(dossier);
    if let Regard::TropGros(_) = vu {
        lignes.push(
            crate::tr!(
                "Fichier de plus de 10 Mo, ignoré sans être lu : il sera refait.",
                "File over 10 MB, ignored without being read: it will be rebuilt."
            )
            .to_string(),
        );
    }
    let fichier = vu.fichier().unwrap_or_else(|| {
        lignes.push(
            crate::tr!(
                "Fichier douteux, ignoré : tout est vérifié à neuf.",
                "Doubtful file, ignored: everything is checked afresh."
            )
            .to_string(),
        );
        Fichier::default()
    });
    for id in ids {
        let (Some(t), Some(duree)) = (en_cache(id), duree_appliquee(id, raccourcies)) else {
            continue;
        };
        let raison = if crate::langue::anglais() {
            t.raison.1
        } else {
            t.raison.0
        };
        lignes.push(crate::trf!(
            "{id} : repris jusqu'à {duree} min ; {raison}.",
            "{id}: reused for up to {duree} min; {raison}."
        ));
        if let Some(e) = fichier.entrees.iter().find(|e| e.regle == *id) {
            let quand = u64::try_from(maintenant.saturating_sub(e.quand)).map_or_else(
                |_| crate::tr!("daté dans l'avenir, ignoré", "dated in the future, ignored").to_string(),
                age_dit,
            );
            lignes.push(if e.reprises == 0 {
                crate::trf!(
                    "  gardé pour le prochain passage ({quand}).",
                    "  kept for the next pass ({quand})."
                )
            } else {
                crate::trf!(
                    "  repris au dernier passage ({quand}), refait au prochain.",
                    "  reused at the last pass ({quand}), redone at the next one."
                )
            });
        }
        if let Some(m) = mesures.get(*id) {
            let (age, gagne) = (m.age_moyen_s() / 60, m.gagne_ms / 1000);
            lignes.push(crate::trf!(
                "  repris {} fois (âge moyen {age} min, {gagne} s gagnées), vérifié à neuf {} fois ; {} écart(s) sur {} comparaison(s).",
                "  reused {} times (average age {age} min, {gagne} s saved), checked afresh {} times; {} mismatch(es) in {} comparison(s).",
                m.repris,
                m.a_neuf,
                m.ecarts,
                m.comparees
            ));
        }
    }
    let jamais: Vec<&str> = EXCLUES
        .iter()
        .map(|(_, fr, en)| if crate::langue::anglais() { *en } else { *fr })
        .collect();
    lignes.push(crate::trf!(
        "Toujours vérifié à neuf : {}.",
        "Always checked afresh: {}.",
        jamais.join(", ")
    ));
    lignes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::regles::Os;

    fn regle(id: &'static str) -> &'static Regle {
        Box::leak(Box::new(Regle {
            id,
            systeme: Os::Linux,
            rang: 1,
            sujet: ("essai", "test"),
            references: &[],
            verifier: Vec::new,
        }))
    }

    fn sain(id: &'static str, message: &str) -> Constat {
        Constat {
            categorie: "Mises à jour",
            probleme: None,
            message: message.to_string(),
            correctif: None,
            verifie: true,
            regle: id,
            objet: Objet::Seul,
            precision: Precision::Aucune,
        }
    }

    fn probleme(id: &'static str) -> Constat {
        Constat {
            probleme: Some(Niveau::Moyen),
            ..sain(id, "12 mises à jour en attente.")
        }
        .corriger("installer", &["true"])
    }

    fn permis() -> Permis {
        Permis {
            raccourcies: Some(BTreeMap::new()),
            reprendre: true,
            ecrire: true,
        }
    }

    fn dossier() -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = crate::socle::dossier_local().join(format!("essai-cache-{n}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const T0: i64 = 1_800_000_000;

    /// Un passage : prépare, lance (`verifier` pour chaque règle non reprise), termine. Rend les constats et les
    /// événements.
    fn passage(
        d: &Path,
        regles: &[&'static Regle],
        quand: i64,
        p: &Permis,
        mut verifier: impl FnMut(&'static str) -> Vec<Constat>,
    ) -> (Vec<Constat>, Vec<Evenement>) {
        let plan = preparer_dans(d, regles, quand, p);
        let mut constats = Vec::new();
        for r in regles {
            constats.extend(plan.constats_de(r.id).unwrap_or_else(|| verifier(r.id)));
        }
        let ev = plan.terminer(regles, &constats);
        (constats, ev)
    }

    #[test]
    fn repris_une_seule_fois_puis_refait() {
        let d = dossier();
        let r = [regle("LNX-MAJ-001")];
        let (c1, ev) = passage(&d, &r, T0, &permis(), |id| vec![probleme(id)]);
        assert_eq!(ev, vec![Evenement::ANeuf { regle: "LNX-MAJ-001" }]);
        assert!(c1[0].correctif.is_some());
        // Passage suivant : repris, tel qu'il était (problème, même niveau), daté, sans correction.
        let (c2, ev) = passage(&d, &r, T0 + 3600, &permis(), |_| panic!("pas refait"));
        assert_eq!(
            ev,
            vec![Evenement::Repris {
                regle: "LNX-MAJ-001",
                age_s: 3600
            }]
        );
        assert_eq!(c2[0].probleme, Some(Niveau::Moyen));
        assert!(c2[0].verifie && c2[0].correctif.is_none());
        assert_eq!(c2[0].cle(), c1[0].cle());
        assert!(c2[0].message.starts_with(&c1[0].message), "{}", c2[0].message);
        assert!(c2[0].message.contains("60 min"), "{}", c2[0].message);
        // Et le suivant refait la vérification, même tout de suite : un passage sur deux au plus.
        let mut refait = false;
        let (_, ev) = passage(&d, &r, T0 + 3700, &permis(), |id| {
            refait = true;
            vec![sain(id, "Système à jour.")]
        });
        assert!(refait);
        assert!(ev.contains(&Evenement::Compare {
            regle: "LNX-MAJ-001",
            ecart: true,
            quand: T0 + 3700
        }));
    }

    #[test]
    fn l_horloge_ne_prolonge_rien() {
        for (ecart, repris) in [
            (-1, false),
            (-86_400, false),
            (90 * 60, true),
            (90 * 60 + 1, false),
            (86_400, false),
        ] {
            let d = dossier();
            let r = [regle("LNX-MAJ-001")];
            passage(&d, &r, T0, &permis(), |id| vec![sain(id, "Système à jour.")]);
            let plan = preparer_dans(&d, &r, T0 + ecart, &permis());
            assert_eq!(plan.reprend("LNX-MAJ-001"), repris, "écart {ecart}");
        }
    }

    #[test]
    fn la_duree_raccourcie_compte_et_reste_dans_ses_bornes() {
        let d = dossier();
        let r = [regle("LNX-MAJ-001")];
        passage(&d, &r, T0, &permis(), |id| vec![sain(id, "Système à jour.")]);
        let mut p = permis();
        p.raccourcies = Some(BTreeMap::from([("LNX-MAJ-001".to_string(), 45)]));
        assert!(!preparer_dans(&d, &r, T0 + 3600, &p).reprend("LNX-MAJ-001"));
        assert_eq!(
            duree_appliquee("LNX-MAJ-001", &BTreeMap::from([("LNX-MAJ-001".to_string(), 1)])),
            Some(45)
        );
        assert_eq!(
            duree_appliquee("LNX-MAJ-001", &BTreeMap::from([("LNX-MAJ-001".to_string(), 600)])),
            Some(90)
        );
        assert_eq!(duree_appliquee("LNX-PFE-001", &BTreeMap::new()), None);
    }

    #[test]
    fn ni_coupe_ni_hebdomadaire_ni_lecture_seule_ni_hors_table() {
        let d = dossier();
        let r = [regle("LNX-MAJ-001"), regle("LNX-PFE-001")];
        passage(&d, &r, T0, &permis(), |id| vec![sain(id, "ok")]);
        let lu = std::fs::read(d.join(CACHE)).unwrap();
        assert!(
            !String::from_utf8_lossy(&lu).contains("LNX-PFE-001"),
            "hors de la table : jamais gardée"
        );
        for p in [
            Permis {
                raccourcies: None,
                ..permis()
            },
            Permis {
                reprendre: false,
                ..permis()
            },
            Permis {
                ecrire: false,
                ..permis()
            },
        ] {
            assert!(!preparer_dans(&d, &r, T0 + 60, &p).reprend("LNX-MAJ-001"), "{p:?}");
        }
        assert!(preparer_dans(&d, &r, T0 + 60, &permis()).reprend("LNX-MAJ-001"));
    }

    #[test]
    fn rien_de_non_verifie_ni_de_notifie_n_est_garde() {
        let d = dossier();
        let r = [regle("LNX-MAJ-001")];
        let non_verifie = |id| {
            vec![Constat {
                verifie: false,
                precision: Precision::NonVerifie(crate::modele::Raison::Delai),
                ..sain(id, "Impossible de vérifier.")
            }]
        };
        passage(&d, &r, T0, &permis(), non_verifie);
        assert!(!preparer_dans(&d, &r, T0 + 60, &permis()).reprend("LNX-MAJ-001"));
        // Une catégorie que la surveillance notifie : jamais gardée, même saine.
        passage(&d, &r, T0, &permis(), |id| {
            vec![Constat {
                categorie: "Fin de support",
                ..sain(id, "ok")
            }]
        });
        assert!(!preparer_dans(&d, &r, T0 + 60, &permis()).reprend("LNX-MAJ-001"));
        // Un résultat mêlé (un constat vérifié, un non vérifié) : rien n'est gardé de lui.
        passage(&d, &r, T0, &permis(), |id| {
            let mut v = non_verifie(id);
            v.push(sain(id, "ok"));
            v
        });
        assert!(!preparer_dans(&d, &r, T0 + 60, &permis()).reprend("LNX-MAJ-001"));
    }

    #[test]
    fn un_sans_objet_revient_sans_objet() {
        let d = dossier();
        let r = [regle("LNX-MAJ-004")];
        let c = Constat {
            precision: Precision::SansObjet(Absence::Logiciel),
            objet: Objet::de("logiciel", "flatpak"),
            ..sain("LNX-MAJ-004", "Flatpak absent.")
        };
        let attendu = c.clone();
        passage(&d, &r, T0, &permis(), move |_| vec![c.clone()]);
        let (repris, _) = passage(&d, &r, T0 + 60, &permis(), |_| panic!("pas refait"));
        assert_eq!(repris[0].etat(), attendu.etat());
        assert_eq!(repris[0].cle(), attendu.cle());
    }

    #[test]
    fn un_fichier_douteux_est_ignore_et_pas_reecrit() {
        let d = dossier();
        let r = [regle("LNX-MAJ-001")];
        passage(&d, &r, T0, &permis(), |id| vec![sain(id, "ok")]);
        let mut texte = std::fs::read_to_string(d.join(CACHE)).unwrap();
        texte = texte.replace("\"reprises\":0", "\"reprises\":0 ");
        std::fs::write(d.join(CACHE), &texte).unwrap();
        let (_, ev) = passage(&d, &r, T0 + 60, &permis(), |id| vec![sain(id, "ok")]);
        assert_eq!(ev, Vec::new(), "douteux : ni reprise ni mesure");
        assert_eq!(
            std::fs::read_to_string(d.join(CACHE)).unwrap(),
            texte,
            "pas réécrit tout seul"
        );
        let l = lignes_dans(&d, T0, &["LNX-MAJ-001"], &BTreeMap::new(), &BTreeMap::new());
        assert!(l[0].contains("douteux") || l[0].contains("doubtful"), "{l:?}");
        // Un geste de la personne le vide.
        oublier_dans(&d, false).unwrap();
        assert!(d.join(CACHE).exists());
        oublier_dans(&d, true).unwrap();
        assert!(!d.join(CACHE).exists());
    }

    #[test]
    fn la_borne_de_10_mo() {
        assert_eq!(TAILLE_MAX, 10 * 1024 * 1024);
        let d = dossier();
        let r = [regle("LNX-MAJ-001")];
        // Un fichier de 10 Mio et un octet (creux : rien n'occupe le disque), et que personne ne peut ouvrir : s'il était
        // lu, il serait illisible, donc douteux, et la cache resterait coupée. Il est ignoré sans être lu, puis refait.
        std::fs::create_dir_all(d.join("autotest")).unwrap();
        let gros = std::fs::File::create(d.join(CACHE)).unwrap();
        gros.set_len(TAILLE_MAX + 1).unwrap();
        drop(gros);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.join(CACHE), std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        assert_eq!(regarder(&d), Regard::TropGros(TAILLE_MAX + 1));
        let lignes = lignes_dans(&d, T0, &["LNX-MAJ-001"], &BTreeMap::new(), &BTreeMap::new());
        assert!(lignes[0].contains("10 Mo") || lignes[0].contains("10 MB"), "{lignes:?}");
        let (_, ev) = passage(&d, &r, T0, &permis(), |id| vec![sain(id, "ok")]);
        assert_eq!(ev, vec![Evenement::ANeuf { regle: "LNX-MAJ-001" }]);
        assert!(std::fs::metadata(d.join(CACHE)).unwrap().len() < 4096, "refait, petit");
        assert!(matches!(regarder(&d), Regard::Cru(_)));
        assert!(preparer_dans(&d, &r, T0 + 60, &permis()).reprend("LNX-MAJ-001"));
        // Au-delà de la borne, les entrées les plus vieilles partent d'abord, jusqu'à tenir ; le fichier ne la
        // dépasse jamais. (Une borne plus petite, pour ne pas écrire 10 Mio.)
        let entree = |regle: &str, quand: i64| Entree {
            regle: regle.to_string(),
            quand,
            reprises: 0,
            constats: vec![Garde {
                categorie: "Mises à jour".to_string(),
                probleme: None,
                message: "x".repeat(200),
                objet: ObjetGarde::Seul,
                absence: None,
            }],
        };
        let mut fichier = Fichier {
            v: 1,
            version: env!("CARGO_PKG_VERSION").to_string(),
            langue: langue().to_string(),
            entrees: vec![
                entree("LNX-MAJ-001", T0 + 120),
                entree("LNX-MAJ-004", T0),
                entree("COM-FIC-001", T0 + 60),
            ],
        };
        let max = u64::try_from(serde_json::to_vec(&fichier).unwrap().len()).unwrap() - 1;
        let o = ecrire_borne(&d, &mut fichier, max).unwrap();
        assert!(u64::try_from(o.len()).unwrap() <= max);
        let restent: Vec<&str> = fichier.entrees.iter().map(|e| e.regle.as_str()).collect();
        assert_eq!(
            restent,
            ["LNX-MAJ-001", "COM-FIC-001"],
            "la plus vieille est partie, seulement elle"
        );
        assert_eq!(regarder_borne(&d, max), Regard::Cru(o.clone()));
        let taille = u64::try_from(o.len()).unwrap();
        assert_eq!(regarder_borne(&d, taille - 1), Regard::TropGros(taille));
        let max = taille - 300;
        ecrire_borne(&d, &mut fichier, max).unwrap();
        let restent: Vec<&str> = fichier.entrees.iter().map(|e| e.regle.as_str()).collect();
        assert_eq!(restent, ["LNX-MAJ-001"]);
        // Même vide, trop gros pour la borne : rien ne s'écrit, le fichier reste tel quel.
        let avant = std::fs::read(d.join(CACHE)).unwrap();
        assert!(ecrire_borne(&d, &mut fichier, 10).is_err());
        assert_eq!(std::fs::read(d.join(CACHE)).unwrap(), avant);
    }

    #[test]
    fn une_autre_version_ou_langue_est_ignoree() {
        let d = dossier();
        let r = [regle("LNX-MAJ-001")];
        passage(&d, &r, T0, &permis(), |id| vec![sain(id, "ok")]);
        let lu = std::fs::read_to_string(d.join(CACHE)).unwrap();
        for (avant, apres) in [
            (
                format!("\"version\":\"{}\"", env!("CARGO_PKG_VERSION")),
                "\"version\":\"0.88.0\"".to_string(),
            ),
            ("\"langue\":\"fr\"".to_string(), "\"langue\":\"en\"".to_string()),
        ] {
            assert!(lu.contains(&avant), "{lu}");
            crate::sceau::ecrire_dans(&d, CACHE, lu.replace(&avant, &apres).as_bytes()).unwrap();
            assert!(!preparer_dans(&d, &r, T0 + 60, &permis()).reprend("LNX-MAJ-001"));
        }
    }

    #[test]
    fn vidée_entre_deux_le_passage_n_ecrit_rien() {
        let d = dossier();
        let r = [regle("LNX-MAJ-001")];
        passage(&d, &r, T0, &permis(), |id| vec![sain(id, "ok")]);
        let plan = preparer_dans(&d, &r, T0 + 60, &permis());
        assert!(plan.reprend("LNX-MAJ-001"));
        // Une correction appliquée pendant le passage vide la cache : le passage ne la remet pas.
        oublier_dans(&d, false).unwrap();
        let constats = plan.constats_de("LNX-MAJ-001").unwrap();
        plan.terminer(&r, &constats);
        assert!(!d.join(CACHE).exists());
    }

    #[test]
    fn un_etat_inchange_n_est_pas_un_ecart() {
        let d = dossier();
        let r = [regle("LNX-MAJ-001")];
        passage(&d, &r, T0, &permis(), |id| vec![probleme(id)]);
        passage(&d, &r, T0 + 3600, &permis(), |_| panic!("pas refait"));
        // Le nombre de paquets a bougé, pas l'état : pas d'écart.
        let (_, ev) = passage(&d, &r, T0 + 7200, &permis(), |id| {
            vec![Constat {
                message: "13 mises à jour en attente.".into(),
                ..probleme(id)
            }]
        });
        assert!(ev.contains(&Evenement::Compare {
            regle: "LNX-MAJ-001",
            ecart: false,
            quand: T0 + 7200
        }));
    }

    #[test]
    fn table_hors_des_exclues() {
        // Les règles des autres systèmes ne sont pas compilées ici : elles se cherchent dans leur source.
        let ids: BTreeSet<&str> = inventory::iter::<Regle>.into_iter().map(|r| r.id).collect();
        let ailleurs = [
            include_str!("../machine/linux/regles.rs"),
            include_str!("../machine/macos/regles.rs"),
            include_str!("../machine/windows/regles.rs"),
        ];
        let mut vues = BTreeSet::new();
        for e in TABLE {
            let declaree = format!("regle!(\n    \"{}\",", e.regle);
            assert!(
                ids.contains(e.regle) || ailleurs.iter().any(|s| s.contains(&declaree)),
                "{} n'existe pas",
                e.regle
            );
            assert!(vues.insert(e.regle), "{} deux fois", e.regle);
            let domaine = e.regle.get(4..7).unwrap();
            assert!(
                !EXCLUES.iter().any(|(d, _, _)| *d == domaine),
                "{} : domaine exclu",
                e.regle
            );
            assert!(
                e.plancher_min >= 30 && e.plancher_min <= e.duree_min && e.duree_min <= 120,
                "{e:?}"
            );
            assert_eq!((e.duree_min - e.plancher_min) % PAS_MIN, 0, "{e:?}");
            assert!(!e.raison.0.is_empty() && !e.raison.1.is_empty());
        }
        // Les mises à jour qui jugent une défense (coupées, en pause) ou qui sont notifiées restent dehors.
        for id in [
            "WIN-MAJ-003",
            "LNX-MAJ-002",
            "MAC-MAJ-001",
            "LNX-MAJ-003",
            "COM-MAJ-001",
        ] {
            assert!(en_cache(id).is_none(), "{id}");
        }
    }
}
