//! Le moteur des règles `EVT-` : chaque événement lu passe une fois, les règles qui l'attendent (même journal,
//! même numéro, même fournisseur) l'examinent ; à la fin, ce que chaque règle a trouvé et ce qui l'a empêchée de
//! tout voir.
//!
//! Trois formes :
//! - `Forme::Chacun` : un événement qui suffit (un service qui lance PowerShell, un journal effacé) ;
//! - `Forme::Rafale` : au moins `nombre` événements dans `fenetre` secondes, regroupés par des champs (le compte,
//!   l'adresse) et l'ordinateur ;
//! - `Forme::Apres` : une rafale d'événements A, puis un événement B de la même clé dans `delai` secondes (des
//!   échecs de connexion en rafale, puis une connexion réussie).
//!
//! Les rafales se jugent à la fin, sur les dates triées : l'ordre de lecture (les plus récents d'abord pour la source
//! vivante, morceau par morceau pour un fichier, un journal tournant qui reprend au début) ne fait ni perdre ni
//! inventer une alerte. Tout est borné : clés, dates, trouvailles et exemples gardés ; ce qui dépasse est compté et
//! rend la règle non vérifiée, jamais tu.
//!
//! Un événement d'un morceau abîmé (`EvenementWindows::verifie` faux) compte comme indice : la trouvaille qui ne
//! tient qu'à de tels événements porte la réserve `Reserve::MorceauAbime`. Ce qui n'a pas pu être lu (journal
//! absent, refusé, illisible, désactivé, lu en partie, sous-catégorie d'audit sans preuve qu'elle écrit) devient un
//! `Manque` de la règle : elle est alors « non vérifiée », avec sa raison, et jamais « rien vu ».
//!
//! Les champs viennent du journal, parfois d'un attaquant : comparés sans jamais servir de motif (aucune expression
//! régulière), coupés avant d'être gardés, jamais interprétés. Module autonome (aucun `crate::`, aucun texte
//! traduit) : le banc de fuzzing l'inclut par son chemin.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::evenement::{EvenementWindows, Origine};
use super::trous::{Nature, Numerotation, Suite};

/// Un texte en français et en anglais, traduit à l'affichage.
pub(crate) type Texte = (&'static str, &'static str);

/// La gravité d'une trouvaille.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Gravite {
    /// À savoir, sans être une attaque à elle seule (un compte créé, un téléchargement par BITS d'un éditeur peu
    /// courant).
    Info,
    /// Ce que fait une attaque, et rarement autre chose.
    Alerte,
    /// Une attaque presque à coup sûr, ou réussie (une rafale d'échecs suivie d'une connexion).
    Critique,
}

/// Une comparaison sur la valeur d'un champ (rognée de ses blancs, comme Windows en laisse au bout de certains).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Test {
    Egal(&'static str),
    Commence(&'static str),
    Finit(&'static str),
    Contient(&'static str),
    /// Égale à l'une d'elles.
    Dans(&'static [&'static str]),
    /// Un nombre (décimal, ou hexadécimal en « 0x ») égal à l'un d'eux.
    NombreDans(&'static [u64]),
    /// Un nombre au moins égal.
    NombreAuMoins(u64),
    /// Le champ est là, non vide et autre que « - » (ce que Windows écrit pour « sans valeur »).
    Rempli,
}

/// Une condition sur un événement.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Condition {
    Toujours,
    /// Sans égard à la casse : Windows ne la distingue ni dans les noms de comptes, ni dans les chemins, ni dans les
    /// SID, ni dans les noms de services.
    Champ(&'static str, Test),
    /// Avec la casse.
    ChampExact(&'static str, Test),
    Tous(&'static [Condition]),
    Un(&'static [Condition]),
    Pas(&'static Condition),
    /// Ce que les données seules ne disent pas (un chemin à découper, une adresse à classer).
    Si(fn(&EvenementWindows) -> bool),
}

/// Le nombre d'un champ : décimal, ou hexadécimal en « 0x » (Status, SubStatus, UserAccountControl).
pub(crate) fn nombre(valeur: &str) -> Option<u64> {
    let v = valeur.trim();
    match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

/// Deux textes égaux sans égard à la casse (en Unicode : un nom de compte accentué aussi).
pub(crate) fn egal_sans_casse(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b) || (!a.is_ascii() || !b.is_ascii()) && a.to_lowercase() == b.to_lowercase()
}

impl Test {
    fn vrai(self, valeur: &str, sans_casse: bool) -> bool {
        let v = valeur.trim();
        let bas = |t: &str| {
            if sans_casse { t.to_lowercase() } else { t.to_string() }
        };
        match self {
            Test::Egal(x) => {
                if sans_casse {
                    egal_sans_casse(v, x)
                } else {
                    v == x
                }
            }
            Test::Commence(x) => bas(v).starts_with(&bas(x)),
            Test::Finit(x) => bas(v).ends_with(&bas(x)),
            Test::Contient(x) => bas(v).contains(&bas(x)),
            Test::Dans(xs) => xs.iter().any(|x| Test::Egal(x).vrai(v, sans_casse)),
            Test::NombreDans(ns) => nombre(v).is_some_and(|n| ns.contains(&n)),
            Test::NombreAuMoins(m) => nombre(v).is_some_and(|n| n >= m),
            Test::Rempli => !v.is_empty() && v != "-",
        }
    }
}

impl Condition {
    pub(crate) fn vrai(&self, e: &EvenementWindows) -> bool {
        match *self {
            Condition::Toujours => true,
            Condition::Champ(nom, t) => e.champ(nom).is_some_and(|v| t.vrai(v, true)),
            Condition::ChampExact(nom, t) => e.champ(nom).is_some_and(|v| t.vrai(v, false)),
            Condition::Tous(cs) => cs.iter().all(|c| c.vrai(e)),
            Condition::Un(cs) => cs.iter().any(|c| c.vrai(e)),
            Condition::Pas(c) => !c.vrai(e),
            Condition::Si(f) => f(e),
        }
    }
}

/// Ce qu'on nomme dans le détail d'une trouvaille.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Libelle {
    Compte,
    Adresse,
    Programme,
    Service,
    Commande,
    Demarrage,
    Groupe,
    Membre,
    Auteur,
    Journal,
    Script,
    Menace,
    Action,
    Reglage,
    AncienneValeur,
    NouvelleValeur,
    AdresseWeb,
    Consommateur,
    TypeConnexion,
    Changement,
    Numeros,
    Serveur,
    Installation,
    PremiereSession,
    Parent,
    Tache,
}

impl Libelle {
    pub(crate) fn textes(self) -> Texte {
        match self {
            Libelle::Compte => ("compte", "account"),
            Libelle::Adresse => ("adresse", "address"),
            Libelle::Programme => ("programme", "program"),
            Libelle::Service => ("service", "service"),
            Libelle::Commande => ("commande", "command"),
            Libelle::Demarrage => ("démarrage", "start type"),
            Libelle::Groupe => ("groupe", "group"),
            Libelle::Membre => ("membre", "member"),
            Libelle::Auteur => ("par", "by"),
            Libelle::Journal => ("journal", "log"),
            Libelle::Script => ("script", "script"),
            Libelle::Menace => ("menace", "threat"),
            Libelle::Action => ("action", "action"),
            Libelle::Reglage => ("réglage", "setting"),
            Libelle::AncienneValeur => ("avant", "before"),
            Libelle::NouvelleValeur => ("après", "after"),
            Libelle::AdresseWeb => ("adresse web", "URL"),
            Libelle::Consommateur => ("consommateur", "consumer"),
            Libelle::TypeConnexion => ("type de connexion", "logon type"),
            Libelle::Changement => ("changement", "change"),
            Libelle::Numeros => ("numéros", "record numbers"),
            Libelle::Serveur => ("serveur", "server"),
            Libelle::Installation => ("Windows installé le", "Windows installed on"),
            Libelle::PremiereSession => ("première session le", "first sign-in on"),
            Libelle::Parent => ("lancé par", "started by"),
            Libelle::Tache => ("tâche", "task"),
        }
    }
}

/// Ce qu'un événement donne à une règle de forme `Chacun`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Indice {
    /// Ce qui distingue la trouvaille (un service et son chemin, un compte) : stable, sans langue, minuscules. Avec
    /// la règle, la clé d'une alerte déclarée normale.
    pub objet: String,
    pub gravite: Gravite,
    pub pourquoi: Texte,
    pub details: Vec<(Libelle, String)>,
    /// Ce que fait aussi la mise en route de Windows (le compte de l'ordinateur crée le premier compte et le met
    /// administrateur) : le pourquoi à dire si l'événement tombe pendant l'installation (`Options::installation`).
    /// Rien : l'événement se juge seul.
    pub mise_en_route: Option<Texte>,
}

/// La forme d'un volet de règle.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Forme {
    /// Chaque événement qui répond est jugé seul ; `None` : rien à dire de celui-ci.
    Chacun(fn(&EvenementWindows) -> Option<Indice>),
    /// Au moins `nombre` événements de la même clé (`par`, et l'ordinateur) en `fenetre` secondes.
    Rafale {
        par: &'static [&'static str],
        nombre: usize,
        fenetre: i64,
        gravite: Gravite,
        pourquoi: Texte,
    },
    /// Une rafale (comme `Rafale`) puis, au plus `delai` secondes après le dernier échec, un événement B
    /// (`b_ids`, `b_quand`) de la même clé.
    Apres {
        par: &'static [&'static str],
        nombre: usize,
        fenetre: i64,
        delai: i64,
        b_ids: &'static [u32],
        b_quand: Condition,
        gravite: Gravite,
        pourquoi: Texte,
    },
    /// Les trous des suites de numéros de tous les journaux lus (`EtatJournal::suites`), croisés avec les arrêts
    /// inattendus (System 6008, Kernel-Power 41).
    Trous,
}

/// Ce que Windows écrit d'origine pour ce volet.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Audit {
    /// Écrit sur un Windows 10 ou 11 tel qu'installé (journal actif, sous-catégorie auditée d'origine).
    DOrigine,
    /// Dépend d'une sous-catégorie de la politique d'audit qu'un réglage peut couper sans que rien ne le dise dans
    /// le journal lu : sans un événement de `preuve` vu (vérifié) dans ce journal, la règle n'est pas vérifiée.
    Preuve { preuve: &'static [u32], quoi: Texte },
    /// Comme `Preuve`, mais la preuve est un événement du volet lui-même (ses numéros, son journal, ses
    /// fournisseurs), vérifié, dont `champ` est rempli : un réglage à part décide si Windows écrit ce champ (la ligne
    /// de commande du 4688, vide d'origine), et seul un événement qui le porte prouve qu'il est allumé. La preuve doit
    /// être récente : le plus récent de ces événements la porte (un réglage coupé ensuite, sans trace dans le journal,
    /// laisse les suivants vides), et il date du dernier jour du journal. `vide_permis` : les événements où le champ
    /// est vide même réglage allumé (les processus du noyau, sans ligne de commande), qui ne comptent pas.
    PreuveChamp {
        champ: &'static str,
        quoi: Texte,
        vide_permis: fn(&EvenementWindows) -> bool,
    },
}

/// Une partie d'une règle : un journal, des numéros d'événements, une forme.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Volet {
    /// Le journal (System/Channel), sans égard à la casse.
    pub journal: &'static str,
    /// Les fournisseurs admis (System/Provider Name), sans égard à la casse ; vide : tous. Un même numéro sert à
    /// d'autres fournisseurs dans d'autres journaux (Application 4625 d'EventSystem, CAPI2 41).
    pub fournisseurs: &'static [&'static str],
    pub ids: &'static [u32],
    pub quand: Condition,
    pub forme: Forme,
    pub audit: Audit,
    /// La sous-catégorie de la politique d'audit qui écrit ces événements (son GUID, en minuscules, tel que le
    /// porte le 4719) : un 4719 qui la réduit pendant la période rend la règle non vérifiée.
    pub sous_categorie: Option<&'static str>,
}

/// Une règle `EVT-`.
#[derive(Debug)]
pub(crate) struct Regle {
    /// « EVT-EFF-001 » : stable, jamais repris.
    pub id: &'static str,
    pub sujet: Texte,
    /// Les techniques d'ATT&CK (« T1685.005 »), dans la numérotation de la version 20 (T1070.001 y est devenue
    /// T1685.005, T1562.001 T1685, T1562.002 T1685.001 : les anciennes ne sont plus que des renvois).
    pub techniques: &'static [&'static str],
    /// La documentation de Microsoft de ses événements, puis la page d'ATT&CK.
    pub references: &'static [&'static str],
    pub volets: &'static [Volet],
    /// Ce que la règle ne peut pas voir, même tout lu (dit avec son verdict).
    pub limite: Option<Texte>,
    /// La règle juge Microsoft Defender : sans objet quand il n'est pas l'antivirus de l'ordinateur.
    pub defender: bool,
    /// Ses journaux sont des sources de rechange (la politique d'audit, ou l'historique du Planificateur de tâches) :
    /// un seul lu en entier, et prouvé, suffit à la vérifier ; ce qui manque aux autres n'est alors pas dit. Faux :
    /// chacun doit l'être.
    pub un_journal_suffit: bool,
}

/// Une réserve sur une trouvaille.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Reserve {
    /// Ne tient qu'à des événements de morceaux abîmés (CRC faux) : un indice, pas une preuve.
    MorceauAbime,
    /// Un trou dans un fichier copié pendant que Windows écrivait : effacement possible, non concluant.
    CopieAChaud,
    /// Un trou dans les numéros d'origine d'un fichier exporté : effacés avant l'export, ou laissés par le filtre de
    /// l'export ; un fichier exporté se fabrique, rien ne prouve son origine.
    AvantExport,
    /// Un arrêt inattendu (6008) ou une coupure de courant (Kernel-Power 41) au même moment explique sans
    /// effacement des enregistrements perdus.
    ArretInattendu,
    /// Un autre antivirus est inscrit au Centre de sécurité : Defender se met alors en retrait de lui-même ; mais un
    /// faux antivirus inscrit fait de même (l'outil defendnot), et c'est l'état d'aujourd'hui qui juge le passé.
    AutreAntivirus,
    /// Fait par le compte de l'ordinateur, comme la mise en route de Windows crée le premier compte ; la date de
    /// l'installation n'est pas connue ici (un dossier rapporté, ou illisible) : l'alerte reste.
    MiseEnRoutePossible,
}

/// Un événement à l'appui d'une trouvaille, pour le retrouver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Repere {
    pub journal: String,
    pub id: u32,
    pub date: Option<DateTime<Utc>>,
    pub numero: Option<u64>,
    pub verifie: bool,
    /// Le fichier .evtx, pour la source fichiers.
    pub fichier: Option<Arc<Path>>,
}

/// Ce qu'une règle a trouvé, regroupé par objet et par ordinateur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Trouvaille {
    /// L'indice du volet dans la règle.
    pub volet: usize,
    pub objet: String,
    pub ordinateur: String,
    /// La plus haute des événements regroupés.
    pub gravite: Gravite,
    pub pourquoi: Texte,
    /// Ceux du plus ancien événement (le plus petit numéro à date égale) : le même quel que soit l'ordre de lecture.
    pub details: Vec<(Libelle, String)>,
    /// Événements à l'appui (pour une rafale : les événements des rafales).
    pub nombre: u64,
    /// Parmi eux, ceux d'un morceau vérifié.
    pub verifies: u64,
    pub premier: Option<DateTime<Utc>>,
    pub dernier: Option<DateTime<Utc>>,
    /// Les plus anciens, au plus `BornesMoteur::reperes`.
    pub reperes: Vec<Repere>,
    pub reserves: BTreeSet<Reserve>,
    /// Le pourquoi « pendant l'installation de Windows », si chacun de ses événements en a un (`Indice`).
    pub mise_en_route: Option<Texte>,
}

/// Pourquoi une règle n'a pas pu tout voir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Manque {
    /// Le journal n'est pas là : pas de fichier dans le dossier, ou absent de cet ordinateur.
    Absent(String),
    /// Lecture refusée (Security sans droits d'administrateur).
    Refuse(String),
    /// Illisible : le journal, et pourquoi (texte déjà dans la langue du moment, donné par la source).
    Illisible(String, String),
    /// Le journal est désactivé : il n'écrit plus rien, ce qui est lu est ancien.
    Desactive(String),
    /// Lu en partie : le journal, et ce qui manque (texte déjà dans la langue du moment).
    Partiel(String, String),
    /// Le journal a été lu mais n'a rien donné sur la période (Security et System écrivent sans cesse sur un
    /// ordinateur en marche) : vidé, remplacé, ou sa politique d'audit coupée.
    Vide(String),
    /// Un journal calme (PowerShell, BITS, WMI, Defender…), présent et lu, mais sans un seul événement sur la période :
    /// rien n'y a été vérifié. Courant (un journal où rien ne s'est passé), mais un journal vidé ressemble à cela :
    /// pas de ✔ pour ses règles, sans alerte.
    VideCalme(String),
    /// Le journal se tait depuis cette date alors que d'autres écrivent encore : service des journaux bloqué,
    /// audit coupé.
    Muet { journal: String, depuis: DateTime<Utc> },
    /// Un 4719 a réduit la sous-catégorie d'audit de ces événements pendant la période.
    AuditReduit { journal: String },
    /// Des événements de morceaux abîmés que la source n'a pas comptés comme une lecture partielle.
    NonVerifies { journal: String, nombre: u64 },
    /// La sous-catégorie d'audit qui écrit ces événements n'a laissé aucune preuve qu'elle est active.
    NonAudite { journal: String, quoi: Texte },
    /// Le champ d'une `Audit::PreuveChamp` a été écrit, puis ne l'est plus depuis cette date (réglage coupé), ou sa
    /// dernière preuve est trop ancienne.
    ChampCoupe {
        journal: String,
        depuis: DateTime<Utc>,
        quoi: Texte,
    },
    /// Le journal ne remonte qu'à cette date, après le début de la période demandée : plus ancien écrasé (journal
    /// plein qui tourne), effacé, ou rien écrit.
    PeriodeCourte { journal: String, debut: DateTime<Utc> },
    /// Une borne du moteur atteinte : des événements de la règle n'ont pas été jugés.
    Bornes(u64),
    /// Des événements de la règle sans date lisible : une rafale ne peut pas les placer.
    SansDate(u64),
    /// Des trous de numéros là où la lecture a perdu quelque chose : non vérifiés.
    TrousIllisibles { journal: String, nombre: u64 },
    /// Des numéros qui ne tiennent qu'à des morceaux abîmés : la suite n'est pas une preuve.
    SuiteNonProuvee { journal: String, nombre: u64 },
    /// Trous au-delà des bornes de la suite, comptés sans être jugés.
    TrousAuDela { journal: String, nombre: u64 },
    /// Rien ne dit si Defender est l'antivirus de l'ordinateur (dossier rapporté) : une protection coupée peut être
    /// celle d'un Defender mis en retrait par un autre antivirus.
    DefenderInconnu,
}

/// Ce que vaut la lecture d'un journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lecture {
    /// Lu ; vide quand tout a été lu et jugé, sinon ce qui manque (dans la langue du moment).
    Lu(Vec<String>),
    Absent,
    Refuse,
    Illisible(String),
}

/// Un journal tel que la source l'a lu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EtatJournal {
    pub nom: String,
    pub lecture: Lecture,
    /// Activé (registre) ; rien si on ne le sait pas.
    pub active: Option<bool>,
    /// La lecture porte sur ce journal lui-même (son fichier, ou le journal de l'ordinateur), pas sur quelques-uns
    /// de ses événements mêlés à d'autres (une archive d'événements transférés, un journal de collecte).
    pub principal: bool,
    pub suites: Vec<Suite>,
}

/// Ce qu'un journal a donné au moteur.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct StatJournal {
    pub nom: String,
    pub evenements: u64,
    pub non_verifies: u64,
    pub sans_date: u64,
    pub premier: Option<DateTime<Utc>>,
    pub dernier: Option<DateTime<Utc>>,
    /// Numéros d'événements vus dans un morceau vérifié (au plus `MAX_IDS_VUS`) : la preuve qu'une sous-catégorie
    /// d'audit écrit.
    ids_vus: HashSet<u32>,
}

/// Ce que l'analyse sait d'avance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Options {
    /// Le début de la période demandée (rien : tout ce que les journaux contiennent).
    pub depuis: Option<DateTime<Utc>>,
    /// Microsoft Defender est-il l'antivirus de l'ordinateur ? Rien : on ne le sait pas (dossier rapporté).
    pub defender_antivirus: Option<bool>,
    /// L'installation de Windows sur cet ordinateur (InstallDate du registre). Rien : pas connue (dossier rapporté,
    /// valeur illisible) ; ce que fait aussi la mise en route reste alors une alerte, avec sa réserve.
    pub installation: Option<DateTime<Utc>>,
}

/// Les bornes du moteur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BornesMoteur {
    /// Trouvailles distinctes gardées par règle.
    pub trouvailles: usize,
    /// Exemples gardés par trouvaille.
    pub reperes: usize,
    /// Dates gardées par volet de rafale (chaque événement A ou B).
    pub dates: usize,
    /// Clés distinctes par volet de rafale.
    pub cles: usize,
    /// Arrêts inattendus gardés pour expliquer les trous.
    pub arrets: usize,
    /// Journaux distincts suivis.
    pub journaux: usize,
}

impl Default for BornesMoteur {
    fn default() -> Self {
        Self {
            trouvailles: 500,
            reperes: 5,
            // Un événement daté fait 24 octets ici : un million de A et un million de B par volet font 48 Mo au
            // plus (96 Mo le temps qu'un vecteur double), pour six volets de rafales du 4625. Un journal de sécurité
            // d'origine (20 Mo) en a quelques dizaines de milliers.
            dates: 1_000_000,
            cles: 20_000,
            arrets: 10_000,
            journaux: 512,
        }
    }
}

/// Les caractères gardés d'un objet ou d'un détail : un chemin de service, une adresse web, un extrait de script.
pub(crate) const TEXTE_MAX: usize = 400;

/// Numéros d'événements retenus par journal pour les preuves d'audit.
const MAX_IDS_VUS: usize = 4096;

/// Une marge autour de la fin d'un trou pour y chercher un arrêt inattendu : Windows écrit le 6008 et le 41 au
/// démarrage qui suit l'arrêt (« logged when the most recent shutdown was unexpected »), comme les premiers
/// enregistrements d'après le trou.
const MARGE_ARRET: i64 = 15 * 60;

/// Le plus d'enregistrements qu'un arrêt inattendu peut faire perdre : un morceau que Windows n'avait pas encore
/// écrit (au plus `CAPACITE_MORCEAU` d'enregistrements minimaux ; un vrai morceau en porte quelques centaines).
const PERTE_ARRET_MAX: u64 = 1000;

/// Coupe un texte venu du journal à `TEXTE_MAX` caractères.
pub(crate) fn couper(t: &str) -> String {
    let t = t.trim();
    match t.char_indices().nth(TEXTE_MAX) {
        Some((i, _)) => format!("{}…", &t[..i]),
        None => t.to_string(),
    }
}

/// Un événement daté d'une rafale.
#[derive(Debug, Clone, Copy)]
struct Marque {
    date: DateTime<Utc>,
    numero: u64,
    verifie: bool,
}

/// Le plus ancien événement d'une clé de rafale, son repère et ses détails.
type Exemple = (Marque, Repere, Vec<(Libelle, String)>);

/// Les événements datés d'un volet de rafale, par clé.
#[derive(Debug, Default)]
struct Rafales {
    /// Chaque clé une seule fois, et son indice dans `par_cle`.
    cles: HashMap<String, u32>,
    /// Par indice de clé : A, B, et les B laissés faute de place (une perte seulement si la clé a des A).
    par_cle: Vec<(Vec<Marque>, Vec<Marque>, u64)>,
    /// A gardés, et B gardés : deux budgets, pour que des millions de connexions réussies (un serveur de fichiers)
    /// ne prennent pas la place des échecs.
    gardes: usize,
    gardes_b: usize,
    /// Événements qu'une borne a fait laisser.
    perdus: u64,
    sans_date: u64,
    /// Un exemple par clé (le plus ancien vu de A), pour les détails.
    exemples: HashMap<u32, Exemple>,
}

/// Le plus récent événement qui porte le champ d'une `Audit::PreuveChamp`, et le plus récent qui ne le porte pas.
type Preuves = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

/// Ce que le moteur garde d'une règle.
#[derive(Debug, Default)]
struct EtatRegle {
    trouvailles: HashMap<(usize, String, String), Trouvaille>,
    au_dela: u64,
    /// La plus grave des trouvailles laissées au-delà de la borne.
    au_dela_pire: Option<Gravite>,
    rafales: HashMap<usize, Rafales>,
    examines: u64,
    /// Par volet `Audit::PreuveChamp` : le plus récent de ses événements vérifiés et datés qui porte le champ, et le
    /// plus récent qui ne le porte pas (hors `vide_permis`).
    prouves: HashMap<usize, Preuves>,
}

/// Le jugement d'une règle.
#[derive(Debug, Clone)]
pub(crate) struct Jugement {
    pub regle: &'static Regle,
    /// Les plus graves d'abord, puis les plus anciennes.
    pub trouvailles: Vec<Trouvaille>,
    /// Trouvailles au-delà de `BornesMoteur::trouvailles`, comptées en événements : à la borne, les moins graves
    /// laissent leur place aux plus graves.
    pub au_dela: u64,
    /// La plus grave des trouvailles laissées.
    pub au_dela_pire: Option<Gravite>,
    pub manques: Vec<Manque>,
    /// Événements que la règle a examinés (de ses journaux, numéros et fournisseurs).
    pub examines: u64,
    /// Les journaux de la règle, et ce qu'ils ont donné.
    pub journaux: Vec<StatJournal>,
    /// Sans objet : la règle juge Defender, qui n'est pas l'antivirus ici.
    pub sans_objet: bool,
}

impl Jugement {
    /// Rien n'a manqué : la règle a tout lu de ce qu'elle cherche.
    pub(crate) fn verifie(&self) -> bool {
        self.manques.is_empty()
    }
}

/// Le moteur, nourri événement par événement.
pub(crate) struct Moteur {
    regles: &'static [Regle],
    bornes: BornesMoteur,
    options: Options,
    /// Par numéro d'événement : (règle, volet, B d'un volet `Apres`).
    index: HashMap<u32, Vec<(usize, usize, bool)>>,
    etats: Vec<EtatRegle>,
    journaux: HashMap<String, StatJournal>,
    journaux_au_dela: u64,
    /// Les arrêts inattendus vérifiés : (date, ordinateur en minuscules).
    arrets: Vec<(DateTime<Utc>, String)>,
    arrets_au_dela: u64,
    /// Les sous-catégories d'audit réduites par un 4719 (GUID en minuscules), au plus `MAX_REDUITES`.
    audit_reduit: BTreeSet<String>,
    /// La première session ouverte par une personne (`session_d_une_personne`), tous noms d'ordinateur confondus :
    /// la mise en route crée le premier compte avant qu'il ouvre sa session, et le nom de l'ordinateur change souvent
    /// pendant elle. La date d'installation n'est connue que de la source vivante, un seul ordinateur.
    premiere_session: Option<DateTime<Utc>>,
    /// Une session d'une personne sans date : on ne sait plus si elle précède, rien n'est admis.
    session_sans_date: bool,
    /// Un 1102 lu (journal de sécurité vidé) : les sessions d'avant ont pu disparaître avec lui.
    securite_videe: bool,
}

/// La clé d'un journal (sans casse).
fn cle_journal(nom: &str) -> String {
    nom.to_lowercase()
}

fn repere(e: &EvenementWindows) -> Repere {
    Repere {
        journal: couper(&e.journal),
        id: e.id,
        date: e.date,
        numero: e.numero,
        verifie: e.verifie,
        fichier: match &e.origine {
            Origine::Fichier { chemin, .. } => Some(chemin.clone()),
            Origine::Vivant => None,
        },
    }
}

/// L'ordre stable de deux événements : date, puis numéro (rien en dernier).
fn rang(date: Option<DateTime<Utc>>, numero: Option<u64>, verifie: bool) -> (bool, Option<DateTime<Utc>>, u64, bool) {
    (date.is_none(), date, numero.unwrap_or(u64::MAX), !verifie)
}

impl Moteur {
    pub(crate) fn nouveau(regles: &'static [Regle], options: Options, bornes: BornesMoteur) -> Self {
        let mut index: HashMap<u32, Vec<(usize, usize, bool)>> = HashMap::new();
        for (r, regle) in regles.iter().enumerate() {
            for (v, volet) in regle.volets.iter().enumerate() {
                for &id in volet.ids {
                    index.entry(id).or_default().push((r, v, false));
                }
                if let Forme::Apres { b_ids, .. } = volet.forme {
                    for &id in b_ids {
                        index.entry(id).or_default().push((r, v, true));
                    }
                }
            }
        }
        Self {
            regles,
            bornes,
            options,
            index,
            etats: regles.iter().map(|_| EtatRegle::default()).collect(),
            journaux: HashMap::new(),
            journaux_au_dela: 0,
            arrets: Vec::new(),
            arrets_au_dela: 0,
            audit_reduit: BTreeSet::new(),
            premiere_session: None,
            session_sans_date: false,
            securite_videe: false,
        }
    }

    /// Un événement lu, d'une source ou de l'autre.
    pub(crate) fn recevoir(&mut self, e: &EvenementWindows) {
        let cle = cle_journal(&e.journal);
        let n = self.journaux.len();
        let stat = match self.journaux.get_mut(&cle) {
            Some(s) => Some(s),
            None if n < self.bornes.journaux => Some(self.journaux.entry(cle).or_insert_with(|| StatJournal {
                nom: couper(&e.journal),
                ..StatJournal::default()
            })),
            None => {
                self.journaux_au_dela += 1;
                None
            }
        };
        if let Some(s) = stat {
            s.evenements += 1;
            s.non_verifies += u64::from(!e.verifie);
            match e.date {
                Some(d) => {
                    s.premier = Some(s.premier.map_or(d, |p| p.min(d)));
                    s.dernier = Some(s.dernier.map_or(d, |p| p.max(d)));
                }
                None => s.sans_date += 1,
            }
            if e.verifie && s.ids_vus.len() < MAX_IDS_VUS {
                s.ids_vus.insert(e.id);
            }
        }
        // Un arrêt d'un morceau abîmé n'excuse rien : il pourrait avoir été posé là exprès.
        if e.verifie && est_arret(e) {
            match e.date {
                Some(d) if self.arrets.len() < self.bornes.arrets => {
                    self.arrets.push((d, couper(&e.ordinateur.to_lowercase())));
                }
                Some(_) => self.arrets_au_dela += 1,
                None => {}
            }
        }
        if let Some(guid) = audit_reduit(e)
            && self.audit_reduit.len() < MAX_REDUITES
        {
            self.audit_reduit.insert(guid);
        }
        if e.id == 1102
            && e.journal.eq_ignore_ascii_case("Security")
            && e.fournisseur.eq_ignore_ascii_case("Microsoft-Windows-Eventlog")
        {
            self.securite_videe = true;
        }
        if session_d_une_personne(e) {
            match e.date {
                Some(d) => self.premiere_session = Some(self.premiere_session.map_or(d, |p| p.min(d))),
                None => self.session_sans_date = true,
            }
        }
        let Some(cibles) = self.index.get(&e.id) else {
            return;
        };
        for &(r, v, b) in cibles {
            let volet = &self.regles[r].volets[v];
            if !e.journal.eq_ignore_ascii_case(volet.journal)
                || !(volet.fournisseurs.is_empty()
                    || volet
                        .fournisseurs
                        .iter()
                        .any(|f| f.eq_ignore_ascii_case(e.fournisseur.trim())))
            {
                continue;
            }
            let etat = &mut self.etats[r];
            if let Audit::PreuveChamp { champ, vide_permis, .. } = volet.audit
                && e.verifie
                && !b
                && let Some(d) = e.date
            {
                let rempli = e.champ(champ).is_some_and(|x| {
                    let x = x.trim();
                    !x.is_empty() && x != "-"
                });
                let (avec, sans) = etat.prouves.entry(v).or_default();
                if rempli {
                    *avec = Some(avec.map_or(d, |a| a.max(d)));
                } else if !vide_permis(e) {
                    *sans = Some(sans.map_or(d, |a| a.max(d)));
                }
            }
            match volet.forme {
                Forme::Chacun(juger) => {
                    if !volet.quand.vrai(e) {
                        continue;
                    }
                    etat.examines += 1;
                    if let Some(indice) = juger(e) {
                        ajouter(etat, &self.bornes, v, &e.ordinateur, indice, e);
                    }
                }
                Forme::Rafale { par, .. } => {
                    if volet.quand.vrai(e) {
                        etat.examines += 1;
                        noter_rafale(etat, &self.bornes, v, par, e, false);
                    }
                }
                Forme::Apres { par, b_quand, .. } => {
                    let voulu = if b { b_quand.vrai(e) } else { volet.quand.vrai(e) };
                    if voulu {
                        etat.examines += 1;
                        noter_rafale(etat, &self.bornes, v, par, e, b);
                    }
                }
                Forme::Trous => {}
            }
        }
    }

    /// Le jugement de chaque règle, d'après ce qu'elle a vu et la lecture de chaque journal.
    pub(crate) fn conclure(mut self, journaux: &[EtatJournal]) -> Vec<Jugement> {
        let arrets = std::mem::take(&mut self.arrets);
        let mut sortie = Vec::new();
        for (r, regle) in self.regles.iter().enumerate() {
            let mut etat = std::mem::take(&mut self.etats[r]);
            let mut manques: Vec<Manque> = Vec::new();
            for (v, volet) in regle.volets.iter().enumerate() {
                match volet.forme {
                    Forme::Trous => trous(&mut etat, &self.bornes, v, journaux, &arrets, &mut manques),
                    Forme::Rafale { .. } | Forme::Apres { .. } => {
                        if let Some(raf) = etat.rafales.remove(&v) {
                            juger_rafales(&mut etat, &self.bornes, v, volet, raf, &mut manques);
                        }
                    }
                    Forme::Chacun(_) => {}
                }
            }
            if self.arrets_au_dela > 0 && regle.volets.iter().any(|v| matches!(v.forme, Forme::Trous)) {
                manques.push(Manque::Bornes(self.arrets_au_dela));
            }
            if self.journaux_au_dela > 0 {
                manques.push(Manque::Bornes(self.journaux_au_dela));
            }
            let plus_recent = self.journaux.values().filter_map(|s| s.dernier).max();
            let mut stats = Vec::new();
            // Ce qui manque à chaque journal de la règle, dans l'ordre de ses volets : une règle à sources de rechange
            // (`Regle::un_journal_suffit`) est vérifiée dès que l'un d'eux n'a rien qui manque.
            let mut par_journal: Vec<(String, Vec<Manque>)> = Vec::new();
            for (v, volet) in regle.volets.iter().enumerate().filter(|(_, v)| !v.journal.is_empty()) {
                let cle = cle_journal(volet.journal);
                let stat = self.journaux.get(&cle).cloned().unwrap_or_else(|| StatJournal {
                    nom: volet.journal.to_string(),
                    ..StatJournal::default()
                });
                let i = if let Some(i) = par_journal.iter().position(|(c, _)| *c == cle) {
                    i
                } else {
                    let m = lecture(volet.journal, journaux, &stat, &self.options, plus_recent);
                    stats.push(stat.clone());
                    par_journal.push((cle, m));
                    par_journal.len() - 1
                };
                let siens = &mut par_journal[i].1;
                let mut noter = |m: Manque| {
                    if !siens.contains(&m) {
                        siens.push(m);
                    }
                };
                if let Some(sc) = volet.sous_categorie
                    && self.audit_reduit.contains(sc)
                {
                    noter(Manque::AuditReduit {
                        journal: volet.journal.to_string(),
                    });
                }
                let non_audite = |quoi| Manque::NonAudite {
                    journal: volet.journal.to_string(),
                    quoi,
                };
                match volet.audit {
                    Audit::Preuve { preuve, quoi } if !preuve.iter().any(|id| stat.ids_vus.contains(id)) => {
                        noter(non_audite(quoi));
                    }
                    Audit::PreuveChamp { quoi, .. } => match etat.prouves.get(&v).copied().unwrap_or_default() {
                        (None, _) => noter(non_audite(quoi)),
                        // Des événements sans le champ après le dernier qui le portait : coupé depuis.
                        (Some(avec), Some(sans)) if sans > avec => noter(Manque::ChampCoupe {
                            journal: volet.journal.to_string(),
                            depuis: avec,
                            quoi,
                        }),
                        // La dernière preuve plus d'un jour avant la fin du journal : plus rien ne la tient.
                        (Some(avec), _) if stat.dernier.is_some_and(|d| d - avec > chrono::Duration::days(1)) => {
                            noter(Manque::ChampCoupe {
                                journal: volet.journal.to_string(),
                                depuis: avec,
                                quoi,
                            });
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            let un_suffit = regle.un_journal_suffit && par_journal.iter().any(|(_, m)| m.is_empty());
            if !un_suffit {
                for m in par_journal.into_iter().flat_map(|(_, m)| m) {
                    if !manques.contains(&m) {
                        manques.push(m);
                    }
                }
            }
            let mut trouvailles: Vec<Trouvaille> = etat.trouvailles.into_values().collect();
            let mut sans_objet = false;
            if regle.defender {
                match self.options.defender_antivirus {
                    // Un Defender en retrait coupe lui-même sa protection en temps réel (5001) : dit, en
                    // information, avec la réserve (un faux antivirus inscrit fait de même), jamais jeté.
                    Some(false) => {
                        for t in trouvailles.iter_mut().filter(|t| t.objet.starts_with("temps-reel")) {
                            t.gravite = t.gravite.min(Gravite::Info);
                            t.reserves.insert(Reserve::AutreAntivirus);
                        }
                        sans_objet = trouvailles.is_empty();
                        if sans_objet {
                            // Un journal de Defender absent va de soi sans lui ; une lecture partielle reste dite.
                            manques
                                .retain(|m| !matches!(m, Manque::Absent(_) | Manque::Vide(_) | Manque::VideCalme(_)));
                        }
                    }
                    Some(true) => {}
                    None => manques.push(Manque::DefenderInconnu),
                }
            }
            self.juger_mise_en_route(&mut trouvailles);
            trouvailles.sort_by(|a, b| {
                b.gravite
                    .cmp(&a.gravite)
                    .then_with(|| rang(a.premier, None, true).cmp(&rang(b.premier, None, true)))
                    .then_with(|| (a.volet, &a.ordinateur, &a.objet).cmp(&(b.volet, &b.ordinateur, &b.objet)))
            });
            for t in &mut trouvailles {
                if t.verifies == 0 {
                    t.reserves.insert(Reserve::MorceauAbime);
                }
            }
            sortie.push(Jugement {
                regle,
                trouvailles,
                au_dela: etat.au_dela,
                au_dela_pire: etat.au_dela_pire,
                manques,
                examines: etat.examines,
                journaux: stats,
                sans_objet,
            });
        }
        sortie
    }

    /// Ce que fait aussi la mise en route de Windows (le compte de l'ordinateur crée le premier compte et le met
    /// administrateur) : une information quand c'est pendant l'installation, une alerte avec sa réserve quand la
    /// date d'installation n'est pas connue, une alerte seule ensuite. SYSTEM est aussi ce qu'obtient un attaquant :
    /// la fenêtre est courte (`pendant_la_mise_en_route`), et l'absence de session ne prouve rien si le journal de
    /// sécurité ne remonte pas jusqu'à l'installation : InstallDate s'écrit sans laisser de trace (un attaquant SYSTEM
    /// peut la mettre à aujourd'hui), mais le journal d'un Windows installé depuis longtemps commence bien avant, et
    /// un journal vidé pour faire croire le contraire laisse son 1102.
    fn juger_mise_en_route(&self, trouvailles: &mut [Trouvaille]) {
        let debut_securite = self.journaux.get(&cle_journal("Security")).and_then(|s| s.premier);
        for t in trouvailles.iter_mut() {
            let Some(pourquoi) = t.mise_en_route else { continue };
            // Une information de toute façon (un compte créé, par SYSTEM ou non) : rien à expliquer.
            let alerte = t.gravite > Gravite::Info;
            match self.options.installation {
                Some(installation) => {
                    let session = self.premiere_session;
                    let couvert = !self.securite_videe
                        && !self.session_sans_date
                        && lu_depuis_l_installation(self.options.depuis, debut_securite, installation);
                    if couvert && pendant_la_mise_en_route(t, installation, session) {
                        t.gravite = Gravite::Info;
                        t.pourquoi = pourquoi;
                    } else if alerte {
                        // Ce qui l'écarte de la mise en route, pour en juger soi-même.
                        let date =
                            |d: DateTime<Utc>| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string();
                        t.details.push((Libelle::Installation, date(installation)));
                        if let Some(s) = session.filter(|s| t.dernier.is_some_and(|d| d > *s)) {
                            t.details.push((Libelle::PremiereSession, date(s)));
                        }
                    }
                }
                None if alerte => {
                    t.reserves.insert(Reserve::MiseEnRoutePossible);
                }
                None => {}
            }
        }
    }

    /// Ce que chaque journal a donné (tous ceux vus), pour la couverture.
    pub(crate) fn journaux(&self) -> Vec<StatJournal> {
        let mut v: Vec<StatJournal> = self.journaux.values().cloned().collect();
        v.sort_by(|a, b| a.nom.cmp(&b.nom));
        v
    }
}

/// Sous-catégories d'audit réduites gardées au plus : Windows en a une soixantaine.
const MAX_REDUITES: usize = 128;

/// Avant la date d'installation : InstallDate peut être récrite après la mise en route, par les mises à jour des
/// premières heures (sur un vrai Windows 11 installé le jour même, une heure après la création du premier compte).
/// L'attaque que cette marge laisserait passer aurait eu lieu avant toute session d'une personne (exigé aussi).
const AVANT_INSTALLATION: i64 = 24 * 3600;

/// Après la date d'installation : la mise en route peut attendre des heures qu'on choisisse son compte (Windows
/// installé le soir, le compte créé le lendemain matin), jamais plus d'un jour.
const APRES_INSTALLATION: i64 = 24 * 3600;

/// Une ouverture de session par une personne (4624 au clavier, au Bureau à distance ou en cache, d'un compte local
/// ou du domaine, S-1-5-21-…, ou d'Entra ID, S-1-12-1-…) : celles des comptes de service et des comptes virtuels ne
/// comptent pas, ni le compte temporaire de la mise en route elle-même (« defaultuser0 », « defaultuser100000 »),
/// qu'elle ouvre avant de créer le vrai.
fn session_d_une_personne(e: &EvenementWindows) -> bool {
    if e.id != 4624
        || !e.journal.eq_ignore_ascii_case("Security")
        || !e
            .fournisseur
            .eq_ignore_ascii_case("Microsoft-Windows-Security-Auditing")
    {
        return false;
    }
    let Some(type_) = e.champ("LogonType").and_then(nombre) else {
        return false;
    };
    let sid = e.champ("TargetUserSid").unwrap_or_default().trim().to_ascii_uppercase();
    let nom = e.champ("TargetUserName").unwrap_or_default().trim().to_lowercase();
    let temporaire = nom
        .strip_prefix("defaultuser")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|o| o.is_ascii_digit()));
    matches!(type_, 2 | 10 | 11) && (sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-")) && !temporaire
}

/// Le journal de sécurité lu remonte jusqu'à l'installation : sans cela, l'absence de session ne prouve rien (lu
/// depuis une date plus récente, ou un journal qui a tourné). La période demandée commence avant la fenêtre, et le
/// plus ancien événement lu tombe autour de l'installation (un Windows installé depuis longtemps a un journal plus
/// ancien : une InstallDate récrite à aujourd'hui ne l'y fait pas passer).
fn lu_depuis_l_installation(
    depuis: Option<DateTime<Utc>>,
    debut_securite: Option<DateTime<Utc>>,
    installation: DateTime<Utc>,
) -> bool {
    let fenetre = installation - chrono::Duration::seconds(AVANT_INSTALLATION);
    depuis.is_none_or(|d| d <= fenetre)
        && debut_securite.is_some_and(|d| d >= fenetre && d <= installation + chrono::Duration::seconds(MARGE_JOURNAL))
}

/// Le journal de sécurité commence avec l'installation (avant InstallDate, sur un vrai Windows 11) ; une heure de
/// marge après elle.
const MARGE_JOURNAL: i64 = 3600;

/// Tous les événements de la trouvaille tombent dans la mise en route : à un jour près de la date d'installation, et
/// avant que quiconque ait ouvert une session sur cet ordinateur. Un événement sans date n'y tombe jamais (et en
/// exclut sa trouvaille : `ajouter`).
fn pendant_la_mise_en_route(t: &Trouvaille, installation: DateTime<Utc>, session: Option<DateTime<Utc>>) -> bool {
    let (Some(premier), Some(dernier)) = (t.premier, t.dernier) else {
        return false;
    };
    premier >= installation - chrono::Duration::seconds(AVANT_INSTALLATION)
        && dernier <= installation + chrono::Duration::seconds(APRES_INSTALLATION)
        && session.is_none_or(|s| dernier <= s)
}

/// La sous-catégorie qu'un 4719 réduit (succès ou échec retiré : %%8448, %%8450), en minuscules.
fn audit_reduit(e: &EvenementWindows) -> Option<String> {
    if e.id != 4719
        || !e.journal.eq_ignore_ascii_case("Security")
        || !e
            .fournisseur
            .eq_ignore_ascii_case("Microsoft-Windows-Security-Auditing")
    {
        return None;
    }
    let changement = e.champ("AuditPolicyChanges")?.to_lowercase();
    let retire = changement.contains("%%8448") || changement.contains("%%8450") || changement.contains("removed");
    retire.then(|| couper(&e.champ("SubcategoryGuid").unwrap_or_default().to_lowercase()))
}

/// System 6008 (arrêt inattendu, écrit par EventLog) ou 41 (Kernel-Power : redémarré sans arrêt propre).
fn est_arret(e: &EvenementWindows) -> bool {
    e.journal.eq_ignore_ascii_case("System")
        && ((e.id == 6008 && e.fournisseur.eq_ignore_ascii_case("EventLog"))
            || (e.id == 41 && e.fournisseur.eq_ignore_ascii_case("Microsoft-Windows-Kernel-Power")))
}

/// Ce que vaut la lecture du journal d'une règle : rien quand il a été lu en entier.
fn lecture(
    journal: &str,
    journaux: &[EtatJournal],
    stat: &StatJournal,
    options: &Options,
    plus_recent: Option<DateTime<Utc>>,
) -> Vec<Manque> {
    let mut m = Vec::new();
    let etats: Vec<&EtatJournal> = journaux
        .iter()
        .filter(|j| j.nom.eq_ignore_ascii_case(journal))
        .collect();
    if etats.is_empty() {
        // La source ne l'a pas nommé : même si quelques-uns de ses événements sont venus d'ailleurs (au-delà des
        // journaux qu'une archive d'événements transférés nomme), le journal lui-même n'a pas été lu.
        m.push(Manque::Absent(journal.to_string()));
        return m;
    }
    let lu = etats.iter().any(|j| j.principal && matches!(j.lecture, Lecture::Lu(_)));
    if !etats.iter().any(|j| j.principal) {
        // Seulement quelques événements de ce journal, mêlés à d'autres (une archive d'événements transférés) : le
        // journal lui-même n'est pas là.
        m.push(Manque::Absent(journal.to_string()));
    }
    for j in &etats {
        match &j.lecture {
            Lecture::Lu(manques) => m.extend(manques.iter().map(|x| Manque::Partiel(journal.to_string(), x.clone()))),
            Lecture::Absent if !lu => m.push(Manque::Absent(journal.to_string())),
            Lecture::Absent => {}
            Lecture::Refuse => m.push(Manque::Refuse(journal.to_string())),
            Lecture::Illisible(x) => m.push(Manque::Illisible(journal.to_string(), x.clone())),
        }
        if j.active == Some(false) {
            m.push(Manque::Desactive(journal.to_string()));
        }
    }
    if stat.non_verifies > 0 && !m.iter().any(|x| matches!(x, Manque::Partiel(..))) {
        // Le bilan de la source le dit déjà d'ordinaire (morceaux non vérifiés) : seulement s'il ne l'a pas dit.
        m.push(Manque::NonVerifies {
            journal: journal.to_string(),
            nombre: stat.non_verifies,
        });
    }
    // Les journaux qui écrivent sans cesse sur un ordinateur en marche : leur plus ancien événement après le début
    // demandé dit qu'il manque le début. Un journal calme (BITS, WMI) peut n'avoir simplement rien écrit avant.
    let actif = journal.eq_ignore_ascii_case("Security") || journal.eq_ignore_ascii_case("System");
    if lu && stat.evenements == 0 {
        m.push(if actif {
            Manque::Vide(journal.to_string())
        } else {
            Manque::VideCalme(journal.to_string())
        });
    }
    // Un journal qui écrit sans cesse et se tait depuis plus d'un jour quand d'autres écrivent encore.
    if let (true, Some(dernier), Some(recent)) = (actif, stat.dernier, plus_recent)
        && recent - dernier > chrono::Duration::days(1)
    {
        m.push(Manque::Muet {
            journal: journal.to_string(),
            depuis: dernier,
        });
    }
    if let (true, Some(depuis), Some(premier)) = (actif, options.depuis, stat.premier)
        && premier - depuis > chrono::Duration::days(1)
    {
        m.push(Manque::PeriodeCourte {
            journal: journal.to_string(),
            debut: premier,
        });
    }
    let mut uniques: Vec<Manque> = Vec::new();
    for x in m {
        if !uniques.contains(&x) {
            uniques.push(x);
        }
    }
    uniques
}

/// Ajoute un indice à la trouvaille de son objet (créée au besoin, sous la borne).
/// Fait place à une trouvaille de cette clé et de cette gravité : vrai si elle peut être gardée. À la borne, la
/// moins grave des gardées (la plus récente à gravité égale) laisse sa place à une plus grave ; sinon la nouvelle
/// est comptée au-delà. Une alerte critique ne disparaît ainsi jamais derrière des centaines d'informations.
fn faire_place(
    etat: &mut EtatRegle,
    bornes: &BornesMoteur,
    cle: &(usize, String, String),
    gravite: Gravite,
    nombre: u64,
) -> bool {
    if etat.trouvailles.contains_key(cle) || etat.trouvailles.len() < bornes.trouvailles {
        return true;
    }
    let victime = etat
        .trouvailles
        .iter()
        .min_by(|(ka, a), (kb, b)| {
            (a.gravite, std::cmp::Reverse(a.premier), *ka).cmp(&(b.gravite, std::cmp::Reverse(b.premier), *kb))
        })
        .map(|(k, t)| (k.clone(), t.gravite));
    let pire = |etat: &mut EtatRegle, g: Gravite| etat.au_dela_pire = Some(etat.au_dela_pire.map_or(g, |p| p.max(g)));
    match victime {
        Some((k, g)) if g < gravite => {
            if let Some(t) = etat.trouvailles.remove(&k) {
                etat.au_dela = etat.au_dela.saturating_add(t.nombre);
                pire(etat, t.gravite);
            }
            true
        }
        _ => {
            etat.au_dela = etat.au_dela.saturating_add(nombre);
            pire(etat, gravite);
            false
        }
    }
}

fn ajouter(
    etat: &mut EtatRegle,
    bornes: &BornesMoteur,
    volet: usize,
    ordinateur: &str,
    indice: Indice,
    e: &EvenementWindows,
) {
    let cle = (volet, couper(&ordinateur.to_lowercase()), couper(&indice.objet));
    if !faire_place(etat, bornes, &cle, indice.gravite, 1) {
        return;
    }
    let t = match etat.trouvailles.get_mut(&cle) {
        Some(t) => t,
        None => etat.trouvailles.entry(cle.clone()).or_insert_with(|| Trouvaille {
            volet,
            objet: cle.2.clone(),
            ordinateur: couper(ordinateur),
            gravite: indice.gravite,
            pourquoi: indice.pourquoi,
            details: Vec::new(),
            nombre: 0,
            verifies: 0,
            premier: None,
            dernier: None,
            reperes: Vec::new(),
            reserves: BTreeSet::new(),
            mise_en_route: indice.mise_en_route,
        }),
    };
    // Un seul de ses événements jugé seul suffit à ce que la trouvaille le soit ; un événement sans date ne se place
    // pas dans la mise en route.
    if indice.mise_en_route.is_none() || e.date.is_none() {
        t.mise_en_route = None;
    }
    let plus_ancien = t
        .reperes
        .first()
        .is_none_or(|p| rang(e.date, e.numero, e.verifie) < rang(p.date, p.numero, p.verifie));
    // La gravité la plus haute l'emporte, et avec elle son pourquoi ; à gravité égale, celui du plus ancien.
    if indice.gravite > t.gravite || (indice.gravite == t.gravite && plus_ancien) || t.nombre == 0 {
        if indice.gravite >= t.gravite {
            t.pourquoi = indice.pourquoi;
        }
        t.gravite = t.gravite.max(indice.gravite);
    }
    if plus_ancien || t.nombre == 0 {
        t.details = indice.details.into_iter().map(|(l, v)| (l, couper(&v))).collect();
    }
    t.nombre += 1;
    t.verifies += u64::from(e.verifie);
    if let Some(d) = e.date {
        t.premier = Some(t.premier.map_or(d, |p| p.min(d)));
        t.dernier = Some(t.dernier.map_or(d, |p| p.max(d)));
    }
    garder_repere(&mut t.reperes, repere(e), bornes.reperes);
}

/// Garde les `n` plus anciens repères, dans l'ordre.
fn garder_repere(reperes: &mut Vec<Repere>, r: Repere, n: usize) {
    let i = reperes.partition_point(|p| rang(p.date, p.numero, p.verifie) <= rang(r.date, r.numero, r.verifie));
    if i < n {
        reperes.insert(i, r);
        reperes.truncate(n);
    }
}

/// Les caractères gardés de chaque partie d'une clé de rafale (l'ordinateur, un compte, une adresse) : un vrai nom
/// en a moins ; des millions de comptes inventés de 64 Kio ne font pas grossir la mémoire d'autant.
const CLE_PARTIE_MAX: usize = 128;

/// Une valeur de clé de rafale comparable : un compte sans son domaine (« DOM\alice », « alice@dom » : « alice »,
/// le 4624 portant le nom canonique quand le 4625 porte ce qui a été tapé), une adresse IPv6 ramenée à son
/// réseau /64 (un attaquant en change à chaque essai dans le sien), en minuscules et coupée.
fn valeur_de_cle(champ: &str, v: &str) -> String {
    let bas = v.trim().to_lowercase();
    let v = if champ.ends_with("UserName") {
        let sans_domaine = bas.rsplit('\\').next().unwrap_or(&bas);
        sans_domaine.split('@').next().unwrap_or(sans_domaine).to_string()
    } else if champ == "IpAddress" {
        match bas.split('%').next().unwrap_or(&bas).parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(v6)) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    v4.to_string()
                } else {
                    let s = v6.segments();
                    format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
                }
            }
            Ok(ip) => ip.to_string(),
            Err(_) => bas,
        }
    } else {
        bas
    };
    v.chars().take(CLE_PARTIE_MAX).collect()
}

/// La clé de regroupement d'un événement : l'ordinateur et les champs `par` (`valeur_de_cle`). Rien si un champ est
/// vide, « - », ou une adresse de boucle (un échec à l'écran de l'ordinateur porte 127.0.0.1 : regroupé par
/// compte, pas par adresse).
fn cle_rafale(par: &[&str], e: &EvenementWindows) -> Option<String> {
    let mut cle: String = e
        .ordinateur
        .trim()
        .to_lowercase()
        .chars()
        .take(CLE_PARTIE_MAX)
        .collect();
    for champ in par {
        let v = e.champ(champ)?.trim();
        if v.is_empty() || v == "-" || v == "127.0.0.1" || v == "::1" {
            return None;
        }
        let v = valeur_de_cle(champ, v);
        if v.is_empty() {
            return None;
        }
        cle.push('\u{1f}');
        cle.push_str(&v);
    }
    Some(cle)
}

fn noter_rafale(
    etat: &mut EtatRegle,
    bornes: &BornesMoteur,
    volet: usize,
    par: &[&str],
    e: &EvenementWindows,
    est_b: bool,
) {
    let raf = etat.rafales.entry(volet).or_default();
    let Some(cle) = cle_rafale(par, e) else {
        return;
    };
    let Some(date) = e.date else {
        raf.sans_date += 1;
        return;
    };
    let indice = match raf.cles.get(&cle) {
        Some(&k) => k,
        // Une réussite d'une clé sans échec encore vu ne crée pas de clé au-delà de la moitié de la borne : des
        // millions de connexions ordinaires ne prennent pas la place des clés qui ont des échecs.
        None if raf.cles.len() < bornes.cles && (!est_b || raf.cles.len() < bornes.cles / 2) => {
            let k = u32::try_from(raf.cles.len()).unwrap_or(u32::MAX);
            raf.cles.insert(cle, k);
            raf.par_cle.push((Vec::new(), Vec::new(), 0));
            k
        }
        None => {
            // Une réussite laissée sans clé n'est une perte que si cette clé a des échecs : on ne le saura pas, la
            // borne est dite.
            raf.perdus += 1;
            return;
        }
    };
    let marque = Marque {
        date,
        numero: e.numero.unwrap_or(u64::MAX),
        verifie: e.verifie,
    };
    let entree = &mut raf.par_cle[indice as usize];
    if est_b {
        if raf.gardes_b >= bornes.dates {
            entree.2 += 1;
            return;
        }
        entree.1.push(marque);
        raf.gardes_b += 1;
        return;
    }
    if raf.gardes >= bornes.dates {
        raf.perdus += 1;
        return;
    }
    entree.0.push(marque);
    raf.gardes += 1;
    let exemple = raf.exemples.get(&indice);
    if exemple.is_none_or(|(x, _, _)| (marque.date, marque.numero, !marque.verifie) < (x.date, x.numero, !x.verifie)) {
        let details = details_rafale(par, e);
        raf.exemples.insert(indice, (marque, repere(e), details));
    }
}

/// Les détails d'une rafale : les champs de sa clé, et le type de connexion s'il y en a un.
fn details_rafale(par: &[&str], e: &EvenementWindows) -> Vec<(Libelle, String)> {
    let mut d: Vec<(Libelle, String)> = par
        .iter()
        .filter_map(|c| {
            let l = match *c {
                "IpAddress" => Libelle::Adresse,
                _ => Libelle::Compte,
            };
            e.champ(c).map(|v| (l, v.trim().chars().take(CLE_PARTIE_MAX).collect()))
        })
        .collect();
    if let Some(t) = e.champ("LogonType") {
        d.push((Libelle::TypeConnexion, t.trim().chars().take(CLE_PARTIE_MAX).collect()));
    }
    d
}

/// Les indices des dates (triées) qui tombent dans une rafale : au moins `nombre` dans `fenetre` secondes.
fn dans_rafale(dates: &[Marque], nombre: usize, fenetre: i64) -> Vec<bool> {
    let mut couvert = vec![false; dates.len()];
    if nombre == 0 {
        return couvert;
    }
    let mut i = 0;
    let mut marque_jusqua = 0usize;
    for j in 0..dates.len() {
        while (dates[j].date - dates[i].date).num_seconds() > fenetre {
            i += 1;
        }
        if j + 1 - i >= nombre {
            for c in couvert.iter_mut().take(j + 1).skip(i.max(marque_jusqua)) {
                *c = true;
            }
            marque_jusqua = j + 1;
        }
    }
    couvert
}

/// Une fenêtre de rafale d'au moins une heure : une rafale « lente ».
const LENTE: i64 = 3600;

/// Les rafales d'échecs (A, triés) d'une clé, pour juger chaque réussite en temps logarithmique : où chaque rafale
/// de `nombre` échecs consécutifs en `fenetre` secondes s'achève, et, jusque-là, le plus tardif de leurs débuts.
/// Sans cela, une réussite se jugeait en parcourant tous les échecs des minutes d'avant : cent mille échecs et cent
/// mille réussites d'une même clé faisaient des milliards de comparaisons.
struct IndexRafales<'a> {
    a: &'a [Marque],
    fins: Vec<DateTime<Utc>>,
    debut_max: Vec<DateTime<Utc>>,
}

impl<'a> IndexRafales<'a> {
    fn de(a: &'a [Marque], nombre: usize, fenetre: i64) -> Self {
        let mut fins = Vec::new();
        let mut debut_max: Vec<DateTime<Utc>> = Vec::new();
        if nombre > 0 {
            for j in nombre - 1..a.len() {
                let debut = a[j + 1 - nombre].date;
                if (a[j].date - debut).num_seconds() <= fenetre {
                    fins.push(a[j].date);
                    let m = debut_max.last().map_or(debut, |&m| m.max(debut));
                    debut_max.push(m);
                }
            }
        }
        Self { a, fins, debut_max }
    }

    /// Une réussite à `s` suit-elle une rafale : le dernier échec au plus `delai` secondes avant elle, et une
    /// rafale tout entière dans les `fenetre + delai` secondes d'avant ?
    fn suit(&self, s: DateTime<Utc>, fenetre: i64, delai: i64) -> bool {
        let fin = self.a.partition_point(|d| d.date <= s);
        let Some(dernier) = fin.checked_sub(1).map(|i| self.a[i].date) else {
            return false;
        };
        if (s - dernier).num_seconds() > delai {
            return false;
        }
        let k = self.fins.partition_point(|&f| f <= s);
        k > 0 && (s - self.debut_max[k - 1]).num_seconds() <= fenetre.saturating_add(delai)
    }
}

fn juger_rafales(
    etat: &mut EtatRegle,
    bornes: &BornesMoteur,
    v: usize,
    volet: &Volet,
    raf: Rafales,
    manques: &mut Vec<Manque>,
) {
    let forme = volet.forme;
    // Les réussites laissées faute de place ne comptent que pour les clés qui ont des échecs.
    let perdus = raf.perdus.saturating_add(
        raf.par_cle
            .iter()
            .filter(|(a, _, _)| !a.is_empty())
            .map(|(_, _, p)| *p)
            .sum::<u64>(),
    );
    if perdus > 0 {
        manques.push(Manque::Bornes(perdus));
    }
    if raf.sans_date > 0 {
        manques.push(Manque::SansDate(raf.sans_date));
    }
    let (nombre, fenetre, delai, gravite, pourquoi) = match forme {
        Forme::Rafale {
            nombre,
            fenetre,
            gravite,
            pourquoi,
            ..
        } => (nombre, fenetre, None, gravite, pourquoi),
        Forme::Apres {
            nombre,
            fenetre,
            delai,
            gravite,
            pourquoi,
            ..
        } => (nombre, fenetre, Some(delai), gravite, pourquoi),
        _ => return,
    };
    // Une rafale sur des heures (l'attaquant patient) se dit « lente » ; celle qu'une rafale rapide de la même clé
    // dit déjà n'est pas dite deux fois.
    let (etiquette, b_id) = match forme {
        Forme::Apres { b_ids, .. } => ("apres", b_ids.first().copied().unwrap_or_default()),
        Forme::Rafale { fenetre, .. } if fenetre >= LENTE => ("lent", 0),
        _ => ("rafale", 0),
    };
    let mut noms: Vec<String> = vec![String::new(); raf.par_cle.len()];
    for (cle, &i) in &raf.cles {
        if let Some(n) = noms.get_mut(i as usize) {
            n.clone_from(cle);
        }
    }
    let mut exemples = raf.exemples;
    for (i, (cle, (mut a, mut b, _))) in noms.into_iter().zip(raf.par_cle).enumerate() {
        let tri = |x: &Marque, y: &Marque| (x.date, x.numero, !x.verifie).cmp(&(y.date, y.numero, !y.verifie));
        a.sort_by(tri);
        b.sort_by(tri);
        // Les événements à l'appui : ceux des rafales, ou les réussites qui en suivent une.
        let appui: Vec<Marque> = match delai {
            None => {
                let couvert = dans_rafale(&a, nombre, fenetre);
                a.iter().zip(couvert).filter(|(_, c)| *c).map(|(d, _)| *d).collect()
            }
            Some(delai) => {
                let index = IndexRafales::de(&a, nombre, fenetre);
                b.iter()
                    .filter(|s| index.suit(s.date, fenetre, delai))
                    .copied()
                    .collect()
            }
        };
        if appui.is_empty() {
            continue;
        }
        // Sans les événements des morceaux abîmés, la rafale tient-elle encore ?
        let a_verifies: Vec<Marque> = a.iter().filter(|d| d.verifie).copied().collect();
        let tient = match delai {
            None => dans_rafale(&a_verifies, nombre, fenetre).contains(&true),
            Some(delai) => {
                let index = IndexRafales::de(&a_verifies, nombre, fenetre);
                b.iter()
                    .filter(|s| s.verifie)
                    .any(|s| index.suit(s.date, fenetre, delai))
            }
        };
        let ordinateur = cle.split('\u{1f}').next().unwrap_or_default().to_string();
        let mut objet: String = cle.split('\u{1f}').skip(1).collect::<Vec<_>>().join("|");
        if objet.is_empty() {
            // Regroupé par ordinateur seulement.
            objet = "*".to_string();
        }
        // La forme dans l'objet : déclarer normale une rafale d'échecs d'un compte ne fait pas taire la réussite
        // qui suivrait une rafale.
        if etiquette == "lent" {
            let rapide = format!("rafale:{objet}");
            if etat
                .trouvailles
                .keys()
                .any(|(_, o, x)| *o == ordinateur && *x == rapide)
            {
                continue;
            }
        }
        let objet = format!("{etiquette}:{objet}");
        let (details, mut reperes) = match u32::try_from(i).ok().and_then(|i| exemples.remove(&i)) {
            Some((_, r, d)) => (d, vec![r]),
            None => (Vec::new(), Vec::new()),
        };
        if delai.is_some()
            && let Some(premiere) = appui.first()
        {
            // La réussite qui fonde l'alerte, à retrouver par son numéro.
            reperes.push(Repere {
                journal: volet.journal.to_string(),
                id: b_id,
                date: Some(premiere.date),
                numero: (premiere.numero != u64::MAX).then_some(premiere.numero),
                verifie: premiere.verifie,
                fichier: None,
            });
        }
        let cle_t = (v, ordinateur.clone(), couper(&objet));
        if !faire_place(etat, bornes, &cle_t, gravite, appui.len() as u64) {
            continue;
        }
        let mut reserves = BTreeSet::new();
        if !tient {
            reserves.insert(Reserve::MorceauAbime);
        }
        etat.trouvailles.insert(
            cle_t,
            Trouvaille {
                volet: v,
                objet: couper(&objet),
                ordinateur,
                gravite,
                pourquoi,
                details,
                nombre: appui.len() as u64,
                // Une rafale qui ne tient pas sans eux n'a pas d'appui vérifié.
                verifies: if tient {
                    appui.iter().filter(|d| d.verifie).count() as u64
                } else {
                    0
                },
                premier: appui.first().map(|d| d.date),
                dernier: appui.last().map(|d| d.date),
                reperes,
                reserves,
                mise_en_route: None,
            },
        );
    }
}

/// Les trous des suites de numéros, jugés : `Retires` (des enregistrements ôtés d'un morceau intact) est un
/// effacement partiel ; `Absents`, sauf si un arrêt inattendu tombe à côté ; `CopieAChaud` et `AvantExport`, des
/// réserves dites ; `Illisible`, ce que la lecture a perdu, non vérifié.
fn trous(
    etat: &mut EtatRegle,
    bornes: &BornesMoteur,
    v: usize,
    journaux: &[EtatJournal],
    arrets: &[(DateTime<Utc>, String)],
    manques: &mut Vec<Manque>,
) {
    for j in journaux {
        for s in &j.suites {
            let (journal, ordinateur) = match &s.numerotation {
                Numerotation::Journal => (j.nom.clone(), String::new()),
                Numerotation::Origine { ordinateur, journal } => (journal.clone(), ordinateur.clone()),
            };
            let mut illisibles = 0u64;
            for t in &s.trous {
                // L'arrêt se note au démarrage qui suit, tout près du premier enregistrement d'après le trou : un
                // arrêt au milieu d'un long trou n'excuse pas ce qui manque avant lui.
                // Et seulement un trou de la taille de ce qu'un arrêt peut perdre (ce que Windows gardait en mémoire,
                // quelques centaines d'enregistrements) : un arrêt n'excuse pas des jours retirés. L'arrêt doit venir
                // du même ordinateur quand la suite le nomme.
                let explique = t.nombre() <= PERTE_ARRET_MAX
                    && t.apres.is_some_and(|apres| {
                        arrets.iter().any(|(a, ordi)| {
                            (apres - *a).num_seconds().abs() <= MARGE_ARRET
                                && t.avant.is_none_or(|avant| (*a - avant).num_seconds() >= -MARGE_ARRET)
                                && (ordinateur.is_empty() || ordinateur.eq_ignore_ascii_case(ordi))
                        })
                    });
                let (gravite, pourquoi, reserve) = match t.nature {
                    Nature::Illisible => {
                        illisibles = illisibles.saturating_add(t.nombre());
                        continue;
                    }
                    Nature::Retires => (
                        Gravite::Critique,
                        (
                            "des enregistrements ont été retirés un à un d'un morceau intact du journal (effacement partiel des traces)",
                            "records were removed one by one from an intact chunk of the log (partial clearing of traces)",
                        ),
                        None,
                    ),
                    Nature::Absents if explique => (
                        Gravite::Info,
                        (
                            "des enregistrements manquent, au moment d'un arrêt inattendu de l'ordinateur, qui les explique sans effacement",
                            "records are missing, at the time of an unexpected shutdown of the computer, which explains them without clearing",
                        ),
                        Some(Reserve::ArretInattendu),
                    ),
                    Nature::Absents => (
                        Gravite::Alerte,
                        (
                            "des enregistrements manquent dans la suite des numéros, sans arrêt inattendu pour l'expliquer : retirés, ou fichier copié incomplet",
                            "records are missing from the numbering, with no unexpected shutdown to explain it: removed, or file copied incomplete",
                        ),
                        None,
                    ),
                    Nature::CopieAChaud => (
                        Gravite::Info,
                        (
                            "des enregistrements manquent dans un fichier copié pendant que Windows écrivait : effacement possible, non concluant",
                            "records are missing in a file copied while Windows was writing: possible clearing, not conclusive",
                        ),
                        Some(Reserve::CopieAChaud),
                    ),
                    Nature::AvantExport => (
                        Gravite::Info,
                        (
                            "des numéros d'origine manquent dans un fichier exporté : effacés avant l'export, ou laissés de côté par son filtre",
                            "original record numbers are missing in an exported file: cleared before the export, or left out by its filter",
                        ),
                        Some(Reserve::AvantExport),
                    ),
                };
                let objet = format!("{}:{}-{}", journal.to_lowercase(), t.de, t.a);
                let cle = (v, couper(&ordinateur.to_lowercase()), couper(&objet));
                if !faire_place(etat, bornes, &cle, gravite, 1) {
                    continue;
                }
                let mut reserves = BTreeSet::new();
                reserves.extend(reserve);
                etat.trouvailles.insert(
                    cle,
                    Trouvaille {
                        volet: v,
                        objet: couper(&objet),
                        ordinateur: couper(&ordinateur),
                        gravite,
                        pourquoi,
                        details: vec![
                            (Libelle::Journal, couper(&journal)),
                            (Libelle::Numeros, format!("{}-{}", t.de, t.a)),
                        ],
                        nombre: t.nombre(),
                        // Un trou se juge sur les numéros qui l'entourent, vérifiés par `trous::juger` : il
                        // n'existe que si un morceau vérifié le réclame ou si la suite vérifiée le borde.
                        verifies: t.nombre(),
                        premier: t.avant,
                        dernier: t.apres,
                        reperes: Vec::new(),
                        reserves,
                        mise_en_route: None,
                    },
                );
            }
            if illisibles > 0 {
                manques.push(Manque::TrousIllisibles {
                    journal: journal.clone(),
                    nombre: illisibles,
                });
            }
            if s.trous_au_dela > 0 {
                manques.push(Manque::TrousAuDela {
                    journal: journal.clone(),
                    nombre: s.trous_au_dela,
                });
            }
            if s.non_verifies > 0 {
                manques.push(Manque::SuiteNonProuvee {
                    journal: journal.clone(),
                    nombre: s.non_verifies,
                });
            }
            if s.doublons > 0 || s.incoherences > 0 {
                let objet = format!("{}:incoherent", journal.to_lowercase());
                let cle = (v, couper(&ordinateur.to_lowercase()), couper(&objet));
                if faire_place(etat, bornes, &cle, Gravite::Alerte, 1) {
                    etat.trouvailles.insert(
                        cle,
                        Trouvaille {
                            volet: v,
                            objet: couper(&objet),
                            ordinateur: couper(&ordinateur),
                            gravite: Gravite::Alerte,
                            pourquoi: (
                                "la numérotation du journal est incohérente (numéros en double, en-tête qui ne suit pas) : un fichier réécrit ou assemblé",
                                "the log numbering is inconsistent (duplicate numbers, header that does not match): a rewritten or assembled file",
                            ),
                            details: vec![(Libelle::Journal, couper(&journal))],
                            nombre: s.doublons.saturating_add(s.incoherences),
                            verifies: s.doublons.saturating_add(s.incoherences),
                            premier: None,
                            dernier: None,
                            reperes: Vec::new(),
                            reserves: BTreeSet::new(),
                            mise_en_route: None,
                        },
                    );
                }
            }
        }
    }
}
