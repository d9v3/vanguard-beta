//! Les sceaux de l'état de Vanguard : les fichiers qu'il garde sur cet ordinateur et qui décident de ce qu'il dit (les
//! alertes déclarées normales, la référence des fichiers critiques et les changements déjà signalés, les connexions
//! à des botnets déjà signalées, la plus haute version signée déjà vue, l'état de la machine au dernier passage de
//! la surveillance, les valeurs d'avant des réglages d'Optimiser, les alertes de la surveillance déclarées normales,
//! l'heure du dernier regard sur les téléchargements, les menaces que le blocage n'a pas pu bloquer déjà signalées, le
//! relevé des corrections et des blocages que « Tout remettre comme avant » rejoue).
//! Un programme qui tourne sous le compte pouvait réécrire l'un d'eux pour faire
//! taire sa propre alerte, sans que rien ne le dise. Chaque écriture de Vanguard note donc l'empreinte BLAKE3 du
//! fichier dans `sceaux.json` ; une lecture qui ne la retrouve pas rend le fichier « falsifié », que chaque lecteur
//! traite comme s'il ne valait rien (jamais comme un feu vert), et le bilan l'annonce (COM-ETA-001).
//!
//! Comme la chaîne de l'historique : barrière, pas coffre. Qui connaît ce mécanisme peut aussi réécrire les sceaux ;
//! seule la séparation des comptes ferait mieux. Les fichiers d'une version d'avant, qui ne scellait rien, sont
//! scellés tels quels la première fois (confiance au premier usage) ; ce départ est daté dans les sceaux. Effacer
//! `sceaux.json` refait ce premier usage : les fichiers alors acceptés tels quels restent marqués « adoptés » (lus
//! `Adopte`) jusqu'à ce que Vanguard les réécrive, et le bilan le dit (COM-ETA-001), au lieu de les croire en
//! silence. Qui efface les sceaux puis en réécrit de valables n'est toujours pas vu.
//!
//! « Jamais écrit » n'est pas « disparu » : des sceaux refaits alors qu'une version qui scelle avait déjà servi sur
//! cet ordinateur (son `sceaux.verrou` est resté), ou illisibles, ne savent plus quels fichiers existaient. Un fichier protégé absent se lit alors `Inconnu`, que
//! chaque lecteur traite comme un état vide (tout est redit), jamais comme un premier passage muet ; et le bilan dit
//! que les sceaux ont été refaits. Effacer d'un coup les sceaux et l'état de la machine ne fait donc plus taire la
//! passe suivante.
//!
//! Un seul juge pour tous les lecteurs (`juge`, sur le modèle de `parametres::charger_juge`) : seul ce que Vanguard a
//! écrit, ou ce qu'il a repris tel quel d'une version d'avant lors de sa mise à jour, est cru ; un fichier changé,
//! effacé, ou accepté tel quel après des sceaux refaits ne vaut jamais un feu vert (aucune défense coupée, aucune
//! alerte tue, aucun accord donné). Depuis le lot S2 : aussi la liste des fichiers-pièges, les ports bloqués, le carnet
//! des appareils de cet ordinateur, les références de la clé VANGUARD, l'état de l'entretien, la note de la sauvegarde
//! et la dernière passe de la surveillance. Un test relit le code pour qu'aucun fichier du dossier de données ne soit
//! lu sans lui (`modele::inventaire`, T14).
//!
//! Un fichier d'état n'est lu que s'il est un simple fichier de taille raisonnable (`socle::lire_ordinaire`) : un tube
//! nommé posé à sa place figeait la surveillance pour toujours. En root, les sceaux ne s'écrivent que dans un dossier
//! à root (`socle::ecriture_sure`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::machine::Constat;
use crate::risk::Niveau;
use crate::ui::*;

/// Les alertes déclarées normales (`apprentissage`).
pub(crate) const APPRIS: &str = "appris.json";
/// La référence des fichiers critiques (`protection::integrite`).
pub(crate) const INTEGRITE: &str = "integrite.json";
/// Les connexions à des botnets déjà notifiées par la surveillance (`protection::sortantes`).
pub(crate) const BOTNETS: &str = "surveillance-botnets.txt";
/// La plus haute version signée déjà vue sur GitHub (`mise_a_jour::github`).
pub(crate) const VERSIONS: &str = "versions/plus-haute-vue.txt";
/// L'état de la machine au passage d'avant de la surveillance (`reseau::surveillance`) : un programme qui y écrit
/// d'avance sa propre alerte, ou qui l'efface, ne la ferait jamais notifier.
pub(crate) const MACHINE: &str = "surveillance-machine.json";
/// Les changements de fichiers critiques déjà notifiés par la surveillance (`protection::integrite`) : un programme
/// qui y écrit d'avance le ~/.bashrc qu'il vient de changer tairait la notification.
pub(crate) const INTEGRITE_SIGNALE: &str = "integrite-signale.json";

/// L'état du mode Wi-Fi public (`reseau::wifi_public`) : ce qu'il a changé et les valeurs d'avant, remises en
/// administrateur à l'extinction. Un programme qui y écrirait une valeur d'avant à lui la ferait poser avec les droits
/// d'administrateur.
pub(crate) const WIFI_PUBLIC: &str = "wifi-public.json";

/// Les valeurs d'avant des réglages d'Optimiser, des corrections du bilan et des réglages pour jouer (`optimiser`,
/// `optimiser::annulables`), remises en administrateur pour annuler : un programme
/// qui y écrirait une valeur à lui la ferait poser avec tous les droits.
pub(crate) const REGLAGES: &str = "reglages.json";

/// Les alertes du veilleur, de la surveillance et du blocage déclarées normales (`protection::normales`) : un
/// programme qui s'y ajouterait ferait taire sa propre alerte.
pub(crate) const NORMALES: &str = "normales.json";

/// La protection en temps réel coupée (`protection::temps_reel`) : un programme qui l'écrirait couperait la
/// surveillance.
pub(crate) const TEMPS_REEL: &str = "temps-reel.json";
/// Le dernier rappel de la coupure (`protection::temps_reel`) : posé d'avance, il taisait la notification.
pub(crate) const TEMPS_REEL_RAPPEL: &str = "temps-reel-rappel.txt";
/// Ce que l'audit du réseau a déjà signalé (`reseau::surveillance`) : une redirection UPnP posée d'avance ne se
/// notifiait plus.
pub(crate) const AUDIT: &str = "surveillance-audit.json";
/// Les sites dangereux déjà signalés (`protection::sortantes`).
pub(crate) const SITES: &str = "surveillance-sites.txt";
/// La passerelle déjà vue (`reseau::surveillance`).
pub(crate) const PASSERELLE: &str = "surveillance-passerelle.json";
/// L'heure du dernier regard de la surveillance sur Téléchargements (`protection::telechargement`) : un « depuis »
/// posé dans le futur taisait tout fichier arrivé depuis.
pub(crate) const TELECHARGEMENTS: &str = "surveillance-telechargements.json";
/// Les menaces que le blocage automatique n'a pas pu bloquer, déjà signalées (`protection::blocage`) : une clé de
/// menace ajoutée d'avance taisait « Vanguard n'a pas pu bloquer ».
pub(crate) const BLOCAGE_SIGNALEES: &str = "blocage-non-bloquees.txt";
/// Les logiciels installés déjà vus (`machine::logiciels_vus`) : un programme qui s'y ajouterait d'avance ne serait
/// jamais signalé comme arrivé.
pub(crate) const LOGICIELS: &str = "logiciels-vus.json";
/// La clé principale des versions révoquée par la clé de secours (`mise_a_jour::github`).
pub(crate) const REVOCATION: &str = "versions/principale-revoquee.txt";

/// Les comptes administrateurs déjà vus (`machine::administrateurs`) : effacés, ou un compte inscrit d'avance, et
/// « Nouveau compte administrateur cette semaine » se taisait.
pub(crate) const ADMINISTRATEURS: &str = "administrateurs.json";
/// Les appareils Bluetooth déjà vus (`machine::bluetooth`).
pub(crate) const BLUETOOTH: &str = "bluetooth.json";
/// Les clés VANGUARD que cet ordinateur reconnaît (`protection::cles_connues`) : un jeton inscrit d'avance faisait
/// d'une clé piégée une clé connue.
pub(crate) const CLES_CONNUES: &str = "cles-connues.json";

/// L'état écrit par le service du veilleur (`machine::linux::veilleur`) : forgé, un faux veilleur passait pour vivant,
/// compteurs à zéro.
pub(crate) const VEILLEUR_ETAT: &str = "veilleur-etat.json";

/// La liste des fichiers-pièges posés (`protection::pieges`) : vidée ou effacée, les pièges n'étaient plus vérifiés ;
/// une empreinte réécrite faisait passer un piège chiffré pour intact.
pub(crate) const PIEGES: &str = "pieges.json";
/// Les ports que Vanguard a bloqués en entrée (`machine`) : un port inscrit d'avance taisait un port exposé, ou un
/// serveur d'IA ouvert.
pub(crate) const PORTS_BLOQUES: &str = "ports-bloques.txt";
/// Le carnet des appareils de cet ordinateur (`reseau`), en clair : un appareil inscrit d'avance n'était jamais dit
/// « Nouvel appareil ».
pub(crate) const APPAREILS: &str = "appareils.json";
/// L'unique référence de la clé VANGUARD des 0.59 (`protection::manifeste`).
pub(crate) const MANIFESTE_CLE: &str = "manifeste-cle.json";
/// Les références de chaque clé VANGUARD (`protection::manifeste`), une par identifiant de volume : réécrite avec
/// l'empreinte d'un fichier planté sur la clé, elle disait « clé intacte ».
pub(crate) const MANIFESTES_CLE: &str = "manifestes-cle";
/// L'état de l'entretien du mois d'avant (`entretien`) : une alerte inscrite d'avance n'était jamais dite nouvelle.
pub(crate) const ENTRETIEN: &str = "entretien.json";
/// La note de la sauvegarde automatique mise en place (`sauvegarde`) : forgée, son annulation coupait Time Machine ou
/// remettait des réglages de Déjà Dup choisis par un autre programme.
pub(crate) const SAUVEGARDE: &str = "sauvegarde.json";
/// La dernière passe de la surveillance (`reseau::tableau`) : forgée, le tableau la disait passée il y a cinq
/// minutes alors qu'elle était coupée.
pub(crate) const SURVEILLANCE_PASSE: &str = "surveillance-passe.txt";

/// Au-delà, ce n'est pas un fichier d'état de Vanguard (le plus gros fait quelques dizaines de Kio) : il n'est pas
/// chargé.
const TAILLE_MAX: u64 = 4 << 20;

/// Les fichiers protégés : ceux que l'inventaire des fichiers d'état dit scellés (`modele::inventaire`). Un fichier
/// d'état s'ajoute là, avec sa constante ici : on ne peut plus en sceller un sans l'inventorier.
fn proteges() -> impl Iterator<Item = &'static str> {
    crate::modele::inventaire::scelles()
}

/// Les fichiers protégés après le premier sceau : une version d'avant les écrivait déjà sans sceau, et des sceaux
/// existants les feraient passer pour falsifiés à la mise à jour. La première fois que des sceaux les rencontrent,
/// ils sont acceptés tels quels (« adoptés », dit au bilan comme tout premier usage), puis jugés comme les autres.
const TARDIFS: &[&str] = &[
    REGLAGES,
    NORMALES,
    TEMPS_REEL,
    TEMPS_REEL_RAPPEL,
    AUDIT,
    SITES,
    PASSERELLE,
    TELECHARGEMENTS,
    BLOCAGE_SIGNALEES,
    // Les résultats des outils, écrits sans sceau jusqu'à la 0.85.
    crate::modele::resultat::FICHIERS[0],
    crate::modele::resultat::FICHIERS[1],
    crate::modele::resultat::FICHIERS[2],
    // Écrits sans sceau jusqu'à la 0.86.
    ADMINISTRATEURS,
    BLUETOOTH,
    CLES_CONNUES,
    crate::changements::RELEVE,
    crate::parametres::PARAMETRES,
    crate::protection::blocage::parametres::BLOCAGE,
    // Jusqu'ici, ceux que connaissaient les versions de la forme 0 (`TARDIFS_D_AVANT`).
    // Écrits sans sceau jusqu'à la 0.87 : adoptés une fois, mais jamais un feu vert (`plugins::reglages::lire_juge`).
    crate::plugins::reglages::SCELLE,
    crate::plugins::APPROUVES_SCELLE,
    // Écrit sans sceau par le veilleur jusqu'à la 0.87 (Linux seulement, mais le nom est le même partout).
    VEILLEUR_ETAT,
    // Écrits sans sceau jusqu'à la 0.87 : adoptés une fois à la mise à jour, jamais un feu vert après des sceaux
    // refaits (`juge`).
    PIEGES,
    PORTS_BLOQUES,
    APPAREILS,
    MANIFESTE_CLE,
    ENTRETIEN,
    SAUVEGARDE,
    SURVEILLANCE_PASSE,
];

/// Les premiers `TARDIFS`, ceux que connaissaient les versions de la forme 0 (jusqu'à la 0.87) : les seuls noms que
/// leurs sceaux ont pu mettre dans leurs `vus`.
const TARDIFS_D_AVANT: usize = 18;

/// Les dossiers dont chaque fichier est protégé tard, sous un nom que le code ne connaît pas d'avance (la référence de
/// chaque clé VANGUARD, nommée par l'identifiant de son volume) : comme `TARDIFS`, ce qu'une version d'avant y a
/// écrit est adopté une fois, puis un fichier posé sans sceau y est falsifié.
const TARDIFS_DOSSIERS: &[&str] = &[MANIFESTES_CLE];

/// Les fichiers déjà là dans les dossiers de `TARDIFS_DOSSIERS` (« `manifestes-cle/<id>.json` »), de simples fichiers
/// seulement.
fn presents_tardifs(dossier: &Path, sous: &str) -> Vec<String> {
    let Ok(lus) = std::fs::read_dir(dossier.join(sous)) else {
        return Vec::new();
    };
    let mut noms: Vec<String> = lus
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| Path::new(n).extension().is_some_and(|x| x == "json"))
        .map(|n| format!("{sous}/{n}"))
        .collect();
    noms.sort();
    noms
}

const REGISTRE: &str = "sceaux.json";
const VERROU: &str = "sceaux.verrou";

/// Les sceaux : depuis quand (AAAA-MM-JJ), l'empreinte de chaque fichier tel que Vanguard l'a écrit, et ceux qui
/// ont été scellés tels quels au premier usage, sans que Vanguard les ait écrits depuis.
#[derive(Serialize, Deserialize, Default, Clone)]
struct Registre {
    /// La forme de ces sceaux (`FORMAT`) : 0 dans ceux d'une version d'avant le lot S2c, qui ne savait pas distinguer
    /// un fichier repris d'une mise à jour d'un fichier accepté au premier usage.
    #[serde(default)]
    format: u32,
    depuis: String,
    fichiers: BTreeMap<String, String>,
    #[serde(default)]
    adoptes: BTreeSet<String>,
    /// La version du format de chaque fichier tel que Vanguard l'a écrit (`modele::inventaire`) : notée ici et non
    /// dans le fichier, qui garde sa forme (l'historique reste un tableau). Absente des sceaux d'avant.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    versions: BTreeMap<String, u16>,
    /// Les fichiers protégés tard (`TARDIFS`) que ces sceaux ont déjà rencontrés : passé ce premier regard, un tel
    /// fichier posé sans sceau est falsifié, comme les autres.
    #[serde(default)]
    vus: BTreeSet<String>,
    /// Les sceaux ont été refaits (effacés ou illisibles) alors que Vanguard avait déjà servi ici.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    refaits: bool,
    /// Les fichiers protégés absents quand les sceaux ont été refaits : ont-ils existé ? On ne le sait plus, jusqu'à
    /// ce que Vanguard les écrive ou les oublie lui-même.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    inconnus: BTreeSet<String>,
    /// Les fichiers adoptés parce qu'une mise à jour connue les a repris (`rattraper_si` : des sceaux d'une forme
    /// d'avant qui ne les protégeaient pas encore) : ils viennent de la version d'avant, et se croient même si les
    /// sceaux ont été refaits un jour. Toute autre adoption (premier usage, témoins effacés) ne se croit pas.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    repris: BTreeSet<String>,
    /// Le jour (AAAA-MM-JJ) où des sceaux réécrits par une version plus ancienne de Vanguard ont été retrouvés ici,
    /// après cette forme-ci (`rattraper_si`) : rien n'en a été repris, et le bilan le dit un mois.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ancienne: Option<String>,
    /// Le jour (AAAA-MM-JJ) où des sceaux d'une forme d'avant ont été retrouvés sans aucune trace du journal des
    /// événements (`Avant::SansJournal`) : ce qui était là a été adopté sans être repris, et le bilan le dit un mois.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sans_journal: Option<String>,
}

/// La forme des sceaux écrits par ce programme. Un fichier de `TARDIFS` absent des `vus` de sceaux de cette forme n'a
/// pas pu être repris d'une mise à jour (cette forme le connaissait déjà) : posé sans sceau, il est falsifié.
pub(crate) const FORMAT: u32 = 2;

/// Ce que Vanguard retrouve d'un de ses fichiers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lecture {
    Absent,
    /// Tel que Vanguard l'a écrit.
    Intact(Vec<u8>),
    /// Scellé tel quel au premier usage, sans sceau d'avant (une version d'avant les sceaux, ou `sceaux.json`
    /// effacé) et pas réécrit depuis par Vanguard : rien ne prouve qu'il n'a pas été changé juste avant.
    Adopte(Vec<u8>),
    /// Changé hors de Vanguard : le contenu actuel, ou `None` s'il a été supprimé.
    Falsifie(Option<Vec<u8>>),
    /// Là, mais il ne se lit pas (droits, dossier, tube ou lien à sa place, trop gros) : le pourquoi.
    Illisible(String),
    /// Absent, mais les sceaux ont été refaits (ou ne se lisent plus) : peut-être effacé par un autre programme.
    /// Jamais un premier passage : chaque lecteur le traite comme un état vide, où rien n'est tu.
    Inconnu,
}

/// L'empreinte d'un fichier d'état : son nom en fait partie, un sceau ne vaut pas pour un autre fichier.
fn empreinte(nom: &str, octets: &[u8]) -> String {
    let mut h = blake3::Hasher::new_derive_key("vanguard sceau 1");
    h.update(nom.as_bytes());
    h.update(&[0]);
    h.update(octets);
    h.finalize().to_hex().to_string()
}

/// Le verrou des sceaux : la surveillance horaire, le veilleur et le menu écrivent chacun leurs fichiers, et un
/// lecteur qui passerait entre l'écriture d'un fichier et celle de son sceau le croirait falsifié. Tenu quelques
/// millisecondes d'ordinaire.
///
/// Un écrivain n'avance jamais sans lui (`ecrire_dans`, `effacer_dans`) : deux Vanguard qui réécrivent le registre
/// en même temps, l'un efface le sceau que l'autre vient de poser, et ce fichier (la tête du journal des événements
/// comprise) se lisait ensuite falsifié. Il attendait deux secondes puis passait ; un Windows lent, ou dont
/// l'antivirus analyse chaque fichier écrit, tient le verrou plus longtemps que cela le temps de deux écritures vidées
/// sur le disque. Le refus va au journal des erreurs (qui ne passe pas par ce verrou) : bien des appelants
/// n'attendent rien de l'écriture.
fn verrou_ecriture(dossier: &Path, nom: &str) -> std::io::Result<crate::socle::Verrou> {
    std::fs::create_dir_all(dossier)?;
    prendre_verrou(dossier, false, crate::socle::ATTENTE_ECRITURE).map_err(|e| {
        let e = e.erreur(VERROU);
        crate::modele::Echec::echoue("sceau/ecrire", format!("{nom} : {e}")).journaliser();
        e
    })
}

/// Les dossiers dont le verrou des sceaux a été refusé à ce processus au-delà de toute l'attente, et pas rendu depuis,
/// avec ce qu'il lui reste à l'attendre. Un `flock` gardé par un programme du compte (ou par un enfant oublié) faisait
/// attendre 30 s chaque écriture scellée et 10 s chaque lecture : une commande durait des minutes, ce qu'elle devait
/// noter se perdait, et le bilan n'en disait rien. Passé un premier refus, plus que `ATTENTE_APRES_REFUS` en tout
/// pour ce processus, quel que soit le nombre de prises ; et le bilan le dit (`constat_verrou`).
static TENUS: std::sync::Mutex<BTreeMap<PathBuf, std::time::Duration>> = std::sync::Mutex::new(BTreeMap::new());

/// Ce qu'un processus attend encore, en tout, un verrou déjà refusé : un Vanguard qui écrit le rend en quelques
/// millisecondes ; épuisé, chaque prise n'est plus qu'un essai.
const ATTENTE_APRES_REFUS: std::time::Duration = std::time::Duration::from_secs(1);

// Les essais attendent moins le verrou que le programme (`verrou_tenu_…`).
#[cfg(test)]
thread_local! {
    static ATTENTE_ESSAI: std::cell::Cell<Option<std::time::Duration>> = const { std::cell::Cell::new(None) };
}

/// Pour les essais d'autres modules : l'attente du verrou des sceaux sur ce fil.
#[cfg(test)]
pub(crate) fn attendre_en_essai(attente: std::time::Duration) {
    ATTENTE_ESSAI.with(|a| a.set(Some(attente)));
}

/// Le verrou des sceaux de `dossier`, attendu au plus `attente`, ou bien moins s'il a déjà été refusé ici (`TENUS`).
fn prendre_verrou(
    dossier: &Path,
    partage: bool,
    attente: std::time::Duration,
) -> Result<crate::socle::Verrou, crate::socle::SansVerrou> {
    #[cfg(test)]
    let attente = ATTENTE_ESSAI.with(std::cell::Cell::get).unwrap_or(attente);
    let tenus = || TENUS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let reste = tenus().get(dossier).copied();
    let attente = reste.map_or(attente, |r| attente.min(r));
    let debut = std::time::Instant::now();
    let v = crate::socle::Verrou::prendre(dossier, VERROU, partage, attente);
    match &v {
        Ok(_) => {
            tenus().remove(dossier);
        }
        Err(crate::socle::SansVerrou::Occupe) => {
            let reste = reste.map_or(ATTENTE_APRES_REFUS, |r| r.saturating_sub(debut.elapsed()));
            tenus().insert(dossier.to_path_buf(), reste);
        }
        Err(crate::socle::SansVerrou::Impossible(_)) => {}
    }
    v
}

/// Le verrou des sceaux de `dossier` a-t-il été refusé à ce processus, tenu ailleurs au-delà de l'attente, et pas
/// rendu depuis ? Ce qui devait s'écrire sous lui (réglages, déjà-vus, tête du journal des événements) ne l'a pas été.
pub(crate) fn verrou_tenu_dans(dossier: &Path) -> bool {
    TENUS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains_key(dossier)
}

/// Au bilan : le verrou des sceaux tenu ailleurs, comme celui du journal (`modele::journal`).
fn constat_verrou(dossier: &Path) -> Option<Constat> {
    if !verrou_tenu_dans(dossier) {
        return None;
    }
    Some(
        crate::machine::alerte(
            CAT,
            Niveau::Moyen,
            tr!(
                "Les sceaux de l'état de Vanguard n'ont pas pu être tenus : leur verrou (sceaux.verrou) est gardé depuis trop longtemps (un Vanguard figé, ou un autre programme qui le garde). Ce que Vanguard devait y noter (réglages, déjà-vus, journal des événements) n'a pas été écrit, et le journal n'est pas tenu pour vérifié.",
                "The seals of Vanguard's state could not be held: their lock (sceaux.verrou) has been kept too long (a frozen Vanguard, or another program keeping it). What Vanguard had to note there (settings, already-seen lists, event log) was not written, and the log is not taken as verified."
            ),
        )
        .manuel(
            tr!(
                "Fermez les autres Vanguard ouverts, puis relancez le bilan ; si cela reste, regardez ce qui tourne sous votre compte",
                "Close the other open Vanguard windows, then run the check-up again; if it stays, look at what runs under your account"
            ),
            &[],
        ),
    )
}

/// Le verrou d'un lecteur. Exclusif là où il peut écrire : au premier usage ou pour un fichier protégé tard, la lecture
/// note ce qu'elle adopte dans le registre (`ecrire`). Ailleurs (le dossier d'un autre compte, un autotest, le
/// processus élevé) partagé, sans rien créer. Sans verrou, rien n'est noté, et la lecture juge quand même : un
/// verrou qui ne s'ouvre pas n'est tenu par aucun écrivain, et tenu au-delà de l'attente, c'est un Vanguard figé ;
/// dire « pas jugé » laisserait sinon n'importe quel programme qui le garde faire taire les falsifications.
fn verrou_lecture(dossier: &Path, ecrire: bool) -> (Option<crate::socle::Verrou>, bool) {
    let ecrire = ecrire && crate::socle::ecriture_sure(dossier);
    match prendre_verrou(dossier, !ecrire, crate::socle::ATTENTE_LECTURE) {
        Ok(v) => (Some(v), ecrire),
        Err(_) => (None, false),
    }
}

/// Les sceaux : `Ok(None)` s'il n'y en a pas encore (une version d'avant), `Err` s'ils ne se lisent plus.
fn registre(dossier: &Path) -> Result<Option<Registre>, ()> {
    match crate::socle::lire_ordinaire(&dossier.join(REGISTRE), TAILLE_MAX) {
        Ok(o) => serde_json::from_slice(&o).map(Some).map_err(|_| ()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

fn enregistrer_registre(dossier: &Path, r: &Registre) -> std::io::Result<()> {
    if !crate::socle::ecriture_sure(dossier) {
        return Err(dossier_d_un_autre());
    }
    let r = Registre {
        format: FORMAT,
        ..r.clone()
    };
    crate::socle::ecrire_atomique(
        &dossier.join(REGISTRE),
        serde_json::to_vec_pretty(&r).map_err(std::io::Error::other)?,
    )
}

/// Root n'écrit pas dans le dossier d'un compte (`socle::ecriture_sure`).
fn dossier_d_un_autre() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        tr!(
            "en administrateur, le dossier de données d'un autre compte n'est pas écrit",
            "as administrator, another account's data folder is not written"
        ),
    )
}

/// Les références des clés VANGUARD relèvent chaque fichier de la clé (une image ISO comptée par sa taille) : quelques
/// centaines de Kio d'ordinaire, jusqu'à 64 Mio lues par `protection::manifeste`.
const TAILLE_MAX_REFERENCE: u64 = 64 << 20;

/// La taille au-delà de laquelle `chemin` n'est pas lu.
fn taille_max(chemin: &Path) -> u64 {
    let nom = |p: Option<&Path>| p.and_then(Path::file_name).and_then(|n| n.to_str()).map(str::to_string);
    if nom(Some(chemin)).as_deref() == Some(MANIFESTE_CLE) || nom(chemin.parent()).as_deref() == Some(MANIFESTES_CLE) {
        TAILLE_MAX_REFERENCE
    } else if nom(Some(chemin)).as_deref() == Some(APPAREILS) {
        // Le carnet des appareils garde sa limite d'avant le sceau : un grand réseau ne le fait pas juger illisible.
        crate::reseau::CARNET_MAX
    } else {
        TAILLE_MAX
    }
}

/// Le contenu d'un fichier d'état, `Ok(None)` s'il n'existe pas.
fn contenu(chemin: &Path) -> Result<Option<Vec<u8>>, String> {
    match crate::socle::lire_ordinaire(chemin, taille_max(chemin)) {
        Ok(o) => Ok(Some(o)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Une version qui scelle a déjà servi ici : seule elle crée `sceaux.verrou` (`verrou`), et rien ne l'efface. Relu
/// avant que `verrou` ne le crée. Le verrou vit pourtant dans le même dossier, écrit par le même compte : effacé
/// avec les sceaux et les fichiers qu'ils protégeaient, il ramenait au premier usage, où la surveillance mémorise
/// sans rien dire. D'autres témoins, que seule une version qui scelle laisse, comptent donc autant : la tête du
/// journal des événements (écrite par le sceau même) et ses segments. Tout effacer d'un coup, journal compris, reste
/// possible : c'est alors le journal vide d'un ordinateur où Vanguard a servi qui le montre.
fn deja_scelle(dossier: &Path) -> bool {
    let present = |p: PathBuf| std::fs::symlink_metadata(p).is_ok();
    present(dossier.join(VERROU))
        || present(dossier.join(crate::modele::journal::TETE))
        // Nés scellés (lot S2b) : aucune version d'avant les sceaux ne les a écrits.
        || present(dossier.join(crate::voulues::FICHIER))
        || present(dossier.join(crate::programmes_poses::FICHIER))
        || std::fs::read_dir(dossier.join(crate::modele::journal::DOSSIER))
            .is_ok_and(|mut d| d.any(|e| e.is_ok_and(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))))
}

/// Premier passage d'une version qui scelle : les fichiers déjà là sont scellés tels quels, et ce départ est daté.
/// Si une version qui scelle avait déjà servi ici (`deja_scelle`), les sceaux ont été effacés : un fichier protégé
/// absent est alors inconnu, pas encore jamais écrit. Une version d'avant les sceaux (0.85) laisse son historique
/// et ses fichiers de surveillance, mais jamais `sceaux.verrou` : sa mise à jour n'est pas des sceaux effacés (elle
/// se disait refaite, en alerte élevée, et l'annonce des versions se taisait). Et effacer avec les sceaux
/// l'historique et ces fichiers ne fait plus passer pour un premier usage : le verrou, lui, est resté.
fn adopter(dossier: &Path, deja_scelle: bool) -> Registre {
    adopter_si(dossier, deja_scelle, true)
}

/// `adopter`, et seulement s'il le faut (`ecrire`), noté dans les sceaux.
fn adopter_si(dossier: &Path, deja_scelle: bool, ecrire: bool) -> Registre {
    let refaits = deja_scelle;
    let mut r = Registre {
        format: FORMAT,
        depuis: chrono::Local::now().format("%Y-%m-%d").to_string(),
        refaits,
        ..Registre::default()
    };
    for nom in proteges() {
        match contenu(&dossier.join(nom)) {
            Ok(Some(o)) => {
                r.fichiers.insert(nom.to_string(), empreinte(nom, &o));
                r.adoptes.insert(nom.to_string());
            }
            Ok(None) if refaits => {
                r.inconnus.insert(nom.to_string());
            }
            _ => {}
        }
    }
    for nom in TARDIFS_DOSSIERS.iter().flat_map(|d| presents_tardifs(dossier, d)) {
        if let Ok(Some(o)) = contenu(&dossier.join(&nom)) {
            r.fichiers.insert(nom.clone(), empreinte(&nom, &o));
            r.adoptes.insert(nom);
        }
    }
    r.vus = tous_les_tardifs();
    if ecrire {
        let _ = enregistrer_registre(dossier, &r);
    }
    r
}

/// Des sceaux d'une version qui ne protégeait pas encore les fichiers `TARDIFS` : celui qui est déjà là, sans sceau,
/// est adopté tel quel (il vient de cette version), une fois pour toutes.
fn rattraper(dossier: &Path, r: Registre) -> Registre {
    rattraper_si(dossier, r, true)
}

/// Ce que des sceaux neufs ont déjà « vu » des fichiers et dossiers protégés tard : tout.
fn tous_les_tardifs() -> BTreeSet<String> {
    TARDIFS
        .iter()
        .chain(TARDIFS_DOSSIERS)
        .map(|n| (*n).to_string())
        .collect()
}

/// `rattraper`, et seulement s'il le faut (`ecrire`), noté dans les sceaux. Seuls des sceaux d'une forme d'avant
/// (`FORMAT`) font reprendre un fichier, et seulement sur la preuve d'une vraie mise à jour (`Avant::MiseAJour`) : dans
/// ceux de cette forme, un nom retiré des `vus` n'est pas une mise à jour.
fn rattraper_si(dossier: &Path, mut r: Registre, ecrire: bool) -> Registre {
    let mut change = false;
    let avant = (r.format < FORMAT).then(|| forme_d_avant(dossier, &r));
    let aujourd_hui = || chrono::Local::now().format("%Y-%m-%d").to_string();
    match avant {
        None => {}
        // Rien ne prouve la mise à jour : des sceaux ramenés en arrière hors de Vanguard (le champ `format` est en
        // clair), pour faire reprendre un fichier posé sans sceau. Ce qui est là est adopté sans être repris (rien
        // ne s'y fie), et le bilan le dit comme des sceaux refaits.
        Some(Avant::Recule) => {
            r.refaits = true;
            r.depuis = aujourd_hui();
            // « Refaits » dit déjà tout, et plus haut : une version plus ancienne constatée avant ne se redit pas.
            r.ancienne = None;
            r.sans_journal = None;
        }
        // Aucune trace du journal : une 0.86 ou une 0.87 qui n'avait encore rien noté, ou des sceaux ramenés en arrière
        // avec le journal effacé. Rien ne prouve la mise à jour, rien n'est repris ; dit moyen, avec les deux causes.
        Some(Avant::SansJournal) => r.sans_journal = Some(aujourd_hui()),
        // Les adoptions des sceaux d'avant : ceux qui n'ont pas été refaits les croyaient (repris d'une version d'avant
        // les sceaux, ou d'une mise à jour) ; refaits, rien ne dit d'où elles viennent.
        Some(Avant::MiseAJour) => {
            if !r.refaits {
                let adoptes = r.adoptes.clone();
                r.repris.extend(adoptes);
            }
        }
        // Une version plus ancienne a servi ici après celle-ci : rien n'est repris, rien de ce qu'elle a laissé hors
        // des sceaux n'est adopté, et le bilan le dit sans parler de sceaux abîmés.
        Some(Avant::Ancienne) => r.ancienne = Some(aujourd_hui()),
    }
    if avant.is_some() {
        r.format = FORMAT;
        change = true;
    }
    let adopter = matches!(avant, Some(Avant::MiseAJour | Avant::Recule | Avant::SansJournal));
    let reprendre = avant == Some(Avant::MiseAJour);
    let adopter_tel_quel = |r: &mut Registre, nom: String| {
        if adopter
            && !r.fichiers.contains_key(&nom)
            && let Ok(Some(o)) = contenu(&dossier.join(&nom))
        {
            r.fichiers.insert(nom.clone(), empreinte(&nom, &o));
            r.adoptes.insert(nom.clone());
            if reprendre {
                r.repris.insert(nom);
            }
        }
    };
    for nom in TARDIFS.iter().copied() {
        if r.vus.contains(nom) {
            continue;
        }
        adopter_tel_quel(&mut r, nom.to_string());
        r.vus.insert(nom.to_string());
        change = true;
    }
    for sous in TARDIFS_DOSSIERS.iter().copied() {
        if r.vus.contains(sous) {
            continue;
        }
        for nom in presents_tardifs(dossier, sous) {
            adopter_tel_quel(&mut r, nom);
        }
        r.vus.insert(sous.to_string());
        change = true;
    }
    if change && ecrire {
        let _ = enregistrer_registre(dossier, &r);
    }
    r
}

/// Ce que sont des sceaux d'une forme d'avant (`format < FORMAT`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Avant {
    /// Une vraie mise à jour depuis la 0.86 ou la 0.87 : ce qu'elle ne scellait pas encore est repris, et cru.
    MiseAJour,
    /// Une version plus ancienne a servi ici après celle-ci (une clé ou un Mac restés en arrière) : rien n'est repris.
    Ancienne,
    /// Rien ne le prouve : ramenés en arrière hors de Vanguard, rien n'est repris et c'est dit comme des sceaux refaits.
    Recule,
    /// Aucune trace du journal (ni tête, ni segment, ni verrou) : une version d'avant qui n'avait rien noté, ou tout
    /// effacé avec des sceaux ramenés en arrière. Rien n'est repris ; dit moyen, sans parler de sceaux refaits.
    SansJournal,
}

/// La preuve, positive, de ce que sont des sceaux d'une forme d'avant : la tête du journal des événements
/// (`modele::journal`), présente et scellée telle quelle dans ces sceaux, note la forme des sceaux de qui l'a écrite.
/// Écrite par une version d'avant (sans cette forme) et sans aucune marque de cette forme-ci dans le registre (`repris`,
/// un nom de `vus` qu'aucune version d'avant ne connaissait) : une mise à jour. Avec une marque de cette forme, ou
/// écrite par elle : une version plus ancienne est repassée après elle (elle réécrit les sceaux sans leur forme). Tête
/// absente, effacée avec le journal, réécrite ou retirée des sceaux : rien ne prouve rien, tout ce qu'effacer ou
/// ramener en arrière des champs en clair pourrait faire croire est refusé.
fn forme_d_avant(dossier: &Path, r: &Registre) -> Avant {
    let tete = crate::modele::journal::TETE;
    let Ok(Some(o)) = contenu(&dossier.join(tete)) else {
        return if sans_trace_du_journal(dossier, r) {
            Avant::SansJournal
        } else {
            Avant::Recule
        };
    };
    if r.fichiers.get(tete) != Some(&empreinte(tete, &o)) {
        return Avant::Recule;
    }
    let Some(forme) = serde_json::from_slice::<serde_json::Value>(&o)
        .ok()
        .map(|v| v.get("sceaux").and_then(serde_json::Value::as_u64).unwrap_or(0))
    else {
        return Avant::Recule;
    };
    let d_avant = &TARDIFS[..TARDIFS_D_AVANT];
    let marque = !r.repris.is_empty() || r.vus.iter().any(|n| !d_avant.contains(&n.as_str()));
    if forme >= u64::from(FORMAT) || marque {
        Avant::Ancienne
    } else {
        Avant::MiseAJour
    }
}

/// Aucune trace du journal des événements : ni tête (sur le disque ou dans les sceaux), ni segment, ni verrou (celui
/// de Vanguard ou celui du système, que chaque écriture du journal laisse). Ce que laisse une version d'avant qui n'a
/// encore rien noté ; un journal effacé hors de Vanguard en laisse sinon presque toujours une.
fn sans_trace_du_journal(dossier: &Path, r: &Registre) -> bool {
    use crate::modele::journal::{DOSSIER, TETE, VERROU};
    let verrou_systeme = format!("{}.lock", VERROU.strip_suffix(".verrou").unwrap_or(VERROU));
    !r.fichiers
        .keys()
        .any(|n| n == TETE || n.starts_with(&format!("{DOSSIER}/")))
        && [TETE, DOSSIER, VERROU, verrou_systeme.as_str()]
            .iter()
            .all(|n| std::fs::symlink_metadata(dossier.join(n)).is_err())
}

/// Des sceaux d'une forme d'avant jugés (`forme_d_avant`) et réécrits dans celle-ci AVANT que le journal des événements
/// laisse dans `dossier` sa première trace : il prenait son verrou et créait son dossier avant de lire sa tête, et
/// c'est cette lecture qui jugeait les sceaux ; ses propres traces faisaient alors prendre une 0.86 ou une 0.87 qui
/// n'avait rien noté pour un journal effacé, des sceaux refaits (élevé). Appelé par chaque chemin du journal qui crée
/// quelque chose. `false` : ils restent d'une forme d'avant, faute de pouvoir les réécrire (verrou des sceaux tenu
/// ailleurs, autotest) ; le journal n'y crée alors rien, pour que le jugement reste juste à la prochaine fois.
pub(crate) fn forme_jugee_avant_le_journal(dossier: &Path) -> bool {
    let d_avant = || matches!(registre(dossier), Ok(Some(r)) if r.format < FORMAT);
    // Le dossier d'un autre compte : ni les sceaux ni le journal n'y écrivent.
    if !d_avant() || !crate::socle::ecriture_sure(dossier) {
        return true;
    }
    let (_verrou, ecrire) = verrou_lecture(dossier, true);
    if ecrire && let Ok(Some(r)) = registre(dossier) {
        let _ = rattraper_si(dossier, r, true);
    }
    !d_avant()
}

/// Le jugement d'un fichier d'après les sceaux (`None` : ils ne se lisent plus, rien ne peut être cru).
fn juger(nom: &str, lu: Result<Option<Vec<u8>>, String>, sceaux: Option<&Registre>) -> Lecture {
    let lu = match lu {
        Ok(lu) => lu,
        Err(e) => return Lecture::Illisible(e),
    };
    let attendu = sceaux.and_then(|r| r.fichiers.get(nom));
    match (lu, attendu) {
        // Sans sceaux lisibles, ou refaits sans lui : absent, mais peut-être effacé.
        (None, None) if sceaux.is_none_or(|r| r.inconnus.contains(nom)) => Lecture::Inconnu,
        (None, None) => Lecture::Absent,
        (None, Some(_)) => Lecture::Falsifie(None),
        (Some(o), Some(e)) if *e == empreinte(nom, &o) => {
            if sceaux.is_some_and(|r| r.adoptes.contains(nom)) {
                Lecture::Adopte(o)
            } else {
                Lecture::Intact(o)
            }
        }
        // Changé, ou posé sans sceau alors que les sceaux existent (par un autre programme, ou par une copie de
        // Vanguard d'avant les sceaux).
        (Some(o), _) => Lecture::Falsifie(Some(o)),
    }
}

/// Un fichier d'état de `dossier`, jugé d'après ses sceaux.
pub(crate) fn lire_dans(dossier: &Path, nom: &str) -> Lecture {
    let deja = deja_scelle(dossier);
    let (_verrou, ecrire) = verrou_lecture(dossier, true);
    let sceaux = match registre(dossier) {
        Ok(Some(r)) => Some(rattraper_si(dossier, r, ecrire)),
        Ok(None) => Some(adopter_si(dossier, deja, ecrire)),
        Err(()) => None,
    };
    juger(nom, contenu(&dossier.join(nom)), sceaux.as_ref())
}

/// `lire_dans` sans rien écrire ni créer : ce que lisent les réglages du lancement, avant que le passage d'une version
/// d'avant ait repris son dossier (des sceaux posés là d'abord feraient passer les fichiers repris pour falsifiés), et
/// le processus élevé. Le même jugement : un premier usage ou un fichier protégé tard s'y lit `Adopte`, sans être noté.
/// Le verrou n'est pris que s'il existe déjà.
pub(crate) fn lire_sans_ecrire(dossier: &Path, nom: &str) -> Lecture {
    let deja = deja_scelle(dossier);
    let _verrou = if deja { verrou_lecture(dossier, false).0 } else { None };
    let sceaux = match registre(dossier) {
        Ok(Some(r)) => Some(rattraper_si(dossier, r, false)),
        Ok(None) => Some(adopter_si(dossier, deja, false)),
        Err(()) => None,
    };
    juger(nom, contenu(&dossier.join(nom)), sceaux.as_ref())
}

/// Écrit un fichier d'état de `dossier` (d'un coup) et son sceau. Des sceaux illisibles repartent de celui-ci : les
/// autres fichiers restent falsifiés jusqu'à ce que Vanguard les réécrive.
pub(crate) fn ecrire_dans(dossier: &Path, nom: &str, octets: &[u8]) -> std::io::Result<()> {
    if !crate::socle::ecriture_sure(dossier) {
        return Err(dossier_d_un_autre());
    }
    let deja = deja_scelle(dossier);
    let _verrou = verrou_ecriture(dossier, nom)?;
    let mut sceaux = match registre(dossier) {
        Ok(Some(r)) => rattraper(dossier, r),
        Ok(None) => adopter(dossier, deja),
        // Les autres fichiers ne peuvent plus être crus : présents, ils sont falsifiés (sans sceau) ; absents,
        // inconnus.
        Err(()) => Registre {
            format: FORMAT,
            depuis: chrono::Local::now().format("%Y-%m-%d").to_string(),
            vus: tous_les_tardifs(),
            refaits: true,
            inconnus: proteges().map(str::to_string).collect(),
            ..Registre::default()
        },
    };
    sceaux.inconnus.remove(nom);
    crate::socle::ecrire_atomique(&dossier.join(nom), octets)?;
    sceaux.fichiers.insert(nom.to_string(), empreinte(nom, octets));
    sceaux.adoptes.remove(nom);
    sceaux.repris.remove(nom);
    sceaux
        .versions
        .insert(nom.to_string(), crate::modele::inventaire::schema(nom));
    enregistrer_registre(dossier, &sceaux)
}

/// Retire un fichier d'état et son sceau (Vanguard l'oublie lui-même).
pub(crate) fn effacer_dans(dossier: &Path, nom: &str) -> std::io::Result<()> {
    if !crate::socle::ecriture_sure(dossier) {
        return Err(dossier_d_un_autre());
    }
    let _verrou = verrou_ecriture(dossier, nom)?;
    match std::fs::remove_file(dossier.join(nom)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    if let Ok(Some(mut r)) = registre(dossier)
        && (r.fichiers.remove(nom).is_some()
            | r.adoptes.remove(nom)
            | r.repris.remove(nom)
            | r.versions.remove(nom).is_some()
            | r.inconnus.remove(nom))
    {
        enregistrer_registre(dossier, &r)?;
    }
    Ok(())
}

/// Oublie des sceaux de `dossier` les fichiers qui n'y sont plus : ce que laisse une désinstallation qui efface le
/// dossier de données sauf ce qu'une défense gardée demande encore (`desinstaller`). Les fichiers gardés restent tels
/// que Vanguard les a écrits ; ceux qui sont partis avec le dossier ne se disent pas effacés hors de Vanguard.
pub(crate) fn oublier_absents_dans(dossier: &Path) -> std::io::Result<()> {
    if !crate::socle::ecriture_sure(dossier) {
        return Err(dossier_d_un_autre());
    }
    let _verrou = verrou_ecriture(dossier, REGISTRE)?;
    let Ok(Some(mut r)) = registre(dossier) else {
        return Ok(());
    };
    let present = |nom: &String| std::fs::symlink_metadata(dossier.join(nom)).is_ok();
    let avant = (r.fichiers.len(), r.adoptes.len(), r.versions.len());
    r.fichiers.retain(|nom, _| present(nom));
    r.adoptes.retain(present);
    r.repris.retain(present);
    r.versions.retain(|nom, _| present(nom));
    if avant == (r.fichiers.len(), r.adoptes.len(), r.versions.len()) {
        return Ok(());
    }
    enregistrer_registre(dossier, &r)
}

fn dossier() -> PathBuf {
    crate::socle::dossier_local()
}

pub(crate) fn lire(nom: &str) -> Lecture {
    lire_dans(&dossier(), nom)
}

pub(crate) fn ecrire(nom: &str, octets: impl AsRef<[u8]>) -> std::io::Result<()> {
    ecrire_dans(&dossier(), nom, octets.as_ref())
}

pub(crate) fn effacer(nom: &str) -> std::io::Result<()> {
    effacer_dans(&dossier(), nom)
}

/// Ce que le bilan doit dire des fichiers d'état.
#[derive(Debug, PartialEq, Eq, Default)]
struct Releve {
    /// Changés hors de Vanguard.
    falsifies: Vec<&'static str>,
    /// Les sceaux eux-mêmes ne se lisent plus.
    illisibles: bool,
    /// Acceptés tels quels au premier usage, pas réécrits depuis.
    adoptes: Vec<&'static str>,
    /// Le jour de ce premier usage.
    depuis: String,
    /// Ce premier usage a refait des sceaux effacés ou illisibles, alors que Vanguard avait déjà servi ici.
    refaits: bool,
    /// Le jour où une version plus ancienne de Vanguard s'est retrouvée avoir servi ici (`Registre::ancienne`).
    ancienne: Option<String>,
    /// Le jour où des sceaux d'avant ont été retrouvés sans trace du journal (`Registre::sans_journal`).
    sans_journal: Option<String>,
}

fn falsifies_dans(dossier: &Path) -> Releve {
    let mut r = Releve {
        illisibles: registre(dossier).is_err(),
        ..Releve::default()
    };
    for nom in proteges() {
        match lire_dans(dossier, nom) {
            Lecture::Falsifie(_) => r.falsifies.push(nom),
            Lecture::Adopte(_) => r.adoptes.push(nom),
            _ => {}
        }
    }
    // Repris d'une mise à jour connue : ce n'est ni un premier usage ni des sceaux refaits, rien à dire.
    if let Ok(Some(s)) = registre(dossier) {
        r.adoptes.retain(|n| !s.repris.contains(*n));
    }
    if let Ok(Some(s)) = registre(dossier)
        && (!r.adoptes.is_empty() || s.refaits)
    {
        r.refaits = s.refaits;
        r.depuis = s.depuis;
    }
    if let Ok(Some(s)) = registre(dossier) {
        r.ancienne = s.ancienne;
        r.sans_journal = s.sans_journal;
    }
    r
}

/// Une version plus ancienne de Vanguard a servi ici après celle-ci (une clé ou un Mac restés en arrière, un retour
/// à une version d'avant) : elle a réécrit les sceaux à sa façon. Pas des sceaux abîmés hors de Vanguard, mais rien
/// de ce qu'elle a laissé n'est repris : ce qu'elle a accepté tel quel se redit, un mois.
fn juger_ancienne(adoptes: &[&str], jour: &str, aujourd_hui: chrono::NaiveDate) -> Option<Constat> {
    let jours = chrono::NaiveDate::parse_from_str(jour, "%Y-%m-%d")
        .map_or(0, |d| aujourd_hui.signed_duration_since(d).num_days());
    if adoptes.is_empty() && jours > REFAITS_JOURS {
        return None;
    }
    let mut message = trf!(
        "Une version plus ancienne de Vanguard a servi sur cet ordinateur après celle-ci (constaté le {jour}) : elle a réécrit les sceaux de l'état de Vanguard (sceaux.json) à sa façon. Rien de ce qu'elle a laissé n'est repris tel quel.",
        "An older version of Vanguard ran on this computer after this one (noticed on {jour}): it rewrote the seals of Vanguard's state (sceaux.json) its own way. Nothing it left behind is taken over as it is."
    );
    if !adoptes.is_empty() {
        let liste = adoptes.join(", ");
        message += &trf!(
            " Fichiers qui ne sont plus crus jusqu'à ce que Vanguard les réécrive : {liste}.",
            " Files no longer trusted until Vanguard rewrites them: {liste}."
        );
    }
    Some(
        crate::machine::alerte(CAT, Niveau::Moyen, message).manuel(
            tr!(
                "Mettez à jour la copie restée en arrière (une clé de secours, un autre ordinateur) ; si aucune version plus ancienne n'a servi ici, regardez ce qui tourne sous votre compte",
                "Update the copy left behind (a rescue drive, another computer); if no older version ran here, look at what runs under your account"
            ),
            &[],
        ),
    )
}

/// Des sceaux d'une forme d'avant sans aucune trace du journal (`Avant::SansJournal`) : une 0.86 ou une 0.87 qui
/// n'avait encore rien noté, ou des sceaux ramenés en arrière avec le journal effacé. Rien ne permet de trancher :
/// rien n'est repris, et ce qui a été accepté tel quel se dit, un mois ou tant qu'il n'est pas réécrit.
fn juger_sans_journal(adoptes: &[&str], jour: &str, aujourd_hui: chrono::NaiveDate) -> Option<Constat> {
    let jours = chrono::NaiveDate::parse_from_str(jour, "%Y-%m-%d")
        .map_or(0, |d| aujourd_hui.signed_duration_since(d).num_days());
    if adoptes.is_empty() && jours > REFAITS_JOURS {
        return None;
    }
    let mut message = trf!(
        "Vanguard n'avait rien noté à son journal avant cette mise à jour, ou les sceaux de son état (sceaux.json) ont été ramenés en arrière (constaté le {jour}) : rien ne prouve la mise à jour, donc rien de ce qui était là n'est repris tel quel.",
        "Vanguard had noted nothing in its log before this update, or the seals of its state (sceaux.json) were rolled back (noticed on {jour}): nothing proves the update, so nothing that was there is taken over as it is."
    );
    if !adoptes.is_empty() {
        let liste = adoptes.join(", ");
        message += &trf!(
            " Fichiers qui ne sont pas crus jusqu'à ce que Vanguard les réécrive : {liste}.",
            " Files not trusted until Vanguard rewrites them: {liste}."
        );
    }
    Some(
        crate::machine::alerte(CAT, Niveau::Moyen, message).manuel(
            tr!(
                "Si Vanguard vient d'être mis à jour, Ce que Vanguard a appris propose de garder vos choix ; sinon, regardez ce qui tourne sous votre compte",
                "If Vanguard was just updated, What Vanguard has learned offers to keep your choices; otherwise, look at what runs under your account"
            ),
            &[],
        ),
    )
}

/// Des sceaux refaits se disent tant qu'un fichier adopté n'a pas été réécrit, et au moins un mois.
const REFAITS_JOURS: i64 = 30;

/// Les sceaux refaits alors que Vanguard avait déjà servi ici : effacés (ou abîmés) par un autre programme, le plus
/// souvent avec un fichier d'état qu'il voulait faire oublier. Dit plus haut que de simples fichiers adoptés, et daté
/// autrement, pour que la surveillance le notifie.
fn juger_refaits(adoptes: &[&str], depuis: &str, aujourd_hui: chrono::NaiveDate) -> Option<Constat> {
    let jours = chrono::NaiveDate::parse_from_str(depuis, "%Y-%m-%d")
        .map_or(0, |d| aujourd_hui.signed_duration_since(d).num_days());
    if adoptes.is_empty() && jours > REFAITS_JOURS {
        return None;
    }
    let liste = if adoptes.is_empty() {
        tr!("aucun", "none").to_string()
    } else {
        adoptes.join(", ")
    };
    Some(
        crate::machine::alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "Les sceaux de l'état de Vanguard (sceaux.json) ont été refaits le {depuis}, alors que Vanguard avait déjà servi sur cet ordinateur : ils ont été effacés ou abîmés hors de Vanguard. Fichiers acceptés tels quels : {liste} ; ceux qui manquaient sont traités comme vides (rien n'est passé sous silence).",
                "The seals of Vanguard's state (sceaux.json) were remade on {depuis}, although Vanguard had already run on this computer: they were deleted or damaged outside Vanguard. Files accepted as they were: {liste}; the missing ones are treated as empty (nothing is silenced)."
            ),
        )
        .manuel(
            tr!(
                "Regardez ce qui tourne sous votre compte (Protection › Qui parle à Internet ?) ; « vanguard integrite --accepter » refait la référence",
                "Look at what runs under your account (Protection › Who talks to the Internet?); “vanguard integrity --accept” remakes the reference"
            ),
            &[],
        ),
    )
}

/// La catégorie du constat.
pub(crate) const CAT: &str = "État de Vanguard";

/// Le constat d'après les fichiers falsifiés ; `copie_ancienne` : la copie de cet ordinateur (celle que lancent la
/// surveillance et l'entretien) est plus ancienne que ce programme, et elle écrit encore ces fichiers sans sceau.
fn juger_constat(falsifies: &[&str], illisibles: bool, copie_ancienne: bool) -> Option<Constat> {
    if falsifies.is_empty() {
        return None;
    }
    let liste = falsifies.join(", ");
    let mut message = if illisibles {
        trf!(
            "Les sceaux de l'état de Vanguard (sceaux.json) ne se lisent plus : {liste} ne peuvent pas être crus. Vanguard les traite comme vides (aucune alerte n'est tue) jusqu'à ce qu'il les réécrive.",
            "The seals of Vanguard's state (sceaux.json) can no longer be read: {liste} cannot be trusted. Vanguard treats them as empty (no alert is silenced) until it rewrites them."
        )
    } else {
        trf!(
            "L'état de Vanguard a été changé hors de Vanguard : {liste}. Un programme qui tourne sous votre compte a pu s'en servir pour faire taire une alerte ; Vanguard n'en tient plus compte (aucune alerte n'est tue) jusqu'à ce qu'il les réécrive.",
            "Vanguard's state was changed outside Vanguard: {liste}. A program running under your account may have used it to silence an alert; Vanguard ignores it (no alert is silenced) until it rewrites it."
        )
    };
    if copie_ancienne {
        message += tr!(
            " Cause probable : la copie de Vanguard de cet ordinateur est plus ancienne et écrit ces fichiers sans sceau ; mettez-la à jour (« vanguard se-mettre-a-jour »).",
            " Likely cause: the copy of Vanguard on this computer is older and writes these files without a seal; update it (“vanguard se-mettre-a-jour”)."
        );
    }
    let niveau = if copie_ancienne { Niveau::Moyen } else { Niveau::Eleve };
    Some(
        crate::machine::alerte(CAT, niveau, message).manuel(
            tr!(
                "Regardez ce qui tourne sous votre compte (Protection › Qui parle à Internet ?) ; Ce que Vanguard a appris et « vanguard integrite --accepter » refont leurs fichiers",
                "Look at what runs under your account (Protection › Who talks to the Internet?); What Vanguard has learned and “vanguard integrity --accept” remake their files"
            ),
            &[],
        ),
    )
}

/// Les fichiers acceptés tels quels au premier usage : normal le jour où Vanguard est passé à une version qui
/// scelle, mais c'est aussi ce que donne `sceaux.json` effacé après qu'un programme a changé ces fichiers. Dit tant
/// que Vanguard ne les a pas réécrits, jamais compté comme sain.
fn juger_adoptes(adoptes: &[&str], depuis: &str) -> Option<Constat> {
    if adoptes.is_empty() {
        return None;
    }
    let liste = adoptes.join(", ");
    Some(
        crate::machine::alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "{liste} ont été acceptés tels quels le {depuis}, sans sceau d'avant. Si Vanguard n'a pas été mis à jour ce jour-là, sceaux.json a été effacé et ces fichiers ne peuvent pas être crus.",
                "{liste} were accepted as they were on {depuis}, without an earlier seal. If Vanguard was not updated that day, sceaux.json was deleted and these files cannot be trusted."
            ),
        )
        .manuel(
            tr!(
                "Ce que Vanguard a appris propose de garder vos choix ; « vanguard integrite --accepter » refait la référence ; les autres sont réécrits par la surveillance",
                "What Vanguard has learned offers to keep your choices; “vanguard integrity --accept” remakes the reference; monitoring rewrites the others"
            ),
            &[],
        ),
    )
}

/// Réécrit, scellé, un fichier accepté tel quel lors d'une mise à jour (`sans_risque` : ce que son lecteur croit de
/// toute façon) : sans cela, chaque version d'avant mise à jour garderait l'alerte « accepté tel quel » jusqu'à ce
/// qu'on change un réglage. Seulement ce qu'une mise à jour connue a repris (`repris_dans`) : accepté au premier usage
/// ou après des sceaux refaits, rien n'est rescellé, l'alerte reste.
pub(crate) fn resceller_si(nom: &str, sans_risque: impl Fn(&[u8]) -> bool) {
    resceller_si_dans(&dossier(), nom, sans_risque);
}

fn resceller_si_dans(dossier: &Path, nom: &str, sans_risque: impl Fn(&[u8]) -> bool) {
    if let Lecture::Adopte(o) = lire_dans(dossier, nom)
        && repris_dans(dossier, nom)
        && sans_risque(&o)
    {
        let _ = ecrire_dans(dossier, nom, &o);
    }
}

/// Les sceaux ont-ils été refaits (effacés ou abîmés alors qu'une version qui scelle avait servi ici) ? Lu sans rien
/// écrire. Un fichier accepté tel quel lors d'une mise à jour (sceaux d'une version d'avant qui ne le protégeaient
/// pas encore) vient de Vanguard ; accepté tel quel quand les sceaux ont été refaits, il vient peut-être de qui les a
/// effacés : ce qui s'y fiait (un réglage qui coupe, un déjà vu, une note rejouée) ne s'y fie plus.
pub(crate) fn refaits_dans(dossier: &Path) -> bool {
    match registre(dossier) {
        Ok(Some(r)) => r.refaits,
        Ok(None) => deja_scelle(dossier),
        Err(()) => true,
    }
}

/// `nom` a-t-il été repris tel quel d'une version d'avant par une mise à jour connue (`Registre::repris`) ? Seul un tel
/// fichier adopté se croit. Lu sans rien écrire, mais comme une lecture le jugerait : des sceaux d'avant pas encore
/// rattrapés (au lancement, avant toute écriture) reprennent déjà ce que la mise à jour reprendra.
pub(crate) fn repris_dans(dossier: &Path, nom: &str) -> bool {
    match registre(dossier) {
        Ok(Some(r)) => rattraper_si(dossier, r, false).repris.contains(nom),
        _ => false,
    }
}

/// Des sceaux refaits ne restent pas « refaits » pour toujours : passé le mois où le bilan l'a dit, et sans plus aucun
/// fichier accepté tel quel (tous réécrits ou rescellés), l'alerte retombe.
fn apaiser_refaits_dans(dossier: &Path, aujourd_hui: chrono::NaiveDate) {
    let Ok(Some(r)) = registre(dossier) else {
        return;
    };
    let passe = |jour: &str| {
        chrono::NaiveDate::parse_from_str(jour, "%Y-%m-%d")
            .map_or(0, |d| aujourd_hui.signed_duration_since(d).num_days())
            > REFAITS_JOURS
    };
    let tous_crus = |r: &Registre| r.adoptes.iter().all(|n| r.repris.contains(n));
    // Ce qui retombe : « refaits », « version plus ancienne » et « sans journal », chacun passé son mois.
    let apaiser = |r: &mut Registre| {
        let mut change = false;
        if tous_crus(r) {
            if r.refaits && passe(&r.depuis) {
                r.refaits = false;
                change = true;
            }
            for jour in [&mut r.ancienne, &mut r.sans_journal] {
                if jour.as_deref().is_some_and(passe) {
                    *jour = None;
                    change = true;
                }
            }
        }
        change
    };
    if !apaiser(&mut r.clone()) {
        return;
    }
    let Ok(_verrou) = verrou_ecriture(dossier, REGISTRE) else {
        return;
    };
    if let Ok(Some(mut r)) = registre(dossier)
        && apaiser(&mut r)
    {
        let _ = enregistrer_registre(dossier, &r);
    }
}

/// Un « déjà vu » scellé (comptes administrateurs, appareils Bluetooth) : `Ok(Some)` tel que Vanguard l'a écrit (ou
/// accepté au premier usage, ce que le bilan dit), `Ok(None)` jamais écrit (un premier passage, muet), `Err(())`
/// effacé, changé hors de Vanguard ou illisible : rien n'y est tenu pour déjà vu, tout est redit. L'effacer, ou s'y
/// inscrire d'avance, taisait sinon « Nouveau compte administrateur cette semaine ».
pub(crate) fn deja_vus(nom: &str) -> Result<Option<Vec<u8>>, ()> {
    match lire(nom) {
        Lecture::Intact(o) => Ok(Some(o)),
        Lecture::Adopte(o) if repris_dans(&dossier(), nom) => Ok(Some(o)),
        Lecture::Absent => Ok(None),
        Lecture::Adopte(_) | Lecture::Falsifie(_) | Lecture::Inconnu | Lecture::Illisible(_) => Err(()),
    }
}

/// Ce que dit une alerte dont le « déjà vu » ne pouvait pas être cru (`deja_vus`).
pub(crate) fn redit() -> &'static str {
    tr!(
        " La liste de ce que Vanguard avait déjà vu a été effacée ou changée hors de Vanguard : tout ce qui est là est redit.",
        " The list of what Vanguard had already seen was deleted or changed outside Vanguard: everything there is reported again."
    )
}

/// Au bilan : rien tant que l'état de Vanguard est tel qu'il l'a écrit.
pub(crate) fn constat() -> Vec<Constat> {
    // Les fichiers protégés à la 0.87 et repris d'une version d'avant : rescellés s'ils ne coupent rien.
    crate::parametres::resceller_d_avant();
    crate::protection::blocage::parametres::resceller_d_avant();
    crate::changements::resceller_d_avant();
    crate::plugins::reglages::resceller_d_avant();
    // Les déjà vus et les clés connues : accepté lors d'une mise à jour, un fichier y vaut comme écrit par Vanguard.
    for nom in [ADMINISTRATEURS, BLUETOOTH, CLES_CONNUES] {
        resceller_si(nom, |_| true);
    }
    // Les fichiers scellés au lot S2c, repris d'une 0.87 : ce qu'elle y avait écrit, rescellé s'il se lit (sans quoi
    // l'alerte « acceptés tels quels » restait des semaines pour des fichiers que seule la personne réécrit).
    let se_lit = |o: &[u8]| std::str::from_utf8(o).is_ok();
    for nom in [
        PIEGES,
        PORTS_BLOQUES,
        APPAREILS,
        ENTRETIEN,
        SAUVEGARDE,
        SURVEILLANCE_PASSE,
        MANIFESTE_CLE,
    ] {
        resceller_si(nom, se_lit);
    }
    for nom in reprises_sous(&dossier(), MANIFESTES_CLE) {
        resceller_si(&nom, se_lit);
    }
    apaiser_refaits_dans(&dossier(), chrono::Local::now().date_naive());
    let mut r = falsifies_dans(&dossier());
    // Les fichiers des extensions ont leur propre constat, avec ce qu'il faut refaire (`plugins::constat_sceaux`) : le
    // « à faire » commun ne les réécrit pas.
    let des_extensions = |n: &&str| n.starts_with("plugins/");
    let extensions_falsifiees = r.falsifies.iter().any(des_extensions);
    let extensions = extensions_falsifiees || r.adoptes.iter().any(des_extensions);
    r.falsifies.retain(|n| !des_extensions(n));
    r.adoptes.retain(|n| !des_extensions(n));
    // L'état du veilleur réécrit sans sceau par le veilleur d'avant une mise à jour, qui tourne encore : pas une
    // falsification ; le bilan du veilleur dit le remède (le relancer).
    #[cfg(target_os = "linux")]
    if r.falsifies.contains(&VEILLEUR_ETAT) && crate::machine::linux::veilleur::etat_ecrit_par_l_ancien() {
        r.falsifies.retain(|n| *n != VEILLEUR_ETAT);
    }
    let aujourd_hui = chrono::Local::now().date_naive();
    let mut constats: Vec<Constat> = if r.refaits {
        juger_refaits(&r.adoptes, &r.depuis, aujourd_hui).into_iter().collect()
    } else if let Some(jour) = &r.ancienne {
        juger_ancienne(&r.adoptes, jour, aujourd_hui).into_iter().collect()
    } else if let Some(jour) = &r.sans_journal {
        juger_sans_journal(&r.adoptes, jour, aujourd_hui).into_iter().collect()
    } else {
        juger_adoptes(&r.adoptes, &r.depuis).into_iter().collect()
    };
    if !r.falsifies.is_empty() {
        constats.extend(juger_constat(
            &r.falsifies,
            r.illisibles,
            crate::mise_a_jour::copie_plus_ancienne(),
        ));
    }
    if extensions {
        constats.extend(crate::plugins::constat_sceaux(extensions_falsifiees));
    }
    // Après les lectures du bilan, qui ont essayé de le prendre.
    constats.extend(constat_verrou(&dossier()));
    constats
}

/// Ce fichier d'état a-t-il été accepté tel quel au premier usage, sans être réécrit depuis ?
pub(crate) fn adopte(nom: &str) -> bool {
    matches!(lire(nom), Lecture::Adopte(_))
}

/// Pourquoi un fichier d'état ne peut pas être cru (`juge`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Doute {
    /// Changé ou effacé hors de Vanguard.
    HorsVanguard,
    /// Accepté tel quel après des sceaux refaits : rien ne prouve qui l'a écrit.
    Adopte,
    /// Absent alors que les sceaux ont été refaits : peut-être effacé.
    Inconnu,
}

impl Doute {
    /// La raison, au masculin (« le fichier … »), pour quelqu'un qui ne connaît pas les sceaux.
    pub(crate) fn texte(self) -> &'static str {
        match self {
            Doute::HorsVanguard => tr!(
                "changé ou effacé hors de Vanguard",
                "changed or deleted outside Vanguard"
            ),
            Doute::Adopte => tr!(
                "accepté tel quel après l'effacement des sceaux de Vanguard (sceaux.json)",
                "accepted as it was after Vanguard's seals (sceaux.json) were deleted"
            ),
            Doute::Inconnu => tr!(
                "peut-être effacé : les sceaux de Vanguard (sceaux.json) ont été refaits",
                "perhaps deleted: Vanguard's seals (sceaux.json) were remade"
            ),
        }
    }
}

/// Ce qu'un lecteur peut croire d'un fichier d'état : le juge commun à tous (celui de `parametres::charger_juge`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Juge {
    /// Jamais écrit, ou oublié par Vanguard lui-même.
    Absent,
    /// Tel que Vanguard l'a écrit, ou repris tel quel d'une version d'avant le sceau lors de sa mise à jour.
    Cru(Vec<u8>),
    /// Ne vaut jamais un feu vert : rien de ce qu'il dit ne coupe une défense, ne tait une alerte ni ne donne un
    /// accord. Le contenu actuel, s'il y en a un, seulement pour le montrer ou le mettre de côté.
    Douteux(Doute, Option<Vec<u8>>),
    /// Là, mais il ne se lit pas : le pourquoi. Pas plus cru qu'un douteux.
    Illisible(String),
}

impl Juge {
    /// Le contenu, seulement s'il peut être cru.
    pub(crate) fn cru(self) -> Option<Vec<u8>> {
        match self {
            Juge::Cru(o) => Some(o),
            _ => None,
        }
    }
}

/// Le jugement d'une lecture : `repris` dit si le fichier, adopté, a été repris d'une version d'avant par une mise à
/// jour connue (`repris_dans`) ; toute autre adoption (premier usage, sceaux refaits, témoins effacés) ne vaut rien,
/// comme `voulues`. Seul un fichier adopté le demande.
pub(crate) fn juger_lecture(lu: Lecture, repris: impl FnOnce() -> bool) -> Juge {
    match lu {
        Lecture::Absent => Juge::Absent,
        Lecture::Intact(o) => Juge::Cru(o),
        Lecture::Adopte(o) if repris() => Juge::Cru(o),
        Lecture::Adopte(o) => Juge::Douteux(Doute::Adopte, Some(o)),
        Lecture::Falsifie(o) => Juge::Douteux(Doute::HorsVanguard, o),
        Lecture::Inconnu => Juge::Douteux(Doute::Inconnu, None),
        Lecture::Illisible(e) => Juge::Illisible(e),
    }
}

/// Un fichier d'état de `dossier`, jugé (`juger_lecture`).
pub(crate) fn juge_dans(dossier: &Path, nom: &str) -> Juge {
    juger_lecture(lire_dans(dossier, nom), || repris_dans(dossier, nom))
}

/// `juge_dans`, sans rien écrire ni créer (`lire_sans_ecrire`).
pub(crate) fn juge_sans_ecrire_dans(dossier: &Path, nom: &str) -> Juge {
    juger_lecture(lire_sans_ecrire(dossier, nom), || repris_dans(dossier, nom))
}

pub(crate) fn juge(nom: &str) -> Juge {
    juge_dans(&dossier(), nom)
}

/// Des sceaux tels que les laissait une version d'avant le lot S2c (forme 0, sans `vus`), avec la tête du journal
/// qu'elle a écrite et scellée (sans forme des sceaux) : ce qui est déjà là sera repris par la mise à jour. Pour les
/// essais qui rejouent une mise à jour.
#[cfg(test)]
pub(crate) fn sceaux_d_une_version_d_avant(dossier: &Path) {
    std::fs::create_dir_all(dossier).unwrap();
    let tete = crate::modele::journal::TETE;
    let o = br#"{"version":"0.87.0","segment":"2026-10","lignes":0,"derniere":""}"#;
    std::fs::write(dossier.join(tete), o).unwrap();
    let r = serde_json::json!({"depuis": "2026-10-01", "fichiers": {tete: empreinte(tete, o)}});
    std::fs::write(dossier.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
}

/// Les fichiers repris sous `sous` (« `manifestes-cle/<id>.json` »).
fn reprises_sous(dossier: &Path, sous: &str) -> Vec<String> {
    let prefixe = format!("{sous}/");
    registre(dossier).ok().flatten().map_or_else(Vec::new, |r| {
        r.repris.into_iter().filter(|n| n.starts_with(&prefixe)).collect()
    })
}

/// Les sceaux de `dossier` connaissent-ils un fichier sous `sous` (« manifestes-cle ») ? Un fichier effacé hors de
/// Vanguard y garde son sceau : il a existé. Lu sans rien écrire.
pub(crate) fn connus_sous(dossier: &Path, sous: &str) -> bool {
    let prefixe = format!("{sous}/");
    registre(dossier).is_ok_and(|r| r.is_some_and(|r| r.fichiers.keys().any(|n| n.starts_with(&prefixe))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-sceau-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn ecrit_par_vanguard_puis_change_a_cote() {
        let d = jetable("change");
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Absent);
        ecrire_dans(&d, APPRIS, br#"{"acceptees":{}}"#).unwrap();
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Intact(br#"{"acceptees":{}}"#.to_vec()));
        // Une ligne ajoutée par un autre programme : falsifié, avec ce qu'il contient maintenant.
        std::fs::write(d.join(APPRIS), br#"{"acceptees":{"x":1}}"#).unwrap();
        assert_eq!(
            lire_dans(&d, APPRIS),
            Lecture::Falsifie(Some(br#"{"acceptees":{"x":1}}"#.to_vec()))
        );
        assert_eq!(falsifies_dans(&d).falsifies, vec![APPRIS]);
        // Réécrit par Vanguard : de nouveau intact.
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        assert_eq!(falsifies_dans(&d), Releve::default());
        // Supprimé hors de Vanguard : la référence des fichiers critiques disparue ne doit pas passer pour « pas
        // encore de référence ».
        ecrire_dans(&d, INTEGRITE, b"{}").unwrap();
        std::fs::remove_file(d.join(INTEGRITE)).unwrap();
        assert_eq!(lire_dans(&d, INTEGRITE), Lecture::Falsifie(None));
        // Oublié par Vanguard lui-même : absent, sans alerte.
        effacer_dans(&d, INTEGRITE).unwrap();
        assert_eq!(lire_dans(&d, INTEGRITE), Lecture::Absent);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn un_sceau_ne_vaut_que_pour_son_fichier() {
        let d = jetable("echange");
        ecrire_dans(&d, BOTNETS, b"1.2.3.4").unwrap();
        // Les sceaux recopiés d'un fichier à l'autre, contenu compris : falsifié quand même.
        let mut r = registre(&d).unwrap().unwrap();
        let sceau = r.fichiers[BOTNETS].clone();
        r.fichiers.insert(APPRIS.into(), sceau);
        enregistrer_registre(&d, &r).unwrap();
        std::fs::write(d.join(APPRIS), b"1.2.3.4").unwrap();
        assert!(matches!(lire_dans(&d, APPRIS), Lecture::Falsifie(Some(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn les_fichiers_d_une_version_d_avant_sont_scelles_tels_quels() {
        let d = jetable("adoption");
        std::fs::create_dir_all(d.join("versions")).unwrap();
        std::fs::write(d.join(APPRIS), b"{}").unwrap();
        std::fs::write(d.join(VERSIONS), b"0.85.0+1792540000").unwrap();
        assert_eq!(lire_dans(&d, VERSIONS), Lecture::Adopte(b"0.85.0+1792540000".to_vec()));
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Adopte(b"{}".to_vec()));
        assert_ne!(registre(&d).unwrap().unwrap().depuis, "");
        // Réécrit par Vanguard : il n'est plus « adopté ».
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Intact(b"{}".to_vec()));
        // Ensuite, un fichier posé sans sceau (par un autre programme, ou par une copie d'avant les sceaux) ne l'est
        // plus : il est falsifié.
        std::fs::write(d.join(BOTNETS), b"5.6.7.8").unwrap();
        assert!(matches!(lire_dans(&d, BOTNETS), Lecture::Falsifie(Some(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Des sceaux abîmés ne rendent jamais un fichier « intact » : rien n'est cru tant que Vanguard ne l'a pas
    /// réécrit, et le constat le dit.
    #[test]
    fn des_sceaux_abimes_ne_font_rien_croire() {
        let d = jetable("abimes");
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        ecrire_dans(&d, BOTNETS, b"").unwrap();
        std::fs::write(d.join(REGISTRE), b"{ pas du json").unwrap();
        assert!(matches!(lire_dans(&d, APPRIS), Lecture::Falsifie(Some(_))));
        let r = falsifies_dans(&d);
        assert_eq!((r.falsifies, r.illisibles), (vec![APPRIS, BOTNETS], true));
        let c = juger_constat(&[APPRIS, BOTNETS], true, false).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("sceaux.json"), "{}", c.message);
        // Vanguard réécrit l'un : il repart de lui, l'autre reste falsifié.
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Intact(b"{}".to_vec()));
        assert!(matches!(lire_dans(&d, BOTNETS), Lecture::Falsifie(Some(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un programme du compte ajoute son alerte aux choix, puis efface les sceaux : le premier usage rejoué accepte
    /// la liste telle quelle, mais elle reste « adoptée », jamais intacte, et le bilan le dit.
    #[test]
    fn sceaux_effaces_jamais_en_silence() {
        let d = jetable("effaces");
        ecrire_dans(&d, APPRIS, br#"{"acceptees":{}}"#).unwrap();
        ecrire_dans(&d, BOTNETS, b"").unwrap();
        std::fs::write(d.join(APPRIS), br#"{"acceptees":{"x":1}}"#).unwrap();
        std::fs::remove_file(d.join(REGISTRE)).unwrap();
        assert_eq!(
            lire_dans(&d, APPRIS),
            Lecture::Adopte(br#"{"acceptees":{"x":1}}"#.to_vec())
        );
        let r = falsifies_dans(&d);
        assert_eq!((r.falsifies.len(), &r.adoptes), (0, &vec![APPRIS, BOTNETS]));
        let c = juger_adoptes(&r.adoptes, &r.depuis).unwrap();
        assert_eq!((c.categorie, c.probleme), (CAT, Some(Niveau::Moyen)));
        assert!(
            c.message.contains(APPRIS) && c.message.contains(&r.depuis),
            "{}",
            c.message
        );
        // Oublié par Vanguard : plus adopté.
        effacer_dans(&d, BOTNETS).unwrap();
        assert_eq!(falsifies_dans(&d).adoptes, vec![APPRIS]);
        assert!(juger_adoptes(&[], "").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un programme du compte efface les sceaux ET l'état de la machine (et la référence) : ce n'est pas un premier
    /// passage. Les fichiers absents se lisent « inconnus » (un état vide, tout est redit), jusqu'à ce que Vanguard
    /// les réécrive ; et le bilan dit que les sceaux ont été refaits, plus haut que de simples adoptés.
    #[test]
    fn sceaux_et_etat_effaces_ne_font_pas_un_premier_passage() {
        let d = jetable("disparus");
        // Une installation toute neuve : rien n'a jamais été écrit, c'est bien un premier passage.
        assert_eq!(lire_dans(&d, MACHINE), Lecture::Absent);
        assert!(!falsifies_dans(&d).refaits);
        std::fs::remove_file(d.join(REGISTRE)).unwrap();
        // Vanguard sert ici depuis un moment ; l'historique est effacé aussi (le verrou des sceaux, lui, reste).
        ecrire_dans(&d, MACHINE, br#"{"alertes":[]}"#).unwrap();
        ecrire_dans(&d, INTEGRITE, b"{}").unwrap();
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        for f in [REGISTRE, MACHINE, INTEGRITE] {
            std::fs::remove_file(d.join(f)).unwrap();
        }
        assert_eq!(lire_dans(&d, MACHINE), Lecture::Inconnu);
        assert_eq!(lire_dans(&d, INTEGRITE), Lecture::Inconnu);
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Adopte(b"{}".to_vec()));
        let r = falsifies_dans(&d);
        assert!(r.refaits);
        let jour = chrono::NaiveDate::parse_from_str(&r.depuis, "%Y-%m-%d").unwrap();
        let c = juger_refaits(&r.adoptes, &r.depuis, jour).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(
            c.message.contains(&r.depuis) && c.message.contains(APPRIS),
            "{}",
            c.message
        );
        // Plus rien d'adopté et plus d'un mois : on ne le redit plus.
        assert!(juger_refaits(&[], &r.depuis, jour + chrono::Days::new(31)).is_none());
        assert!(juger_refaits(&[APPRIS], &r.depuis, jour + chrono::Days::new(31)).is_some());
        // Réécrit par Vanguard : de nouveau connu.
        ecrire_dans(&d, MACHINE, b"{}").unwrap();
        assert_eq!(lire_dans(&d, MACHINE), Lecture::Intact(b"{}".to_vec()));
        effacer_dans(&d, INTEGRITE).unwrap();
        assert_eq!(lire_dans(&d, INTEGRITE), Lecture::Absent);
        // Des sceaux illisibles à côté d'un fichier supprimé : inconnu, pas absent.
        std::fs::write(d.join(REGISTRE), b"x").unwrap();
        std::fs::remove_file(d.join(MACHINE)).unwrap();
        assert_eq!(lire_dans(&d, MACHINE), Lecture::Inconnu);
        // Réécrits depuis cet état : les autres fichiers absents restent inconnus.
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        assert_eq!(lire_dans(&d, MACHINE), Lecture::Inconnu);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une 0.85 (avant les sceaux) mise à jour : son historique est là, sans sceaux ni leur verrou. Ce n'est pas des
    /// sceaux effacés : rien n'est « refait », la plus haute version vue est absente (pas inconnue, l'annonce des
    /// versions ne se tait pas) et le bilan ne dit rien de refait.
    #[test]
    fn une_version_d_avant_les_sceaux_n_est_pas_des_sceaux_refaits() {
        let d = jetable("v085");
        std::fs::write(d.join("historique.json"), b"[]").unwrap();
        std::fs::write(d.join("surveillance-passe.txt"), b"1792540000").unwrap();
        assert_eq!(lire_dans(&d, VERSIONS), Lecture::Absent);
        assert_eq!(lire_dans(&d, INTEGRITE), Lecture::Absent);
        let r = falsifies_dans(&d);
        assert!(!r.refaits);
        assert!(registre(&d).unwrap().unwrap().inconnus.is_empty());
        // Ensuite, le verrou est là : effacer les sceaux (même avec l'historique) les fait refaire.
        std::fs::remove_file(d.join(REGISTRE)).unwrap();
        std::fs::remove_file(d.join("historique.json")).unwrap();
        assert_eq!(lire_dans(&d, VERSIONS), Lecture::Inconnu);
        assert!(falsifies_dans(&d).refaits);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les sceaux, leur verrou et l'état de la machine effacés d'un coup : la tête du journal (ou un de ses segments),
    /// que seule une version qui scelle écrit, dit encore que Vanguard a servi ici. Ce n'est pas un premier passage.
    #[test]
    fn verrou_efface_avec_les_sceaux_n_est_pas_un_premier_usage() {
        for temoin in [crate::modele::journal::TETE, "evenements/2026-10.jsonl"] {
            let d = jetable("verrou-efface");
            ecrire_dans(&d, MACHINE, br#"{"alertes":[]}"#).unwrap();
            let t = d.join(temoin);
            std::fs::create_dir_all(t.parent().unwrap()).unwrap();
            std::fs::write(&t, b"{}").unwrap();
            for f in [REGISTRE, VERROU, MACHINE] {
                std::fs::remove_file(d.join(f)).unwrap();
            }
            assert_eq!(lire_dans(&d, MACHINE), Lecture::Inconnu, "{temoin}");
            assert!(falsifies_dans(&d).refaits, "{temoin}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// Un tube nommé ou un fichier énorme à la place d'un fichier d'état ou des sceaux : illisible tout de suite,
    /// jamais une lecture qui ne finit pas.
    #[cfg(unix)]
    #[test]
    fn un_tube_a_la_place_d_un_fichier_d_etat_ne_fige_rien() {
        let d = jetable("tube");
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        let tube = |chemin: &Path| {
            let _ = std::fs::remove_file(chemin);
            let c = std::ffi::CString::new(chemin.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY : mkfifo reçoit un chemin terminé par zéro, qui vit le temps de l'appel.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        };
        let debut = std::time::Instant::now();
        tube(&d.join(APPRIS));
        assert!(matches!(lire_dans(&d, APPRIS), Lecture::Illisible(_)));
        std::fs::remove_file(d.join(APPRIS)).unwrap();
        std::fs::File::create(d.join(APPRIS)).unwrap().set_len(8 << 30).unwrap();
        assert!(matches!(lire_dans(&d, APPRIS), Lecture::Illisible(_)));
        tube(&d.join(VERROU));
        tube(&d.join(REGISTRE));
        assert!(matches!(lire_dans(&d, APPRIS), Lecture::Illisible(_)));
        assert_eq!(lire_dans(&d, MACHINE), Lecture::Inconnu);
        assert!(
            debut.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            debut.elapsed()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un dossier posé à la place du verrou : plus aucun écrivain ne peut le tenir, et rien ne s'écrit sans lui (deux
    /// écrivains effaceraient l'un le sceau de l'autre) ; la lecture, elle, juge toujours.
    #[test]
    fn sans_verrou_rien_ne_s_ecrit() {
        let d = jetable("sans-verrou");
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        std::fs::remove_file(d.join(VERROU)).unwrap();
        std::fs::create_dir(d.join(VERROU)).unwrap();
        assert!(ecrire_dans(&d, APPRIS, b"{\"x\":1}").is_err());
        assert!(effacer_dans(&d, APPRIS).is_err());
        assert_eq!(std::fs::read(d.join(APPRIS)).unwrap(), b"{}");
        assert!(matches!(lire_dans(&d, APPRIS), Lecture::Intact(_)));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une version d'avant écrivait reglages.json sans sceau, à côté de sceaux existants : à la mise à jour, il est
    /// adopté une fois (pas falsifié) ; ensuite, un fichier protégé tard posé sans sceau est falsifié comme un autre.
    #[test]
    fn un_fichier_protege_tard_est_adopte_une_fois() {
        let d = jetable("tardif");
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        // Les sceaux de cette version d'avant : sans « vus », d'une forme d'avant.
        let mut r = registre(&d).unwrap().unwrap();
        r.vus.clear();
        r.format = 0;
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
        std::fs::write(d.join(REGLAGES), br#"{"reglages":{}}"#).unwrap();
        assert_eq!(lire_dans(&d, REGLAGES), Lecture::Adopte(br#"{"reglages":{}}"#.to_vec()));
        assert_eq!(lire_dans(&d, APPRIS), Lecture::Intact(b"{}".to_vec()));
        ecrire_dans(&d, REGLAGES, b"{}").unwrap();
        assert_eq!(lire_dans(&d, REGLAGES), Lecture::Intact(b"{}".to_vec()));
        // Passé ce premier regard : un fichier protégé tard posé sans sceau est falsifié.
        std::fs::write(d.join(NORMALES), b"{}").unwrap();
        assert!(matches!(lire_dans(&d, NORMALES), Lecture::Falsifie(Some(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn constat_selon_la_cause_probable() {
        assert!(juger_constat(&[], false, true).is_none());
        let c = juger_constat(&[INTEGRITE], false, false).unwrap();
        assert_eq!((c.categorie, c.probleme), (CAT, Some(Niveau::Eleve)));
        assert!(c.message.contains(INTEGRITE) && !c.message.contains("se-mettre-a-jour"));
        // Une copie plus ancienne écrit encore sans sceau : la cause probable est dite, un cran plus bas.
        let c = juger_constat(&[BOTNETS], false, true).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("se-mettre-a-jour"), "{}", c.message);
    }

    #[test]
    fn ecritures_en_meme_temps_sans_fausse_alerte() {
        let d = jetable("ensemble");
        let fils: Vec<_> = proteges()
            .map(|nom| {
                let d = d.clone();
                std::thread::spawn(move || {
                    for i in 0..20 {
                        ecrire_dans(&d, nom, format!("{nom} {i}").as_bytes()).unwrap();
                        let lu = lire_dans(&d, nom);
                        assert!(matches!(lu, Lecture::Intact(_)), "{nom}, écriture {i} : {lu:?}");
                    }
                })
            })
            .collect();
        for f in fils {
            f.join().unwrap();
        }
        assert_eq!(falsifies_dans(&d), Releve::default());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les sceaux d'une version d'avant l'inventaire n'ont pas de versions de format : ils se relisent tels quels, et
    /// la prochaine écriture note la version de chaque fichier qu'elle scelle.
    #[test]
    fn sceaux_sans_versions_relus_puis_completes() {
        let d = jetable("versions");
        ecrire_dans(&d, APPRIS, br#"{"acceptees":{}}"#).unwrap();
        let mut brut: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join(REGISTRE)).unwrap()).unwrap();
        assert_eq!(brut["versions"][APPRIS], 1);
        brut.as_object_mut().unwrap().remove("versions");
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&brut).unwrap()).unwrap();
        assert!(matches!(lire_dans(&d, APPRIS), Lecture::Intact(_)));
        ecrire_dans(&d, MACHINE, b"{}").unwrap();
        let r = registre(&d).unwrap().unwrap();
        assert_eq!(r.versions.get(MACHINE), Some(&1));
        assert_eq!(r.versions.get(APPRIS), None);
        effacer_dans(&d, MACHINE).unwrap();
        assert_eq!(registre(&d).unwrap().unwrap().versions.get(MACHINE), None);
        // Ce que protège le sceau, c'est l'inventaire qui le dit.
        assert_eq!(proteges().count(), crate::modele::inventaire::scelles().count());
        assert!(proteges().any(|n| n == WIFI_PUBLIC));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le juge commun : adopté lors d'une mise à jour, cru ; adopté après des sceaux refaits, changé, effacé ou
    /// inconnu, jamais cru.
    #[test]
    fn le_juge_ne_croit_que_ce_que_vanguard_a_ecrit() {
        let d = jetable("juge");
        assert_eq!(juge_dans(&d, PIEGES), Juge::Absent);
        ecrire_dans(&d, PIEGES, b"[]").unwrap();
        assert_eq!(juge_dans(&d, PIEGES), Juge::Cru(b"[]".to_vec()));
        std::fs::write(d.join(PIEGES), b"[1]").unwrap();
        assert_eq!(
            juge_dans(&d, PIEGES),
            Juge::Douteux(Doute::HorsVanguard, Some(b"[1]".to_vec()))
        );
        std::fs::remove_file(d.join(PIEGES)).unwrap();
        assert_eq!(juge_dans(&d, PIEGES), Juge::Douteux(Doute::HorsVanguard, None));
        // Les sceaux effacés : le fichier forgé est adopté, jamais cru ; l'absent est inconnu.
        std::fs::write(d.join(PIEGES), b"[2]").unwrap();
        ecrire_dans(&d, ENTRETIEN, b"{}").unwrap();
        std::fs::remove_file(d.join(ENTRETIEN)).unwrap();
        std::fs::remove_file(d.join(REGISTRE)).unwrap();
        assert_eq!(
            juge_dans(&d, PIEGES),
            Juge::Douteux(Doute::Adopte, Some(b"[2]".to_vec()))
        );
        assert_eq!(juge_dans(&d, ENTRETIEN), Juge::Douteux(Doute::Inconnu, None));
        assert_ne!(Doute::Adopte.texte(), "");
        let _ = std::fs::remove_dir_all(&d);
        // Sans aucun sceau (premier usage, ou tous les témoins effacés) : adopté, jamais cru.
        let d = jetable("juge-avant");
        std::fs::write(d.join(PIEGES), b"[]").unwrap();
        assert_eq!(
            juge_dans(&d, PIEGES),
            Juge::Douteux(Doute::Adopte, Some(b"[]".to_vec()))
        );
        let _ = std::fs::remove_dir_all(&d);
        // Les sceaux d'une version d'avant qui ne le protégeait pas encore : repris par la mise à jour, cru.
        let d = jetable("juge-mise-a-jour");
        sceaux_d_une_version_d_avant(&d);
        std::fs::write(d.join(PIEGES), b"[]").unwrap();
        assert_eq!(juge_dans(&d, PIEGES), Juge::Cru(b"[]".to_vec()));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les références des clés, nommées par leur volume : adoptées une fois à la mise à jour (des sceaux d'avant qui
    /// ne les connaissaient pas), puis une référence posée sans sceau est falsifiée ; effacée, son sceau dit qu'elle
    /// a existé.
    #[test]
    fn un_dossier_protege_tard_est_adopte_une_fois() {
        let d = jetable("tardif-dossier");
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        ecrire_dans(&d, crate::modele::journal::TETE, br#"{"version":"0.87.0"}"#).unwrap();
        let mut r = registre(&d).unwrap().unwrap();
        r.vus.clear();
        r.format = 0;
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
        std::fs::create_dir_all(d.join(MANIFESTES_CLE)).unwrap();
        let ref_a = format!("{MANIFESTES_CLE}/1A2B-3C4D.json");
        std::fs::write(d.join(&ref_a), b"{}").unwrap();
        assert_eq!(lire_dans(&d, &ref_a), Lecture::Adopte(b"{}".to_vec()));
        assert_eq!(juge_dans(&d, &ref_a), Juge::Cru(b"{}".to_vec()));
        let ref_b = format!("{MANIFESTES_CLE}/5E6F-7A8B.json");
        std::fs::write(d.join(&ref_b), b"{}").unwrap();
        assert!(matches!(lire_dans(&d, &ref_b), Lecture::Falsifie(Some(_))));
        assert!(connus_sous(&d, MANIFESTES_CLE));
        std::fs::remove_file(d.join(&ref_a)).unwrap();
        assert_eq!(lire_dans(&d, &ref_a), Lecture::Falsifie(None));
        let _ = std::fs::remove_dir_all(&d);
        // Au tout premier usage, celles déjà là sont adoptées, et une nouvelle posée ensuite sans sceau est falsifiée.
        let d = jetable("tardif-dossier-premier");
        std::fs::create_dir_all(d.join(MANIFESTES_CLE)).unwrap();
        std::fs::write(d.join(&ref_a), b"{}").unwrap();
        assert_eq!(lire_dans(&d, &ref_a), Lecture::Adopte(b"{}".to_vec()));
        std::fs::write(d.join(&ref_b), b"{}").unwrap();
        assert!(matches!(lire_dans(&d, &ref_b), Lecture::Falsifie(Some(_))));
        assert!(!connus_sous(&jetable("tardif-vide"), MANIFESTES_CLE));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// S2c (arbitrage) : sceaux de cette forme, un nom retiré de leurs `vus` et de leurs `fichiers` à la main, le
    /// fichier posé : pas une mise à jour, falsifié.
    #[test]
    fn un_nom_retire_des_sceaux_n_est_pas_une_mise_a_jour() {
        let d = jetable("retire-des-vus");
        ecrire_dans(&d, TEMPS_REEL, b"{}").unwrap();
        let mut r = registre(&d).unwrap().unwrap();
        r.vus.remove(TEMPS_REEL);
        r.fichiers.remove(TEMPS_REEL);
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
        std::fs::write(d.join(TEMPS_REEL), br#"{"coupee_le":1792000000}"#).unwrap();
        assert!(matches!(
            juge_dans(&d, TEMPS_REEL),
            Juge::Douteux(Doute::HorsVanguard, Some(_))
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// S2c (Opus 1 et 2) : chez qui les sceaux ont été refaits un jour, une mise à jour reprend les nouveaux fichiers
    /// (crus, jamais listés comme « acceptés tels quels »), le bilan les rescelle, et « refaits » retombe passé le mois.
    #[test]
    fn une_mise_a_jour_apres_des_sceaux_refaits_un_jour() {
        let d = jetable("refaits-un-jour");
        std::fs::write(d.join(VERROU), b"").unwrap();
        sceaux_d_une_version_d_avant(&d);
        let mut r: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join(REGISTRE)).unwrap()).unwrap();
        r["depuis"] = "2026-08-01".into();
        r["refaits"] = true.into();
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
        std::fs::write(d.join(PORTS_BLOQUES), b"11434/tcp\n").unwrap();
        assert_eq!(juge_dans(&d, PORTS_BLOQUES), Juge::Cru(b"11434/tcp\n".to_vec()));
        let r = falsifies_dans(&d);
        assert!(r.refaits && r.adoptes.is_empty(), "{r:?}");
        resceller_si_dans(&d, PORTS_BLOQUES, |_| true);
        assert!(matches!(lire_dans(&d, PORTS_BLOQUES), Lecture::Intact(_)));
        // Un mois passé, plus rien d'accepté tel quel : l'alerte retombe.
        let jour = chrono::NaiveDate::from_ymd_opt(2026, 8, 15).unwrap();
        apaiser_refaits_dans(&d, jour);
        assert!(refaits_dans(&d));
        apaiser_refaits_dans(&d, jour + chrono::Days::new(30));
        assert!(!refaits_dans(&d));
        // Un fichier adopté au premier usage (pas repris), lui, n'est jamais rescellé.
        let d2 = jetable("premier-usage-pas-rescelle");
        std::fs::write(d2.join(PORTS_BLOQUES), b"4444/tcp\n").unwrap();
        resceller_si_dans(&d2, PORTS_BLOQUES, |_| true);
        assert!(matches!(lire_dans(&d2, PORTS_BLOQUES), Lecture::Adopte(_)));
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&d2);
    }

    /// F4 (E-M1) : une vraie mise à jour depuis une 0.87 reprend ce qu'elle ne scellait pas encore, et le croit.
    #[test]
    fn une_vraie_mise_a_jour_depuis_une_087_reprend() {
        assert_eq!(
            TARDIFS[TARDIFS_D_AVANT - 1],
            crate::protection::blocage::parametres::BLOCAGE
        );
        let d = jetable("vraie-087");
        ecrire_dans(&d, crate::parametres::PARAMETRES, br#"{"hors_ligne":false}"#).unwrap();
        // Sa tête de journal, écrite par elle : sans forme des sceaux.
        ecrire_dans(
            &d,
            crate::modele::journal::TETE,
            br#"{"version":"0.87.0","segment":"2026-10"}"#,
        )
        .unwrap();
        // Ses sceaux : forme 0, ses fichiers protégés tard vus.
        let mut r = registre(&d).unwrap().unwrap();
        r.format = 0;
        r.vus = TARDIFS[..TARDIFS_D_AVANT].iter().map(|n| (*n).to_string()).collect();
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
        std::fs::write(d.join(PIEGES), b"[]").unwrap();
        assert_eq!(juge_dans(&d, PIEGES), Juge::Cru(b"[]".to_vec()));
        assert!(repris_dans(&d, PIEGES) && !refaits_dans(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un dossier où cette forme-ci a servi (un réglage écrit, un événement noté), dont les sceaux sont ramenés à une
    /// forme d'avant comme le ferait qui veut faire reprendre un `parametres.json` forgé : `format` à 0, plus de
    /// `repris`, `parametres.json` retiré des `vus` et des `fichiers`, et seulement les `vus` d'avant.
    fn ramene(nom: &str, abimer: impl FnOnce(&Path, &mut Registre)) -> PathBuf {
        let d = jetable(nom);
        ecrire_dans(&d, crate::parametres::PARAMETRES, br#"{"hors_ligne":false}"#).unwrap();
        crate::modele::journal::noter_dans(
            &d,
            crate::modele::evenement::Evenement::action(crate::modele::evenement::Source::Blocage, "bloqué", true, &[]),
            chrono::Utc::now(),
        )
        .unwrap();
        let mut r = registre(&d).unwrap().unwrap();
        r.format = 0;
        r.refaits = false;
        r.repris.clear();
        r.vus.remove(crate::parametres::PARAMETRES);
        r.fichiers.remove(crate::parametres::PARAMETRES);
        r.vus.retain(|n| TARDIFS[..TARDIFS_D_AVANT].contains(&n.as_str()));
        abimer(&d, &mut r);
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
        d
    }

    const FORGE: &[u8] = br#"{"hors_ligne":true,"sans_autotest":true}"#;

    /// F4 (E-M1) : des sceaux ramenés à une forme d'avant sans la preuve d'une vraie mise à jour (la tête du journal,
    /// présente, scellée telle quelle, écrite par une version d'avant) ne font rien reprendre : le `parametres.json`
    /// forgé est accepté tel quel sans être cru, et le bilan dit les sceaux refaits. Tête effacée avec le journal,
    /// tête réécrite sans sa forme, tête retirée des sceaux : aucune ne le fait passer.
    #[test]
    fn un_format_qui_recule_ne_fait_rien_reprendre() {
        type Abimer = fn(&Path, &mut Registre);
        let cas: [(&str, Abimer); 4] = [
            ("journal-efface", |d, r| {
                std::fs::remove_file(d.join(crate::modele::journal::TETE)).unwrap();
                std::fs::remove_dir_all(d.join(crate::modele::journal::DOSSIER)).unwrap();
                r.fichiers.retain(|n, _| !n.starts_with("evenements"));
            }),
            ("tete-effacee", |d, _| {
                std::fs::remove_file(d.join(crate::modele::journal::TETE)).unwrap();
            }),
            ("tete-sans-forme", |d, _| {
                std::fs::write(
                    d.join(crate::modele::journal::TETE),
                    br#"{"version":"0.87.0","segment":"2026-10"}"#,
                )
                .unwrap();
            }),
            ("tete-hors-des-sceaux", |d, r| {
                std::fs::write(
                    d.join(crate::modele::journal::TETE),
                    br#"{"version":"0.87.0","segment":"2026-10"}"#,
                )
                .unwrap();
                r.fichiers.remove(crate::modele::journal::TETE);
            }),
        ];
        for (nom, abimer) in cas {
            let d = ramene(&format!("recule-{nom}"), abimer);
            std::fs::write(d.join(crate::parametres::PARAMETRES), FORGE).unwrap();
            assert!(!repris_dans(&d, crate::parametres::PARAMETRES), "{nom}");
            assert_eq!(
                juge_dans(&d, crate::parametres::PARAMETRES),
                Juge::Douteux(Doute::Adopte, Some(FORGE.to_vec())),
                "{nom}"
            );
            let rel = falsifies_dans(&d);
            assert!(
                rel.refaits && rel.adoptes.contains(&crate::parametres::PARAMETRES),
                "{nom} : {rel:?}"
            );
            assert!(registre(&d).unwrap().unwrap().repris.is_empty(), "{nom}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// F4 (E-M1) : le seul champ `format` ramené à 0, la tête du journal intacte et écrite par cette forme : comme une
    /// version plus ancienne repassée ici, rien n'est repris ni adopté, le `parametres.json` forgé reste falsifié.
    #[test]
    fn un_format_seul_ramene_ne_fait_rien_reprendre() {
        let d = ramene("format-seul", |_, _| {});
        std::fs::write(d.join(crate::parametres::PARAMETRES), FORGE).unwrap();
        assert!(!repris_dans(&d, crate::parametres::PARAMETRES));
        assert_eq!(
            lire_dans(&d, crate::parametres::PARAMETRES),
            Lecture::Falsifie(Some(FORGE.to_vec()))
        );
        let rel = falsifies_dans(&d);
        assert!(rel.falsifies.contains(&crate::parametres::PARAMETRES), "{rel:?}");
        assert!(!rel.refaits && rel.ancienne.is_some(), "{rel:?}");
        assert!(registre(&d).unwrap().unwrap().repris.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// F4 (relecture) : 0.87, puis cette version, puis la 0.87 de nouveau (une clé ou un Mac restés en arrière), puis
    /// cette version : la 0.87 a réécrit la tête du journal et les sceaux à sa façon (sans leur forme ni `repris`).
    /// Pas « sceaux effacés ou abîmés hors de Vanguard » (élevé) : une version plus ancienne a servi ici, dit moyen,
    /// et rien de ce qu'elle a laissé n'est repris.
    #[test]
    fn une_version_plus_ancienne_repassee_se_dit_sans_rien_reprendre() {
        let d = jetable("ancienne-repassee");
        ecrire_dans(&d, crate::parametres::PARAMETRES, br#"{"hors_ligne":false}"#).unwrap();
        // La 0.87 de retour : elle réécrit, scellées, sa tête de journal (sans forme des sceaux) et un fichier qu'elle
        // connaît, et ses sceaux perdent les champs qu'elle ne connaît pas.
        ecrire_dans(
            &d,
            crate::modele::journal::TETE,
            br#"{"version":"0.87.0","segment":"2026-10"}"#,
        )
        .unwrap();
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        let mut r = registre(&d).unwrap().unwrap();
        r.format = 0;
        r.repris.clear();
        r.adoptes.insert(APPRIS.to_string());
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
        // Un fichier qu'elle ne scelle pas, posé hors des sceaux : pas adopté pour autant.
        std::fs::write(d.join(PIEGES), b"[]").unwrap();
        assert!(!repris_dans(&d, APPRIS));
        assert!(matches!(lire_dans(&d, PIEGES), Lecture::Falsifie(_)));
        assert_eq!(
            juge_dans(&d, APPRIS),
            Juge::Douteux(Doute::Adopte, Some(b"{}".to_vec()))
        );
        let rel = falsifies_dans(&d);
        assert!(!rel.refaits && rel.ancienne.is_some(), "{rel:?}");
        assert_eq!(rel.adoptes, vec![APPRIS]);
        let r = registre(&d).unwrap().unwrap();
        assert!(r.repris.is_empty() && !r.refaits && r.format == FORMAT);
        let jour = chrono::Local::now().date_naive();
        let c = juger_ancienne(&rel.adoptes, rel.ancienne.as_deref().unwrap(), jour).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains(APPRIS), "{}", c.message);
        // Un mois plus tard, sans plus rien d'accepté tel quel : plus rien à dire.
        assert!(juger_ancienne(&[], rel.ancienne.as_deref().unwrap(), jour + chrono::Days::new(31)).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Des sceaux d'une 0.87 qui n'avait encore rien noté au journal (ni tête, ni segment, ni verrou), avec un
    /// `parametres.json` qu'elle ne scellait pas.
    fn sceaux_d_avant_sans_journal(nom: &str) -> PathBuf {
        let d = jetable(nom);
        std::fs::write(d.join(REGISTRE), br#"{"depuis":"2026-10-01","fichiers":{}}"#).unwrap();
        std::fs::write(d.join(crate::parametres::PARAMETRES), FORGE).unwrap();
        d
    }

    /// F4 (relecture du delta) : une 0.86 ou une 0.87 qui n'avait rien noté au journal, mise à jour. Rien n'est repris
    /// (rien ne prouve la mise à jour), mais ce n'est pas « sceaux effacés ou abîmés » (élevé) : dit moyen, avec les
    /// deux causes possibles, un mois ou tant qu'un fichier accepté n'est pas réécrit. La moindre trace du journal
    /// (tête scellée, segment, verrou de Vanguard ou du système) le refait dire comme des sceaux refaits.
    #[test]
    fn des_sceaux_d_avant_sans_journal_se_disent_moyen_sans_rien_reprendre() {
        type Trace = fn(&Path);
        let d = sceaux_d_avant_sans_journal("sans-journal");
        assert!(!repris_dans(&d, crate::parametres::PARAMETRES));
        assert_eq!(
            juge_dans(&d, crate::parametres::PARAMETRES),
            Juge::Douteux(Doute::Adopte, Some(FORGE.to_vec()))
        );
        let rel = falsifies_dans(&d);
        assert!(!rel.refaits && rel.ancienne.is_none(), "{rel:?}");
        assert!(rel.sans_journal.is_some(), "{rel:?}");
        assert_eq!(rel.adoptes, vec![crate::parametres::PARAMETRES]);
        assert!(registre(&d).unwrap().unwrap().repris.is_empty());
        let jour = chrono::Local::now().date_naive();
        let c = juger_sans_journal(&rel.adoptes, rel.sans_journal.as_deref().unwrap(), jour).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(
            c.message.contains(crate::parametres::PARAMETRES) && c.message.contains("ramenés en arrière"),
            "{}",
            c.message
        );
        assert!(juger_sans_journal(&[], rel.sans_journal.as_deref().unwrap(), jour + chrono::Days::new(31)).is_none());
        let _ = std::fs::remove_dir_all(&d);
        let traces: [(&str, Trace); 4] = [
            ("segment", |d| {
                std::fs::create_dir(d.join(crate::modele::journal::DOSSIER)).unwrap();
            }),
            ("verrou", |d| {
                std::fs::write(d.join(crate::modele::journal::VERROU), b"").unwrap();
            }),
            ("verrou-systeme", |d| {
                std::fs::write(d.join("evenements.lock"), b"").unwrap();
            }),
            ("tete-scellee", |d| {
                let mut r: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(d.join(REGISTRE)).unwrap()).unwrap();
                r["fichiers"][crate::modele::journal::TETE] = "0".repeat(64).into();
                std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
            }),
        ];
        for (nom, laisser) in traces {
            let d = sceaux_d_avant_sans_journal(&format!("trace-{nom}"));
            laisser(&d);
            assert!(!repris_dans(&d, crate::parametres::PARAMETRES), "{nom}");
            let _ = juge_dans(&d, crate::parametres::PARAMETRES);
            let rel = falsifies_dans(&d);
            assert!(rel.refaits && rel.sans_journal.is_none(), "{nom} : {rel:?}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// F4 (relecture du delta) : « une version plus ancienne a servi ici » ne reste pas pour toujours. Des sceaux
    /// refaits ensuite l'effacent (ils disent déjà tout, plus haut) ; sinon il retombe passé son mois, une fois chaque
    /// fichier accepté tel quel réécrit, comme « sans journal ».
    #[test]
    fn une_version_plus_ancienne_ne_se_dit_pas_toujours() {
        // Refaits après : effacée.
        let d = sceaux_d_avant_sans_journal("ancienne-puis-refaits");
        std::fs::write(d.join(crate::modele::journal::VERROU), b"").unwrap();
        let mut r: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join(REGISTRE)).unwrap()).unwrap();
        r["ancienne"] = "2026-09-01".into();
        r["sans_journal"] = "2026-09-01".into();
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
        let _ = juge_dans(&d, crate::parametres::PARAMETRES);
        let rel = falsifies_dans(&d);
        assert!(
            rel.refaits && rel.ancienne.is_none() && rel.sans_journal.is_none(),
            "{rel:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
        // Passé le mois : retombée, mais pas tant qu'un fichier accepté tel quel n'est pas réécrit.
        let d = jetable("ancienne-apaisee");
        let mut r = Registre {
            format: FORMAT,
            depuis: "2026-08-01".into(),
            ancienne: Some("2026-08-01".into()),
            sans_journal: Some("2026-08-01".into()),
            ..Registre::default()
        };
        r.adoptes.insert(APPRIS.to_string());
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
        let jour = chrono::NaiveDate::from_ymd_opt(2026, 8, 15).unwrap();
        apaiser_refaits_dans(&d, jour + chrono::Days::new(60));
        let lu = registre(&d).unwrap().unwrap();
        assert!(lu.ancienne.is_some() && lu.sans_journal.is_some());
        r.adoptes.clear();
        std::fs::write(d.join(REGISTRE), serde_json::to_vec(&r).unwrap()).unwrap();
        apaiser_refaits_dans(&d, jour);
        let lu = registre(&d).unwrap().unwrap();
        assert!(lu.ancienne.is_some() && lu.sans_journal.is_some());
        apaiser_refaits_dans(&d, jour + chrono::Days::new(30));
        let lu = registre(&d).unwrap().unwrap();
        assert!(lu.ancienne.is_none() && lu.sans_journal.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// F4 (E-M2) : le verrou des sceaux gardé par un autre programme ne fait plus attendre chaque écriture toute
    /// l'attente (un refus, puis presque rien), et il se dit : au bilan, et au journal des événements, qui n'est plus
    /// lu « intact ». Rendu, tout repart.
    #[test]
    fn verrou_tenu_ailleurs_court_et_dit() {
        let d = jetable("verrou-tenu");
        ecrire_dans(&d, APPRIS, b"{}").unwrap();
        crate::modele::journal::noter_dans(
            &d,
            crate::modele::evenement::Evenement::action(crate::modele::evenement::Source::Blocage, "bloqué", true, &[]),
            chrono::Utc::now(),
        )
        .unwrap();
        assert!(matches!(
            crate::modele::journal::lire_dans(&d).lecture,
            crate::modele::journal::Lecture::Intact
        ));
        ATTENTE_ESSAI.with(|a| a.set(Some(std::time::Duration::from_secs(3))));
        let tenu = crate::socle::Verrou::prendre(&d, VERROU, false, std::time::Duration::ZERO).unwrap();
        let debut = std::time::Instant::now();
        assert!(ecrire_dans(&d, APPRIS, b"{\"x\":1}").is_err());
        assert!(debut.elapsed() >= std::time::Duration::from_secs(3));
        assert!(verrou_tenu_dans(&d) && constat_verrou(&d).is_some());
        // Déjà refusé : les suivants n'attendent plus, tous ensemble, que `ATTENTE_APRES_REFUS`.
        let debut = std::time::Instant::now();
        for _ in 0..5 {
            assert!(ecrire_dans(&d, APPRIS, b"{\"x\":1}").is_err());
            assert!(matches!(lire_dans(&d, APPRIS), Lecture::Intact(_)));
        }
        assert!(
            debut.elapsed() < ATTENTE_APRES_REFUS + std::time::Duration::from_secs(1),
            "{:?}",
            debut.elapsed()
        );
        assert!(!matches!(
            crate::modele::journal::lire_dans(&d).lecture,
            crate::modele::journal::Lecture::Intact
        ));
        drop(tenu);
        ecrire_dans(&d, APPRIS, b"{\"x\":1}").unwrap();
        assert!(!verrou_tenu_dans(&d) && constat_verrou(&d).is_none());
        ATTENTE_ESSAI.with(|a| a.set(None));
        let _ = std::fs::remove_dir_all(&d);
    }
}
