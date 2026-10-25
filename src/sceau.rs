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
    // Écrits sans sceau jusqu'à la 0.87 : adoptés une fois, mais jamais un feu vert (`plugins::reglages::lire_juge`).
    crate::plugins::reglages::SCELLE,
    crate::plugins::APPROUVES_SCELLE,
];

const REGISTRE: &str = "sceaux.json";
const VERROU: &str = "sceaux.verrou";

/// Les sceaux : depuis quand (AAAA-MM-JJ), l'empreinte de chaque fichier tel que Vanguard l'a écrit, et ceux qui
/// ont été scellés tels quels au premier usage, sans que Vanguard les ait écrits depuis.
#[derive(Serialize, Deserialize, Default)]
struct Registre {
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
}

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
    crate::socle::Verrou::prendre(dossier, VERROU, false, crate::socle::ATTENTE_ECRITURE).map_err(|e| {
        let e = e.erreur(VERROU);
        crate::modele::Echec::echoue("sceau/ecrire", format!("{nom} : {e}")).journaliser();
        e
    })
}

/// Le verrou d'un lecteur. Exclusif là où il peut écrire : au premier usage ou pour un fichier protégé tard, la lecture
/// note ce qu'elle adopte dans le registre (`ecrire`). Ailleurs (le dossier d'un autre compte, un autotest, le
/// processus élevé) partagé, sans rien créer. Sans verrou, rien n'est noté, et la lecture juge quand même : un
/// verrou qui ne s'ouvre pas n'est tenu par aucun écrivain, et tenu au-delà de l'attente, c'est un Vanguard figé ;
/// dire « pas jugé » laisserait sinon n'importe quel programme qui le garde faire taire les falsifications.
fn verrou_lecture(dossier: &Path, ecrire: bool) -> (Option<crate::socle::Verrou>, bool) {
    let ecrire = ecrire && crate::socle::ecriture_sure(dossier);
    match crate::socle::Verrou::prendre(dossier, VERROU, !ecrire, crate::socle::ATTENTE_LECTURE) {
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
    crate::socle::ecrire_atomique(
        &dossier.join(REGISTRE),
        serde_json::to_vec_pretty(r).map_err(std::io::Error::other)?,
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

/// Le contenu d'un fichier d'état, `Ok(None)` s'il n'existe pas.
fn contenu(chemin: &Path) -> Result<Option<Vec<u8>>, String> {
    match crate::socle::lire_ordinaire(chemin, TAILLE_MAX) {
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
    r.vus = TARDIFS.iter().map(|n| (*n).to_string()).collect();
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

/// `rattraper`, et seulement s'il le faut (`ecrire`), noté dans les sceaux.
fn rattraper_si(dossier: &Path, mut r: Registre, ecrire: bool) -> Registre {
    let mut change = false;
    for nom in TARDIFS.iter().copied() {
        if r.vus.contains(nom) {
            continue;
        }
        if !r.fichiers.contains_key(nom)
            && let Ok(Some(o)) = contenu(&dossier.join(nom))
        {
            r.fichiers.insert(nom.to_string(), empreinte(nom, &o));
            r.adoptes.insert(nom.to_string());
        }
        r.vus.insert(nom.to_string());
        change = true;
    }
    if change && ecrire {
        let _ = enregistrer_registre(dossier, &r);
    }
    r
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
            depuis: chrono::Local::now().format("%Y-%m-%d").to_string(),
            vus: TARDIFS.iter().map(|n| (*n).to_string()).collect(),
            refaits: true,
            inconnus: proteges().map(str::to_string).collect(),
            ..Registre::default()
        },
    };
    sceaux.inconnus.remove(nom);
    crate::socle::ecrire_atomique(&dossier.join(nom), octets)?;
    sceaux.fichiers.insert(nom.to_string(), empreinte(nom, octets));
    sceaux.adoptes.remove(nom);
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
            | r.versions.remove(nom).is_some()
            | r.inconnus.remove(nom))
    {
        enregistrer_registre(dossier, &r)?;
    }
    Ok(())
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
    if let Ok(Some(s)) = registre(dossier)
        && (!r.adoptes.is_empty() || s.refaits)
    {
        r.refaits = s.refaits;
        r.depuis = s.depuis;
    }
    r
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
/// qu'on change un réglage. Jamais après des sceaux refaits.
pub(crate) fn resceller_si(nom: &str, sans_risque: impl Fn(&[u8]) -> bool) {
    // Accepté quand les sceaux ont été refaits : rien n'est rescellé, l'alerte reste.
    if refaits() {
        return;
    }
    if let Lecture::Adopte(o) = lire(nom)
        && sans_risque(&o)
    {
        let _ = ecrire(nom, &o);
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

pub(crate) fn refaits() -> bool {
    refaits_dans(&dossier())
}

/// Un « déjà vu » scellé (comptes administrateurs, appareils Bluetooth) : `Ok(Some)` tel que Vanguard l'a écrit (ou
/// accepté au premier usage, ce que le bilan dit), `Ok(None)` jamais écrit (un premier passage, muet), `Err(())`
/// effacé, changé hors de Vanguard ou illisible : rien n'y est tenu pour déjà vu, tout est redit. L'effacer, ou s'y
/// inscrire d'avance, taisait sinon « Nouveau compte administrateur cette semaine ».
pub(crate) fn deja_vus(nom: &str) -> Result<Option<Vec<u8>>, ()> {
    match lire(nom) {
        Lecture::Intact(o) => Ok(Some(o)),
        Lecture::Adopte(o) if !refaits() => Ok(Some(o)),
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
    let mut r = falsifies_dans(&dossier());
    // Les fichiers des extensions ont leur propre constat, avec ce qu'il faut refaire (`plugins::constat_sceaux`) : le
    // « à faire » commun ne les réécrit pas.
    let des_extensions = |n: &&str| n.starts_with("plugins/");
    let extensions_falsifiees = r.falsifies.iter().any(des_extensions);
    let extensions = extensions_falsifiees || r.adoptes.iter().any(des_extensions);
    r.falsifies.retain(|n| !des_extensions(n));
    r.adoptes.retain(|n| !des_extensions(n));
    let mut constats: Vec<Constat> = if r.refaits {
        juger_refaits(&r.adoptes, &r.depuis, chrono::Local::now().date_naive())
            .into_iter()
            .collect()
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
    constats
}

/// Ce fichier d'état a-t-il été accepté tel quel au premier usage, sans être réécrit depuis ?
pub(crate) fn adopte(nom: &str) -> bool {
    matches!(lire(nom), Lecture::Adopte(_))
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
        // Les sceaux de cette version d'avant : sans « vus ».
        let mut r = registre(&d).unwrap().unwrap();
        r.vus.clear();
        enregistrer_registre(&d, &r).unwrap();
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
}
