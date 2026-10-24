//! Ce que Vanguard a changé : chaque correction lancée après accord (commandes, date, réussie ou non) est notée sur cet
//! ordinateur seulement (changements.jsonl, jamais sur la clé ni ailleurs), et se relit au menu Cette machine ou par
//! `vanguard changements`. Les réglages d'Optimiser et les corrections du bilan qui le peuvent gardent en plus leur
//! valeur d'avant (reglages.json, `optimiser::annulables`), pour s'annuler exactement : une correction s'annule ici,
//! une à une ; un blocage (protection/blocage) garde de quoi se défaire exactement, et `vanguard blocage annuler` le
//! défait. « Tout remettre comme avant » (`annulation`) défait le tout.

use serde::{Deserialize, Serialize};

use crate::ui::*;

/// Au-delà, les plus anciens partent : le fichier ne grossit pas sans fin.
const GARDES: usize = 500;
/// Et au-delà de cette taille aussi (les preuves des blocages pèsent) : le relevé scellé doit se relire en entier
/// (`sceau`, 4 Mio au plus).
const OCTETS_GARDES: usize = 3 << 20;

/// D'où vient une ligne du relevé qui n'a pas été relue scellée telle que Vanguard l'a écrite. Notée dans la ligne
/// même, puis scellée avec elle : réécrire le relevé ne la blanchit pas.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Origine {
    /// Écrite par une version d'avant le sceau du relevé (acceptée telle quelle au premier usage, ou sceaux refaits).
    Avant,
    /// Trouvée dans un relevé changé hors de Vanguard.
    HorsVanguard,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Changement {
    /// « AAAA-MM-JJ HH:MM ».
    date: String,
    commandes: Vec<String>,
    reussi: bool,
    /// Un blocage de menace : ce qui a été bloqué, et ce qui l'annule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocage: Option<Blocage>,
    /// Une correction du bilan qui se défait : l'id de la note qui garde ses valeurs d'avant (reglages.json).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    annulable: Option<String>,
    /// La date où elle a été défaite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    defaite: Option<String>,
    /// L'événement Action du journal commun (`modele::journal`) : l'annulation s'y relie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evenement: Option<String>,
    /// `None` : écrite par Vanguard et relue sous son sceau.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origine: Option<Origine>,
}

/// Un blocage noté : de quoi le montrer, le reconnaître et l'annuler exactement.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Blocage {
    /// Unique sur cet ordinateur : c'est par lui qu'on l'annule.
    pub id: String,
    /// La menace (« connexion:203.0.113.7 ») : tant que le blocage est en place, elle n'est pas reproposée.
    pub cle: String,
    /// Ce qui a été fait, et pourquoi, prêt à montrer.
    pub quoi: String,
    /// Fait tout seul par la protection active (sinon, après un clic).
    #[serde(default)]
    pub automatique: bool,
    /// Ce qui le défait ; `None` : rien à défaire (un processus arrêté sans fichier ne se relance pas d'ici).
    pub annulation: Option<Annulation>,
    /// Date de l'annulation ; `None` : toujours en place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annule: Option<String>,
    /// Le fichier isolé a été supprimé pour de bon depuis le menu Quarantaine, pas remis à sa place : `annule` dit
    /// seulement qu'il n'est plus à défaire, et les traces ne doivent pas lire « annulé » le contraire de ce qui
    /// s'est passé.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub supprime: bool,
    /// Ce qui a été relevé juste avant le geste (processus, ligne de commande, empreinte, connexions) : le geste
    /// efface ce qui disparaît le plus vite, la preuve le garde. Absente des blocages d'avant la 0.86.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preuve: Option<crate::protection::preuve::Preuve>,
    /// L'événement Action du journal commun : son annulation s'y relie, et le fil d'incident remonte de là à la
    /// preuve et à l'alerte. Absent des blocages d'avant la 0.86.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evenement: Option<String>,
    /// L'origine de sa ligne (`Changement::origine`), reprise à la lecture : ce qui décide s'il se défait tout seul
    /// (`refus_d_origine`).
    #[serde(skip)]
    pub origine: Option<Origine>,
}

/// Ce qui défait un blocage, exactement.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "genre", rename_all = "kebab-case")]
pub(crate) enum Annulation {
    /// Les commandes inverses (règle de pare-feu retirée, valeur d'avant remise), par `machine::appliquer`. `port` :
    /// le port fermé en entrée (« 11434/tcp ») que Vanguard a retenu, à oublier avec la règle.
    ///
    /// Ces commandes ne sont plus jamais rejouées telles qu'elles sont relues : ce fichier est celui du compte, et un
    /// programme du compte y glissait une commande sudo qu'« annuler » lançait en root. L'annulation est refaite
    /// depuis `inverse` (des champs typés : une adresse, un port, une valeur), ou, pour une note d'avant elle, depuis
    /// ce que Vanguard aurait écrit lui-même (`blocage::gestes::inverse_reconnue`) ; sinon, elle se fait à la main.
    /// `commandes` et `port` restent écrits : les copies d'avant (0.85 et plus anciennes) ne lisent qu'eux.
    Commandes {
        commandes: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inverse: Option<Inverse>,
    },
    /// Le fichier mis en quarantaine, à remettre à sa place (son nom dans la quarantaine).
    Quarantaine { nom: String },
    /// Le fichier de réglages réécrit : sa copie d'avant, remise seulement s'il n'a pas changé depuis (empreinte
    /// SHA-256 de ce que Vanguard y a écrit).
    Copie {
        fichier: String,
        copie: String,
        empreinte: String,
    },
    /// Le programme retiré du démarrage : le réglage d'Optimiser (« demarrage:… ») à remettre.
    Demarrage { id: String },
}

/// Ce que défait un blocage par des commandes, en champs typés : les commandes inverses en sont refaites au moment
/// d'annuler, jamais relues du fichier.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(tag = "genre", rename_all = "kebab-case")]
pub(crate) enum Inverse {
    /// La règle sortante vers une adresse.
    Sortante {
        pare_feu: crate::protection::blocage::pare_feu::PareFeu,
        adresse: std::net::IpAddr,
    },
    /// La règle qui ferme un port TCP en entrée.
    Entrante {
        pare_feu: crate::protection::blocage::pare_feu::PareFeu,
        port: u16,
    },
    /// La liste de blocage des pilotes vulnérables de Windows remise à sa valeur d'avant (`None` : absente).
    Pilotes { avant: Option<u32> },
}

/// Le relevé des corrections faites ici, dans le dossier de données : le seul endroit où leurs commandes sont notées.
pub(crate) const RELEVE: &str = "changements.jsonl";

fn fichier() -> std::path::PathBuf {
    crate::socle::dossier_local().join(RELEVE)
}

/// Note des corrections lancées (une liste de commandes chacune) et leur résultat.
pub fn noter(correctifs: &[Vec<String>], resultats: &[bool]) {
    noter_dans(&fichier(), correctifs, resultats, &[]);
}

/// Comme `noter`, avec pour chaque correction l'id de la note qui la défait (`None` : elle ne se défait pas).
pub(crate) fn noter_annulables(correctifs: &[Vec<String>], resultats: &[bool], annulables: &[Option<String>]) {
    noter_dans(&fichier(), correctifs, resultats, annulables);
}

fn noter_dans(chemin: &std::path::Path, correctifs: &[Vec<String>], resultats: &[bool], annulables: &[Option<String>]) {
    use crate::modele::evenement::{Evenement, Genre, Source};
    let date = maintenant();
    let mut tous = lire_de(chemin);
    for (i, (commandes, &reussi)) in correctifs.iter().zip(resultats).enumerate() {
        let annulable = annulables.get(i).cloned().flatten();
        let mut ev = Evenement::action(
            Source::Correction,
            commandes.first().map_or("", String::as_str),
            reussi,
            commandes,
        );
        if let Genre::Action { annulable: a, .. } = &mut ev.quoi {
            a.clone_from(&annulable);
        }
        tous.push(Changement {
            date: date.clone(),
            commandes: commandes.clone(),
            reussi,
            blocage: None,
            annulable,
            defaite: None,
            evenement: crate::modele::journal::noter(ev),
            origine: None,
        });
    }
    ecrire(chemin, &tous);
}

/// Note que la correction liée à cette note (`annulable`) est défaite.
pub(crate) fn marquer_defaite(id: &str) {
    marquer_defaite_dans(&fichier(), id);
}

fn marquer_defaite_dans(chemin: &std::path::Path, id: &str) {
    let mut tous = lire_de(chemin);
    let date = maintenant();
    for c in tous.iter_mut().filter(|c| c.annulable.as_deref() == Some(id)) {
        c.defaite = Some(date.clone());
    }
    if let Some(c) = tous.iter().rev().find(|c| c.annulable.as_deref() == Some(id)) {
        noter_annulation(id, c.evenement.as_deref(), false);
    }
    ecrire(chemin, &tous);
}

fn maintenant() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M").to_string()
}

/// Un blocage en place, qui sait se défaire : jamais élagué, sans quoi une règle de pare-feu resterait sans que
/// Vanguard sache plus la retirer.
fn en_place(c: &Changement) -> bool {
    c.blocage
        .as_ref()
        .is_some_and(|b| b.annule.is_none() && b.annulation.is_some())
}

/// Garde les `GARDES` derniers changements (et `OCTETS_GARDES` au plus), plus tous les blocages en place, puis
/// réécrit le fichier d'un coup, scellé (`sceau`).
fn ecrire(chemin: &std::path::Path, tous: &[Changement]) {
    let mut lignes: Vec<(bool, String)> = tous
        .iter()
        .filter_map(|c| Some((en_place(c), serde_json::to_string(c).ok()? + "\n")))
        .collect();
    let mut en_trop = lignes.len().saturating_sub(GARDES);
    let mut taille: usize = lignes.iter().map(|(_, l)| l.len()).sum();
    lignes.retain(|(garde, l)| {
        if !garde && (en_trop > 0 || taille > OCTETS_GARDES) {
            en_trop = en_trop.saturating_sub(1);
            taille -= l.len();
            return false;
        }
        true
    });
    let texte: String = lignes.into_iter().map(|(_, l)| l).collect();
    let (dossier, nom) = lieu(chemin);
    let _ = crate::sceau::ecrire_dans(dossier, nom, texte.as_bytes());
}

/// Le dossier et le nom du relevé, tels que les sceaux les connaissent.
fn lieu(chemin: &std::path::Path) -> (&std::path::Path, &str) {
    (
        chemin.parent().unwrap_or_else(|| std::path::Path::new(".")),
        chemin.file_name().and_then(|n| n.to_str()).unwrap_or(RELEVE),
    )
}

/// L'annulation d'un geste ou d'une correction (`objet` : l'identifiant du blocage ou de la note), reliée à son
/// Action dans le journal commun quand elle est connue.
fn noter_annulation(objet: &str, action: Option<&str>, supprime: bool) {
    use crate::modele::evenement::{Evenement, Genre, Source};
    crate::modele::journal::noter(
        Evenement::nouveau(
            Source::Utilisateur,
            Genre::Annulation {
                objet: objet.to_string(),
                supprime,
            },
        )
        .cause(action),
    );
}

/// Note un blocage : ses commandes (telles que lancées), sa réussite, et de quoi l'annuler. Le jeton de preuve est
/// exigé : on ne note pas un geste sans le relevé d'avant (`preuve::relever`), et le geste va au journal commun,
/// relié à sa preuve.
pub(crate) fn noter_blocage(
    commandes: Vec<String>,
    reussi: bool,
    blocage: Blocage,
    preuve: crate::protection::preuve::PreuveFaite,
) {
    use crate::modele::evenement::{Evenement, Genre, Source};
    let mut ev = Evenement::action(Source::Blocage, &blocage.quoi, reussi, &commandes)
        .cle(Some(&blocage.cle))
        .cause(preuve.evenement());
    if let Genre::Action {
        automatique,
        blocage: b,
        ..
    } = &mut ev.quoi
    {
        *automatique = blocage.automatique;
        *b = Some(blocage.id.clone());
    }
    let evenement = crate::modele::journal::noter(ev);
    ecrire_blocage(
        &fichier(),
        commandes,
        reussi,
        Blocage {
            preuve: preuve.en_preuve(),
            evenement,
            ..blocage
        },
    );
}

/// Les essais notent un blocage dans leur propre relevé, preuve comprise, sans passer par le journal.
#[cfg(test)]
pub(crate) fn noter_blocage_dans(chemin: &std::path::Path, commandes: Vec<String>, reussi: bool, blocage: Blocage) {
    ecrire_blocage(chemin, commandes, reussi, blocage);
}

fn ecrire_blocage(chemin: &std::path::Path, commandes: Vec<String>, reussi: bool, blocage: Blocage) {
    let mut tous = lire_de(chemin);
    tous.push(Changement {
        date: maintenant(),
        commandes,
        reussi,
        // Un échec n'a rien à défaire : il n'est pas proposé à l'annulation.
        blocage: Some(Blocage {
            annulation: blocage.annulation.filter(|_| reussi),
            ..blocage
        }),
        annulable: None,
        defaite: None,
        evenement: None,
        origine: None,
    });
    ecrire(chemin, &tous);
}

/// Les blocages en place (réussis, pas encore annulés), du plus ancien au plus récent, avec leur date.
pub(crate) fn blocages_en_place() -> Vec<(String, Blocage)> {
    blocages_en_place_de(&fichier())
}

fn blocages_en_place_de(chemin: &std::path::Path) -> Vec<(String, Blocage)> {
    lire_de(chemin)
        .into_iter()
        .filter(|c| c.reussi && en_place(c))
        .filter_map(|c| Some((c.date, c.blocage?)))
        .collect()
}

/// Tous les blocages notés (réussis ou non, en place ou annulés), du plus ancien au plus récent : (date, réussi,
/// blocage). Les traces d'incident lisent le relevé elles-mêmes (`blocages_du_texte`) ; les tests, d'ici.
#[cfg(test)]
pub(crate) fn blocages() -> Vec<(String, bool, Blocage)> {
    lire()
        .into_iter()
        .filter_map(|c| Some((c.date, c.reussi, c.blocage?)))
        .collect()
}

/// Les blocages d'un relevé déjà lu (les traces d'incident le lisent elles-mêmes, dans le dossier du compte qui a
/// lancé sudo s'il le faut), comme `blocages`.
pub(crate) fn blocages_du_texte(texte: &str) -> Vec<(String, bool, Blocage)> {
    lire_texte(texte)
        .into_iter()
        .filter_map(|c| Some((c.date, c.reussi, c.blocage?)))
        .collect()
}

/// Note que ce blocage est défait : il n'est plus proposé à l'annulation, et la menace peut revenir.
pub(crate) fn marquer_annule(id: &str) {
    marquer_annule_dans(&fichier(), id, false);
}

fn marquer_annule_dans(chemin: &std::path::Path, id: &str, supprime: bool) {
    let mut tous = lire_de(chemin);
    let date = maintenant();
    let mut trouve = None;
    for c in &mut tous {
        if let Some(b) = c.blocage.as_mut().filter(|b| b.id == id) {
            b.annule = Some(date.clone());
            b.supprime = supprime;
            trouve = Some(b.evenement.clone());
        }
    }
    if let Some(action) = trouve {
        noter_annulation(id, action.as_deref(), supprime);
    }
    ecrire(chemin, &tous);
}

/// Le fichier isolé sous ce nom est sorti de la quarantaine depuis son menu, remis ou `supprime` pour de bon : le
/// blocage qui l'y avait mis n'est plus proposé à l'annulation.
pub(crate) fn marquer_annule_quarantaine(nom: &str, supprime: bool) {
    marquer_annule_quarantaine_dans(&fichier(), nom, supprime);
}

fn marquer_annule_quarantaine_dans(chemin: &std::path::Path, nom: &str, supprime: bool) {
    let ids: Vec<String> = lire_de(chemin)
        .into_iter()
        .filter_map(|c| c.blocage)
        .filter(|b| matches!(&b.annulation, Some(Annulation::Quarantaine { nom: n }) if n == nom))
        .map(|b| b.id)
        .collect();
    for id in ids {
        marquer_annule_dans(chemin, &id, supprime);
    }
}

/// Ce qu'il est advenu d'un blocage défait, pour les traces (« — annulé le … » ou « — fichier supprimé le … »).
pub(crate) fn fin_du_blocage(b: &Blocage) -> Option<String> {
    let le = b.annule.as_ref()?;
    Some(if b.supprime {
        format!(" — fichier supprimé le/file deleted on {le}")
    } else {
        format!(" — annulé le/undone on {le}")
    })
}

/// Un identifiant neuf pour un blocage : l'heure en nanosecondes et le numéro du processus, sans hasard à tirer.
pub(crate) fn nouvel_id() -> String {
    static SUITE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let n = SUITE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{nanos:x}-{:x}-{n}", std::process::id())
}

/// Les changements notés, du plus ancien au plus récent ; une ligne abîmée est sautée.
fn lire() -> Vec<Changement> {
    lire_de(&fichier())
}

/// Relu sous son sceau. Écrit par Vanguard : tel quel. Accepté tel quel au premier usage du sceau (une version
/// d'avant) : chaque ligne marquée `Avant`. Changé hors de Vanguard : chaque ligne marquée `HorsVanguard`, qu'aucune
/// annulation ne rejoue. Supprimé, illisible (un tube, un lien, trop gros) : rien.
fn lire_de(chemin: &std::path::Path) -> Vec<Changement> {
    use crate::sceau::Lecture;
    let (dossier, nom) = lieu(chemin);
    let (octets, douteuse) = match crate::sceau::lire_dans(dossier, nom) {
        Lecture::Intact(o) => (o, None),
        Lecture::Adopte(o) => (o, Some(Origine::Avant)),
        Lecture::Falsifie(Some(o)) => (o, Some(Origine::HorsVanguard)),
        Lecture::Absent | Lecture::Inconnu | Lecture::Falsifie(None) | Lecture::Illisible(_) => return Vec::new(),
    };
    let mut tous = lire_texte(&String::from_utf8_lossy(&octets));
    for c in &mut tous {
        c.origine = c.origine.max(douteuse);
        if let Some(b) = &mut c.blocage {
            b.origine = c.origine;
        }
    }
    tous
}

/// Le relevé d'une version d'avant, accepté tel quel : réécrit et scellé, chaque ligne gardant sa marque `Avant`
/// (ce qu'elle permet de rejouer ne change pas).
pub(crate) fn resceller_d_avant() {
    if crate::sceau::adopte(RELEVE) {
        let chemin = fichier();
        let tous = lire_de(&chemin);
        ecrire(&chemin, &tous);
    }
}

/// Pourquoi ce blocage ne se défait pas tout seul d'après sa note, ou `None`.
///
/// Une ligne trouvée dans un relevé changé hors de Vanguard n'est jamais rejouée. Une ligne d'une version d'avant le
/// sceau (rien ne prouve qu'elle n'a pas été écrite par un autre programme avant la mise à jour) ne l'est que si ce
/// qui la défait est rejugé sans elle : une règle de pare-feu retirée par les ordres typés (jamais un port de
/// session, une adresse locale ou un DNS public, et rejugée par celui qui agit), ou un programme remis au démarrage
/// depuis sa note d'Optimiser (scellée). Jamais, sur sa foi seule, la liste de blocage des pilotes vulnérables
/// remise, un fichier sorti de la quarantaine ou une copie de réglages remise : ceux-là se font à la main.
pub(crate) fn refus_d_origine(b: &Blocage) -> Option<String> {
    use crate::protection::blocage::gestes;
    let a_la_main = || {
        b.annulation.as_ref().map_or_else(String::new, |a| match a {
            Annulation::Commandes { commandes, .. } => trf!(
                " ; à défaire à la main si ce blocage est bien le vôtre : {}",
                "; undo it by hand if this block really is yours: {}",
                commandes
                    .iter()
                    .map(|c| crate::protection::blocage::commande_montree(c))
                    .collect::<Vec<_>>()
                    .join(" ; ")
            ),
            _ => tr!(
                " ; à défaire à la main si ce blocage est bien le vôtre",
                "; undo it by hand if this block really is yours"
            )
            .to_string(),
        })
    };
    match b.origine? {
        Origine::HorsVanguard => Some(format!(
            "{}{}",
            tr!(
                "noté dans un relevé changé hors de Vanguard (changements.jsonl) : rien n'est rejoué",
                "noted in a record changed outside Vanguard (changements.jsonl): nothing is replayed"
            ),
            a_la_main()
        )),
        Origine::Avant => {
            let rejuge = match &b.annulation {
                Some(Annulation::Commandes {
                    commandes,
                    port,
                    inverse,
                }) => matches!(
                    inverse.or_else(|| gestes::inverse_reconnue(commandes, port.as_deref())),
                    Some(Inverse::Sortante { .. } | Inverse::Entrante { .. })
                ),
                Some(Annulation::Demarrage { .. }) => true,
                _ => false,
            };
            (!rejuge).then(|| {
                format!(
                    "{}{}",
                    tr!(
                        "noté par une version d'avant le sceau du relevé : ce geste ne se refait pas sur la foi de la note seule",
                        "noted by a version from before the record was sealed: this action is not redone on the strength of the note alone"
                    ),
                    a_la_main()
                )
            })
        }
    }
}

fn lire_texte(texte: &str) -> Vec<Changement> {
    texte.lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// Les corrections réussies qui ne sont ni des blocages ni des corrections qui se défont (leur note gardée dans
/// reglages.json), du plus ancien au plus récent : (date, première commande). Sans valeur d'avant notée, elles se
/// défont à la main, avec la commande inverse.
pub(crate) fn a_defaire_a_la_main() -> Vec<(String, String)> {
    let notes: std::collections::HashSet<String> = crate::optimiser::annulables::notes(None)
        .into_iter()
        .map(|n| n.id)
        .collect();
    lire()
        .into_iter()
        .filter(|c| c.reussi && c.blocage.is_none())
        .filter(|c| c.annulable.as_ref().is_none_or(|id| !notes.contains(id)) && c.defaite.is_none())
        .map(|c| (c.date, c.commandes.into_iter().next().unwrap_or_default()))
        .collect()
}

/// Pour le rapport HTML : (corrections notées, réussies, date de la dernière). Les commandes n'y vont pas : le rapport
/// voyage sur la clé et sert aux captures d'écran, et une commande peut citer un nom de fichier ou de compte.
pub fn resume() -> Option<(usize, usize, String)> {
    resume_de(&fichier())
}

fn resume_de(chemin: &std::path::Path) -> Option<(usize, usize, String)> {
    let tous = lire_de(chemin);
    let derniere = tous.last()?.date.clone();
    Some((tous.len(), tous.iter().filter(|c| c.reussi).count(), derniere))
}

/// `vanguard changements` et le menu Cette machine : les changements notés, puis, s'il y en a, les corrections qui se
/// défont, à annuler une par une (ou tout remettre comme avant).
pub fn afficher() {
    titre(tr!("Ce que Vanguard a changé", "What Vanguard changed"));
    let tous = lire();
    if tous.is_empty() {
        trp!(
            "  Rien encore : aucune correction n'a été lancée sur cet ordinateur.",
            "  Nothing yet: no fix has been run on this computer."
        );
        return;
    }
    let notes = crate::optimiser::annulables::notes(None);
    let a_sa_note = |id: &String| notes.iter().any(|n| &n.id == id);
    for c in tous.iter().rev().take(30) {
        let marque = if c.reussi {
            format!("{VERT}✔{RESET}")
        } else {
            format!("{}✖{RESET}", couleur(crate::risk::Niveau::Eleve))
        };
        let douteuse = match c.origine {
            Some(Origine::HorsVanguard) => tr!(" (changé hors de Vanguard)", " (changed outside Vanguard)"),
            Some(Origine::Avant) => tr!(" (noté avant le sceau)", " (noted before the seal)"),
            None => "",
        };
        if let Some(b) = &c.blocage {
            let etat = match (&b.annule, &b.annulation, b.automatique) {
                (Some(le), _, _) if b.supprime => trf!(" (fichier supprimé le {le})", " (file deleted on {le})"),
                (Some(le), _, _) => trf!(" (annulé le {le})", " (undone on {le})"),
                (None, Some(_), true) => tr!(" (automatique, annulable)", " (automatic, undoable)").to_string(),
                (None, Some(_), false) => tr!(" (annulable)", " (undoable)").to_string(),
                (None, None, _) => String::new(),
            };
            afficher_aligne(
                &format!("  {marque} {GRIS}{}{RESET}  ", c.date),
                &format!("{}{etat}{douteuse}", affichable(&b.quoi)),
                21,
                "",
            );
            // La preuve relevée avant le geste, en une ligne ; le détail est dans les traces d'incident.
            if let Some(p) = b.preuve.as_ref().map(crate::protection::preuve::Preuve::resume)
                && !p.is_empty()
            {
                afficher_aligne(
                    &" ".repeat(21),
                    &trf!("preuve gardée : {p}", "evidence kept: {p}"),
                    21,
                    GRIS,
                );
            }
            continue;
        }
        let premiere = c.commandes.first().map(String::as_str).unwrap_or_default();
        let suite = if c.commandes.len() > 1 {
            trf!(" (+{} commande(s))", " (+{} command(s))", c.commandes.len() - 1)
        } else {
            String::new()
        };
        let etat = match (&c.defaite, &c.annulable) {
            (Some(le), _) => trf!(" (défaite le {le})", " (undone on {le})"),
            (None, Some(id)) if a_sa_note(id) => tr!(" (annulable)", " (undoable)").to_string(),
            _ => String::new(),
        };
        afficher_aligne(
            &format!("  {marque} {GRIS}{}{RESET}  ", c.date),
            &format!("{}{suite}{etat}{douteuse}", commande_affichable(premiere)),
            21,
            "",
        );
    }
    if tous.len() > 30 {
        trp!(
            "  {GRIS}… et {} plus ancien(s), dans {}{RESET}",
            "  {GRIS}… and {} older, in {}{RESET}",
            tous.len() - 30,
            chemin_affichable(&fichier())
        );
    }
    println!();
    afficher_aligne(
        "  ",
        tr!(
            "Une correction marquée « annulable » se défait ici ; les réglages d'Optimiser et de Gaming, les blocages et le mode Wi-Fi public, par « Tout remettre comme avant » (ou leur menu) ; une autre correction se défait à la main, avec la commande inverse.",
            "A fix marked “undoable” is undone here; Optimize and Gaming settings, blocks and public Wi-Fi mode, with “Put everything back” (or their menu); any other fix is undone by hand, with the opposite command."
        ),
        2,
        GRIS,
    );
    annuler_des_corrections();
}

/// Les corrections du bilan qui se défont (leur note gardée), de la plus récente à la plus ancienne, à annuler une
/// par une ; « T » remet tout comme avant.
fn annuler_des_corrections() {
    use crate::optimiser::annulables::{self, Issue, Origine};
    use crate::selection::{Ligne, choisir};
    loop {
        let notes = annulables::notes(Some(Origine::Bilan));
        if notes.is_empty() {
            return;
        }
        let mut lignes = vec![
            Ligne::Texte(String::new()),
            Ligne::Texte(ligne_section(tr!("Annuler une correction", "Undo a fix"))),
        ];
        for (i, n) in notes.iter().enumerate() {
            lignes.push(Ligne::choix(
                &(i + 1).to_string(),
                &couper(&affichable(&n.titre), 44),
                &n.date,
            ));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix(
            "T",
            tr!("Tout remettre comme avant", "Put everything back"),
            tr!("bilan, Optimiser, Gaming…", "check-up, Optimize, Gaming…"),
        ));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        let Some(choix) = choisir(
            &lignes,
            tr!("\n  Numéro (Entrée pour revenir) : ", "\n  Number (Enter to go back): "),
            "1",
            tr!("revenir", "back"),
        ) else {
            return;
        };
        if choix.trim().eq_ignore_ascii_case("t") {
            crate::annulation::tout_remettre();
            return;
        }
        let Some(n) = choix
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|i| notes.get(i.checked_sub(1)?))
        else {
            return;
        };
        println!();
        afficher_aligne("  ", &affichable(&n.titre), 2, GRAS);
        if let Some(Issue::Revenu | Issue::Absent) = annulables::annuler_une(&n.id) {
            marquer_defaite(&n.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le relevé d'un essai, dans son propre dossier jetable (ses sceaux à côté) : d'autres tests lancent des
    /// corrections, notées dans le fichier habituel.
    fn releve(nom: &str) -> std::path::PathBuf {
        let d = crate::socle::dossier_local().join(format!("essai-changements-{nom}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join(RELEVE)
    }

    #[test]
    fn notes_ecrites_relues_et_limitees() {
        let f = releve("limites");
        noter_dans(
            &f,
            &[vec!["chmod 700 ~/.ssh".into()], vec!["false".into(), "true".into()]],
            &[true, false],
            &[],
        );
        let tous = lire_de(&f);
        assert_eq!(tous.len(), 2);
        assert!(tous[0].reussi && !tous[1].reussi);
        assert_eq!(tous[1].commandes.len(), 2);
        // Une ligne abîmée ne fait pas tout perdre.
        let t = format!("{{pas du json\n{}\n", serde_json::to_string(&tous[0]).unwrap());
        assert_eq!(lire_texte(&t).len(), 1);
        // Au-delà de la limite, les plus anciens partent.
        let beaucoup: Vec<Vec<String>> = (0..GARDES + 5).map(|i| vec![format!("echo {i}")]).collect();
        noter_dans(&f, &beaucoup, &vec![true; beaucoup.len()], &[]);
        let tous = lire_de(&f);
        assert_eq!(tous.len(), GARDES);
        assert_eq!(tous.last().unwrap().commandes[0], format!("echo {}", GARDES + 4));
        assert_eq!(resume_de(&f).map(|(n, r, _)| (n, r)), Some((GARDES, GARDES)));
        let _ = std::fs::remove_file(&f);
        assert_eq!(resume_de(&f), None);
    }

    fn blocage(id: &str, annulation: Option<Annulation>) -> Blocage {
        Blocage {
            id: id.into(),
            cle: format!("connexion:{id}"),
            quoi: "Règle sortante vers 203.0.113.7".into(),
            automatique: true,
            annulation,
            annule: None,
            supprime: false,
            evenement: None,
            origine: None,
            preuve: None,
        }
    }

    /// Garde-fou : chaque blocage est noté avec de quoi l'annuler, n'est jamais élagué tant qu'il est en place, et
    /// sort de la liste des blocages en place une fois annulé. Un échec n'a rien à annuler.
    #[test]
    fn blocages_notes_annulables_jamais_elagues() {
        let f = releve("blocages");
        let retirer = Annulation::Commandes {
            commandes: vec!["sudo ufw delete deny out to 203.0.113.7".into()],
            port: None,
            inverse: None,
        };
        noter_blocage_dans(
            &f,
            vec!["sudo ufw prepend deny out to 203.0.113.7".into()],
            true,
            blocage("a", Some(retirer.clone())),
        );
        noter_blocage_dans(&f, vec!["false".into()], false, blocage("b", Some(retirer.clone())));
        let en_place = blocages_en_place_de(&f);
        assert_eq!(en_place.len(), 1, "{en_place:?}");
        assert_eq!(en_place[0].1.annulation, Some(retirer));
        assert!(lire_de(&f)[1].blocage.as_ref().unwrap().annulation.is_none());
        // Bien plus de corrections que la limite : le blocage en place reste, le reste est élagué.
        let beaucoup: Vec<Vec<String>> = (0..GARDES + 20).map(|i| vec![format!("echo {i}")]).collect();
        noter_dans(&f, &beaucoup, &vec![true; beaucoup.len()], &[]);
        let tous = lire_de(&f);
        assert_eq!(tous.len(), GARDES);
        assert_eq!(tous[0].blocage.as_ref().map(|b| b.id.as_str()), Some("a"));
        assert_eq!(blocages_en_place_de(&f).len(), 1);
        // Annulé : plus en place, et il peut maintenant être élagué comme le reste.
        marquer_annule_dans(&f, "a", false);
        assert_eq!(blocages_en_place_de(&f), Vec::new());
        assert!(
            lire_de(&f)
                .iter()
                .any(|c| c.blocage.as_ref().is_some_and(|b| b.annule.is_some()))
        );
        noter_dans(&f, &[vec!["echo fin".into()]], &[true], &[]);
        let tous = lire_de(&f);
        assert_eq!(tous.len(), GARDES);
        assert!(tous.iter().all(|c| c.blocage.is_none()));
        // Une ligne d'une version d'avant (sans blocage) se relit toujours.
        assert_eq!(
            lire_texte("{\"date\":\"2026-10-01 10:00\",\"commandes\":[\"x\"],\"reussi\":true}\n").len(),
            1
        );
        let _ = std::fs::remove_file(&f);
        assert_ne!(nouvel_id(), nouvel_id());
    }
    /// Un fichier isolé puis supprimé pour de bon depuis le menu Quarantaine se lit « supprimé », jamais « annulé »
    /// (comme s'il avait été remis) ; remis, il se lit « annulé ». Une ligne d'avant ce champ se relit.
    #[test]
    fn fichier_supprime_de_la_quarantaine_pas_annule() {
        let f = releve("supprime");
        for nom in ["x", "y"] {
            noter_blocage_dans(
                &f,
                vec![format!("quarantaine : /tmp/{nom}")],
                true,
                blocage(nom, Some(Annulation::Quarantaine { nom: nom.into() })),
            );
        }
        marquer_annule_quarantaine_dans(&f, "x", true);
        marquer_annule_quarantaine_dans(&f, "y", false);
        let fins: Vec<String> = lire_de(&f)
            .iter()
            .filter_map(|c| fin_du_blocage(c.blocage.as_ref()?))
            .collect();
        assert_eq!(fins.len(), 2, "{fins:?}");
        assert!(
            fins[0].contains("supprimé") && !fins[0].contains("annulé"),
            "{}",
            fins[0]
        );
        assert!(
            fins[1].contains("annulé") && !fins[1].contains("supprimé"),
            "{}",
            fins[1]
        );
        assert_eq!(blocages_en_place_de(&f), Vec::new());
        let _ = std::fs::remove_file(&f);
    }

    fn regle(ip: &str) -> Annulation {
        Annulation::Commandes {
            commandes: vec![format!("sudo ufw delete deny out to {ip}")],
            port: None,
            inverse: Some(Inverse::Sortante {
                pare_feu: crate::protection::blocage::pare_feu::PareFeu::Ufw,
                adresse: ip.parse().unwrap(),
            }),
        }
    }

    /// Le relevé est scellé : une ligne ajoutée par un autre programme (des champs typés qui remettraient la liste de
    /// blocage des pilotes vulnérables à 0) se lit « changée hors de Vanguard », jamais rejouée, et le reste
    /// aussi tant que le relevé l'était. Réécrit par Vanguard, la marque reste : réécrire ne blanchit rien.
    #[test]
    fn releve_change_hors_de_vanguard_jamais_rejoue() {
        let f = releve("forge");
        noter_blocage_dans(&f, vec!["x".into()], true, blocage("vrai", Some(regle("203.0.113.7"))));
        let en_place = blocages_en_place_de(&f);
        assert_eq!(en_place.len(), 1);
        assert_eq!(refus_d_origine(&en_place[0].1), None, "écrit et scellé par Vanguard");
        // Un autre programme ajoute un blocage « en place » qui couperait la défense contre les pilotes vulnérables.
        let forge = Changement {
            date: "2026-10-24 03:00".into(),
            commandes: vec!["x".into()],
            reussi: true,
            blocage: Some(blocage(
                "forge",
                Some(Annulation::Commandes {
                    commandes: Vec::new(),
                    port: None,
                    inverse: Some(Inverse::Pilotes { avant: Some(0) }),
                }),
            )),
            annulable: None,
            defaite: None,
            evenement: None,
            origine: None,
        };
        let mut texte = std::fs::read_to_string(&f).unwrap();
        texte += &(serde_json::to_string(&forge).unwrap() + "\n");
        std::fs::write(&f, texte).unwrap();
        let en_place = blocages_en_place_de(&f);
        assert_eq!(en_place.len(), 2);
        for (_, b) in &en_place {
            let refus = refus_d_origine(b).unwrap_or_default();
            assert!(
                refus.contains("hors de Vanguard") || refus.contains("outside Vanguard"),
                "{refus}"
            );
            assert!(crate::protection::blocage::gestes::defaire(b).is_err());
        }
        // Vanguard note autre chose : le relevé est réécrit et rescellé, les lignes trouvées changées le restent.
        noter_dans(&f, &[vec!["echo apres".into()]], &[true], &[]);
        assert!(matches!(
            crate::sceau::lire_dans(f.parent().unwrap(), RELEVE),
            crate::sceau::Lecture::Intact(_)
        ));
        let en_place = blocages_en_place_de(&f);
        assert!(
            en_place.iter().all(|(_, b)| refus_d_origine(b).is_some()),
            "{en_place:?}"
        );
        assert_eq!(lire_de(&f).last().unwrap().origine, None);
    }

    /// Un relevé d'une version d'avant le sceau, accepté tel quel à la mise à jour : seules les annulations qui se
    /// rejugent sans la note (règle de pare-feu par les ordres typés, programme remis au démarrage par sa note
    /// scellée) se défont toutes seules ; la liste des pilotes, la quarantaine et une copie de réglages, à la main.
    #[test]
    fn releve_d_avant_le_sceau_rejoue_seulement_ce_qui_se_rejuge() {
        let f = releve("avant");
        let lignes: Vec<Changement> = [
            ("regle", Some(regle("203.0.113.7"))),
            (
                "ancienne",
                Some(Annulation::Commandes {
                    commandes: crate::protection::blocage::pare_feu::ancien::entrante(
                        crate::protection::blocage::pare_feu::PareFeu::Ufw,
                        8188,
                    )
                    .unwrap()
                    .retirer,
                    port: Some("8188/tcp".into()),
                    inverse: None,
                }),
            ),
            (
                "demarrage",
                Some(Annulation::Demarrage {
                    id: "demarrage:x".into(),
                }),
            ),
            (
                "pilotes",
                Some(Annulation::Commandes {
                    commandes: Vec::new(),
                    port: None,
                    inverse: Some(Inverse::Pilotes { avant: Some(0) }),
                }),
            ),
            ("quarantaine", Some(Annulation::Quarantaine { nom: "x".into() })),
        ]
        .into_iter()
        .map(|(id, a)| Changement {
            date: "2026-10-20 10:00".into(),
            commandes: vec!["x".into()],
            reussi: true,
            blocage: Some(blocage(id, a)),
            annulable: None,
            defaite: None,
            evenement: None,
            origine: None,
        })
        .collect();
        let texte: String = lignes
            .iter()
            .map(|c| serde_json::to_string(c).unwrap() + "\n")
            .collect();
        // Écrit sans sceau, comme une 0.86 : adopté au premier regard.
        std::fs::write(&f, texte).unwrap();
        let refus: Vec<(String, bool)> = blocages_en_place_de(&f)
            .into_iter()
            .map(|(_, b)| (b.id.clone(), refus_d_origine(&b).is_some()))
            .collect();
        assert_eq!(
            refus,
            [
                ("regle".to_string(), false),
                ("ancienne".to_string(), false),
                ("demarrage".to_string(), false),
                ("pilotes".to_string(), true),
                ("quarantaine".to_string(), true),
            ]
        );
        // Réécrit par Vanguard : la marque « d'avant » reste avec chaque ligne.
        noter_dans(&f, &[vec!["echo apres".into()]], &[true], &[]);
        assert!(
            blocages_en_place_de(&f)
                .iter()
                .all(|(_, b)| b.origine == Some(Origine::Avant))
        );
    }

    /// Un tube nommé ou un lien vers /dev/zero à la place du relevé : rien ne fige, rien ne se charge sans fin.
    #[cfg(unix)]
    #[test]
    fn releve_tube_ou_lien_ne_fige_rien() {
        let f = releve("tube");
        let c = std::ffi::CString::new(f.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY : mkfifo reçoit un chemin terminé par zéro, qui vit le temps de l'appel.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let debut = std::time::Instant::now();
        assert_eq!(blocages_en_place_de(&f), Vec::new());
        std::fs::remove_file(&f).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &f).unwrap();
        assert_eq!(blocages_en_place_de(&f), Vec::new());
        assert!(debut.elapsed() < std::time::Duration::from_secs(5));
    }
}
