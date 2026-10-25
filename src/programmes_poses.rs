//! Le programme que lancent les tâches de Vanguard (surveillance horaire, entretien du mois, veilleur) : son chemin et
//! son empreinte BLAKE3, scellés (`sceau`) quand Vanguard pose la tâche ou met sa copie à jour.
//!
//! Pourquoi : une tâche était jugée sur l'existence seule de son programme. Une unité réécrite (ExecStart=, l'action
//! de la tâche planifiée, ProgramArguments de l'agent) qui lançait autre chose, ou la copie de cet ordinateur
//! remplacée, laissaient le bilan vert, et tout ce que la surveillance disait ensuite venait d'un autre programme. Le
//! bilan compare donc le chemin ET l'empreinte : un écart est une alerte ; ce qui ne se lit pas, ou un sceau qui ne
//! peut pas être cru, est « non vérifié », jamais sain.
//!
//! Le programme qui tourne se reconnaît lui-même : sous Linux, `/proc/self/exe` est l'image lancée, même si le
//! fichier a été remplacé depuis. Une tâche qui lance exactement ses octets lance Vanguard, quel que soit le sceau ;
//! le sceau est alors renoté, ce qui suit une mise à jour faite hors de Vanguard (gestionnaire de paquets, cargo) au
//! premier bilan de la nouvelle version. Ailleurs, le chemin du programme lancé peut désigner un fichier remplacé
//! depuis son lancement : seul le sceau compte.
//!
//! Le texte de la tâche (l'unité et sa minuterie, le plist, le XML de la tâche) est scellé aussi : changé hors de
//! Vanguard, c'est une alerte élevée, quoi qu'il change. Une tâche posée par une version d'avant, sans rien de noté,
//! est notée telle quelle au premier bilan (confiance au premier usage, comme `sceau`), jamais par-dessus une liste
//! qui ne peut pas être crue. Un programme remplacé par une version publiée et signée (l'historique signé des versions
//! le dit) est renoté et dit en information ; sans réponse de l'historique, il reste dit, jamais tu.
//!
//! Comme tout sceau : barrière, pas coffre. Un programme qui connaît ce mécanisme peut refaire le sceau ; un
//! programme remplacé qu'on lance soi-même n'est plus Vanguard, et rien de ce qu'il dit ne compte.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::machine::Constat;
use crate::risk::Niveau;
use crate::sceau::Lecture;
use crate::voulues::Doute;
use crate::{tr, trf};

/// L'état scellé des programmes posés, dans le dossier de données.
pub(crate) const FICHIER: &str = "programmes-planifies.json";

/// Au-delà, ce n'est pas le programme de Vanguard : il n'est pas lu en entier.
const TAILLE_MAX: u64 = 512 << 20;

/// Ce que Vanguard planifie et qui lance son programme sans personne devant l'écran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tache {
    Surveillance,
    Entretien,
    Veilleur,
}

impl Tache {
    /// Son nom dans l'état : stable, jamais traduit.
    fn cle(self) -> &'static str {
        match self {
            Tache::Surveillance => "surveillance",
            Tache::Entretien => "entretien",
            Tache::Veilleur => "veilleur",
        }
    }

    fn dans_une_phrase(self) -> &'static str {
        match self {
            Tache::Surveillance => tr!("la surveillance horaire", "the hourly monitoring"),
            Tache::Entretien => tr!("l'entretien du mois", "the monthly check-up"),
            Tache::Veilleur => tr!("le veilleur", "the watcher"),
        }
    }

    /// La commande qui refait la tâche, et renote son programme.
    fn refaire(self) -> &'static str {
        match self {
            Tache::Surveillance => tr!("vanguard surveillance on", "vanguard monitor on"),
            Tache::Entretien => tr!("vanguard entretien on", "vanguard maintenance on"),
            Tache::Veilleur => tr!("vanguard veilleur on", "vanguard watcher on"),
        }
    }
}

/// Le programme posé pour une tâche.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Pose {
    chemin: String,
    empreinte: String,
    /// L'empreinte BLAKE3 du texte de la tâche tel que Vanguard l'a posé (Linux : le service et sa minuterie ; macOS :
    /// le plist ; Windows : le XML de la tâche). Le programme seul ne suffit pas : une ligne `ExecCondition=` ajoutée,
    /// une seconde `ExecStart=` ou une minuterie annuelle coupent la défense, ou lancent autre chose, sous son nom.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    texte: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Fichier {
    #[serde(default)]
    taches: BTreeMap<String, Pose>,
}

/// L'empreinte BLAKE3 du programme `chemin`, lu en entier. Le lien est suivi (la tâche le suit aussi) ; ouvert sans
/// attendre puis jugé sur ce qui a été ouvert : un tube nommé posé à sa place ne fige pas le bilan.
pub(crate) fn empreinte_de(chemin: &Path) -> Result<String, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let f = options.open(chemin).map_err(|e| e.to_string())?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() {
        return Err(tr!("pas un simple fichier", "not a plain file").into());
    }
    if m.len() > TAILLE_MAX {
        return Err(tr!("fichier démesuré", "oversized file").into());
    }
    let mut h = blake3::Hasher::new();
    h.update_reader(std::io::Read::take(f, TAILLE_MAX))
        .map_err(|e| e.to_string())?;
    Ok(h.finalize().to_hex().to_string())
}

/// L'empreinte de l'image du programme qui tourne (Linux seulement, voir l'en-tête), lue une fois. Jamais pendant
/// les tests : le programme des essais n'est pas Vanguard.
pub(crate) fn soi() -> Option<&'static str> {
    static SOI: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    if cfg!(test) || !cfg!(target_os = "linux") {
        return None;
    }
    SOI.get_or_init(|| empreinte_de(Path::new("/proc/self/exe")).ok())
        .as_deref()
}

fn lire_dans(dossier: &Path) -> Result<Fichier, Doute> {
    let octets = match crate::sceau::lire_dans(dossier, FICHIER) {
        Lecture::Absent => return Ok(Fichier::default()),
        Lecture::Intact(o) => o,
        // Né scellé : jamais écrit sans sceau par une version d'avant. Accepté tel quel, c'est que sceaux.json a
        // disparu, refait ou pas (tout effacer d'un coup ne laisse pas de témoin).
        Lecture::Adopte(_) => return Err(Doute::Adopte),
        Lecture::Falsifie(_) => return Err(Doute::HorsVanguard),
        Lecture::Inconnu => return Err(Doute::Inconnu),
        Lecture::Illisible(_) => return Err(Doute::Illisible),
    };
    serde_json::from_slice(&octets).map_err(|_| Doute::Illisible)
}

/// L'empreinte d'un texte de tâche lu.
fn empreinte_texte(texte: &std::io::Result<Vec<u8>>) -> std::io::Result<String> {
    match texte {
        Ok(o) => Ok(blake3::hash(o).to_hex().to_string()),
        Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
    }
}

/// Réécrit l'état. Un état qui ne pouvait pas être cru repart de zéro : ce qu'il disait des autres tâches n'est pas
/// recopié, et elles se diront « jamais notées », donc non vérifiées.
fn changer_dans(dossier: &Path, changer: impl FnOnce(&mut Fichier) -> bool) -> std::io::Result<()> {
    let mut f = lire_dans(dossier).unwrap_or_default();
    if !changer(&mut f) {
        return Ok(());
    }
    let octets = serde_json::to_vec_pretty(&f).map_err(std::io::Error::other)?;
    crate::sceau::ecrire_dans(dossier, FICHIER, &octets)
}

fn retenir_dans(
    dossier: &Path,
    t: Tache,
    chemin: &Path,
    empreinte: String,
    texte: Option<String>,
) -> std::io::Result<()> {
    let pose = Pose {
        chemin: chemin.display().to_string(),
        empreinte,
        texte,
    };
    changer_dans(dossier, |f| {
        f.taches.insert(t.cle().to_string(), pose.clone()) != Some(pose)
    })
}

/// Ce qui est scellé pour une tâche que Vanguard vient de poser : l'empreinte lue à `chemin`, sauf si le programme qui
/// tourne se connaît (`soi`) et n'a pas ces octets alors que `chemin` n'est pas la copie de cet ordinateur. Vanguard
/// pose alors ce programme-ci : un fichier changé entre la pose et sa lecture, ou un chemin d'origine soufflé par une
/// variable d'environnement du compte (`VANGUARD_ORIGINE`), n'est jamais scellé comme le sien ; il se dira remplacé.
/// La copie de cet ordinateur peut, elle, être une version plus récente gardée (`mise_a_jour::poser_copie`) : ses
/// octets à elle.
fn a_sceller(chemin: &Path, lu: String, soi: Option<&str>, copie: &Path) -> String {
    match soi {
        Some(s) if s != lu && !meme_chemin(chemin, copie) => s.to_string(),
        _ => lu,
    }
}

/// Vanguard vient de poser la tâche `t`, qui lance `chemin`, et dont le texte posé est `texte` : leurs empreintes
/// sont scellées. Un nom sans chemin (le programme ne s'est pas situé) n'a rien à sceller : le bilan le dit non
/// vérifié.
pub(crate) fn noter(t: Tache, chemin: &Path, texte: &std::io::Result<Vec<u8>>) {
    if !chemin.is_absolute() {
        return;
    }
    let copie = crate::mise_a_jour::copie_de_cet_ordinateur();
    let r = empreinte_de(chemin).map_err(std::io::Error::other).and_then(|lu| {
        retenir_dans(
            &crate::socle::dossier_local(),
            t,
            chemin,
            a_sceller(chemin, lu, soi(), &copie),
            empreinte_texte(texte).ok(),
        )
    });
    if let Err(e) = r {
        crate::modele::Echec::echoue("programmes_poses/noter", e.to_string()).journaliser();
    }
}

/// Le chemin posé pour la tâche `t`, s'il est noté (et la liste crue).
pub(crate) fn chemin_pose(t: Tache) -> Option<String> {
    lire_dans(&crate::socle::dossier_local())
        .ok()?
        .taches
        .get(t.cle())
        .map(|p| p.chemin.clone())
}

pub(crate) fn oublier_dans(dossier: &Path, t: Tache) {
    let _ = changer_dans(dossier, |f| f.taches.remove(t.cle()).is_some());
}

/// Vanguard a retiré la tâche `t`.
pub(crate) fn oublier(t: Tache) {
    oublier_dans(&crate::socle::dossier_local(), t);
}

/// Vanguard vient de mettre `octets` à la place de `cible` (sa copie de cet ordinateur, une mise à jour) : chaque
/// tâche qui la lance garde un sceau juste. Rend les tâches concernées.
pub(crate) fn copie_posee_dans(dossier: &Path, cible: &Path, octets: &[u8]) -> Vec<Tache> {
    let empreinte = blake3::hash(octets).to_hex().to_string();
    let mut touchees = Vec::new();
    let _ = changer_dans(dossier, |f| {
        for t in [Tache::Surveillance, Tache::Entretien, Tache::Veilleur] {
            if let Some(p) = f.taches.get_mut(t.cle())
                && meme_chemin(Path::new(&p.chemin), cible)
                && p.empreinte != empreinte
            {
                p.empreinte.clone_from(&empreinte);
                touchees.push(t);
            }
        }
        !touchees.is_empty()
    });
    touchees
}

pub(crate) fn copie_posee(cible: &Path, octets: &[u8]) -> Vec<Tache> {
    copie_posee_dans(&crate::socle::dossier_local(), cible, octets)
}

/// Deux chemins du même programme : sous Windows, sans « \\?\ » ni casse ; ailleurs tels quels, puis canoniques.
pub(crate) fn meme_chemin(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        let court = |p: &Path| {
            crate::reseau::surveillance::sans_verbatim(p)
                .display()
                .to_string()
                .to_lowercase()
        };
        return court(a) == court(b);
    }
    a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
}

/// Le jugement du programme qu'une tâche lance.
#[derive(Debug, PartialEq, Eq)]
enum Jugement {
    /// Le programme que Vanguard a posé, tel qu'il l'a posé, et la tâche telle qu'il l'a posée.
    Sain,
    /// Au bon chemin, les octets du programme qui tourne (Vanguard lui-même, mis à jour) : l'empreinte est renotée.
    Soi,
    /// Rien de noté pour cette tâche (posée par une version d'avant) : notée telle quelle, premier usage.
    Premier,
    /// Un autre chemin que celui que Vanguard a posé.
    AutreChemin(String),
    /// Le chemin posé, mais d'autres octets.
    Remplace,
    /// Le texte de la tâche (unité, minuterie, plist, XML) n'est plus celui que Vanguard a posé.
    TexteChange,
    /// La liste des programmes posés a été changée hors de Vanguard, et le programme lancé n'est pas celui qui tourne.
    ListeForgee,
    NonVerifie(String),
}

/// Le jugement, sans rien lire : le programme lancé, son empreinte lue, ce que le sceau dit de la tâche,
/// l'empreinte du programme qui tourne quand elle se connaît, et l'empreinte du texte de la tâche lu.
fn juger(
    programme: &Path,
    lu: &Result<String, String>,
    pose: Result<Option<&Pose>, Doute>,
    soi: Option<&str>,
    texte: &std::io::Result<String>,
) -> Jugement {
    let lu = match lu {
        Ok(l) => l,
        Err(e) => {
            return Jugement::NonVerifie(trf!(
                "son programme ne se lit pas : {e}",
                "its program cannot be read: {e}"
            ));
        }
    };
    let soi_ok = soi == Some(lu.as_str());
    let p = match pose {
        // La liste changée hors de Vanguard est une écriture étrangère prouvée : un programme lancé qui n'est pas
        // celui qui tourne ne se croit pas.
        Err(Doute::HorsVanguard) if soi.is_some() && !soi_ok => return Jugement::ListeForgee,
        Err(d) => {
            return Jugement::NonVerifie(trf!(
                "la liste des programmes posés par Vanguard {}",
                "the list of programs placed by Vanguard {}",
                d.texte()
            ));
        }
        Ok(None) => return Jugement::Premier,
        Ok(Some(p)) => p,
    };
    // Le chemin d'abord : même aux octets du programme qui tourne, une copie ailleurs n'est pas ce que Vanguard a
    // posé (« vanguard surveillance on » est la seule voie pour en changer).
    if !meme_chemin(Path::new(&p.chemin), programme) {
        return Jugement::AutreChemin(p.chemin.clone());
    }
    if p.empreinte != *lu && !soi_ok {
        return Jugement::Remplace;
    }
    match (&p.texte, texte) {
        (Some(h), Ok(t)) if h != t => return Jugement::TexteChange,
        (Some(_), Ok(_)) => {}
        (Some(_), Err(e)) => {
            return Jugement::NonVerifie(trf!("sa tâche ne se lit pas : {e}", "its task cannot be read: {e}"));
        }
        (None, _) => {
            return Jugement::NonVerifie(
                tr!(
                    "le texte de sa tâche n'a pas été noté quand Vanguard l'a posée",
                    "the text of its task was not noted when Vanguard set it up"
                )
                .to_string(),
            );
        }
    }
    if p.empreinte == *lu {
        Jugement::Sain
    } else {
        Jugement::Soi
    }
}

/// Le programme remplacé est-il une version publiée et signée ? Seulement pour un programme qui n'est plus celui
/// noté : ce qu'en dit l'historique signé des versions (rien de cet ordinateur ne part).
#[derive(Debug, PartialEq, Eq)]
enum Signee {
    Oui(String),
    Non,
    /// L'historique n'a pas répondu (hors ligne, pas encore publié) : la raison.
    Inconnu(String),
}

fn signee(programme: &Path) -> Signee {
    let Some(sha) = crate::protection::empreintes::sha256(programme) else {
        return Signee::Inconnu(tr!("programme illisible", "unreadable program").to_string());
    };
    match crate::mise_a_jour::version_signee(&sha) {
        Ok(Some((v, _))) => Signee::Oui(v),
        Ok(None) => Signee::Non,
        Err(e) => Signee::Inconnu(e),
    }
}

/// Le constat d'un jugement : rien quand c'est Vanguard ; une alerte élevée pour un autre programme ou une tâche
/// changée ; une information pour une version signée posée hors de Vanguard ; « non vérifié » sinon. `signee` : ce
/// que l'historique signé dit d'un programme remplacé.
fn constat_de(t: Tache, programme: &Path, j: &Jugement, signee: Option<&Signee>) -> Option<Constat> {
    const CAT: &str = "Surveillance";
    let tache = t.dans_une_phrase();
    let chemin = crate::ui::chemin_affichable(programme);
    let remettre = || {
        trf!(
            "Si c'est vous qui l'avez changé : « {} » refait la tâche et note son programme ; sinon, regardez ce qui tourne sous votre compte (Protection › Qui parle à Internet ?)",
            "If you changed it yourself: “{}” redoes the task and notes its program; otherwise, look at what runs under your account (Protection › Who talks to the Internet?)",
            t.refaire()
        )
    };
    let eleve = |texte: String| Some(crate::machine::alerte(CAT, Niveau::Eleve, texte).manuel(remettre(), &[]));
    match j {
        Jugement::Sain | Jugement::Soi | Jugement::Premier => None,
        Jugement::AutreChemin(pose) => eleve(trf!(
            "{tache} lance un autre programme que celui que Vanguard a posé : {chemin}, au lieu de {}. Un logiciel malveillant peut s'y faire passer pour Vanguard.",
            "{tache} starts a different program from the one Vanguard placed: {chemin}, instead of {}. Malware can pass itself off as Vanguard there.",
            crate::ui::chemin_affichable(Path::new(pose))
        )),
        Jugement::Remplace => match signee {
            Some(Signee::Oui(v)) => Some(crate::machine::alerte(
                CAT,
                Niveau::Info,
                trf!(
                    "Le programme que lance {tache} ({chemin}) a été mis à jour hors de Vanguard, vers la version {v}, publiée et signée par l'auteur : Vanguard l'a noté.",
                    "The program {tache} starts ({chemin}) was updated outside Vanguard, to version {v}, published and signed by the author: Vanguard noted it."
                ),
            )),
            Some(Signee::Inconnu(e)) => Some(
                crate::machine::Constat {
                    verifie: false,
                    ..crate::machine::alerte(
                        CAT,
                        Niveau::Moyen,
                        trf!(
                            "Le programme que lance {tache} ({chemin}) a été remplacé hors de Vanguard, et l'historique signé des versions n'a pas pu dire si c'est une version publiée ({e}) : non vérifié.",
                            "The program {tache} starts ({chemin}) was replaced outside Vanguard, and the signed version history could not tell whether it is a published version ({e}): not checked."
                        ),
                    )
                }
                .manuel(remettre(), &[]),
            ),
            Some(Signee::Non) | None => eleve(trf!(
                "Le programme que lance {tache} ({chemin}) a été remplacé hors de Vanguard : ce ne sont plus les octets que Vanguard a posés, ni une version publiée et signée. Ce qu'il fait et dit ne vient peut-être plus de Vanguard.",
                "The program {tache} starts ({chemin}) was replaced outside Vanguard: these are no longer the bytes Vanguard placed, nor a published and signed version. What it does and says may no longer come from Vanguard."
            )),
        },
        Jugement::TexteChange => eleve(trf!(
            "La tâche de {tache} a été changée hors de Vanguard : ce n'est plus celle que Vanguard a posée (un programme lancé en plus, une heure changée, une condition qui la fait sauter…). Un logiciel malveillant peut s'en servir pour la couper ou lancer autre chose sous son nom.",
            "The task of {tache} was changed outside Vanguard: it is no longer the one Vanguard set up (an extra program started, a changed schedule, a condition that skips it…). Malware can use this to switch it off or run something else under its name."
        )),
        Jugement::ListeForgee => eleve(trf!(
            "La liste des programmes posés par Vanguard a été changée hors de Vanguard, et {tache} lance un programme qui n'est pas ce Vanguard-ci ({chemin}).",
            "The list of programs placed by Vanguard was changed outside Vanguard, and {tache} starts a program that is not this Vanguard ({chemin})."
        )),
        Jugement::NonVerifie(raison) => Some(
            crate::machine::impossible(
                CAT,
                &trf!(
                    "programme lancé par {tache} ({chemin}) non vérifié : {raison}",
                    "program started by {tache} ({chemin}) not checked: {raison}"
                ),
            )
            .manuel(
                trf!(
                    "« {} » refait la tâche et note son programme",
                    "“{}” redoes the task and notes its program",
                    t.refaire()
                ),
                &[],
            ),
        ),
    }
}

/// Le constat d'une tâche qui lance `programme` (un nom sans chemin, que rien d'ici ne situe) alors que Vanguard a posé
/// `pose` : un autre programme, dit en élevé.
pub(crate) fn autre_chemin(t: Tache, programme: &Path, pose: &str) -> Constat {
    constat_de(t, programme, &Jugement::AutreChemin(pose.to_string()), None)
        .unwrap_or_else(|| crate::machine::impossible("Surveillance", pose))
}

/// L'empreinte notée pour la tâche `t` (essais d'autres modules).
#[cfg(test)]
pub(crate) fn empreinte_notee(t: Tache) -> Option<String> {
    lire_dans(&crate::socle::dossier_local())
        .ok()?
        .taches
        .get(t.cle())
        .map(|p| p.empreinte.clone())
}

/// Au bilan : le programme que lance la tâche `t`, et le texte de la tâche (`texte`, lu par l'appelant), sont-ils
/// ceux que Vanguard a posés ? Rien s'ils le sont. Renoté sans rien dire : le programme qui tourne au bon chemin
/// (une mise à jour par paquet), une tâche posée par une version d'avant (premier usage) ; une version signée posée
/// hors de Vanguard, dite. Jamais par-dessus une liste qui ne peut pas être crue : la réécrire effacerait ce doute
/// pour les autres tâches.
pub(crate) fn constat(t: Tache, programme: &Path, texte: &std::io::Result<Vec<u8>>) -> Option<Constat> {
    let dossier = crate::socle::dossier_local();
    let lu = empreinte_de(programme);
    let texte = empreinte_texte(texte);
    let poses = lire_dans(&dossier);
    let pose = poses.as_ref().map(|f| f.taches.get(t.cle())).map_err(|d| *d);
    let ancien_texte = pose.as_ref().ok().and_then(|p| p.and_then(|p| p.texte.clone()));
    let j = juger(programme, &lu, pose, soi(), &texte);
    let signe = (j == Jugement::Remplace).then(|| signee(programme));
    let renoter = match (&j, &signe) {
        (Jugement::Soi, _) | (Jugement::Remplace, Some(Signee::Oui(_))) => Some(ancien_texte),
        (Jugement::Premier, _) => Some(texte.ok()),
        _ => None,
    };
    if let (Some(texte), Ok(e)) = (renoter, &lu) {
        let _ = retenir_dans(&dossier, t, programme, e.clone(), texte);
    }
    constat_de(t, programme, &j, signe.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-poses-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Un faux programme dans le dossier jetable, et son chemin.
    fn programme(d: &Path, octets: &[u8]) -> PathBuf {
        let p = d.join("bin-vanguard");
        std::fs::write(&p, octets).unwrap();
        p
    }

    const UNITE: &[u8] = b"[Service]\nExecStart=\"/x/vanguard\" surveiller\n";

    fn texte(o: &[u8]) -> std::io::Result<String> {
        empreinte_texte(&Ok(o.to_vec()))
    }

    /// Pose la tâche `t` comme `noter` (sans `soi` : les essais ne sont pas Vanguard).
    fn poser(d: &Path, t: Tache, p: &Path) {
        retenir_dans(d, t, p, empreinte_de(p).unwrap(), texte(UNITE).ok()).unwrap();
    }

    fn juger_dans(d: &Path, t: Tache, p: &Path, soi: Option<&str>, unite: &[u8]) -> Jugement {
        let lu = empreinte_de(p);
        let f = lire_dans(d);
        juger(
            p,
            &lu,
            f.as_ref().map(|f| f.taches.get(t.cle())).map_err(|x| *x),
            soi,
            &texte(unite),
        )
    }

    #[test]
    fn empreinte_d_un_fichier() {
        let d = jetable("empreinte");
        let p = programme(&d, b"vanguard 1");
        assert_eq!(
            empreinte_de(&p).unwrap(),
            blake3::hash(b"vanguard 1").to_hex().to_string()
        );
        assert!(empreinte_de(&d).is_err(), "un dossier n'est pas un programme");
        assert!(empreinte_de(&d.join("absent")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn programme_pose_puis_remplace() {
        let d = jetable("remplace");
        let p = programme(&d, b"vanguard 1");
        poser(&d, Tache::Surveillance, &p);
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None, UNITE), Jugement::Sain);
        // Remplacé par un autre programme du compte : alerte élevée, jamais sain.
        std::fs::write(&p, b"autre chose").unwrap();
        let j = juger_dans(&d, Tache::Surveillance, &p, None, UNITE);
        assert_eq!(j, Jugement::Remplace);
        for s in [None, Some(&Signee::Non)] {
            let c = constat_de(Tache::Surveillance, &p, &j, s).expect("alerte");
            assert_eq!(c.probleme, Some(Niveau::Eleve));
            assert!(c.verifie);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Remplacé par une version publiée et signée (mise à jour hors de Vanguard) : dit en information, pas en
    /// élevé ; sans réponse de l'historique : moyen et non vérifié, jamais tu.
    #[test]
    fn version_signee_posee_hors_de_vanguard() {
        let p = Path::new("/x/vanguard");
        let c = constat_de(
            Tache::Surveillance,
            p,
            &Jugement::Remplace,
            Some(&Signee::Oui("0.88.0".into())),
        )
        .unwrap();
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("0.88.0"), "{}", c.message);
        let c = constat_de(
            Tache::Surveillance,
            p,
            &Jugement::Remplace,
            Some(&Signee::Inconnu("hors ligne".into())),
        )
        .unwrap();
        assert!(c.probleme == Some(Niveau::Moyen) && !c.verifie, "{}", c.message);
    }

    /// L'unité pointée vers un autre programme : l'autre chemin est dit, même s'il existe, et même aux octets du
    /// programme qui tourne (une copie ailleurs n'est pas ce que Vanguard a posé).
    #[test]
    fn unite_pointee_ailleurs() {
        let d = jetable("ailleurs");
        let p = programme(&d, b"vanguard 1");
        poser(&d, Tache::Veilleur, &p);
        let autre = d.join("faux-veilleur");
        std::fs::write(&autre, b"vanguard 1").unwrap();
        let soi = empreinte_de(&autre).unwrap();
        for s in [None, Some(soi.as_str())] {
            let j = juger_dans(&d, Tache::Veilleur, &autre, s, UNITE);
            assert!(matches!(j, Jugement::AutreChemin(_)), "{j:?}");
            assert_eq!(
                constat_de(Tache::Veilleur, &autre, &j, None).unwrap().probleme,
                Some(Niveau::Eleve)
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le texte de la tâche changé (une seconde ExecStart=, une condition, une minuterie annuelle), programme
    /// intact : alerte élevée ; illisible : non vérifié.
    #[test]
    fn tache_changee_hors_de_vanguard() {
        let d = jetable("texte");
        let p = programme(&d, b"vanguard 1");
        poser(&d, Tache::Surveillance, &p);
        let change = b"[Service]\nExecCondition=/bin/false\nExecStart=\"/x/vanguard\" surveiller\n";
        let j = juger_dans(&d, Tache::Surveillance, &p, None, change);
        assert_eq!(j, Jugement::TexteChange);
        assert_eq!(
            constat_de(Tache::Surveillance, &p, &j, None).unwrap().probleme,
            Some(Niveau::Eleve)
        );
        // Même le programme qui tourne n'excuse pas une tâche changée.
        let soi = empreinte_de(&p).unwrap();
        assert_eq!(
            juger_dans(&d, Tache::Surveillance, &p, Some(&soi), change),
            Jugement::TexteChange
        );
        let lu = empreinte_de(&p);
        let f = lire_dans(&d);
        let j = juger(
            &p,
            &lu,
            f.as_ref().map(|f| f.taches.get("surveillance")).map_err(|x| *x),
            None,
            &Err(std::io::Error::other("refus")),
        );
        assert!(matches!(j, Jugement::NonVerifie(_)), "{j:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La liste réécrite sans sceau (l'empreinte d'un autre programme mise à la place) : non vérifiée, ou élevée
    /// quand le programme lancé n'est pas celui qui tourne ; adoptée après des sceaux effacés : non vérifiée.
    #[test]
    fn liste_forgee() {
        let d = jetable("forgee");
        let p = programme(&d, b"vanguard 1");
        poser(&d, Tache::Entretien, &p);
        std::fs::write(&p, b"autre chose").unwrap();
        let forge = format!(
            r#"{{"taches":{{"entretien":{{"chemin":"{}","empreinte":"{}"}}}}}}"#,
            p.display(),
            empreinte_de(&p).unwrap()
        );
        std::fs::write(d.join(FICHIER), forge).unwrap();
        let j = juger_dans(&d, Tache::Entretien, &p, None, UNITE);
        assert!(matches!(j, Jugement::NonVerifie(_)), "{j:?}");
        assert!(!constat_de(Tache::Entretien, &p, &j, None).unwrap().verifie);
        assert_eq!(
            juger_dans(&d, Tache::Entretien, &p, Some("0000"), UNITE),
            Jugement::ListeForgee
        );
        // Adoptée après des sceaux effacés : jamais crue (née scellée).
        std::fs::remove_file(d.join("sceaux.json")).unwrap();
        assert!(matches!(lire_dans(&d), Err(Doute::Adopte)));
        assert!(matches!(
            juger_dans(&d, Tache::Entretien, &p, None, UNITE),
            Jugement::NonVerifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Rien de noté (tâche d'une version d'avant) : premier usage ; programme illisible : non vérifié.
    #[test]
    fn premier_usage_ou_illisible() {
        let d = jetable("jamais");
        let p = programme(&d, b"vanguard 1");
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None, UNITE), Jugement::Premier);
        assert!(constat_de(Tache::Surveillance, &p, &Jugement::Premier, None).is_none());
        let absent = d.join("absent");
        assert!(matches!(
            juger_dans(&d, Tache::Surveillance, &absent, None, UNITE),
            Jugement::NonVerifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le programme qui tourne, au chemin posé, se reconnaît (mise à jour par paquet) ; d'autres octets : remplacé.
    #[test]
    fn le_programme_qui_tourne_se_reconnait() {
        let d = jetable("soi");
        let p = programme(&d, b"vanguard 1");
        poser(&d, Tache::Surveillance, &p);
        std::fs::write(&p, b"vanguard 2").unwrap();
        let e = empreinte_de(&p).unwrap();
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, Some(&e), UNITE), Jugement::Soi);
        assert!(constat_de(Tache::Surveillance, &p, &Jugement::Soi, None).is_none());
        assert_eq!(
            juger_dans(&d, Tache::Surveillance, &p, Some("0000"), UNITE),
            Jugement::Remplace
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// À la pose, le programme qui tourne scelle ses propres octets, sauf pour la copie de cet ordinateur (une
    /// version plus récente gardée) : un fichier changé entre la pose et sa lecture n'est pas scellé comme le sien.
    #[test]
    fn pose_scelle_les_octets_du_programme_qui_tourne() {
        let (p, copie) = (Path::new("/x/vanguard"), Path::new("/d/bin/vanguard"));
        assert_eq!(a_sceller(p, "etranger".into(), Some("soi"), copie), "soi");
        assert_eq!(a_sceller(p, "soi".into(), Some("soi"), copie), "soi");
        assert_eq!(a_sceller(copie, "recente".into(), Some("soi"), copie), "recente");
        assert_eq!(a_sceller(p, "lu".into(), None, copie), "lu");
    }

    /// Un nom sans chemin (« vanguard », « @… ») alors qu'un chemin a été posé : un autre programme, élevé.
    #[test]
    fn nom_sans_chemin_apres_une_pose() {
        let c = autre_chemin(Tache::Surveillance, Path::new("vanguard"), "/x/bin/vanguard");
        assert_eq!(c.probleme, Some(Niveau::Eleve), "{}", c.message);
    }

    /// Une mise à jour par Vanguard renote l'empreinte de chaque tâche qui lance la copie ; les autres ne bougent pas.
    #[test]
    fn mise_a_jour_par_vanguard_renote() {
        let d = jetable("maj");
        let p = programme(&d, b"vanguard 1");
        let ailleurs = d.join("autre-vanguard");
        std::fs::write(&ailleurs, b"vanguard x").unwrap();
        poser(&d, Tache::Surveillance, &p);
        poser(&d, Tache::Veilleur, &ailleurs);
        std::fs::write(&p, b"vanguard 2").unwrap();
        assert_eq!(copie_posee_dans(&d, &p, b"vanguard 2"), vec![Tache::Surveillance]);
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None, UNITE), Jugement::Sain);
        assert_eq!(juger_dans(&d, Tache::Veilleur, &ailleurs, None, UNITE), Jugement::Sain);
        assert_eq!(copie_posee_dans(&d, &p, b"vanguard 2"), Vec::<Tache>::new());
        oublier_dans(&d, Tache::Surveillance);
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None, UNITE), Jugement::Premier);
        let _ = std::fs::remove_dir_all(&d);
    }
}
