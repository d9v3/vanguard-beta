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
fn soi() -> Option<&'static str> {
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
        Lecture::Adopte(o) if !crate::sceau::refaits_dans(dossier) => o,
        Lecture::Adopte(_) => return Err(Doute::Adopte),
        Lecture::Falsifie(_) => return Err(Doute::HorsVanguard),
        Lecture::Inconnu => return Err(Doute::Inconnu),
        Lecture::Illisible(_) => return Err(Doute::Illisible),
    };
    serde_json::from_slice(&octets).map_err(|_| Doute::Illisible)
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

fn retenir_dans(dossier: &Path, t: Tache, chemin: &Path, empreinte: String) -> std::io::Result<()> {
    let pose = Pose {
        chemin: chemin.display().to_string(),
        empreinte,
    };
    changer_dans(dossier, |f| {
        f.taches.insert(t.cle().to_string(), pose.clone()) != Some(pose)
    })
}

/// Vanguard vient de poser la tâche `t`, qui lance `chemin` : son empreinte est scellée. Un nom sans chemin (le
/// programme ne s'est pas situé) n'a rien à sceller : le bilan le dit non vérifié.
pub(crate) fn noter(t: Tache, chemin: &Path) {
    if !chemin.is_absolute() {
        return;
    }
    let r = empreinte_de(chemin)
        .map_err(std::io::Error::other)
        .and_then(|e| retenir_dans(&crate::socle::dossier_local(), t, chemin, e));
    if let Err(e) = r {
        crate::modele::Echec::echoue("programmes_poses/noter", e.to_string()).journaliser();
    }
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
fn meme_chemin(a: &Path, b: &Path) -> bool {
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
    /// Le programme que Vanguard a posé, tel qu'il l'a posé.
    Sain,
    /// Les octets du programme qui tourne : Vanguard lui-même.
    Soi,
    /// Un autre chemin que celui que Vanguard a posé.
    AutreChemin(String),
    /// Le chemin posé, mais d'autres octets.
    Remplace,
    NonVerifie(String),
}

/// Le jugement, sans rien lire : le programme lancé, son empreinte lue, ce que le sceau dit de la tâche, et
/// l'empreinte du programme qui tourne quand elle se connaît.
fn juger(
    programme: &Path,
    lu: &Result<String, String>,
    pose: Result<Option<&Pose>, Doute>,
    soi: Option<&str>,
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
    if soi == Some(lu.as_str()) {
        return Jugement::Soi;
    }
    match pose {
        Err(d) => Jugement::NonVerifie(trf!(
            "la liste des programmes posés par Vanguard ({FICHIER}) {}",
            "the list of programs placed by Vanguard ({FICHIER}) {}",
            d.texte()
        )),
        Ok(None) => Jugement::NonVerifie(
            tr!(
                "son empreinte n'a jamais été notée (tâche posée par une version d'avant)",
                "its fingerprint was never noted (task set up by an earlier version)"
            )
            .to_string(),
        ),
        Ok(Some(p)) if !meme_chemin(Path::new(&p.chemin), programme) => Jugement::AutreChemin(p.chemin.clone()),
        Ok(Some(p)) if p.empreinte != *lu => Jugement::Remplace,
        Ok(Some(_)) => Jugement::Sain,
    }
}

/// Le constat d'un jugement : rien quand c'est Vanguard ; une alerte élevée pour un autre programme ; « non vérifié »
/// sinon.
fn constat_de(t: Tache, programme: &Path, j: &Jugement) -> Option<Constat> {
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
    match j {
        Jugement::Sain | Jugement::Soi => None,
        Jugement::AutreChemin(pose) => Some(
            crate::machine::alerte(
                CAT,
                Niveau::Eleve,
                trf!(
                    "{tache} lance un autre programme que celui que Vanguard a posé : {chemin}, au lieu de {}. Un logiciel malveillant peut s'y faire passer pour Vanguard.",
                    "{tache} starts another program than the one Vanguard placed: {chemin}, instead of {}. Malware can pass itself off as Vanguard there.",
                    crate::ui::chemin_affichable(Path::new(pose))
                ),
            )
            .manuel(remettre(), &[]),
        ),
        Jugement::Remplace => Some(
            crate::machine::alerte(
                CAT,
                Niveau::Eleve,
                trf!(
                    "Le programme que lance {tache} ({chemin}) a été remplacé hors de Vanguard : ce ne sont plus les octets que Vanguard a posés. Ce qu'il fait et dit ne vient peut-être plus de Vanguard.",
                    "The program {tache} starts ({chemin}) was replaced outside Vanguard: these are no longer the bytes Vanguard placed. What it does and says may no longer come from Vanguard."
                ),
            )
            .manuel(remettre(), &[]),
        ),
        Jugement::NonVerifie(raison) => Some(
            crate::machine::impossible(
                CAT,
                &trf!(
                    "programme lancé par {tache} ({chemin}) non vérifié : {raison}",
                    "program started by {tache} ({chemin}) not checked: {raison}"
                ),
            )
            .manuel(
                &trf!(
                    "« {} » refait la tâche et note son programme",
                    "“{}” redoes the task and notes its program",
                    t.refaire()
                ),
                &[],
            ),
        ),
    }
}

/// Au bilan : le programme que lance la tâche `t` est-il celui que Vanguard a posé ? Rien s'il l'est ; s'il est le
/// programme qui tourne, son sceau est renoté (jamais par-dessus un état qui ne peut pas être cru : le réécrire
/// effacerait ce doute pour les autres tâches).
pub(crate) fn constat(t: Tache, programme: &Path) -> Option<Constat> {
    let dossier = crate::socle::dossier_local();
    let lu = empreinte_de(programme);
    let poses = lire_dans(&dossier);
    let pose = poses.as_ref().map(|f| f.taches.get(t.cle())).map_err(|d| *d);
    let j = juger(programme, &lu, pose, soi());
    if j == Jugement::Soi
        && poses.is_ok()
        && let Ok(e) = lu
    {
        let _ = retenir_dans(&dossier, t, programme, e);
    }
    constat_de(t, programme, &j)
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

    fn juger_dans(d: &Path, t: Tache, p: &Path, soi: Option<&str>) -> Jugement {
        let lu = empreinte_de(p);
        let f = lire_dans(d);
        juger(p, &lu, f.as_ref().map(|f| f.taches.get(t.cle())).map_err(|x| *x), soi)
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
        retenir_dans(&d, Tache::Surveillance, &p, empreinte_de(&p).unwrap()).unwrap();
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None), Jugement::Sain);
        // Remplacé par un autre programme du compte : alerte élevée, jamais sain.
        std::fs::write(&p, b"autre chose").unwrap();
        let j = juger_dans(&d, Tache::Surveillance, &p, None);
        assert_eq!(j, Jugement::Remplace);
        let c = constat_de(Tache::Surveillance, &p, &j).expect("alerte");
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.verifie);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'unité pointée vers un autre programme : l'autre chemin est dit, même s'il existe.
    #[test]
    fn unite_pointee_ailleurs() {
        let d = jetable("ailleurs");
        let p = programme(&d, b"vanguard 1");
        retenir_dans(&d, Tache::Veilleur, &p, empreinte_de(&p).unwrap()).unwrap();
        let autre = d.join("faux-veilleur");
        std::fs::write(&autre, b"vanguard 1").unwrap();
        let j = juger_dans(&d, Tache::Veilleur, &autre, None);
        assert!(matches!(j, Jugement::AutreChemin(_)), "{j:?}");
        assert_eq!(
            constat_de(Tache::Veilleur, &autre, &j).unwrap().probleme,
            Some(Niveau::Eleve)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La liste réécrite sans sceau (l'empreinte d'un autre programme mise à la place) : non vérifié, jamais sain.
    #[test]
    fn liste_forgee_non_verifiee() {
        let d = jetable("forgee");
        let p = programme(&d, b"vanguard 1");
        retenir_dans(&d, Tache::Entretien, &p, empreinte_de(&p).unwrap()).unwrap();
        std::fs::write(&p, b"autre chose").unwrap();
        let forge = format!(
            r#"{{"taches":{{"entretien":{{"chemin":"{}","empreinte":"{}"}}}}}}"#,
            p.display(),
            empreinte_de(&p).unwrap()
        );
        std::fs::write(d.join(FICHIER), forge).unwrap();
        let j = juger_dans(&d, Tache::Entretien, &p, None);
        assert!(matches!(j, Jugement::NonVerifie(_)), "{j:?}");
        let c = constat_de(Tache::Entretien, &p, &j).unwrap();
        assert!(!c.verifie);
        // Adoptée après des sceaux refaits : non vérifiée aussi.
        std::fs::remove_file(d.join("sceaux.json")).unwrap();
        assert!(matches!(lire_dans(&d), Err(Doute::Adopte)));
        assert!(matches!(
            juger_dans(&d, Tache::Entretien, &p, None),
            Jugement::NonVerifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn jamais_note_ou_illisible_non_verifie() {
        let d = jetable("jamais");
        let p = programme(&d, b"vanguard 1");
        assert!(matches!(
            juger_dans(&d, Tache::Surveillance, &p, None),
            Jugement::NonVerifie(_)
        ));
        let absent = d.join("absent");
        assert!(matches!(
            juger_dans(&d, Tache::Surveillance, &absent, None),
            Jugement::NonVerifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le programme qui tourne se reconnaît, même quand le sceau ne peut pas être cru : ce sont ses octets.
    #[test]
    fn le_programme_qui_tourne_se_reconnait() {
        let d = jetable("soi");
        let p = programme(&d, b"vanguard 2");
        let e = empreinte_de(&p).unwrap();
        std::fs::write(d.join(FICHIER), b"{}").unwrap();
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, Some(&e)), Jugement::Soi);
        assert!(constat_de(Tache::Surveillance, &p, &Jugement::Soi).is_none());
        // D'autres octets que les siens : rien n'est reconnu.
        assert!(matches!(
            juger_dans(&d, Tache::Surveillance, &p, Some("0000")),
            Jugement::NonVerifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une mise à jour par Vanguard renote l'empreinte de chaque tâche qui lance la copie ; les autres ne bougent pas.
    #[test]
    fn mise_a_jour_par_vanguard_renote() {
        let d = jetable("maj");
        let p = programme(&d, b"vanguard 1");
        let ailleurs = d.join("autre-vanguard");
        std::fs::write(&ailleurs, b"vanguard x").unwrap();
        retenir_dans(&d, Tache::Surveillance, &p, empreinte_de(&p).unwrap()).unwrap();
        retenir_dans(&d, Tache::Veilleur, &ailleurs, empreinte_de(&ailleurs).unwrap()).unwrap();
        std::fs::write(&p, b"vanguard 2").unwrap();
        assert_eq!(copie_posee_dans(&d, &p, b"vanguard 2"), vec![Tache::Surveillance]);
        assert_eq!(juger_dans(&d, Tache::Surveillance, &p, None), Jugement::Sain);
        assert_eq!(juger_dans(&d, Tache::Veilleur, &ailleurs, None), Jugement::Sain);
        assert_eq!(copie_posee_dans(&d, &p, b"vanguard 2"), Vec::<Tache>::new());
        oublier_dans(&d, Tache::Surveillance);
        assert!(matches!(
            juger_dans(&d, Tache::Surveillance, &p, None),
            Jugement::NonVerifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }
}
