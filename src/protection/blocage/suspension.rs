//! Suspendre un programme menaçant au lieu de l'arrêter : il ne fait plus rien, mais il est toujours là (ses fichiers
//! ouverts, sa mémoire, ses connexions), le temps de regarder ou de demander conseil ; la suspension se lève par
//! `vanguard blocage reprendre`. Toujours demandée par la personne (menu des gestes, `vanguard blocage suspendre`),
//! jamais automatique, et derrière les mêmes garde-fous que l'arrêt (rejugés par `ordres::juger`).
//!
//! Sans course entre la lecture du programme et le geste :
//! - Linux : le départ du processus lu, son programme relu, puis SIGSTOP par un pidfd ouvert AVANT de relire le
//!   départ (`socle::processus::geler_si`, comme l'arrêt du veilleur) ; gelé, son programme est relu une dernière
//!   fois (un `exec` juste avant le gel garde le départ) et, s'il a changé, il est repris aussitôt.
//! - Windows : la poignée qui lit le chemin et l'heure de création est celle qui suspend (NtSuspendProcess), puis des
//!   passes fil par fil rattrapent les fils nés pendant (`machine::windows::processus::suspendre_si`).
//!
//! Ce qui est suspendu est noté dans une liste scellée (`sceau::SUSPENDUS`) : au bilan, ce qu'un tiers a repris est
//! resuspendu, ce qui reste suspendu est rappelé (un programme gelé et oublié tient ses fichiers), ce qui est fini
//! est oublié.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use serde::{Deserialize, Serialize};

use super::ordres::{self, Ordre};
use crate::modele::Echec;
use crate::ui::*;

const OU: &str = "blocage/suspension";
/// Au plus tant de programmes suspendus retenus : au-delà, la liste n'est pas celle de Vanguard.
const SUSPENDUS_MAX: usize = 64;

/// Un programme suspendu par Vanguard.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Suspendu {
    pub(crate) pid: u32,
    /// Son départ (Linux : 22e champ de stat ; Windows : heure de création) : un numéro repris par un autre processus
    /// n'est jamais resuspendu ni repris à sa place. `None` : illisible au moment de suspendre.
    pub(crate) depart: Option<u64>,
    pub(crate) chemin: String,
    /// Ce que la menace disait (« Programme malveillant en marche : x »), pour le rappel.
    pub(crate) quoi: String,
    /// AAAA-MM-JJ HH:MM, heure locale.
    pub(crate) le: String,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
struct Liste {
    #[serde(default)]
    suspendus: Vec<Suspendu>,
}

/// La liste ; changée hors de Vanguard (ou acceptée sans sceau, ce fichier étant né avec eux) : la raison. Une liste
/// forgée ne fait rien reprendre : la reprise relit le programme du processus et ne vise qu'un processus gelé.
fn charger() -> Result<Liste, &'static str> {
    use crate::sceau::Lecture;
    match crate::sceau::lire(crate::sceau::SUSPENDUS) {
        Lecture::Absent | Lecture::Inconnu => Ok(Liste::default()),
        Lecture::Intact(o) => serde_json::from_slice(&o).map_err(|_| illisible()),
        Lecture::Adopte(_) | Lecture::Falsifie(_) => Err(tr!(
            "la liste des programmes suspendus a été changée hors de Vanguard",
            "the list of suspended programs was changed outside Vanguard"
        )),
        Lecture::Illisible(_) => Err(illisible()),
    }
}

fn illisible() -> &'static str {
    tr!(
        "la liste des programmes suspendus ne se lit plus",
        "the list of suspended programs can no longer be read"
    )
}

fn enregistrer(l: &Liste) -> std::io::Result<()> {
    crate::sceau::ecrire(
        crate::sceau::SUSPENDUS,
        serde_json::to_string_pretty(l).map_err(std::io::Error::other)?,
    )
}

// Windows : `suspendre_si` relit le chemin par la poignée qui suspend, un refus y dit les deux cas.
#[cfg(target_os = "linux")]
fn reaffecte(pid: u32) -> Echec {
    Echec::refuse(
        OU,
        trf!(
            "le PID {pid} désigne maintenant un autre programme (ou plus aucun) : rien n'est suspendu",
            "PID {pid} now points to another program (or none): nothing is suspended"
        ),
    )
}

fn refuse_par_le_systeme(pid: u32) -> Echec {
    Echec::refuse(
        OU,
        trf!(
            "le système refuse de suspendre le processus {pid} (droits, ou déjà fini) : rien n'est suspendu",
            "the system refuses to suspend process {pid} (rights, or already ended): nothing is suspended"
        ),
    )
}

/// Le départ du processus `pid` (voir `Suspendu::depart`).
fn depart(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        crate::socle::processus::debut(pid)
    }
    #[cfg(windows)]
    {
        crate::machine::windows::processus::creation(pid)
    }
}

/// Suspend `pid` s'il fait toujours tourner `chemin`, avec les droits de ce processus, sans autre garde (celles de
/// `ordres::juger` sont passées avant) : le départ du processus suspendu, ou pourquoi rien ne l'est.
pub(crate) fn suspendre_ici(pid: u32, chemin: &str) -> Result<Option<u64>, Echec> {
    #[cfg(target_os = "linux")]
    {
        use crate::socle::processus;
        let d = processus::debut(pid).ok_or_else(|| reaffecte(pid))?;
        if !super::gestes::chemin_du_processus(pid).is_some_and(|a| super::gestes::meme_chemin(&a, chemin)) {
            return Err(reaffecte(pid));
        }
        // Le pidfd est ouvert, puis le départ relu : le même, c'est ce processus qui est gelé.
        if !processus::geler_si(pid, d) {
            return Err(refuse_par_le_systeme(pid));
        }
        // Le gel se fait quand le noyau sert le processus : un instant après le signal (2 s au plus).
        for _ in 0..200u8 {
            if processus::est_gele(pid) != Some(false) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Gelé, il ne peut plus changer de programme : relu une dernière fois (un exec juste avant le gel garde le
        // départ). Un autre programme est repris aussitôt, rien ne reste gelé à tort.
        if !super::gestes::chemin_du_processus(pid).is_some_and(|a| super::gestes::meme_chemin(&a, chemin)) {
            processus::reprendre_si(pid, d);
            return Err(reaffecte(pid));
        }
        if processus::est_gele(pid) != Some(true) {
            return Err(refuse_par_le_systeme(pid));
        }
        Ok(Some(d))
    }
    #[cfg(windows)]
    {
        use crate::machine::windows::processus;
        let c = processus::creation(pid);
        if processus::suspendre_si(pid, chemin, c) {
            Ok(c)
        } else {
            Err(refuse_par_le_systeme(pid))
        }
    }
}

/// Reprend `pid` s'il fait toujours tourner `chemin` (et depuis `depart`, s'il est connu), avec les droits de ce
/// processus.
pub(crate) fn reprendre_ici(pid: u32, chemin: &str, depart_connu: Option<u64>) -> Result<(), Echec> {
    let refus = || {
        Echec::refuse(
            OU,
            trf!(
                "le processus {pid} n'est plus ce programme, est fini, ou le système refuse : rien n'est repris",
                "process {pid} no longer runs this program, has ended, or the system refuses: nothing is resumed"
            ),
        )
    };
    #[cfg(target_os = "linux")]
    {
        use crate::socle::processus;
        let d = depart_connu.or_else(|| processus::debut(pid)).ok_or_else(refus)?;
        let meme = super::gestes::chemin_du_processus(pid).is_some_and(|a| super::gestes::meme_chemin(&a, chemin));
        if !meme || !processus::reprendre_si(pid, d) {
            return Err(refus());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        if crate::machine::windows::processus::reprendre_si(pid, chemin, depart_connu) {
            Ok(())
        } else {
            Err(refus())
        }
    }
}

/// Ce processus noté est-il encore là et suspendu ? `None` : fini, ou un autre processus sur ce numéro.
fn est_suspendu(s: &Suspendu) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        use crate::socle::processus;
        if s.depart.is_some_and(|d| processus::debut(s.pid) != Some(d)) {
            return None;
        }
        if !super::gestes::chemin_du_processus(s.pid).is_some_and(|a| super::gestes::meme_chemin(&a, &s.chemin)) {
            return None;
        }
        processus::est_gele(s.pid)
    }
    #[cfg(windows)]
    {
        crate::machine::windows::processus::est_suspendu_si(s.pid, &s.chemin, s.depart)
    }
}

/// Ce compte peut-il suspendre ce processus lui-même ? Sinon l'ordre passe par l'assistant élevé (Linux) ou le
/// processus élevé (Windows), qui le rejuge.
fn sans_droits_de_plus(pid: u32) -> bool {
    #[cfg(windows)]
    {
        crate::machine::windows::processus::peut_suspendre(pid)
    }
    #[cfg(unix)]
    {
        super::gestes::arret_sans_droits(pid)
    }
}

/// Fait un ordre de suspension ou de reprise : ici si ce compte en a les droits (rejugé ici), sinon par l'assistant
/// élevé (qui le rejuge à son tour). `Err` : ce qui l'a empêché.
fn faire_l_ordre(o: &Ordre, pid: u32) -> Result<(), Echec> {
    if sans_droits_de_plus(pid) {
        let r = ordres::juger_et_faire(o, &ordres::Juge::lire(None));
        return if r.reussi {
            Ok(())
        } else {
            Err(Echec::refuse(OU, r.raison))
        };
    }
    // Jugé ici d'abord : un refus évident ne demande pas les droits pour rien.
    if let Some(raison) = ordres::juger(o, &ordres::Juge::lire(None)) {
        return Err(Echec::refuse(OU, raison));
    }
    let (fait, notes) = crate::machine::appliquer_sans_noter(&[o.ligne()]);
    if fait {
        Ok(())
    } else {
        let raison = notes.join(" ; ");
        Err(Echec::refuse(
            OU,
            if raison.is_empty() {
                tr!("refusé ou droits non accordés", "refused or rights not granted").to_string()
            } else {
                raison
            },
        ))
    }
}

/// Suspend le programme d'une menace, demandé par la personne : garde-fous rejugés, geste sans course, puis noté
/// (liste scellée et journal). `cle` : la clé de la menace, au journal.
pub(crate) fn suspendre(pid: u32, chemin: &str, quoi: &str, cle: Option<&str>) -> Result<(), Echec> {
    let o = Ordre::SuspendreProcessus {
        pid,
        chemin: chemin.to_string(),
    };
    let resultat = faire_l_ordre(&o, pid);
    noter_au_journal(&o, resultat.is_ok(), cle);
    resultat?;
    retenir(Suspendu {
        pid,
        depart: depart(pid),
        chemin: chemin.to_string(),
        quoi: quoi.to_string(),
        le: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
    })
}

/// Le geste au journal des événements, avec sa ligne d'ordre : ce qui a été suspendu ou repris, et quand.
fn noter_au_journal(o: &Ordre, reussi: bool, cle: Option<&str>) {
    use crate::modele::evenement::{Evenement, Source};
    crate::modele::journal::noter(Evenement::action(Source::Utilisateur, &o.texte(), reussi, &[o.ligne()]).cle(cle));
}

/// Ajoute un suspendu à la liste (le même numéro remplacé). Une liste changée hors de Vanguard est remise à neuf :
/// le programme reste suspendu, c'est dit.
fn retenir(s: Suspendu) -> Result<(), Echec> {
    let mut l = charger().unwrap_or_default();
    l.suspendus.retain(|x| x.pid != s.pid);
    l.suspendus.push(s);
    if l.suspendus.len() > SUSPENDUS_MAX {
        l.suspendus.remove(0);
    }
    enregistrer(&l).map_err(|e| Echec::ecriture(OU, &e))
}

/// Les programmes suspendus retenus (vide si la liste ne compte pas).
/// La liste se lit-elle (pas changée hors de Vanguard) ? Sinon, pourquoi.
pub(crate) fn lisible() -> Result<(), &'static str> {
    charger().map(|_| ())
}

#[cfg(test)]
fn suspendus() -> Vec<Suspendu> {
    charger().map(|l| l.suspendus).unwrap_or_default()
}

/// Reprend un programme suspendu par Vanguard (`pid`), ou tous (`None`) : chacun relu, repris par ses droits ou ceux
/// de l'assistant, puis oublié. Rend, pour chacun, ce qu'il est et le résultat.
pub(crate) fn reprendre(pid: Option<u32>) -> Vec<(Suspendu, Result<(), Echec>)> {
    let Ok(mut l) = charger() else {
        return Vec::new();
    };
    let (vises, gardes): (Vec<Suspendu>, Vec<Suspendu>) =
        l.suspendus.drain(..).partition(|s| pid.is_none_or(|p| p == s.pid));
    l.suspendus = gardes;
    let mut faits = Vec::new();
    for s in vises {
        // Fini ou remplacé : il n'y a plus rien à reprendre, il est oublié.
        let r = if est_suspendu(&s).is_none() {
            Ok(())
        } else {
            let o = Ordre::ReprendreProcessus {
                pid: s.pid,
                chemin: s.chemin.clone(),
            };
            let r = if sans_droits_de_plus(s.pid) {
                reprendre_ici(s.pid, &s.chemin, s.depart)
            } else {
                faire_l_ordre(&o, s.pid)
            };
            noter_au_journal(&o, r.is_ok(), None);
            r
        };
        if r.is_err() {
            l.suspendus.push(s.clone());
        }
        faits.push((s, r));
    }
    let _ = enregistrer(&l);
    faits
}

/// Ce que le bilan constate d'un programme suspendu.
#[derive(Debug, PartialEq)]
pub(crate) enum Constat {
    /// Toujours suspendu.
    Suspendu,
    /// Un tiers l'avait repris : resuspendu.
    Resuspendu,
    /// Un tiers l'a repris, et il ne se resuspend pas (droits) : il tourne.
    Repris,
}

/// Que faire d'un suspendu, d'après ce qu'on lit : `None` (fini, remplacé) l'oublie ; repris par un tiers, il se
/// resuspend. Pur.
pub(crate) fn constat(lu: Option<bool>, resuspendu: impl FnOnce() -> bool) -> Option<Constat> {
    match lu? {
        true => Some(Constat::Suspendu),
        false if resuspendu() => Some(Constat::Resuspendu),
        false => Some(Constat::Repris),
    }
}

/// Au bilan : chaque suspendu relu, resuspendu s'il a été repris, oublié s'il est fini ; la liste de ce qui reste.
pub(crate) fn verifier() -> Vec<(Suspendu, Constat)> {
    let Ok(mut l) = charger() else {
        return Vec::new();
    };
    let mut restent = Vec::new();
    let mut constats = Vec::new();
    for s in l.suspendus.drain(..) {
        let c = constat(est_suspendu(&s), || {
            sans_droits_de_plus(s.pid) && suspendre_ici(s.pid, &s.chemin).is_ok()
        });
        if let Some(c) = c {
            restent.push(s.clone());
            constats.push((s, c));
        }
    }
    l.suspendus = restent;
    let _ = enregistrer(&l);
    constats
}

/// Au bilan : rappelle ce qui reste suspendu, et ce qu'un tiers a repris.
pub(crate) fn rappeler() {
    let constats = verifier();
    if constats.is_empty() {
        return;
    }
    crate::ui::section(tr!("PROGRAMMES SUSPENDUS", "SUSPENDED PROGRAMS"));
    for (s, c) in &constats {
        let (signe, etat) = match c {
            Constat::Suspendu => (format!("{GRIS}‖{RESET}"), tr!("toujours suspendu", "still suspended")),
            Constat::Resuspendu => (
                format!("{}‖{RESET}", couleur(crate::risk::Niveau::Eleve)),
                tr!(
                    "un autre programme l'avait repris : suspendu de nouveau",
                    "another program had resumed it: suspended again"
                ),
            ),
            Constat::Repris => (
                format!("{}⚠{RESET}", couleur(crate::risk::Niveau::Eleve)),
                tr!(
                    "un autre programme l'a repris, et il ne se suspend plus d'ici",
                    "another program resumed it, and it can no longer be suspended from here"
                ),
            ),
        };
        afficher_aligne(
            &format!("  {signe} "),
            &format!(
                "{} (PID {}, {}) : {etat}.",
                affichable(&s.quoi),
                s.pid,
                trf!("depuis le {}", "since {}", s.le)
            ),
            4,
            "",
        );
    }
    afficher_aligne(
        "    ",
        &trf!(
            "Pour le reprendre : vanguard blocage reprendre {} ; pour l'arrêter, choisissez « Bloquer » à sa menace.",
            "To resume it: vanguard blocking resume {}; to stop it, choose “Block” on its threat.",
            constats.first().map_or(0, |(s, _)| s.pid)
        ),
        4,
        GRIS,
    );
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// Fini ou remplacé : oublié ; suspendu : rappelé ; repris par un tiers : resuspendu si possible, sinon dit.
    #[test]
    fn constats_du_bilan() {
        assert_eq!(constat(None, || panic!("rien à resuspendre")), None);
        assert_eq!(constat(Some(true), || panic!("déjà suspendu")), Some(Constat::Suspendu));
        assert_eq!(constat(Some(false), || true), Some(Constat::Resuspendu));
        assert_eq!(constat(Some(false), || false), Some(Constat::Repris));
    }

    /// La liste se relit telle qu'écrite (dossier jetable des essais) ; un même numéro remplace l'ancien.
    #[test]
    fn liste_relue() {
        let s = |pid, quoi: &str| Suspendu {
            pid,
            depart: Some(7),
            chemin: "/tmp/x".into(),
            quoi: quoi.into(),
            le: "2026-11-07 10:00".into(),
        };
        retenir(s(4242, "a")).unwrap();
        retenir(s(4243, "b")).unwrap();
        retenir(s(4242, "c")).unwrap();
        let l = suspendus();
        assert!(l.contains(&s(4243, "b")) && l.contains(&s(4242, "c")));
        assert!(!l.contains(&s(4242, "a")));
    }

    /// Un enfant jetable (`sleep`) suspendu sans course : un autre programme attendu ne le touche pas ; le bon le
    /// gèle ; la reprise par un programme faux ne fait rien, la bonne le reprend.
    #[cfg(target_os = "linux")]
    #[test]
    fn suspension_d_un_enfant() {
        use crate::socle::processus::est_gele;
        let Ok(mut enfant) = std::process::Command::new("sleep").arg("30").spawn() else {
            return crate::essais::saute("sleep ne se lance pas");
        };
        let pid = enfant.id();
        let moi = std::env::current_exe().unwrap().to_string_lossy().into_owned();
        let mut programme = None;
        for _ in 0..500 {
            match super::super::gestes::chemin_du_processus(pid) {
                Some(p) if p != moi => {
                    programme = Some(p);
                    break;
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        let Some(programme) = programme else {
            let _ = enfant.kill();
            return crate::essais::saute("l'enfant ne passe pas à sleep");
        };
        let autre = suspendre_ici(pid, "/autre/programme");
        let libre = est_gele(pid);
        let bon = suspendre_ici(pid, &programme);
        let gele = est_gele(pid);
        let reprise_fausse = reprendre_ici(pid, "/autre/programme", None);
        let toujours = est_gele(pid);
        let reprise = reprendre_ici(pid, &programme, bon.as_ref().ok().copied().flatten());
        let mut repris = est_gele(pid);
        for _ in 0..200 {
            if repris != Some(true) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            repris = est_gele(pid);
        }
        let _ = enfant.kill();
        let _ = enfant.wait();
        assert!(autre.is_err());
        assert_eq!(libre, Some(false));
        assert!(bon.as_ref().is_ok_and(Option::is_some), "{bon:?}");
        assert_eq!(gele, Some(true));
        assert!(reprise_fausse.is_err());
        assert_eq!(toujours, Some(true));
        assert!(reprise.is_ok(), "{reprise:?}");
        assert_eq!(repris, Some(false));
        assert!(suspendre_ici(pid, &programme).is_err(), "fini : rien à suspendre");
    }
}
