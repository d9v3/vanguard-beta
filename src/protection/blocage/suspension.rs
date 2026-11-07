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
//! Seul le processus visé est gelé : les programmes qu'il a déjà lancés (ses enfants) continuent, et c'est dit avant
//! de suspendre. Sous Linux, tout programme du même compte (un enfant du malware, par exemple) peut le reprendre
//! (SIGCONT), un administrateur aussi ; sous Windows, tout programme qui a le droit de reprendre ses fils.
//!
//! Ce qui est suspendu est noté dans une liste scellée (`sceau::SUSPENDUS`). Au bilan, chacun est relu : toujours
//! suspendu, il est rappelé (un programme gelé et oublié tient ses fichiers) ; repris par un tiers, il est resuspendu
//! si ce compte en a les droits et que son départ est connu, sinon c'est dit ; illisible d'ici (un processus élevé ou
//! d'un autre compte), il est gardé et dit tel quel, jamais oublié en silence ; fini, il est oublié ; devenu un autre
//! programme, c'est dit, puis il est oublié. Une liste changée hors de Vanguard est annoncée.
//!
//! Windows compte les suspensions de chaque fil : Vanguard n'en pose qu'une par processus (NtSuspendProcess, une
//! seule fois, puis les fils qui tournent encore, un par un) ; une resuspension ne touche qu'aux fils qui tournent ;
//! la reprise (NtResumeProcess) retire donc exactement la sienne (`comptes`, essai `compte_des_fils`).

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::ordres::{self, Ordre};
use crate::modele::Echec;
use crate::ui::*;

const OU: &str = "blocage/suspension";
/// Au plus tant de programmes suspendus à la fois : au-delà, une nouvelle suspension est refusée (et c'est dit).
const SUSPENDUS_MAX: usize = 64;

/// Un programme suspendu par Vanguard.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Suspendu {
    pub(crate) pid: u32,
    /// Son départ (Linux : 22e champ de stat ; Windows : heure de création) : un numéro repris par un autre processus
    /// n'est jamais resuspendu ni repris à sa place. `None` : illisible au moment de suspendre ; il n'est alors jamais
    /// resuspendu par le bilan.
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

/// Une liste qui ne compte pas : pourquoi, et ce qu'elle dit (sans foi : une liste changée hors de Vanguard ne fait
/// jamais rien suspendre ni reprendre d'elle-même ; elle sert à nommer ses numéros).
struct Refus {
    raison: &'static str,
    dit: Vec<Suspendu>,
}

/// La liste ; changée hors de Vanguard (ou acceptée sans sceau, ce fichier étant né avec eux) ou illisible : le refus.
fn charger() -> Result<Liste, Refus> {
    use crate::sceau::Lecture;
    let dit = |o: &[u8]| {
        serde_json::from_slice::<Liste>(o)
            .map(|l| l.suspendus)
            .unwrap_or_default()
    };
    match crate::sceau::lire(crate::sceau::SUSPENDUS) {
        Lecture::Absent | Lecture::Inconnu => Ok(Liste::default()),
        Lecture::Intact(o) => serde_json::from_slice(&o).map_err(|_| Refus {
            raison: illisible(),
            dit: Vec::new(),
        }),
        Lecture::Adopte(o) | Lecture::Falsifie(Some(o)) => Err(Refus {
            raison: falsifiee(),
            dit: dit(&o),
        }),
        Lecture::Falsifie(None) => Err(Refus {
            raison: falsifiee(),
            dit: Vec::new(),
        }),
        Lecture::Illisible(_) => Err(Refus {
            raison: illisible(),
            dit: Vec::new(),
        }),
    }
}

fn falsifiee() -> &'static str {
    tr!(
        "la liste des programmes suspendus a été changée hors de Vanguard",
        "the list of suspended programs was changed outside Vanguard"
    )
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

/// Les comptes de suspension des fils d'un processus (Windows), en fonctions pures : ce que chaque appel de Vanguard
/// y fait. L'essai `compte_des_fils` rejoue avec elles ce qu'un tiers peut faire entre la suspension et la reprise.
#[cfg(any(windows, test))]
pub(crate) mod comptes {
    /// Une passe fil par fil (`suspendre`) : un fil qui tournait (`avant` = 0) reste suspendu ; les autres, comptés
    /// en passant (suspendus puis repris aussitôt), gardent leur compte. Ainsi une resuspension n'ajoute rien à un fil
    /// déjà suspendu, et la reprise de Vanguard (une seule) suffit toujours.
    #[must_use]
    pub(crate) fn reste_suspendu(avant: u32, suspendre: bool) -> bool {
        suspendre && avant == 0
    }

    /// NtSuspendProcess : une suspension de plus à chaque fil.
    #[cfg(test)]
    pub(crate) fn tout_suspendre(fils: &mut [u32]) {
        for f in fils {
            *f = f.saturating_add(1);
        }
    }

    /// NtResumeProcess : une suspension de moins à chaque fil suspendu.
    #[cfg(test)]
    pub(crate) fn tout_reprendre(fils: &mut [u32]) {
        for f in fils {
            *f = f.saturating_sub(1);
        }
    }

    /// Une passe : chaque fil compté, et suspendu s'il tournait (`suspendre`).
    #[cfg(test)]
    pub(crate) fn passe(fils: &mut [u32], suspendre: bool) {
        for f in fils {
            if reste_suspendu(*f, suspendre) {
                *f = f.saturating_add(1);
            }
        }
    }
}

/// Ce qu'on lit d'un processus noté.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lu {
    /// Gelé : aucun de ses fils ne tourne.
    Gele,
    /// Windows : des fils suspendus, d'autres repris par un tiers.
    EnPartie,
    /// Il tourne.
    Tourne,
    /// Plus rien à ce numéro.
    Fini,
    /// Un autre processus sur ce numéro, ou ce processus fait tourner un autre programme.
    Autre,
    /// Là, mais son programme ou son état ne se relit pas d'ici (droits : un processus élevé, d'un autre compte) :
    /// peut-être toujours suspendu.
    Illisible,
}

/// Le processus `pid` fait-il toujours tourner `chemin` (depuis `depart`, s'il est connu), et est-il gelé ?
pub(crate) fn lire(pid: u32, chemin: &str, depart_connu: Option<u64>) -> Lu {
    #[cfg(target_os = "linux")]
    {
        use crate::socle::processus;
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return Lu::Fini;
        };
        if matches!(processus::etat_du_stat(&stat), Some('Z' | 'X')) {
            return Lu::Fini;
        }
        let Some(d) = processus::debut_du_stat(&stat) else {
            return Lu::Illisible;
        };
        if depart_connu.is_some_and(|attendu| attendu != d) {
            return Lu::Autre;
        }
        // /proc/<pid>/exe ne se lit que pour un processus de ce compte (ou en root) : là mais illisible. Avec son
        // départ connu et le même, c'est bien le processus suspendu (un `exec` garde le départ) : stat, lisible de
        // tous, dit s'il tourne ; alors la suspension de Vanguard n'y est plus, rien à reprendre.
        match super::gestes::chemin_du_processus(pid) {
            None if depart_connu.is_some() && processus::est_gele(pid) == Some(false) => return Lu::Tourne,
            None => return Lu::Illisible,
            Some(a) if !super::gestes::meme_chemin(&a, chemin) => return Lu::Autre,
            Some(_) => {}
        }
        match processus::est_gele(pid) {
            Some(true) => Lu::Gele,
            Some(false) => Lu::Tourne,
            None => Lu::Fini,
        }
    }
    #[cfg(windows)]
    {
        crate::machine::windows::processus::etat_si(pid, chemin, depart_connu)
    }
}

/// Windows, sans le droit de suspendre (un processus élevé, d'un autre compte, de SYSTEM) : ce que disent la poignée
/// limitée (son chemin, son heure de création) ou, refusée elle aussi, le nom que donne la liste des processus
/// (lisible sans droits, comme le Gestionnaire des tâches). Un autre programme ou une autre heure de création :
/// `Autre`, le processus suspendu n'est plus là (un numéro repris après un redémarrage) ; le même, ou rien de
/// lisible : `Illisible`. Pur.
#[cfg(any(windows, test))]
pub(crate) fn sans_droit_de_suspendre(
    attendu: &str,
    creation: Option<u64>,
    chemin_lu: Option<&str>,
    creation_lue: Option<u64>,
    nom_liste: Option<&str>,
) -> Lu {
    if chemin_lu.is_some_and(|c| !c.eq_ignore_ascii_case(attendu)) {
        return Lu::Autre;
    }
    if creation.zip(creation_lue).is_some_and(|(a, c)| a != c) {
        return Lu::Autre;
    }
    if chemin_lu.is_none() {
        let fichier = attendu.rsplit(['\\', '/']).next().unwrap_or(attendu);
        let court = fichier
            .len()
            .checked_sub(4)
            .filter(|i| fichier.get(*i..).is_some_and(|e| e.eq_ignore_ascii_case(".exe")))
            .and_then(|i| fichier.get(..i))
            .unwrap_or(fichier);
        if nom_liste.is_some_and(|n| !n.eq_ignore_ascii_case(&crate::ui::affichable(court))) {
            return Lu::Autre;
        }
    }
    Lu::Illisible
}

/// Suspend `pid` s'il fait toujours tourner `chemin` (depuis `depart_attendu`, s'il est donné), avec les droits de ce
/// processus, sans autre garde (celles de `ordres::juger` sont passées avant) : le départ du processus suspendu, ou
/// pourquoi rien ne l'est. `premiere` : la suspension de Vanguard ; sinon une resuspension (Windows : seuls les fils
/// qui tournent sont suspendus, voir `comptes`).
pub(crate) fn suspendre_ici(
    pid: u32,
    chemin: &str,
    depart_attendu: Option<u64>,
    premiere: bool,
) -> Result<Option<u64>, Echec> {
    #[cfg(target_os = "linux")]
    {
        use crate::socle::processus;
        let _ = premiere;
        let d = processus::debut(pid).ok_or_else(|| reaffecte(pid))?;
        if depart_attendu.is_some_and(|attendu| attendu != d) {
            return Err(reaffecte(pid));
        }
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
        let fait = if premiere {
            processus::suspendre_si(pid, chemin, depart_attendu)
        } else {
            processus::resuspendre_si(pid, chemin, depart_attendu)
        };
        fait.map(Some).ok_or_else(|| refuse_par_le_systeme(pid))
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

/// Le rôle d'un programme du système à nommer avant de le suspendre (« montré et confirmé ») ; `None` : un programme
/// du compte. Windows : les programmes du système ne se suspendent pas du tout (gardes de l'arrêt).
pub(crate) fn role(pid: u32, chemin: &str) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata(format!("/proc/{pid}")).ok().map(|m| m.uid());
        let nom = crate::socle::processus::nom_court(pid).unwrap_or_default();
        super::gardes::role_a_confirmer(&nom, chemin, uid)
    }
    #[cfg(windows)]
    {
        let _ = (pid, chemin);
        None
    }
}

/// Ce compte peut-il suspendre ce processus lui-même ? Sinon l'ordre passe par l'assistant élevé (Linux) ou le
/// processus élevé (Windows), qui le rejuge.
pub(super) fn sans_droits_de_plus(pid: u32) -> bool {
    #[cfg(windows)]
    {
        crate::machine::windows::processus::peut_suspendre(pid)
    }
    #[cfg(unix)]
    {
        super::gestes::arret_sans_droits(pid)
    }
}

/// Un ordre confié à l'assistant élevé (Linux) ou au processus élevé (Windows), qui le rejuge lui-même.
fn par_l_assistant(o: &Ordre) -> Result<(), Echec> {
    par_l_assistant_tous(std::slice::from_ref(o))
        .pop()
        .unwrap_or_else(|| Err(refus_de_l_assistant(&[])))
}

/// Des ordres confiés ensemble à l'assistant élevé ou au processus élevé : une seule demande de droits pour tous,
/// l'issue de chacun.
fn par_l_assistant_tous(ordres: &[Ordre]) -> Vec<Result<(), Echec>> {
    let groupes: Vec<Vec<String>> = ordres.iter().map(|o| vec![o.ligne()]).collect();
    let (faits, notes) = crate::machine::appliquer_chacune_sans_noter(&groupes);
    (0..ordres.len())
        .map(|i| {
            if faits.get(i).copied().unwrap_or(false) {
                Ok(())
            } else {
                Err(refus_de_l_assistant(notes.get(i).map_or(&[][..], Vec::as_slice)))
            }
        })
        .collect()
}

fn refus_de_l_assistant(notes: &[String]) -> Echec {
    let raison = notes.join(" ; ");
    Echec::refuse(
        OU,
        if raison.is_empty() {
            tr!("refusé ou droits non accordés", "refused or rights not granted").to_string()
        } else {
            raison
        },
    )
}

/// Suspend le programme d'une menace : garde-fous rejugés (avec les processus que Vanguard protège, `intouchables`,
/// comme au menu), geste sans course, puis noté (liste scellée et journal). `cle` : la clé de la menace, au journal ;
/// `source` : qui l'a voulu (la personne, ou la protection active quand une suite le fait toute seule), au journal
/// aussi : une suspension faite sans personne n'y est jamais dite demandée par la personne.
pub(crate) fn suspendre(
    pid: u32,
    chemin: &str,
    quoi: &str,
    cle: Option<&str>,
    intouchables: &HashSet<u32>,
    source: crate::modele::evenement::Source,
) -> Result<(), Echec> {
    // Lu avant l'ordre, et porté par lui : le processus que l'ordre vise, et pas un autre venu après sur ce numéro
    // (l'assistant élevé n'agit que sur ce départ-là).
    let avant = depart(pid);
    let o = Ordre::SuspendreProcessus {
        pid,
        chemin: chemin.to_string(),
        depart: avant,
    };
    let juge = ordres::Juge::lire(None).avec(intouchables);
    if let Some(raison) = ordres::juger(&o, &juge) {
        return Err(Echec::refuse(OU, raison));
    }
    // La liste pleine : la suspension est refusée plutôt que d'oublier en silence le plus ancien suspendu.
    if charger().is_ok_and(|l| pleine(&l, pid)) {
        return Err(Echec::refuse(
            OU,
            trf!(
                "déjà {SUSPENDUS_MAX} programmes suspendus par Vanguard : reprenez-en un d'abord (vanguard blocage reprendre <PID>)",
                "already {SUSPENDUS_MAX} programs suspended by Vanguard: resume one first (vanguard blocking resume <PID>)"
            ),
        ));
    }
    let lu = lire(pid, chemin, avant);
    if lu == Lu::Gele {
        return Err(deja_gele(pid));
    }
    // Repris en partie par un tiers (Windows) : seulement ses fils qui tournent, jamais un NtSuspendProcess empilé sur
    // les fils qui portent déjà une suspension (`comptes`). L'assistant élevé en décide de même de son côté.
    let premiere = lu != Lu::EnPartie;
    let resultat = if lu != Lu::Illisible && sans_droits_de_plus(pid) {
        suspendre_ici(pid, chemin, avant, premiere)
    } else {
        par_l_assistant(&o).and_then(|()| depart_apres_l_assistant(pid, chemin, avant))
    };
    crate::modele::journal::noter(evenement(source, &o, resultat.is_ok(), cle));
    let d = resultat?;
    retenir(Suspendu {
        pid,
        depart: d,
        chemin: chemin.to_string(),
        quoi: quoi.to_string(),
        le: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
    })
}

/// La liste n'a plus de place pour `pid` : `SUSPENDUS_MAX` programmes, et pas lui (un même numéro remplace l'ancien).
fn pleine(l: &Liste, pid: u32) -> bool {
    l.suspendus.len() >= SUSPENDUS_MAX && l.suspendus.iter().all(|s| s.pid != pid)
}

/// Le refus d'un programme déjà gelé (par Vanguard ou un autre) : une seconde suspension Windows ajouterait une
/// suspension à chaque fil, que la reprise de Vanguard ne retirerait pas.
pub(crate) fn deja_gele(pid: u32) -> Echec {
    Echec::refuse(
        OU,
        trf!(
            "le processus {pid} est déjà suspendu (par Vanguard ou un autre programme) : rien n'est ajouté",
            "process {pid} is already suspended (by Vanguard or another program): nothing is added"
        ),
    )
}

/// Le départ à retenir d'un processus suspendu par l'assistant, qui ne le rend pas : celui lu avant l'ordre, s'il n'a
/// pas changé ; changé, celui d'après seulement s'il est bien gelé (sinon rien n'est retenu, et c'est dit).
fn depart_apres_l_assistant(pid: u32, chemin: &str, avant: Option<u64>) -> Result<Option<u64>, Echec> {
    let apres = depart(pid);
    if apres == avant {
        return Ok(avant);
    }
    match apres {
        Some(d) if lire(pid, chemin, Some(d)) == Lu::Gele => Ok(Some(d)),
        _ => Err(Echec::refuse(
            OU,
            trf!(
                "le processus {pid} a changé pendant la suspension (fini, ou un autre sur ce numéro) : rien n'est retenu",
                "process {pid} changed during the suspension (ended, or another one on this number): nothing is saved"
            ),
        )),
    }
}

/// Le geste au journal des événements, avec sa ligne d'ordre : ce qui a été suspendu ou repris, et quand.
fn noter_au_journal(o: &Ordre, reussi: bool, cle: Option<&str>) {
    crate::modele::journal::noter(evenement(crate::modele::evenement::Source::Utilisateur, o, reussi, cle));
}

/// L'action au journal d'un ordre de suspension ou de reprise, sous la source de qui l'a voulu.
fn evenement(
    source: crate::modele::evenement::Source,
    o: &Ordre,
    reussi: bool,
    cle: Option<&str>,
) -> crate::modele::evenement::Evenement {
    crate::modele::evenement::Evenement::action(source, &o.texte(), reussi, &[o.ligne()]).cle(cle)
}

/// Après une suite : le processus qu'elle a suspendu, puis que Bloquer a arrêté, n'est plus là ; son entrée est
/// oubliée tout de suite (le bilan le ferait en silence) pour que « reprendre » ne soit plus conseillé d'un processus
/// mort. Une liste qui ne compte pas n'est pas touchée. Vrai si l'entrée est oubliée.
pub(crate) fn oublier_s_il_est_fini(pid: u32) -> bool {
    let Ok(mut l) = charger() else {
        return false;
    };
    retirer_fini(&mut l, pid, |s| lire(s.pid, &s.chemin, s.depart)) && enregistrer(&l).is_ok()
}

/// Retire l'entrée de `pid` si elle se relit finie (`lu`) ; jamais une autre, ni un processus encore là (même un
/// autre sur ce numéro, `Lu::Autre` : le bilan le dira). Vrai si retirée.
fn retirer_fini(l: &mut Liste, pid: u32, lu: impl Fn(&Suspendu) -> Lu) -> bool {
    let avant = l.suspendus.len();
    l.suspendus.retain(|s| s.pid != pid || lu(s) != Lu::Fini);
    l.suspendus.len() != avant
}

/// Ajoute un suspendu à la liste (le même numéro remplacé). Une liste changée hors de Vanguard ne compte pas : elle
/// est remplacée par une liste neuve, et c'est dit, avec les numéros qu'elle nommait.
fn retenir(s: Suspendu) -> Result<(), Echec> {
    let mut l = match charger() {
        Ok(l) => l,
        Err(r) => {
            dire_liste_remplacee(&r);
            Liste::default()
        }
    };
    // Jamais tronquée : `suspendre` refuse avant d'agir quand elle est pleine (`SUSPENDUS_MAX`).
    l.suspendus.retain(|x| x.pid != s.pid);
    l.suspendus.push(s);
    enregistrer(&l).map_err(|e| Echec::ecriture(OU, &e))
}

/// Les numéros qu'une liste nomme, pour les dire (« 4242, 4243 »), au plus dix.
fn numeros(l: &[Suspendu]) -> String {
    let mut n: Vec<String> = l.iter().take(10).map(|s| s.pid.to_string()).collect();
    if l.len() > 10 {
        n.push("…".into());
    }
    n.join(", ")
}

fn dire_liste_remplacee(r: &Refus) {
    let nommes = if r.dit.is_empty() {
        String::new()
    } else {
        trf!(
            " Elle nommait les PID {} : des numéros écrits hors de Vanguard, à ne pas croire.",
            " It named PIDs {}: numbers written outside Vanguard, not to be trusted.",
            numeros(&r.dit)
        )
    };
    afficher_aligne(
        &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
        &trf!(
            "{} : elle ne compte plus, une liste neuve la remplace.{nommes}",
            "{}: it no longer counts, a new list replaces it.{nommes}",
            capitale(r.raison)
        ),
        4,
        "",
    );
}

/// La première lettre en capitale (« la liste… » → « La liste… »).
fn capitale(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|p| p.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// La liste se lit-elle (pas changée hors de Vanguard) ? Sinon, pourquoi.
#[cfg(test)]
fn lisible() -> Result<(), &'static str> {
    charger().map(|_| ()).map_err(|r| r.raison)
}

#[cfg(test)]
fn suspendus() -> Vec<Suspendu> {
    charger().map(|l| l.suspendus).unwrap_or_default()
}

/// Ce qu'une reprise a fait.
#[derive(Debug, PartialEq)]
pub(crate) enum Reprise {
    /// Repris, et relu : il tourne.
    Faite,
    /// Repris par l'assistant élevé ; son état ne se relit pas d'ici.
    NonRelu,
    /// La suspension de Vanguard est levée, mais un autre programme le tient encore suspendu (Windows : une
    /// suspension à lui ; Linux : un traceur).
    TenuAilleurs,
    /// Plus rien à ce numéro : rien à reprendre.
    DejaFini,
    /// Il tournait déjà (un autre programme l'avait repris).
    DejaRepris,
    /// Ce numéro est maintenant un autre processus, ou un autre programme : rien n'est touché.
    Autre,
}

/// L'ordre de reprise d'un suspendu : son numéro, son programme et son départ (l'assistant élevé n'agit que sur ce
/// processus-là).
fn ordre_de_reprise(s: &Suspendu) -> Ordre {
    Ordre::ReprendreProcessus {
        pid: s.pid,
        chemin: s.chemin.clone(),
        depart: s.depart,
    }
}

/// Reprend des programmes suspendus : chacun relu, puis repris par ses droits, ou par l'assistant élevé s'il ne se
/// relit pas d'ici ou que ce compte n'a pas les droits (l'assistant le rejuge : le même processus, le même programme,
/// et suspendu). Ceux qui passent par l'assistant y vont tous ensemble : une seule demande de droits. Rien n'est dit
/// repris qui ne l'ait été ; l'issue de chacun, dans l'ordre reçu.
fn reprendre_ceux(liste: &[Suspendu]) -> Vec<Result<Reprise, Echec>> {
    let mut issues: Vec<Option<Result<Reprise, Echec>>> = Vec::with_capacity(liste.len());
    let mut par_l_assistant = Vec::new();
    for (i, s) in liste.iter().enumerate() {
        let lu = lire(s.pid, &s.chemin, s.depart);
        issues.push(match lu {
            Lu::Fini => Some(Ok(Reprise::DejaFini)),
            Lu::Autre => Some(Ok(Reprise::Autre)),
            Lu::Tourne => Some(Ok(Reprise::DejaRepris)),
            Lu::Gele | Lu::EnPartie if sans_droits_de_plus(s.pid) => {
                let r = reprendre_ici(s.pid, &s.chemin, s.depart);
                noter_au_journal(&ordre_de_reprise(s), r.is_ok(), None);
                Some(r.map(|()| relire_apres_reprise(s)))
            }
            Lu::Gele | Lu::EnPartie | Lu::Illisible => {
                par_l_assistant.push(i);
                None
            }
        });
    }
    if !par_l_assistant.is_empty() {
        let ordres: Vec<Ordre> = par_l_assistant
            .iter()
            .filter_map(|i| liste.get(*i).map(ordre_de_reprise))
            .collect();
        for ((i, o), r) in par_l_assistant.iter().zip(&ordres).zip(par_l_assistant_tous(&ordres)) {
            noter_au_journal(o, r.is_ok(), None);
            if let (Some(case), Some(s)) = (issues.get_mut(*i), liste.get(*i)) {
                *case = Some(r.map(|()| relire_apres_reprise(s)));
            }
        }
    }
    issues
        .into_iter()
        .map(|r| r.unwrap_or_else(|| Err(refus_de_l_assistant(&[]))))
        .collect()
}

/// Relu après la reprise : un SIGCONT se sert quand le noyau sert le processus, un instant après (2 s au plus).
fn relire_apres_reprise(s: &Suspendu) -> Reprise {
    let mut apres = lire(s.pid, &s.chemin, s.depart);
    for _ in 0..200u8 {
        if apres != Lu::Gele {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        apres = lire(s.pid, &s.chemin, s.depart);
    }
    match apres {
        Lu::Tourne | Lu::EnPartie => Reprise::Faite,
        Lu::Gele => Reprise::TenuAilleurs,
        Lu::Illisible => Reprise::NonRelu,
        Lu::Fini => Reprise::DejaFini,
        Lu::Autre => Reprise::Autre,
    }
}

/// Ce que `reprendre` a fait : la liste ne comptait pas (pourquoi, et les numéros qu'elle nommait), puis chaque
/// programme visé et son issue.
pub(crate) struct Reprises {
    pub(crate) liste_refusee: Option<(&'static str, String)>,
    pub(crate) faits: Vec<(Suspendu, Result<Reprise, Echec>)>,
}

/// Reprend un programme suspendu par Vanguard (`pid`), ou tous (`None`) : chacun relu et repris (`reprendre_ceux`),
/// puis oublié, sauf s'il n'a pas pu l'être.
///
/// Liste changée hors de Vanguard : elle ne vaut rien, mais reprendre ne relâche aucune défense. Un `pid` donné à la
/// main est relu ici, et repris seulement s'il se relit d'ici et qu'il est gelé (`reprendre_hors_liste`) ; sans
/// `pid`, rien n'est repris sur la foi de la liste, ses numéros sont dits, et une liste neuve la remplace.
pub(crate) fn reprendre(pid: Option<u32>) -> Reprises {
    let mut l = match charger() {
        Ok(l) => l,
        Err(r) => {
            let nommes = numeros(&r.dit);
            let faits = if let Some(p) = pid {
                reprendre_hors_liste(p).into_iter().collect()
            } else {
                let _ = enregistrer(&Liste::default());
                Vec::new()
            };
            return Reprises {
                liste_refusee: Some((r.raison, nommes)),
                faits,
            };
        }
    };
    let (vises, gardes): (Vec<Suspendu>, Vec<Suspendu>) =
        l.suspendus.drain(..).partition(|s| pid.is_none_or(|p| p == s.pid));
    l.suspendus = gardes;
    let issues = reprendre_ceux(&vises);
    let mut faits = Vec::new();
    for (s, r) in vises.into_iter().zip(issues) {
        if r.is_err() {
            l.suspendus.push(s.clone());
        }
        faits.push((s, r));
    }
    let _ = enregistrer(&l);
    Reprises {
        liste_refusee: None,
        faits,
    }
}

/// La reprise d'un `pid` donné à la main quand la liste ne compte pas : rien de la liste n'est cru. Son programme et
/// son départ sont lus maintenant, sur le processus vivant ; il n'est repris (ici ou par l'assistant élevé) que s'il
/// se relit d'ici et qu'il est gelé. Illisible d'ici, rien n'est repris, et c'est dit. `None` : rien à ce numéro.
fn reprendre_hors_liste(pid: u32) -> Option<(Suspendu, Result<Reprise, Echec>)> {
    let d = depart(pid);
    let chemin = super::gestes::chemin_du_processus(pid);
    let s = Suspendu {
        pid,
        depart: d,
        chemin: chemin.clone().unwrap_or_default(),
        quoi: tr!("Processus nommé à la main", "Process named by hand").to_string(),
        le: String::new(),
    };
    let illisible = || {
        Err(Echec::refuse(
            OU,
            trf!(
                "le processus {pid} ne se relit pas d'ici : rien n'est repris sans la liste de Vanguard",
                "process {pid} cannot be read from here: nothing is resumed without Vanguard's list"
            ),
        ))
    };
    if chemin.is_none() {
        // Son programme ne se lit pas d'ici : rien ne part vers l'assistant élevé, aucun chemin n'est pris à la liste.
        return match lire(pid, "", d) {
            Lu::Fini => None,
            Lu::Tourne => Some((s, Ok(Reprise::DejaRepris))),
            _ => Some((s, illisible())),
        };
    }
    let r = match lire(pid, &s.chemin, d) {
        Lu::Fini => return None,
        Lu::Gele | Lu::EnPartie => reprendre_ceux(std::slice::from_ref(&s))
            .pop()
            .unwrap_or_else(|| Err(refus_de_l_assistant(&[]))),
        Lu::Tourne => Ok(Reprise::DejaRepris),
        Lu::Autre => Ok(Reprise::Autre),
        Lu::Illisible => illisible(),
    };
    Some((s, r))
}

/// Ce que le bilan constate d'un programme suspendu.
#[derive(Debug, PartialEq)]
pub(crate) enum Constat {
    /// Toujours suspendu.
    Suspendu,
    /// Un tiers l'avait repris : resuspendu.
    Resuspendu,
    /// Un tiers l'a repris, et il ne se resuspend pas d'ici (droits, ou départ inconnu) : il tourne.
    Repris,
    /// Il ne se relit pas d'ici (droits) : peut-être toujours suspendu ; gardé.
    Illisible,
    /// Ce numéro est un autre processus, ou un autre programme : dit une fois, puis oublié.
    Autre,
}

impl Constat {
    /// Reste-t-il dans la liste ?
    pub(crate) fn garde(&self) -> bool {
        *self != Constat::Autre
    }
}

/// Que faire d'un suspendu, d'après ce qu'on lit : fini, il est oublié (`None`) ; repris par un tiers, il se
/// resuspend si possible ; illisible, il est gardé et dit. Pur.
pub(crate) fn constat(lu: Lu, resuspendu: impl FnOnce() -> bool) -> Option<Constat> {
    match lu {
        Lu::Fini => None,
        Lu::Autre => Some(Constat::Autre),
        Lu::Illisible => Some(Constat::Illisible),
        Lu::Gele => Some(Constat::Suspendu),
        Lu::Tourne | Lu::EnPartie => Some(if resuspendu() {
            Constat::Resuspendu
        } else {
            Constat::Repris
        }),
    }
}

/// Au bilan : chaque suspendu relu, resuspendu s'il a été repris (par ce compte, et seulement le même processus :
/// son départ connu), oublié s'il est fini ; ce qui est constaté. `Err` : la liste ne compte pas (pourquoi, et les
/// numéros qu'elle nommait).
fn verifier() -> Result<Vec<(Suspendu, Constat)>, (&'static str, String)> {
    let mut l = charger().map_err(|r| (r.raison, numeros(&r.dit)))?;
    let mut restent = Vec::new();
    let mut constats = Vec::new();
    for s in l.suspendus.drain(..) {
        let c = constat(lire(s.pid, &s.chemin, s.depart), || {
            s.depart.is_some() && sans_droits_de_plus(s.pid) && suspendre_ici(s.pid, &s.chemin, s.depart, false).is_ok()
        });
        if let Some(c) = c {
            if c.garde() {
                restent.push(s.clone());
            }
            constats.push((s, c));
        }
    }
    l.suspendus = restent;
    let _ = enregistrer(&l);
    Ok(constats)
}

/// Au bilan : rappelle ce qui reste suspendu, ce qu'un tiers a repris, ce qui ne se relit pas ; et une liste changée
/// hors de Vanguard.
pub(crate) fn rappeler() {
    let constats = match verifier() {
        Ok(c) => c,
        Err((raison, nommes)) => {
            crate::ui::section(tr!("PROGRAMMES SUSPENDUS", "SUSPENDED PROGRAMS"));
            let nommes = if nommes.is_empty() {
                String::new()
            } else {
                trf!(
                    " Elle nomme les PID {nommes} : des numéros écrits hors de Vanguard, à ne pas croire.",
                    " It names PIDs {nommes}: numbers written outside Vanguard, not to be trusted."
                )
            };
            afficher_aligne(
                &format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)),
                &trf!(
                    "{} : ce qu'elle dit ne compte plus, et rien n'est resuspendu.{nommes} « vanguard blocage reprendre » la remet à neuf ; « vanguard blocage reprendre <PID> » ne reprend qu'un processus relu ici et gelé, jamais sur la foi de cette liste.",
                    "{}: what it says no longer counts, and nothing is suspended again.{nommes} “vanguard blocking resume” resets it; “vanguard blocking resume <PID>” only resumes a process read again here and frozen, never on this list's word.",
                    capitale(raison)
                ),
                4,
                "",
            );
            return;
        }
    };
    if constats.is_empty() {
        return;
    }
    crate::ui::section(tr!("PROGRAMMES SUSPENDUS", "SUSPENDED PROGRAMS"));
    for (s, c) in &constats {
        let eleve = couleur(crate::risk::Niveau::Eleve);
        let (signe, etat) = match c {
            Constat::Suspendu => (format!("{GRIS}‖{RESET}"), tr!("toujours suspendu", "still suspended")),
            Constat::Resuspendu => (
                format!("{eleve}‖{RESET}"),
                tr!(
                    "un autre programme l'avait repris : suspendu de nouveau",
                    "another program had resumed it: suspended again"
                ),
            ),
            Constat::Repris => (
                format!("{eleve}⚠{RESET}"),
                tr!(
                    "un autre programme l'a repris, et il ne se resuspend pas d'ici (droits, ou départ inconnu) : il tourne ; « vanguard blocage suspendre <PID> » le suspend de nouveau",
                    "another program resumed it, and it cannot be suspended again from here (rights, or unknown start): it is running; “vanguard blocking suspend <PID>” suspends it again"
                ),
            ),
            Constat::Illisible => (
                format!("{eleve}?{RESET}"),
                tr!(
                    "ne se relit pas d'ici (droits) : peut-être toujours suspendu ; « vanguard blocage reprendre <PID> » le reprend par l'assistant élevé",
                    "cannot be read from here (rights): perhaps still suspended; “vanguard blocking resume <PID>” resumes it through the elevated helper"
                ),
            ),
            Constat::Autre => (
                format!("{GRIS}·{RESET}"),
                tr!(
                    "fini, son numéro pris par un autre processus, ou devenu un autre programme : oublié",
                    "ended, its number taken by another process, or turned into another program: forgotten"
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
    if let Some((s, _)) = constats.iter().find(|(_, c)| c.garde()) {
        afficher_aligne(
            "    ",
            &trf!(
                "Pour le reprendre : vanguard blocage reprendre {} ; pour l'arrêter, choisissez « Bloquer » à sa menace.",
                "To resume it: vanguard blocking resume {}; to stop it, choose “Block” on its threat.",
                s.pid
            ),
            4,
            GRIS,
        );
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// Fini : oublié ; autre programme : dit, puis oublié ; suspendu : rappelé ; illisible d'ici : gardé et dit, jamais
    /// oublié en silence ; repris par un tiers : resuspendu si possible, sinon dit.
    #[test]
    fn constats_du_bilan() {
        assert_eq!(constat(Lu::Fini, || panic!("rien à resuspendre")), None);
        let autre = constat(Lu::Autre, || panic!("pas le même"));
        assert_eq!(autre, Some(Constat::Autre));
        assert!(!autre.unwrap().garde());
        let illisible = constat(Lu::Illisible, || panic!("illisible : rien à resuspendre d'ici"));
        assert_eq!(illisible, Some(Constat::Illisible));
        assert!(illisible.unwrap().garde());
        assert_eq!(constat(Lu::Gele, || panic!("déjà suspendu")), Some(Constat::Suspendu));
        assert_eq!(constat(Lu::Tourne, || true), Some(Constat::Resuspendu));
        assert_eq!(constat(Lu::EnPartie, || true), Some(Constat::Resuspendu));
        assert_eq!(constat(Lu::Tourne, || false), Some(Constat::Repris));
        assert!(Constat::Repris.garde() && Constat::Suspendu.garde());
    }

    /// Les comptes de suspension des fils (Windows) : la suspension de Vanguard, un tiers qui reprend un fil, un fil né
    /// pendant, la resuspension du bilan, puis la reprise de Vanguard ; chaque fil revient à son compte d'avant (le
    /// fil 2, suspendu par son propre programme, le reste).
    #[test]
    fn compte_des_fils() {
        let avant = [0u32, 0, 1];
        let mut fils = avant.to_vec();
        comptes::tout_suspendre(&mut fils);
        comptes::passe(&mut fils, true);
        assert_eq!(fils, [1, 1, 2]);
        // Un tiers reprend le fil 0 ; un fil naît, qui tourne.
        fils[0] -= 1;
        fils.push(0);
        // Le bilan : des passes seulement, jamais NtSuspendProcess.
        comptes::passe(&mut fils, true);
        comptes::passe(&mut fils, true);
        assert_eq!(fils, [1, 1, 2, 1]);
        comptes::tout_reprendre(&mut fils);
        assert_eq!(fils, [0, 0, 1, 0]);
        // Une seconde suspension refusée (`deja_gele`) : sinon il en resterait une après la reprise.
        let mut deux = avant.to_vec();
        comptes::tout_suspendre(&mut deux);
        comptes::tout_suspendre(&mut deux);
        comptes::tout_reprendre(&mut deux);
        assert_ne!(deux, avant);
        assert!(comptes::reste_suspendu(0, true));
        assert!(!comptes::reste_suspendu(1, true) && !comptes::reste_suspendu(0, false));
    }

    /// La liste se relit telle qu'écrite (dossier jetable des essais) ; un même numéro remplace l'ancien. Changée hors
    /// de Vanguard : elle ne compte plus, c'est dit (avec ses numéros), reprendre tout ne reprend rien sur sa foi et la
    /// remet à neuf, et retenir repart d'une liste neuve. Un seul essai : la liste est un fichier partagé.
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
        assert!(lisible().is_ok());

        let fichier = crate::socle::dossier_local().join(crate::sceau::SUSPENDUS);
        let changee = Liste {
            suspendus: vec![s(4244, "d")],
        };
        std::fs::write(&fichier, serde_json::to_string(&changee).unwrap()).unwrap();
        assert!(lisible().is_err());
        let r = reprendre(None);
        let (raison, nommes) = r.liste_refusee.expect("la liste changée est dite");
        assert_eq!(raison, falsifiee());
        assert_eq!(nommes, "4244");
        assert!(r.faits.is_empty(), "rien n'est repris sur la foi d'une liste changée");
        assert!(lisible().is_ok() && suspendus().is_empty(), "remise à neuf");

        // Un PID donné à la main, la liste changée : relu en direct, jamais le chemin de la liste ; ce processus-ci
        // tourne, rien n'est repris ni confié à l'assistant élevé.
        let moi = std::process::id();
        let forgee = Liste {
            suspendus: vec![s(moi, "f")],
        };
        std::fs::write(&fichier, serde_json::to_string(&forgee).unwrap()).unwrap();
        let r = reprendre(Some(moi));
        assert!(r.liste_refusee.is_some());
        assert_eq!(r.faits.len(), 1);
        let (lu, fait) = r.faits.first().unwrap();
        assert_ne!(lu.chemin, "/tmp/x", "le chemin de la liste changée n'est pas cru");
        assert!(matches!(fait, Ok(Reprise::DejaRepris)), "{:?}", fait.as_ref().err());

        std::fs::write(&fichier, serde_json::to_string(&changee).unwrap()).unwrap();
        assert!(verifier().is_err(), "le bilan dit la liste changée");
        retenir(s(4245, "e")).unwrap();
        assert_eq!(suspendus(), vec![s(4245, "e")]);
        retenir(s(4245, "e")).unwrap();
        let _ = enregistrer(&Liste::default());
    }

    /// Pleine : 64 programmes, et une suspension de plus refusée (jamais le plus ancien oublié en silence) ; un même
    /// numéro, lui, remplace l'ancien.
    #[test]
    fn liste_pleine() {
        let s = |pid| Suspendu {
            pid,
            depart: None,
            chemin: "/tmp/x".into(),
            quoi: String::new(),
            le: String::new(),
        };
        let mut l = Liste::default();
        for pid in 1..=63u32 {
            l.suspendus.push(s(pid));
        }
        assert!(!pleine(&l, 1000));
        l.suspendus.push(s(64));
        assert!(pleine(&l, 1000));
        assert!(!pleine(&l, 64));
    }

    /// Après Suspendre puis Bloquer : seule l'entrée du processus arrêté (relu fini) est oubliée ; un processus
    /// encore là, ou un autre sur ce numéro, reste, comme les autres entrées.
    #[test]
    fn oubli_du_processus_arrete() {
        let s = |pid| Suspendu {
            pid,
            depart: Some(7),
            chemin: "/home/alice/.local/bin/x".into(),
            quoi: String::new(),
            le: String::new(),
        };
        let mut l = Liste {
            suspendus: vec![s(10), s(11)],
        };
        assert!(!retirer_fini(&mut l, 10, |_| Lu::Gele));
        assert!(!retirer_fini(&mut l, 10, |_| Lu::Autre));
        assert_eq!(l.suspendus.len(), 2);
        assert!(retirer_fini(&mut l, 10, |_| Lu::Fini));
        assert_eq!(l.suspendus, vec![s(11)]);
        assert!(!retirer_fini(&mut l, 99, |_| Lu::Fini));
        assert_eq!(l.suspendus, vec![s(11)]);
    }

    /// Une suspension faite par une suite toute seule est notée sous la protection active, jamais « demandée par la
    /// personne » ; celle d'un menu, sous la personne.
    #[test]
    fn suspension_notee_avec_sa_source() {
        use crate::modele::evenement::Source;
        let o = Ordre::SuspendreProcessus {
            pid: 4242,
            chemin: "/home/alice/.local/bin/x".into(),
            depart: None,
        };
        let e = evenement(Source::Blocage, &o, true, Some("fichier:/home/alice/.local/bin/x"));
        assert!(matches!(e.source, Source::Blocage));
        let e = evenement(Source::Utilisateur, &o, true, None);
        assert!(matches!(e.source, Source::Utilisateur));
    }

    /// Windows, sans le droit de suspendre : un autre programme, une autre heure de création ou un autre nom dans la
    /// liste des processus disent que le processus suspendu n'est plus là ; le même, ou rien de lisible : illisible.
    #[test]
    fn sans_droit_relu_au_mieux() {
        let a = r"C:\Program Files\Outil\outil.EXE";
        assert_eq!(
            sans_droit_de_suspendre(a, Some(5), Some(r"c:\program files\outil\outil.exe"), Some(5), None),
            Lu::Illisible
        );
        assert_eq!(
            sans_droit_de_suspendre(a, Some(5), Some(r"C:\Windows\System32\svchost.exe"), Some(5), None),
            Lu::Autre
        );
        assert_eq!(sans_droit_de_suspendre(a, Some(5), Some(a), Some(6), None), Lu::Autre);
        assert_eq!(sans_droit_de_suspendre(a, None, Some(a), Some(6), None), Lu::Illisible);
        assert_eq!(
            sans_droit_de_suspendre(a, Some(5), None, None, Some("svchost")),
            Lu::Autre
        );
        assert_eq!(
            sans_droit_de_suspendre(a, Some(5), None, None, Some("OUTIL")),
            Lu::Illisible
        );
        assert_eq!(
            sans_droit_de_suspendre(a, Some(5), None, Some(6), Some("outil")),
            Lu::Autre
        );
        assert_eq!(sans_droit_de_suspendre(a, Some(5), None, None, None), Lu::Illisible);
        assert_eq!(
            sans_droit_de_suspendre("/usr/bin/sleep", None, None, None, Some("sleep")),
            Lu::Illisible
        );
        assert_eq!(sans_droit_de_suspendre("", None, None, None, Some("outil")), Lu::Autre);
    }

    /// Un enfant jetable (`sleep`) suspendu sans course : un autre programme attendu ne le touche pas ; le bon le
    /// gèle ; la reprise par un programme faux ne fait rien, la bonne le reprend. `lire` suit chaque état.
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
        let autre = suspendre_ici(pid, "/autre/programme", None, true);
        let libre = est_gele(pid);
        let lu_libre = lire(pid, &programme, None);
        let mauvais_depart = suspendre_ici(pid, &programme, Some(1), true);
        let bon = suspendre_ici(pid, &programme, None, true);
        let d = bon.as_ref().ok().copied().flatten();
        let gele = est_gele(pid);
        let lu_gele = lire(pid, &programme, d);
        let lu_autre = lire(pid, "/autre/programme", d);
        let lu_autre_depart = lire(pid, &programme, d.map(|d| d.wrapping_add(1)));
        let reprise_fausse = reprendre_ici(pid, "/autre/programme", None);
        let toujours = est_gele(pid);
        let reprise = reprendre_ici(pid, &programme, d);
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
        assert_eq!(lu_libre, Lu::Tourne);
        assert!(mauvais_depart.is_err());
        assert!(bon.as_ref().is_ok_and(Option::is_some), "{bon:?}");
        assert_eq!(gele, Some(true));
        assert_eq!(lu_gele, Lu::Gele);
        assert_eq!(lu_autre, Lu::Autre);
        assert_eq!(lu_autre_depart, Lu::Autre);
        assert!(reprise_fausse.is_err());
        assert_eq!(toujours, Some(true));
        assert!(reprise.is_ok(), "{reprise:?}");
        assert_eq!(repris, Some(false));
        assert!(
            suspendre_ici(pid, &programme, None, true).is_err(),
            "fini : rien à suspendre"
        );
        assert_eq!(lire(pid, &programme, d), Lu::Fini);
    }
}
