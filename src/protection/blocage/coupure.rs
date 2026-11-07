//! Couper le réseau d'un programme sans l'arrêter (Défense R3) : il tourne toujours, mais ne parle plus à personne,
//! le temps de regarder ; `vanguard blocage rendre-reseau` le lui rend. Toujours demandé (la personne, ou une suite
//! de gestes), jamais deviné, et derrière ses gardes (`gardes::reseau_intouchable`), rejugées par l'élevé.
//!
//! - Linux : l'assistant élevé met le processus dans un scope transitoire à lui (`vanguard.slice/coupe-<pid>-<départ>
//!   .scope`), demandé à systemd par D-Bus (StartTransientUnit), jamais déplacé à la main dans /sys/fs/cgroup ; puis
//!   nf_tables jette tout paquet d'une prise de ce cgroup (`socket cgroupv2 level 2`, table `inet vanguard`). Le cgroup
//!   d'une prise est figé à sa création : les prises déjà ouvertes sont donc coupées dans le même geste (sock_diag,
//!   SOCK_DESTROY). nf_tables ne survit pas au redémarrage : la coupure dure « jusqu'au redémarrage ». Le processus
//!   seul est coupé : les programmes qu'il a déjà lancés gardent leur réseau. Rendre retire l'élément de nf_tables et
//!   remet le processus dans l'unité d'où il venait (lue par l'assistant, notée dans /run, jamais crue de la ligne).
//!   Le processus fini, son scope disparaît avec lui (systemd le ramasse) ; l'élément d'un cgroup mort, qui ne vise
//!   plus rien, est retiré à la coupure ou au retour suivants.
//! - Windows : deux règles du Pare-feu Windows (sortante et entrante) sur le FICHIER du programme : TOUS ses processus
//!   sont coupés, pas seulement ce PID, et les règles restent après un redémarrage, jusqu'au retour. Les connexions
//!   déjà ouvertes ne sont pas coupées par une règle : c'est dit.
//!
//! Ce qui est coupé est noté dans une liste scellée (`sceau::COUPURES`) et rappelé au bilan ; une liste changée hors
//! de Vanguard ne compte pas, et c'est dit.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::ordres::{self, Ordre, Resultat};
use crate::modele::Echec;
use crate::ui::*;

const OU: &str = "blocage/coupure";
/// Au plus tant de programmes coupés à la fois : au-delà, une nouvelle coupure est refusée (et c'est dit).
const COUPES_MAX: usize = 64;

/// Un programme dont Vanguard a coupé le réseau.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Coupe {
    pub(crate) pid: u32,
    /// Son départ (Linux : 22e champ de stat ; Windows : heure de création).
    pub(crate) depart: u64,
    pub(crate) chemin: String,
    /// Ce que la menace disait, pour le rappel.
    pub(crate) quoi: String,
    /// AAAA-MM-JJ HH:MM, heure locale.
    pub(crate) le: String,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
struct Liste {
    #[serde(default)]
    coupes: Vec<Coupe>,
}

/// La liste ; changée hors de Vanguard ou illisible : pourquoi elle ne compte pas.
fn charger() -> Result<Liste, &'static str> {
    use crate::sceau::Lecture;
    match crate::sceau::lire(crate::sceau::COUPURES) {
        Lecture::Absent | Lecture::Inconnu => Ok(Liste::default()),
        Lecture::Intact(o) => serde_json::from_slice(&o).map_err(|_| illisible()),
        Lecture::Adopte(_) | Lecture::Falsifie(_) => Err(tr!(
            "la liste des programmes coupés du réseau a été changée hors de Vanguard",
            "the list of programs cut from the network was changed outside Vanguard"
        )),
        Lecture::Illisible(_) => Err(illisible()),
    }
}

fn illisible() -> &'static str {
    tr!(
        "la liste des programmes coupés du réseau ne se lit plus",
        "the list of programs cut from the network can no longer be read"
    )
}

fn enregistrer(l: &Liste) -> std::io::Result<()> {
    crate::sceau::ecrire(
        crate::sceau::COUPURES,
        serde_json::to_string_pretty(l).map_err(std::io::Error::other)?,
    )
}

/// Le nom d'une règle de coupure du Pare-feu Windows : « Vanguard : couper <chemin> (sortie|entrée) ». Un chemin de
/// Windows ne contient jamais « | », que INetFwRule refuse dans un nom.
#[cfg(any(windows, test))]
pub(crate) fn nom_de_regle(chemin: &str, sortie: bool) -> String {
    let sens = if sortie { "sortie" } else { "entrée" };
    format!("Vanguard : couper {chemin} ({sens})")
}

// ------------------------------------------------------------- du côté de celui qui agit (root, administrateur)

/// Coupe le réseau de `pid` s'il fait toujours tourner `chemin` depuis `depart`, avec les droits de ce processus
/// (l'assistant élevé, le processus élevé), sans autre garde (celles de `ordres::juger` sont passées avant).
#[cfg(target_os = "linux")]
pub(crate) fn couper_ici(pid: u32, chemin: &str, depart: u64) -> Resultat {
    linux::couper(pid, chemin, depart).unwrap_or_else(|e| Resultat::echec(e.to_string()))
}

/// Rend le réseau à `pid` : seulement ce que l'assistant a noté lui-même en le coupant.
#[cfg(target_os = "linux")]
pub(crate) fn rendre_ici(pid: u32, chemin: &str, depart: u64) -> Resultat {
    let _ = chemin;
    linux::rendre(pid, depart).unwrap_or_else(|e| Resultat::echec(e.to_string()))
}

#[cfg(windows)]
pub(crate) fn couper_ici(pid: u32, chemin: &str, depart: u64) -> Resultat {
    use crate::machine::windows::processus;
    // Relu ici, par l'élevé : le même processus (heure de création), le même programme.
    let meme = processus::creation(pid) == Some(depart)
        && processus::chemin(pid).is_some_and(|a| super::gestes::meme_chemin(&a, chemin));
    if !meme {
        return Resultat::echec(trf!(
            "le PID {pid} désigne maintenant un autre programme (ou plus aucun) : rien n'est coupé",
            "PID {pid} now points to another program (or none): nothing is cut"
        ));
    }
    let r = crate::machine::windows::pare_feu::couper_programme(chemin);
    if r.reussi { Resultat::ok_note(note_windows()) } else { r }
}

#[cfg(windows)]
pub(crate) fn rendre_ici(pid: u32, chemin: &str, depart: u64) -> Resultat {
    // Les règles visent le fichier, pas le processus : elles se retirent même le processus fini.
    let _ = (pid, depart);
    crate::machine::windows::pare_feu::rendre_programme(chemin)
}

#[cfg(any(windows, test))]
fn note_windows() -> &'static str {
    tr!(
        "tous les processus de ce fichier ; les connexions déjà ouvertes ne sont pas coupées ; les règles restent après un redémarrage",
        "all processes of this file; connections already open are not cut; the rules stay after a restart"
    )
}

/// L'unité de systemd (du gestionnaire du système) d'un chemin de cgroup, et le sous-cgroup sous elle : la première
/// composante en .service ou .scope (sous elle, l'arbre est délégué : `user@<uid>.service/app.slice/…`). `None` :
/// aucune unité (un processus hors des unités de systemd), ou un nom refusé. Pur.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn unite_et_sous_cgroupe(chemin: &str) -> Option<(String, String)> {
    let reste = chemin.strip_prefix('/')?;
    let composantes: Vec<&str> = reste.split('/').collect();
    let i = composantes.iter().position(|c| {
        c.rsplit_once('.')
            .is_some_and(|(_, genre)| genre == "service" || genre == "scope")
    })?;
    let unite = (*composantes.get(i)?).to_string();
    let dessous = composantes.get(i.checked_add(1)?..).unwrap_or_default();
    let sous = if dessous.is_empty() {
        String::new()
    } else {
        format!("/{}", dessous.join("/"))
    };
    #[cfg(target_os = "linux")]
    {
        use crate::machine::linux::dbus::systeme;
        if !systeme::unite_de_retour_admise(&unite) || !systeme::sous_cgroupe_admis(&sous) {
            return None;
        }
    }
    Some((unite, sous))
}

/// Le cgroup (v2) d'un processus d'après le texte de `/proc/<pid>/cgroup` : la ligne « 0:: ». Pur.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn cgroupe_du_texte(texte: &str) -> Option<String> {
    texte
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_string)
        .filter(|c| c.starts_with('/'))
}

/// La note de l'assistant pour une coupure : le cgroup coupé (son numéro) et celui d'où venait le processus.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NoteDeCoupure {
    pub(crate) cgroupe: u64,
    pub(crate) origine: String,
}

#[cfg(any(target_os = "linux", test))]
impl NoteDeCoupure {
    pub(crate) fn ecrire(&self) -> String {
        format!("cgroupe={}\norigine={}\n", self.cgroupe, self.origine)
    }

    /// Relue : les deux lignes, et rien d'autre ; une origine qui n'est pas un chemin de cgroup est refusée.
    pub(crate) fn lire(texte: &str) -> Option<NoteDeCoupure> {
        let mut lignes = texte.lines();
        let cgroupe = lignes.next()?.strip_prefix("cgroupe=")?.parse().ok()?;
        let origine = lignes.next()?.strip_prefix("origine=")?.to_string();
        (lignes.next().is_none() && origine.starts_with('/') && origine.len() <= 4096 && !origine.contains(".."))
            .then_some(NoteDeCoupure { cgroupe, origine })
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    use super::{NoteDeCoupure, OU, Resultat, cgroupe_du_texte, unite_et_sous_cgroupe};
    use crate::machine::linux::dbus::systeme::{self, TRANCHE_DES_COUPURES};
    use crate::machine::linux::nftables::{self, Element, NIVEAU_DES_COUPES, Retrait};
    use crate::modele::Echec;
    use crate::{tr, trf};

    /// Les notes de l'assistant : dans /run (effacé au redémarrage, comme la coupure), à root seul.
    const NOTES: &str = "/run/vanguard/coupes";
    const RACINE_DES_CGROUPES: &str = "/sys/fs/cgroup";

    fn refus(phrase: impl Into<String>) -> Echec {
        Echec::refuse(OU, phrase)
    }

    fn reaffecte(pid: u32) -> Echec {
        refus(trf!(
            "le PID {pid} désigne maintenant un autre programme (ou plus aucun) : rien n'est coupé",
            "PID {pid} now points to another program (or none): nothing is cut"
        ))
    }

    fn cgroupe_de(pid: u32) -> Option<String> {
        cgroupe_du_texte(&std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?)
    }

    fn meme_processus(pid: u32, chemin: &str, depart: u64) -> bool {
        crate::socle::processus::debut(pid) == Some(depart)
            && super::super::gestes::chemin_du_processus(pid)
                .is_some_and(|a| super::super::gestes::meme_chemin(&a, chemin))
    }

    fn fichier_de_note(pid: u32, depart: u64) -> String {
        format!("{NOTES}/{pid}-{depart}")
    }

    fn noter(pid: u32, depart: u64, note: &NoteDeCoupure) -> std::io::Result<()> {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(NOTES)?;
        std::fs::write(fichier_de_note(pid, depart), note.ecrire())
    }

    /// Les numéros des cgroups vivants sous vanguard.slice (les scopes de coupure encore là).
    fn cgroupes_vivants() -> Vec<u64> {
        std::fs::read_dir(format!("{RACINE_DES_CGROUPES}/{TRANCHE_DES_COUPURES}"))
            .map(|d| {
                d.flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .filter(|e| systeme::est_nom_de_coupure(&e.file_name().to_string_lossy()))
                    .filter_map(|e| e.metadata().ok().map(|m| m.ino()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Retire de nf_tables les cgroups morts (leur processus fini, le scope ramassé) et leurs notes : un numéro de
    /// cgroup ne revient jamais, l'élément ne visait plus rien.
    fn elaguer() {
        let vivants = cgroupes_vivants();
        for id in nftables::cgroupes_coupes().unwrap_or_default() {
            if !vivants.contains(&id) {
                let _ = nftables::retirer(Element::Cgroupe(id));
            }
        }
        if let Ok(d) = std::fs::read_dir(NOTES) {
            for e in d.flatten() {
                let morte = std::fs::read_to_string(e.path())
                    .ok()
                    .and_then(|t| NoteDeCoupure::lire(&t))
                    .is_none_or(|n| !vivants.contains(&n.cgroupe));
                if morte {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }

    pub(super) fn couper(pid: u32, chemin: &str, depart: u64) -> Result<Resultat, Echec> {
        if !meme_processus(pid, chemin, depart) {
            return Err(reaffecte(pid));
        }
        if !systeme::systemd_present() {
            return Err(refus(tr!(
                "systemd n'est pas le gestionnaire de ce système : le processus ne peut pas être mis à part, rien n'est coupé",
                "systemd is not this system's manager: the process cannot be set apart, nothing is cut"
            )));
        }
        let origine = cgroupe_de(pid).ok_or_else(|| reaffecte(pid))?;
        if origine.starts_with(&format!("/{TRANCHE_DES_COUPURES}/")) {
            return Err(refus(trf!(
                "le réseau du processus {pid} est déjà coupé",
                "process {pid}'s network is already cut"
            )));
        }
        // D'où il vient, pour l'y remettre : sans unité de systemd lisible, il ne serait pas remis, rien n'est fait.
        let (unite, sous) = unite_et_sous_cgroupe(&origine).ok_or_else(|| {
            refus(tr!(
                "l'unité de systemd du processus ne se lit pas : il ne pourrait pas y être remis, rien n'est coupé",
                "the process's systemd unit cannot be read: it could not be put back, nothing is cut"
            ))
        })?;
        elaguer();
        let nom = systeme::nom_de_coupure(pid, depart);
        let mut bus = systeme::bus_pour_agir()?;
        let description = trf!(
            "Vanguard : réseau coupé pour {chemin}",
            "Vanguard: network cut for {chemin}"
        );
        systeme::scope_de_coupure(&mut bus, &nom, pid, &description)?;
        let attendu = format!("/{TRANCHE_DES_COUPURES}/{nom}");
        // Le bus ne passe pas le processus par un descripteur : relu après coup. Changé (fini, un autre), il est
        // remis d'où il venait s'il est encore dans le scope, et rien n'est coupé.
        if !meme_processus(pid, chemin, depart) || cgroupe_de(pid).as_deref() != Some(attendu.as_str()) {
            if cgroupe_de(pid).as_deref() == Some(attendu.as_str()) {
                let _ = systeme::remettre_dans(&mut bus, &unite, &sous, pid);
            }
            return Err(reaffecte(pid));
        }
        let remettre = |bus: &mut _| {
            let _ = systeme::remettre_dans(bus, &unite, &sous, pid);
        };
        let id = match std::fs::metadata(format!("{RACINE_DES_CGROUPES}{attendu}")) {
            Ok(m) => m.ino(),
            Err(e) => {
                remettre(&mut bus);
                return Err(Echec::io(OU, &e));
            }
        };
        if let Err(e) = nftables::couper_cgroupe(id, NIVEAU_DES_COUPES) {
            remettre(&mut bus);
            return Err(e);
        }
        if let Err(e) = noter(pid, depart, &NoteDeCoupure { cgroupe: id, origine }) {
            let _ = nftables::retirer(Element::Cgroupe(id));
            remettre(&mut bus);
            return Err(Echec::ecriture(OU, &e));
        }
        // Après la règle : une prise ouverte avant le scope garde son ancien cgroup, la règle ne la voit pas.
        let prises = match crate::machine::linux::couper::couper_processus(pid) {
            Ok(c) => trf!(
                "{} connexion(s) déjà ouverte(s) coupée(s)",
                "{} connection(s) already open cut",
                c.coupees
            ),
            Err(e) => trf!(
                "connexions déjà ouvertes NON coupées ({e}) : seules les nouvelles sont bloquées",
                "connections already open NOT cut ({e}): only new ones are blocked"
            ),
        };
        Ok(Resultat::ok_note(trf!(
            "jusqu'au redémarrage ; {prises}",
            "until restart; {prises}"
        )))
    }

    pub(super) fn rendre(pid: u32, depart: u64) -> Result<Resultat, Echec> {
        let fichier = fichier_de_note(pid, depart);
        let Some(note) = std::fs::read_to_string(&fichier)
            .ok()
            .and_then(|t| NoteDeCoupure::lire(&t))
        else {
            elaguer();
            return Ok(Resultat::ok_note(tr!(
                "aucune coupure notée pour ce processus (l'ordinateur a redémarré, ou c'est déjà rendu) : rien à rendre",
                "no cut noted for this process (the computer restarted, or it was already given back): nothing to give back"
            )));
        };
        let retrait = nftables::retirer(Element::Cgroupe(note.cgroupe))?;
        // Toujours là et toujours dans son scope : remis d'où il venait.
        let attendu = format!("/{TRANCHE_DES_COUPURES}/{}", systeme::nom_de_coupure(pid, depart));
        let mut dit = Vec::new();
        if crate::socle::processus::debut(pid) == Some(depart) && cgroupe_de(pid).as_deref() == Some(attendu.as_str()) {
            let remis = unite_et_sous_cgroupe(&note.origine)
                .ok_or_else(|| refus(tr!("unité d'origine illisible", "original unit unreadable")))
                .and_then(|(unite, sous)| {
                    systeme::bus_pour_agir().and_then(|mut bus| systeme::remettre_dans(&mut bus, &unite, &sous, pid))
                });
            if let Err(e) = remis {
                dit.push(trf!(
                    "le processus reste dans {TRANCHE_DES_COUPURES}, systemd ne l'a pas remis ({e})",
                    "the process stays in {TRANCHE_DES_COUPURES}, systemd did not put it back ({e})"
                ));
            }
        }
        let _ = std::fs::remove_file(&fichier);
        elaguer();
        if retrait == Retrait::SansTable {
            dit.push(
                tr!(
                    "plus de table de Vanguard (l'ordinateur a redémarré)",
                    "no Vanguard table any more (the computer restarted)"
                )
                .to_string(),
            );
        }
        Ok(if dit.is_empty() {
            Resultat::ok()
        } else {
            Resultat::ok_note(dit.join(" ; "))
        })
    }
}

// ------------------------------------------------------------- du côté de la personne

/// La précision d'un ordre réussi, telle que l'élevé l'a notée (`<ligne> (<précision>)`).
fn precision(ligne: &str, notes: &[String]) -> Option<String> {
    notes.iter().find_map(|n| {
        n.strip_prefix(ligne)?
            .trim()
            .strip_prefix('(')?
            .strip_suffix(')')
            .map(ordres::note_lisible)
    })
}

fn refus_de_l_elevation(notes: &[String]) -> Echec {
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

fn evenement(
    source: crate::modele::evenement::Source,
    o: &Ordre,
    reussi: bool,
    cle: Option<&str>,
) -> crate::modele::evenement::Evenement {
    crate::modele::evenement::Evenement::action(source, &o.texte(), reussi, &[o.ligne()]).cle(cle)
}

/// Coupe le réseau du programme d'une menace : gardes rejugées (avec les processus que Vanguard protège), puis
/// l'ordre confié à l'élevé (toujours : il faut les droits d'administrateur), noté au journal et dans la liste
/// scellée. Rend la précision de l'élevé (connexions coupées, « jusqu'au redémarrage »).
pub(crate) fn couper(
    pid: u32,
    chemin: &str,
    quoi: &str,
    cle: Option<&str>,
    intouchables: &HashSet<u32>,
    source: crate::modele::evenement::Source,
) -> Result<String, Echec> {
    let depart = super::suspension::depart_de(pid).ok_or_else(|| {
        Echec::refuse(
            OU,
            trf!(
                "le processus {pid} est fini ou ne se relit pas : rien n'est coupé",
                "process {pid} has ended or cannot be read: nothing is cut"
            ),
        )
    })?;
    let o = Ordre::CouperReseauProgramme {
        pid,
        chemin: chemin.to_string(),
        depart,
    };
    if let Some(raison) = ordres::juger(&o, &ordres::Juge::lire(None).avec(intouchables)) {
        return Err(Echec::refuse(OU, raison));
    }
    if charger().is_ok_and(|l| l.coupes.len() >= COUPES_MAX && l.coupes.iter().all(|c| c.pid != pid)) {
        return Err(Echec::refuse(
            OU,
            trf!(
                "déjà {COUPES_MAX} programmes coupés du réseau par Vanguard : rendez-en un d'abord (vanguard blocage rendre-reseau <PID>)",
                "already {COUPES_MAX} programs cut from the network by Vanguard: give one back first (vanguard blocking restore-network <PID>)"
            ),
        ));
    }
    let ligne = o.ligne();
    let (faits, notes) = crate::machine::appliquer_chacune_sans_noter(&[vec![ligne.clone()]]);
    let notes = notes.into_iter().next().unwrap_or_default();
    let reussi = faits.first().copied().unwrap_or(false);
    crate::modele::journal::noter(evenement(source, &o, reussi, cle));
    if !reussi {
        return Err(refus_de_l_elevation(&notes));
    }
    retenir(Coupe {
        pid,
        depart,
        chemin: chemin.to_string(),
        quoi: quoi.to_string(),
        le: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
    })?;
    Ok(precision(&ligne, &notes).unwrap_or_default())
}

/// Ajoute une coupure à la liste (le même numéro remplacé) ; une liste qui ne compte pas est remplacée, et c'est dit.
fn retenir(c: Coupe) -> Result<(), Echec> {
    let mut l = charger().unwrap_or_else(|raison| {
        afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
            &trf!(
                "{raison} : elle ne compte plus, une liste neuve la remplace.",
                "{raison}: it no longer counts, a new list replaces it."
            ),
            4,
            "",
        );
        Liste::default()
    });
    l.coupes.retain(|x| x.pid != c.pid);
    l.coupes.push(c);
    enregistrer(&l).map_err(|e| Echec::ecriture(OU, &e))
}

/// Ce qu'a donné le retour du réseau à un programme.
pub(crate) struct Rendu {
    pub(crate) pid: u32,
    pub(crate) chemin: String,
    pub(crate) issue: Result<Option<String>, Echec>,
}

/// Rend le réseau à `pid` (sans : à tous ceux que Vanguard a coupés), en une seule demande de droits. Un PID hors de
/// la liste (ou une liste changée hors de Vanguard) est relu ici : son programme et son départ, jamais ceux de la
/// liste ; l'élevé ne lève de toute façon que ce qu'il a posé lui-même.
pub(crate) fn rendre(pid: Option<u32>) -> (Vec<Rendu>, Option<&'static str>) {
    let (mut liste, refus) = match charger() {
        Ok(l) => (l.coupes, None),
        Err(r) => (Vec::new(), Some(r)),
    };
    // Tous : un processus fini (Linux) a emporté sa coupure, il est oublié sans demander de droits pour rien.
    if pid.is_none() && refus.is_none() && liste.iter().any(|c| !tient(c)) {
        liste.retain(tient);
        if let Err(e) = enregistrer(&Liste { coupes: liste.clone() }) {
            trp!("  ✖ {}", "  ✖ {}", Echec::ecriture(OU, &e));
        }
    }
    let mut visees: Vec<Coupe> = liste
        .iter()
        .filter(|c| pid.is_none_or(|p| c.pid == p))
        .cloned()
        .collect();
    if let Some(p) = pid
        && visees.is_empty()
        && let (Some(chemin), Some(depart)) = (super::gestes::chemin_du_processus(p), super::suspension::depart_de(p))
    {
        visees.push(Coupe {
            pid: p,
            depart,
            chemin,
            quoi: String::new(),
            le: String::new(),
        });
    }
    if visees.is_empty() {
        return (Vec::new(), refus);
    }
    let ordres: Vec<Ordre> = visees
        .iter()
        .map(|c| Ordre::RendreReseauProgramme {
            pid: c.pid,
            chemin: c.chemin.clone(),
            depart: c.depart,
        })
        .collect();
    let groupes: Vec<Vec<String>> = ordres.iter().map(|o| vec![o.ligne()]).collect();
    let (faits, notes) = crate::machine::appliquer_chacune_sans_noter(&groupes);
    let mut rendus = Vec::new();
    for (i, (c, o)) in visees.iter().zip(&ordres).enumerate() {
        let fait = faits.get(i).copied().unwrap_or(false);
        let n = notes.get(i).map_or(&[][..], Vec::as_slice);
        crate::modele::journal::noter(evenement(crate::modele::evenement::Source::Utilisateur, o, fait, None));
        rendus.push(Rendu {
            pid: c.pid,
            chemin: c.chemin.clone(),
            issue: if fait {
                Ok(precision(&o.ligne(), n))
            } else {
                Err(refus_de_l_elevation(n))
            },
        });
    }
    // Rendus : oubliés de la liste (une liste qui ne compte pas n'est pas réécrite).
    if refus.is_none() {
        let faits: Vec<u32> = rendus.iter().filter(|r| r.issue.is_ok()).map(|r| r.pid).collect();
        let mut l = Liste { coupes: liste };
        l.coupes.retain(|c| !faits.contains(&c.pid));
        if let Err(e) = enregistrer(&l) {
            trp!("  ✖ {}", "  ✖ {}", Echec::ecriture(OU, &e));
        }
    }
    (rendus, refus)
}

/// La coupure tient-elle toujours ? Linux : seulement tant que ce processus vit (son scope part avec lui, et tout
/// part au redémarrage) ; Windows : les règles visent le fichier, elles restent.
fn tient(c: &Coupe) -> bool {
    cfg!(windows) || super::suspension::depart_de(c.pid) == Some(c.depart)
}

/// Au bilan : chaque programme coupé est rappelé (un programme coupé et oublié ne parle plus à personne) ; sous Linux,
/// un processus fini (ou l'ordinateur redémarré) est oublié, sa coupure partie avec lui. Une liste changée hors de
/// Vanguard est dite.
pub(crate) fn rappeler() {
    let l = match charger() {
        Ok(l) => l,
        Err(raison) => {
            crate::ui::section(tr!("RÉSEAU COUPÉ", "NETWORK CUT"));
            afficher_aligne(
                &format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)),
                &trf!(
                    "{raison} : ce qu'elle dit ne compte plus. « vanguard blocage rendre-reseau <PID> » rend le réseau à un processus relu ici.",
                    "{raison}: what it says no longer counts. “vanguard blocking restore-network <PID>” gives the network back to a process read again here."
                ),
                4,
                "",
            );
            return;
        }
    };
    let (vivantes, finies): (Vec<Coupe>, Vec<Coupe>) = l.coupes.into_iter().partition(tient);
    if !finies.is_empty() {
        let _ = enregistrer(&Liste {
            coupes: vivantes.clone(),
        });
    }
    if vivantes.is_empty() {
        return;
    }
    crate::ui::section(tr!("RÉSEAU COUPÉ", "NETWORK CUT"));
    for c in &vivantes {
        afficher_aligne(
            &format!("  {GRIS}⊘{RESET} "),
            &trf!(
                "PID {} ({}), depuis le {} : « vanguard blocage rendre-reseau {} » le lui rend.",
                "PID {} ({}), since {}: “vanguard blocking restore-network {}” gives it back.",
                c.pid,
                affichable(&c.chemin),
                c.le,
                c.pid
            ),
            4,
            "",
        );
    }
}

/// Le rôle d'un programme du système à nommer avant de couper son réseau (« montré et confirmé ») ; `None` : un
/// programme du compte. Windows : un programme du système est refusé (gardes de l'arrêt).
pub(crate) fn role(pid: u32, chemin: &str) -> Option<String> {
    super::suspension::role(pid, chemin)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unite_d_origine_lue_dans_le_cgroupe() {
        assert_eq!(
            unite_et_sous_cgroupe("/user.slice/user-1000.slice/session-3.scope"),
            Some(("session-3.scope".into(), String::new()))
        );
        let delegue = concat!(
            "/user.slice/user-1000.slice/user",
            "@1000.service/app.slice/app-x.scope"
        );
        assert_eq!(
            unite_et_sous_cgroupe(delegue),
            Some((concat!("user", "@1000.service").into(), "/app.slice/app-x.scope".into()))
        );
        assert_eq!(
            unite_et_sous_cgroupe("/system.slice/cups.service"),
            Some(("cups.service".into(), String::new()))
        );
        // Aucune unité : rien à quoi le remettre.
        assert_eq!(unite_et_sous_cgroupe("/"), None);
        assert_eq!(unite_et_sous_cgroupe("/user.slice"), None);
        assert_eq!(unite_et_sous_cgroupe("relatif.scope"), None);
        // Un nom qui sortirait de l'arbre est refusé (Linux : les mêmes règles que le message D-Bus).
        if cfg!(target_os = "linux") {
            assert_eq!(unite_et_sous_cgroupe("/a.service/../b"), None);
            assert_eq!(unite_et_sous_cgroupe("/a b.service"), None);
        }
    }

    #[test]
    fn cgroupe_de_la_ligne_unifiee() {
        assert_eq!(
            cgroupe_du_texte("0::/user.slice/x.scope\n"),
            Some("/user.slice/x.scope".into())
        );
        // Une hiérarchie v1 seule ne dit rien de la v2.
        assert_eq!(cgroupe_du_texte("1:name=systemd:/x\n"), None);
        assert_eq!(cgroupe_du_texte("12:cpu:/a\n0::/b.scope\n"), Some("/b.scope".into()));
        assert_eq!(cgroupe_du_texte("0::relatif\n"), None);
    }

    #[test]
    fn note_de_l_assistant_aller_retour() {
        let n = NoteDeCoupure {
            cgroupe: 4242,
            origine: "/user.slice/session-3.scope".into(),
        };
        assert_eq!(NoteDeCoupure::lire(&n.ecrire()), Some(n));
        for forgee in [
            "",
            "cgroupe=x\norigine=/a\n",
            "cgroupe=1\norigine=a\n",
            "cgroupe=1\norigine=/a/../b\n",
            "cgroupe=1\norigine=/a\nen-trop\n",
            "origine=/a\ncgroupe=1\n",
        ] {
            assert_eq!(NoteDeCoupure::lire(forgee), None, "{forgee:?}");
        }
    }

    #[test]
    fn regles_de_windows_nommees_par_programme_et_sens() {
        let c = r"C:\Users\alice\AppData\Local\Temp\outil.exe";
        assert_eq!(
            nom_de_regle(c, true),
            r"Vanguard : couper C:\Users\alice\AppData\Local\Temp\outil.exe (sortie)"
        );
        assert_ne!(nom_de_regle(c, true), nom_de_regle(c, false));
        assert!(!nom_de_regle(c, false).contains('|'));
        assert!(note_windows().contains(tr!("tous les processus", "all processes")));
    }

    #[test]
    fn precision_relue_de_la_note_de_l_eleve() {
        let ligne = "vanguard:rendre-reseau-programme 7 2f 1";
        let notes = vec![format!(
            "{ligne} (jusqu'au redémarrage ; 2 connexion(s) déjà ouverte(s) coupée(s))"
        )];
        assert_eq!(
            precision(ligne, &notes).as_deref(),
            Some("jusqu'au redémarrage ; 2 connexion(s) déjà ouverte(s) coupée(s)")
        );
        assert_eq!(precision(ligne, &[ligne.to_string()]), None);
        assert_eq!(precision(ligne, &["autre (x)".to_string()]), None);
    }

    /// La liste scellée, dans le dossier jetable des essais : écrite, relue ; changée à la main, elle ne compte plus.
    #[test]
    fn liste_scellee_relue_et_falsifiee_refusee() {
        let _ = std::fs::remove_file(crate::socle::dossier_local().join(crate::sceau::COUPURES));
        assert_eq!(charger(), Ok(Liste::default()));
        let c = Coupe {
            pid: 4242,
            depart: 99,
            chemin: "/home/alice/.cache/x".into(),
            quoi: "essai".into(),
            le: "2026-11-07 10:00".into(),
        };
        retenir(c.clone()).unwrap();
        assert_eq!(charger().unwrap().coupes, vec![c]);
        let f = crate::socle::dossier_local().join(crate::sceau::COUPURES);
        std::fs::write(&f, r#"{"coupes":[]}"#).unwrap();
        assert!(charger().is_err());
        let _ = std::fs::remove_file(f);
    }
}
