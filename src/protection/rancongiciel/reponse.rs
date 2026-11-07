//! La réponse à un rançongiciel quasi certain (Linux) : geler toute la lignée AVANT tout, pour arrêter le chiffrement
//! en quelques millisecondes et figer les traces (P3), puis laisser le blocage relever la preuve, arrêter et mettre en
//! quarantaine, sous ses garde-fous. Rien n'est effacé par le gel ; « Reprendre » l'annule. Si un garde-fou refuse
//! l'arrêt, le programme RESTE gelé et on le dit : jamais laissé gelé en silence.
//!
//! Dite comme une suite de gestes (`blocage::suites`), c'est la suite par défaut du rançongiciel : suspendre (ici,
//! toute la lignée ; ses envois s'arrêtent avec elle), couper ses connexions (l'arrêt les ferme), relever la preuve
//! (le blocage la relève avant l'arrêt), arrêter et mettre en quarantaine, puis prévenir (l'alerte du veilleur). Le
//! veilleur la fait toujours ainsi, tout seul : une suite réglée dans blocage.json ne sert que lorsqu'on répond à son
//! alerte, et son geste Suspendre ne gèle alors que le processus désigné, pas sa lignée.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::protection::blocage;
use crate::socle::processus;
use crate::tr;

/// Le programme à geler et arrêter.
#[derive(Debug, Clone)]
pub(crate) struct Cible {
    /// La racine de la lignée (le processus à arrêter en premier).
    pub racine: u32,
    pub nom: String,
    pub chemin: Option<PathBuf>,
    /// Ce qui serait mis en quarantaine (le blocage n'y met jamais un interpréteur : seulement son script).
    pub fichier: Option<PathBuf>,
    /// Ce qui l'a désigné, gardé avec le fichier en quarantaine.
    pub detection: String,
    /// La clé stable « `rancongiciel:<chemin>` », qui relie l'alerte, la preuve et le geste.
    pub cle: String,
    /// Le départ de la racine (`processus::debut`), quand celui qui l'a désignée l'a lu avec ce qu'il a jugé (le
    /// veilleur, au lancement) : la racine n'est alors gelée que par un pidfd si elle est encore ce processus-là, et
    /// n'est arrêtée que si son départ n'a pas changé. Un numéro repris entre le jugement et l'arrêt ne fait jamais
    /// geler ni arrêter un autre programme. `None` : la racine se juge maintenant (le rançongiciel, attribué à
    /// l'instant).
    pub debut: Option<u64>,
    /// L'inode lancé (périphérique, numéro), tenu par qui l'a jugé, avec `debut` : le programme à arrêter se
    /// reconnaît à lui, plus à son chemin. Le chemin est relu juste avant l'arrêt et le fichier n'est mis en
    /// quarantaine que s'il y désigne encore cet inode (`chemin` et `fichier` ne servent alors plus) : un programme
    /// qui renomme son fichier n'échappe pas à l'arrêt, et un fichier mis à sa place n'est jamais isolé.
    pub inode: Option<(u64, u64)>,
}

/// Ce qu'a donné la réponse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Issue {
    /// Gelé, arrêté et mis en quarantaine : la phrase de ce qui a été fait.
    Arrete(String),
    /// Gelé, mais pas arrêté (un garde-fou a refusé) : la raison, et les pid restés gelés.
    Gele { raison: String, geles: Vec<u32> },
    /// Rien n'a pu être gelé (la racine est intouchable) : la raison. Alerte seulement.
    Refuse(String),
}

/// Un membre de la lignée, tel que l'appelant le relit (pid, nom, chemin).
pub(crate) type Membre = (u32, String, Option<PathBuf>);

/// Essais d'arrêt au plus quand le fichier lancé change encore de nom entre la relecture de son chemin et l'arrêt
/// (un processus hors de la lignée gelée le renomme) ; au-delà, il est arrêté par son pidfd, sans quarantaine.
const ESSAIS_RENOMME: usize = 3;

/// Nombre de passes de gel au plus : un `fork` entre la liste et le signal échappe au gel, donc on répète liste + gel
/// jusqu'à deux passes sans nouveau membre, sans dépasser cinq.
const PASSES_MAX: usize = 5;

/// Gèle la lignée puis arrête et met en quarantaine le programme. `lignee()` relit la lignée à geler (appelée à chaque
/// passe : elle rattrape un `fork` arrivé entre-temps). La racine est gelée en premier pour couper le chiffrement tout
/// de suite.
pub(crate) fn geler_et_arreter(cible: &Cible, lignee: impl Fn() -> Vec<Membre>) -> Issue {
    // Les mêmes intouchables que le blocage (Vanguard, ce qu'il a lancé, ce qui le fait tourner) : un ensemble vide
    // laissait geler puis tuer le terminal ou la session d'où Vanguard tourne, s'ils tombaient dans la lignée.
    let Some((_, intouchables)) = crate::machine::chasse::en_marche() else {
        return Issue::Refuse(
            tr!(
                "la liste des programmes en marche ne se lit pas : rien n'est gelé à l'aveugle",
                "the list of running programs cannot be read: nothing is frozen blindly"
            )
            .to_string(),
        );
    };
    let chemin_racine = cible.chemin.as_ref().map(|c| c.to_string_lossy().into_owned());
    // La racine doit pouvoir être gelée : sinon rien (alerte seulement).
    if let Some(raison) = blocage::processus_gelable(cible.racine, &cible.nom, chemin_racine.as_deref(), &intouchables)
    {
        return Issue::Refuse(raison.to_string());
    }

    // Chaque membre gelé avec son départ, lu une fois gelé : regelé ou tué plus tard par un pidfd seulement s'il est
    // encore ce processus-là (un numéro libéré puis repris, même gelé par Ctrl-Z, n'est jamais touché).
    let mut geles: HashMap<u32, Option<u64>> = HashMap::new();
    match cible.debut {
        #[cfg(target_os = "linux")]
        Some(debut) => {
            if !processus::geler_si(cible.racine, debut) {
                return Issue::Refuse(
                    tr!(
                        "le processus jugé n'est plus là (parti, ou son numéro repris par un autre) : rien n'est gelé",
                        "the judged process is gone (exited, or its number reused by another): nothing is frozen"
                    )
                    .to_string(),
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        Some(_) => {
            return Issue::Refuse(
                tr!(
                    "le départ d'un processus ne se vérifie pas ici : rien n'est gelé",
                    "a process start cannot be checked here: nothing is frozen"
                )
                .to_string(),
            );
        }
        None => {
            processus::geler(cible.racine);
        }
    }
    geles.insert(cible.racine, processus::debut(cible.racine));

    // Un membre pris dans la lignée (le même groupe de processus) sans descendre de la racine, sous un hôte de session
    // à distance (SSH, xrdp), n'est ni gelé ni tué : ce serait figer ou couper cette session (défense D6a, relecture).
    // Lu jusqu'à la racine seulement : ce qu'elle a lancé est à elle, et elle passe elle-même par le blocage.
    let sessions = blocage::gardes::sessions_a_distance();
    let hors_session = |pid: u32, sessions: Option<&blocage::gardes::Sessions>| {
        blocage::gardes::lignee_de_session_sous(pid, cible.racine, sessions).is_none()
    };

    // Passes : liste + gel, jusqu'à deux passes de suite sans nouveau membre (au plus cinq).
    let mut sans_nouveau = 0usize;
    for _ in 0..PASSES_MAX {
        let mut nouveau = false;
        for (pid, nom, chemin) in lignee() {
            if geles.contains_key(&pid) {
                continue;
            }
            let c = chemin.as_ref().map(|c| c.to_string_lossy().into_owned());
            if blocage::processus_gelable(pid, &nom, c.as_deref(), &intouchables).is_none()
                && hors_session(pid, sessions.as_ref())
                && processus::geler(pid)
            {
                geles.insert(pid, processus::debut(pid));
                nouveau = true;
            }
        }
        sans_nouveau = if nouveau { 0 } else { sans_nouveau.saturating_add(1) };
        if sans_nouveau >= 2 {
            break;
        }
    }

    // Un tiers a pu envoyer SIGCONT : regeler ce qui n'est plus « T », s'il est encore ce processus-là.
    for (&pid, &debut) in &geles {
        if processus::est_gele(pid) == Some(false)
            && let Some(debut) = debut
        {
            processus::geler_si(pid, debut);
        }
    }

    // Gelée, la racine ne peut plus finir d'elle-même ; son départ relu juste avant l'arrêt dit qu'elle est encore
    // celle qui a été jugée (un tiers a pu la tuer pendant les passes, et son numéro être repris).
    #[cfg(target_os = "linux")]
    if let Some(debut) = cible.debut
        && processus::debut(cible.racine) != Some(debut)
    {
        let mut v: Vec<u32> = geles.into_keys().filter(|&p| p != cible.racine).collect();
        v.sort_unstable();
        reprendre(&v);
        return Issue::Refuse(
            tr!(
                "le processus jugé n'est plus là (son numéro repris par un autre) : rien n'est arrêté, sa lignée est reprise",
                "the judged process is gone (its number reused by another): nothing is stopped, its lineage is resumed"
            )
            .to_string(),
        );
    }

    // Arrêt + quarantaine de la racine, sous les garde-fous du blocage (preuve relevée avant).
    let fait = match (cible.debut, cible.inode) {
        (Some(debut), Some(inode)) => arreter_tenu(cible, &intouchables, debut, inode),
        _ => blocage::arreter_programme_automatique(
            &intouchables,
            cible.racine,
            &cible.nom,
            cible.chemin.clone(),
            cible.fichier.clone(),
            &cible.detection,
            &cible.cle,
        )
        .map_err(|e| Fin::Garde(String::from(e))),
    };
    match fait {
        Ok(quoi) => {
            // La racine arrêtée, tuer le reste de la lignée gelée (le chiffrement était déjà figé).
            // Seulement ce qui est encore gelé, et encore le processus gelé (son départ) : un numéro libéré
            // entre-temps a pu être repris par un autre programme, qui n'a pas à être tué (comme « Reprendre » ne
            // dégèle que ce qui l'est encore). Les sessions relues, comme avant tout arrêt : une ouverte depuis le gel
            // compte.
            let sessions = blocage::gardes::sessions_a_distance();
            for (&pid, &debut) in &geles {
                if pid != cible.racine
                    && processus::est_gele(pid) == Some(true)
                    && hors_session(pid, sessions.as_ref())
                    && let Some(debut) = debut
                {
                    processus::tuer_si(pid, debut);
                }
            }
            Issue::Arrete(quoi)
        }
        Err(Fin::Garde(raison)) => {
            let mut v: Vec<u32> = geles.into_keys().collect();
            v.sort_unstable();
            Issue::Gele { raison, geles: v }
        }
        Err(Fin::Autre(raison)) => {
            let mut v: Vec<u32> = geles.into_keys().collect();
            v.sort_unstable();
            reprendre(&v);
            Issue::Refuse(raison)
        }
    }
}

/// Pourquoi l'arrêt n'a pas eu lieu.
enum Fin {
    /// Un garde-fou du blocage l'a refusé (programme intouchable, session à distance, droits) : la raison.
    Garde(String),
    /// Le processus ne tourne plus le programme jugé : la raison ; rien n'est arrêté et sa lignée est reprise.
    Autre(String),
}

/// Le chemin actuel du programme lancé par `pid`, si `pid` est encore le processus parti à `debut` et tourne encore
/// l'inode `inode` (« (deleted) » retiré, comme le blocage le relit) ; `None` sinon.
fn chemin_tenu(pid: u32, debut: u64, inode: (u64, u64)) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    if processus::debut(pid) != Some(debut) {
        return None;
    }
    let m = std::fs::metadata(format!("/proc/{pid}/exe")).ok()?;
    if (m.dev(), m.ino()) != inode {
        return None;
    }
    let lien = processus::programme(pid)?;
    let lien = lien.to_string_lossy();
    Some(PathBuf::from(lien.strip_suffix(" (deleted)").unwrap_or(&lien)))
}

/// `chemin` désigne-t-il encore l'inode `inode`, en fichier ordinaire ? Sinon (effacé, ou un autre fichier mis à sa
/// place), ce qui est là n'est pas ce qui a été jugé : jamais mis en quarantaine.
pub(crate) fn fichier_tenu(chemin: &Path, inode: (u64, u64)) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(chemin).is_ok_and(|m| m.is_file() && (m.dev(), m.ino()) == inode)
}

/// Arrête la racine reconnue par son départ et son inode lancé (le veilleur) : le chemin relu juste avant l'arrêt est
/// celui que le blocage attend. Un programme qui renomme son fichier (lui-même avant le gel, ou un autre processus
/// depuis) est arrêté quand même : un refus parce que le chemin a encore changé se rejoue, puis, au-delà de
/// `ESSAIS_RENOMME`, l'arrêt passe par le pidfd, après les mêmes garde-fous (intouchable, système, session).
fn arreter_tenu(cible: &Cible, intouchables: &HashSet<u32>, debut: u64, inode: (u64, u64)) -> Result<String, Fin> {
    let parti = || {
        Fin::Autre(
            tr!(
                "le processus ne tourne plus le programme jugé (parti, ou numéro repris) : rien n'est arrêté, sa lignée est reprise",
                "the process no longer runs the judged program (exited, or number reused): nothing is stopped, its lineage is resumed"
            )
            .to_string(),
        )
    };
    for _ in 0..ESSAIS_RENOMME {
        let chemin = chemin_tenu(cible.racine, debut, inode).ok_or_else(parti)?;
        let fichier = fichier_tenu(&chemin, inode).then(|| chemin.clone());
        match blocage::arreter_programme_automatique(
            intouchables,
            cible.racine,
            &cible.nom,
            Some(chemin.clone()),
            fichier,
            &cible.detection,
            &cible.cle,
        ) {
            Ok(quoi) => return Ok(quoi),
            // Toujours ce processus et cet inode, sous un autre nom : le refus ne venait que du chemin, on relit.
            Err(_) if chemin_tenu(cible.racine, debut, inode).is_some_and(|c| c != chemin) => {}
            Err(e) => return Err(Fin::Garde(String::from(e))),
        }
    }
    let chemin = chemin_tenu(cible.racine, debut, inode).ok_or_else(parti)?;
    let texte = chemin.to_string_lossy();
    let sessions = blocage::gardes::sessions_a_distance();
    if let Some(raison) = blocage::gardes::processus_intouchable(
        cible.racine,
        &cible.nom,
        Some(&texte),
        intouchables,
        crate::machine::regles::Os::Linux,
    )
    .or_else(|| blocage::gardes::lignee_de_session(cible.racine, sessions.as_ref()))
    {
        return Err(Fin::Garde(raison.to_string()));
    }
    if processus::tuer_si(cible.racine, debut) {
        Ok(tr!(
            "arrêté par son pidfd ; son fichier change de nom sans cesse : pas mis en quarantaine",
            "stopped through its pidfd; its file keeps changing name: not quarantined"
        )
        .to_string())
    } else {
        Err(parti())
    }
}

/// Reprend (dégèle) une lignée : « Reprendre » après un gel. Seulement ce qui est encore gelé : un PID noté il y a
/// longtemps a pu être repris par un autre processus, qui n'a pas à recevoir de SIGCONT.
pub(crate) fn reprendre(pids: &[u32]) {
    for &pid in pids {
        if processus::est_gele(pid) == Some(true) {
            processus::reprendre(pid);
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use crate::protection::blocage::suites::{Etape, Type, defaut, plancher_tenu};

    /// La réponse, dans l'ordre où elle agit, est la suite par défaut du rançongiciel, et celle-ci tient le plancher
    /// du certain : changer l'une sans l'autre fait échouer l'essai.
    #[test]
    fn la_reponse_est_la_suite_par_defaut() {
        use Etape::*;
        let reponse = [Suspendre, CouperConnexions, Preuve, Bloquer, Prevenir];
        assert_eq!(defaut(Type::Rancongiciel), reponse);
        assert!(plancher_tenu(Type::Rancongiciel, &reponse));
    }
}
