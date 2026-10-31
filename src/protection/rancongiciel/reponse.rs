//! La réponse à un rançongiciel quasi certain (Linux) : geler toute la lignée AVANT tout, pour arrêter le chiffrement
//! en quelques millisecondes et figer les traces (P3), puis laisser le blocage relever la preuve, arrêter et mettre en
//! quarantaine, sous ses garde-fous. Rien n'est effacé par le gel ; « Reprendre » l'annule. Si un garde-fou refuse
//! l'arrêt, le programme RESTE gelé et on le dit : jamais laissé gelé en silence.

use std::collections::HashSet;
use std::path::PathBuf;

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

    let mut geles: HashSet<u32> = HashSet::new();
    processus::geler(cible.racine);
    geles.insert(cible.racine);

    // Passes : liste + gel, jusqu'à deux passes de suite sans nouveau membre (au plus cinq).
    let mut sans_nouveau = 0;
    for _ in 0..PASSES_MAX {
        let mut nouveau = false;
        for (pid, nom, chemin) in lignee() {
            if geles.contains(&pid) {
                continue;
            }
            let c = chemin.as_ref().map(|c| c.to_string_lossy().into_owned());
            if blocage::processus_gelable(pid, &nom, c.as_deref(), &intouchables).is_none() && processus::geler(pid) {
                geles.insert(pid);
                nouveau = true;
            }
        }
        sans_nouveau = if nouveau { 0 } else { sans_nouveau + 1 };
        if sans_nouveau >= 2 {
            break;
        }
    }

    // Un tiers a pu envoyer SIGCONT : regeler ce qui n'est plus « T ».
    for &pid in &geles {
        if processus::est_gele(pid) == Some(false) {
            processus::geler(pid);
        }
    }

    // Arrêt + quarantaine de la racine, sous les garde-fous du blocage (preuve relevée avant).
    match blocage::arreter_programme_automatique(
        &intouchables,
        cible.racine,
        &cible.nom,
        cible.chemin.clone(),
        cible.fichier.clone(),
        &cible.detection,
        &cible.cle,
    ) {
        Ok(quoi) => {
            // La racine arrêtée, tuer le reste de la lignée gelée (le chiffrement était déjà figé).
            // Seulement ce qui est encore gelé : un numéro libéré entre-temps a pu être repris par un autre
            // programme, qui n'a pas à être tué (comme « Reprendre » ne dégèle que ce qui l'est encore).
            for &pid in &geles {
                if pid != cible.racine && processus::est_gele(pid) == Some(true) {
                    tuer(pid);
                }
            }
            Issue::Arrete(quoi)
        }
        Err(e) => {
            let mut v: Vec<u32> = geles.into_iter().collect();
            v.sort_unstable();
            Issue::Gele {
                raison: String::from(e),
                geles: v,
            }
        }
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

#[cfg(unix)]
// FFI de libc : kill (SIGKILL au processus fautif).
#[allow(unsafe_code)]
fn tuer(pid: u32) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: SIGKILL à un numéro de processus ; il arrête aussi un processus gelé.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn tuer(_pid: u32) {}
