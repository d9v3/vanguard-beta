//! Les cas du corpus de détection propres à Linux (`modele::corpus`) : les données fabriquées d'un cas données aux
//! fonctions de jugement de la dissimulation (dissimulation.rs), sans rien lire de /proc ni de /sys.

use std::collections::BTreeSet;

use super::dissimulation::{
    Carte, Couverture, drapeaux_carte, hors_arbre_inconnus, juger_ecoute, juger_exe, juger_modules,
    juger_processus_caches, juger_sans_fichier, modules_caches, modules_charges, sonder,
};
use crate::machine::Constat;
use crate::modele::corpus::{Entree, Juge};

pub(crate) const CAS: &[(&str, Juge)] = &[
    ("LNX-PRS-003", processus_caches),
    ("LNX-PRS-004", sans_fichier),
    ("LNX-NOY-006", modules),
    ("LNX-RES-002", ecoute),
];

/// LNX-PRS-003 : `liste|pid,pid…` (ce que montre /proc) et `fiche|pid|nom|tgid` (ce qui répond au noyau).
fn processus_caches(e: &Entree) -> Vec<Constat> {
    let listes: BTreeSet<u32> = e
        .de("liste")
        .iter()
        .flat_map(|c| c[0].split(','))
        .map(|p| p.trim().parse().unwrap())
        .collect();
    let fiches: Vec<(u32, String)> = e
        .de("fiche")
        .iter()
        .map(|c| {
            let pid: u32 = c[0].parse().unwrap();
            (pid, format!("Name:\t{}\nTgid:\t{}\nPid:\t{pid}\n", c[1], c[2]))
        })
        .collect();
    let borne = listes
        .iter()
        .copied()
        .chain(fiches.iter().map(|(p, _)| *p))
        .max()
        .unwrap_or(1);
    let fiche = |pid: u32| fiches.iter().find(|(p, _)| *p == pid).map(|(_, f)| f.clone());
    let (caches, jusqu_a) = sonder(&listes, borne, fiche, || false);
    vec![juger_processus_caches(
        &caches,
        &Couverture::Pids { jusqu_a, borne },
        &[],
    )]
}

/// LNX-PRS-004 : `exe|pid|nom|lien de /proc/<pid>/exe|remplacé (oui, non)`.
fn sans_fichier(e: &Entree) -> Vec<Constat> {
    let exes = e.de("exe");
    let reperes: Vec<_> = exes
        .iter()
        .filter_map(|c| {
            let raison = juger_exe(c[2], c[3] == "oui", "")?;
            Some((c[0].parse().unwrap(), c[1].to_string(), raison))
        })
        .collect();
    juger_sans_fichier(&reperes, exes.len(), 0, &[])
}

/// LNX-NOY-006 : `proc|ligne de /proc/modules`, `sysfs|module|initstate`, `souillure|valeur de kernel/tainted`.
fn modules(e: &Entree) -> Vec<Constat> {
    let liste = e.de("proc").iter().map(|c| c[0]).collect::<Vec<_>>().join("\n");
    let charges = modules_charges(&liste);
    let sysfs: Vec<(String, String)> = e
        .de("sysfs")
        .iter()
        .map(|c| (c[0].to_string(), c[1].to_string()))
        .collect();
    let caches = modules_caches(&sysfs, &charges);
    let inconnus = hors_arbre_inconnus(&charges, |_| false);
    let souillure = e.de("souillure").first().and_then(|c| c[0].parse().ok());
    juger_modules(&caches, &inconnus, &charges, souillure, &[])
}

/// LNX-RES-002 : `carte|nom|flags de /sys/class/net|matérielle (oui, non)|esclave (oui, non)`.
fn ecoute(e: &Entree) -> Vec<Constat> {
    let cartes: Vec<Carte> = e
        .de("carte")
        .iter()
        .map(|c| Carte {
            nom: c[0].to_string(),
            drapeaux: drapeaux_carte(c[1]).unwrap(),
            materielle: c[2] == "oui",
            esclave: c[3] == "oui",
        })
        .collect();
    juger_ecoute(&cartes).into_iter().collect()
}
