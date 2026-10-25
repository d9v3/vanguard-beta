//! Les cas du corpus de détection communs aux systèmes (`modele::corpus`) : les adaptateurs qui donnent les données
//! fabriquées d'un cas à la fonction de jugement de sa règle.

use std::collections::HashSet;

use super::Constat;
use super::chasse::{EnMarche, intrusions, juger_intrusions, juger_programmes, tentatives_ssh_datees};
use super::regles::Os;
use crate::modele::corpus::{Entree, Juge};

pub(crate) const CAS: &[(&str, Juge)] = &[
    ("COM-CPT-001", super::administrateurs::corpus),
    ("COM-CPT-003", connexion_forcee),
    ("COM-CRT-001", super::certificats::corpus),
    #[cfg(unix)]
    ("COM-DIS-001", crate::protection::distance::corpus),
    ("COM-INT-002", crate::protection::pieges::corpus),
    ("COM-JRN-001", super::journaux::corpus),
    ("COM-NAV-001", super::extensions::corpus),
    ("COM-PRG-001", programmes),
    #[cfg(unix)]
    ("LNX-PRV-004", dossiers_de_root),
    #[cfg(unix)]
    ("MAC-PRV-004", dossiers_du_mac),
];

/// COM-CPT-003 : des lignes du journal de sshd.
fn connexion_forcee(e: &Entree) -> Vec<Constat> {
    let lignes: Vec<((), &str)> = e.lignes().into_iter().map(|l| ((), l)).collect();
    let tentatives: Vec<_> = tentatives_ssh_datees(&lignes).into_iter().map(|((), t)| t).collect();
    vec![juger_intrusions(&intrusions(&tentatives), Os::Linux, None)]
}

/// COM-PRG-001 : `pid|nom|chemin|ligne de commande`.
fn programmes(e: &Entree) -> Vec<Constat> {
    let liste: Vec<EnMarche> = e
        .champs()
        .iter()
        .map(|c| EnMarche {
            pid: c[0].parse().unwrap(),
            parent: None,
            nom: c[1].to_string(),
            chemin: Some(c[2].to_string()),
            ligne: Some(c[3].to_string()),
            sans_fichier: false,
            ne: None,
        })
        .collect();
    juger_programmes(&liste, Os::Linux, &HashSet::new(), None)
}

/// LNX-PRV-004 (le propriétaire compte) et MAC-PRV-004 (il ne compte pas) : `chemin|mode en octal|uid|root` (« oui » :
/// root y cherche ses commandes).
#[cfg(unix)]
fn dossiers_de_commandes(e: &Entree, proprietaire: bool) -> Vec<Constat> {
    let dossiers: Vec<super::unix::DossierDeCommandes> = e
        .champs()
        .iter()
        .map(|c| super::unix::DossierDeCommandes {
            chemin: c[0].to_string(),
            mode: u32::from_str_radix(c[1], 8).unwrap(),
            proprietaire: c[2].parse().unwrap(),
            de_root: c[3] == "oui",
        })
        .collect();
    super::unix::juger_dossiers_de_commandes(&dossiers, proprietaire)
        .into_iter()
        .collect()
}

#[cfg(unix)]
fn dossiers_de_root(e: &Entree) -> Vec<Constat> {
    dossiers_de_commandes(e, true)
}

#[cfg(unix)]
fn dossiers_du_mac(e: &Entree) -> Vec<Constat> {
    dossiers_de_commandes(e, false)
}
