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
    ("LNX-PRS-001", fichiers_suspects),
    ("LNX-PRS-002", persistance),
    ("LNX-CPT-001", comptes),
    ("LNX-SSH-002", echecs_ssh),
    ("LNX-PRV-003", sudo),
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

/// LNX-PRS-001 : `anormal|chemin` (privilégié hors paquet ou dans un dossier temporaire), `modifie|chemin|paquet`,
/// `systeme|nombre` (programmes privilégiés du système), `path|dossier` (ouvert à d'autres), `non_verifies|nombre`,
/// `gestion|absent` (gestionnaire de paquets non reconnu) et `getcap|absent`. Les parcours, getcap et la
/// vérification des paquets restent hors du corpus : ils lisent le vrai système.
fn fichiers_suspects(e: &Entree) -> Vec<Constat> {
    let releve = super::persistance::Releve {
        modifies: e
            .de("modifie")
            .iter()
            .map(|c| (c[0].to_string(), c[1].to_string()))
            .collect(),
        anormaux: e.de("anormal").iter().map(|c| std::path::PathBuf::from(c[0])).collect(),
        systeme: e.de("systeme").first().map_or(0, |c| c[0].parse().unwrap()),
        gestion: !e.de("gestion").iter().any(|c| c[0] == "absent"),
        non_verifies: e.de("non_verifies").first().map_or(0, |c| c[0].parse().unwrap()),
        capacites_lues: !e.de("getcap").iter().any(|c| c[0] == "absent"),
        path_dangereux: e.de("path").iter().map(|c| c[0].to_string()).collect(),
        reinstaller: "sudo pacman -S --noconfirm corpus".into(),
    };
    super::persistance::juger_fichiers_suspects(&releve)
}

/// LNX-PRS-002 : `fichier|chemin sous la racine|contenu` (« \n » pour un saut de ligne), posés dans une racine
/// jetable que la persistance lit comme « / » ; le dossier personnel y est home/alice. Ni variable de session, ni
/// crontab, ni gestionnaire de paquets : la branche « bibliothèque d'un paquet » et les services ajoutés hors paquet
/// demanderaient un gestionnaire fabriqué, qui n'existe pas encore (hors corpus).
fn persistance(e: &Entree) -> Vec<Constat> {
    let racine = e.jetable("racine");
    for c in e.de("fichier") {
        let chemin = racine.join(c[0]);
        std::fs::create_dir_all(chemin.parent().unwrap()).unwrap();
        std::fs::write(&chemin, c[1].replace("\\n", "\n")).unwrap();
    }
    let maison = racine.join("home/alice");
    std::fs::create_dir_all(&maison).unwrap();
    // Sans gestionnaire de paquets (`None`) : les services ajoutés hors paquet et la bibliothèque préchargée connue
    // d'un paquet ne sont pas exercés ici : `Paquets` lance pacman ou dpkg, sans imitation possible (reste déclaré).
    super::persistance::persistance_dans(&racine, &maison, |_| None, None, None)
}

/// LNX-CPT-001 : le texte de /etc/passwd.
fn comptes(e: &Entree) -> Vec<Constat> {
    vec![super::juger_comptes(&e.texte)]
}

/// LNX-SSH-002 : des lignes du journal de sshd des dernières 24 h, et `mots_de_passe|non` quand sshd n'accepte que
/// les clés (sans elle, permis : la valeur d'origine de sshd) ; aucun service qui bloque. La lecture de sshd_config
/// et la recherche du service qui bloque restent hors du corpus.
fn echecs_ssh(e: &Entree) -> Vec<Constat> {
    let mots_de_passe = !e.de("mots_de_passe").iter().any(|c| c[0] == "non");
    let journal: Vec<&str> = e
        .lignes()
        .into_iter()
        .filter(|l| !l.starts_with("mots_de_passe|"))
        .collect();
    super::juger_echecs_ssh(&journal.join("\n"), mots_de_passe, || None)
        .into_iter()
        .collect()
}

/// LNX-PRV-003 : la sortie de « sudo -n -l ».
fn sudo(e: &Entree) -> Vec<Constat> {
    crate::machine::unix::juger_sudo(&e.texte, super::privileges::tout_permis())
}
