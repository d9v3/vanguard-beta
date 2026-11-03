//! `vanguard blocage juger` : ce que le blocage refuserait, et pourquoi, sans rien faire. Chaque garde dit son mot
//! (programmes du système et Vanguard, session à distance par l'ascendance, signature, chemin court 8.3, destination
//! de la quarantaine), puis le verdict du geste tel que « Bloquer » le préparerait. Rien n'est arrêté, rien n'est
//! déplacé, aucune règle n'est posée : le geste préparé n'est jamais fait (défense D6a, essais de la VM).

use std::collections::HashSet;
use std::path::Path;

use super::gardes;
use super::gestes::{self, Contexte};
use super::menaces::{Geste, Menace};
use super::parametres::Categorie;
use crate::machine::regles::Os;
use crate::modele::Echec;
use crate::ui::*;

/// `quoi` : un PID, « parent » (le programme qui a lancé Vanguard : un cmd ouvert dans une session SSH), ou le
/// chemin d'un fichier. `destination` : un dossier jugé comme destination de la quarantaine en administrateur.
pub(super) fn commande(quoi: &str, destination: bool) {
    titre(tr!(
        "Ce que le blocage refuserait (rien n'est fait)",
        "What blocking would refuse (nothing is done)"
    ));
    if destination {
        juger_destination(Path::new(quoi));
        return;
    }
    let pid = if super::est(quoi, &["parent"]) {
        let Some(pid) = parent_de_vanguard() else {
            trp!(
                "  Le programme qui a lancé Vanguard ne se lit pas.",
                "  The program that started Vanguard cannot be read."
            );
            return;
        };
        Some(pid)
    } else {
        quoi.trim().parse::<u32>().ok()
    };
    let ctx = contexte();
    match pid {
        Some(pid) => juger_processus(pid, &ctx),
        None => juger_fichier(Path::new(quoi), &ctx),
    }
}

/// Le contexte d'un vrai passage, sans le pare-feu : juger un programme ou un fichier ne le lit pas, et rien ici ne
/// doit lancer d'outil du pare-feu.
fn contexte() -> Contexte {
    let intouchables = crate::machine::chasse::en_marche().map_or_else(HashSet::new, |(_, i)| i);
    Contexte {
        os: Os::actuel(),
        intouchables,
        sessions: gardes::sessions_a_distance(),
        pare_feu: Err(Echec::refuse(
            // Jamais journalisé (le pare-feu ne sert pas à juger) : le contexte du geste préparé.
            "blocage/preparer",
            tr!("pare-feu non lu ici", "firewall not read here"),
        )),
        admin: gestes::administrateur_ou_inconnu(),
        interactif: false,
        mon_programme: std::env::current_exe().ok().map(|c| c.to_string_lossy().into_owned()),
    }
}

fn parent_de_vanguard() -> Option<u32> {
    #[cfg(unix)]
    {
        // Rattaché à init : celui qui l'a lancé est déjà fini.
        Some(std::os::unix::process::parent_id()).filter(|&p| p > 1)
    }
    #[cfg(windows)]
    {
        let moi = std::process::id();
        crate::machine::windows::processus::liste()
            .into_iter()
            .find(|p| p.pid == moi)
            .map(|p| p.parent)
    }
}

/// Une ligne : la garde, puis son mot (« refuse : … » ou « ne refuse pas »).
fn ligne(garde: &str, raison: Option<&str>) {
    match raison {
        Some(r) => afficher_aligne(
            &format!("  {}✗{RESET} ", couleur(crate::risk::Niveau::Moyen)),
            &trf!("{garde} : refuse — {r}", "{garde}: refuses — {r}"),
            4,
            "",
        ),
        None => afficher_aligne(
            &format!("  {GRIS}·{RESET} "),
            &trf!("{garde} : ne refuse pas", "{garde}: does not refuse"),
            4,
            GRIS,
        ),
    }
}

/// La garde de signature : Microsoft lisible refuse ; illisible ne refuse plus d'office (choix 3.1) mais demandera
/// confirmation à la personne, avec pourquoi elle ne se lit pas.
fn ligne_signature(chemin: &str) {
    let garde = tr!("Signature", "Signature");
    match gardes::signature_lue(chemin) {
        gardes::Signature::Illisible(r) => afficher_aligne(
            &format!("  {}?{RESET} ", couleur(crate::risk::Niveau::Moyen)),
            &trf!(
                "{garde} : signature illisible : demandera confirmation — {}",
                "{garde}: unreadable signature: will ask for confirmation — {}",
                r.texte()
            ),
            4,
            "",
        ),
        s => ligne(garde, gardes::signature_intouchable(s).as_deref()),
    }
}

/// Le chemin long, quand Windows en donne un autre que celui écrit (nom court 8.3).
fn dire_chemin_long(chemin: &str) {
    #[cfg(windows)]
    match crate::machine::windows::environnement::chemin_long(chemin) {
        Some(long) if !long.eq_ignore_ascii_case(chemin) => {
            trp!("  Chemin long : {long}", "  Long path: {long}");
        }
        Some(_) => {}
        None => trp!(
            "  Chemin long : illisible (absent, ou refusé par Windows)",
            "  Long path: unreadable (missing, or refused by Windows)"
        ),
    }
    #[cfg(not(windows))]
    let _ = chemin;
}

fn verdict(m: &Menace, ctx: &Contexte) {
    match gestes::preparer(m, ctx, false) {
        Err(e) => afficher_aligne(
            &format!("  {}✗{RESET} ", couleur(crate::risk::Niveau::Moyen)),
            &trf!("Verdict : refusé — {e}", "Verdict: refused — {e}"),
            4,
            "",
        ),
        Ok(pret) => {
            trp!(
                "  Verdict : « Bloquer » proposerait (rien n'est fait ici) :",
                "  Verdict: “Block” would offer (nothing is done here):"
            );
            for e in pret.etapes {
                afficher_aligne("    - ", &e, 6, "");
            }
        }
    }
}

fn juger_processus(pid: u32, ctx: &Contexte) {
    let chemin = gestes::chemin_du_processus(pid);
    let nom = chemin
        .as_deref()
        .and_then(|c| Path::new(c).file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match chemin.as_deref() {
        Some(c) => {
            trp!("  Processus {pid} : {c}", "  Process {pid}: {c}");
            dire_chemin_long(c);
        }
        None => trp!(
            "  Processus {pid} : programme illisible (fini, ou d'un autre compte)",
            "  Process {pid}: program unreadable (ended, or another account's)"
        ),
    }
    ligne(
        tr!(
            "Programmes du système, Vanguard (chemin court compris)",
            "System programs, Vanguard (short path included)"
        ),
        gardes::processus_intouchable(pid, &nom, chemin.as_deref(), &ctx.intouchables, ctx.os),
    );
    ligne(
        tr!("Session à distance (ascendance)", "Remote session (ancestry)"),
        gardes::lignee_de_session(pid, ctx.sessions.as_ref()),
    );
    if let Some(c) = chemin.as_deref() {
        ligne_signature(c);
    }
    let menace = Menace {
        categorie: Categorie::Programmes,
        certaine: false,
        quoi: nom.clone(),
        cle: format!("juger:{pid}"),
        geste: Geste::Programme {
            pid: Some(pid),
            nom,
            chemin: chemin.map(Into::into),
            fichier: None,
            detection: tr!("essai : juger", "test: judge").to_string(),
        },
    };
    verdict(&menace, ctx);
}

fn juger_fichier(chemin: &Path, ctx: &Contexte) {
    let texte = chemin.to_string_lossy();
    trp!("  Fichier : {texte}", "  File: {texte}");
    if !chemin.is_file() {
        trp!(
            "  Ce n'est pas un fichier qui existe : rien à juger.",
            "  This is not an existing file: nothing to judge."
        );
        return;
    }
    dire_chemin_long(&texte);
    ligne(
        tr!(
            "Fichiers du système, Vanguard (chemin court compris)",
            "System files, Vanguard (short path included)"
        ),
        gardes::fichier_intouchable(&texte, ctx.os, ctx.mon_programme.as_deref()),
    );
    ligne_signature(&texte);
    #[cfg(windows)]
    juger_destination(&crate::protection::quarantaine::dossier());
    let menace = Menace {
        categorie: Categorie::Programmes,
        certaine: false,
        quoi: texte.to_string(),
        cle: format!("juger:{texte}"),
        geste: Geste::Programme {
            pid: None,
            nom: String::new(),
            chemin: None,
            fichier: Some(chemin.to_path_buf()),
            detection: tr!("essai : juger", "test: judge").to_string(),
        },
    };
    verdict(&menace, ctx);
}

/// La destination de la quarantaine telle que Vanguard administrateur la jugerait (Windows).
fn juger_destination(dossier: &Path) {
    trp!(
        "  Destination de la quarantaine : {}",
        "  Quarantine destination: {}",
        dossier.display()
    );
    #[cfg(windows)]
    {
        let raison = match crate::machine::windows::environnement::profil() {
            Some(profil) => gardes::destination_de_quarantaine(
                dossier,
                &profil,
                |d| std::fs::symlink_metadata(d).map(|m| crate::machine::vidage::est_lien(&m)),
                true,
            ),
            None => Some(tr!("profil du compte illisible", "account profile unreadable")),
        };
        ligne(
            tr!(
                "Quarantaine en administrateur (liens, jonctions)",
                "Quarantine as administrator (links, junctions)"
            ),
            raison,
        );
    }
    #[cfg(not(windows))]
    trp!(
        "  Cette garde ne sert que sous Windows (Vanguard administrateur).",
        "  This guard only applies on Windows (Vanguard as administrator)."
    );
}

#[cfg(test)]
mod essais {
    #[test]
    fn juger_ne_fait_rien() {
        let dossier = crate::essais::Jetable::nouveau("juger");
        let fichier = dossier.join("menace.exe");
        std::fs::write(&fichier, b"MZ essai").expect("fichier d'essai");
        super::commande(&fichier.to_string_lossy(), false);
        super::commande(&dossier.to_string_lossy(), true);
        // Un processus jugé n'est pas arrêté : ce fil le dit de lui-même, toujours là.
        super::commande(&std::process::id().to_string(), false);
        assert_eq!(std::fs::read(&fichier).expect("toujours là"), b"MZ essai");
        assert!(!crate::protection::quarantaine::dossier().join("menace.exe").exists());
    }
}
