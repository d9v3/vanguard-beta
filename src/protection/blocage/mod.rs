//! Blocage des menaces. Chaque menace trouvée propose « Bloquer » : le geste est montré, accepté, fait, noté dans « Ce
//! que Vanguard a changé » et toujours annulable (`vanguard blocage annuler`). La protection active, activée une
//! fois avec accord, bloque toute seule ce qui est certain (un fichier dont l'empreinte est dans MalwareBazaar, un
//! outil d'attaque connu en marche, une connexion vers un serveur de commande connu), puis prévient ; le douteux reste
//! une alerte avec son bouton. Elle tourne au bilan et dans la surveillance horaire, jamais dans un service à part ;
//! la protection en temps réel coupée (`protection::temps_reel`), elle ne bloque plus rien toute seule, sans que ses
//! réglages changent, et ce qu'elle a déjà bloqué reste bloqué.
//!
//! Quatre catégories, chacune désactivée, en un clic (par défaut) ou automatique (le certain seulement) : programmes
//! malveillants, connexions dangereuses, démarrage et pilotes, agents et serveurs d'IA (`parametres`). Les
//! garde-fous (`gardes`) passent avant tout : jamais Vanguard ni ce qui le fait tourner, jamais un processus critique
//! ou un programme du système, jamais une connexion à distance en cours ; sans les droits, rien n'est fait à moitié.
//!
//! Chaque type d'alerte a sa suite de gestes (`suites`, enchaînée par `enchainer`) : suspendre, couper les
//! connexions, relever la preuve, bloquer, surveiller, prévenir, dans l'ordre choisi (menu Blocage). Le certain la
//! fait tout seul, le douteux la propose d'une touche ; chaque geste repasse ses garde-fous, est noté et s'annule à
//! part.

// Le programme sous Linux : ses parties Windows ne sont pas encore relues, et les essais en sont exemptés
// (y déborder fait échouer l'essai). L'en-tête vaut aussi pour les sous-modules.
#![cfg_attr(
    all(target_os = "linux", not(test)),
    warn(clippy::arithmetic_side_effects, clippy::as_conversions)
)]

mod arret;
pub(crate) mod gardes;
pub(crate) mod gestes;
mod juger;
mod menaces;
pub(crate) mod ordres;
// La forme des lignes des ordres : du code pur, lu aussi par le banc de fuzzing.
pub(crate) mod choix;
// Couper le réseau d'un programme sans l'arrêter (R3).
pub(crate) mod coupure;
mod ordres_ligne;
pub(crate) mod parametres;
pub(crate) mod pare_feu;
pub(crate) mod surveiller;
pub(crate) mod suspension;
// Les suites préréglées : du code pur.
mod enchainer;
pub(crate) mod suites;

use std::collections::{BTreeSet, HashSet};
use std::io::IsTerminal;

use gestes::Contexte;
pub(crate) use gestes::chemin_du_processus;
// Le bilan de Windows ne propose pas de fermer ce que le processus élevé refuserait (SSH, Bureau à distance, le port
// d'une session en cours).
#[cfg(windows)]
pub(crate) use gardes::{port_a_garder, port_intouchable, sessions_a_distance};
// L'assistant élevé de Linux ne redémarre pas le réseau pendant une session à distance entrante.
#[cfg(target_os = "linux")]
pub(crate) use gardes::session_entrante_ouverte;
use menaces::Menace;
use parametres::{Categorie, Decision, Mode, Parametres, decider};

use crate::changements::Annulation;
use crate::reseau::tableau::Genre;
use crate::selection::{Ligne, choisir};
use crate::ui::*;

/// Les réglages ; illisibles, ceux par défaut (un clic, rien d'automatique), et c'est dit.
fn parametres() -> Parametres {
    if let Some(raison) = parametres::ignores() {
        afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
            &trf!(
                "blocage.json {raison} : les catégories qu'il désactivait restent sur « un clic », son accord à la protection active ne fait rien bloquer sans clic, et ses suites de gestes ne comptent pas (celles par défaut s'appliquent). Réglez-les de nouveau ici si c'est bien votre choix.",
                "blocage.json {raison}: the categories it turned off stay on “one click”, its consent to active protection blocks nothing without a click, and its action suites do not count (the default ones apply). Set them again here if that really is your choice."
            ),
            4,
            "",
        );
    }
    parametres::charger().unwrap_or_else(|e| {
        trp!(
            "  {}⚠{RESET} Réglages du blocage illisibles ({e}) : un clic partout, rien d'automatique.",
            "  {}⚠{RESET} Blocking settings unreadable ({e}): one click everywhere, nothing automatic.",
            couleur(crate::risk::Niveau::Moyen)
        );
        Parametres::default()
    })
}

/// Les réglages, sans redire ce que `parametres` a déjà dit (fichier non cru ou illisible) : pour les tours d'un
/// même éditeur, entré par `parametres`.
fn parametres_tus() -> Parametres {
    parametres::charger().unwrap_or_default()
}

/// Enregistre les réglages. Un fichier illisible n'est pas écrasé en silence : il est d'abord mis de côté, intact.
fn enregistrer(p: &Parametres) -> bool {
    if parametres::charger().is_err() {
        let f = crate::socle::dossier_local().join(parametres::BLOCAGE);
        let copie = f.with_extension(format!(
            "illisible-{}.json",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        ));
        // Seulement un simple fichier, borné : un tube ou un lien vers /dev/zero à sa place ne se recopie pas.
        if crate::socle::ecriture_sure(&crate::socle::dossier_local())
            && crate::socle::lire_ordinaire(&f, 1 << 20).is_ok_and(|o| crate::socle::ecrire_atomique(&copie, o).is_ok())
        {
            trp!(
                "  {GRIS}Ancien fichier illisible gardé : {}{RESET}",
                "  {GRIS}Unreadable old file kept: {}{RESET}",
                chemin_affichable(&copie)
            );
        }
    }
    match parametres::enregistrer(p) {
        Ok(()) => true,
        Err(e) => {
            trp!(
                "  ✖ Réglages du blocage non enregistrés ({e}).",
                "  ✖ Blocking settings not saved ({e})."
            );
            false
        }
    }
}

/// Les réglages qui décident de ce qui se bloque tout seul. En administrateur, l'accord de blocage.json ne compte
/// pas : tout processus du compte peut écrire ce fichier (sous Windows, une fenêtre « en tant qu'administrateur »
/// garde le même %LOCALAPPDATA%), et il ne doit pas faire agir Vanguard avec tous les droits sans une question. Le
/// certain s'y propose alors d'un clic, comme le reste ; les extensions font de même (en administrateur, leurs
/// réglages ne lèvent rien). La protection en temps réel coupée fait de même, le temps de la coupure : blocage.json
/// n'est pas touché, et l'accord revient tel quel à la reprise.
fn pour_agir(mut p: Parametres, rien_tout_seul: bool) -> Parametres {
    if rien_tout_seul {
        p.accord = None;
    }
    p
}

/// Vanguard tourne-t-il en administrateur, ou ne peut-il pas le savoir ? Le garde-fou de la protection active, que le
/// réglage de la protection en temps réel suit aussi.
pub(crate) fn administrateur_ou_inconnu() -> bool {
    gestes::administrateur_ou_inconnu()
}

/// Une session à distance (SSH, Bureau à distance) est-elle en cours ? `None` : les connexions ne se lisent pas.
#[cfg(windows)]
pub(crate) fn session_a_distance() -> Option<bool> {
    gardes::sessions_a_distance().map(|s| !s.sessions.is_empty())
}

/// La protection active est-elle réglée (accord donné, une catégorie automatique) ? Ce que la coupure du temps réel
/// arrêterait.
pub(crate) fn protection_active() -> bool {
    parametres::charger().is_ok_and(|p| p.actif())
}

/// Le garde-fou du gel, exposé au veilleur anti-rançongiciel (Linux) : `None` si le processus peut être gelé.
#[cfg(target_os = "linux")]
pub(crate) use gardes::processus_gelable;

/// La confiance accordée à un fichier certain (P5), lue par le veilleur avant d'arrêter un certain.
#[cfg(target_os = "linux")]
pub(crate) use choix::confiance_accordee;

/// Lot D7b : l'arrêt d'un programme que la personne a accepté, sur le terminal de l'assistant élevé. Les gardes des
/// sessions à distance et de la signature passent encore juste avant le signal ; `attendu` : son programme, sans
/// « (deleted) ».
#[cfg(target_os = "linux")]
pub(crate) fn arreter_confirme(pid: u32, attendu: &str) -> Result<(), crate::modele::Echec> {
    arret::arreter(pid, attendu, &arret::Confirmation::Jamais).map(|_| ())
}

/// L'arrêt automatique d'un programme est-il permis en ce moment ? La catégorie Programmes réglée en automatique avec
/// l'accord (menace certaine), Vanguard non administrateur, protection en temps réel non coupée (plan §2.5).
#[cfg(target_os = "linux")]
pub(crate) fn arret_automatique_programmes_permis() -> bool {
    if gestes::administrateur_ou_inconnu() || crate::protection::temps_reel::coupure().is_some() {
        return false;
    }
    let Ok(p) = parametres::charger() else {
        return false;
    };
    decider(&p, Categorie::Programmes, true) == Decision::Auto
}

/// Arrête puis met en quarantaine un programme, tout seul (protection active), avec TOUS les garde-fous du blocage
/// (processus critique, Vanguard, session à distance, programme du système, interpréteur jamais mis en quarantaine) ;
/// la preuve est relevée avant le geste, reliée à l'alerte par `cle`. Utilisé par le veilleur anti-rançongiciel après
/// avoir gelé la lignée, avec les intouchables du blocage (`chasse::en_marche`). `Err` dit pourquoi rien n'a été
/// fait : le programme reste alors gelé.
#[cfg(target_os = "linux")]
pub(crate) fn arreter_programme_automatique(
    intouchables: &std::collections::HashSet<u32>,
    pid: u32,
    nom: &str,
    chemin: Option<std::path::PathBuf>,
    fichier: Option<std::path::PathBuf>,
    detection: &str,
    cle: &str,
) -> Result<String, crate::modele::Echec> {
    let menace = Menace {
        categorie: Categorie::Programmes,
        certaine: false,
        quoi: detection.to_string(),
        cle: cle.to_string(),
        geste: menaces::Geste::Programme {
            pid: Some(pid),
            nom: nom.to_string(),
            chemin,
            fichier,
            detection: detection.to_string(),
        },
    };
    let ctx = Contexte::lire(intouchables.clone(), false);
    let pret = gestes::preparer(&menace, &ctx, true)?;
    gestes::faire(&menace, pret, true).map(|f| f.quoi)
}

/// Ce que la protection active devient en administrateur, dit là où elle tournerait.
fn dire_administrateur() {
    afficher_aligne(
        &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Moyen)),
        tr!(
            "Vanguard est en administrateur : la protection active ne bloque rien toute seule (ses réglages peuvent être écrits par n'importe quel programme de ce compte). Le certain se propose d'un clic, comme le reste.",
            "Vanguard is running as administrator: active protection blocks nothing by itself (its settings can be written by any program of this account). What is certain is offered with one click, like the rest."
        ),
        4,
        "",
    );
}

/// L'état, court, pour la ligne du menu.
pub fn etat_court() -> &'static str {
    etat_court_de(
        parametres::charger(),
        crate::protection::temps_reel::coupure().is_some(),
    )
}

/// L'état court de `lu` ; `coupee` : la protection en temps réel est coupée, et la protection active ne bloque donc
/// rien toute seule.
fn etat_court_de(lu: Result<Parametres, crate::modele::Echec>, coupee: bool) -> &'static str {
    match lu {
        Ok(p) if p.actif() && coupee => tr!("en pause (temps réel coupé)", "paused (real-time off)"),
        Ok(p) if p.actif() => tr!("protection active", "active protection"),
        Ok(p) if p.rien() => tr!("désactivé", "off"),
        Ok(_) => tr!("un clic, avec votre accord", "one click, with your consent"),
        Err(_) => tr!("réglages illisibles", "settings unreadable"),
    }
}

fn est(mot: &str, mots: &[&str]) -> bool {
    mots.contains(&mot.trim().to_lowercase().as_str())
}

/// `vanguard blocage` : le menu ; « chercher », « annuler », « etat » ; « auto » ou « clic » pour la protection
/// active ; une catégorie suivie d'un mode (« connexions auto ») ; « juger » un PID, « parent » ou un fichier, en
/// lecture seulement.
pub fn commande(mots: &[String]) {
    let mots: Vec<&str> = mots.iter().map(String::as_str).collect();
    match mots.as_slice() {
        [] => menu(),
        [m] if est(m, &["chercher", "scan", "search", "maintenant", "now"]) => chercher_et_proposer(),
        [m] if est(m, &["annuler", "undo", "defaire", "défaire"]) => annuler(),
        [m] if est(m, &["etat", "état", "status", "state"]) => afficher_etat(&parametres()),
        // En lecture seulement : ce que chaque garde refuserait, et pourquoi (essais de la VM, défense D6a).
        [m, d, dossier] if est(m, &["juger", "judge"]) && est(d, &["destination"]) => juger::commande(dossier, true),
        [m, quoi] if est(m, &["juger", "judge"]) => juger::commande(quoi, false),
        [m, pid] if est(m, &["suspendre", "suspend"]) => suspendre_par_pid(pid),
        [m] if est(m, &["reprendre", "resume"]) => reprendre_les_suspendus(None),
        [m, pid] if est(m, &["reprendre", "resume"]) => match pid.parse::<u32>() {
            Ok(p) if p > 0 => reprendre_les_suspendus(Some(p)),
            _ => usage(),
        },
        [m, pid] if est(m, &["couper-reseau", "cut-network"]) => couper_le_reseau_par_pid(pid),
        [m] if est(m, &["rendre-reseau", "restore-network"]) => rendre_le_reseau(None),
        [m, pid] if est(m, &["rendre-reseau", "restore-network"]) => match pid.parse::<u32>() {
            Ok(p) if p > 0 => rendre_le_reseau(Some(p)),
            _ => usage(),
        },
        [m] if est(m, &["isoler", "isolate"]) => crate::protection::isolement::isoler_avec_accord(),
        [m] if est(m, &["lever-isolement", "lift-isolation"]) => {
            crate::protection::isolement::lever_avec_accord();
        }
        [m] if est(m, &["auto", "actif", "active", "on"]) => {
            for c in Categorie::TOUTES.into_iter().filter(|c| c.a_du_certain()) {
                if !changer_mode(c, Mode::Automatique) {
                    break;
                }
            }
        }
        [m] if est(m, &["clic", "click", "manuel", "manual"]) => {
            for c in Categorie::TOUTES.into_iter().filter(|c| c.a_du_certain()) {
                changer_mode(c, Mode::UnClic);
            }
        }
        [c, m] => match (Categorie::depuis_mot(c), Mode::depuis_mot(m)) {
            (Some(c), Some(m)) => {
                changer_mode(c, m);
            }
            _ => usage(),
        },
        _ => usage(),
    }
}

fn usage() {
    let categories = Categorie::TOUTES.map(Categorie::mot).join(", ");
    trp!(
        "  Usage : vanguard blocage [chercher | annuler | etat | auto | clic | <catégorie> <mode> | juger <PID | parent | fichier> | juger destination <dossier> | suspendre <PID> | reprendre [<PID>] | couper-reseau <PID> | rendre-reseau [<PID>] | isoler | lever-isolement]\n  Catégories : {categories}. Modes : off, clic, auto (programmes et connexions seulement). « juger » montre ce que le blocage refuserait, et pourquoi, sans rien faire. « suspendre » gèle un processus (réversible ; pas les programmes qu'il a déjà lancés) ; « reprendre » le relance (sans PID : tous ceux que Vanguard a suspendus). « couper-reseau » coupe le réseau d'un processus sans l'arrêter (réversible ; sous Windows, tous les processus de ce fichier) ; « rendre-reseau » le lui rend (sans PID : à tous ceux que Vanguard a coupés). « isoler » coupe l'ordinateur du réseau, sauf la session à distance en cours, le DNS et les serveurs de Vanguard (mot de passe demandé) ; « lever-isolement » le lève (aussi par « annuler »).",
        "  Usage: vanguard blocking [search | undo | status | auto | click | <category> <mode> | judge <PID | parent | file> | judge destination <folder> | suspend <PID> | resume [<PID>] | cut-network <PID> | restore-network [<PID>] | isolate | lift-isolation]\n  Categories: {categories}. Modes: off, click, auto (programs and connections only). “judge” shows what blocking would refuse, and why, without doing anything. “suspend” freezes a process (reversible; not the programs it already started); “resume” starts it again (without a PID: all those Vanguard suspended). “cut-network” cuts a process's network without stopping it (reversible; on Windows, all processes of that file); “restore-network” gives it back (without a PID: to all those Vanguard cut). “isolate” cuts the computer off the network, except the remote session in progress, DNS and Vanguard's servers (password asked); “lift-isolation” lifts it (also through “undo”)."
    );
}

/// `vanguard blocage suspendre <PID>` : le programme du processus lu, les gardes du gel rejugées, montré, confirmé.
fn suspendre_par_pid(mot: &str) {
    let Some(pid) = mot.parse::<u32>().ok().filter(|p| *p > 0) else {
        usage();
        return;
    };
    let Some(chemin) = chemin_du_processus(pid) else {
        trp!(
            "  ✖ Le processus {pid} est fini, ou son programme ne se lit pas : rien n'est suspendu.",
            "  ✖ Process {pid} has ended, or its program cannot be read: nothing is suspended."
        );
        return;
    };
    let o = ordres::Ordre::SuspendreProcessus {
        pid,
        chemin: chemin.clone(),
        depart: None,
    };
    let intouchables = crate::machine::chasse::en_marche().map_or_else(HashSet::new, |(_, i)| i);
    if let Some(raison) = ordres::juger(&o, &ordres::Juge::lire(None).avec(&intouchables)) {
        afficher_aligne(
            "  ✖ ",
            &trf!("Rien n'est suspendu : {raison}.", "Nothing is suspended: {raison}."),
            4,
            "",
        );
        return;
    }
    if !confirmer_la_suspension(pid, &chemin, &chemin) {
        return;
    }
    let quoi = trf!("Suspendu à la main : {}", "Suspended by hand: {}", chemin);
    let intouchables = crate::machine::chasse::en_marche().map_or_else(HashSet::new, |(_, i)| i);
    match suspension::suspendre(
        pid,
        &chemin,
        &quoi,
        None,
        &intouchables,
        crate::modele::evenement::Source::Utilisateur,
    ) {
        Ok(()) => trp!("  {VERT}✔{RESET} Suspendu.", "  {VERT}✔{RESET} Suspended."),
        Err(e) => trp!("  ✖ {e}", "  ✖ {e}"),
    }
}

/// `vanguard blocage couper-reseau <PID>` : le programme du processus lu, les gardes de la coupure rejugées, montré,
/// confirmé ; puis l'ordre confié à l'élevé, qui relit et rejuge le processus.
fn couper_le_reseau_par_pid(mot: &str) {
    let Some(pid) = mot.parse::<u32>().ok().filter(|p| *p > 0) else {
        usage();
        return;
    };
    let (Some(chemin), Some(depart)) = (chemin_du_processus(pid), suspension::depart_de(pid)) else {
        trp!(
            "  ✖ Le processus {pid} est fini, ou son programme ne se lit pas : rien n'est coupé.",
            "  ✖ Process {pid} has ended, or its program cannot be read: nothing is cut."
        );
        return;
    };
    let o = ordres::Ordre::CouperReseauProgramme {
        pid,
        chemin: chemin.clone(),
        depart,
    };
    // Lus une fois : le jugement d'ici et celui de `coupure::couper` sur les mêmes processus protégés.
    let intouchables = crate::machine::chasse::en_marche().map_or_else(HashSet::new, |(_, i)| i);
    if let Some(raison) = ordres::juger(&o, &ordres::Juge::lire(None).avec(&intouchables)) {
        afficher_aligne(
            "  ✖ ",
            &trf!("Rien n'est coupé : {raison}.", "Nothing is cut: {raison}."),
            4,
            "",
        );
        return;
    }
    if !confirmer_la_coupure(pid, &chemin, &chemin) {
        return;
    }
    let quoi = trf!(
        "Coupé du réseau à la main : {}",
        "Cut from the network by hand: {}",
        chemin
    );
    match coupure::couper(
        pid,
        &chemin,
        &quoi,
        None,
        &intouchables,
        crate::modele::evenement::Source::Utilisateur,
    ) {
        Ok(c) => dire_coupe(pid, &c),
        Err(e) => trp!("  ✖ {e}", "  ✖ {e}"),
    }
}

/// La coupure faite : ce que l'élevé en a dit (connexions coupées, combien de temps), et comment la lever. Partielle
/// (les connexions déjà ouvertes non coupées) : jamais un « ✔ » ; Bloquer, qui arrête le programme, les ferme.
fn dire_coupe(pid: u32, c: &coupure::Coupee) {
    if c.partielle {
        afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
            &trf!(
                "Réseau coupé en partie ({}). Ce qu'il a déjà ouvert continue : Bloquer (« vanguard blocage chercher », ou le menu de la menace) l'arrête et ferme tout. Pour lui rendre le réseau : vanguard blocage rendre-reseau {pid}.",
                "Network partly cut ({}). What it already opened goes on: Block (“vanguard blocking search”, or the threat's menu) stops it and closes everything. To give the network back: vanguard blocking restore-network {pid}.",
                c.precision
            ),
            4,
            "",
        );
        return;
    }
    let precision = if c.precision.is_empty() {
        String::new()
    } else {
        format!(" ({})", c.precision)
    };
    afficher_aligne(
        &format!("  {VERT}✔{RESET} "),
        &trf!(
            "Réseau coupé{precision}. Pour le lui rendre : vanguard blocage rendre-reseau {pid}.",
            "Network cut{precision}. To give it back: vanguard blocking restore-network {pid}."
        ),
        4,
        "",
    );
}

/// Ce que couper le réseau fait et ne fait pas (selon le système), le rôle d'un programme du système nommé, puis la
/// question : `true` si la personne confirme.
fn confirmer_la_coupure(pid: u32, nom: &str, chemin: &str) -> bool {
    let nom = affichable(nom);
    let texte = if cfg!(windows) {
        trf!(
            "Couper le réseau de « {nom} » (PID {pid}) : il tourne toujours mais ne parle plus à personne, le temps de regarder. Deux règles du Pare-feu Windows visent son FICHIER : TOUS les processus de ce fichier sont coupés, pas seulement ce PID. Les connexions déjà ouvertes ne sont pas coupées par une règle. Les règles restent après un redémarrage ; « vanguard blocage rendre-reseau {pid} » les retire. Il faut les droits d'administrateur.",
            "Cut the network of “{nom}” (PID {pid}): it keeps running but talks to no one, while you look. Two Windows Firewall rules target its FILE: ALL processes of that file are cut, not only this PID. Connections already open are not cut by a rule. The rules stay after a restart; “vanguard blocking restore-network {pid}” removes them. Administrator rights are needed."
        )
    } else {
        trf!(
            "Couper le réseau de « {nom} » (PID {pid}) : il tourne toujours mais ne parle plus à personne, ni vers l'extérieur ni de l'extérieur, le temps de regarder ; ses connexions déjà ouvertes sont coupées aussi. Seul ce processus est coupé : les programmes qu'il a déjà lancés gardent leur réseau. Jusqu'au redémarrage ; « vanguard blocage rendre-reseau {pid} » le lui rend. Il faut les droits d'administrateur.",
            "Cut the network of “{nom}” (PID {pid}): it keeps running but talks to no one, neither out nor in, while you look; its connections already open are cut too. Only this process is cut: the programs it already started keep their network. Until restart; “vanguard blocking restore-network {pid}” gives it back. Administrator rights are needed."
        )
    };
    afficher_aligne("  ", &texte, 2, "");
    let Some(role) = coupure::role(pid, chemin) else {
        return demander(tr!("\n  Couper son réseau ? [o/N] : ", "\n  Cut its network? [y/N]: ")).oui();
    };
    afficher_aligne(
        &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
        &trf!(
            "C'est {role} : tant que son réseau est coupé, ce qu'il fait en ligne pour l'ordinateur s'arrête aussi.",
            "This is {role}: while its network is cut, what it does online for the computer stops too."
        ),
        4,
        "",
    );
    demander(&trf!(
        "\n  Couper le réseau de {role} quand même ? [o/N] : ",
        "\n  Cut the network of {role} anyway? [y/N]: "
    ))
    .oui()
}

/// `vanguard blocage rendre-reseau [<PID>]` : ce que Vanguard a coupé (sa liste scellée), ou un PID relu ici ;
/// l'élevé ne lève que ce qu'il a posé lui-même, et rien n'est dit rendu qui ne l'ait été.
fn rendre_le_reseau(pid: Option<u32>) {
    let (rendus, refus) = coupure::rendre(pid, crate::modele::evenement::Source::Utilisateur);
    if let Some(raison) = refus {
        afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
            &trf!(
                "{} : elle ne compte plus ; un PID donné est relu ici, rien de la liste n'est cru.",
                "{}: it no longer counts; a given PID is read again here, nothing from the list is believed.",
                capitale(raison)
            ),
            4,
            "",
        );
    }
    if rendus.is_empty() {
        match pid {
            Some(p) => trp!(
                "  Le processus {p} est fini, ou son programme ne se lit pas : rien à rendre (sous Linux, sa coupure est partie avec lui).",
                "  Process {p} has ended, or its program cannot be read: nothing to give back (on Linux, its cut went with it)."
            ),
            None if refus.is_some() => {}
            None => trp!(
                "  Aucun programme coupé du réseau par Vanguard.",
                "  No program cut from the network by Vanguard."
            ),
        }
        return;
    }
    for r in rendus {
        let quoi = match r.pid {
            Some(p) => format!("{} (PID {p})", affichable(&r.chemin)),
            None => trf!(
                "{} (règles du Pare-feu retrouvées par leur nom)",
                "{} (Firewall rules found by their name)",
                affichable(&r.chemin)
            ),
        };
        let reessai = r.pid.map(|p| format!(" {p}")).unwrap_or_default();
        match r.issue {
            Ok(None) => trp!(
                "  {VERT}✔{RESET} Rendu : {quoi}.",
                "  {VERT}✔{RESET} Given back: {quoi}."
            ),
            Ok(Some(n)) => afficher_aligne(
                &format!("  {VERT}✔{RESET} "),
                &trf!("Rendu : {quoi} ({n}).", "Given back: {quoi} ({n})."),
                4,
                "",
            ),
            Err(e) => trp!(
                "  ✖ {quoi} : {e}. Il reste noté ; « vanguard blocage rendre-reseau{reessai} » réessaie.",
                "  ✖ {quoi}: {e}. It stays noted; “vanguard blocking restore-network{reessai}” tries again."
            ),
        }
    }
}

/// `vanguard blocage reprendre [<PID>]` : ce que Vanguard a suspendu (sa liste scellée), toujours le même programme,
/// repris par les droits de ce compte ou par l'assistant élevé ; rien n'est dit repris qui ne l'ait été. Une liste
/// changée hors de Vanguard est dite : un PID donné est relu ici et repris seulement s'il s'y relit et qu'il est gelé
/// (rien de la liste n'est cru), sans PID rien n'est repris sur sa foi.
fn reprendre_les_suspendus(pid: Option<u32>) {
    use suspension::Reprise;
    let r = suspension::reprendre(pid);
    if let Some((raison, nommes)) = &r.liste_refusee {
        let nommes = if nommes.is_empty() {
            String::new()
        } else {
            trf!(
                " Elle nommait les PID {nommes} : des numéros écrits hors de Vanguard, à ne pas croire.",
                " It named PIDs {nommes}: numbers written outside Vanguard, not to be trusted."
            )
        };
        let suite = match pid {
            Some(_) => tr!(
                "le processus donné est relu ici, et repris seulement s'il se relit d'ici et qu'il est gelé ; rien de la liste n'est cru.",
                "the given process is read again here, and resumed only if it can be read from here and is frozen; nothing from the list is believed."
            ),
            None => tr!(
                "rien n'est repris sur sa foi, et une liste neuve la remplace.",
                "nothing is resumed on its word, and a new list replaces it."
            ),
        };
        afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
            &trf!(
                "{} : elle ne compte plus ;{nommes} {suite}",
                "{}: it no longer counts;{nommes} {suite}",
                capitale(raison)
            ),
            4,
            "",
        );
    }
    if r.faits.is_empty() {
        match pid {
            Some(p) if r.liste_refusee.is_some() => trp!(
                "  Le processus {p} est fini : rien n'est repris.",
                "  Process {p} has ended: nothing is resumed."
            ),
            Some(p) => trp!(
                "  Le processus {p} n'a pas été suspendu par Vanguard : rien n'est repris.",
                "  Process {p} was not suspended by Vanguard: nothing is resumed."
            ),
            None if r.liste_refusee.is_some() => {}
            None => trp!(
                "  Aucun programme suspendu par Vanguard.",
                "  No program suspended by Vanguard."
            ),
        }
        return;
    }
    for (s, fait) in r.faits {
        // Une menace dit déjà son PID ; « Suspendu à la main » non.
        let quoi = if s.quoi.contains(&format!("PID {}", s.pid)) {
            affichable(&s.quoi)
        } else {
            format!("{} (PID {})", affichable(&s.quoi), s.pid)
        };
        let eleve = couleur(crate::risk::Niveau::Eleve);
        match fait {
            Ok(Reprise::Faite) => trp!("  {VERT}✔{RESET} Repris : {quoi}.", "  {VERT}✔{RESET} Resumed: {quoi}."),
            Ok(Reprise::NonRelu) => trp!(
                "  {VERT}✔{RESET} Repris par l'assistant élevé : {quoi} (son état ne se relit pas d'ici).",
                "  {VERT}✔{RESET} Resumed by the elevated helper: {quoi} (its state cannot be read from here)."
            ),
            Ok(Reprise::TenuAilleurs) => trp!(
                "  {eleve}⚠{RESET} {quoi} : la suspension de Vanguard est levée, mais il reste suspendu par un autre programme (un débogueur, ou lui-même).",
                "  {eleve}⚠{RESET} {quoi}: Vanguard's suspension is lifted, but it stays suspended by another program (a debugger, or itself)."
            ),
            Ok(Reprise::DejaFini) => trp!(
                "  {GRIS}·{RESET} Déjà fini : {quoi}.",
                "  {GRIS}·{RESET} Already ended: {quoi}."
            ),
            Ok(Reprise::DejaRepris) => trp!(
                "  {GRIS}·{RESET} Il tournait déjà (un autre programme l'avait repris) : {quoi}.",
                "  {GRIS}·{RESET} It was already running (another program had resumed it): {quoi}."
            ),
            Ok(Reprise::Autre) => trp!(
                "  {GRIS}·{RESET} Ce numéro est maintenant un autre programme : rien n'est touché ({quoi}).",
                "  {GRIS}·{RESET} This number is now another program: nothing is touched ({quoi})."
            ),
            Err(e) => trp!(
                "  ✖ {quoi} : {e}. Il reste noté ; « vanguard blocage reprendre {} » réessaie.",
                "  ✖ {quoi}: {e}. It stays noted; “vanguard blocking resume {}” tries again.",
                s.pid
            ),
        }
    }
}

/// La première lettre en capitale.
fn capitale(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|p| p.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// L'état des quatre catégories, et de la protection active.
fn afficher_etat(p: &Parametres) {
    titre(tr!("Blocage des menaces", "Threat blocking"));
    for c in Categorie::TOUTES {
        let mode = p.effectif(c);
        let marque = match mode {
            Mode::Automatique => format!("{VERT}●{RESET}"),
            Mode::UnClic => format!("{ACCENT}○{RESET}"),
            Mode::Desactive => format!("{GRIS}·{RESET}"),
        };
        println!("  {marque} {GRAS}{:<26}{RESET} {}", c.titre(), mode.libelle());
        afficher_aligne("      ", c.geste(), 6, GRIS);
    }
    println!();
    match &p.accord {
        Some(le) if p.actif() => trp!(
            "  Protection active : {VERT}oui{RESET} (accord donné le {le}). Elle tourne au bilan et dans la surveillance horaire ({}).",
            "  Active protection: {VERT}yes{RESET} (consent given on {le}). It runs at the check-up and in the hourly monitoring ({}).",
            if crate::reseau::surveillance::active() {
                tr!("activée", "on")
            } else {
                tr!("coupée : vanguard surveillance on", "off: vanguard monitor on")
            }
        ),
        _ => trp!(
            "  Protection active : non. Rien n'est bloqué sans votre clic.",
            "  Active protection: no. Nothing is blocked without your click."
        ),
    }
    if p.actif() && gestes::administrateur_ou_inconnu() {
        dire_administrateur();
    }
    crate::protection::temps_reel::dire_si_coupee(crate::protection::temps_reel::Ou::Blocage);
    dire_si_pare_feu_coupe();
}

/// Le texte de l'accord, montré une seule fois, avant le premier « automatique ».
fn demander_accord() -> bool {
    titre(tr!("Protection active", "Active protection"));
    for t in [
        tr!(
            "La protection active bloque toute seule, sans vous demander, seulement ce qui est certain :",
            "Active protection blocks by itself, without asking you, only what is certain:"
        ),
        tr!(
            "• un programme dont l'empreinte SHA-256 est dans MalwareBazaar, ou un outil d'attaque connu en marche : arrêté, puis mis en quarantaine ;",
            "• a program whose SHA-256 fingerprint is in MalwareBazaar, or a known attack tool running: stopped, then quarantined;"
        ),
        tr!(
            "• une connexion vers un serveur de commande de botnet connu (Feodo Tracker, ThreatFox) : bloquée par le pare-feu.",
            "• a connection to a known botnet command server (Feodo Tracker, ThreatFox): blocked by the firewall."
        ),
        tr!(
            "Chaque blocage vous prévient (notification, tableau de bord), est noté dans « Ce que Vanguard a changé » et s'annule par « vanguard blocage annuler ». Jamais Vanguard, un processus critique, un programme du système ni une connexion à distance en cours. Le douteux reste une alerte avec son bouton. Elle tourne au bilan et dans la surveillance horaire ; sans les droits d'administrateur, ce qui les demande n'est pas fait, et c'est dit. En administrateur, rien n'est bloqué tout seul : le certain s'y propose d'un clic.",
            "Each block warns you (notification, dashboard), is written in “What Vanguard changed” and is undone with “vanguard blocking undo”. Never Vanguard, a critical process, a system program or a remote connection in progress. What is doubtful stays an alert with its button. It runs at the check-up and in the hourly monitoring; without administrator rights, what needs them is not done, and you are told. As administrator, nothing is blocked by itself: what is certain is offered with one click there."
        ),
    ] {
        afficher_aligne("  ", t, 4, "");
    }
    demander(tr!(
        "\n  Activer la protection active ? [o/N] : ",
        "\n  Turn active protection on? [y/N]: "
    ))
    .oui()
}

/// Règle le mode d'une catégorie (l'accord d'abord, une fois, pour le premier « automatique »). `false` : rien changé.
fn changer_mode(c: Categorie, m: Mode) -> bool {
    let mut p = parametres();
    if m == Mode::Automatique && c.a_du_certain() && p.accord.is_none() {
        if !demander_accord() {
            trp!(
                "  Rien n'a changé : tout reste en un clic.",
                "  Nothing changed: everything stays one click."
            );
            return false;
        }
        p.accord = Some(chrono::Local::now().format("%Y-%m-%d %H:%M").to_string());
    }
    if let Err(e) = p.regler(c, m) {
        trp!("  ✖ {e}", "  ✖ {e}");
        return false;
    }
    if !enregistrer(&p) {
        return false;
    }
    trp!(
        "  {VERT}✔{RESET} {} : {}",
        "  {VERT}✔{RESET} {}: {}",
        c.titre(),
        p.effectif(c).libelle()
    );
    if m == Mode::Automatique && crate::protection::temps_reel::coupure().is_some() {
        afficher_aligne(
            "  ",
            tr!(
                "La protection en temps réel est coupée : rien ne se bloquera tout seul avant qu'elle reprenne (vanguard parametres temps-reel oui).",
                "Real-time protection is off: nothing will be blocked by itself until it comes back (vanguard settings real-time yes)."
            ),
            2,
            GRIS,
        );
    } else if m == Mode::Automatique && !crate::reseau::surveillance::active() {
        afficher_aligne(
            "  ",
            tr!(
                "La surveillance horaire est coupée : la protection active ne tourne qu'au bilan. Pour qu'elle veille aussi : vanguard surveillance on.",
                "Hourly monitoring is off: active protection only runs at the check-up. To have it watch too: vanguard monitor on."
            ),
            2,
            GRIS,
        );
    }
    true
}

/// Le menu Antivirus et protection › Blocage des menaces.
pub fn menu() {
    let mut dernier = String::from("1");
    loop {
        let p = parametres();
        let mut lignes = vec![
            Ligne::Texte(String::new()),
            Ligne::Texte(ligne_titre(tr!("Blocage des menaces", "Threat blocking"))),
            Ligne::Texte(if p.actif() && crate::protection::temps_reel::coupure().is_some() {
                trf!(
                    "  {}Protection en temps réel coupée{RESET} {GRIS}: rien ne se bloque tout seul.{RESET}",
                    "  {}Real-time protection off{RESET}{GRIS}: nothing is blocked by itself.{RESET}",
                    couleur(crate::risk::Niveau::Moyen)
                )
            } else if p.actif() {
                trf!(
                    "  {VERT}Protection active{RESET} {GRIS}: le certain est bloqué tout seul.{RESET}",
                    "  {VERT}Active protection{RESET}{GRIS}: what is certain is blocked by itself.{RESET}"
                )
            } else {
                trf!(
                    "  {GRIS}Rien n'est bloqué sans votre clic. Une catégorie se règle :{RESET}",
                    "  {GRIS}Nothing is blocked without your click. Set a category:{RESET}"
                )
            }),
            Ligne::Texte(String::new()),
        ];
        for (i, c) in Categorie::TOUTES.iter().enumerate() {
            lignes.push(Ligne::choix(
                &i.saturating_add(1).to_string(),
                c.titre(),
                p.effectif(*c).libelle(),
            ));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix(
            "5",
            tr!("Chercher les menaces maintenant", "Look for threats now"),
            tr!("et bloquer d'un clic", "and block with one click"),
        ));
        let en_place = crate::changements::blocages_en_place().len();
        lignes.push(Ligne::choix(
            "6",
            tr!("Annuler un blocage", "Undo a block"),
            &trf!("{en_place} en place", "{en_place} in place"),
        ));
        lignes.push(Ligne::choix(
            "7",
            tr!("Suites de gestes", "Action suites"),
            tr!("par type d'alerte", "by alert type"),
        ));
        let isole = crate::protection::isolement::en_place().is_some();
        lignes.push(if isole {
            Ligne::choix(
                "8",
                tr!("Lever l'isolement", "Lift the isolation"),
                tr!("l'ordinateur est isolé", "the computer is isolated"),
            )
        } else {
            Ligne::choix(
                "8",
                tr!("Isoler l'ordinateur du réseau", "Isolate the computer"),
                tr!("sauf la session à distance", "except the remote session"),
            )
        });
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        let Some(choix) = choisir(
            &lignes,
            tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim().to_string();
        match choix.as_str() {
            "5" => chercher_et_proposer(),
            "6" => annuler(),
            "7" => editer_suites(),
            "8" if isole => {
                crate::protection::isolement::lever_avec_accord();
            }
            "8" => crate::protection::isolement::isoler_avec_accord(),
            n => match n
                .parse::<usize>()
                .ok()
                .and_then(|i| Categorie::TOUTES.get(i.checked_sub(1)?))
            {
                Some(&c) => regler_categorie(c),
                None => return,
            },
        }
        dernier = choix;
    }
}

/// Le choix du mode d'une catégorie.
fn regler_categorie(c: Categorie) {
    let p = parametres();
    let actuel = p.effectif(c);
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(c.titre())),
        Ligne::Texte(format!("  {GRIS}{}{RESET}", c.geste())),
    ];
    if !c.a_du_certain() {
        lignes.push(Ligne::Texte(format!(
            "  {GRIS}{}{RESET}",
            tr!(
                "Rien n'y est certain : jamais automatique.",
                "Nothing there is certain: never automatic."
            )
        )));
    }
    lignes.push(Ligne::Texte(String::new()));
    let modes: Vec<Mode> = Mode::TOUS
        .into_iter()
        .filter(|m| *m != Mode::Automatique || c.a_du_certain())
        .collect();
    for (i, m) in modes.iter().enumerate() {
        let precision = match m {
            _ if *m == actuel => tr!("← en ce moment", "← now"),
            Mode::Desactive => tr!("l'alerte seulement", "the alert only"),
            Mode::UnClic => tr!("montré, puis accepté", "shown, then accepted"),
            Mode::Automatique => tr!("le certain, tout seul", "what is certain, by itself"),
        };
        lignes.push(Ligne::choix(&i.saturating_add(1).to_string(), m.libelle(), precision));
    }
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    let Some(choix) = choisir(
        &lignes,
        tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
        "1",
        tr!("revenir", "back"),
    ) else {
        return;
    };
    if let Some(&m) = choix
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|i| modes.get(i.checked_sub(1)?))
    {
        changer_mode(c, m);
    }
}

/// L'éditeur des suites : un type d'alerte, puis ses gestes (choisir, ordonner, retirer). Pas de langage de règles :
/// seulement les gestes de la liste fermée, dans l'ordre choisi.
fn editer_suites() {
    let mut dernier = String::from("1");
    // Un fichier non cru ou illisible est dit ici, une fois, pas à chaque tour de l'éditeur.
    let _ = parametres();
    loop {
        let p = parametres_tus();
        let mut lignes = vec![
            Ligne::Texte(String::new()),
            Ligne::Texte(ligne_titre(tr!("Suites de gestes", "Action suites"))),
        ];
        for l in envelopper(
            tr!(
                "Ce que Vanguard enchaîne pour chaque type d'alerte : tout seul pour le certain, proposé d'une touche pour le douteux. Chaque geste est noté et s'annule à part.",
                "What Vanguard chains for each alert type: by itself for what is certain, offered with one key for what is doubtful. Each action is logged and undone on its own."
            ),
            LARGEUR.saturating_sub(4),
        ) {
            lignes.push(Ligne::Texte(format!("  {GRIS}{l}{RESET}")));
        }
        lignes.push(Ligne::Texte(String::new()));
        for (i, t) in suites::Type::TOUS.iter().enumerate() {
            let marque = if suites::lire(&p.suites, *t).is_ok_and(|s| s.is_some()) {
                " *"
            } else {
                ""
            };
            lignes.push(Ligne::choix(
                &i.saturating_add(1).to_string(),
                &format!("{}{marque}", t.titre()),
                t.origine(),
            ));
        }
        lignes.push(Ligne::Texte(format!(
            "  {GRIS}{}{RESET}",
            tr!("* : suite choisie ici", "* : suite chosen here")
        )));
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        let Some(choix) = choisir(
            &lignes,
            tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim().to_string();
        let Some(&t) = choix
            .parse::<usize>()
            .ok()
            .and_then(|i| suites::Type::TOUS.get(i.checked_sub(1)?))
        else {
            return;
        };
        editer_suite(t);
        dernier = choix;
    }
}

/// La suite d'un type : ses gestes dans l'ordre ; un geste choisi se monte ou se retire, un autre s'ajoute à la fin,
/// et celle par défaut se remet. Chaque changement est enregistré (scellé) tout de suite.
fn editer_suite(t: suites::Type) {
    let mut dernier = String::from("1");
    loop {
        let p = parametres_tus();
        let (etapes, choisie, abimee) = match suites::lire(&p.suites, t) {
            Ok(Some(s)) => (s, true, None),
            Ok(None) => (suites::defaut(t), false, None),
            Err(e) => (suites::defaut(t), false, Some(e)),
        };
        let mut lignes = vec![
            Ligne::Texte(String::new()),
            Ligne::Texte(ligne_titre(t.titre())),
            Ligne::Texte(format!(
                "  {GRIS}{}{RESET}",
                if choisie {
                    tr!("Suite choisie ici.", "Suite chosen here.")
                } else {
                    tr!("Suite par défaut.", "Default suite.")
                }
            )),
        ];
        let mut avertir = |texte: &str| {
            for l in envelopper(texte, LARGEUR.saturating_sub(4)) {
                lignes.push(Ligne::Texte(format!(
                    "  {}{l}{RESET}",
                    couleur(crate::risk::Niveau::Moyen)
                )));
            }
        };
        if let Some(e) = &abimee {
            avertir(&trf!(
                "⚠ La suite écrite ne se lit pas ({e}) : celle par défaut s'applique.",
                "⚠ The written suite cannot be read ({e}): the default one applies."
            ));
        }
        if !suites::plancher_tenu(t, &etapes) {
            avertir(&format!("⚠ {}", suites::plancher_dit(t)));
        }
        if t == suites::Type::Rancongiciel {
            avertir(tr!(
                "Le veilleur, tout seul, fait toujours la suite par défaut et gèle tout ce que le programme a lancé ; celle-ci sert quand vous répondez à son alerte, et son « suspendre » ne gèle que le processus désigné.",
                "The watcher, by itself, always runs the default suite and freezes everything the program started; this one is used when you answer its alert, and its “suspend” freezes only the named process."
            ));
        }
        if etapes.contains(&suites::Etape::Bloquer) {
            // Bloquer relève toujours la preuve juste avant son geste : l'étape ne se retire pas en vérité.
            for l in envelopper(
                tr!(
                    "La preuve est toujours relevée juste avant Bloquer, même sans l'étape « Relever la preuve ».",
                    "The evidence is always recorded just before Block, even without the “Record the evidence” step."
                ),
                LARGEUR.saturating_sub(4),
            ) {
                lignes.push(Ligne::Texte(format!("  {GRIS}{l}{RESET}")));
            }
        }
        lignes.push(Ligne::Texte(String::new()));
        for (i, e) in etapes.iter().enumerate() {
            lignes.push(Ligne::choix(
                &i.saturating_add(1).to_string(),
                e.texte(),
                e.precision(t),
            ));
        }
        lignes.push(Ligne::Texte(String::new()));
        let manquants = suites::a_ajouter(&etapes);
        if !manquants.is_empty() {
            lignes.push(Ligne::choix("a", tr!("Ajouter un geste", "Add an action"), ""));
        }
        if choisie || abimee.is_some() {
            lignes.push(Ligne::choix(
                "d",
                tr!("Remettre la suite par défaut", "Restore the default suite"),
                "",
            ));
        }
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        let Some(choix) = choisir(
            &lignes,
            tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim().to_string();
        let nouvelle = match choix.as_str() {
            "a" if !manquants.is_empty() => {
                let Some(e) = choisir_geste_a_ajouter(t, &manquants) else {
                    continue;
                };
                let mut s = etapes.clone();
                s.push(e);
                Some(s)
            }
            "d" if choisie || abimee.is_some() => None,
            autre => {
                let Some(rang) = autre
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .filter(|n| *n < etapes.len())
                else {
                    return;
                };
                let mut suite = etapes.clone();
                if !changer_geste(&mut suite, rang) {
                    dernier = choix;
                    continue;
                }
                Some(suite)
            }
        };
        let mut p = p;
        // Une suite redevenue celle par défaut ne s'écrit pas : le défaut d'une version suivante s'appliquera.
        let nouvelle = nouvelle.filter(|s| *s != suites::defaut(t));
        p.regler_suite(t, nouvelle.as_deref());
        if enregistrer(&p) {
            trp!(
                "  {VERT}✔{RESET} {} : suite enregistrée.",
                "  {VERT}✔{RESET} {}: suite saved.",
                t.titre()
            );
        }
        // « d » disparaît avec la suite choisie : Entrée revient alors, au lieu de rouvrir le premier geste.
        dernier = if choix == "d" { "↵".to_string() } else { choix };
    }
}

/// Le geste à ajouter à la fin de la suite (`None` : rien).
fn choisir_geste_a_ajouter(t: suites::Type, manquants: &[suites::Etape]) -> Option<suites::Etape> {
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(tr!("Ajouter un geste", "Add an action"))),
        Ligne::Texte(String::new()),
    ];
    for (i, e) in manquants.iter().enumerate() {
        lignes.push(Ligne::choix(
            &i.saturating_add(1).to_string(),
            e.texte(),
            e.precision(t),
        ));
    }
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    let choix = choisir(
        &lignes,
        tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
        "1",
        tr!("revenir", "back"),
    )?;
    let e = *choix
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|i| manquants.get(i.checked_sub(1)?))?;
    Some(e)
}

/// Monter ou retirer le geste `i` (`false` : rien changé).
fn changer_geste(s: &mut Vec<suites::Etape>, i: usize) -> bool {
    let Some(e) = s.get(i).copied() else {
        return false;
    };
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(e.texte())),
        Ligne::Texte(String::new()),
    ];
    if i > 0 {
        lignes.push(Ligne::choix("1", tr!("Monter d'un cran", "Move up one step"), ""));
    }
    if s.len() > 1 {
        lignes.push(Ligne::choix(
            "2",
            tr!("Retirer de la suite", "Remove from the suite"),
            "",
        ));
    }
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    let Some(choix) = choisir(
        &lignes,
        tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
        if i > 0 { "1" } else { "2" },
        tr!("revenir", "back"),
    ) else {
        return false;
    };
    match choix.trim() {
        "1" if i > 0 => {
            suites::monter(s, i);
            true
        }
        "2" => suites::retirer(s, i),
        _ => false,
    }
}

/// Les catégories où quelque chose se cherche (pas désactivées).
fn categories_actives(p: &Parametres) -> Vec<Categorie> {
    Categorie::TOUTES
        .into_iter()
        .filter(|&c| p.effectif(c) != Mode::Desactive)
        .collect()
}

/// Les menaces déclarées normales ici, laissées de côté : dites, pour qu'un choix oublié ne passe pas inaperçu.
fn dire_normales(n: usize) {
    if n > 0 {
        afficher_aligne(
            "  ",
            &trf!(
                "{n} menace(s) déclarée(s) normale(s) ici, ni proposée(s) ni bloquée(s) : Ce que Vanguard a appris.",
                "{n} threat(s) declared normal here, neither offered nor blocked: What Vanguard has learned."
            ),
            2,
            GRIS,
        );
    }
}

fn dire_non_verifie(non_verifie: &[String]) {
    if !non_verifie.is_empty() {
        let liste = non_verifie
            .iter()
            .map(|t| affichable(t))
            .collect::<Vec<_>>()
            .join(" ; ");
        afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Moyen)),
            &trf!("Pas vérifié : {liste}.", "Not checked: {liste}."),
            4,
            "",
        );
    }
}

/// « Chercher les menaces maintenant » : tout se propose d'un clic, même le certain (c'est toi qui as demandé).
fn chercher_et_proposer() {
    let p = parametres();
    titre(tr!("Menaces à bloquer", "Threats to block"));
    let categories = categories_actives(&p);
    if categories.is_empty() {
        trp!(
            "  Tout est désactivé : rien n'est cherché. Réglez une catégorie sur « un clic ».",
            "  Everything is off: nothing is looked for. Set a category to “one click”."
        );
        return;
    }
    trp!(
        "  {GRIS}Recherche : programmes en marche, connexions, démarrage, agents d'IA…{RESET}",
        "  {GRIS}Looking at: running programs, connections, startup, AI agents…{RESET}"
    );
    let t = menaces::chercher(&categories, false);
    let interactif = std::io::stdin().is_terminal();
    let ctx = Contexte::lire(t.intouchables.clone(), interactif);
    proposer(t.menaces, &ctx, &p);
    dire_normales(t.normales);
    dire_non_verifie(&t.non_verifie);
}

/// Au bilan : le certain des catégories automatiques est bloqué tout seul (jamais en administrateur ni la protection
/// en temps réel coupée, voir `pour_agir`), puis chaque autre menace propose « Bloquer » (dans un terminal ; sinon
/// elle est seulement dite, sans question).
pub fn au_bilan() {
    // Ce que la personne a suspendu ou demandé de surveiller se rappelle à chaque bilan, même le blocage coupé : un
    // programme gelé et oublié tient ses fichiers ; un tiers qui l'a repris est vu (et le programme resuspendu si ce
    // compte en a les droits, sinon c'est dit) ; un programme qui ne se relit pas d'ici est dit, jamais oublié.
    suspension::rappeler();
    coupure::rappeler();
    surveiller::rappeler();
    let p = parametres();
    if p.rien() {
        return;
    }
    titre(tr!("Blocage des menaces", "Threat blocking"));
    let t = menaces::chercher(
        &categories_actives(&p),
        p.effectif(Categorie::Programmes) == Mode::Automatique,
    );
    let interactif = std::io::stdin().is_terminal();
    let ctx = Contexte::lire(t.intouchables.clone(), interactif);
    let administrateur = gestes::administrateur_ou_inconnu();
    if p.actif() && administrateur {
        dire_administrateur();
    }
    let coupee = crate::protection::temps_reel::dire_si_coupee(crate::protection::temps_reel::Ou::Blocage);
    let p = pour_agir(p, administrateur || coupee);
    let (auto, un_clic): (Vec<Menace>, Vec<Menace>) = t
        .menaces
        .into_iter()
        .filter(|m| decider(&p, m.categorie, m.certaine) != Decision::Rien)
        .partition(|m| decider(&p, m.categorie, m.certaine) == Decision::Auto);
    for m in &auto {
        bloquer_tout_seul(m, &ctx, &p, None);
    }
    if interactif {
        proposer(un_clic, &ctx, &p);
    } else if !un_clic.is_empty() {
        for m in &un_clic {
            afficher_aligne(
                &format!("  {}!{RESET} ", couleur(crate::risk::Niveau::Eleve)),
                &m.quoi,
                4,
                "",
            );
        }
        afficher_aligne(
            "  ",
            tr!(
                "Pour les bloquer d'un clic : vanguard blocage chercher (dans un terminal).",
                "To block them with one click: vanguard blocking search (in a terminal)."
            ),
            2,
            GRIS,
        );
    } else if auto.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Aucune menace à bloquer.",
            "  {VERT}✔{RESET} No threat to block."
        );
    }
    dire_normales(t.normales);
    dire_non_verifie(&t.non_verifie);
}

/// Bloque une menace certaine sans rien demander, par la suite de son type (`suites`, celle par défaut si la sienne
/// ne tient pas le plancher du certain), puis prévient (notification et tableau de bord). `signalees` : en
/// surveillance, les menaces déjà dites non bloquées au passage d'avant, pour ne pas le répéter chaque heure ; elle
/// y ajoute celle-ci si elle reste non bloquée.
fn bloquer_tout_seul(
    m: &Menace,
    ctx: &Contexte,
    p: &Parametres,
    mut signalees: Option<(&BTreeSet<String>, &mut BTreeSet<String>)>,
) {
    let retenue = enchainer::type_de(m).map(|t| p.suite(t, true));
    let dit = retenue.as_ref().and_then(|r| r.dit.clone());
    if ctx.interactif
        && let Some(d) = &dit
    {
        afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Moyen)),
            &capitaliser(d),
            4,
            "",
        );
    }
    let etapes = retenue.map_or_else(|| suites::defaut(suites::Type::MalwareConnu), |r| r.etapes);
    let pret = gestes::preparer(m, ctx, true);
    if let Err(raison) = &pret
        && deja_refusee(&m.cle, &mut signalees)
    {
        // Bloquer refusé d'avance (souvent : pas administrateur) et déjà dit au passage d'avant : rien à refaire,
        // ni preuve ni action au journal, sinon la passe horaire les répéterait chaque heure.
        if ctx.interactif {
            afficher_aligne(
                &format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)),
                &trf!("{} : pas bloqué, {raison}", "{}: not blocked, {raison}", m.quoi),
                4,
                "",
            );
        }
        return;
    }
    let d = enchainer::derouler(m, &etapes, ctx, true, pret, &mut |d| {
        prevenir_tout_seul(m, ctx, d, dit.as_deref(), &mut signalees)
    });
    if ctx.interactif {
        dire_les_autres_gestes(&d);
    }
}

/// Note la menace comme signalée (Bloquer refusé d'avance) et dit si elle l'était déjà au passage d'avant : la suite
/// entière est alors tue. Sans liste (`None`, une passe hors surveillance), jamais déjà signalée.
fn deja_refusee(cle: &str, signalees: &mut Option<(&BTreeSet<String>, &mut BTreeSet<String>)>) -> bool {
    match signalees {
        Some((avant, maintenant)) => {
            maintenant.insert(cle.to_string());
            avant.contains(cle)
        }
        None => false,
    }
}

/// Le geste Prévenir d'une suite faite toute seule : le blocage (ou son échec, dit une fois) à l'écran et au tableau
/// de bord, avec ce que la suite a fait d'autre.
fn prevenir_tout_seul(
    m: &Menace,
    ctx: &Contexte,
    d: &enchainer::Deroule,
    dit: Option<&str>,
    signalees: &mut Option<(&BTreeSet<String>, &mut BTreeSet<String>)>,
) -> enchainer::Issue {
    let (titre, texte) = alerte_de_la_suite(m, d, dit);
    match &d.bloque {
        Some(Ok(fait)) => {
            if ctx.interactif {
                let quoi = &fait.quoi;
                if fait.verifie {
                    trp!(
                        "  {VERT}✔{RESET} Bloqué tout seul (protection active).",
                        "  {VERT}✔{RESET} Blocked by itself (active protection)."
                    );
                } else {
                    afficher_aligne(
                        &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Moyen)),
                        &trf!(
                            "Règle posée toute seule (protection active), non vérifiée : {quoi}.",
                            "Rule added by itself (active protection), not verified: {quoi}."
                        ),
                        4,
                        "",
                    );
                }
            }
        }
        Some(Err(raison)) => {
            if ctx.interactif {
                afficher_aligne(
                    &format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)),
                    &trf!("{} : pas bloqué, {raison}", "{}: not blocked, {raison}", m.quoi),
                    4,
                    "",
                );
            }
            let nouvelle = match signalees {
                Some((avant, maintenant)) => {
                    maintenant.insert(m.cle.clone());
                    !avant.contains(&m.cle)
                }
                None => true,
            };
            if !nouvelle {
                return enchainer::Issue::Saute(
                    tr!("déjà dit au passage d'avant", "already said on the previous pass").to_string(),
                );
            }
        }
        None => {}
    }
    alerter_blocage(m, titre, &texte);
    enchainer::Issue::Fait(tr!("notification et tableau de bord", "notification and dashboard").to_string())
}

/// Le titre et le texte de l'alerte d'une suite : ce que Bloquer a fait (ou pourquoi pas), ce que la suite a fait
/// d'autre jusque-là, ce qui l'a remplacée par celle par défaut, et comment défaire chaque geste.
fn alerte_de_la_suite(m: &Menace, d: &enchainer::Deroule, dit: Option<&str>) -> (&'static str, String) {
    let titre = match &d.bloque {
        Some(Ok(f)) if f.verifie => tr!("Vanguard a bloqué une menace", "Vanguard blocked a threat"),
        Some(Ok(_)) => tr!(
            "Vanguard a posé une règle sans pouvoir la vérifier",
            "Vanguard added a rule without being able to verify it"
        ),
        Some(Err(_)) => tr!("Vanguard n'a pas pu bloquer", "Vanguard could not block"),
        None => tr!("Vanguard a fait une suite de gestes", "Vanguard ran a suite of actions"),
    };
    let mut texte = match &d.bloque {
        Some(Ok(f)) => f.quoi.clone(),
        Some(Err(raison)) => trf!("{} : {raison}", "{}: {raison}", m.quoi),
        None => m.quoi.clone(),
    };
    let autres: Vec<String> = d
        .issues
        .iter()
        .filter(|(e, i)| *e != suites::Etape::Bloquer && !matches!(i, enchainer::Issue::AvecBloquer(_)))
        .map(|(e, i)| i.ligne(*e))
        .collect();
    let suspendu = d.a_reprendre;
    let coupe = d
        .issues
        .iter()
        .any(|(e, i)| *e == suites::Etape::CouperReseau && matches!(i, enchainer::Issue::Fait(_)));
    if !autres.is_empty() {
        texte += &trf!(". Suite : {}", ". Suite: {}", autres.join(" ; "));
    }
    if let Some(d) = dit {
        texte += &trf!(" ({d})", " ({d})");
    }
    // Chaque geste se défait à part : le blocage par « annuler », la suspension par « reprendre », la coupure du
    // réseau par « rendre-reseau ».
    if suspendu || coupe {
        let mut defaire = vec!["vanguard blocage annuler"];
        let mut undo = vec!["vanguard blocking undo"];
        if suspendu {
            defaire.push("vanguard blocage reprendre");
            undo.push("vanguard blocking resume");
        }
        if coupe {
            defaire.push("vanguard blocage rendre-reseau");
            undo.push("vanguard blocking restore-network");
        }
        let (defaire, undo) = (defaire.join(", "), undo.join(", "));
        texte += &trf!(
            ". Pour annuler, chaque geste à part : {defaire}.",
            ". To undo, each action on its own: {undo}."
        );
    } else if matches!(d.bloque, Some(Ok(_))) {
        texte += tr!(
            ". Pour annuler : vanguard blocage annuler.",
            ". To undo: vanguard blocking undo."
        );
    }
    (titre, texte)
}

/// Les gestes de la suite autres que Bloquer et Prévenir (déjà dits), une ligne chacun.
fn dire_les_autres_gestes(d: &enchainer::Deroule) {
    for (e, i) in &d.issues {
        if matches!(e, suites::Etape::Bloquer | suites::Etape::Prevenir) {
            continue;
        }
        afficher_aligne("    ", &affichable(&i.ligne(*e)), 4, GRIS);
    }
}

/// La première lettre en capitale (une raison écrite pour suivre « : »).
fn capitaliser(t: &str) -> String {
    let mut c = t.chars();
    c.next()
        .map(|p| p.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// L'alerte d'un blocage fait tout seul, ou manqué. Une menace certaine n'est jamais tue (`menaces::chercher`) :
/// son alerte non plus, même si sa clé a été déclarée normale, sans quoi elle serait bloquée sans que personne le
/// sache.
///
/// L'alerte est reliée, dans le journal des événements, au geste qu'elle annonce (ou à son échec, noté aussi) : le
/// fil va de l'alerte de détection à la preuve, au geste, puis à cette alerte, au lieu d'alertes sans lien.
fn alerter_blocage(m: &Menace, titre: &str, texte: &str) {
    let cle = m.cle_normale_ici();
    if !m.certaine && crate::protection::normales::est_normale(&cle) {
        return;
    }
    let geste = crate::modele::journal::dernier(
        |e| {
            matches!(e.quoi, crate::modele::evenement::Genre::Action { .. }) && e.cle.as_deref() == Some(m.cle.as_str())
        },
        chrono::Duration::minutes(10),
    );
    let id = crate::reseau::tableau::noter_alerte_liee(Genre::Blocage, Some(&cle), geste.as_deref(), titre, texte);
    crate::reseau::surveillance::notifier(
        titre,
        &crate::reseau::surveillance::corps_a_choisir(texte, id.as_deref()),
    );
}

/// Les menaces déjà signalées comme non bloquées, d'après les sceaux : intactes ou adoptées, leurs clés ; changées
/// hors de Vanguard, inconnues ou illisibles, aucune, pour que tout soit redit (une clé ajoutée par un programme du
/// compte taisait l'échec de son propre blocage).
fn signalees_lues(lu: crate::sceau::Juge) -> BTreeSet<String> {
    // Acceptées telles quelles après des sceaux refaits, elles ne taisent rien non plus (`sceau::juge`).
    lu.cru()
        .map(|o| String::from_utf8_lossy(&o).lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Dans la surveillance horaire : le certain des catégories automatiques seulement, sans jamais rien demander ; chaque
/// blocage, et chaque menace qui n'a pas pu l'être (une fois), est notifié.
pub(crate) fn en_surveillance() {
    let Ok(p) = parametres::charger() else {
        return;
    };
    // En administrateur, ou la protection en temps réel coupée (la passe s'arrête déjà avant ; ceci tient même si elle
    // ne le faisait plus), rien ne s'y bloque tout seul (`pour_agir`) : il n'y a rien à chercher.
    let p = pour_agir(
        p,
        gestes::administrateur_ou_inconnu() || crate::protection::temps_reel::coupure().is_some(),
    );
    if !p.actif() {
        return;
    }
    let categories: Vec<Categorie> = Categorie::TOUTES
        .into_iter()
        .filter(|&c| p.effectif(c) == Mode::Automatique)
        .collect();
    let t = menaces::chercher(&categories, p.effectif(Categorie::Programmes) == Mode::Automatique);
    let ctx = Contexte::lire(t.intouchables.clone(), false);
    let avant = signalees_lues(crate::sceau::juge(crate::sceau::BLOCAGE_SIGNALEES));
    let mut maintenant = BTreeSet::new();
    for m in t
        .menaces
        .iter()
        .filter(|m| decider(&p, m.categorie, m.certaine) == Decision::Auto)
    {
        bloquer_tout_seul(m, &ctx, &p, Some((&avant, &mut maintenant)));
    }
    let _ = crate::sceau::ecrire(
        crate::sceau::BLOCAGE_SIGNALEES,
        maintenant.into_iter().collect::<Vec<_>>().join("\n"),
    );
}

/// Une commande telle qu'elle est montrée : la phrase d'un ordre ou d'une correction native de Windows, la commande
/// sinon.
pub(crate) fn commande_montree(c: &str) -> String {
    #[cfg(windows)]
    {
        crate::machine::windows::corrections::affichable(c)
    }
    #[cfg(not(windows))]
    {
        ordres::affichable(c)
    }
}

/// Le pare-feu coupé sur un profil du réseau actuel : une règle « Vanguard : bloquer … » n'y bloquerait rien. Dit en
/// une ligne, avec le chemin pour le rallumer ; rien quand il est illisible (le geste le refusera de lui-même).
#[cfg(windows)]
fn dire_si_pare_feu_coupe() {
    let Some(coupes) = crate::machine::windows::pare_feu::profils_courants_coupes() else {
        return;
    };
    if coupes.is_empty() {
        return;
    }
    let profils = coupes
        .into_iter()
        .map(crate::options_defense::nom_profil_pare_feu)
        .collect::<Vec<_>>()
        .join(", ");
    afficher_aligne(
        &format!("  {}ℹ{RESET} ", couleur(crate::risk::Niveau::Moyen)),
        &trf!(
            "Pare-feu coupé sur ce profil ({profils}) : vos blocages ne s'appliquent pas. Rallumez-le : Options de défense › Pare-feu.",
            "Firewall off on this profile ({profils}): your blocks do not apply. Turn it back on: Defense options › Firewall."
        ),
        4,
        "",
    );
}

#[cfg(not(windows))]
fn dire_si_pare_feu_coupe() {}

/// Le geste, montré avant l'accord : chaque étape, puis les commandes.
fn montrer(m: &Menace, pret: &gestes::Pret) {
    println!();
    afficher_aligne("  ", &m.quoi, 2, GRAS);
    for e in &pret.etapes {
        afficher_aligne("    → ", e, 6, "");
    }
    for c in pret.commandes.iter().chain(&pret.apres) {
        afficher_aligne(&format!("      {GRIS}>{RESET} "), &commande_montree(c), 8, GRIS);
    }
}

/// Chaque menace ouvre son menu des gestes (`choix`) : Bloquer en tête, puis Suspendre, Surveiller de plus près, Faire
/// confiance (ou « c'est normal ici ») et Ignorer. Ce que les garde-fous refusent reste visible, grisé, avec sa raison.
fn proposer(menaces: Vec<Menace>, ctx: &Contexte, p: &Parametres) {
    if menaces.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Aucune menace à bloquer.",
            "  {VERT}✔{RESET} No threat to block."
        );
        return;
    }
    dire_si_pare_feu_coupe();
    let mut restantes = menaces;
    loop {
        if restantes.is_empty() {
            return;
        }
        let mut lignes = vec![
            Ligne::Texte(String::new()),
            Ligne::Texte(trf!(
                "  {GRIS}Choisissez une menace : ses gestes sont montrés, le prévu en tête.{RESET}",
                "  {GRIS}Pick a threat: its actions are shown, the planned one first.{RESET}"
            )),
        ];
        for (i, m) in restantes.iter().enumerate() {
            let precision = if m.certaine {
                tr!("certain", "certain")
            } else {
                tr!("douteux", "doubtful")
            };
            lignes.push(Ligne::choix(
                &i.saturating_add(1).to_string(),
                &couper(&m.quoi, 52),
                precision,
            ));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Ne rien faire de plus", "Do nothing more"), ""));
        let Some(choix) = choisir(
            &lignes,
            tr!("\n  Choix (Entrée : rien) : ", "\n  Choice (Enter: nothing): "),
            "1",
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let Some(i) = choix
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .filter(|&i| i < restantes.len())
        else {
            return;
        };
        let m = restantes.remove(i);
        if !agir(&m, ctx, p) {
            restantes.insert(i, m);
        }
    }
}

/// Un identifiant d'événement tel que Vanguard les écrit (chiffres, lettres, tirets), borné : rien d'autre ne passe
/// de la ligne de commande.
fn id_d_alerte_valide(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|o| o.is_ascii_alphanumeric() || o == b'-')
}

/// La menace cherchée maintenant est-elle celle que désigne la clé d'une alerte du journal ? Celle du blocage (sa clé
/// « normale »), ou celle du veilleur (« veilleur|raison|chemin ») pour un programme au même chemin.
fn alerte_designe(m: &Menace, cle: &str) -> bool {
    if m.cle_normale() == cle || m.cle_normale_ici() == cle {
        return true;
    }
    // La surveillance rapprochée (« veilleur|rapprochee|<empreinte> ») : le même fichier.
    if let Some(e) = cle.strip_prefix("veilleur|rapprochee|") {
        return m.empreinte().is_some_and(|m| surveiller::hex(&m) == e);
    }
    let menaces::Geste::Programme { chemin: Some(c), .. } = &m.geste else {
        return false;
    };
    cle.starts_with("veilleur|") && cle.ends_with(&format!("|{}", c.to_string_lossy()))
}

/// `vanguard alerte <id>` (depuis la notification) : seul l'identifiant vient de la ligne de commande. L'alerte est
/// relue dans la partie vérifiée du journal scellé, la menace cherchée de nouveau et rejugée (`menaces::chercher`,
/// puis les garde-fous de chaque geste) : une ligne forgée, ou une menace partie, ne fait rien faire.
pub fn alerte(id: &str) {
    use crate::modele::evenement::{Genre as Quoi, Source};
    titre(tr!("Alerte", "Alert"));
    if !id_d_alerte_valide(id) {
        trp!(
            "  ✖ Identifiant d'alerte invalide : rien n'est fait.",
            "  ✖ Invalid alert identifier: nothing is done."
        );
        return;
    }
    let lu = crate::modele::journal::lire();
    let Some(ev) = lu.verifies().iter().find(|e| e.id == id) else {
        afficher_aligne(
            "  ✖ ",
            tr!(
                "Aucune alerte de cet identifiant dans la partie vérifiée du journal (vanguard evenements) : rien n'est fait.",
                "No alert with this identifier in the verified part of the log (vanguard events): nothing is done."
            ),
            4,
            "",
        );
        return;
    };
    let (Quoi::Alerte { titre: t, texte, .. }, Some(cle), Source::Blocage | Source::Veilleur) =
        (&ev.quoi, ev.cle.as_deref(), &ev.source)
    else {
        afficher_aligne(
            "  ✖ ",
            tr!(
                "Cet événement n'est pas l'alerte d'une menace du blocage ou du veilleur : rien à proposer.",
                "This event is not the alert of a blocking or watcher threat: nothing to offer."
            ),
            4,
            "",
        );
        return;
    };
    afficher_aligne("  ", &affichable(t), 2, GRAS);
    afficher_aligne("  ", &affichable(texte), 2, GRIS);
    trp!(
        "  {GRIS}Recherche de la menace, rejugée maintenant…{RESET}",
        "  {GRIS}Looking for the threat, judged again now…{RESET}"
    );
    // Une alerte du veilleur anti-rançongiciel : le processus qu'elle nomme (son numéro, ou le seul à ce chemin),
    // s'il y est encore, avec la suite « rançongiciel » (douteux : proposée, jamais faite sans la question).
    if let Some(objet) = cle.strip_prefix("veilleur|rancongiciel|") {
        match menaces::rancongiciel(objet, &ev.quand) {
            menaces::Rancon::Menace(m, intouchables) => {
                if !std::io::stdin().is_terminal() {
                    trp!(
                        "  Ses gestes se choisissent dans un terminal : vanguard alerte {id}.",
                        "  Its actions are chosen in a terminal: vanguard alert {id}."
                    );
                    return;
                }
                let ctx = Contexte::lire(intouchables, true);
                agir(&m, &ctx, &parametres());
                return;
            }
            menaces::Rancon::Choisir { pids, interpreteur } => {
                afficher_aligne("  ⚠ ", &a_choisir(&pids, interpreteur), 4, "");
                return;
            }
            menaces::Rancon::Absent => {}
        }
    }
    let t = menaces::chercher(&Categorie::TOUTES, false);
    let Some(m) = t.menaces.iter().find(|m| alerte_designe(m, cle)) else {
        afficher_aligne(
            "  ",
            tr!(
                "Cette menace n'est plus là (finie, déjà bloquée, ou tenue pour normale) : rien à faire.",
                "This threat is no longer there (ended, already blocked, or held as normal): nothing to do."
            ),
            2,
            "",
        );
        dire_non_verifie(&t.non_verifie);
        return;
    };
    if !std::io::stdin().is_terminal() {
        trp!(
            "  Ses gestes se choisissent dans un terminal : vanguard alerte {id}.",
            "  Its actions are chosen in a terminal: vanguard alert {id}."
        );
        return;
    }
    let ctx = Contexte::lire(t.intouchables.clone(), true);
    agir(m, &ctx, &parametres());
}

/// Plusieurs processus à un chemin nommé par le veilleur (ou un interpréteur) : aucun n'est pris au hasard, la
/// personne dit lequel (dix numéros au plus à l'écran).
fn a_choisir(pids: &[u32], interpreteur: bool) -> String {
    let mut liste = pids.iter().take(10).map(u32::to_string).collect::<Vec<_>>().join(", ");
    if pids.len() > 10 {
        liste.push_str(", …");
    }
    let n = pids.len();
    let pourquoi = if interpreteur {
        trf!(
            "c'est un interpréteur ({n} en marche : {liste}) : son chemin ne dit pas quel script chiffrait",
            "it is an interpreter ({n} running: {liste}): its path does not tell which script was encrypting"
        )
    } else {
        trf!(
            "{n} processus à ce chemin ({liste})",
            "{n} processes at this path ({liste})"
        )
    };
    trf!(
        "{pourquoi}. Vanguard n'en prend aucun au hasard : vérifiez lequel, puis « vanguard blocage suspendre <PID> ».",
        "{pourquoi}. Vanguard does not pick one at random: check which, then “vanguard blocking suspend <PID>”."
    )
}

/// Ce que le menu des gestes doit savoir de la menace, lu maintenant.
fn faits_de(m: &Menace, ctx: &Contexte, pret: &Result<gestes::Pret, crate::modele::Echec>) -> choix::Faits {
    let suspendre = match &m.geste {
        menaces::Geste::Programme {
            pid: Some(pid),
            chemin: Some(c),
            ..
        } => ordres::juger(
            &ordres::Ordre::SuspendreProcessus {
                pid: *pid,
                chemin: c.to_string_lossy().into_owned(),
                depart: None,
            },
            &ordres::Juge::lire(None).avec(&ctx.intouchables),
        ),
        _ => Some(tr!("aucun processus en marche à suspendre", "no running process to suspend").to_string()),
    };
    let couper_reseau = match &m.geste {
        menaces::Geste::Programme {
            pid: Some(pid),
            chemin: Some(c),
            ..
        } => match suspension::depart_de(*pid) {
            Some(depart) => ordres::juger(
                &ordres::Ordre::CouperReseauProgramme {
                    pid: *pid,
                    chemin: c.to_string_lossy().into_owned(),
                    depart,
                },
                &ordres::Juge::lire(None).avec(&ctx.intouchables),
            ),
            None => Some(tr!("le processus est fini", "the process has ended").to_string()),
        },
        _ => Some(tr!("aucun processus en marche à couper", "no running process to cut").to_string()),
    };
    choix::Faits {
        certaine: m.certaine,
        bloquer: match pret {
            Ok(p) => Ok(p.confirmera()),
            Err(e) => Err(e.to_string()),
        },
        suspendre,
        couper_reseau,
        empreinte: m.empreinte().is_some(),
        surveillance_ici: cfg!(target_os = "linux"),
    }
}

/// Le menu des gestes d'une menace, puis le geste choisi. `true` : la menace est traitée (bloquée, surveillée, tenue
/// pour normale ou ignorée) et quitte la liste ; `false` : elle y reste (rien fait, refusé, ou suspendue : Bloquer
/// reste à faire).
fn agir(m: &Menace, ctx: &Contexte, p: &Parametres) -> bool {
    let pret = gestes::preparer(m, ctx, false);
    let gestes_menu = choix::gestes(&faits_de(m, ctx, &pret));
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(format!("  {}", couper(&affichable(&m.quoi), 74))),
    ];
    // La suite de son type, proposée en tête : une touche (Entrée) pour toute la suite. Un Bloquer refusé par ses
    // garde-fous la grise aussi, avec la même raison.
    let suite = enchainer::type_de(m).map(|t| (t, p.suite(t, false)));
    let mut decalage = 0usize;
    if let Some((t, r)) = &suite {
        let precision = t.titre();
        let texte = trf!(
            "Toute la suite ({} gestes)",
            "The whole suite ({} actions)",
            r.etapes.len()
        );
        match &pret {
            Err(e) if r.etapes.contains(&suites::Etape::Bloquer) => {
                lignes.push(Ligne::Texte(format!("  {GRIS}✖  {texte}{RESET}")));
                for l in envelopper(&affichable(&e.to_string()), 68) {
                    lignes.push(Ligne::Texte(format!("      {GRIS}{l}{RESET}")));
                }
            }
            _ => {
                lignes.push(Ligne::choix("1", &texte, precision));
                decalage = 1;
            }
        }
    }
    let mut permis: Vec<(String, choix::Choix, choix::Etat)> = Vec::new();
    for (c, e) in &gestes_menu {
        if let choix::Etat::Grise(raison) = e {
            lignes.push(Ligne::Texte(format!(
                "  {GRIS}✖  {}{RESET}",
                choix::texte(*c, m.certaine)
            )));
            for l in envelopper(&affichable(raison), 68) {
                lignes.push(Ligne::Texte(format!("      {GRIS}{l}{RESET}")));
            }
            continue;
        }
        let touche = permis.len().saturating_add(1).saturating_add(decalage).to_string();
        lignes.push(Ligne::choix(
            &touche,
            choix::texte(*c, m.certaine),
            choix::precision(*c, e),
        ));
        permis.push((touche, *c, e.clone()));
    }
    let Some(reponse) = choisir(
        &lignes,
        tr!(
            "\n  Geste (Entrée : le premier) : ",
            "\n  Action (Enter: the first one): "
        ),
        "1",
        tr!("revenir", "back"),
    ) else {
        return false;
    };
    let reponse = reponse.trim();
    let reponse = if reponse.is_empty() { "1" } else { reponse };
    if decalage == 1
        && reponse == "1"
        && let Some((t, r)) = suite
    {
        return toute_la_suite(m, ctx, t, &r, pret);
    }
    let Some((_, c, etat)) = permis.into_iter().find(|(t, _, _)| t == reponse) else {
        return false;
    };
    if let choix::Etat::Confirmer(raison) = &etat {
        afficher_aligne("  ", &affichable(raison), 2, GRIS);
    }
    match c {
        choix::Choix::Bloquer => match pret {
            Ok(p) => bloquer(m, p),
            Err(e) => {
                trp!("  ✖ {e}", "  ✖ {e}");
                false
            }
        },
        choix::Choix::Suspendre => suspendre_la_menace(m),
        choix::Choix::CouperReseau => couper_le_reseau_de_la_menace(m),
        choix::Choix::Surveiller => surveiller_la_menace(m),
        choix::Choix::Confiance if m.certaine => faire_confiance(m),
        choix::Choix::Confiance => declarer_normale(m),
        choix::Choix::Ignorer => {
            trp!(
                "  Ignorée pour cette fois : le prochain bilan la montrera de nouveau.",
                "  Ignored this time: the next check will show it again."
            );
            true
        }
    }
}

/// Toute la suite d'un type, proposée : chaque geste montré, fait ou sauté (avec pourquoi), le détail du blocage,
/// puis une seule question pour toute la suite. `true` : la menace est traitée (bloquée, ou mise sous surveillance
/// sans blocage dans la suite) ; une suspension seule la laisse dans la liste, Bloquer reste à faire.
fn toute_la_suite(
    m: &Menace,
    ctx: &Contexte,
    t: suites::Type,
    retenue: &suites::Retenue,
    pret: Result<gestes::Pret, crate::modele::Echec>,
) -> bool {
    println!();
    afficher_aligne("  ", &trf!("Suite « {} »", "“{}” suite", t.titre()), 2, GRAS);
    if let Some(d) = &retenue.dit {
        afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Moyen)),
            &capitaliser(d),
            4,
            "",
        );
    }
    let releve = enchainer::avant(m);
    for (i, (e, plan)) in enchainer::plan(&retenue.etapes, &releve, pret.is_ok())
        .iter()
        .enumerate()
    {
        let n = i.saturating_add(1);
        let (texte, gris) = match plan {
            suites::Plan::Faire => (e.texte().to_string(), false),
            suites::Plan::AvecBloquer(pourquoi) => (format!("{} : {pourquoi}", e.texte()), false),
            suites::Plan::SansObjet(pourquoi) => (
                trf!("{} : sauté, {pourquoi}", "{}: skipped, {pourquoi}", e.texte()),
                true,
            ),
        };
        afficher_aligne(&format!("    {n}. "), &texte, 7, if gris { GRIS } else { "" });
        if *e == suites::Etape::Suspendre
            && *plan == suites::Plan::Faire
            && let menaces::Geste::Programme {
                pid: Some(pid),
                chemin: Some(c),
                ..
            } = &m.geste
            && let Some(role) = suspension::role(*pid, &c.to_string_lossy())
        {
            afficher_aligne(
                "       ",
                &trf!(
                    "C'est {role} : il ne sera pas suspendu dans la suite (Suspendre, à part, le montre et le confirme).",
                    "This is {role}: it will not be suspended in the suite (Suspend, on its own, shows and confirms it)."
                ),
                7,
                GRIS,
            );
        }
    }
    match &pret {
        Ok(p) if retenue.etapes.contains(&suites::Etape::Bloquer) => montrer(m, p),
        Err(e) if retenue.etapes.contains(&suites::Etape::Bloquer) => {
            afficher_aligne("  ✖ ", &trf!("Bloquer : {e}", "Block: {e}"), 4, "");
        }
        _ => {}
    }
    afficher_aligne(
        "  ",
        tr!(
            "Chaque geste est noté et s'annule à part (vanguard blocage annuler ; reprendre pour une suspension ; rendre-reseau pour une coupure du réseau).",
            "Each action is noted and undone on its own (vanguard blocking undo; resume for a suspension; restore-network for a network cut)."
        ),
        2,
        GRIS,
    );
    if !demander(tr!(
        "\n  Faire toute la suite ? [o/N] : ",
        "\n  Run the whole suite? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a été fait.", "  Nothing was done.");
        return false;
    }
    let d = enchainer::derouler(m, &retenue.etapes, ctx, false, pret, &mut |d| {
        let (titre, texte) = alerte_de_la_suite(m, d, retenue.dit.as_deref());
        alerter_blocage(m, titre, &texte);
        enchainer::Issue::Fait(tr!("notification et tableau de bord", "notification and dashboard").to_string())
    });
    for (e, i) in &d.issues {
        let marque = match i {
            enchainer::Issue::Fait(_) | enchainer::Issue::AvecBloquer(_) => format!("  {VERT}✔{RESET} "),
            enchainer::Issue::Saute(_) => format!("  {GRIS}–{RESET} "),
            enchainer::Issue::Echoue(_) => format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)),
        };
        afficher_aligne(&marque, &affichable(&i.phrase(*e)), 4, "");
    }
    matches!(d.bloque, Some(Ok(_)))
        || (d.bloque.is_none()
            && d.issues
                .iter()
                .any(|(e, i)| *e == suites::Etape::Surveiller && matches!(i, enchainer::Issue::Fait(_))))
}

/// Bloquer : le geste montré, puis fait après accord.
fn bloquer(m: &Menace, pret: gestes::Pret) -> bool {
    montrer(m, &pret);
    if !demander(tr!("\n  Bloquer ? [o/N] : ", "\n  Block? [y/N]: ")).oui() {
        trp!("  Rien n'a été fait.", "  Nothing was done.");
        return false;
    }
    match gestes::faire(m, pret, false) {
        Ok(f) if f.verifie => trp!(
            "  {VERT}✔{RESET} Bloqué. Pour annuler : vanguard blocage annuler.",
            "  {VERT}✔{RESET} Blocked. To undo: vanguard blocking undo."
        ),
        Ok(f) => afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Moyen)),
            &trf!(
                "Non vérifié : {f}. Pour retirer la règle : vanguard blocage annuler.",
                "Not verified: {f}. To remove the rule: vanguard blocking undo."
            ),
            4,
            "",
        ),
        Err(e) => {
            trp!("  ✖ {e}", "  ✖ {e}");
            return false;
        }
    }
    true
}

/// Suspendre : montré, confirmé, puis fait sous les gardes du gel (rejugées juste avant). La menace reste dans la
/// liste : Bloquer peut suivre.
fn suspendre_la_menace(m: &Menace) -> bool {
    let menaces::Geste::Programme {
        pid: Some(pid),
        chemin: Some(chemin),
        nom,
        ..
    } = &m.geste
    else {
        return false;
    };
    let chemin = chemin.to_string_lossy();
    if !confirmer_la_suspension(*pid, nom, &chemin) {
        return false;
    }
    let intouchables = crate::machine::chasse::en_marche().map_or_else(HashSet::new, |(_, i)| i);
    match suspension::suspendre(
        *pid,
        &chemin,
        &m.quoi,
        Some(&m.cle_normale()),
        &intouchables,
        crate::modele::evenement::Source::Utilisateur,
    ) {
        Ok(()) => trp!(
            "  {VERT}✔{RESET} Suspendu. Pour le reprendre : vanguard blocage reprendre {pid} ; pour l'arrêter : Bloquer.",
            "  {VERT}✔{RESET} Suspended. To resume it: vanguard blocking resume {pid}; to stop it: Block."
        ),
        Err(e) => trp!("  ✖ {e}", "  ✖ {e}"),
    }
    false
}

/// Couper son réseau : montré, confirmé, puis fait sous les gardes de la coupure (rejugées juste avant, puis par
/// l'élevé). La menace reste dans la liste : Bloquer peut suivre.
fn couper_le_reseau_de_la_menace(m: &Menace) -> bool {
    let menaces::Geste::Programme {
        pid: Some(pid),
        chemin: Some(chemin),
        nom,
        ..
    } = &m.geste
    else {
        return false;
    };
    let chemin = chemin.to_string_lossy();
    if !confirmer_la_coupure(*pid, nom, &chemin) {
        return false;
    }
    let intouchables = crate::machine::chasse::en_marche().map_or_else(HashSet::new, |(_, i)| i);
    match coupure::couper(
        *pid,
        &chemin,
        &m.quoi,
        Some(&m.cle_normale()),
        &intouchables,
        crate::modele::evenement::Source::Utilisateur,
    ) {
        Ok(c) => dire_coupe(*pid, &c),
        Err(e) => trp!("  ✖ {e}", "  ✖ {e}"),
    }
    false
}

/// Ce que suspendre fait et ne fait pas, le rôle d'un programme du système nommé, puis la question : `true` si la
/// personne confirme.
fn confirmer_la_suspension(pid: u32, nom: &str, chemin: &str) -> bool {
    afficher_aligne(
        "  ",
        &trf!(
            "Suspendre « {} » (PID {pid}) : il ne fait plus rien mais reste là (fichiers, mémoire), le temps de regarder. Rien n'est effacé ; « vanguard blocage reprendre {pid} » le relance. Seul ce processus est suspendu : les programmes qu'il a déjà lancés (ses enfants) continuent. Un autre programme peut le reprendre (sous Linux, tout processus du même compte peut envoyer SIGCONT ; un administrateur aussi) : le bilan le revoit et le suspend de nouveau si ce compte en a les droits, sinon il le dit.",
            "Suspend “{}” (PID {pid}): it does nothing more but stays there (files, memory), while you look. Nothing is deleted; “vanguard blocking resume {pid}” starts it again. Only this process is suspended: the programs it already started (its children) keep running. Another program can resume it (on Linux, any process of the same account can send SIGCONT; an administrator too): the check sees it and suspends it again if this account has the rights, otherwise it says so.",
            affichable(nom)
        ),
        2,
        "",
    );
    let Some(role) = suspension::role(pid, chemin) else {
        return demander(tr!("\n  Suspendre ? [o/N] : ", "\n  Suspend? [y/N]: ")).oui();
    };
    afficher_aligne(
        &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
        &trf!(
            "C'est {role} : tant qu'il est suspendu, ce qu'il fait pour l'ordinateur s'arrête aussi.",
            "This is {role}: while it is suspended, what it does for the computer stops too."
        ),
        4,
        "",
    );
    demander(&trf!(
        "\n  Suspendre {role} quand même ? [o/N] : ",
        "\n  Suspend {role} anyway? [y/N]: "
    ))
    .oui()
}

/// Surveiller de plus près : 7 jours, une alerte quand il se lance, au plus une par heure (le veilleur Linux).
fn surveiller_la_menace(m: &Menace) -> bool {
    let (Some(fichier), Some(empreinte)) = (m.fichier_du_programme(), m.empreinte()) else {
        return false;
    };
    match surveiller::ajouter(&fichier.to_string_lossy(), &empreinte, &m.quoi) {
        Ok(fin) => {
            afficher_aligne(
                &format!("  {VERT}✔{RESET} "),
                &trf!(
                    "Surveillé de près jusqu'au {fin} : le veilleur alerte quand il se lance, au plus une fois par heure (s'il est en marche : vanguard veilleur). Rien n'est arrêté.",
                    "Watched closely until {fin}: the watcher alerts when it starts, at most once per hour (if it is running: vanguard watcher). Nothing is stopped."
                ),
                4,
                "",
            );
            true
        }
        Err(e) => {
            trp!("  ✖ {e}", "  ✖ {e}");
            false
        }
    }
}

/// Un douteux : c'est normal ici, 90 jours.
fn declarer_normale(m: &Menace) -> bool {
    match crate::protection::normales::declarer(
        &m.cle_normale_ici(),
        crate::reseau::tableau::nom_genre(Genre::Blocage),
        tr!("Menace déclarée normale", "Threat declared normal"),
        &m.quoi,
    ) {
        Ok(()) => {
            afficher_aligne(
                "  ",
                tr!(
                    "Retenu pour 90 jours : ni proposée ni bloquée (Ce que Vanguard a appris l'oublie).",
                    "Saved for 90 days: neither offered nor blocked (What Vanguard has learned forgets it)."
                ),
                2,
                GRIS,
            );
            true
        }
        Err(e) => {
            afficher_aligne(
                "  ✖ ",
                &trf!("Rien n'est retenu : {e}.", "Nothing is saved: {e}."),
                4,
                "",
            );
            false
        }
    }
}

/// Un certain (P5) : faire confiance à CE fichier, par son empreinte relue maintenant, 90 jours, sur un mot tapé. Le
/// même chemin réécrit par un autre fichier n'en profite pas.
fn faire_confiance(m: &Menace) -> bool {
    let (Some(fichier), Some(empreinte)) = (m.fichier_du_programme(), m.empreinte()) else {
        return false;
    };
    let hex = surveiller::hex(&empreinte);
    afficher_aligne(
        &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
        &trf!(
            "Ce fichier est un logiciel malveillant CONNU ({}). Déconseillé : lui faire confiance, c'est le laisser tourner, ni proposé, ni bloqué, ni arrêté par le veilleur pendant 90 jours. Seulement ce fichier-là : « {} », empreinte {}…{}.",
            "This file is KNOWN malware ({}). Not recommended: trusting it lets it run, neither offered, nor blocked, nor stopped by the watcher for 90 days. Only this exact file: “{}”, fingerprint {}…{}.",
            affichable(&m.quoi),
            chemin_affichable(fichier),
            hex.get(..12).unwrap_or(&hex),
            hex.get(hex.len().saturating_sub(4)..).unwrap_or_default()
        ),
        4,
        "",
    );
    let mot = choix::mot_de_confiance();
    let reponse = demander(&trf!(
        "\n  Pour lui faire confiance, tapez {mot} (Entrée : non) : ",
        "\n  To trust it, type {mot} (Enter: no): "
    ));
    if !choix::confiance_tapee(&reponse) {
        trp!("  Rien n'a été fait.", "  Nothing was done.");
        return false;
    }
    // Relue après la réponse : un fichier changé pendant la question n'hérite pas de la confiance.
    if m.empreinte() != Some(empreinte) {
        trp!(
            "  ✖ Le fichier a changé pendant la question : rien n'est retenu.",
            "  ✖ The file changed during the question: nothing is saved."
        );
        return false;
    }
    match crate::protection::normales::declarer(
        &choix::cle_confiance(&empreinte),
        crate::reseau::tableau::nom_genre(Genre::Blocage),
        tr!(
            "Confiance accordée à un fichier certain",
            "Trust given to a certain file"
        ),
        &m.quoi,
    ) {
        Ok(()) => {
            afficher_aligne(
                "  ",
                tr!(
                    "Retenu pour 90 jours, pour ce fichier précis (Ce que Vanguard a appris l'oublie).",
                    "Saved for 90 days, for this exact file (What Vanguard has learned forgets it)."
                ),
                2,
                GRIS,
            );
            true
        }
        Err(e) => {
            afficher_aligne(
                "  ✖ ",
                &trf!("Rien n'est retenu : {e}.", "Nothing is saved: {e}."),
                4,
                "",
            );
            false
        }
    }
}

/// Ce que l'annulation va faire, en une phrase.
fn decrire_annulation(a: &Annulation) -> String {
    match a {
        // Ce qui sera vraiment lancé : refait depuis la note, pas les chaînes relues (`gestes::commandes_d_annulation`).
        Annulation::Commandes {
            commandes,
            port,
            inverse,
        } => match gestes::commandes_d_annulation(commandes, port.as_deref(), *inverse) {
            Some((commandes, _)) => trf!(
                "Lancer : {}",
                "Run: {}",
                commandes
                    .iter()
                    .map(|c| commande_montree(c))
                    .collect::<Vec<_>>()
                    .join(" ; ")
            ),
            None => gestes::refus_d_annulation(commandes),
        },
        Annulation::Quarantaine { .. } => tr!(
            "Remettre le fichier exactement où il était, depuis la quarantaine (le programme ne se relance pas tout seul)",
            "Put the file back exactly where it was, from the quarantine (the program does not restart by itself)"
        )
        .to_string(),
        Annulation::Copie { fichier, copie, .. }
            if !gestes::copie_admise(std::path::Path::new(fichier), std::path::Path::new(copie)) =>
        {
            gestes::refus_de_copie(std::path::Path::new(fichier), std::path::Path::new(copie))
        }
        Annulation::Copie { fichier, .. } => trf!(
            "Remettre la copie d'avant de {}, seulement s'il n'a pas changé depuis",
            "Put back the previous copy of {}, only if it has not changed since",
            affichable(fichier)
        ),
        Annulation::Demarrage { .. } => tr!(
            "Remettre le programme au démarrage, exactement comme avant",
            "Put the program back at startup, exactly as before"
        )
        .to_string(),
    }
}

/// `vanguard blocage annuler` : les blocages en place, du plus récent au plus ancien ; celui qu'on choisit est défait
/// exactement, après accord.
pub fn annuler() {
    titre(tr!("Annuler un blocage", "Undo a block"));
    // L'isolement d'abord (Défense R4) : c'est lui qui coupe le plus, et sa levée doit se trouver sans chercher.
    if let Some(b) = crate::protection::isolement::banniere() {
        afficher_aligne("  ⚠ ", &b, 4, "");
        crate::protection::isolement::lever_avec_accord();
        println!();
    }
    loop {
        let mut liste = crate::changements::blocages_en_place();
        liste.reverse();
        if liste.is_empty() {
            trp!(
                "  Aucun blocage en place : rien à annuler.",
                "  No block in place: nothing to undo."
            );
            return;
        }
        let mut lignes = vec![Ligne::Texte(String::new())];
        for (i, (date, b)) in liste.iter().enumerate() {
            lignes.push(Ligne::choix(
                &i.saturating_add(1).to_string(),
                &couper(&affichable(&b.quoi), 52),
                date,
            ));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        let Some(choix) = choisir(
            &lignes,
            tr!("\n  Numéro (Entrée pour revenir) : ", "\n  Number (Enter to go back): "),
            "1",
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let Some((_, b)) = choix
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| liste.get(n.checked_sub(1)?))
        else {
            return;
        };
        println!();
        afficher_aligne("  ", &affichable(&b.quoi), 2, GRAS);
        if let Some(refus) = crate::changements::refus_d_origine(b) {
            afficher_aligne("    → ", &refus, 6, "");
        } else if let Some(a) = &b.annulation {
            afficher_aligne("    → ", &decrire_annulation(a), 6, "");
        }
        if !demander(tr!("\n  Annuler ce blocage ? [o/N] : ", "\n  Undo this block? [y/N]: ")).oui() {
            trp!("  Rien n'a été fait.", "  Nothing was done.");
            continue;
        }
        match gestes::defaire(b) {
            Ok(_) => trp!("  {VERT}✔{RESET} Annulé.", "  {VERT}✔{RESET} Undone."),
            Err(e) => trp!("  ✖ {e}", "  ✖ {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plusieurs processus à choisir : leurs numéros (dix au plus) et la commande pour dire lequel, l'interpréteur
    /// dit comme tel.
    #[test]
    fn a_choisir_dit_les_numeros() {
        let t = a_choisir(&[14, 15], false);
        assert!(t.contains("14, 15") && t.contains("suspend"), "{t}");
        let beaucoup: Vec<u32> = (1..=12).collect();
        let t = a_choisir(&beaucoup, true);
        assert!(t.contains("10, …") && !t.contains("11"), "{t}");
        assert!(t.contains("12"), "{t}");
    }

    /// Bloquer refusé d'avance (sans administrateur) : la première passe horaire fait la suite (preuve, action,
    /// alerte), les suivantes la taisent toute, sinon preuve et action reviendraient au journal chaque heure.
    #[test]
    fn refus_redit_une_seule_fois() {
        let cle = "adresse:203.0.113.9";
        let avant = BTreeSet::new();
        let mut premiere = BTreeSet::new();
        assert!(!deja_refusee(cle, &mut Some((&avant, &mut premiere))));
        assert!(premiere.contains(cle));
        let mut seconde = BTreeSet::new();
        assert!(deja_refusee(cle, &mut Some((&premiere, &mut seconde))));
        // Toujours notée : à la troisième heure aussi, elle reste tue.
        assert!(seconde.contains(cle));
        // Hors surveillance (pas de liste), jamais tue.
        assert!(!deja_refusee(cle, &mut None));
    }

    /// Une clé de menace ajoutée hors de Vanguard aux menaces déjà signalées ne tait plus l'échec de son blocage :
    /// le fichier changé sans sceau se lit vide, et la menace est redite.
    #[test]
    fn cle_ajoutee_hors_de_vanguard_ne_tait_plus_l_echec() {
        let d = crate::essais::temporaire().join(format!("vanguard-blocage-signalees-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let lu = || signalees_lues(crate::sceau::juge_dans(&d, crate::sceau::BLOCAGE_SIGNALEES));
        crate::sceau::ecrire_dans(&d, crate::sceau::BLOCAGE_SIGNALEES, b"fichier:/home/alice/a").unwrap();
        assert!(lu().contains("fichier:/home/alice/a"));
        std::fs::write(
            d.join(crate::sceau::BLOCAGE_SIGNALEES),
            "fichier:/home/alice/a\nfichier:/home/alice/.local/bin/x",
        )
        .unwrap();
        assert!(lu().is_empty());
        // S2c : acceptée telle quelle après des sceaux refaits, elle ne tait rien non plus.
        std::fs::remove_file(d.join("sceaux.json")).unwrap();
        assert!(lu().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// En administrateur, l'accord et les « automatique » de blocage.json (que tout processus du compte peut écrire)
    /// ne font rien bloquer tout seul : le certain se propose d'un clic. Hors administrateur, ils comptent.
    #[test]
    fn en_administrateur_rien_tout_seul() {
        let mut p = Parametres {
            accord: Some("x".into()),
            ..Parametres::default()
        };
        p.regler(Categorie::Programmes, Mode::Automatique).unwrap();
        p.regler(Categorie::Connexions, Mode::Automatique).unwrap();
        let compte = pour_agir(p.clone(), false);
        assert!(compte.actif());
        assert_eq!(decider(&compte, Categorie::Connexions, true), Decision::Auto);
        let admin = pour_agir(p, true);
        assert!(!admin.actif());
        for c in [Categorie::Programmes, Categorie::Connexions] {
            assert_eq!(decider(&admin, c, true), Decision::UnClic, "{c:?}");
            assert_eq!(decider(&admin, c, false), Decision::UnClic, "{c:?}");
        }
        // Ce qui est désactivé le reste, et ce qui se cherche se cherche encore.
        let mut p = admin;
        p.regler(Categorie::AgentsIa, Mode::Desactive).unwrap();
        let admin = pour_agir(p, true);
        assert_eq!(decider(&admin, Categorie::AgentsIa, true), Decision::Rien);
        assert_eq!(categories_actives(&admin).len(), 3);
    }

    /// La ligne du menu : la protection active en pause quand le temps réel est coupé, pas « protection active ».
    #[test]
    fn ligne_du_menu_pendant_une_coupure() {
        let mut p = Parametres {
            accord: Some("x".into()),
            ..Parametres::default()
        };
        p.regler(Categorie::Programmes, Mode::Automatique).unwrap();
        assert_eq!(
            etat_court_de(Ok(p.clone()), false),
            tr!("protection active", "active protection")
        );
        let pause = etat_court_de(Ok(p), true);
        assert_eq!(pause, tr!("en pause (temps réel coupé)", "paused (real-time off)"));
        assert!(crate::ui::largeur_affichee(pause) <= 33);
        // Sans protection active, la coupure ne change rien à la ligne.
        assert_eq!(
            etat_court_de(Ok(Parametres::default()), true),
            etat_court_de(Ok(Parametres::default()), false)
        );
        assert_eq!(
            etat_court_de(
                Err(crate::modele::Echec::new(
                    "essai",
                    crate::modele::Raison::Illisible("x".into())
                )),
                true
            ),
            tr!("réglages illisibles", "settings unreadable")
        );
    }
}
