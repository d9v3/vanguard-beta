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

mod arret;
mod gardes;
pub(crate) mod gestes;
mod menaces;
pub(crate) mod ordres;
pub(crate) mod parametres;
pub(crate) mod pare_feu;

use std::collections::BTreeSet;
use std::io::IsTerminal;

use gestes::Contexte;
pub(crate) use gestes::chemin_du_processus;
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
                "blocage.json {raison} : les catégories qu'il désactivait restent sur « un clic », et son accord à la protection active ne fait rien bloquer sans clic. Réglez-les de nouveau ici si c'est bien votre choix.",
                "blocage.json {raison}: the categories it turned off stay on “one click”, and its consent to active protection blocks nothing without a click. Set them again here if that really is your choice."
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
/// active ; ou une catégorie suivie d'un mode (« connexions auto »).
pub fn commande(mots: &[String]) {
    let mots: Vec<&str> = mots.iter().map(String::as_str).collect();
    match mots.as_slice() {
        [] => menu(),
        [m] if est(m, &["chercher", "scan", "search", "maintenant", "now"]) => chercher_et_proposer(),
        [m] if est(m, &["annuler", "undo", "defaire", "défaire"]) => annuler(),
        [m] if est(m, &["etat", "état", "status", "state"]) => afficher_etat(&parametres()),
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
        "  Usage : vanguard blocage [chercher | annuler | etat | auto | clic | <catégorie> <mode>]\n  Catégories : {categories}. Modes : off, clic, auto (programmes et connexions seulement).",
        "  Usage: vanguard blocking [search | undo | status | auto | click | <category> <mode>]\n  Categories: {categories}. Modes: off, click, auto (programs and connections only)."
    );
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
            lignes.push(Ligne::choix(&(i + 1).to_string(), c.titre(), p.effectif(*c).libelle()));
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
        lignes.push(Ligne::choix(&(i + 1).to_string(), m.libelle(), precision));
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
    proposer(t.menaces, &ctx);
    dire_normales(t.normales);
    dire_non_verifie(&t.non_verifie);
}

/// Au bilan : le certain des catégories automatiques est bloqué tout seul (jamais en administrateur ni la protection
/// en temps réel coupée, voir `pour_agir`), puis chaque autre menace propose « Bloquer » (dans un terminal ; sinon
/// elle est seulement dite, sans question).
pub fn au_bilan() {
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
        bloquer_tout_seul(m, &ctx, None);
    }
    if interactif {
        proposer(un_clic, &ctx);
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

/// Bloque une menace certaine sans rien demander, puis prévient (notification et tableau de bord). `signalees` : en
/// surveillance, les menaces déjà dites non bloquées au passage d'avant, pour ne pas le répéter chaque heure ; elle
/// y ajoute celle-ci si elle reste non bloquée.
fn bloquer_tout_seul(m: &Menace, ctx: &Contexte, signalees: Option<(&BTreeSet<String>, &mut BTreeSet<String>)>) {
    let resultat = gestes::preparer(m, ctx, true).and_then(|pret| {
        if ctx.interactif {
            montrer(m, &pret);
        }
        gestes::faire(m, pret, true)
    });
    match resultat {
        Ok(fait) => {
            let quoi = &fait.quoi;
            if ctx.interactif {
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
            let titre = if fait.verifie {
                tr!("Vanguard a bloqué une menace", "Vanguard blocked a threat")
            } else {
                tr!(
                    "Vanguard a posé une règle sans pouvoir la vérifier",
                    "Vanguard added a rule without being able to verify it"
                )
            };
            alerter_blocage(
                m,
                titre,
                &trf!(
                    "{quoi}. Pour annuler : vanguard blocage annuler.",
                    "{quoi}. To undo: vanguard blocking undo."
                ),
            );
        }
        Err(raison) => {
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
            if nouvelle {
                alerter_blocage(
                    m,
                    tr!("Vanguard n'a pas pu bloquer", "Vanguard could not block"),
                    &trf!("{} : {raison}", "{}: {raison}", m.quoi),
                );
            }
        }
    }
}

/// L'alerte d'un blocage fait tout seul, ou manqué. Une menace certaine n'est jamais tue (`menaces::chercher`) :
/// son alerte non plus, même si sa clé a été déclarée normale, sans quoi elle serait bloquée sans que personne le
/// sache.
///
/// L'alerte est reliée, dans le journal des événements, au geste qu'elle annonce (ou à son échec, noté aussi) : le
/// fil va de l'alerte de détection à la preuve, au geste, puis à cette alerte, au lieu d'alertes sans lien.
fn alerter_blocage(m: &Menace, titre: &str, texte: &str) {
    let cle = m.cle_normale();
    if !m.certaine && crate::protection::normales::est_normale(&cle) {
        return;
    }
    let geste = crate::modele::journal::dernier(
        |e| {
            matches!(e.quoi, crate::modele::evenement::Genre::Action { .. }) && e.cle.as_deref() == Some(m.cle.as_str())
        },
        chrono::Duration::minutes(10),
    );
    crate::reseau::tableau::noter_alerte_liee(Genre::Blocage, Some(&cle), geste.as_deref(), titre, texte);
    crate::reseau::surveillance::notifier(titre, texte);
}

/// Les menaces déjà signalées comme non bloquées, d'après les sceaux : intactes ou adoptées, leurs clés ; changées
/// hors de Vanguard, inconnues ou illisibles, aucune, pour que tout soit redit (une clé ajoutée par un programme du
/// compte taisait l'échec de son propre blocage).
fn signalees_lues(lu: crate::sceau::Lecture) -> BTreeSet<String> {
    use crate::sceau::Lecture;
    match lu {
        Lecture::Intact(o) | Lecture::Adopte(o) => String::from_utf8_lossy(&o).lines().map(str::to_string).collect(),
        _ => BTreeSet::new(),
    }
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
    let avant = signalees_lues(crate::sceau::lire(crate::sceau::BLOCAGE_SIGNALEES));
    let mut maintenant = BTreeSet::new();
    for m in t
        .menaces
        .iter()
        .filter(|m| decider(&p, m.categorie, m.certaine) == Decision::Auto)
    {
        bloquer_tout_seul(m, &ctx, Some((&avant, &mut maintenant)));
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

/// Chaque menace propose « Bloquer » : choisie, son geste est montré, puis fait après accord. Ce que les garde-fous
/// refusent d'avance reste une alerte, avec sa raison.
fn proposer(menaces: Vec<Menace>, ctx: &Contexte) {
    let mut restantes: Vec<Menace> = Vec::new();
    let mut refusees = 0;
    for m in menaces {
        match gestes::preparer(&m, ctx, false) {
            Ok(_) => restantes.push(m),
            Err(r) => {
                refusees += 1;
                afficher_aligne(
                    &format!("  {}ℹ{RESET} ", couleur(crate::risk::Niveau::Info)),
                    &m.quoi,
                    4,
                    "",
                );
                afficher_aligne("    ", &trf!("Alerte seulement : {r}", "Alert only: {r}"), 4, GRIS);
            }
        }
    }
    if restantes.is_empty() {
        if refusees == 0 {
            trp!(
                "  {VERT}✔{RESET} Aucune menace à bloquer.",
                "  {VERT}✔{RESET} No threat to block."
            );
        }
        return;
    }
    loop {
        if restantes.is_empty() {
            return;
        }
        let mut lignes = vec![
            Ligne::Texte(String::new()),
            Ligne::Texte(trf!(
                "  {GRIS}Choisissez une menace : son geste est montré avant d'être fait.{RESET}",
                "  {GRIS}Pick a threat: its action is shown before it is done.{RESET}"
            )),
        ];
        for (i, m) in restantes.iter().enumerate() {
            let texte = couper(&trf!("Bloquer : {}", "Block: {}", m.quoi), 52);
            let precision = if m.certaine {
                tr!("certain", "certain")
            } else {
                tr!("douteux", "doubtful")
            };
            lignes.push(Ligne::choix(&(i + 1).to_string(), &texte, precision));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix(
            "↵",
            tr!("Ne rien bloquer de plus", "Block nothing more"),
            "",
        ));
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
        let pret = match gestes::preparer(&m, ctx, false) {
            Ok(p) => p,
            Err(raison) => {
                trp!("  ✖ {raison}", "  ✖ {raison}");
                continue;
            }
        };
        montrer(&m, &pret);
        // Une menace certaine ne se tait jamais (`menaces::chercher`) : « c'est normal » ne lui est pas proposé.
        let reponse = demander(if m.certaine {
            tr!("\n  Bloquer ? [o/N] : ", "\n  Block? [y/N]: ")
        } else {
            tr!(
                "\n  Bloquer ? [o/N] ; « i » : c'est normal ici (90 jours) : ",
                "\n  Block? [y/N]; “i”: this is normal here (90 days): "
            )
        });
        if !m.certaine && reponse.trim().eq_ignore_ascii_case("i") {
            match crate::protection::normales::declarer(
                &m.cle_normale(),
                crate::reseau::tableau::nom_genre(Genre::Blocage),
                tr!("Menace déclarée normale", "Threat declared normal"),
                &m.quoi,
            ) {
                Ok(()) => afficher_aligne(
                    "  ",
                    tr!(
                        "Retenu pour 90 jours : ni proposée ni bloquée (Ce que Vanguard a appris l'oublie).",
                        "Saved for 90 days: neither offered nor blocked (What Vanguard has learned forgets it)."
                    ),
                    2,
                    GRIS,
                ),
                Err(e) => afficher_aligne(
                    "  ✖ ",
                    &trf!("Rien n'est retenu : {e}.", "Nothing is saved: {e}."),
                    4,
                    "",
                ),
            }
            continue;
        }
        if !reponse.oui() {
            trp!("  Rien n'a été fait.", "  Nothing was done.");
            restantes.insert(i, m);
            continue;
        }
        match gestes::faire(&m, pret, false) {
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
            Err(e) => trp!("  ✖ {e}", "  ✖ {e}"),
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
                &(i + 1).to_string(),
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

    /// Une clé de menace ajoutée hors de Vanguard aux menaces déjà signalées ne tait plus l'échec de son blocage :
    /// le fichier changé sans sceau se lit vide, et la menace est redite.
    #[test]
    fn cle_ajoutee_hors_de_vanguard_ne_tait_plus_l_echec() {
        let d = std::env::temp_dir().join(format!("vanguard-blocage-signalees-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let lu = || signalees_lues(crate::sceau::lire_dans(&d, crate::sceau::BLOCAGE_SIGNALEES));
        crate::sceau::ecrire_dans(&d, crate::sceau::BLOCAGE_SIGNALEES, b"fichier:/home/alice/a").unwrap();
        assert!(lu().contains("fichier:/home/alice/a"));
        std::fs::write(
            d.join(crate::sceau::BLOCAGE_SIGNALEES),
            "fichier:/home/alice/a\nfichier:/home/alice/.local/bin/x",
        )
        .unwrap();
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
