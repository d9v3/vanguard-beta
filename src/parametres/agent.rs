//! Paramètres › Agent Vanguard (sans IA) › ses missions et son journal : un interrupteur par mission (scellé, dans
//! `agent/agent.json`, par `agent::couper_dans`), et le journal en lecture seule, le plus récent d'abord. Tout ce qui
//! se montre vient de `agent::sortie`, la vue que `vanguard agent --json` donne aussi : des noms de la liste fermée,
//! des identifiants de règle, des nombres et des dates, mis en phrases ici.

use crate::agent::sortie::{self, EtatMission, Fichier, MissionVue, Pourquoi, Sorte, Vue};
use crate::agent::{Decision, Levier, MissionId};
use crate::ui::*;

/// Le journal montré au plus, le plus récent d'abord.
const JOURNAL_MAX: usize = 40;

/// Le nom d'une mission, tel qu'à l'écran.
pub(crate) fn nom(id: MissionId) -> &'static str {
    match id {
        MissionId::Reglage => tr!("Délais et seconds essais", "Time limits and second attempts"),
        MissionId::Cache => tr!("Cache du passage horaire", "Hourly pass cache"),
        MissionId::Releve => tr!("Relevé local", "Local record"),
        MissionId::Corrections => tr!("Avis sur les corrections", "Notes on fixes"),
    }
}

/// Ce que fait la mission, et ce que la couper change.
fn role(id: MissionId) -> &'static str {
    match id {
        MissionId::Reglage => tr!(
            "Monte le délai d'une règle qui le frôle, et donne un second essai à celle qui conclut d'ordinaire au bilan suivant. Coupée : plus rien ne monte ; ce qui l'est déjà reste, et s'annule dans l'écran d'avant.",
            "Raises the time limit of a rule that comes close to it, and gives a second attempt to one that usually concludes at the next check. Off: nothing goes up any more; what already did stays, and can be undone on the previous screen."
        ),
        MissionId::Cache => tr!(
            "Règle combien de temps le passage horaire reprend le résultat de quelques vérifications lentes. Coupée : le passage horaire ne reprend plus rien et vérifie tout à neuf.",
            "Sets how long the hourly pass reuses the result of a few slow checks. Off: the hourly pass reuses nothing and checks everything afresh."
        ),
        MissionId::Releve => tr!(
            "Passe la main au relevé local, celui que le partage avec l'auteur peut envoyer. Coupée ici : plus rien n'est noté, mais ce qui l'est déjà reste sur cet ordinateur, et partira encore si le partage est à « oui », le jour où le relais de l'auteur sera en service. « Non » dans Paramètres › Partage avec l'auteur, au contraire, arrête le relevé et l'efface.",
            "Hands over to the local record, the one sharing with the author can send. Off here: nothing more is noted, but what already is stays on this computer, and will still be sent if sharing is “yes”, once the author's relay is in service. “No” in Settings › Sharing with the author, on the other hand, stops the record and erases it."
        ),
        MissionId::Corrections => tr!(
            "Montre une correction qui échoue souvent, ou un problème qui revient après elle. Coupée : plus aucun avis ; les corrections elles-mêmes ne changent pas.",
            "Shows a fix that often fails, or a problem that comes back after it. Off: no more notes; the fixes themselves do not change."
        ),
    }
}

/// L'état d'une mission, en quelques mots.
fn etat(m: &MissionVue) -> &'static str {
    match (m.etat, m.pourquoi) {
        (EtatMission::EnMarche, _) => tr!("en marche", "on"),
        (_, Some(Pourquoi::CoupeeIci)) => tr!("coupée ici, plus aucun tour", "off here, no more turns"),
        (_, Some(Pourquoi::AgentCoupe)) => tr!("coupée avec l'agent, aucun tour", "off with the agent, no turn"),
        (_, Some(Pourquoi::AgentDouteux)) => tr!(
            "coupée (le réglage de l'agent a changé hors de Vanguard)",
            "off (the agent's setting changed outside Vanguard)"
        ),
        (_, Some(Pourquoi::InterrupteursDouteux)) => tr!(
            "coupée (les interrupteurs ont changé hors de Vanguard)",
            "off (the switches changed outside Vanguard)"
        ),
        (_, Some(Pourquoi::EtatDouteux)) => tr!(
            "arrêtée (son état a changé hors de Vanguard)",
            "stopped (its state changed outside Vanguard)"
        ),
        (_, Some(Pourquoi::JournalDouteux)) => tr!(
            "arrêtée (le journal a changé hors de Vanguard)",
            "stopped (the journal changed outside Vanguard)"
        ),
        (_, None) => tr!("coupée", "off"),
    }
}

/// La ligne d'une mission : son état, son dernier tour, ce qu'elle a décidé.
fn ligne(m: &MissionVue) -> String {
    let mut t = trf!("{} : {}", "{}: {}", nom(m.nom), etat(m));
    if let Some(d) = m.dernier_tour.and_then(sortie::Jour::date) {
        t.push_str(&trf!(
            " ; dernier tour le {}",
            "; last turn on {}",
            d.format("%Y-%m-%d")
        ));
    }
    if let Some(n) = m.decisions_total.filter(|n| *n > 0) {
        t.push_str(&trf!(" ; {} décision(s)", "; {} decision(s)", n));
    }
    t
}

/// Ce que dit une ligne du journal, en phrase.
fn phrase(sorte: Sorte, d: &Decision) -> String {
    let texte = match d {
        Decision::Ajuster(a) => match a.levier {
            Levier::Delai {
                regle,
                avant_s,
                apres_s,
            } => trf!(
                "{} : délai monté de {} à {} min",
                "{}: time limit raised from {} to {} min",
                regle.texte(),
                avant_s / 60,
                apres_s / 60
            ),
            Levier::Cache {
                regle,
                avant_min,
                apres_min,
            } => trf!(
                "{} : reprise raccourcie de {} à {} min",
                "{}: reuse shortened from {} to {} min",
                regle.texte(),
                avant_min,
                apres_min
            ),
            Levier::CacheRallonge {
                regle,
                avant_min,
                apres_min,
            } => trf!(
                "{} : reprise rallongée de {} à {} min",
                "{}: reuse lengthened from {} to {} min",
                regle.texte(),
                avant_min,
                apres_min
            ),
            Levier::CacheCoupee { regle } => trf!(
                "{} : plus reprise du tout, trop d'écarts",
                "{}: no longer reused at all, too many differences",
                regle.texte()
            ),
            Levier::SecondEssai { regle, .. } => trf!(
                "{} : second essai en fin de bilan",
                "{}: second attempt at the end of the check",
                regle.texte()
            ),
        },
        Decision::Proposer(crate::agent::Proposition::RevoirRegle { regle }) => {
            trf!("{} : à revoir", "{}: to be reviewed", regle.texte())
        }
        Decision::Proposer(crate::agent::Proposition::CorrectionFragile { regle, echecs, .. }) => trf!(
            "{} : correction fragile, {} échec(s) de suite",
            "{}: fragile fix, {} failure(s) in a row",
            regle.texte(),
            echecs
        ),
        Decision::Proposer(crate::agent::Proposition::NeTientPas { regle }) => trf!(
            "{} : le problème revient après la correction",
            "{}: the problem comes back after the fix",
            regle.texte()
        ),
        Decision::Signaler(crate::agent::Signal::Nouveaute { regle }) => {
            trf!("{} : nouveauté", "{}: something new", regle.texte())
        }
    };
    match sorte {
        Sorte::Appliquee => texte,
        Sorte::Montree => trf!("{} (avis)", "{} (note)", texte),
        Sorte::Refusee => trf!("{} (refusé par l'agent)", "{} (refused by the agent)", texte),
    }
}

/// Une date du journal (secondes depuis 1970), à l'heure de l'ordinateur.
fn quand(secondes: i64) -> String {
    chrono::DateTime::from_timestamp(secondes, 0).map_or_else(
        || "????-??-?? ??:??".to_string(),
        |d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string(),
    )
}

/// L'écran des missions, lu sans rien écrire.
pub(crate) fn afficher_missions(vue: &Vue) {
    titre(tr!("Missions de l'agent", "Agent missions"));
    afficher_aligne(
        "  ",
        tr!(
            "Chaque mission se coupe ici seule. Coupée, elle ne prend plus aucun tour. Les règles du bilan et ce qu'elles jugent ne changent jamais : couper une mission ne retire aucune vérification.",
            "Each mission can be turned off here on its own. Off, it takes no more turns. The check's rules and how they judge never change: turning a mission off removes no check."
        ),
        2,
        GRIS,
    );
    println!();
    for (i, m) in vue.missions.iter().enumerate() {
        afficher_aligne(&format!("  {TOUCHE}{}{RESET} ", i + 1), &ligne(m), 4, "");
        afficher_aligne("    ", role(m.nom), 4, GRIS);
    }
    if matches!(vue.interrupteurs, Fichier::Douteux) {
        println!();
        afficher_aligne(
            "  ",
            tr!(
                "Les interrupteurs ont changé hors de Vanguard : toutes les missions restent coupées jusqu'à ce que vous en remettiez une en marche ici.",
                "The switches changed outside Vanguard: every mission stays off until you turn one back on here."
            ),
            2,
            ACCENT,
        );
    }
}

/// Le journal, le plus récent d'abord, lu sans rien écrire.
pub(crate) fn afficher_journal() {
    let (fichier, entrees) = sortie::journal_dans(&crate::socle::dossier_local());
    titre(tr!("Journal de l'agent", "Agent journal"));
    afficher_aligne(
        "  ",
        tr!(
            "Ce que l'agent a fait, le plus récent d'abord. Le journal est scellé : changé hors de Vanguard, il n'est plus cru.",
            "What the agent did, most recent first. The journal is sealed: changed outside Vanguard, it is no longer trusted."
        ),
        2,
        GRIS,
    );
    println!();
    match fichier {
        Fichier::Absent => trp!("  Rien au journal pour l'instant.", "  Nothing in the journal yet."),
        Fichier::Douteux | Fichier::Rompu => afficher_aligne(
            "  ",
            tr!(
                "Le journal a changé hors de Vanguard : rien n'en est montré, et l'agent ne prend plus de tour. « Tout remettre » dans l'écran d'avant repart d'un journal neuf.",
                "The journal changed outside Vanguard: nothing of it is shown, and the agent takes no more turns. “Put everything back” on the previous screen starts a new journal."
            ),
            2,
            ACCENT,
        ),
        Fichier::Intact => {
            for e in entrees.iter().take(JOURNAL_MAX) {
                let texte = match sortie::de_fait(&e.fait) {
                    Some((mission, sorte, d)) => format!("{} › {}", nom(mission), phrase(sorte, &d)),
                    None => tr!("Tout remis comme à l'origine", "Everything put back to the original").to_string(),
                };
                afficher_aligne(&format!("  {GRIS}{}{RESET} ", quand(e.quand)), &texte, 4, "");
            }
            if entrees.is_empty() {
                trp!("  Rien au journal pour l'instant.", "  Nothing in the journal yet.");
            } else if entrees.len() > JOURNAL_MAX {
                trp!(
                    "  … et {} ligne(s) plus ancienne(s).",
                    "  … and {} older line(s).",
                    entrees.len() - JOURNAL_MAX
                );
            }
        }
    }
}

/// `vanguard agent` sans --json : les missions et le journal, sans rien écrire.
pub(crate) fn afficher_tout() {
    afficher_missions(&sortie::vue_dans(&crate::socle::dossier_local()));
    afficher_journal();
}

/// Coupe (`coupee`) ou remet en marche la mission `id`, et le dit.
fn dire_coupee(id: MissionId, coupee: bool) {
    let dossier = crate::socle::dossier_local();
    let fait = crate::agent::geste_dans(&dossier).and_then(|g| crate::agent::couper_dans(&dossier, id, coupee, &g));
    match fait {
        Err(e) => trp!(
            "  {ACCENT}✘{RESET} Rien n'a changé : {e}",
            "  {ACCENT}✘{RESET} Nothing changed: {e}"
        ),
        Ok(false) if coupee => trp!(
            "  Rien n'a changé : « {} » était déjà coupée.",
            "  Nothing changed: “{}” was already off.",
            nom(id)
        ),
        Ok(false) => trp!(
            "  Rien n'a changé : « {} » était déjà en marche.",
            "  Nothing changed: “{}” was already on.",
            nom(id)
        ),
        Ok(true) if coupee => {
            trp!(
                "  {VERT}✔{RESET} « {} » : coupée. Elle ne prend plus aucun tour.",
                "  {VERT}✔{RESET} “{}”: off. It takes no more turns.",
                nom(id)
            );
            afficher_aligne("    ", role(id), 4, GRIS);
        }
        Ok(true) => trp!(
            "  {VERT}✔{RESET} « {} » : en marche, dès son prochain tour.",
            "  {VERT}✔{RESET} “{}”: on, from its next turn.",
            nom(id)
        ),
    }
}

/// Le journal, puis une pause avant de revenir : le menu d'où il vient efface l'écran.
pub(crate) fn journal_et_revenir() {
    afficher_journal();
    crate::selection::attendre_retour(tr!("\n  Entrée pour revenir : ", "\n  Enter to go back: "));
}

/// L'écran des missions de Paramètres : un numéro coupe ou remet en marche cette mission, et l'écran se redessine
/// sous ce qui a été fait.
pub(crate) fn menu() {
    loop {
        afficher_missions(&sortie::vue_dans(&crate::socle::dossier_local()));
        let reponse = demander(tr!(
            "\n  Numéro : couper cette mission, ou la remettre en marche ; « j » : le journal ; Entrée pour revenir : ",
            "\n  Number: turn this mission off, or back on; “j”: the journal; Enter to go back: "
        ));
        let reponse = reponse.trim();
        if reponse.is_empty() {
            return;
        }
        if reponse.eq_ignore_ascii_case("j") {
            journal_et_revenir();
            continue;
        }
        match reponse
            .parse::<usize>()
            .ok()
            .and_then(|i| MissionId::TOUTES.get(i.checked_sub(1)?))
        {
            Some(&id) => {
                let coupee = crate::agent::mission_coupee_dans(&crate::socle::dossier_local(), id);
                dire_coupee(id, !coupee);
            }
            None => trp!("  Rien n'a changé.", "  Nothing changed."),
        }
    }
}

/// Une mission par son mot de la ligne de commande.
fn mission_du_mot(mot: &str) -> Option<MissionId> {
    match mot {
        "reglage" | "réglage" | "delais" | "délais" | "tuning" | "limits" => Some(MissionId::Reglage),
        "cache" => Some(MissionId::Cache),
        "releve" | "relevé" | "record" => Some(MissionId::Releve),
        "corrections" | "fixes" => Some(MissionId::Corrections),
        _ => None,
    }
}

/// `vanguard parametres auto-reglage mission <reglage|cache|releve|corrections> <oui|non>` ; rend faux si les mots
/// ne se lisent pas.
pub(crate) fn commande_mission(mission: &str, etat: &str) -> bool {
    let Some(id) = mission_du_mot(mission) else {
        return false;
    };
    match etat {
        "oui" | "o" | "yes" | "y" | "on" => dire_coupee(id, false),
        "non" | "n" | "no" | "off" => dire_coupee(id, true),
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chaque mission a son mot, et chaque mot sa mission.
    #[test]
    fn chaque_mission_a_son_mot() {
        for (id, mot) in MissionId::TOUTES
            .into_iter()
            .zip(["reglage", "cache", "releve", "corrections"])
        {
            assert_eq!(mission_du_mot(mot), Some(id));
        }
        assert_eq!(mission_du_mot("detection"), None);
    }

    /// Le texte du relevé coupé ici dit ce qui le sépare de « Non » au partage.
    #[test]
    fn le_releve_coupe_ici_n_est_pas_ne_pas_partager() {
        let t = role(MissionId::Releve);
        assert!(t.contains("Partage avec l'auteur") || t.contains("Sharing with the author"));
        assert!(t.contains("efface") || t.contains("erases"));
    }
}
