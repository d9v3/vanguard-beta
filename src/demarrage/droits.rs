//! Les droits du processus au démarrage : élevé ou non, d'où il vient, et ce qu'on refuse alors.

use crate::demarrage::arguments::Commande;
#[cfg(windows)]
use crate::machine;
use crate::risk;
use crate::ui::*;

/// Vanguard lui-même en administrateur : root ou setuid (compte effectif ≠ compte réel), console administrateur
/// sous Windows. Un jeton illisible compte pour élevé : c'est un garde-fou, il échoue fermé.
pub(crate) fn processus_eleve() -> bool {
    #[cfg(unix)]
    {
        let (effectif, reel) = (crate::socle::euid(), crate::socle::uid());
        (effectif == 0 && !root_d_un_espace_de_noms()) || effectif != reel
    }
    #[cfg(windows)]
    {
        machine::windows::processus::eleve_ou_inconnu()
    }
}

/// Root seulement dans un espace de noms d'utilisateurs (« unshare -r », conteneur sans droits) : le compte 0 y est
/// un compte ordinaire de l'ordinateur, sans aucun droit sur lui.
#[cfg(unix)]
fn root_d_un_espace_de_noms() -> bool {
    std::fs::read_to_string("/proc/self/uid_map").is_ok_and(|t| root_hors_de_l_espace(&t) == Some(false))
}

/// Le compte 0 de cet espace est-il le root de l'ordinateur ? D'après /proc/self/uid_map (« dedans dehors nombre »
/// par ligne) ; `None` si 0 n'y est pas.
#[cfg(any(unix, test))]
pub(crate) fn root_hors_de_l_espace(uid_map: &str) -> Option<bool> {
    uid_map.lines().find_map(|l| {
        let mut champs = l.split_whitespace().map(str::parse::<u64>);
        let (Some(Ok(dedans)), Some(Ok(dehors)), Some(Ok(nombre))) = (champs.next(), champs.next(), champs.next())
        else {
            return None;
        };
        (dedans == 0 && nombre > 0).then_some(dehors == 0)
    })
}

/// Vanguard élevé l'a-t-il été depuis un compte ordinaire, qui pourrait le relancer sans droits et ne demander les
/// droits qu'au moment voulu ? Windows : un jeton élevé séparé par l'UAC (type 2), ou illisible (échoue fermé) ; pas
/// sans UAC ni pour le compte Administrateur intégré, qui n'ont pas de jeton ordinaire. Ailleurs : venu de sudo, run0,
/// pkexec ou doas, ou d'une session ouverte par un autre compte (`venu_d_un_autre_compte`) ; pas « ssh root@ » ni un
/// conteneur où root est le seul compte.
fn droits_demandables() -> bool {
    #[cfg(unix)]
    {
        let variables = ["SUDO_UID", "PKEXEC_UID", "DOAS_USER"]
            .iter()
            .any(|v| std::env::var_os(v).is_some());
        let session = std::fs::read_to_string("/proc/self/loginuid")
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        venu_d_un_autre_compte(variables, session)
    }
    #[cfg(windows)]
    {
        machine::windows::processus::type_d_elevation() != Some(1)
    }
}

/// `variables` : SUDO_UID, PKEXEC_UID ou DOAS_USER présentes (run0 pose aussi SUDO_UID) ; `session` : le compte qui a
/// ouvert la session (/proc/self/loginuid, Linux ; 4294967295 : aucun).
#[cfg(any(unix, test))]
pub(crate) fn venu_d_un_autre_compte(variables: bool, session: Option<u32>) -> bool {
    variables || session.is_some_and(|u| u != 0 && u != u32::MAX)
}

/// Les outils d'Optimiser installent, effacent, changent des réglages ou lisent ce que le réseau leur envoie : rien
/// de cela n'a à tourner avec tous les droits dans le processus, chaque geste d'administrateur est demandé à part.
/// Refusés quand Vanguard est déjà élevé depuis un compte ordinaire (`droits_demandables`) ; là où ce compte n'existe
/// pas (root seul, Windows sans UAC), le refus ne protégerait rien : l'outil tourne, avec l'avertissement.
pub(crate) fn optimiser_refuse(eleve: bool, demandables: bool) -> bool {
    eleve && demandables
}

fn texte_refus_optimiser() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Vanguard tourne en administrateur : les outils d'Optimiser refusent de tourner avec tous les droits (ils installent, effacent, changent des réglages ou lisent ce que le réseau envoie). Relancez Vanguard normalement (double-clic, ou une console ordinaire) : chaque outil demandera l'autorisation de Windows au moment voulu.",
            "Vanguard is running as administrator: the Optimize tools refuse to run with full administrator rights (they install, delete, change settings or read what the network sends). Start Vanguard again normally (double-click, or an ordinary console): each tool will ask for Windows' permission when needed."
        )
    } else {
        tr!(
            "Vanguard tourne en root (sudo) : les outils d'Optimiser refusent de tourner avec tous les droits (ils installent, effacent, changent des réglages ou lisent ce que le réseau envoie). Relancez Vanguard sans sudo : chaque outil demandera le mot de passe au moment voulu.",
            "Vanguard is running as root (sudo): the Optimize tools refuse to run with full administrator rights (they install, delete, change settings or read what the network sends). Start Vanguard again without sudo: each tool will ask for the password when needed."
        )
    }
}

/// Un outil d'Optimiser demandé alors qu'il est refusé (`optimiser_refuse`) : le refus est dit, et l'outil ne part pas.
pub(crate) fn refuser_optimiser() -> bool {
    if !optimiser_refuse(processus_eleve(), droits_demandables()) {
        return false;
    }
    avertir(texte_refus_optimiser());
    true
}

/// Une sous-commande d'un outil d'Optimiser (`optimiser_refuse`) ; « optimiser annuler » n'en est pas une : c'est
/// « Tout remettre comme avant », qui doit marcher en urgence. Le test `commandes_d_optimiser` la compare à la table.
pub(crate) fn commande_d_optimiser(c: &Commande) -> bool {
    match c {
        Commande::Optimiser { quoi } => !matches!(quoi.as_deref(), Some("annuler" | "undo")),
        Commande::Logiciels { .. }
        | Commande::Nettoyer { .. }
        | Commande::Lenteur { .. }
        | Commande::Demarrage { .. }
        | Commande::Gaming
        | Commande::DnsRapide
        | Commande::Connexion { .. }
        | Commande::Nat
        | Commande::Canaux => true,
        _ => false,
    }
}

/// Un avertissement, enveloppé, sur la sortie d'erreur.
pub(crate) fn avertir(texte: &str) {
    for (i, ligne) in envelopper(texte, LARGEUR - 4).into_iter().enumerate() {
        if i == 0 {
            eprintln!("  {}⚠{RESET} {ligne}", couleur(risk::Niveau::Moyen));
        } else {
            eprintln!("    {ligne}");
        }
    }
}

/// Lancé en administrateur : Vanguard n'en a pas besoin (chaque correction demande les droits au moment voulu, par
/// pkexec, run0 ou sudo dans le terminal, ou l'UAC), et une sortie piégée aurait ici tous les droits. Dit, jamais
/// imposé ; seuls les outils d'Optimiser refusent, et seulement là où un compte ordinaire existe (`optimiser_refuse`).
pub(crate) fn avertir_si_eleve() {
    if !processus_eleve() {
        return;
    }
    avertir(match (cfg!(windows), droits_demandables()) {
        (true, true) => tr!(
            "Vanguard tourne en administrateur : il n'en a pas besoin, chaque correction demande l'autorisation de Windows au moment voulu. Les outils d'Optimiser refuseront : relancez-le normalement pour eux.",
            "Vanguard is running as administrator: it does not need it, each fix asks for Windows' permission when needed. The Optimize tools will refuse: start it again normally for them."
        ),
        (true, false) => tr!(
            "Vanguard tourne en administrateur sans contrôle de compte (UAC coupé, ou compte Administrateur intégré) : il continue ainsi, mais une sortie piégée aurait ici tous les droits. Mieux vaut un compte ordinaire, avec l'UAC.",
            "Vanguard is running as administrator without account control (UAC off, or the built-in Administrator account): it carries on this way, but a booby-trapped output would have full administrator rights here. An ordinary account, with UAC, is better."
        ),
        (false, true) => tr!(
            "Vanguard tourne en root (sudo) : il n'en a pas besoin, chaque correction demande le mot de passe au moment voulu (même sans session graphique), et une sortie piégée aurait ici tous les droits. Relancez-le sans sudo ; les outils d'Optimiser refuseront sinon.",
            "Vanguard is running as root (sudo): it does not need it, each fix asks for the password when needed (even without a graphical session), and a booby-trapped output would have full administrator rights here. Start it again without sudo; otherwise the Optimize tools will refuse."
        ),
        (false, false) => tr!(
            "Vanguard tourne en root, ouvert directement par ce compte (pas depuis un compte ordinaire) : il continue ainsi, mais une sortie piégée aurait ici tous les droits.",
            "Vanguard is running as root, opened directly by that account (not from an ordinary account): it carries on this way, but a booby-trapped output would have full administrator rights here."
        ),
    });
}
