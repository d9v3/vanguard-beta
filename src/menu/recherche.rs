//! Où mène une touche ou une recherche du menu, et les noms des commandes.

use crate::demarrage::aide::{AIDES_EN, rubriques_des_commandes};
use crate::demarrage::arguments::Args;
use crate::demarrage::droits::refuser_optimiser;
use crate::menu::etat::{lignes_du_menu, touche_de};
use crate::menu::lancer::{executer, lancer, revenir_au_menu, sous_menu};
use crate::menu::outils::{Action, GROUPES, Groupe, OUTILS, places};
use crate::ui::*;
use crate::{Session, depanner, guide, logiciels, selection};
use clap::CommandFactory;

/// Un outil désigné par son chemin, tapé ou trouvé par la recherche : « 5.2 », « 6.1.3 », « 11.13 ».
pub(crate) fn outil_au_chemin(chemin: &str) -> Option<Action> {
    places().into_iter().find(|(c, _)| c == chemin).map(|(_, a)| a)
}

/// Où mène une touche du menu principal, tapée ou trouvée par la recherche.
#[derive(Debug, PartialEq)]
pub(crate) enum Destination {
    /// Une page ou une commande du guide (« 10.3.1.2 »).
    Guide(usize, Option<usize>, Option<usize>),
    /// Un parcours de dépannage (« 11.4 »).
    Parcours(usize),
    /// Un outil par son chemin (« 5.2 », « 6.1.3 », « 11.13 »).
    Chemin(Action),
    /// Un logiciel du catalogue : sa catégorie (« 12.1.5 »).
    Logiciel(usize),
    /// Un groupe (« 5 »).
    Groupe(Groupe),
    /// 1 à 3, ou une lettre d'avant la 0.43.
    Outil(Action),
}

/// La destination d'une touche : 1 à 3, un groupe, un chemin, une page du guide, un parcours, un logiciel, une
/// lettre d'avant la 0.43. Un seul aiguillage pour le menu et `vanguard chercher` ; `None` : rien n'y répond.
pub(crate) fn destination(choix: &str) -> Option<Destination> {
    let cle_de = |voulu: Groupe| {
        GROUPES
            .iter()
            .position(|g| *g == voulu)
            .map(|i| i.saturating_add(4).to_string())
    };
    if let Some((groupe, reste)) = choix.split_once('.') {
        if cle_de(Groupe::Guide).as_deref() == Some(groupe) {
            return guide::chemin(reste).map(|(s, p, c)| Destination::Guide(s, p, c));
        }
        if cle_de(Groupe::Depanner).as_deref() == Some(groupe)
            && let Some(n) = depanner::chemin(reste)
        {
            return Some(Destination::Parcours(n));
        }
        if let Some(action) = outil_au_chemin(choix) {
            return Some(Destination::Chemin(action));
        }
        return touche_de(Action::Logiciels)
            .and_then(|l| choix.strip_prefix(&format!("{l}.")).map(str::to_string))
            .and_then(|n| n.parse::<usize>().ok())
            .map(Destination::Logiciel);
    }
    if let Some(g) = choix
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(4))
        .and_then(|i| GROUPES.get(i))
    {
        return Some(Destination::Groupe(*g));
    }
    match choix {
        "1" => Some(Destination::Outil(Action::Complet)),
        "2" => Some(Destination::Outil(Action::Corriger)),
        "3" => Some(Destination::Outil(Action::Rapport)),
        // Raccourcis des versions précédentes (une lettre par outil), toujours acceptés.
        autre => OUTILS
            .iter()
            .find(|o| !o.lettre.is_empty() && o.lettre == autre)
            .map(|o| Destination::Outil(o.action)),
    }
}

/// Ouvre ce que désigne une touche du menu principal (`destination`). `false` : rien n'y répond.
pub(crate) async fn ouvrir_touche(s: &mut Session, choix: &str) -> bool {
    match destination(choix) {
        None => return false,
        Some(Destination::Guide(systeme, programme, commande)) => guide::ouvrir(systeme, programme, commande),
        Some(Destination::Parcours(n)) => depanner::ouvrir(n),
        Some(Destination::Chemin(action)) => {
            lancer(s, action, &chemin_de(choix)).await;
            revenir_au_menu(action);
        }
        Some(Destination::Logiciel(place)) => {
            if refuser_optimiser() {
                revenir_au_menu(Action::Logiciels);
            } else {
                logiciels::ouvrir_sur(place);
            }
        }
        Some(Destination::Groupe(g)) => sous_menu(s, g).await,
        Some(Destination::Outil(action)) => {
            executer(s, action).await;
            revenir_au_menu(action);
        }
    }
    true
}

/// `vanguard chercher` : les dix meilleurs résultats de la recherche du menu, avec leur place et leur commande ; un
/// numéro (dans un terminal) ou `--premier` ouvre le résultat par le même aiguillage que le menu. `false` : rien trouvé.
pub(crate) async fn chercher(requete: &str, premier: bool, json: bool) -> bool {
    use std::io::IsTerminal;
    let lignes = lignes_du_menu(Vec::new());
    let (trouves, corrections, partiels) = selection::chercher(&lignes, requete);
    let trouves: Vec<_> = trouves.into_iter().take(10).collect();
    let commande_de = |touche: &str| {
        outil_au_chemin(touche)
            .map(|a| a.outil().commande)
            .filter(|c| !c.is_empty())
            .map(|c| format!("vanguard {c}"))
            .unwrap_or_default()
    };
    if json {
        let liste: Vec<serde_json::Value> = trouves
            .iter()
            .map(|t| {
                serde_json::json!({
                    "touche": t.touche, "texte": t.texte, "precision": t.precision, "commande": commande_de(&t.touche)
                })
            })
            .collect();
        let corrections: Vec<_> = corrections
            .iter()
            .map(|(a, b)| serde_json::json!({"tape": a, "corrige": b}))
            .collect();
        println!(
            "{}",
            serde_json::json!({"resultats": liste, "partiels": partiels, "corrections": corrections})
        );
        return !trouves.is_empty();
    }
    if trouves.is_empty() {
        trp!(
            "  Aucun résultat pour « {} ». Essayez : disque, wifi, dns, mise à jour.",
            "  No result for “{}”. Try: disk, wifi, dns, update.",
            affichable(requete)
        );
        return false;
    }
    if premier && let Some(trouve) = trouves.first() {
        let touche = trouve.touche.clone();
        let mut s = Session::default();
        return ouvrir_touche(&mut s, &touche).await;
    }
    for (a, b) in &corrections {
        trp!(
            "  {GRIS}Résultats pour « {b} » (tapé : « {a} »).{RESET}",
            "  {GRIS}Results for “{b}” (typed: “{a}”).{RESET}"
        );
    }
    if partiels {
        trp!(
            "  {GRIS}Aucun résultat n'a tous les mots : résultats partiels.{RESET}",
            "  {GRIS}No result has every word: partial results.{RESET}"
        );
    }
    let largeur = trouves.iter().map(|t| largeur_affichee(&t.touche)).max().unwrap_or(0);
    for (i, t) in trouves.iter().enumerate() {
        let commande = commande_de(&t.touche);
        let tete = format!("  {:>2}  {:<largeur$}  ", i.saturating_add(1), t.touche);
        let reste = LARGEUR.saturating_sub(largeur_affichee(&tete));
        println!("{tete}{}", couper(&t.texte, reste));
        let detail: Vec<&str> = [t.precision.as_str(), commande.as_str()]
            .into_iter()
            .filter(|x| !x.is_empty())
            .collect();
        if !detail.is_empty() {
            println!(
                "{}{GRIS}{}{RESET}",
                " ".repeat(largeur_affichee(&tete)),
                couper(&detail.join(" · "), reste)
            );
        }
    }
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return true;
    }
    let reponse = demander(tr!(
        "\n  Numéro à ouvrir (Entrée : rien) : ",
        "\n  Number to open (Enter: nothing): "
    ));
    if let Some(t) = reponse
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| trouves.get(i))
    {
        let mut s = Session::default();
        ouvrir_touche(&mut s, &t.touche).await;
    }
    true
}

/// La touche du guide au menu principal (« 10 »).
pub(crate) fn cle_du_guide() -> String {
    GROUPES
        .iter()
        .position(|g| *g == Groupe::Guide)
        .map_or(0, |i| i.saturating_add(4))
        .to_string()
}

/// Les commandes qui ne changent rien sur l'ordinateur (elles lisent, montrent, cherchent ; au plus une page ou un
/// rapport dans le dossier de Vanguard) : le guide (10.9) les dit « ✔ ne fait que lire ». Toute autre est marquée ⚠,
/// même si chaque changement demande un accord.
pub(crate) const COMMANDES_EN_LECTURE: &[&str] = &[
    "bilan",
    "rapport",
    "chercher",
    "audit",
    "dernieres-failles",
    "fiche-ordinateur",
    "secrets",
    "conteneurs",
    "logiciels-perimes",
    "options-defense",
    "appareils",
    "audit-reseau",
    "objets-connectes",
    "cameras-cachees",
    "listes-noires",
    "tableau-de-bord",
    "logiciels-espions",
    "connexions-sortantes",
    "memoire",
    "verifier-fichier",
    "lien",
    "courriel-suspect",
    "fuite-mot-de-passe",
    "mots-de-passe-navigateurs",
    "fuite-courriel",
    "camera-micro",
    "bilan-confidentialite",
    "evenements",
    "journaux-windows",
    "changements",
    "verifier-sauvegarde",
    "verifier-copie",
    "guide",
    "diagnostic",
    "lenteur",
    "test-connexion",
    "nat",
    "canaux-wifi",
    "verifier-moi",
    "autotest",
    "regles",
    "ordinateurs",
];

/// L'essentiel d'une aide de commande pour le guide, qui tient en deux lignes : ce qui précède son premier « : »,
/// « ; » ou point (« Rapport détaillé dans le navigateur : le bilan… » → « Rapport détaillé dans le navigateur »).
pub(crate) fn essentiel(aide: &str) -> String {
    aide.split([':', ';', '.']).next().unwrap_or(aide).trim().to_string()
}

/// Une explication du guide en deux lignes au plus (la règle de ses pages), sa place au menu gardée : des mots
/// retirés à la fin, remplacés par « … », quand il le faut.
fn en_deux_lignes(texte: &str, place: &str) -> String {
    let tient = |t: &str| envelopper(t, LARGEUR - 6).len() <= 2;
    let mut mots: Vec<&str> = texte.split_whitespace().collect();
    let entier = format!("{texte}{place}");
    if tient(&entier) {
        return entier;
    }
    while mots.len() > 1 {
        mots.pop();
        let court = format!("{}…{place}", mots.join(" "));
        if tient(&court) {
            return court;
        }
    }
    entier
}

/// La place au menu d'une commande : 1 à 3, le chemin de son outil (les raccourcis 8.3 à 8.5 laissés de côté pour
/// « depanner »), ou la touche d'un groupe ouvert directement (« 10 », « 11 »).
pub(crate) fn place_de_commande(nom: &str) -> Option<String> {
    let principal = [Action::Complet, Action::Corriger, Action::Rapport];
    let raccourcis = [Action::DepannerInfection, Action::DepannerCompte, Action::Traces];
    let outil = OUTILS
        .iter()
        .find(|o| o.commande == nom && !raccourcis.contains(&o.action))?;
    if let Some(i) = principal.iter().position(|a| *a == outil.action) {
        return Some(i.saturating_add(1).to_string());
    }
    if let Some(g) = outil.groupe.filter(|g| g.direct())
        && g.actions().first() == Some(&outil.action)
    {
        return GROUPES
            .iter()
            .position(|x| *x == g)
            .map(|i| i.saturating_add(4).to_string());
    }
    touche_de(outil.action)
}

/// Les commandes de Vanguard pour le guide (10.9) : un programme par rubrique de `--help`, une commande par ligne,
/// avec son aide et sa place au menu. Construites une fois, depuis le menu et clap.
pub(crate) fn programmes_vanguard() -> &'static [guide::Programme] {
    static PROGRAMMES: std::sync::OnceLock<Vec<guide::Programme>> = std::sync::OnceLock::new();
    PROGRAMMES.get_or_init(|| {
        let garder = |t: String| -> &'static str { Box::leak(t.into_boxed_str()) };
        let clap = Args::command();
        rubriques_des_commandes()
            .into_iter()
            .map(|(groupe, noms)| {
                let (numero, [fr, en]) = match groupe {
                    None => ("1 2 3".to_string(), ["Bilan de sécurité", "Security check"]),
                    Some(g) => (
                        GROUPES
                            .iter()
                            .position(|x| *x == g)
                            .map_or(0, |i| i.saturating_add(4))
                            .to_string(),
                        g.titres(),
                    ),
                };
                let titre = (fr, en);
                let commandes: Vec<guide::Commande> = noms
                    .iter()
                    .filter_map(|nom| clap.find_subcommand(nom))
                    .map(|c| {
                        let nom = c.get_name();
                        let anglais = c.get_visible_aliases().next().unwrap_or(nom);
                        let aide_fr = c.get_about().map(ToString::to_string).unwrap_or_default();
                        let aide_en = AIDES_EN
                            .iter()
                            .find(|(n, _)| *n == nom)
                            .map_or(aide_fr.clone(), |(_, a)| (*a).to_string());
                        let place = place_de_commande(nom)
                            .map(|t| (format!(" (menu {t})"), format!(" (menu {t})")))
                            .unwrap_or_default();
                        guide::traduite(
                            garder(format!("vanguard {nom}")),
                            garder(format!("vanguard {anglais}")),
                            garder(en_deux_lignes(&essentiel(&aide_fr), &place.0)),
                            garder(en_deux_lignes(&essentiel(&aide_en), &place.1)),
                            !COMMANDES_EN_LECTURE.contains(&nom),
                        )
                    })
                    .collect();
                guide::Programme {
                    nom: garder(format!("vanguard ({numero})")),
                    role: titre,
                    executable: "",
                    commandes: Box::leak(commandes.into_boxed_slice()),
                }
            })
            .collect()
    })
}

/// Les noms de commandes d'avant la 0.87, que la ligne de commande n'accepte plus (décision de l'auteur) : la
/// recherche les trouve encore (« harden » mène à Defender, « maj » aux mises à jour).
pub(crate) const ANCIENS_NOMS: &[(&str, &str)] = &[
    ("bilan", "complet full"),
    ("audit", "machine"),
    ("appareils", "reseau network"),
    ("mises-a-jour", "maj update"),
    ("fuite-mot-de-passe", "motdepasse password"),
    ("fuite-courriel", "courriel email"),
    ("mots-de-passe-navigateurs", "navigateurs"),
    ("connexions-sortantes", "sortantes outbound"),
    ("acces-a-distance", "distance"),
    ("bilan-confidentialite", "acces permissions"),
    ("objets-connectes", "objets iot"),
    ("cameras-cachees", "cameras"),
    ("canaux-wifi", "canaux channels"),
    ("test-connexion", "connexion connection"),
    ("tableau-de-bord", "tableau"),
    ("fiche-ordinateur", "fiche"),
    ("options-defense", "defender durcir harden"),
    ("rapport-a-laisser", "a-laisser"),
    ("exporter", "sauvegarder backup"),
    ("jeux", "gaming"),
    ("depanner", "traces evidence proche relative"),
];

/// Le titre de l'écran d'où s'ouvre un outil désigné par son chemin (« 6.1.3 » : Virus et logiciels espions).
pub(crate) fn chemin_de(chemin: &str) -> String {
    chemin
        .split('.')
        .next()
        .and_then(|g| g.parse::<usize>().ok()?.checked_sub(4))
        .and_then(|i| GROUPES.get(i))
        .map_or_else(String::new, |g| g.titre().to_string())
}
