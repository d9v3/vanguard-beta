//! L'état affiché en tête du menu et les lignes du menu principal.

use crate::demarrage::aide::nom_de_commande;
use crate::demarrage::arguments::Args;
use crate::menu::lancer::avis_du_nouveau_menu_vu;
use crate::menu::outils::{Action, ECRANS, GROUPES, Groupe, PREMIER_EN_PLUS, places};
use crate::menu::recherche::ANCIENS_NOMS;
use crate::selection::Ligne;
use crate::ui::*;
use crate::{depanner, guide, historique, logiciels, mise_a_jour, parametres, protection, reseau, risk};
use clap::CommandFactory;

/// État affiché en tête du menu : dernier bilan, dernier test de connexion, clé, surveillance, et un avis s'il y en
/// a un (copie périmée, nouvelle version sur la clé).
pub(crate) fn etat_du_menu(surveillance_active: bool, nouveau_menu: bool) -> Vec<String> {
    let historique = historique::charger();
    let bilan = match historique.last() {
        Some(b) => {
            let note = |s: Option<u32>| s.map_or_else(|| "—".to_string(), etiquette_note);
            trf!(
                "  {GRIS}Dernier bilan{RESET}  {}   ordinateur {}   réseau {}",
                "  {GRIS}Last check{RESET}     {}   computer {}   network {}",
                b.date,
                note(b.machine),
                note(b.reseau)
            )
        }
        None => trf!(
            "  {GRIS}Aucun bilan encore : commencez par 1.{RESET}",
            "  {GRIS}No check yet: start with 1.{RESET}"
        ),
    };
    let connexion = reseau::connexion::historique().last().map(|c| {
        let debit = |d: Option<f64>| d.map_or_else(|| "?".to_string(), |d| format!("{d:.0}"));
        let bufferbloat = c
            .hausse_ms
            .map(|h| {
                let (n, niveau) = reseau::connexion::note_bufferbloat(h);
                format!("{}{n}{RESET}", couleur(niveau))
            })
            .unwrap_or_default();
        trf!(
            "  {GRIS}Connexion{RESET}      {:.0} ms · ↓ {} ↑ {} Mbit/s · bufferbloat {bufferbloat}",
            "  {GRIS}Connection{RESET}     {:.0} ms · ↓ {} ↑ {} Mbit/s · bufferbloat {bufferbloat}",
            c.internet_ms,
            debit(c.descendant),
            debit(c.montant)
        )
    });
    let cle = match reseau::etat_de_la_cle() {
        reseau::EtatCle::ProtegeeEnEcriture => format!(
            "{VERT}{}{RESET}",
            tr!(
                "clé VANGUARD branchée (protégée en écriture)",
                "VANGUARD key plugged in (write-protected)"
            )
        ),
        reseau::EtatCle::Branchee => format!(
            "{VERT}{}{RESET}",
            tr!("clé VANGUARD branchée", "VANGUARD key plugged in")
        ),
        // Un volume au témoin sans jeton connu d'ici : dit, pour que personne ne croie sa clé reconnue.
        reseau::EtatCle::Inconnue => format!(
            "{}{}{RESET}",
            couleur(risk::Niveau::Moyen),
            tr!("clé VANGUARD inconnue, ignorée", "unknown VANGUARD key, ignored")
        ),
        // Une copie de la clé branchée avec elle : ni l'une ni l'autre n'est prise, et ce n'est pas une clé inconnue.
        reseau::EtatCle::EnDouble => format!(
            "{}{}{RESET}",
            couleur(risk::Niveau::Moyen),
            tr!("clé VANGUARD en double, ignorée", "VANGUARD key duplicated, ignored")
        ),
        reseau::EtatCle::Aucune => format!("{GRIS}{}{RESET}", tr!("clé non branchée", "key not plugged in")),
    };
    let surveillance = if surveillance_active {
        format!("{VERT}{}{RESET}", tr!("surveillance active", "monitoring on"))
    } else {
        format!("{GRIS}{}{RESET}", tr!("surveillance coupée", "monitoring off"))
    };
    let cle = ligne_de_la_cle(&cle, &surveillance, protection::temps_reel::en_tete());
    // La copie périmée d'abord : remettre la clé à jour passe avant d'en recopier le programme.
    let avis = protection::manifeste::avertissement_perime()
        .map(|a| format!("  {}⚠{RESET} {a}", couleur(risk::Niveau::Moyen)))
        .or_else(|| {
            touche_de(Action::MettreAJour)
                .and_then(|t| mise_a_jour::avertissement(&t))
                .map(|a| format!("  {ACCENT}↑{RESET} {a}"))
        })
        .or_else(|| {
            nouveau_menu.then(|| {
                // Posée quand l'avis paraît, pas avant : caché par un autre avis, il revient à la session suivante.
                avis_du_nouveau_menu_vu();
                trf!(
                    "  {ACCENT}›{RESET} Le menu a été réorganisé : tapez un mot pour retrouver un outil.",
                    "  {ACCENT}›{RESET} The menu has been reorganized: type a word to find a tool."
                )
            })
        });
    lignes_d_etat(bilan, connexion, cle, avis)
}

/// La ligne de la clé et de la surveillance, avec la protection en temps réel quand elle est coupée : à côté de la
/// surveillance si tout tient dans la largeur, sinon à sa place (elle ne passe plus, de toute façon), et sans son
/// échéance en dernier recours.
pub(crate) fn ligne_de_la_cle(cle: &str, surveillance: &str, temps_reel: Option<(String, String)>) -> String {
    let point = format!(" {GRIS}·{RESET} ");
    let Some((long, court)) = temps_reel else {
        return format!("  {cle}{point}{surveillance}");
    };
    [
        format!("  {cle}{point}{surveillance}{point}{long}"),
        format!("  {cle}{point}{long}"),
    ]
    .into_iter()
    .find(|l| largeur_affichee(l) <= LARGEUR)
    .unwrap_or_else(|| format!("  {cle}{point}{court}"))
}

/// Les lignes d'état, trois au plus : avec plus, le menu ne tiendrait plus dans un terminal de 24 lignes (test). Un
/// avis prend la place de la connexion, la ligne la moins utile ici.
pub(crate) fn lignes_d_etat(
    bilan: String,
    connexion: Option<String>,
    cle: String,
    avis: Option<String>,
) -> Vec<String> {
    match avis {
        Some(avis) => vec![bilan, cle, avis],
        None => [Some(bilan), connexion, Some(cle)].into_iter().flatten().collect(),
    }
}

/// Les fonctions du menu, rangées comme lui, pour le tableau de bord : chaque outil proposé ici avec sa place, son
/// titre, sa précision et la commande qui fait la même chose. Une commande déjà dite à la ligne d'avant (les variantes
/// d'un écran à choix ouvrent le même écran) ne se répète pas.
pub(crate) fn fonctions_du_menu() -> Vec<reseau::tableau::Rubrique> {
    use reseau::tableau::{Fonction, Rubrique};
    let clap = Args::command();
    let rubrique = |titre: String, resume: &str, outils: Vec<(String, Action)>| {
        let mut derniere = None;
        let fonctions = outils
            .into_iter()
            .map(|(place, a)| {
                let (titre, precision) = a.libelle();
                let nom = a.outil().commande;
                let commande = (!nom.is_empty())
                    .then(|| clap.find_subcommand(nom))
                    .flatten()
                    .map(|c| format!("vanguard {}", nom_de_commande(c)));
                let repetee = commande.is_some() && commande == derniere;
                derniere.clone_from(&commande);
                Fonction {
                    place,
                    titre: titre.to_string(),
                    precision: precision.to_string(),
                    commande: if repetee { None } else { commande },
                }
            })
            .collect();
        Rubrique {
            titre,
            resume: resume.to_string(),
            fonctions,
        }
    };
    let principal = [Action::Complet, Action::Corriger, Action::Rapport]
        .into_iter()
        .zip(1u32..)
        .map(|(a, i)| (i.to_string(), a))
        .collect();
    let mut rubriques = vec![rubrique(
        tr!("1 à 3 · Menu principal", "1 to 3 · Main menu").to_string(),
        tr!("le bilan et ses suites", "the check and what follows"),
        principal,
    )];
    let places = places();
    for (i, groupe) in GROUPES.iter().enumerate() {
        let cle = i.saturating_add(4).to_string();
        let prefixe = format!("{cle}.");
        // Le guide et le dépannage s'ouvrent directement, sur leur premier outil : sa place est celle du groupe.
        let mut outils: Vec<(String, Action)> = groupe
            .direct()
            .then(|| groupe.actions().first().map(|a| (cle.clone(), *a)))
            .flatten()
            .into_iter()
            .collect();
        outils.extend(places.iter().filter(|(p, _)| p.starts_with(&prefixe)).cloned());
        rubriques.push(rubrique(format!("{cle} · {}", groupe.titre()), groupe.resume(), outils));
    }
    rubriques
}

/// La place d'un outil au menu (« 13.3 » : groupe 13, 3e outil proposé ici), comme la recherche la tape.
pub(crate) fn touche_de(action: Action) -> Option<String> {
    places()
        .into_iter()
        .find(|(_, a)| *a == action)
        .map(|(chemin, _)| chemin)
}

/// Les lignes du menu principal, sous l'état (dernier bilan, clé, surveillance).
pub(crate) fn lignes_du_menu(etat: Vec<String>) -> Vec<Ligne> {
    let mut lignes: Vec<Ligne> = vec![Ligne::cadre(
        &format!("{ACCENT}VANGUARD{RESET} {GRIS}{}{RESET}", env!("CARGO_PKG_VERSION")),
        tr!(
            "Cyberdéfense portable des postes et des réseaux",
            "Portable cyber defense for endpoints and networks"
        ),
    )];
    lignes.extend(etat.into_iter().map(Ligne::Texte));

    // Trois intertitres, sans ligne vide : cadre (3), état (3 au plus), intertitres (3) et 13 lignes font 22 rangées,
    // et l'aide et la saisie 24, la hauteur d'un petit terminal où les flèches marchent encore.
    lignes.push(Ligne::Texte(ligne_section(tr!("BILAN DE SÉCURITÉ", "SECURITY CHECK"))));
    for (touche, action) in [Action::Complet, Action::Corriger, Action::Rapport]
        .into_iter()
        .enumerate()
    {
        let (texte, precision) = action.libelle();
        let commande = action.outil().commande;
        let anciens = ANCIENS_NOMS
            .iter()
            .find(|(n, _)| *n == commande)
            .map_or("", |(_, a)| *a);
        lignes.push(
            Ligne::choix(&touche.saturating_add(1).to_string(), texte, precision)
                .avec_mots(&format!("{commande} {anciens}"))
                .avec_description(action.description()),
        );
    }
    for (i, groupe) in GROUPES.iter().enumerate() {
        if i == 0 {
            lignes.push(Ligne::Texte(ligne_section(tr!("CYBERDÉFENSE", "CYBER DEFENSE"))));
        } else if *groupe == PREMIER_EN_PLUS {
            lignes.push(Ligne::Texte(ligne_section(tr!("EN PLUS", "ALSO INCLUDED"))));
        }
        lignes.push(
            Ligne::choix(
                &i.saturating_add(4).to_string(),
                &format!("{} {ACCENT}›{RESET}", groupe.titre()),
                groupe.resume(),
            )
            .avec_description(groupe.description()),
        );
    }

    // Ce que la recherche trouve en plus, sans l'afficher : chaque place des sous-menus (« 5.2 », « 6.1.3 », aussi
    // tapable telle quelle), chaque parcours de dépannage et chaque page du guide. Les pages du guide en dernier : la
    // recherche garde cet ordre, et un outil ou un parcours répond mieux à « son » qu'une commande à taper.
    let cle_de = |voulu: Groupe| {
        GROUPES
            .iter()
            .position(|g| *g == voulu)
            .map_or(0, |i| i.saturating_add(4))
            .to_string()
    };
    lignes.extend(depanner::lignes_de_recherche(&cle_de(Groupe::Depanner)));
    for (chemin, a) in places() {
        let mut niveaux = chemin.split('.');
        let groupe = niveaux
            .next()
            .and_then(|g| g.parse::<usize>().ok())
            // Les groupes commencent à 4 : un numéro plus petit n'en désigne aucun.
            .and_then(|g| GROUPES.get(g.checked_sub(4)?));
        let mut ou = groupe.map_or_else(String::new, |g| format!("{} ›", g.titre()));
        // Une variante : l'écran à choix d'où elle vient, après le groupe.
        if let Some(parent) = ECRANS.iter().find(|(_, v)| v.contains(&a)).map(|(e, _)| *e) {
            ou = format!("{ou} {} ›", parent.libelle().0);
        }
        let (texte, precision) = a.libelle();
        // Le nom de sa sous-commande aussi, et ses anciens noms : qui connaît « vanguard connexions-sortantes » ou
        // « harden » la retrouve au menu.
        let commande = a.outil().commande;
        // Les raccourcis 8.3 à 8.5 mènent à « depanner » : ses anciens noms (« proche », « traces ») restent au groupe 11.
        let raccourci = matches!(a, Action::DepannerInfection | Action::DepannerCompte | Action::Traces);
        let anciens = ANCIENS_NOMS
            .iter()
            .find(|(n, _)| *n == commande && !raccourci)
            .map_or("", |(_, a)| *a);
        let mots = format!("{} {commande} {anciens}", a.outil().mots);
        lignes.push(
            Ligne::cachee(&chemin, &ou, texte, precision)
                .avec_mots(&mots)
                .avec_description(a.description())
                .avec_sous(a.ce_qu_il_ouvre()),
        );
    }
    // Ce qu'il y a dans les outils : les logiciels du catalogue, les réglages des Paramètres.
    if let Some(cle) = touche_de(Action::Logiciels) {
        lignes.extend(logiciels::lignes_de_recherche(&cle));
    }
    if let Some(cle) = touche_de(Action::Parametres) {
        lignes.extend(parametres::lignes_de_recherche(&cle));
    }
    lignes.extend(guide::lignes_de_recherche(&cle_de(Groupe::Guide)));
    lignes
}
