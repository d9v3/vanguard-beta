//! Les alertes déclarées normales hors du bilan : celles du veilleur, de la surveillance horaire et du blocage. Un
//! faux positif durable (un outil de développement lancé depuis /tmp, un appareil connu qui réapparaît) revenait
//! sans fin, et le seul remède était de couper la défense ; la fatigue d'alerte pousse à tout désactiver. Comme les
//! choix du bilan (`apprentissage`), un choix vaut 90 jours, se relit et s'oublie dans « Ce que Vanguard a appris ».
//!
//! Le choix porte sur la clé de l'alerte, jamais sur son texte traduit : l'objet précis (le programme et sa raison,
//! l'adresse et le port, l'appareil), si bien qu'accepter un programme ne fait pas taire son voisin. Le fichier est
//! scellé (`sceau::NORMALES`) : changé hors de Vanguard, accepté sans sceau ou illisible, il ne fait rien taire.

use std::collections::BTreeMap;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::langue::Reponse;
use crate::ui::*;

/// Durée d'un choix : au-delà, l'alerte revient (la situation a pu changer).
const DUREE_JOURS: i64 = 90;
/// Les alertes récentes proposées : celles des 30 derniers jours, les plus récentes d'abord.
const JOURS_RECENTS: i64 = 30;
const RECENTES_MAX: usize = 9;

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
struct Normales {
    #[serde(default)]
    alertes: BTreeMap<String, Normale>,
}

/// Une alerte déclarée normale : telle qu'elle a été vue, et quand.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Normale {
    /// Le genre du tableau de bord (« veilleur », « botnet »), jamais traduit.
    genre: String,
    titre: String,
    texte: String,
    /// AAAA-MM-JJ.
    le: String,
}

/// Pourquoi la liste ne compte pas : rien n'est alors tu (les alertes reviennent, jamais l'inverse).
#[derive(Debug, PartialEq)]
enum Refus {
    /// Changée hors de Vanguard, ou acceptée sans sceau (sceaux effacés) : un programme du compte qui s'y ajoute
    /// ferait taire sa propre alerte.
    Falsifiee,
    Illisible,
}

fn charger() -> Result<Normales, Refus> {
    use crate::sceau::Lecture;
    match crate::sceau::lire(crate::sceau::NORMALES) {
        Lecture::Absent | Lecture::Inconnu => Ok(Normales::default()),
        Lecture::Intact(o) => serde_json::from_slice(&o).map_err(|_| Refus::Illisible),
        // Ce fichier n'existe que depuis les sceaux : accepté sans sceau, c'est que les sceaux ont été effacés.
        Lecture::Adopte(_) | Lecture::Falsifie(_) => Err(Refus::Falsifiee),
        Lecture::Illisible(_) => Err(Refus::Illisible),
    }
}

fn enregistrer(n: &Normales) -> std::io::Result<()> {
    crate::sceau::ecrire(
        crate::sceau::NORMALES,
        serde_json::to_string_pretty(n).map_err(std::io::Error::other)?,
    )
}

fn aujourd_hui() -> NaiveDate {
    chrono::Local::now().date_naive()
}

fn date(texte: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(texte, "%Y-%m-%d").ok()
}

/// Le choix vaut-il encore, ce jour-là ?
fn en_vigueur(n: &Normale, jour: NaiveDate) -> bool {
    date(&n.le).is_some_and(|le| (jour - le).num_days() < DUREE_JOURS && le <= jour)
}

fn est_normale_dans(n: &Normales, cle: &str, jour: NaiveDate) -> bool {
    n.alertes.get(cle).is_some_and(|x| en_vigueur(x, jour))
}

/// Cette alerte a-t-elle été déclarée normale ici, et le choix vaut-il encore ? Liste changée hors de Vanguard ou
/// illisible : non, rien n'est tu.
pub(crate) fn est_normale(cle: &str) -> bool {
    charger().is_ok_and(|n| est_normale_dans(&n, cle, aujourd_hui()))
}

/// Les alertes déclarées normales, pour les traces d'incident : (clé, jour du choix, titre), ou pourquoi la liste
/// ne compte pas.
pub(crate) fn pour_traces() -> Result<Vec<(String, String, String)>, &'static str> {
    charger()
        .map(|n| n.alertes.into_iter().map(|(c, a)| (c, a.le, a.titre)).collect())
        .map_err(|r| raison(&r))
}

/// La clé d'une alerte du veilleur.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn cle_veilleur(cle: &str) -> String {
    format!("veilleur|{cle}")
}

/// La clé d'une menace du blocage.
pub(crate) fn cle_blocage(cle: &str) -> String {
    format!("blocage|{cle}")
}

/// Retient qu'une alerte est normale ici. `Err` : pourquoi rien n'a été retenu.
pub(crate) fn declarer(cle: &str, genre: &str, titre: &str, texte: &str) -> Result<(), crate::modele::Echec> {
    use crate::modele::{Echec, Raison};
    const OU: &str = "normales/declarer";
    let mut n = charger().map_err(|r| match r {
        Refus::Falsifiee => Echec::new(OU, Raison::Falsifie).detail(raison(&r)),
        Refus::Illisible => Echec::new(OU, Raison::Illisible(raison(&r).to_string())),
    })?;
    n.alertes.insert(
        cle.to_string(),
        Normale {
            genre: genre.to_string(),
            titre: titre.to_string(),
            texte: texte.to_string(),
            le: aujourd_hui().format("%Y-%m-%d").to_string(),
        },
    );
    enregistrer(&n).map_err(|e| Echec::ecriture(OU, &e))?;
    noter_au_journal(cle, Some(titre));
    Ok(())
}

fn raison(r: &Refus) -> &'static str {
    match r {
        Refus::Falsifiee => tr!(
            "la liste des alertes normales a été changée hors de Vanguard",
            "the list of normal alerts was changed outside Vanguard"
        ),
        Refus::Illisible => tr!(
            "la liste des alertes normales ne se lit plus",
            "the list of normal alerts can no longer be read"
        ),
    }
}

/// Le genre que Vanguard donne aux alertes d'une clé : une alerte du journal ne se déclare normale que si son genre
/// est celui de sa clé. Le journal n'est pas scellé : une ligne ajoutée par un programme du compte (titre anodin,
/// genre « veilleur ») avec la clé d'un blocage aurait fait taire le blocage de ce programme pendant 90 jours.
fn genre_de_la_cle(cle: &str, genre: &str) -> bool {
    use crate::reseau::tableau::{Genre, nom_genre};
    let attendus: &[Genre] = match cle.split_once('|').map(|(p, _)| p) {
        // Le veilleur note aussi, avec sa clé, la connexion fermée avec un serveur de botnet et les rafales de
        // chiffrement (« veilleur|rancongiciel|… ») : sans ce genre, un outil de chiffrement voulu ne pouvait jamais
        // être déclaré normal. Le garde-fou reste entier : une ligne forgée ne tait que la clé qu'elle nomme, jamais
        // un blocage.
        Some("veilleur") => &[Genre::Veilleur, Genre::Botnet, Genre::Rancongiciel],
        Some("blocage") => &[Genre::Blocage],
        Some("botnet") => &[Genre::Botnet],
        Some("site") => &[Genre::Telechargement],
        Some("appareil") => &[Genre::Appareil],
        Some("port") => &[Genre::Port],
        // Les alertes des journaux de Windows (`journaux_windows::regles::resultat::cle_normale`).
        Some("evenements") => &[Genre::Evenements],
        _ => &[],
    };
    attendus.iter().any(|g| nom_genre(*g) == genre)
}

/// Ce que désigne la clé d'une alerte, à montrer avant de la déclarer normale : le titre et le texte se lisent
/// dans un journal que tout programme du compte peut écrire, la clé dit ce qui sera vraiment tu.
fn concerne(cle: &str) -> String {
    const MAX: usize = 160;
    let montre = affichable(cle);
    match montre.char_indices().nth(MAX) {
        Some((i, _)) => format!("{}…", &montre[..i]),
        None => montre,
    }
}

/// Les alertes récentes du journal qu'on peut déclarer normales : une par clé (la plus récente), pas déjà normales,
/// des 30 derniers jours, les plus récentes d'abord ; seulement celles dont le genre est celui de leur clé.
fn recentes(
    alertes: &[crate::reseau::tableau::Alerte],
    n: &Normales,
    jour: NaiveDate,
) -> Vec<crate::reseau::tableau::Alerte> {
    let limite = (jour - chrono::Duration::days(JOURS_RECENTS))
        .format("%Y-%m-%d")
        .to_string();
    let mut vues = std::collections::HashSet::new();
    alertes
        .iter()
        .rev()
        .filter(|a| a.date >= limite)
        // Une alerte critique des journaux de Windows ne se tait jamais (le résultat l'ignore) : la proposer
        // tromperait.
        .filter(|a| {
            !(a.genre == crate::reseau::tableau::FAMILLE_EVENEMENTS && a.gravite == Some(crate::risk::Niveau::Critique))
        })
        .filter(|a| {
            a.cle
                .as_deref()
                .is_some_and(|c| genre_de_la_cle(c, &a.genre) && !est_normale_dans(n, c, jour))
        })
        .filter(|a| vues.insert(a.cle.clone()))
        .take(RECENTES_MAX)
        .cloned()
        .collect()
}

/// Dans « Ce que Vanguard a appris » : les alertes du veilleur, de la surveillance et du blocage déclarées normales
/// (à oublier), et les récentes (à déclarer normales).
pub(crate) fn section() {
    crate::ui::section(tr!("ALERTES DE LA SURVEILLANCE", "MONITORING ALERTS"));
    let mut n = match charger() {
        Ok(n) => n,
        Err(r) => {
            afficher_aligne(
                "  ✖ ",
                &trf!("{} : aucune alerte n'est tue.", "{}: no alert is silenced.", raison(&r)),
                4,
                "",
            );
            if demander(tr!(
                "  La remettre à zéro (les alertes reviennent toutes) ? [o/N] : ",
                "  Reset it (all alerts come back)? [y/N]: "
            ))
            .oui()
            {
                match enregistrer(&Normales::default()) {
                    Ok(()) => trp!("  {VERT}✔{RESET} Remise à zéro.", "  {VERT}✔{RESET} Reset."),
                    Err(e) => trp!("  ✖ Impossible d'enregistrer ({e}).", "  ✖ Could not save ({e})."),
                }
            }
            return;
        }
    };
    let jour = aujourd_hui();
    let declarees: Vec<(String, Normale)> = n.alertes.clone().into_iter().collect();
    let recentes = recentes(&crate::reseau::tableau::alertes(), &n, jour);
    if declarees.is_empty() && recentes.is_empty() {
        afficher_aligne(
            "  ",
            tr!(
                "Rien pour l'instant : les alertes du veilleur, de la surveillance et du blocage se déclarent normales ici quand elles reviennent sans raison.",
                "Nothing yet: watcher, monitoring and blocking alerts are declared normal here when they keep coming back for no reason."
            ),
            2,
            GRIS,
        );
        return;
    }
    let mut i = 0;
    if !declarees.is_empty() {
        trp!("  Déclarées normales :\n", "  Declared normal:\n");
        for (_, a) in &declarees {
            i += 1;
            let etat = match date(&a.le).map(|le| le + chrono::Duration::days(DUREE_JOURS)) {
                Some(f) if f > jour => trf!("jusqu'au {}", "until {}", f.format(tr!("%d/%m/%Y", "%Y-%m-%d"))),
                _ => tr!("expiré : elle revient", "expired: it comes back").to_string(),
            };
            afficher_aligne(
                &format!("  {TOUCHE}{i:>2}{RESET} "),
                &format!(
                    "{} · {} : {}",
                    crate::reseau::tableau::libelle_genre(&a.genre),
                    affichable(&a.titre),
                    affichable(&a.texte)
                ),
                5,
                "",
            );
            println!("     {GRIS}{etat}{RESET}");
        }
    }
    if !recentes.is_empty() {
        trp!("\n  Alertes récentes :\n", "\n  Recent alerts:\n");
        for a in &recentes {
            i += 1;
            afficher_aligne(
                &format!("  {TOUCHE}{i:>2}{RESET} "),
                &format!(
                    "{} · {} · {} : {}",
                    a.date.get(..16).unwrap_or(&a.date),
                    crate::reseau::tableau::libelle_genre(&a.genre),
                    a.titre,
                    a.texte
                ),
                5,
                "",
            );
            if let Some(cle) = &a.cle {
                afficher_aligne("     ", &trf!("Concerne : {}", "Concerns: {}", concerne(cle)), 5, GRIS);
            }
        }
    }
    let reponse = demander(tr!(
        "\n  Numéro(s) : une alerte normale s'oublie, une récente devient\n  normale pour 90 jours ; Entrée pour passer : ",
        "\n  Number(s): a normal alert is forgotten, a recent one becomes\n  normal for 90 days; Enter to skip: "
    ));
    let mut choix: Vec<usize> = reponse
        .split([' ', ','])
        .filter_map(|x| x.trim().parse::<usize>().ok())
        .filter(|x| (1..=i).contains(x))
        .collect();
    choix.sort_unstable();
    choix.dedup();
    if choix.is_empty() {
        return;
    }
    let mut faits = Vec::new();
    for c in &choix {
        if let Some((cle, _)) = declarees.get(c - 1) {
            n.alertes.remove(cle);
            faits.push((cle.clone(), None));
        } else if let Some(a) = recentes.get(c - 1 - declarees.len())
            && let Some(cle) = &a.cle
        {
            faits.push((cle.clone(), Some(a.titre.clone())));
            n.alertes.insert(
                cle.clone(),
                Normale {
                    genre: a.genre.clone(),
                    titre: a.titre.clone(),
                    texte: a.texte.clone(),
                    le: jour.format("%Y-%m-%d").to_string(),
                },
            );
        }
    }
    match enregistrer(&n) {
        Ok(()) => {
            for (cle, titre) in &faits {
                noter_au_journal(cle, titre.as_deref());
            }
            afficher_aligne(
                &format!("  {VERT}✔{RESET} "),
                tr!(
                    "Retenu : une alerte normale n'est plus notée ni notifiée (celle du blocage : la menace n'est plus proposée ni bloquée, sauf une menace certaine), une alerte oubliée revient.",
                    "Saved: a normal alert is no longer logged or notified (a blocking one: the threat is no longer offered or blocked, unless it is certain), a forgotten one comes back."
                ),
                4,
                "",
            );
        }
        Err(e) => trp!("  ✖ Impossible d'enregistrer ({e}).", "  ✖ Could not save ({e})."),
    }
}

/// Le choix va au journal des événements (`Some(titre)` : déclarée normale ; `None` : oubliée) : une alerte qui
/// cesse de sonner a sa raison datée, à côté des alertes qu'elle tait.
fn noter_au_journal(cle: &str, titre: Option<&str>) {
    use crate::modele::evenement::{Evenement, Genre, Source};
    let quoi = match titre {
        Some(t) => Genre::Normale { titre: t.to_string() },
        None => Genre::NormaleOubliee,
    };
    crate::modele::journal::noter(Evenement::nouveau(Source::Utilisateur, quoi).cle(Some(cle)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normale(le: &str) -> Normale {
        Normale {
            genre: "veilleur".into(),
            titre: "Vanguard : programme suspect lancé".into(),
            texte: "« outil » (PID 4242) lancé depuis /tmp".into(),
            le: le.into(),
        }
    }

    /// Un choix vaut 90 jours, pour sa clé seulement ; daté du futur (horloge reculée, fichier retouché), il ne
    /// vaut rien.
    #[test]
    fn un_choix_vaut_90_jours_pour_sa_cle() {
        let mut n = Normales::default();
        n.alertes
            .insert(cle_veilleur("dossier temporaire|/tmp/outil"), normale("2026-10-01"));
        let jour = |t| NaiveDate::parse_from_str(t, "%Y-%m-%d").unwrap();
        let cle = cle_veilleur("dossier temporaire|/tmp/outil");
        assert!(est_normale_dans(&n, &cle, jour("2026-10-23")));
        assert!(!est_normale_dans(&n, &cle, jour("2026-12-30")));
        assert!(!est_normale_dans(
            &n,
            &cle_veilleur("dossier temporaire|/tmp/outil2"),
            jour("2026-10-23")
        ));
        n.alertes
            .insert(cle_blocage("connexion:203.0.113.7"), normale("2027-01-01"));
        assert!(!est_normale_dans(
            &n,
            &cle_blocage("connexion:203.0.113.7"),
            jour("2026-10-23")
        ));
    }

    /// Déclarée normale, puis la liste réécrite hors de Vanguard : plus rien n'est tu, et une nouvelle déclaration
    /// n'écrase pas la liste en silence.
    #[test]
    fn liste_falsifiee_ne_tait_rien() {
        let cle = cle_blocage("connexion:198.51.100.77");
        declarer(&cle, "blocage", "Vanguard a bloqué une menace", "x").unwrap();
        assert!(est_normale(&cle));
        let chemin = crate::reseau::dossier_local().join(crate::sceau::NORMALES);
        let mut texte = std::fs::read_to_string(&chemin).unwrap();
        texte.push(' ');
        std::fs::write(&chemin, texte).unwrap();
        assert!(!est_normale(&cle));
        assert!(declarer(&cle_blocage("autre"), "blocage", "t", "x").is_err());
        enregistrer(&Normales::default()).unwrap();
        assert!(!est_normale(&cle));
    }

    /// Les alertes récentes proposées : une par clé, sans celles qui n'en ont pas ni celles déjà normales.
    #[test]
    fn alertes_recentes_a_declarer() {
        let ligne = |date: &str, cle: Option<&str>| crate::reseau::tableau::Alerte {
            gravite: None,
            date: date.into(),
            genre: "veilleur".into(),
            titre: "t".into(),
            texte: date.into(),
            cle: cle.map(str::to_string),
        };
        let journal = vec![
            ligne("2026-08-01 10:00:00", Some("veilleur|vieille")),
            ligne("2026-10-20 10:00:00", Some("veilleur|a")),
            ligne("2026-10-21 10:00:00", None),
            ligne("2026-10-22 10:00:00", Some("veilleur|a")),
            ligne("2026-10-22 11:00:00", Some("veilleur|deja")),
        ];
        let mut n = Normales::default();
        n.alertes.insert("veilleur|deja".into(), normale("2026-10-22"));
        let jour = NaiveDate::parse_from_str("2026-10-23", "%Y-%m-%d").unwrap();
        let r = recentes(&journal, &n, jour);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].texte, "2026-10-22 10:00:00");
    }

    /// Une ligne ajoutée au journal par un programme du compte : genre « veilleur », titre anodin, mais la clé d'un
    /// blocage. Elle n'est pas proposée, sans quoi la déclarer normale ferait taire le blocage de ce programme.
    #[test]
    fn alerte_dont_le_genre_n_est_pas_celui_de_sa_cle_pas_proposee() {
        let ligne = |genre: &str, cle: &str| crate::reseau::tableau::Alerte {
            gravite: None,
            date: "2026-10-22 10:00:00".into(),
            genre: genre.into(),
            titre: "Mise à jour de Firefox".into(),
            texte: cle.into(),
            cle: Some(cle.into()),
        };
        let journal = vec![
            ligne("veilleur", "blocage|programme:/tmp/x"),
            ligne("autre", "veilleur|dossier temporaire|/tmp/y"),
            ligne("blocage", "blocage|connexion:203.0.113.7"),
            ligne("botnet", "veilleur|203.0.113.8:443"),
        ];
        let jour = NaiveDate::parse_from_str("2026-10-23", "%Y-%m-%d").unwrap();
        let r = recentes(&journal, &Normales::default(), jour);
        let cles: Vec<&str> = r.iter().filter_map(|a| a.cle.as_deref()).collect();
        assert_eq!(cles, ["veilleur|203.0.113.8:443", "blocage|connexion:203.0.113.7"]);
        assert_eq!(concerne("blocage|x\x1b[2Jy"), affichable("blocage|x\x1b[2Jy"));
        assert!(concerne(&"a".repeat(400)).ends_with('…'));
    }

    /// Un outil de chiffrement voulu, alerté par la veille des fichiers : son alerte (genre « rancongiciel », clé du
    /// veilleur) se propose ; la même clé sous le genre « blocage » reste écartée.
    #[test]
    fn alerte_rancongiciel_du_veilleur_proposee() {
        let ligne = |genre: &str| crate::reseau::tableau::Alerte {
            gravite: None,
            date: "2026-10-22 10:00:00".into(),
            genre: genre.into(),
            titre: "t".into(),
            texte: genre.into(),
            cle: Some("veilleur|rancongiciel|/home/user/outil".into()),
        };
        let jour = NaiveDate::parse_from_str("2026-10-23", "%Y-%m-%d").unwrap();
        let r = recentes(&[ligne("rancongiciel")], &Normales::default(), jour);
        assert_eq!(r.len(), 1);
        let r = recentes(&[ligne("blocage")], &Normales::default(), jour);
        assert_eq!(r.len(), 0);
    }

    /// Une alerte des journaux de Windows se propose, sous son genre seulement ; une critique jamais (le résultat ne
    /// la tait pas : la proposer tromperait).
    #[test]
    fn alerte_des_journaux_de_windows_proposee_sauf_critique() {
        use crate::risk::Niveau;
        let ligne = |genre: &str, cle: &str, gravite: Niveau| crate::reseau::tableau::Alerte {
            gravite: Some(gravite),
            date: "2026-10-22 10:00:00".into(),
            genre: genre.into(),
            titre: "EVT-SRV-001 : alerte".into(),
            texte: cle.into(),
            cle: Some(cle.into()),
        };
        let jour = NaiveDate::parse_from_str("2026-10-23", "%Y-%m-%d").unwrap();
        let journal = vec![
            ligne("evenements", "evenements|EVT-SRV-001|x|c:\\temp\\x.exe", Niveau::Eleve),
            ligne("evenements", "evenements|EVT-EFF-001|security|1", Niveau::Critique),
            ligne("veilleur", "evenements|EVT-ADM-001|alice", Niveau::Eleve),
        ];
        let r = recentes(&journal, &Normales::default(), jour);
        let cles: Vec<&str> = r.iter().filter_map(|a| a.cle.as_deref()).collect();
        assert_eq!(cles, ["evenements|EVT-SRV-001|x|c:\\temp\\x.exe"]);
    }
}
