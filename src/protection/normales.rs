//! Les alertes déclarées normales hors du bilan : celles du veilleur, de la surveillance horaire et du blocage. Un
//! faux positif durable (un outil de développement lancé depuis /tmp, un appareil connu qui réapparaît) revenait
//! sans fin, et le seul remède était de couper la défense ; la fatigue d'alerte pousse à tout désactiver. Comme les
//! choix du bilan (`apprentissage`), un choix vaut 90 jours, se relit et s'oublie dans « Ce que Vanguard a appris ».
//!
//! Le choix porte sur la clé de l'alerte, jamais sur son texte traduit : l'objet précis (le programme et sa raison,
//! l'adresse et le port, l'appareil), si bien qu'accepter un programme ne fait pas taire son voisin. Le fichier est
//! scellé (`sceau::NORMALES`) : changé hors de Vanguard, accepté sans sceau ou illisible, il ne fait rien taire.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

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
    charger_de(&crate::socle::dossier_local())
}

/// La liste du dossier `dossier` : les essais qui la falsifient en ont un à eux, sans toucher celle des autres.
fn charger_de(dossier: &std::path::Path) -> Result<Normales, Refus> {
    use crate::sceau::Lecture;
    match crate::sceau::lire_dans(dossier, crate::sceau::NORMALES) {
        Lecture::Absent | Lecture::Inconnu => Ok(Normales::default()),
        Lecture::Intact(o) => serde_json::from_slice(&o).map_err(|_| Refus::Illisible),
        // Ce fichier n'existe que depuis les sceaux : accepté sans sceau, c'est que les sceaux ont été effacés.
        Lecture::Adopte(_) | Lecture::Falsifie(_) => Err(Refus::Falsifiee),
        Lecture::Illisible(_) => Err(Refus::Illisible),
    }
}

fn enregistrer_vers(dossier: &std::path::Path, n: &Normales) -> std::io::Result<()> {
    crate::sceau::ecrire_dans(
        dossier,
        crate::sceau::NORMALES,
        serde_json::to_string_pretty(n)
            .map_err(std::io::Error::other)?
            .as_bytes(),
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
    date(&n.le).is_some_and(|le| jour.signed_duration_since(le).num_days() < DUREE_JOURS && le <= jour)
}

fn est_normale_dans(n: &Normales, cle: &str, jour: NaiveDate) -> bool {
    n.alertes.get(cle).is_some_and(|x| en_vigueur(x, jour))
}

/// Cette alerte a-t-elle été déclarée normale ici, et le choix vaut-il encore ? Liste changée hors de Vanguard ou
/// illisible : non, rien n'est tu.
pub(crate) fn est_normale(cle: &str) -> bool {
    est_normale_de(&crate::socle::dossier_local(), cle)
}

fn est_normale_de(dossier: &std::path::Path, cle: &str) -> bool {
    charger_de(dossier).is_ok_and(|n| est_normale_dans(&n, cle, aujourd_hui()))
}

/// Les alertes déclarées normales, pour les traces d'incident : (clé, jour du choix, titre), ou pourquoi la liste
/// ne compte pas.
pub(crate) fn pour_traces() -> Result<Vec<(String, String, String)>, &'static str> {
    charger()
        .map(|n| n.alertes.into_iter().map(|(c, a)| (c, a.le, a.titre)).collect())
        .map_err(|r| raison(&r))
}

/// La clé d'une alerte du veilleur.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn cle_veilleur(cle: &str) -> String {
    format!("veilleur|{cle}")
}

/// La clé d'une menace du blocage.
pub(crate) fn cle_blocage(cle: &str) -> String {
    format!("blocage|{cle}")
}

/// La clé que pose la sortie de quarantaine d'un fichier : son contenu exact (empreinte) à ce chemin. Un autre
/// préfixe que `cle_blocage` : « c'est normal ici » (un douteux) ne la pose jamais, et elle seule tait un certain.
pub(crate) fn cle_remise(empreinte: &[u8; 32], chemin: &std::path::Path) -> String {
    format!(
        "quarantaine-remise|sha256:{}|fichier:{}",
        crate::protection::empreintes::hex(empreinte),
        chemin.display()
    )
}

/// Retient qu'une alerte est normale ici. `Err` : pourquoi rien n'a été retenu.
pub(crate) fn declarer(cle: &str, genre: &str, titre: &str, texte: &str) -> Result<(), crate::modele::Echec> {
    declarer_dans(&crate::socle::dossier_local(), cle, genre, titre, texte)
}

fn declarer_dans(
    dossier: &std::path::Path,
    cle: &str,
    genre: &str,
    titre: &str,
    texte: &str,
) -> Result<(), crate::modele::Echec> {
    sous_verrou(dossier, "normales/declarer", |n| {
        n.alertes.insert(
            cle.to_string(),
            Normale {
                genre: genre.to_string(),
                titre: titre.to_string(),
                texte: texte.to_string(),
                le: aujourd_hui().format("%Y-%m-%d").to_string(),
            },
        );
    })?;
    noter_au_journal(cle, Some(titre));
    Ok(())
}

/// Le verrou des changements de la liste, à côté d'elle : tenu de la relecture jusqu'à l'écriture. À part du verrou
/// des sceaux, qu'`ecrire_dans` prend lui-même (un `flock` ne se reprend pas dans le même processus).
pub(crate) const VERROU: &str = "normales.lock";

/// Le seul chemin d'écriture de la liste, avec sa remise à zéro (vérification 0.94) : sous `VERROU`, elle est
/// relue, `changer` la change telle qu'elle est maintenant, puis elle est écrite. Relue avant le verrou des sceaux,
/// deux Vanguard qui déclaraient en même temps (le blocage en direct, une sortie de quarantaine, le menu) écrivaient
/// chacun sa liste sans le choix de l'autre : une sortie de quarantaine oubliée, le fichier y retournait ; un choix
/// oublié dans le menu, réécrit par l'autre, taisait de nouveau son alerte. `Err` : rien n'a changé.
fn sous_verrou(
    dossier: &std::path::Path,
    ou: &'static str,
    changer: impl FnOnce(&mut Normales),
) -> Result<(), crate::modele::Echec> {
    use crate::modele::{Echec, Raison};
    let _verrou = verrou(dossier, ou)?;
    let mut n = charger_de(dossier).map_err(|r| match r {
        Refus::Falsifiee => Echec::new(ou, Raison::Falsifie).detail(raison(&r)),
        Refus::Illisible => Echec::new(ou, Raison::Illisible(raison(&r).to_string())),
    })?;
    changer(&mut n);
    enregistrer_vers(dossier, &n).map_err(|e| Echec::ecriture(ou, &e))
}

/// `VERROU` pris pour écrire la liste. Comme les sceaux : en administrateur dans le dossier d'un compte, rien n'y est
/// créé, pas même le verrou.
fn verrou(dossier: &std::path::Path, ou: &'static str) -> Result<crate::socle::Verrou, crate::modele::Echec> {
    use crate::modele::Echec;
    if !crate::socle::ecriture_sure(dossier) {
        return Err(Echec::ecriture(ou, &crate::sceau::dossier_d_un_autre()));
    }
    crate::socle::Verrou::prendre(dossier, VERROU, false, crate::socle::ATTENTE_ECRITURE)
        .map_err(|e| Echec::ecriture(ou, &e.erreur(VERROU)))
}

/// La liste remise à zéro (falsifiée ou illisible, à la demande), sous `VERROU` comme toute écriture : une
/// déclaration qui l'a relue juste avant n'écrit pas par-dessus (correction n° 2 de la 0.94, n3). `Err` : rien écrit.
fn remettre_a_zero_dans(dossier: &std::path::Path) -> Result<(), crate::modele::Echec> {
    let ou = "normales:remise-a-zero";
    let _verrou = verrou(dossier, ou)?;
    enregistrer_vers(dossier, &Normales::default()).map_err(|e| crate::modele::Echec::ecriture(ou, &e))
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
    // La confiance accordée à un fichier certain se tape dans le menu des gestes (P5), jamais d'ici : une ligne du
    // journal ne la propose pas.
    if cle.starts_with(crate::protection::blocage::choix::PREFIXE_CONFIANCE) {
        return false;
    }
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
    // Une date hors de chrono (impossible depuis l'horloge) : toutes les alertes passent pour récentes.
    let limite = jour
        .checked_sub_signed(chrono::Duration::days(JOURS_RECENTS))
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();
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
    let n = match charger() {
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
                match remettre_a_zero_dans(&crate::socle::dossier_local()) {
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
    let mut i = 0usize;
    if !declarees.is_empty() {
        trp!("  Déclarées normales :\n", "  Declared normal:\n");
        for (_, a) in &declarees {
            i = i.saturating_add(1);
            let etat = match date(&a.le).and_then(|le| le.checked_add_signed(chrono::Duration::days(DUREE_JOURS))) {
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
            i = i.saturating_add(1);
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
        // Un numéro 0 ne désigne rien (la liste commence à 1).
        let rang = c.checked_sub(1);
        if let Some((cle, _)) = rang.and_then(|r| declarees.get(r)) {
            faits.push((cle.clone(), None));
        } else if let Some(a) = rang
            .and_then(|r| r.checked_sub(declarees.len()))
            .and_then(|r| recentes.get(r))
            && let Some(cle) = &a.cle
        {
            faits.push((
                cle.clone(),
                Some(Normale {
                    genre: a.genre.clone(),
                    titre: a.titre.clone(),
                    texte: a.texte.clone(),
                    le: jour.format("%Y-%m-%d").to_string(),
                }),
            ));
        }
    }
    // Les choix seuls, posés sur la liste relue sous le verrou : celle lue avant la question a pu changer depuis.
    match sous_verrou(&crate::socle::dossier_local(), "normales/section", |n| {
        appliquer(n, &faits);
    }) {
        Ok(()) => {
            for (cle, choix) in &faits {
                noter_au_journal(cle, choix.as_ref().map(|a| a.titre.as_str()));
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

/// Les choix du menu sur la liste : `Some` la déclare normale, `None` l'oublie.
fn appliquer(n: &mut Normales, faits: &[(String, Option<Normale>)]) {
    for (cle, choix) in faits {
        match choix {
            Some(a) => {
                n.alertes.insert(cle.clone(), a.clone());
            }
            None => {
                n.alertes.remove(cle);
            }
        }
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

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
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
    /// n'écrase pas la liste en silence. Dans un dossier à lui : falsifiée dans le dossier commun des essais, elle
    /// faisait échouer au hasard ceux qui tournaient en même temps (la quarantaine, sous Wine).
    #[test]
    fn liste_falsifiee_ne_tait_rien() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let cle = cle_blocage("connexion:198.51.100.77");
        declarer_dans(&d, &cle, "blocage", "Vanguard a bloqué une menace", "x").unwrap();
        assert!(est_normale_de(&d, &cle));
        let chemin = d.join(crate::sceau::NORMALES);
        let mut texte = std::fs::read_to_string(&chemin).unwrap();
        texte.push(' ');
        std::fs::write(&chemin, texte).unwrap();
        assert!(!est_normale_de(&d, &cle));
        assert!(declarer_dans(&d, &cle_blocage("autre"), "blocage", "t", "x").is_err());
        enregistrer_vers(&d, &Normales::default()).unwrap();
        assert!(!est_normale_de(&d, &cle));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Correction n° 2 de la 0.94, n3 : la remise à zéro prend `VERROU` comme toute écriture. Verrou impossible à
    /// prendre (un dossier à sa place) : rien n'est écrit, la liste falsifiée le reste et rien n'est tu.
    #[test]
    fn remise_a_zero_sous_le_verrou() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let cle = cle_blocage("connexion:198.51.100.78");
        declarer_dans(&d, &cle, "blocage", "t", "x").unwrap();
        let chemin = d.join(crate::sceau::NORMALES);
        let mut texte = std::fs::read_to_string(&chemin).unwrap();
        texte.push(' ');
        std::fs::write(&chemin, &texte).unwrap();
        std::fs::remove_file(d.join(VERROU)).unwrap();
        std::fs::create_dir(d.join(VERROU)).unwrap();
        assert!(remettre_a_zero_dans(&d).is_err());
        assert_eq!(
            std::fs::read_to_string(&chemin).unwrap(),
            texte,
            "écrite sans le verrou"
        );
        std::fs::remove_dir(d.join(VERROU)).unwrap();
        remettre_a_zero_dans(&d).unwrap();
        assert!(charger_de(&d).unwrap().alertes.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Deux Vanguard qui déclarent en même temps (le blocage en direct, une sortie de quarantaine) ne s'effacent pas :
    /// relue avant le verrou des sceaux, la liste de l'un était réécrite sans le choix de l'autre (vu sous Wine : la
    /// sortie de quarantaine oubliée, le fichier y serait retourné à la passe suivante).
    #[test]
    fn declarations_simultanees_toutes_gardees() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        std::thread::scope(|s| {
            for fil in 0..8 {
                let d = &d;
                s.spawn(move || {
                    for i in 0..10 {
                        declarer_dans(d, &cle_blocage(&format!("essai:{fil}-{i}")), "blocage", "t", "x").unwrap();
                    }
                });
            }
        });
        let n = charger_de(&d).unwrap();
        let perdues: Vec<_> = (0..8)
            .flat_map(|fil| (0..10).map(move |i| cle_blocage(&format!("essai:{fil}-{i}"))))
            .filter(|c| !n.alertes.contains_key(c))
            .collect();
        assert!(
            perdues.is_empty(),
            "{} déclaration(s) perdue(s) : {perdues:?}",
            perdues.len()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le menu pose ses choix sur la liste relue au moment d'écrire, pas sur celle montrée avant la question : un
    /// choix déclaré ailleurs pendant qu'il attendait reste, celui qu'il oublie s'en va.
    #[test]
    fn choix_du_menu_poses_sur_la_liste_du_moment() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let (oubliee, venue) = (cle_blocage("essai:oubliee"), cle_blocage("essai:venue-entre-temps"));
        declarer_dans(&d, &oubliee, "blocage", "t", "x").unwrap();
        declarer_dans(&d, &venue, "blocage", "t", "x").unwrap();
        let faits = vec![
            (oubliee.clone(), None),
            (cle_veilleur("essai:choisie"), Some(normale("2026-11-11"))),
        ];
        sous_verrou(&d, "essai", |n| appliquer(n, &faits)).unwrap();
        let n = charger_de(&d).unwrap();
        assert!(!n.alertes.contains_key(&oubliee));
        assert!(n.alertes.contains_key(&venue));
        assert!(n.alertes.contains_key(&cle_veilleur("essai:choisie")));
        let _ = std::fs::remove_dir_all(&d);
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
            // La confiance à un fichier certain se tape au menu des gestes, jamais depuis le journal.
            ligne("blocage", "blocage|confiance|abcdef"),
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
