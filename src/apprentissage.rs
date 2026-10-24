//! Ce que Vanguard apprend sur cet ordinateur, gardé ici seulement (appris.json) : les alertes que tu as déclarées
//! normales chez toi. Une alerte acceptée reste visible, au niveau info, avec la date de ton choix ; elle n'est plus
//! proposée à la correction ni notifiée par la surveillance. Elle revient au bout de 90 jours, ou tout de suite si
//! elle devient plus grave qu'au moment de ton choix. « Ce que Vanguard a appris » (menu Cette machine) montre tout et
//! permet d'oublier.

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
    use crate::sceau::Lecture;
    match crate::sceau::lire(crate::sceau::APPRIS) {
        // Inconnue (sceaux refaits) : une liste vide ne tait rien.
        Lecture::Absent | Lecture::Inconnu => Ok(Appris::default()),
        // Adoptée au premier usage : appliquée comme avant les sceaux, mais le bilan le dit (COM-ETA-001) et le menu
        // propose de la garder.
        Lecture::Intact(o) | Lecture::Adopte(o) => serde_json::from_slice(&o).map_err(|_| Refus::Illisible),
        Lecture::Falsifie(o) => Err(Refus::Falsifiee(o.and_then(|o| serde_json::from_slice(&o).ok()))),
        Lecture::Illisible(_) => Err(Refus::Illisible),
    }
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
    while i < lettres.len() {
        if !lettres[i].is_ascii_digit() {
            sortie.push(lettres[i]);
            i += 1;
            continue;
        }
        // Un bloc de chiffres, avec ce qui les lie (« 10.0.0.5 », « 12:30 », « 4.5.4 »).
        let debut = i;
        while i < lettres.len()
            && (lettres[i].is_ascii_digit()
                || (matches!(lettres[i], '.' | ':') && lettres.get(i + 1).is_some_and(char::is_ascii_digit)))
        {
            i += 1;
        }
        let bloc: String = lettres[debut..i].iter().collect();
        let lie = |c: Option<&char>| c.is_some_and(|c| c.is_alphanumeric() || *c == '_');
        // Avant : une lettre, « _ », ou un « - » qui suit lui-même une lettre ou un chiffre (« S-1-5 », pas « -60 »).
        let avant = lie(debut.checked_sub(1).and_then(|j| lettres.get(j)))
            || (debut >= 2 && lettres[debut - 1] == '-' && lie(lettres.get(debut - 2)));
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
fn en_vigueur(choix: &Acceptee, niveau: Niveau, jour: NaiveDate) -> bool {
    niveau <= choix.niveau && date(&choix.le).is_some_and(|le| (jour - le).num_days() < DUREE_JOURS)
}

/// Retient qu'une alerte est normale ici.
pub fn accepter(c: &Constat) {
    let Some(niveau) = c.probleme else {
        return;
    };
    let mut appris = match charger() {
        Ok(a) => a,
        Err(Refus::Illisible) => {
            trp!(
                "    ✖ La liste de vos choix ne se lit plus ({}) : rien n'est retenu, pour ne pas l'écraser.",
                "    ✖ Your choice list can no longer be read ({}): nothing is saved, so as not to overwrite it.",
                fichier().display()
            );
            return;
        }
        Err(Refus::Falsifiee(_)) => {
            trp!(
                "    ✖ La liste de vos choix a été changée hors de Vanguard : rien\n      n'est retenu. « Ce que Vanguard a appris » la montre, pour la\n      reprendre ou l'oublier.",
                "    ✖ Your choice list was changed outside Vanguard: nothing is\n      saved. “What Vanguard has learned” shows it, to take it back or\n      forget it."
            );
            return;
        }
    };
    retenir(&mut appris, c, niveau, aujourd_hui());
    match enregistrer(&appris) {
        Ok(()) => trp!(
            "    {GRIS}retenu pour {DUREE_JOURS} jours, sauf si elle s'aggrave{RESET}",
            "    {GRIS}noted for {DUREE_JOURS} days, unless it gets worse{RESET}"
        ),
        Err(e) => trp!("    ✖ Choix non retenu ({e}).", "    ✖ Choice not saved ({e})."),
    }
}

/// Ajoute le choix d'une alerte à la liste. Un seul choix par clé : l'ancien, écrit dans une autre langue ou une
/// autre tournure (donc sous une autre signature), resterait à côté et pourrait masquer celui-ci dans `choix_pour`.
fn retenir(appris: &mut Appris, c: &Constat, niveau: Niveau, jour: NaiveDate) {
    let cle = c.cle().map(|k| k.to_string());
    if let Some(k) = &cle {
        appris.acceptees.retain(|_, a| a.cle.as_ref() != Some(k));
    }
    appris.acceptees.insert(
        signature(c.categorie, &c.message),
        Acceptee {
            categorie: c.categorie.to_string(),
            message: c.message.clone(),
            niveau,
            le: jour.format("%Y-%m-%d").to_string(),
            cle,
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
    let mut cles = Vec::new();
    let n = appliquer_avec(&appris, constats, aujourd_hui(), &mut cles);
    // Pas sur une liste adoptée au premier usage des sceaux : la réécrire la scellerait sans ton accord (le menu le
    // demande).
    if completer(&mut appris, cles) && !crate::sceau::adopte(crate::sceau::APPRIS) {
        let _ = enregistrer(&appris);
    }
    n
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
        .map(|e| signature(CAT, e)[CAT.len() + 3..].to_string())
        .collect();
    appris.acceptees.iter().find_map(|(sig, a)| {
        (a.cle.is_none() && sig.starts_with(&debut) && elements.iter().all(|e| sig.contains(e.as_str()))).then_some(a)
    })
}

/// Complète les choix retrouvés par leur texte de la clé de leur alerte ; `true` s'il y a lieu de réécrire la liste.
fn completer(appris: &mut Appris, cles: Vec<(String, String)>) -> bool {
    let mut change = false;
    for (signature, cle) in cles {
        if let Some(a) = appris.acceptees.get_mut(&signature)
            && a.cle.is_none()
        {
            a.cle = Some(cle);
            change = true;
        }
    }
    change
}

fn appliquer_avec(
    appris: &Appris,
    constats: &mut [Constat],
    jour: NaiveDate,
    a_completer: &mut Vec<(String, String)>,
) -> usize {
    let mut n = 0;
    for c in constats.iter_mut() {
        let Some(niveau) = c.probleme else {
            continue;
        };
        let Some((choix, completer)) = choix_pour(appris, c) else {
            continue;
        };
        if !en_vigueur(choix, niveau, jour) {
            continue;
        }
        a_completer.extend(completer);
        let le = date(&choix.le).map(affichee).unwrap_or_default();
        c.probleme = Some(Niveau::Info);
        c.correctif = None;
        c.message += &trf!(
            " (normal chez vous, selon votre choix du {le})",
            " (normal for you, as you chose on {le})"
        );
        n += 1;
    }
    n
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
    let mut appris = match charger() {
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
            let _ = enregistrer(&appris);
        }
        for ligne in envelopper(
            tr!(
                "Rien pour l'instant. Quand une alerte est normale chez vous, répondez « i » au moment de la corriger : Vanguard s'en souviendra pendant 90 jours, et vous la montrera seulement pour info.",
                "Nothing yet. When an alert is normal for you, answer “i” when it is offered as a fix: Vanguard will remember it for 90 days, and only show it for information."
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
        let fin = date(&a.le).map(|le| le + chrono::Duration::days(DUREE_JOURS));
        let etat = match fin {
            Some(f) if f > jour => trf!("jusqu'au {}", "until {}", affichee(f)),
            _ => tr!("expiré : la question reviendra", "expired: the question will come back").to_string(),
        };
        afficher_aligne(
            &format!("  {TOUCHE}{:>2}{RESET} ", i + 1),
            &format!("{} : {}", crate::langue::categorie(&a.categorie), a.message),
            5,
            "",
        );
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
            .map(|n| n - 1)
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
    for i in &a_oublier {
        appris.acceptees.remove(&liste[*i].0);
    }
    match enregistrer(&appris) {
        Ok(()) => trp!(
            "  {VERT}✔{RESET} {} choix oublié(s) : ces alertes reviendront normalement.",
            "  {VERT}✔{RESET} {} choice(s) forgotten: these alerts will come back as usual.",
            a_oublier.len()
        ),
        Err(e) => trp!("  ✖ Impossible d'enregistrer ({e}).", "  ✖ Could not save ({e})."),
    }
}

/// La liste acceptée telle quelle au premier usage des sceaux (le jour où Vanguard est passé à une version qui
/// scelle, ou `sceaux.json` effacé par un autre programme) : appliquée, mais seulement rescellée sur ton accord.
fn garder_adoptee(appris: &Appris) {
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
    match enregistrer(appris) {
        Ok(()) => trp!("  {VERT}✔{RESET} C'est noté.", "  {VERT}✔{RESET} Noted."),
        Err(e) => trp!("  ✖ Impossible d'enregistrer ({e}).", "  ✖ Could not save ({e})."),
    }
}

/// La liste changée hors de Vanguard : montrée telle qu'elle est maintenant, sans être appliquée. Toi seul sais si ces
/// choix sont les tiens (une copie de Vanguard plus ancienne écrit aussi sans sceau) : les garder les rescelle, sinon
/// ils sont oubliés, et leurs alertes reviennent.
fn reprendre(contenu: Option<Appris>) {
    trp!(
        "  ✖ La liste de vos choix a été changée hors de Vanguard :\n    aucun n'est appliqué.",
        "  ✖ Your choice list was changed outside Vanguard:\n    none is applied."
    );
    let appris = contenu.unwrap_or_default();
    for a in appris.acceptees.values() {
        afficher_aligne(
            "    ",
            &format!("{} : {}", crate::langue::categorie(&a.categorie), a.message),
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
    let ecrit = if garder {
        enregistrer(&appris)
    } else if demander(tr!(
        "  Tout oublier (leurs alertes reviendront) ? [o/N] : ",
        "  Forget everything (their alerts will come back)? [y/N]: "
    ))
    .oui()
    {
        crate::sceau::effacer(crate::sceau::APPRIS)
    } else {
        return;
    };
    match ecrit {
        Ok(()) => trp!("  {VERT}✔{RESET} C'est noté.", "  {VERT}✔{RESET} Noted."),
        Err(e) => trp!("  ✖ Impossible d'enregistrer ({e}).", "  ✖ Could not save ({e})."),
    }
}

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
                defaire: crate::machine::Defaire::Inconnu,
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
            },
        );
        a
    }

    fn jour(t: &str) -> NaiveDate {
        date(t).unwrap()
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
        assert!(completer(&mut a, cles));
        assert!(!completer(&mut a, vec![]), "rien à réécrire");
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

    /// macOS : accepter un agent de démarrage ne fait taire ni un autre programme lancé par le même fichier, ni ce
    /// fichier devenu illisible.
    #[test]
    fn agent_accepte_puis_reecrit() {
        let plist = "/Users/alice/Library/LaunchAgents/com.exemple.aide.plist";
        let agent = |lance: Option<&str>| {
            let mut c = constat(
                "Persistance",
                Niveau::Eleve,
                "« com.exemple.aide » se relance à chaque démarrage.",
            )
            .avec_objet(crate::modele::Objet::agent(plist, lance));
            c.regle = "MAC-PRS-001";
            c
        };
        let mut a = Appris::default();
        retenir(
            &mut a,
            &agent(Some("/opt/exemple/aide ")),
            Niveau::Eleve,
            jour("2026-10-22"),
        );
        let mut meme = [agent(Some("/opt/exemple/aide "))];
        assert_eq!(appliquer_le(&a, &mut meme, jour("2026-10-23")), 1);
        for autre in [Some("/tmp/x "), None] {
            let mut c = [agent(autre)];
            assert_eq!(appliquer_le(&a, &mut c, jour("2026-10-23")), 0);
            assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        }
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
