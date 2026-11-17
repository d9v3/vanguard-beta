//! La liste blanche des mots de la porte : un texte venu de l'ordinateur (message d'un constat, titre d'une alerte,
//! nom d'un programme) ne sort que fait des mots que Vanguard écrit lui-même dans ses propres messages, en français et
//! en anglais. Tout autre mot, chiffre ou signe devient « … » : un chemin, une adresse, un numéro, une valeur à
//! chiffres ou à signes n'ont pas à être reconnus pour être retenus. Un nom ou un secret fait de mots du vocabulaire
//! (« admin », « maison »), lui, n'est retenu que par les filets de `vues::texte_externe` (après un mot qui annonce un
//! secret, dans l'extrait d'une commande).
//!
//! Le vocabulaire est tiré du code à la compilation (`build.rs`, fonction `vocabulaire`) : les chaînes des macros de
//! texte, sans les marques de format et sans les essais. Il suit donc le code sans geste humain. Il est découpé ici
//! avec les règles mêmes qui jugent un texte (`mots`), pour qu'un mot du code et le même mot dans un texte se
//! reconnaissent toujours.
//!
//! La limite, dite au modèle de menace : un texte fait de mots du vocabulaire sort tel quel, avec sa casse, ses
//! guillemets de tête et sa ponctuation. Un attaquant qui écrit sur l'ordinateur peut composer une phrase avec ces mots
//! (et épeler une valeur par leurs initiales) ; un nom qui est un mot du vocabulaire sort aussi.

use std::collections::HashSet;
use std::sync::LazyLock;

/// Les morceaux des chaînes de texte du code, un par ligne (écrits par `build.rs`).
const BRUT: &str = include_str!(concat!(env!("OUT_DIR"), "/vocabulaire.txt"));

/// Le vocabulaire, en minuscules, découpé comme un texte jugé.
static VOCABULAIRE: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let mut mots = HashSet::new();
    for ligne in BRUT.lines() {
        for jeton in normalise(ligne).split_whitespace() {
            let (_, coeur, _) = peler(jeton);
            if !forme_de_mot(coeur) {
                continue;
            }
            let bas = coeur.to_lowercase();
            if let Some(reste) = sans_elision(&bas) {
                mots.insert(reste.to_string());
            }
            mots.insert(bas);
        }
    }
    mots
});

/// Construit le vocabulaire dès l'ouverture de la porte. Construit à la première réponse, il en allongerait le
/// traitement (plus de 22 000 morceaux à découper), compté dans le silence du client : sous charge, une session d'essai
/// aux délais courts finissait par « inactivité ».
pub(crate) fn preparer() {
    LazyLock::force(&VOCABULAIRE);
}

/// Le nombre de mots du vocabulaire.
#[cfg(test)]
pub(crate) fn taille() -> usize {
    VOCABULAIRE.len()
}

/// Ce qui remplace un mot, un chiffre ou un signe hors vocabulaire.
pub(crate) const RETENU: &str = "…";

/// La ponctuation qui sort seule : rien qui ouvre ou ferme un groupe (ni parenthèse ni crochet), rien qui forme un
/// lien, du code ou une adresse.
const PONCTUATION: &[char] = &['.', ',', ';', ':', '!', '?', '"', '\'', '-', '–', '—', '→', '…'];
/// Ce qui peut précéder un mot (pelé et gardé).
const TETE: &[char] = &['"', '\''];
/// Ce qui peut suivre un mot (pelé et gardé).
const QUEUE: &[char] = &['.', ',', ';', ':', '!', '?', '"', '\'', '…'];
/// Ce qui peut entourer un mot sans jamais sortir (« (numéro », « illisible) ») : pelé et jeté.
const GROUPES: &[char] = &['(', ')', '[', ']'];
/// Les mots d'une seule lettre admis : sans eux, une valeur pourrait s'épeler lettre par lettre.
const UNE_LETTRE: [&str; 3] = ["a", "à", "y"];
/// Les formes élidées : « l'alerte » est connu si « alerte » l'est.
const ELISIONS: [&str; 12] = [
    "l'", "d'", "j'", "m'", "n'", "s'", "t'", "c'", "qu'", "jusqu'", "lorsqu'", "puisqu'",
];

/// Le texte normalisé comme le juge la porte : celle du nettoyeur commun (pleine chasse, invisibles, guillemets et
/// apostrophes typographiques, espaces), puis les lettres latines accentuées recomposées (NFC) : « e » suivi d'un
/// accent combinant est « é ». Les autres formes de compatibilité (ligatures, lettres mathématiques ou cerclées) ne
/// sont pas ramenées : elles ne sont pas des mots du vocabulaire et sortent « … ». Les traits d'union typographiques
/// (U+2010, U+2011 insécable) deviennent « - » : « wi‑fi » est « wi-fi ». Le tiret demi-cadratin (« – ») reste un
/// séparateur.
pub(crate) fn normalise(texte: &str) -> String {
    let mut sortie = String::with_capacity(texte.len());
    for x in crate::amelioration::texte::normalise(texte).chars() {
        let x = if matches!(x, '\u{2010}' | '\u{2011}') { '-' } else { x };
        let compose = sortie.chars().last().and_then(|base| composer(base, x));
        match compose {
            Some(c) => {
                sortie.pop();
                sortie.push(c);
            }
            None => sortie.push(x),
        }
    }
    sortie
}

/// Les accents combinants qu'on recompose, avec leurs bases et les lettres composées (dans le même ordre). Une marque
/// restée seule n'est pas une lettre : le mot qui la porte n'est pas connu (fermé par défaut).
const COMPOSITIONS: [(char, &str, &str); 13] = [
    ('\u{300}', "AEIOUaeiou", "ÀÈÌÒÙàèìòù"),
    ('\u{301}', "AEIOUYaeiouyCcLlNnRrSsZz", "ÁÉÍÓÚÝáéíóúýĆćĹĺŃńŔŕŚśŹź"),
    ('\u{302}', "AEIOUaeiouCcGgHhJjSsWwYy", "ÂÊÎÔÛâêîôûĈĉĜĝĤĥĴĵŜŝŴŵŶŷ"),
    ('\u{303}', "ANOanoIiUu", "ÃÑÕãñõĨĩŨũ"),
    ('\u{304}', "AaEeIiOoUu", "ĀāĒēĪīŌōŪū"),
    ('\u{306}', "AaEeGgIiOoUu", "ĂăĔĕĞğĬĭŎŏŬŭ"),
    ('\u{307}', "CcEeGgIZz", "ĊċĖėĠġİŻż"),
    ('\u{308}', "AEIOUaeiouyY", "ÄËÏÖÜäëïöüÿŸ"),
    ('\u{30a}', "AaUu", "ÅåŮů"),
    ('\u{30b}', "OoUu", "ŐőŰű"),
    ('\u{30c}', "CcDdEeLlNnRrSsTtZz", "ČčĎďĚěĽľŇňŘřŠšŤťŽž"),
    ('\u{327}', "CcGgKkLlNnRrSsTt", "ÇçĢģĶķĻļŅņŖŗŞşŢţ"),
    ('\u{328}', "AaEeIiUu", "ĄąĘęĮįŲų"),
];

/// La lettre composée de `base` et de l'accent combinant `marque`, s'il y en a une.
fn composer(base: char, marque: char) -> Option<char> {
    let (_, bases, composes) = COMPOSITIONS.iter().find(|(m, _, _)| *m == marque)?;
    let rang = bases.chars().position(|b| b == base)?;
    composes.chars().nth(rang)
}

/// Le jeton en trois parts : sa tête (guillemets, apostrophe), son cœur, sa queue (ponctuation de fin). Les
/// parenthèses et crochets qui l'entourent sont pelés aussi, mais jetés : ni la tête ni la queue ne les gardent, rien
/// qui ouvre ou ferme un groupe ne sort.
pub(crate) fn peler(jeton: &str) -> (String, &str, String) {
    let sans_tete = jeton.trim_start_matches(|x: char| TETE.contains(&x) || GROUPES.contains(&x));
    let coeur = sans_tete.trim_end_matches(|x: char| QUEUE.contains(&x) || GROUPES.contains(&x));
    let tete = jeton
        .get(..jeton.len().saturating_sub(sans_tete.len()))
        .unwrap_or_default()
        .chars()
        .filter(|x| !GROUPES.contains(x))
        .collect();
    let queue = sans_tete
        .get(coeur.len()..)
        .unwrap_or_default()
        .chars()
        .filter(|x| !GROUPES.contains(x))
        .collect();
    (tete, coeur, queue)
}

/// Une lettre telle qu'elle s'écrit d'habitude : une minuscule, ou une majuscule dont la minuscule revient à elle (le
/// signe Kelvin, qui ressemble à « K », n'en est pas une).
fn lettre(x: char) -> bool {
    if !x.is_alphabetic() {
        return false;
    }
    let mut bas = x.to_lowercase();
    let (Some(b), None) = (bas.next(), bas.next()) else {
        return false;
    };
    if b == x {
        return true;
    }
    let mut haut = b.to_uppercase();
    matches!((haut.next(), haut.next()), (Some(h), None) if h == x)
}

/// La forme d'un mot : des lettres, avec des apostrophes, traits d'union ou barres obliques internes (« l'alerte »,
/// « pare-feu », « TCP/IP »), jamais deux de suite ni au bord.
fn forme_de_mot(coeur: &str) -> bool {
    let mut avant_lettre = false;
    for x in coeur.chars() {
        if lettre(x) {
            avant_lettre = true;
        } else if matches!(x, '\'' | '-' | '/') && avant_lettre {
            avant_lettre = false;
        } else {
            return false;
        }
    }
    avant_lettre
}

/// Le mot sans sa forme élidée de tête (« alerte » de « l'alerte »).
fn sans_elision(bas: &str) -> Option<&str> {
    ELISIONS
        .iter()
        .find_map(|e| bas.strip_prefix(e))
        .filter(|r| !r.is_empty())
}

/// Le cœur est-il un mot du vocabulaire (en entier, ou après sa forme élidée) ?
pub(crate) fn connu(coeur: &str) -> bool {
    if !forme_de_mot(coeur) {
        return false;
    }
    let bas = coeur.to_lowercase();
    if bas.chars().nth(1).is_none() && !UNE_LETTRE.contains(&bas.as_str()) {
        return false;
    }
    VOCABULAIRE.contains(&bas)
        || sans_elision(&bas).is_some_and(|r| r.chars().nth(1).is_some() && VOCABULAIRE.contains(r))
}

/// Le jeton tel qu'il peut sortir : seule ponctuation (« … » si elle forme des points de suspension ou s'allonge),
/// ou mot du vocabulaire entouré de sa ponctuation ; « … » sinon, sans rien autour. Un mot suivi de points de
/// suspension (« admin… », « maison.. ») a pu être coupé par celui qui l'a écrit : son début n'est pas le mot, il sort
/// « … » en entier.
pub(crate) fn juger(jeton: &str) -> String {
    if jeton.chars().all(|x| PONCTUATION.contains(&x)) {
        let points = jeton.chars().filter(|x| *x == '.').count();
        return if points >= 2 || jeton.chars().nth(2).is_some() {
            RETENU.into()
        } else {
            jeton.to_string()
        };
    }
    let (tete, coeur, queue) = peler(jeton);
    if queue.contains(RETENU) || queue.chars().filter(|x| *x == '.').count() >= 2 {
        return RETENU.into();
    }
    let queue_courte = queue.chars().nth(2).is_none();
    if connu(coeur) && queue_courte {
        format!("{tete}{coeur}{queue}")
    } else if connu(coeur) {
        format!("{tete}{coeur}{RETENU}")
    } else {
        RETENU.into()
    }
}

/// Le chaînon d'une sortie : un « … » qui suit un autre « … » n'y ajoute rien.
pub(crate) fn ajouter(sortie: &mut Vec<String>, jeton: String) {
    if jeton == RETENU && sortie.last().is_some_and(|d| d == RETENU || d.ends_with(RETENU)) {
        return;
    }
    sortie.push(jeton);
}
