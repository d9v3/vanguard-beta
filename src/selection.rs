//! Menus au clavier : ↑ ↓ pour se déplacer, Entrée pour lancer, Échap pour revenir. Les touches d'avant (un chiffre
//! ou une lettre, puis Entrée) marchent toujours, et la ligne en surbrillance les suit. Taper un mot cherche : seules
//! les lignes qui le contiennent restent à l'écran, sans tenir compte des accents ni des majuscules ; au menu
//! principal, la recherche voit aussi les outils des sous-menus et les pages du guide (lignes « cachées »). Un menu
//! plus haut que la fenêtre défile : l'en-tête reste en place, la liste suit la ligne en surbrillance, et « ↑ » ou
//! « ↓ » disent combien de lignes sont cachées. Sans vrai terminal (réponses envoyées par un tube : tests, scripts), ou
//! dans une fenêtre minuscule, la réponse se lit ligne par ligne, comme avant ; un mot qui ne désigne qu'un seul choix
//! le choisit. Pendant une recherche, la fin du mot le plus probable s'affiche en gris (`prediction`), et Tab ou →
//! la complète : la même prédiction dans tous les menus et les listes à cocher. Dans une fenêtre assez large
//! (`COLONNES_AVEC_APERCU`), un panneau à droite montre la ligne en surbrillance : son titre, sa description et ce
//! qu'elle ouvre ; plus étroite, le menu reste tel quel.

use std::fmt::Write as _;
use std::io::{IsTerminal, Write};
use std::ops::ControlFlow;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;

use crate::prediction::Vocabulaire;
use crate::ui::*;

/// Une ligne d'un menu.
pub enum Ligne {
    /// Affichée telle quelle : cadre, titre, état, ligne vide.
    Texte(String),
    /// Ligne qu'on peut choisir : la touche qui la désigne, son texte, une précision en gris à droite, et des mots que
    /// la recherche trouve sans qu'ils s'affichent. `description` et `sous` (ce qu'elle ouvre, quand ce ne sont pas des
    /// lignes cachées de ce menu) ne se lisent que dans l'aperçu.
    Choix {
        touche: String,
        texte: String,
        precision: String,
        mots: String,
        description: String,
        sous: Vec<String>,
    },
    /// Choix que seule la recherche montre : un outil d'un sous-menu, une page du guide. `chemin` dit où il se trouve
    /// (« Réseau et Internet › »).
    Cachee {
        touche: String,
        chemin: String,
        texte: String,
        precision: String,
        mots: String,
        description: String,
    },
}

impl Ligne {
    pub fn choix(touche: &str, texte: &str, precision: &str) -> Self {
        Ligne::Choix {
            touche: touche.into(),
            texte: texte.into(),
            precision: precision.into(),
            mots: String::new(),
            description: String::new(),
            sous: Vec::new(),
        }
    }

    pub fn cachee(touche: &str, chemin: &str, texte: &str, precision: &str) -> Self {
        Ligne::Cachee {
            touche: touche.into(),
            chemin: chemin.into(),
            texte: texte.into(),
            precision: precision.into(),
            mots: String::new(),
            description: String::new(),
        }
    }

    /// Ce que l'aperçu dit de la ligne, sous son titre : ce qu'elle fait, ce qu'elle change.
    #[must_use]
    pub fn avec_description(mut self, texte: &str) -> Self {
        if let Ligne::Choix { description, .. } | Ligne::Cachee { description, .. } = &mut self {
            texte.clone_into(description);
        }
        self
    }

    /// Ce que la ligne ouvre, pour l'aperçu : les variantes d'un écran à choix, absentes du menu.
    #[must_use]
    pub fn avec_sous(mut self, noms: Vec<String>) -> Self {
        if let Ligne::Choix { sous, .. } = &mut self {
            *sous = noms;
        }
        self
    }

    /// Des mots de plus pour la recherche : ce qu'un outil sait faire, les commandes d'un programme du guide.
    #[must_use]
    pub fn avec_mots(mut self, en_plus: &str) -> Self {
        if let Ligne::Choix { mots, .. } | Ligne::Cachee { mots, .. } = &mut self {
            mots.push(' ');
            mots.push_str(en_plus);
        }
        self
    }
}

/// Minuscules, sans accents, sans tirets et sans codes de couleur : « Wi-Fi » se trouve en tapant « wifi », « Réseau »
/// en tapant « reseau ».
pub fn simplifier(t: &str) -> String {
    let mut sortie = String::with_capacity(t.len());
    let mut code = false;
    for c in t.chars() {
        if code {
            code = c != 'm';
            continue;
        }
        if c == '\x1b' {
            code = true;
            continue;
        }
        if c == '-' {
            continue;
        }
        for m in c.to_lowercase() {
            match m {
                'à' | 'â' | 'ä' | 'á' => sortie.push('a'),
                'é' | 'è' | 'ê' | 'ë' => sortie.push('e'),
                'î' | 'ï' | 'í' => sortie.push('i'),
                'ô' | 'ö' | 'ó' => sortie.push('o'),
                'ù' | 'û' | 'ü' | 'ú' => sortie.push('u'),
                'ç' => sortie.push('c'),
                'œ' => sortie.push_str("oe"),
                autre => sortie.push(autre),
            }
        }
    }
    sortie
}

/// Tous les mots de `recherche` paraissent-ils dans `texte`, déjà passé par `simplifier` ? Un mot de trois lettres au
/// plus doit commencer un mot (« ip » ne trouve pas « description ») ; un plus long peut être n'importe où (« update »
/// trouve « windowsupdate »), et sa fin peut changer : on tape « vider », « réparer », « disques », le texte dit
/// « Vide », « Répare », « disque ».
pub fn correspond(recherche: &str, texte: &str) -> bool {
    let voulus: Vec<String> = recherche
        .split_whitespace()
        .map(simplifier)
        .filter(|m| !m.is_empty())
        .collect();
    !voulus.is_empty()
        && voulus.iter().all(|v| {
            let n = v.chars().count();
            if n <= 3 {
                return texte
                    .split(|c: char| !c.is_alphanumeric())
                    .any(|m| m.starts_with(v.as_str()));
            }
            // La racine garde au moins quatre lettres (cinq quand on en retire deux) : « réseau » ne devient pas
            // « rese », qui trouverait « reset ».
            let racine = |retire: usize| v.chars().take(n - retire).collect::<String>();
            texte.contains(v.as_str())
                || (n >= 5 && texte.contains(&racine(1)))
                || (n >= 7 && texte.contains(&racine(2)))
        })
}

/// Le rang d'une ligne trouvée par `recherche` : 0 si son texte commence par le premier mot tapé (« tar » : la page
/// tar), 1 s'il contient tous les mots, 2 si seuls ses mots cachés ou sa précision les ont. Les lignes se rangent
/// par rang, et à rang égal gardent l'ordre du menu : les outils restent devant les commandes du guide.
fn rang(recherche: &str, nom: &str) -> u8 {
    let nom = nom.trim_start_matches(|c: char| !c.is_alphanumeric());
    let premier = recherche.split_whitespace().next().map(simplifier).unwrap_or_default();
    if !premier.is_empty() && nom.starts_with(premier.as_str()) {
        0
    } else if correspond(recherche, nom) {
        1
    } else {
        2
    }
}

/// Les lignes trouvées par `tape`, de la mieux notée à la moins bien notée (à égalité, l'ordre du menu : les outils
/// avant les pages du guide), avec les fautes corrigées et si ce ne sont que des résultats partiels (pas tous les
/// mots tapés). `mots` : le vocabulaire du menu, vers lequel une faute se corrige.
fn trier<'a, 'b>(
    choix: &'b [Choisissable<'a>],
    tape: &str,
    mots: &[String],
) -> (Vec<&'b Choisissable<'a>>, Vec<(String, String)>, bool) {
    use crate::recherche::{score, termes_corriges};
    let (termes, corrections) = termes_corriges(tape, mots, |forme| {
        let un = crate::recherche::termes(forme);
        choix.iter().any(|c| score(&un, &c.nom, &c.cherche).is_some())
    });
    let notes: Vec<(&Choisissable, u32, bool)> = choix
        .iter()
        .filter_map(|c| score(&termes, &c.nom, &c.cherche).map(|(n, tous)| (c, n, tous)))
        .collect();
    let complets = notes.iter().any(|(_, _, tous)| *tous);
    let mut gardes: Vec<(&Choisissable, u32)> = notes
        .into_iter()
        .filter(|(_, _, tous)| *tous || !complets)
        .map(|(c, n, _)| (c, n))
        .collect();
    gardes.sort_by_key(|g| std::cmp::Reverse(g.1));
    let partiels = !complets && !gardes.is_empty();
    (gardes.into_iter().map(|(c, _)| c).collect(), corrections, partiels)
}

/// Une ligne trouvée par `chercher` : sa touche, son texte (précédé de son chemin pour une ligne cachée) et sa précision.
pub(crate) struct Trouve {
    pub touche: String,
    pub texte: String,
    pub precision: String,
}

/// La recherche du menu, hors du menu (`vanguard chercher`) : les lignes trouvées, de la mieux notée à la moins
/// bien notée, les fautes corrigées (« tapé → corrigé ») et si ce ne sont que des résultats partiels.
pub(crate) fn chercher(lignes: &[Ligne], requete: &str) -> (Vec<Trouve>, Vec<(String, String)>, bool) {
    let choix = choisissables(lignes);
    let mots = crate::recherche::vocabulaire(choix.iter().map(|c| c.cherche.as_str()));
    let (trouves, corrections, partiels) = trier(&choix, requete, &mots);
    let trouves = trouves
        .into_iter()
        .map(|c| Trouve {
            touche: c.touche.to_string(),
            texte: c.texte.clone(),
            precision: simplement_affiche(c.precision),
        })
        .collect();
    (trouves, corrections, partiels)
}

/// Le titre de la recherche : ce qui est tapé, ou le mot corrigé et ce qui avait été tapé ; « partiels » quand aucune
/// ligne n'a tous les mots.
fn titre_de_recherche(tape: &str, corrections: &[(String, String)], partiels: bool) -> String {
    let mot = if corrections.is_empty() {
        trf!("RECHERCHE « {} »", "SEARCH “{}”", couper(tape.trim(), 40))
    } else {
        let corrige = corrections
            .iter()
            .map(|(_, c)| c.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        trf!(
            "RECHERCHE « {} » (tapé : « {} »)",
            "SEARCH “{}” (typed: “{}”)",
            couper(&corrige, 24),
            couper(tape.trim(), 24)
        )
    };
    let titre = if partiels {
        trf!("{mot} : RÉSULTATS PARTIELS", "{mot}: PARTIAL RESULTS")
    } else {
        mot
    };
    // Le filet de la section l'entoure : sur une seule rangée, même pour un long mot tapé.
    couper(&titre, LARGEUR - 8)
}

/// Ce qui est tapé est-il une recherche ? Pas une touche du menu ni le début d'une touche (« 1 » de « 10 », « 4. » de
/// « 4.2 »), et au moins deux lettres : une lettre seule reste un raccourci des anciennes versions (u, r, o…).
fn est_une_recherche(tape: &str, touches: &[&str]) -> bool {
    let t = tape.trim().to_lowercase();
    t.chars().count() >= 2 && !touches.iter().any(|k| k.to_lowercase().starts_with(&t))
}

/// Une ligne qu'on peut choisir, telle que la recherche la voit.
struct Choisissable<'a> {
    /// La ligne du menu, pour son aperçu.
    ligne: &'a Ligne,
    touche: &'a str,
    /// Le texte sans couleurs, précédé de son chemin pour une ligne cachée (« Réseau et Internet › Scanner le réseau »).
    texte: String,
    precision: &'a str,
    /// Tout ce que lit la recherche, simplifié une fois pour toutes.
    cherche: String,
    /// Le texte seul (sans chemin, précision ni mots cachés), simplifié : ce qui le commence ou le contient passe
    /// devant (`rang`).
    nom: String,
    visible: bool,
}

fn choisissables(lignes: &[Ligne]) -> Vec<Choisissable<'_>> {
    lignes
        .iter()
        .filter_map(|l| match l {
            Ligne::Texte(_) => None,
            Ligne::Choix {
                touche,
                texte,
                precision,
                mots,
                ..
            } => Some(Choisissable {
                ligne: l,
                touche,
                texte: simplement_affiche(texte),
                precision,
                cherche: simplifier(&format!("{texte} {precision} {mots}")),
                nom: simplifier(texte),
                visible: true,
            }),
            Ligne::Cachee {
                touche,
                chemin,
                texte,
                precision,
                mots,
                ..
            } => Some(Choisissable {
                ligne: l,
                touche,
                texte: simplement_affiche(&if chemin.is_empty() {
                    texte.clone()
                } else {
                    format!("{chemin} {texte}")
                }),
                precision,
                cherche: simplifier(&format!("{chemin} {texte} {precision} {mots}")),
                nom: simplifier(texte),
                visible: false,
            }),
        })
        .collect()
}

/// Le texte sans ses codes de couleur, pour pouvoir le couper.
fn simplement_affiche(t: &str) -> String {
    let mut sortie = String::with_capacity(t.len());
    let mut code = false;
    for c in t.chars() {
        match (code, c) {
            (false, '\x1b') => code = true,
            (true, 'm') => code = false,
            (false, _) => sortie.push(c),
            _ => {}
        }
    }
    sortie
}

/// La suite prédite du mot en cours, en gris après ce qui est tapé, et le code qui ramène le curseur devant elle :
/// on tape par-dessus, ou Tab la prend.
fn fantome(suite: Option<&str>) -> (String, String) {
    match suite {
        Some(s) if !s.is_empty() => (format!("{DISCRET}{s}{RESET}"), format!("\x1b[{}D", largeur_affichee(s))),
        _ => (String::new(), String::new()),
    }
}

/// Ce que la prédiction lit d'un menu : le texte, la précision et les mots cachés de chaque ligne, sans couleurs.
fn textes_du_menu(lignes: &[Ligne]) -> Vec<String> {
    lignes
        .iter()
        .filter_map(|l| match l {
            Ligne::Texte(_) => None,
            Ligne::Choix {
                texte, precision, mots, ..
            }
            | Ligne::Cachee {
                texte, precision, mots, ..
            } => Some(simplement_affiche(&format!("{texte} {precision} {mots}"))),
        })
        .collect()
}

/// Une ligne trouvée par la recherche : la touche, le texte, puis la précision s'il reste de la place. Toujours dans
/// `LARGEUR` colonnes, même avec un long chemin : l'écran est redessiné depuis le haut et ne doit pas défiler.
fn rendu_trouve(c: &Choisissable<'_>, largeur_touche: usize, en_cours: bool) -> String {
    let (marque, gras) = if en_cours {
        (format!("{ACCENT}►{RESET}"), GRAS)
    } else {
        (" ".to_string(), "")
    };
    let dispo = LARGEUR.saturating_sub(largeur_touche + 5);
    let texte = couper(&c.texte, dispo);
    let reste = dispo.saturating_sub(largeur_affichee(&texte) + 2);
    let precision = simplement_affiche(c.precision);
    let precision = if precision.is_empty() || reste < 10 {
        String::new()
    } else {
        format!("  {DISCRET}{}{RESET}", couper(&precision, reste))
    };
    format!(
        " {marque} {TOUCHE}{:>largeur_touche$}{RESET}  {gras}{texte}{RESET}{precision}",
        c.touche
    )
}

fn largeur_des_touches<'a>(trouves: impl Iterator<Item = &'a Choisissable<'a>>) -> usize {
    trouves.map(|c| largeur_affichee(c.touche)).max().unwrap_or(2).max(2)
}

/// Sans terminal : la réponse se lit ligne par ligne. Un mot qui n'est pas une touche cherche : un seul choix trouvé
/// est choisi ; plusieurs sont montrés avec leur touche, et la question revient.
fn par_ligne(choix: &[Choisissable<'_>], touches: &[&str], invite: &str) -> String {
    loop {
        let reponse = demander(invite);
        if !est_une_recherche(&reponse, touches) {
            return reponse;
        }
        let mut trouves: Vec<&Choisissable> = choix.iter().filter(|c| correspond(&reponse, &c.cherche)).collect();
        trouves.sort_by_key(|c| rang(&reponse, &c.nom));
        match trouves.as_slice() {
            [seul] => return seul.touche.to_string(),
            [] => trp!(
                "  Rien ne correspond à « {reponse} ».",
                "  Nothing matches “{reponse}”."
            ),
            plusieurs => {
                let largeur = largeur_des_touches(plusieurs.iter().copied());
                for c in plusieurs {
                    println!("{}", rendu_trouve(c, largeur, false));
                }
                trp!(
                    "  {GRIS}Tapez la touche de votre choix, ou d'autres mots.{RESET}",
                    "  {GRIS}Type the key of your choice, or other words.{RESET}"
                );
            }
        }
    }
}

/// Une ligne de choix : la touche en blanc vif, le texte, sa précision en gris à partir de la colonne `colonne`. La
/// ligne en cours est marquée « ► » (présent dans les polices de l'ancienne console Windows) et écrite en gras.
fn rendu(touche: &str, texte: &str, precision: &str, colonne: usize, en_cours: bool) -> String {
    let (marque, gras) = if en_cours {
        (format!("{ACCENT}►{RESET}"), GRAS)
    } else {
        (" ".to_string(), "")
    };
    if precision.is_empty() {
        format!(" {marque} {TOUCHE}{touche:>2}{RESET}  {gras}{texte}{RESET}")
    } else {
        format!(
            " {marque} {TOUCHE}{touche:>2}{RESET}  {gras}{}{RESET}{DISCRET}{precision}{RESET}",
            ajuster(texte, colonne)
        )
    }
}

/// Colonne des précisions : la même pour toutes les lignes du menu, après le texte le plus long.
fn colonne(lignes: &[Ligne]) -> usize {
    let plus_long = lignes
        .iter()
        .filter_map(|l| match l {
            Ligne::Choix { texte, .. } => Some(largeur_affichee(texte)),
            Ligne::Texte(_) | Ligne::Cachee { .. } => None,
        })
        .max()
        .unwrap_or(0);
    (plus_long + 2).clamp(36, 48)
}

/// La ligne à l'écran, ou rien pour une ligne cachée (seule la recherche la montre).
fn texte(l: &Ligne, colonne: usize, en_cours: bool) -> Option<String> {
    match l {
        Ligne::Texte(t) => Some(t.clone()),
        Ligne::Choix {
            touche,
            texte,
            precision,
            ..
        } => Some(rendu(touche, texte, precision, colonne, en_cours)),
        Ligne::Cachee { .. } => None,
    }
}

/// Hauteur de fenêtre en dessous de laquelle un menu se lit ligne par ligne : trop peu de place pour défiler.
const RANGEES_MINIMUM: usize = 10;

/// Ce qui tient dans `place` rangées d'un menu trop haut pour la fenêtre : l'en-tête (`entete` premières rangées :
/// cadre, titre) reste en place s'il laisse de la place à la liste, puis la partie de la liste qui contient la rangée
/// `en_cours`, entre deux annonces de ce qui est caché au-dessus et au-dessous. `haut`, la première rangée montrée de
/// la liste, est gardé d'un affichage à l'autre : la liste ne bouge que si la ligne en cours allait en sortir, et
/// garde alors une rangée de contexte (le titre d'une section). Rend au plus `place` rangées.
fn fenetre(rangees: &[String], entete: usize, en_cours: usize, place: usize, haut: &mut usize) -> Vec<String> {
    if rangees.len() <= place {
        *haut = 0;
        return rangees.to_vec();
    }
    // Au moins trois rangées de liste sous l'en-tête et les deux annonces ; sinon l'en-tête défile aussi.
    let entete = if entete + 2 + 3 <= place { entete } else { 0 };
    // `entete` <= `place` < `rangees.len()` ici ; le `min` le garantit même si l'appelant se trompe.
    let (tete, liste) = rangees.split_at(entete.min(rangees.len()));
    let hauteur = place.saturating_sub(entete + 2).max(1);
    let ligne = en_cours.saturating_sub(entete).min(liste.len().saturating_sub(1));
    let marge = usize::from(hauteur >= 5);
    // Borné d'abord : l'appelant demande la fin de la liste avec `usize::MAX`.
    let dernier_haut = liste.len().saturating_sub(hauteur);
    *haut = (*haut).min(dernier_haut);
    if ligne < *haut + marge {
        *haut = ligne.saturating_sub(marge);
    } else if ligne + marge >= *haut + hauteur {
        *haut = (ligne + marge + 1).saturating_sub(hauteur);
    }
    *haut = (*haut).min(dernier_haut);
    let reste = liste.len().saturating_sub(*haut + hauteur);
    let annonce = |fleche: char, n: usize, texte: String| {
        if n == 0 {
            String::new()
        } else {
            format!("  {GRIS}{fleche} {texte}{RESET}")
        }
    };
    let mut ecran: Vec<String> = tete.to_vec();
    ecran.push(annonce(
        '↑',
        *haut,
        trf!("{} ligne(s) plus haut", "{} more line(s) above", *haut),
    ));
    ecran.extend(liste.iter().skip(*haut).take(hauteur).cloned());
    ecran.push(annonce(
        '↓',
        reste,
        trf!("{reste} ligne(s) plus bas", "{reste} more line(s) below"),
    ));
    ecran
}

/// Le panneau d'aperçu prend ce qui reste à droite du menu, entre ces deux largeurs de texte : plus étroit, ses lignes
/// ne diraient plus grand-chose ; plus large, l'œil irait trop loin du menu.
const APERCU_MIN: usize = 30;
const APERCU_MAX: usize = 40;

/// Les colonnes d'avant le texte du panneau : une vide après le menu, le filet, une espace.
const AVANT_APERCU: usize = 3;

/// La largeur de fenêtre que demande `fenetre` : le menu, le panneau le plus large, et la dernière colonne laissée
/// vide (y écrire fait passer certains terminaux à la ligne).
pub(crate) const COLONNES_AVEC_APERCU: usize = LARGEUR + AVANT_APERCU + APERCU_MAX + 1;

/// La largeur du texte du panneau dans une fenêtre de `colonnes` colonnes, ou `None` si elle est trop étroite : le
/// menu reste alors tel quel.
fn largeur_apercu(colonnes: usize) -> Option<usize> {
    let reste = colonnes.checked_sub(LARGEUR + AVANT_APERCU + 1)?;
    (reste >= APERCU_MIN).then_some(reste.min(APERCU_MAX))
}

/// Un menu a-t-il de quoi remplir un aperçu ? Une description, un sous-menu : sinon (une question oui ou non, un menu
/// d'extension), le panneau ne répéterait que la ligne en surbrillance.
fn a_des_apercus(lignes: &[Ligne]) -> bool {
    lignes.iter().any(|l| match l {
        Ligne::Choix { description, sous, .. } => !description.is_empty() || !sous.is_empty(),
        Ligne::Cachee { .. } => true,
        Ligne::Texte(_) => false,
    })
}

/// Le texte d'une ligne sans couleurs ni « › » final : le titre de l'aperçu, un nom de sa liste.
fn nom_seul(t: &str) -> String {
    simplement_affiche(t)
        .trim()
        .trim_end_matches('›')
        .trim_end()
        .to_string()
}

/// Ce que `ligne` ouvre : ses `sous`, sinon les lignes cachées du menu juste sous sa touche (« 5 » ouvre « 5.1 »,
/// « 5.2 »…, pas « 5.1.1 »), chacune une fois (les réglages des Paramètres partagent une touche).
fn ce_qu_elle_ouvre(lignes: &[Ligne], ligne: &Ligne) -> Vec<String> {
    let touche = match ligne {
        Ligne::Choix { sous, .. } if !sous.is_empty() => return sous.iter().map(|s| nom_seul(s)).collect(),
        Ligne::Choix { touche, .. } | Ligne::Cachee { touche, .. } => touche.as_str(),
        Ligne::Texte(_) => return Vec::new(),
    };
    let mut vues: Vec<&str> = Vec::new();
    let mut noms = Vec::new();
    for l in lignes {
        let Ligne::Cachee { touche: t, texte, .. } = l else {
            continue;
        };
        let Some(suite) = t.strip_prefix(touche).and_then(|s| s.strip_prefix('.')) else {
            continue;
        };
        if !suite.is_empty() && !suite.contains('.') && !vues.contains(&t.as_str()) {
            vues.push(t);
            noms.push(nom_seul(texte));
        }
    }
    noms
}

/// Le panneau d'aperçu de `ligne`, en rangées d'au plus `largeur` colonnes et `hauteur` rangées : où elle se trouve
/// et sa précision (une ligne cachée, que la recherche montre coupée), son titre, sa description, puis ce qu'elle
/// ouvre, avec « … et N autres » pour ce qui ne tient pas.
fn apercu(lignes: &[Ligne], ligne: &Ligne, largeur: usize, hauteur: usize) -> Vec<String> {
    let (chemin, texte, precision, description) = match ligne {
        Ligne::Choix { texte, description, .. } => ("", texte, "", description),
        Ligne::Cachee {
            chemin,
            texte,
            precision,
            description,
            ..
        } => (chemin.as_str(), texte, precision.as_str(), description),
        Ligne::Texte(_) => return Vec::new(),
    };
    // Chaque rangée coupée au besoin : `envelopper` laisse entier un mot plus long que la largeur.
    let rangees = |t: &str, style: &str| -> Vec<String> {
        envelopper(t, largeur)
            .iter()
            .map(|l| format!("{style}{}{RESET}", couper(l, largeur)))
            .collect()
    };
    let mut panneau = Vec::new();
    if !chemin.is_empty() {
        panneau.extend(rangees(&nom_seul(chemin), DISCRET));
    }
    panneau.extend(rangees(&nom_seul(texte), ACCENT));
    panneau.extend(rangees(&simplement_affiche(precision), GRIS));
    if !description.is_empty() {
        panneau.push(String::new());
        panneau.extend(rangees(description, ""));
    }
    let ouvre = ce_qu_elle_ouvre(lignes, ligne);
    if !ouvre.is_empty() {
        panneau.push(String::new());
        panneau.push(format!("{GRIS}{}{RESET}", tr!("Dans ce menu :", "In this menu:")));
        // Ce qui reste de place, moins une rangée pour dire combien d'autres ne tiennent pas.
        let place = hauteur.saturating_sub(panneau.len());
        let montres = if ouvre.len() <= place {
            ouvre.len()
        } else {
            place.saturating_sub(1)
        };
        for nom in ouvre.iter().take(montres) {
            panneau.push(format!("{ACCENT}›{RESET} {}", couper(nom, largeur.saturating_sub(2))));
        }
        if montres < ouvre.len() {
            let autres = ouvre.len() - montres;
            panneau.push(format!(
                "{GRIS}{}{RESET}",
                trf!("… et {autres} autre(s)", "… and {autres} more")
            ));
        }
    }
    panneau.truncate(hauteur);
    panneau
}

/// La rangée où commence le panneau : sous le cadre de tête s'il est à l'écran, sinon tout en haut.
fn debut_apercu(rangees: &[String]) -> usize {
    rangees
        .iter()
        .take(4)
        .position(|r| simplement_affiche(r).starts_with('╰'))
        .map_or(0, |i| i + 1)
}

/// Les rangées d'un écran, chacune effacée jusqu'au bout de la ligne, et le panneau à droite à partir de la rangée
/// `debut` : un filet sur toute la hauteur qui reste, son texte en haut. Placé par colonne (`\x1b[nG`), il ne dépend
/// pas de la largeur de ce qui est à gauche.
fn avec_panneau(rangees: &[String], panneau: Option<(&[String], usize)>) -> String {
    let mut ecran = String::new();
    for (i, r) in rangees.iter().enumerate() {
        ecran += r;
        ecran += "\x1b[K";
        if let Some((texte, debut)) = panneau
            && let Some(n) = i.checked_sub(debut)
        {
            let _ = write!(
                ecran,
                "\x1b[{}G{DISCRET}│{RESET} {}",
                LARGEUR + 2,
                texte.get(n).map_or("", String::as_str)
            );
        }
        ecran += "\r\n";
    }
    ecran
}

/// Le mode clavier (touches lues une à une, sans écho), rendu au terminal quoi qu'il arrive : choix fait, plantage.
pub(crate) struct ModeClavier;

impl ModeClavier {
    pub(crate) fn activer() -> Option<Self> {
        terminal::enable_raw_mode().ok().map(|()| ModeClavier)
    }
}

impl Drop for ModeClavier {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

/// Montre le menu et attend un choix : la touche de la ligne choisie, ce qui a été tapé (raccourci), ou `None` pour
/// Échap ou ←. `invite` : la question quand la réponse se lit ligne par ligne. `depart` : la touche de la ligne en
/// surbrillance au départ (la dernière choisie). `echap` : ce que fait Échap (« revenir », « quitter »).
pub fn choisir(lignes: &[Ligne], invite: &str, depart: &str, echap: &str) -> Option<String> {
    let choix = choisir_ou(lignes, invite, depart, echap, true);
    noter_retour(choix.is_none());
    choix
}

/// Le menu principal : ← n'y quitte pas Vanguard (un appui de trop en revenant d'un sous-menu le fermerait), Échap
/// et « q » si.
pub fn choisir_au_sommet(lignes: &[Ligne], invite: &str, depart: &str, echap: &str) -> Option<String> {
    let choix = choisir_ou(lignes, invite, depart, echap, false);
    noter_retour(choix.is_none());
    choix
}

/// Les trois lignes d'aide d'un menu ou d'une liste : sans recherche, pendant une recherche, et quand une fin de mot
/// est proposée.
struct Aides {
    menu: String,
    recherche: String,
    prediction: String,
}

fn aides_du_menu(gauche_revient: bool, echap: &str) -> Aides {
    let menu = if gauche_revient {
        trf!(
            "  {GRIS}↑ ↓ choisir · Entrée/→ lancer · un mot : chercher · Échap/← {echap}{RESET}",
            "  {GRIS}↑ ↓ select · Enter/→ run · a word: search · Esc/← {echap}{RESET}"
        )
    } else {
        // Le menu principal : « s » (Paramètres) et « q » n'y ont plus de ligne à eux.
        trf!(
            "  {GRIS}↑ ↓ choisir · Entrée ouvrir · un mot : chercher · s réglages · q quitter{RESET}",
            "  {GRIS}↑ ↓ select · Enter open · a word: search · s settings · q quit{RESET}"
        )
    };
    Aides {
        menu,
        recherche: trf!(
            "  {GRIS}↑ ↓ choisir · Entrée/→ lancer · Échap/← effacer la recherche{RESET}",
            "  {GRIS}↑ ↓ select · Enter/→ run · Esc/← clear the search{RESET}"
        ),
        prediction: trf!(
            "  {GRIS}↑ ↓ choisir · Tab/→ compléter · Entrée lancer · Échap effacer la recherche{RESET}",
            "  {GRIS}↑ ↓ select · Tab/→ complete · Enter run · Esc clear the search{RESET}"
        ),
    }
}

/// L'en-tête (cadre, titre, état) qui reste en place pendant la recherche, et sa hauteur en rangées. Sans le
/// sous-titre ni la ligne vide qui annonçaient la première section (« BILAN DE SÉCURITÉ ») : les lignes trouvées
/// viennent de partout.
fn entete_de_recherche(lignes: &[Ligne], colonne: usize) -> (Vec<String>, usize) {
    let mut entete: Vec<String> = lignes
        .iter()
        .take_while(|l| matches!(l, Ligne::Texte(_)))
        .filter_map(|l| texte(l, colonne, false))
        .collect();
    while entete.last().is_some_and(|t| {
        let t = simplement_affiche(t);
        t.trim().is_empty() || t.trim_start().starts_with("── ")
    }) {
        entete.pop();
    }
    entete.push(String::new());
    let hauteur: usize = entete.iter().map(|t| 1 + t.matches('\n').count()).sum();
    (entete, hauteur)
}

/// Où en est un menu au clavier, d'une touche à l'autre.
struct EtatMenu {
    en_cours: usize,
    /// La ligne en surbrillance parmi celles que la recherche a trouvées.
    en_cours_trouve: usize,
    /// Première rangée montrée de la liste, quand le menu défile.
    haut: usize,
    /// Ce qui est tapé au clavier : un raccourci validé par Entrée, comme avant, ou des mots à chercher.
    tape: String,
}

/// Ce que la recherche en cours a trouvé (vide hors d'une recherche).
struct Trouvailles<'b, 'a> {
    trouves: Vec<&'b Choisissable<'a>>,
    corrections: Vec<(String, String)>,
    partiels: bool,
    /// La fin du mot le plus probable, montrée en gris.
    suite: Option<String>,
}

fn choisir_ou(lignes: &[Ligne], invite: &str, depart: &str, echap: &str, gauche_revient: bool) -> Option<String> {
    let choix = choisissables(lignes);
    let touches: Vec<&str> = choix.iter().map(|c| c.touche).collect();
    // Les flèches ne parcourent que les lignes affichées ; la recherche, elle, voit aussi les lignes cachées.
    let visibles: Vec<&str> = choix.iter().filter(|c| c.visible).map(|c| c.touche).collect();
    let colonne = colonne(lignes);
    // Le menu est redessiné depuis le haut de la fenêtre, sans retour à la ligne : assez large pour ses lignes ; s'il
    // est plus haut que la fenêtre, il défile.
    let tient = terminal::size()
        .is_ok_and(|(largeur, rangees)| usize::from(largeur) > LARGEUR && usize::from(rangees) >= RANGEES_MINIMUM);
    let clavier = std::io::stdin().is_terminal() && std::io::stdout().is_terminal() && tient && !visibles.is_empty();
    let Some(_mode) = clavier.then(ModeClavier::activer).flatten() else {
        for t in lignes.iter().filter_map(|l| texte(l, colonne, false)) {
            println!("{t}");
        }
        return Some(par_ligne(&choix, &touches, invite));
    };

    let mut etat = EtatMenu {
        en_cours: visibles
            .iter()
            .position(|t| t.eq_ignore_ascii_case(depart))
            .unwrap_or(0),
        en_cours_trouve: 0,
        haut: 0,
        tape: String::new(),
    };
    let aides = aides_du_menu(gauche_revient, echap);
    // Les mots du menu, lus à la première recherche seulement : pour la fin de mot proposée, et pour corriger une faute.
    let mut vocabulaire: Option<Vocabulaire> = None;
    let mut mots_du_menu: Option<Vec<String>> = None;
    let (entete, hauteur_entete) = entete_de_recherche(lignes, colonne);
    let apercus = a_des_apercus(lignes);
    let mut sortie = std::io::stdout();
    let _ = sortie.write_all(b"\x1b[2J");
    loop {
        // La grille avant de dessiner : si elle change ensuite, sans que le terminal le dise, le menu se redessine.
        let grille = terminal::size().ok();
        let recherche = est_une_recherche(&etat.tape, &touches);
        let (trouves, corrections, partiels): (Vec<&Choisissable>, Vec<(String, String)>, bool) = if recherche {
            let mots = mots_du_menu
                .get_or_insert_with(|| crate::recherche::vocabulaire(choix.iter().map(|c| c.cherche.as_str())));
            trier(&choix, &etat.tape, mots)
        } else {
            (Vec::new(), Vec::new(), false)
        };
        etat.en_cours_trouve = etat.en_cours_trouve.min(trouves.len().saturating_sub(1));
        let suite = if recherche {
            vocabulaire
                .get_or_insert_with(|| Vocabulaire::nouveau(&textes_du_menu(lignes)))
                .suite(&etat.tape, |q| choix.iter().any(|c| correspond(q, &c.cherche)))
        } else {
            None
        };
        let trouvailles = Trouvailles {
            trouves,
            corrections,
            partiels,
            suite,
        };
        // Mesuré à chaque dessin : la fenêtre élargie, ou rétrécie, montre ou retire le panneau.
        let panneau = grille
            .filter(|_| apercus)
            .and_then(|(colonnes, _)| largeur_apercu(usize::from(colonnes)));
        // En mode clavier, le terminal ne revient plus seul au début de la ligne : d'où les « \r\n ».
        let mut ecran = String::from("\x1b[H");
        if recherche {
            let entete = (&entete[..], hauteur_entete);
            ecran += &ecran_de_recherche(lignes, &etat, entete, &trouvailles, &aides, panneau);
        } else {
            ecran += &ecran_du_menu(lignes, colonne, visibles.len(), &mut etat, &aides.menu, panneau);
        }
        let _ = sortie.write_all(ecran.as_bytes());
        let _ = sortie.flush();

        let Some(Event::Key(k)) = evenement(grille) else {
            continue;
        };
        // Windows signale aussi le relâchement de la touche : un seul événement par appui.
        if k.kind == KeyEventKind::Release {
            continue;
        }
        if let ControlFlow::Break(choisi) =
            touche_du_menu(k, &mut etat, &trouvailles, recherche, &visibles, gauche_revient)
        {
            let _ = sortie.write_all(b"\r\n");
            return choisi;
        }
    }
}

/// L'écran d'une recherche : l'en-tête (ses lignes et sa hauteur) s'il laisse au moins trois lignes trouvées, le
/// titre de la recherche, les lignes trouvées et l'aperçu de celle en surbrillance (`panneau` : la largeur de son
/// texte), puis l'aide et la saisie.
fn ecran_de_recherche(
    lignes: &[Ligne],
    etat: &EtatMenu,
    (entete, hauteur_entete): (&[String], usize),
    t: &Trouvailles<'_, '_>,
    aides: &Aides,
    panneau: Option<usize>,
) -> String {
    let mut ecran: Vec<String> = Vec::new();
    let rangees = terminal::size().map_or(24, |(_, r)| usize::from(r));
    let montre_entete = hauteur_entete + 4 + 3 <= rangees;
    if montre_entete {
        for l in entete {
            ecran.extend(l.split('\n').map(String::from));
        }
    }
    ecran.push(ligne_section(&titre_de_recherche(
        &etat.tape,
        &t.corrections,
        t.partiels,
    )));
    // Ce qui tient sous l'en-tête, au-dessus de l'aide et de la saisie ; au-delà, une ligne le dit.
    let au_dessus = if montre_entete { hauteur_entete } else { 0 };
    let mut place = rangees.saturating_sub(au_dessus + 4).max(1);
    if t.trouves.len() > place {
        place = place.saturating_sub(1).max(1);
    }
    let debut = (etat.en_cours_trouve + 1).saturating_sub(place);
    let largeur = largeur_des_touches(t.trouves.iter().copied());
    for (i, c) in t.trouves.iter().enumerate().skip(debut).take(place) {
        ecran.push(rendu_trouve(c, largeur, i == etat.en_cours_trouve));
    }
    if t.trouves.is_empty() {
        ecran.push(format!(
            "  {GRIS}{}{RESET}",
            tr!(
                "Rien ne correspond : Retour arrière pour corriger, Échap pour effacer.",
                "Nothing matches: Backspace to correct, Esc to clear."
            )
        ));
    } else if t.trouves.len() > place {
        ecran.push(format!(
            "  {GRIS}{}{RESET}",
            trf!(
                "… {} en tout : ajoutez un mot pour préciser.",
                "… {} in all: add a word to narrow it down.",
                t.trouves.len()
            )
        ));
    }
    // L'aperçu peut descendre sous les lignes trouvées, jusqu'à l'aide : peu de lignes trouvées ne le coupent pas.
    let panneau = panneau.and_then(|largeur| {
        let c = t.trouves.get(etat.en_cours_trouve)?;
        let debut = debut_apercu(&ecran);
        let texte = apercu(lignes, c.ligne, largeur, rangees.saturating_sub(debut + 2));
        if ecran.len() < debut + texte.len() {
            ecran.resize(debut + texte.len(), String::new());
        }
        Some((texte, debut))
    });
    let mut ecran = avec_panneau(&ecran, panneau.as_ref().map(|(p, d)| (p.as_slice(), *d)));
    let aide = if t.suite.is_some() {
        &aides.prediction
    } else {
        &aides.recherche
    };
    let (gris, recul) = fantome(t.suite.as_deref());
    let tape = &etat.tape;
    let _ = write!(
        ecran,
        "{aide}\x1b[K\r\n  {ACCENT}›{RESET} {tape}{gris}\x1b[K\x1b[J{recul}"
    );
    ecran
}

/// L'écran du menu entier : ses rangées dans la fenêtre (l'en-tête fixe, la liste qui défile) et l'aperçu de la ligne
/// en cours (`panneau` : la largeur de son texte), puis l'aide et la saisie. Garde `etat.haut` d'un affichage à
/// l'autre.
fn ecran_du_menu(
    lignes: &[Ligne],
    colonne: usize,
    nombre_visibles: usize,
    etat: &mut EtatMenu,
    aide: &str,
    panneau: Option<usize>,
) -> String {
    let en_cours = etat.en_cours;
    // Les rangées du menu ; l'en-tête est ce qui précède la première ligne de choix.
    let mut rangees: Vec<String> = Vec::new();
    let (mut n, mut rangee_en_cours, mut entete_menu) = (0, 0, None);
    for l in lignes {
        let ligne_de_choix = matches!(l, Ligne::Choix { .. });
        if ligne_de_choix {
            entete_menu.get_or_insert(rangees.len());
            if n == en_cours {
                rangee_en_cours = rangees.len();
            }
        }
        if let Some(t) = texte(l, colonne, ligne_de_choix && n == en_cours) {
            rangees.extend(t.split('\n').map(String::from));
        }
        n += usize::from(ligne_de_choix);
    }
    // L'en-tête fixe s'arrête avant le titre de la première section et sa ligne vide : ils défilent avec la
    // liste, qu'ils annoncent.
    let mut entete_menu = entete_menu.unwrap_or(0);
    while entete_menu > 0
        && rangees.get(entete_menu - 1).is_some_and(|r| {
            let t = simplement_affiche(r);
            t.trim().is_empty() || t.trim_start().starts_with("── ")
        })
    {
        entete_menu -= 1;
    }
    // Première ou dernière ligne : la liste montre son début ou sa fin, titres compris.
    if en_cours == 0 {
        etat.haut = 0;
    } else if en_cours + 1 == nombre_visibles {
        etat.haut = usize::MAX;
    }
    // Assez de rangées pour le plus long des aperçus du menu, pas seulement celui de la ligne en cours : l'aide ne
    // monte ni ne descend d'une flèche à l'autre.
    let voulues = panneau.map_or(rangees.len(), |largeur| {
        let plus_long = lignes
            .iter()
            .filter(|l| matches!(l, Ligne::Choix { .. }))
            .map(|l| apercu(lignes, l, largeur, usize::MAX).len())
            .max()
            .unwrap_or(0);
        rangees.len().max(debut_apercu(&rangees) + plus_long)
    });
    // L'aide et la saisie restent sous le menu ; la fenêtre se fait à sa hauteur.
    crate::fenetre::epouser(voulues + 2);
    let place = terminal::size().map_or(24, |(_, r)| usize::from(r)).saturating_sub(2);
    // Des rangées vides pour l'aperçu, jamais au point de faire défiler le menu.
    if voulues > rangees.len() {
        rangees.resize(voulues.min(place.max(rangees.len())), String::new());
    }
    let montrees = fenetre(&rangees, entete_menu, rangee_en_cours, place, &mut etat.haut);
    let panneau = panneau.map(|largeur| {
        let debut = debut_apercu(&montrees);
        let courante = lignes.iter().filter(|l| matches!(l, Ligne::Choix { .. })).nth(en_cours);
        let texte = courante.map_or_else(Vec::new, |l| {
            apercu(lignes, l, largeur, montrees.len().saturating_sub(debut))
        });
        (texte, debut)
    });
    let mut ecran = avec_panneau(&montrees, panneau.as_ref().map(|(p, d)| (p.as_slice(), *d)));
    let tape = &etat.tape;
    let _ = write!(ecran, "{aide}\x1b[K\r\n  {ACCENT}›{RESET} {tape}\x1b[K\x1b[J");
    ecran
}

/// Ce que fait une touche dans un menu : `Continue` pour continuer (le menu se redessine), `Break(choix)` pour le
/// quitter avec ce choix (`Break(None)` : Échap ou ←).
fn touche_du_menu(
    k: event::KeyEvent,
    etat: &mut EtatMenu,
    t: &Trouvailles<'_, '_>,
    recherche: bool,
    visibles: &[&str],
    gauche_revient: bool,
) -> ControlFlow<Option<String>> {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    // Tab ou → prennent la prédiction : le mot se complète, suivi d'une espace pour taper le suivant.
    if let Some(s) = &t.suite
        && matches!(k.code, KeyCode::Tab | KeyCode::Right)
    {
        etat.tape.push_str(s);
        etat.tape.push(' ');
        etat.en_cours_trouve = 0;
        return ControlFlow::Continue(());
    }
    // Les flèches parcourent les lignes trouvées pendant une recherche, celles du menu sinon.
    let nombre = if recherche { t.trouves.len() } else { visibles.len() };
    let actuelle = if recherche { etat.en_cours_trouve } else { etat.en_cours };
    let derniere = nombre.saturating_sub(1);
    let deplacement = match k.code {
        KeyCode::Up | KeyCode::BackTab => Some(actuelle.checked_sub(1).unwrap_or(derniere)),
        KeyCode::Down | KeyCode::Tab => Some(if actuelle >= derniere { 0 } else { actuelle + 1 }),
        KeyCode::Home | KeyCode::PageUp => Some(0),
        KeyCode::End | KeyCode::PageDown => Some(derniere),
        _ => None,
    };
    // Ctrl-J ou Ctrl-M : le saut de ligne que certains terminaux envoient pour Entrée. → entre aussi (quand il ne
    // complète pas une prédiction, plus haut) et ← revient, comme Échap.
    let entree =
        matches!(k.code, KeyCode::Enter | KeyCode::Right) || (ctrl && matches!(k.code, KeyCode::Char('j' | 'm')));
    if let Some(i) = deplacement {
        if recherche {
            etat.en_cours_trouve = i;
        } else {
            etat.en_cours = i;
            etat.tape.clear();
        }
    } else if entree {
        if recherche {
            // Rien de trouvé : Entrée ne lance rien, on corrige ou on efface.
            let Some(c) = t.trouves.get(etat.en_cours_trouve) else {
                return ControlFlow::Continue(());
            };
            return ControlFlow::Break(Some(c.touche.to_string()));
        }
        if !etat.tape.is_empty() {
            return ControlFlow::Break(Some(std::mem::take(&mut etat.tape)));
        }
        // Un menu vide : Entrée ne choisit rien, comme une recherche qui ne trouve rien.
        let Some(choix) = visibles.get(etat.en_cours) else {
            return ControlFlow::Continue(());
        };
        return ControlFlow::Break(Some(choix.to_string()));
    } else if ctrl && matches!(k.code, KeyCode::Char('c' | 'd')) {
        // Ctrl-C arrête Vanguard ; Ctrl-D (fin de l'entrée) le quitte, comme avant.
        let _ = terminal::disable_raw_mode();
        println!();
        crate::machine::quitter(if k.code == KeyCode::Char('c') { 130 } else { 0 });
    } else if matches!(k.code, KeyCode::Esc | KeyCode::Left) || (k.code == KeyCode::Backspace && etat.tape.is_empty()) {
        // Retour arrière sans rien de tapé : revient en arrière, comme Échap.
        if etat.tape.is_empty() {
            if k.code == KeyCode::Left && !gauche_revient {
                return ControlFlow::Continue(());
            }
            return ControlFlow::Break(None);
        }
        // Échap pendant une recherche l'efface : le menu revient en entier.
        etat.tape.clear();
        etat.en_cours_trouve = 0;
    } else {
        match k.code {
            KeyCode::Backspace => {
                etat.tape.pop();
            }
            KeyCode::Char(c) if !ctrl => etat.tape.push(c),
            _ => return ControlFlow::Continue(()),
        }
        // Chaque lettre change ce qui est trouvé : la surbrillance repart du premier.
        etat.en_cours_trouve = 0;
        // La surbrillance suit la touche tapée.
        if let Some(i) = visibles.iter().position(|v| v.eq_ignore_ascii_case(&etat.tape)) {
            etat.en_cours = i;
        }
    }
    ControlFlow::Continue(())
}

/// Le prochain événement du clavier ou du terminal, ou `None` quand la grille n'est plus `grille`, celle du dessin :
/// le menu est à redessiner. La vieille console de Windows (conhost) n'annonce que les changements de son tampon
/// (WINDOW_BUFFER_SIZE_EVENT), pas ceux de la fenêtre : son tampon a des milliers de lignes, et la fenêtre qui
/// grandit (`fenetre::epouser`, ou la personne qui tire son bord) n'en montre qu'une plus grande partie, sans
/// qu'aucun événement n'arrive. D'où la grille relue quand rien n'arrive.
fn evenement(grille: Option<(u16, u16)>) -> Option<Event> {
    loop {
        match event::poll(std::time::Duration::from_millis(150)) {
            Ok(true) => return event::read().ok(),
            Ok(false) if terminal::size().ok() == grille => {}
            Ok(false) => return None,
            // Un terminal qui ne répond plus : le menu se redessine, sans tourner à vide.
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(150));
                return None;
            }
        }
    }
}

/// Une pause « Entrée pour revenir… » : Entrée, ←, Échap ou Retour arrière reviennent d'un seul appui, comme dans les
/// menus (une ligne lue au clavier écrivait « ^[[D » pour ←, et il fallait Entrée de plus). Hors d'un terminal, la
/// ligne est lue comme avant.
pub fn attendre_retour(question: &str) {
    attendre_retour_avant(question, None);
}

/// La même pause, qui cesse d'attendre à `fin` : `false` si le temps est écoulé avant un appui. Hors d'un terminal,
/// la ligne lue ne peut pas expirer.
pub fn attendre_retour_avant(question: &str, fin: Option<std::time::Instant>) -> bool {
    let clavier = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut sortie = std::io::stdout();
    let _ = write!(sortie, "{}", question_en_lignes(question));
    let _ = sortie.flush();
    let Some(_mode) = clavier.then(ModeClavier::activer).flatten() else {
        demander("");
        return true;
    };
    noter_retour(false);
    loop {
        if let Some(f) = fin
            && matches!(
                event::poll(f.saturating_duration_since(std::time::Instant::now())),
                Ok(false)
            )
        {
            let _ = sortie.write_all(b"\r\n");
            return false;
        }
        let Ok(Event::Key(k)) = event::read() else {
            continue;
        };
        if k.kind == KeyEventKind::Release {
            continue;
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(k.code, KeyCode::Char('c' | 'd')) {
            let _ = terminal::disable_raw_mode();
            println!();
            crate::machine::quitter(if k.code == KeyCode::Char('c') { 130 } else { 0 });
        }
        if matches!(
            k.code,
            KeyCode::Enter | KeyCode::Left | KeyCode::Esc | KeyCode::Backspace
        ) || (ctrl && matches!(k.code, KeyCode::Char('j' | 'm')))
        {
            let _ = sortie.write_all(b"\r\n");
            return true;
        }
    }
}

/// Une petite liste au clavier à la place d'une question à lettres, dessinée sous ce qui est déjà à l'écran (rien
/// n'est effacé : le résultat qu'elle suit reste lisible). ↑ ↓ choisissent, la lettre d'une option y pose la marque,
/// Entrée la confirme ; Échap, ← ou la dernière ligne (« ↵ ») : rien. Une lettre seule ne lance rien : « supprimer
/// pour de bon » demande Entrée. Sans terminal, la ligne est lue comme avant (`invite`). `options` : (lettre, texte).
pub fn choisir_en_ligne(options: &[(&str, &str)], invite: &str) -> Option<String> {
    let clavier = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut sortie = std::io::stdout();
    let Some(_mode) = clavier.then(ModeClavier::activer).flatten() else {
        let r = demander(invite).trim().to_lowercase();
        return options.iter().any(|(t, _)| *t == r).then_some(r);
    };
    let rien = tr!("Rien", "Nothing");
    let toutes: Vec<(&str, &str)> = options.iter().copied().chain(std::iter::once(("↵", rien))).collect();
    let colonne = toutes.iter().map(|(t, _)| largeur_affichee(t)).max().unwrap_or(1) + 4;
    let mut en_cours = 0;
    let dessiner = |sortie: &mut std::io::Stdout, en_cours: usize, redessiner: bool| {
        if redessiner {
            let _ = write!(sortie, "\x1b[{}A", toutes.len());
        }
        for (i, (t, texte)) in toutes.iter().enumerate() {
            let _ = write!(sortie, "\r\x1b[K{}\r\n", rendu(t, texte, "", colonne, i == en_cours));
        }
        let _ = sortie.flush();
    };
    let _ = sortie.write_all(b"\r\n");
    dessiner(&mut sortie, en_cours, false);
    loop {
        let Ok(Event::Key(k)) = event::read() else {
            continue;
        };
        if k.kind == KeyEventKind::Release {
            continue;
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(k.code, KeyCode::Char('c' | 'd')) {
            let _ = terminal::disable_raw_mode();
            println!();
            crate::machine::quitter(if k.code == KeyCode::Char('c') { 130 } else { 0 });
        }
        match k.code {
            KeyCode::Up => en_cours = en_cours.checked_sub(1).unwrap_or(toutes.len() - 1),
            KeyCode::Down | KeyCode::Tab => en_cours = (en_cours + 1) % toutes.len(),
            KeyCode::Enter => {
                // `en_cours` reste dans la liste (modulo, position) ; « ↵ » (Rien) est toujours au bout.
                let t = toutes.get(en_cours).map_or("↵", |(t, _)| *t);
                return (t != "↵").then(|| t.to_string());
            }
            KeyCode::Esc | KeyCode::Left => return None,
            KeyCode::Char(c) if !ctrl => {
                let c = c.to_lowercase().to_string();
                match toutes.iter().position(|(t, _)| *t == c) {
                    Some(i) => en_cours = i,
                    None => continue,
                }
            }
            _ => continue,
        }
        dessiner(&mut sortie, en_cours, true);
    }
}

/// Une question dont la réponse vide revient en arrière (« Choix (Entrée pour revenir) : ») : ← ou Échap, sur une
/// ligne encore vide, reviennent d'un seul appui, comme Entrée. Le reste se tape comme avant (numéro, lettre, chemin),
/// corrigé par Retour arrière. Hors d'un terminal, la ligne est lue comme avant.
pub fn demander_ou_revenir(question: &str) -> String {
    let reponse = lire_ou_revenir(question);
    noter_retour(reponse.is_empty());
    reponse
}

fn lire_ou_revenir(question: &str) -> String {
    let clavier = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut sortie = std::io::stdout();
    let Some(_mode) = clavier.then(ModeClavier::activer).flatten() else {
        return demander(question);
    };
    // En mode clavier, le terminal ne revient plus seul au début de la ligne.
    let _ = write!(sortie, "{}", question_en_lignes(question).replace('\n', "\r\n"));
    let _ = sortie.flush();
    let mut tape = String::new();
    loop {
        let Ok(Event::Key(k)) = event::read() else {
            continue;
        };
        if k.kind == KeyEventKind::Release {
            continue;
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(k.code, KeyCode::Char('c' | 'd')) {
            let _ = terminal::disable_raw_mode();
            println!();
            crate::machine::quitter(if k.code == KeyCode::Char('c') { 130 } else { 0 });
        }
        let entree = k.code == KeyCode::Enter || (ctrl && matches!(k.code, KeyCode::Char('j' | 'm')));
        if entree || (tape.is_empty() && matches!(k.code, KeyCode::Left | KeyCode::Esc)) {
            let _ = sortie.write_all(b"\r\n");
            return tape.trim().to_string();
        }
        match k.code {
            KeyCode::Backspace => {
                if tape.pop().is_some() {
                    let _ = sortie.write_all(b"\x08 \x08");
                }
            }
            KeyCode::Char(c) if !ctrl && !c.is_control() => {
                tape.push(c);
                let _ = write!(sortie, "{c}");
            }
            _ => continue,
        }
        let _ = sortie.flush();
    }
}

/// Une ligne de choix d'une liste à cocher.
pub struct Case {
    pub texte: String,
    /// État en gris à droite (« fait », « à faire »…).
    pub precision: String,
    /// Explication montrée sous la liste quand la ligne est en surbrillance.
    pub detail: String,
    pub cochee: bool,
    /// Cochée par R (« recommandés »).
    pub recommandee: bool,
    /// Déjà faite (un logiciel installé) : montrée « [✔] », ni Espace ni R ne la changent.
    pub fixe: bool,
}

fn rendu_case(n: usize, c: &Case, cochee: bool, colonne: usize, en_cours: bool) -> String {
    let (marque, gras) = if en_cours {
        (format!("{ACCENT}►{RESET}"), GRAS)
    } else {
        (" ".to_string(), "")
    };
    let case = if c.fixe {
        format!("{VERT}[✔]{RESET}")
    } else if cochee {
        format!("{VERT}[x]{RESET}")
    } else {
        "[ ]".to_string()
    };
    format!(
        " {marque} {TOUCHE}{n:>2}{RESET} {case} {gras}{}{RESET}{DISCRET}{}{RESET}",
        ajuster(&c.texte, colonne),
        c.precision
    )
}

/// Liste à cocher, sous un titre : ↑ ↓ pour se déplacer, Espace pour cocher ou décocher, R pour cocher les
/// recommandés, « / » ou une lettre pour chercher, Entrée pour valider, Échap pour revenir sans rien changer. Retourne
/// l'état final des cases, ou `None` pour Échap. Sans terminal, les numéros à inverser se tapent sur une ligne
/// (« 1 4 », « r »), et un mot cherche. Une case `fixe` garde son état.
pub fn cocher(titre: &[String], cases: &[Case]) -> Option<Vec<bool>> {
    let etats = cocher_ou_revenir(titre, cases);
    noter_retour(etats.is_none());
    etats
}

/// Lignes de l'explication sous une liste à cocher, toujours le même nombre : l'écran ne saute pas.
const LIGNES_DETAIL: usize = 3;
/// Sous la liste : une ligne vide, l'explication de la ligne en cours, l'aide.
const DESSOUS_LISTE: usize = 1 + LIGNES_DETAIL + 1;

/// Une liste à cocher et ce que sa recherche lit : le texte, l'état et l'explication de chaque ligne, simplifiés une
/// fois pour toutes.
struct Liste<'a> {
    titre: &'a [String],
    cases: &'a [Case],
    colonne: usize,
    cherche: Vec<String>,
}

impl Liste<'_> {
    fn filtrer(&self, recherche: &str) -> Vec<usize> {
        lignes_trouvees(recherche, &self.cherche)
    }
}

/// Où en est une liste à cocher au clavier, d'une touche à l'autre.
struct EtatListe {
    etats: Vec<bool>,
    en_cours: usize,
    haut: usize,
    /// Pendant une recherche, ce qui est tapé : seules les lignes qui le contiennent restent à l'écran.
    recherche: Option<String>,
}

fn cocher_ou_revenir(titre: &[String], cases: &[Case]) -> Option<Vec<bool>> {
    let etats: Vec<bool> = cases.iter().map(|c| c.cochee).collect();
    if cases.is_empty() {
        return Some(etats);
    }
    let liste = Liste {
        titre,
        cases,
        colonne: cases
            .iter()
            .map(|c| largeur_affichee(&c.texte) + 2)
            .max()
            .unwrap_or(0)
            .clamp(30, 44),
        cherche: cases
            .iter()
            .map(|c| simplifier(&format!("{} {} {}", c.texte, c.precision, c.detail)))
            .collect(),
    };
    // Une liste plus haute que la fenêtre défile ; une fenêtre minuscule lit la réponse ligne par ligne.
    let tient = terminal::size().is_ok_and(|(largeur, rangees)| {
        usize::from(largeur) > LARGEUR && usize::from(rangees) >= RANGEES_MINIMUM + DESSOUS_LISTE - 2
    });
    let clavier = std::io::stdin().is_terminal() && std::io::stdout().is_terminal() && tient;
    let Some(_mode) = clavier.then(ModeClavier::activer).flatten() else {
        return cocher_par_ligne(&liste, etats);
    };

    let aides = Aides {
        menu: trf!(
            "  {GRIS}↑ ↓  Espace cocher · R recommandés · / chercher · Entrée OK · Échap retour{RESET}",
            "  {GRIS}↑ ↓  Space check · R recommended · / search · Enter confirm · Esc back{RESET}"
        ),
        recherche: trf!(
            "  {GRIS}↑ ↓ choisir · Espace cocher · Entrée ou Échap : fin de la recherche{RESET}",
            "  {GRIS}↑ ↓ select · Space check · Enter or Esc: end the search{RESET}"
        ),
        prediction: trf!(
            "  {GRIS}↑ ↓ choisir · Tab compléter · Espace cocher · Entrée ou Échap : fin{RESET}",
            "  {GRIS}↑ ↓ select · Tab complete · Space check · Enter or Esc: done{RESET}"
        ),
    };
    // Les mots de la liste, lus à la première recherche seulement.
    let mut vocabulaire: Option<Vocabulaire> = None;
    let mut etat = EtatListe {
        etats,
        en_cours: 0,
        haut: 0,
        recherche: None,
    };
    let mut sortie = std::io::stdout();
    let _ = sortie.write_all(b"\x1b[2J");
    loop {
        let grille = terminal::size().ok();
        let montrees: Vec<usize> = etat
            .recherche
            .as_deref()
            .map_or_else(|| (0..cases.len()).collect(), |r| liste.filtrer(r));
        // La ligne en cours reste la même si la recherche la montre encore ; sinon, la première trouvée.
        if !montrees.contains(&etat.en_cours)
            && let Some(&i) = montrees.first()
        {
            etat.en_cours = i;
        }
        let rang = montrees.iter().position(|&i| i == etat.en_cours);
        let suite = etat.recherche.as_deref().and_then(|t| {
            vocabulaire
                .get_or_insert_with(|| {
                    let textes: Vec<String> = cases
                        .iter()
                        .map(|c| simplement_affiche(&format!("{} {} {}", c.texte, c.precision, c.detail)))
                        .collect();
                    Vocabulaire::nouveau(&textes)
                })
                .suite(t, |q| liste.cherche.iter().any(|c| correspond(q, c)))
        });
        let ecran = ecran_de_la_liste(&liste, &mut etat, &montrees, rang, suite.as_deref(), &aides);
        let _ = sortie.write_all(ecran.as_bytes());
        let _ = sortie.flush();

        let Some(Event::Key(k)) = evenement(grille) else {
            continue;
        };
        if k.kind == KeyEventKind::Release {
            continue;
        }
        if let ControlFlow::Break(fin) = touche_de_la_liste(k, &mut etat, cases, &montrees, rang, suite.as_deref()) {
            let _ = sortie.write_all(b"\r\n");
            return fin;
        }
    }
}

/// La liste sans terminal (réponses envoyées par un tube, fenêtre minuscule) : les numéros à inverser se tapent sur
/// une ligne, et un mot cherche.
fn cocher_par_ligne(liste: &Liste<'_>, mut etats: Vec<bool>) -> Option<Vec<bool>> {
    let (cases, colonne) = (liste.cases, liste.colonne);
    for l in liste.titre {
        println!("{l}");
    }
    for (i, c) in cases.iter().enumerate() {
        println!("{}", rendu_case(i + 1, c, c.cochee, colonne, false));
    }
    loop {
        let reponse = demander(tr!(
            "\n  Numéros à (dé)cocher (ex. 1 4), r = recommandés, un mot = chercher.\n  Entrée = valider, q = revenir : ",
            "\n  Numbers to check or uncheck (e.g. 1 4), r = recommended, a word = search.\n  Enter = confirm, q = back: "
        ));
        if reponse.eq_ignore_ascii_case("q") {
            return None;
        }
        let mots: Vec<&str> = reponse
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|m| !m.is_empty())
            .collect();
        // Autre chose que des numéros et « r » : des mots à chercher. Les lignes trouvées s'affichent avec leur
        // numéro, et la question revient.
        if mots
            .iter()
            .any(|m| m.parse::<usize>().is_err() && !m.eq_ignore_ascii_case("r"))
        {
            let trouves = liste.filtrer(&reponse);
            if trouves.is_empty() {
                trp!(
                    "  Rien ne correspond à « {reponse} ».",
                    "  Nothing matches “{reponse}”."
                );
            }
            for i in trouves {
                if let (Some(c), Some(&e)) = (cases.get(i), etats.get(i)) {
                    println!("{}", rendu_case(i + 1, c, e, colonne, false));
                }
            }
            continue;
        }
        for mot in mots {
            if mot.eq_ignore_ascii_case("r") {
                for (e, c) in etats.iter_mut().zip(cases) {
                    *e |= c.recommandee && !c.fixe;
                }
            } else if let Some(i) = mot
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .filter(|&i| cases.get(i).is_some_and(|c| !c.fixe))
                && let Some(e) = etats.get_mut(i)
            {
                *e = !*e;
            }
        }
        return Some(etats);
    }
}

/// L'écran d'une liste à cocher : le titre et les lignes montrées dans la fenêtre, l'explication de la ligne en cours,
/// puis l'aide (et la saisie pendant une recherche). Garde `etat.haut` d'un affichage à l'autre.
fn ecran_de_la_liste(
    liste: &Liste<'_>,
    etat: &mut EtatListe,
    montrees: &[usize],
    rang: Option<usize>,
    suite: Option<&str>,
    aides: &Aides,
) -> String {
    let cases = liste.cases;
    let mut ecran = String::from("\x1b[H");
    let mut rangees: Vec<String> = liste
        .titre
        .iter()
        .flat_map(|l| l.split('\n').map(String::from))
        .collect();
    let entete = rangees.len();
    rangees.extend(montrees.iter().filter_map(|&i| {
        let (c, e) = (cases.get(i)?, *etat.etats.get(i)?);
        Some(rendu_case(i + 1, c, e, liste.colonne, i == etat.en_cours))
    }));
    if montrees.is_empty() {
        rangees.push(format!(
            "  {GRIS}{}{RESET}",
            tr!(
                "Rien ne correspond : Retour arrière pour corriger, Échap pour finir.",
                "Nothing matches: Backspace to correct, Esc to finish."
            )
        ));
    }
    let rang_ecran = rang.unwrap_or(0);
    if rang_ecran == 0 {
        etat.haut = 0;
    } else if rang_ecran + 1 == montrees.len() {
        etat.haut = usize::MAX;
    }
    // La fenêtre se fait à la hauteur de la liste entière ; une recherche, qui la raccourcit, n'y change rien.
    if etat.recherche.is_none() {
        crate::fenetre::epouser(rangees.len() + DESSOUS_LISTE);
    }
    // Pendant une recherche, la saisie prend une ligne de plus sous l'aide.
    let place = terminal::size()
        .map_or(24, |(_, r)| usize::from(r))
        .saturating_sub(DESSOUS_LISTE + usize::from(etat.recherche.is_some()));
    for t in fenetre(&rangees, entete, entete + rang_ecran, place, &mut etat.haut) {
        ecran += &t;
        ecran += "\x1b[K\r\n";
    }
    ecran += "\x1b[K\r\n";
    // L'explication de la ligne en cours, toujours sur le même nombre de lignes : l'écran ne saute pas.
    let explication = rang
        .and_then(|_| cases.get(etat.en_cours))
        .map_or("", |c| c.detail.as_str());
    let mut detail = envelopper(explication, LARGEUR - 4);
    detail.resize(LIGNES_DETAIL, String::new());
    for l in detail.iter().take(LIGNES_DETAIL) {
        let _ = write!(ecran, "  {GRIS}{l}{RESET}\x1b[K\r\n");
    }
    if let Some(t) = &etat.recherche {
        let aide = if suite.is_some() {
            &aides.prediction
        } else {
            &aides.recherche
        };
        let (gris, recul) = fantome(suite);
        let _ = write!(
            ecran,
            "{aide}\x1b[K\r\n  {ACCENT}›{RESET} /{t}{gris}\x1b[K\x1b[J{recul}"
        );
    } else {
        let aide = &aides.menu;
        let _ = write!(ecran, "{aide}\x1b[K\x1b[J");
    }
    ecran
}

/// Ce que fait une touche dans une liste à cocher : `Continue` pour continuer (la liste se redessine), `Break(fin)`
/// pour la quitter (`Break(Some(états))` : Entrée ; `Break(None)` : Échap, ← ou Retour arrière).
fn touche_de_la_liste(
    k: event::KeyEvent,
    etat: &mut EtatListe,
    cases: &[Case],
    montrees: &[usize],
    rang: Option<usize>,
    suite: Option<&str>,
) -> ControlFlow<Option<Vec<bool>>> {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    // Tab ou → prennent la prédiction ; pas d'espace après : Espace coche.
    if let (Some(t), Some(s)) = (&mut etat.recherche, suite)
        && matches!(k.code, KeyCode::Tab | KeyCode::Right)
    {
        t.push_str(s);
        return ControlFlow::Continue(());
    }
    // Les flèches parcourent les lignes montrées : toute la liste, ou celles que la recherche a trouvées.
    let rang_ecran = rang.unwrap_or(0);
    let derniere = montrees.len().saturating_sub(1);
    let deplacement = match k.code {
        KeyCode::Up | KeyCode::BackTab => Some(rang_ecran.checked_sub(1).unwrap_or(derniere)),
        KeyCode::Down | KeyCode::Tab => Some(if rang_ecran >= derniere { 0 } else { rang_ecran + 1 }),
        KeyCode::Home | KeyCode::PageUp => Some(0),
        KeyCode::End | KeyCode::PageDown => Some(derniere),
        _ => None,
    };
    if let Some(r) = deplacement {
        if let Some(&i) = montrees.get(r) {
            etat.en_cours = i;
        }
        return ControlFlow::Continue(());
    }
    if ctrl && matches!(k.code, KeyCode::Char('c' | 'd')) {
        let _ = terminal::disable_raw_mode();
        println!();
        crate::machine::quitter(if k.code == KeyCode::Char('c') { 130 } else { 0 });
    }
    // Ctrl-J ou Ctrl-M : le saut de ligne que certains terminaux envoient pour Entrée.
    let entree = k.code == KeyCode::Enter || (ctrl && matches!(k.code, KeyCode::Char('j' | 'm')));
    if k.code == KeyCode::Char(' ') {
        if rang.is_some()
            && cases.get(etat.en_cours).is_some_and(|c| !c.fixe)
            && let Some(e) = etat.etats.get_mut(etat.en_cours)
        {
            *e = !*e;
        }
    } else if let Some(t) = &mut etat.recherche {
        // Entrée ou Échap finissent la recherche : toute la liste revient, la ligne en cours gardée. Entrée ne
        // valide pas la liste ici : on la valide en la voyant entière.
        if entree || matches!(k.code, KeyCode::Esc | KeyCode::Left) || (k.code == KeyCode::Backspace && t.is_empty()) {
            etat.recherche = None;
        } else if k.code == KeyCode::Backspace {
            t.pop();
        } else if let KeyCode::Char(c) = k.code
            && !ctrl
        {
            t.push(c);
        }
    } else if entree {
        return ControlFlow::Break(Some(std::mem::take(&mut etat.etats)));
    } else {
        match k.code {
            KeyCode::Char('r' | 'R') if !ctrl => {
                for (e, c) in etat.etats.iter_mut().zip(cases) {
                    *e |= c.recommandee && !c.fixe;
                }
            }
            KeyCode::Char('/') => etat.recherche = Some(String::new()),
            // Une lettre ou un chiffre commence aussi une recherche ; « r » reste les recommandés (« / » d'abord
            // pour chercher un mot en r).
            KeyCode::Char(c) if !ctrl && c.is_alphanumeric() => etat.recherche = Some(c.to_string()),
            // Retour arrière ou ←, sans rien de tapé, reviennent en arrière comme Échap. → ne valide pas : une
            // liste à cocher lance souvent des changements (nettoyer, désinstaller), Entrée seule les confirme.
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Left => return ControlFlow::Break(None),
            _ => {}
        }
    }
    ControlFlow::Continue(())
}

/// Les lignes (leur rang) dont le texte simplifié contient tous les mots de `recherche` ; toutes si rien n'est tapé.
fn lignes_trouvees(recherche: &str, cherche: &[String]) -> Vec<usize> {
    cherche
        .iter()
        .enumerate()
        .filter(|(_, c)| recherche.trim().is_empty() || correspond(recherche, c))
        .map(|(i, _)| i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_ligne_en_cours_se_voit_et_tout_reste_aligne() {
        let lignes = [
            Ligne::choix("1", "Bilan complet", "← commencer ici"),
            Ligne::choix("q", "Quitter", ""),
        ];
        let c = colonne(&lignes);
        let normale = rendu("1", "Bilan complet", "← commencer ici", c, false);
        let choisie = rendu("1", "Bilan complet", "← commencer ici", c, true);
        assert!(choisie.contains('►') && !normale.contains('►'));
        assert_eq!(largeur_affichee(&normale), largeur_affichee(&choisie));
        // Un long titre (réparations) n'est pas coupé : la colonne des précisions se pousse.
        let long = "Navigation détournée (proxy, fichier hosts)";
        let c = colonne(&[Ligne::choix("2", long, "rien à faire")]);
        assert!(rendu("2", long, "rien à faire", c, false).contains(long));
    }

    #[test]
    fn recherche_sans_accents_ni_majuscules() {
        let t = simplifier("Réseau et Internet › Scanner le Wi-Fi");
        assert_eq!(t, "reseau et internet › scanner le wifi");
        assert!(correspond("RESEAU", &t));
        // Tous les mots comptent, dans n'importe quel ordre.
        assert!(correspond("wi-fi scanner", &t));
        assert!(!correspond("wifi imprimante", &t));
        // Un mot court commence un mot : « sc » trouve « scanner », « an » ne trouve rien.
        assert!(correspond("sc", &t));
        assert!(!correspond("an", &t));
        assert!(!correspond("", &t));
        // La fin d'un mot peut changer : l'infinitif, le pluriel.
        let vide = simplifier("Vide le cache DNS. Répare les disques.");
        assert!(correspond("vider dns", &vide) && correspond("réparer", &vide) && correspond("disque", &vide));
        assert!(!correspond("réseau", &simplifier("Resets the TCP/IP settings")));
        assert_eq!(simplifier("\x1b[1;96mCœur\x1b[0m"), "coeur");
    }

    #[test]
    fn ce_qui_commence_par_le_mot_passe_devant() {
        assert_eq!(rang("tar", &simplifier("tar")), 0);
        assert_eq!(rang("tar", &simplifier("⚠ tar -czf <archive>")), 0);
        assert_eq!(rang("archive tar", &simplifier("tar -tzf archive.tar.gz")), 1);
        assert_eq!(rang("tar", &simplifier("akmods")), 2);
        assert_eq!(rang("Réseau", &simplifier("Réseau et Internet")), 0);
    }

    #[test]
    fn une_lettre_ou_une_touche_n_est_pas_une_recherche() {
        let touches = ["1", "10", "4.2", "q", "↵"];
        // Les raccourcis des anciennes versions (une lettre) et les touches, même à moitié tapées.
        assert!(!est_une_recherche("u", &touches));
        assert!(!est_une_recherche("10", &touches));
        assert!(!est_une_recherche("4.", &touches));
        assert!(!est_une_recherche(" 4.2 ", &touches));
        assert!(est_une_recherche("wifi", &touches));
        assert!(est_une_recherche("1a", &touches));
    }

    #[test]
    fn les_lignes_cachees_se_trouvent_et_tiennent_dans_l_ecran() {
        let lignes = [
            Ligne::Texte("titre".into()),
            Ligne::choix("1", "Bilan complet", "← commencer ici"),
            Ligne::cachee(
                "5.2",
                "Réseau et Internet ›",
                "Scan approfondi d'un appareil",
                "tous les ports",
            )
            .avec_mots("nmap"),
        ];
        let choix = choisissables(&lignes);
        assert_eq!(choix.len(), 2);
        assert!(choix[0].visible && !choix[1].visible);
        assert!(correspond("approfondi", &choix[1].cherche));
        // Les mots en plus se trouvent sans s'afficher.
        assert!(correspond("nmap", &choix[1].cherche));
        assert!(!choix[1].texte.contains("nmap"));
        // Hors recherche, une ligne cachée ne s'affiche pas.
        assert!(texte(&lignes[2], 36, false).is_none());
        // Un très long chemin est coupé : la ligne trouvée tient dans LARGEUR.
        let long = [Ligne::cachee(
            "10.1.12",
            &"chemin très long ".repeat(10),
            "texte",
            "précision",
        )];
        let c = choisissables(&long);
        assert!(largeur_affichee(&rendu_trouve(&c[0], 7, true)) <= LARGEUR);
    }

    #[test]
    fn un_menu_trop_haut_defile() {
        let rangees: Vec<String> = (0..40).map(|i| format!("r{i}")).collect();
        let mut haut = 0;
        // Il tient : tout, tel quel.
        assert_eq!(fenetre(&rangees[..10], 2, 5, 20, &mut haut), rangees[..10].to_vec());
        // 40 rangées dont 3 d'en-tête, dans 20 : l'en-tête reste, la ligne en cours se voit, 20 rangées au plus.
        for en_cours in 3..40 {
            let e = fenetre(&rangees, 3, en_cours, 20, &mut haut);
            assert!(e.len() <= 20, "{e:?}");
            assert_eq!(e[..3], rangees[..3]);
            assert!(e.contains(&rangees[en_cours]), "{en_cours} : {e:?}");
        }
        // Au bout : l'annonce du dessus dit ce qui est caché, celle du dessous est vide.
        let e = fenetre(&rangees, 3, 39, 20, &mut haut);
        assert!(e[3].contains('↑') && e[3].contains("22"), "{e:?}");
        assert!(e.last().is_some_and(String::is_empty));
        // Remonter d'une ligne, sans sortir de l'écran, ne fait pas bouger la liste.
        let avant = haut;
        let _ = fenetre(&rangees, 3, 37, 20, &mut haut);
        assert_eq!(haut, avant);
        // Revenir en haut garde une rangée de contexte au-dessus de la ligne en cours (un titre de section).
        let e = fenetre(&rangees, 3, 10, 20, &mut haut);
        assert!(e.contains(&rangees[9]) && e.contains(&rangees[10]), "{e:?}");
        // La fin demandée par usize::MAX (touche Fin, dernière ligne) : le bas de la liste, sans débordement.
        let mut tout_en_bas = usize::MAX;
        let e = fenetre(&rangees, 3, 39, 20, &mut tout_en_bas);
        assert!(e.contains(&rangees[39]) && e.last().is_some_and(String::is_empty) && tout_en_bas == 22);
        // Un en-tête trop haut pour la fenêtre défile avec le reste.
        let e = fenetre(&rangees, 30, 35, 20, &mut haut);
        assert!(e.len() <= 20 && e.contains(&rangees[35]));
        // Toutes les tailles de fenêtre : jamais plus de rangées que de place, la ligne en cours toujours là.
        for place in 5..45 {
            for en_cours in 0..40 {
                for depart in [0, 7, usize::MAX] {
                    let mut h = depart;
                    let e = fenetre(&rangees, 3, en_cours, place, &mut h);
                    assert!(
                        e.len() <= place && e.contains(&rangees[en_cours]),
                        "{place} {en_cours} : {e:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn la_recherche_d_une_liste_a_cocher_lit_le_texte_l_etat_et_l_explication() {
        let cherche: Vec<String> = [
            "Firefox installé Navigateur web rapide",
            "LibreWolf MPL-2.0 Firefox renforcé",
            "Brave MPL-2.0 Navigateur Chromium",
        ]
        .iter()
        .map(|t| simplifier(t))
        .collect();
        assert_eq!(lignes_trouvees("fire", &cherche), [0, 1]);
        assert_eq!(lignes_trouvees("WOLF", &cherche), [1]);
        assert_eq!(lignes_trouvees("mpl navigateur", &cherche), [2]);
        assert_eq!(lignes_trouvees("imprimante", &cherche), [] as [usize; 0]);
        // Rien de tapé (« / » seul) : toute la liste.
        assert_eq!(lignes_trouvees(" ", &cherche), [0, 1, 2]);
    }

    /// Chaque ligne d'aide, dans les deux langues, tient dans `LARGEUR` colonnes : lue dans ce fichier, « {echap} »
    /// remplacé par un mot de dix lettres, plus long que ceux que les menus donnent.
    #[test]
    fn lignes_d_aide_dans_la_largeur() {
        let aides: Vec<&str> = include_str!("selection.rs")
            .lines()
            .filter_map(|l| l.trim().strip_prefix("\"  {GRIS}↑ ↓"))
            .collect();
        assert!(aides.len() >= 6, "{aides:?}");
        for aide in aides {
            let texte = format!(
                "  ↑ ↓{}",
                aide.split("{RESET}")
                    .next()
                    .unwrap()
                    .replace("{echap}", "xxxxxxxxxx")
                    .replace("{gauche}", "/←")
            );
            assert!(
                largeur_affichee(&texte) <= LARGEUR,
                "{} colonnes : {texte}",
                largeur_affichee(&texte)
            );
        }
    }

    #[test]
    fn l_apercu_ne_paraît_que_s_il_a_la_place() {
        assert_eq!(largeur_apercu(LARGEUR + 2), None);
        assert_eq!(largeur_apercu(LARGEUR + AVANT_APERCU + APERCU_MIN), None);
        assert_eq!(
            largeur_apercu(LARGEUR + AVANT_APERCU + APERCU_MIN + 1),
            Some(APERCU_MIN)
        );
        assert_eq!(largeur_apercu(COLONNES_AVEC_APERCU), Some(APERCU_MAX));
        assert_eq!(largeur_apercu(400), Some(APERCU_MAX));
        // Un menu sans description ni sous-menu (oui ou non, extension) n'en a pas.
        assert!(!a_des_apercus(&[
            Ligne::choix("1", "Oui", ""),
            Ligne::choix("2", "Non", "")
        ]));
        assert!(a_des_apercus(&[
            Ligne::choix("1", "Oui", "").avec_description("Accepte.")
        ]));
    }

    #[test]
    fn un_groupe_montre_ses_outils_sans_leurs_variantes() {
        let lignes = [
            Ligne::choix("5", &format!("Réseau {ACCENT}›{RESET}"), "routeur, Wi-Fi"),
            Ligne::choix("6", "Virus ›", ""),
            Ligne::cachee("5.1", "Réseau ›", "Appareils du réseau ›", ""),
            Ligne::cachee("5.1.1", "Réseau › Appareils du réseau ›", "Scan du réseau", ""),
            Ligne::cachee("5.2", "Réseau ›", "Audit du réseau", ""),
            Ligne::cachee("5.2", "Réseau ›", "Audit du réseau (double)", ""),
            Ligne::cachee("55.1", "Autre ›", "Pas à lui", ""),
            Ligne::cachee("6.1", "Virus ›", "Analyse antivirus", ""),
        ];
        assert_eq!(
            ce_qu_elle_ouvre(&lignes, &lignes[0]),
            ["Appareils du réseau", "Audit du réseau"]
        );
        // Une ligne cachée trouvée par la recherche montre aussi ce qu'elle ouvre.
        assert_eq!(ce_qu_elle_ouvre(&lignes, &lignes[2]), ["Scan du réseau"]);
        // Les variantes données à la main passent avant.
        let ecran = Ligne::choix("3", "Antivirus ›", "").avec_sous(vec!["Analyse rapide".into()]);
        assert_eq!(ce_qu_elle_ouvre(&lignes, &ecran), ["Analyse rapide"]);
    }

    #[test]
    fn l_apercu_tient_dans_sa_largeur_et_sa_hauteur() {
        let mut lignes = vec![
            Ligne::choix("4", "Cet ordinateur ›", "failles")
                .avec_description("Une description assez longue pour tenir sur plusieurs lignes du panneau de droite, avec un motextrêmementlongquinetientpasdutoutdanslalargeur."),
        ];
        for i in 1..=30 {
            lignes.push(Ligne::cachee(
                &format!("4.{i}"),
                "Cet ordinateur ›",
                &format!("Outil {i} au nom long"),
                "",
            ));
        }
        let largeur = APERCU_MIN;
        let panneau = apercu(&lignes, &lignes[0], largeur, 15);
        assert_eq!(panneau.len(), 15);
        assert!(panneau.iter().all(|r| largeur_affichee(r) <= largeur), "{panneau:#?}");
        assert_eq!(simplement_affiche(&panneau[0]), "Cet ordinateur");
        let fin = simplement_affiche(panneau.last().unwrap());
        assert!(fin.starts_with('…') && fin.contains("autre"), "{fin}");
        // Sans limite de hauteur, tout y est : 30 outils et aucune annonce.
        let tout = apercu(&lignes, &lignes[0], largeur, usize::MAX);
        assert_eq!(
            tout.iter().filter(|r| simplement_affiche(r).starts_with("› ")).count(),
            30
        );
    }

    #[test]
    fn le_panneau_se_place_par_colonne_sous_le_cadre() {
        let rangees: Vec<String> = lignes_cadre("VANGUARD", "titre")
            .into_iter()
            .chain(["  1  Bilan".to_string(), String::new()])
            .collect();
        let debut = debut_apercu(&rangees);
        assert_eq!(debut, 3);
        let texte = vec!["Bilan".to_string()];
        let ecran = avec_panneau(&rangees, Some((&texte, debut)));
        let lignes: Vec<&str> = ecran.split("\r\n").collect();
        let colonne = format!("\x1b[{}G", LARGEUR + 2);
        assert!(lignes[..3].iter().all(|l| !l.contains(&colonne)));
        assert!(lignes[3].ends_with(&format!("│{RESET} Bilan")), "{:?}", lignes[3]);
        // Le filet continue sous le texte du panneau.
        assert!(lignes[4].contains(&colonne) && lignes[4].ends_with(&format!("│{RESET} ")));
        // Sans panneau, l'écran est celui d'avant.
        assert!(!avec_panneau(&rangees, None).contains(&colonne));
    }
}
