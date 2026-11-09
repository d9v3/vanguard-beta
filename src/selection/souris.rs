//! La souris dans les menus et les listes du terminal : un clic sur une ligne l'ouvre (la coche, dans une liste), la
//! souris qui passe dessus la met en surbrillance, la roulette fait défiler, le clic droit revient en arrière, et les
//! touches de la ligne d'aide (« Entrée ouvrir », « Échap revenir », « q quitter »…) se cliquent comme des boutons.
//! Le même code partout : le terminal envoie ses clics comme des touches (Linux, macOS, SSH), la console de Windows
//! par son API ; crossterm les rend tous pareils. Rien ne se lance sans un clic ou une touche : le survol ne fait que
//! montrer. Pendant qu'un menu attend, le terminal ne sélectionne plus le texte d'un simple glisser : Maj (Shift) et
//! glisser le fait toujours. Hors des menus (la sortie d'une commande), la souris est rendue au terminal.

use std::io::Write as _;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

use crate::ui::largeur_affichee;

/// La capture est-elle en place ? Rendue une seule fois, et seulement si elle a été prise : sous Windows, la rendre
/// sans l'avoir prise remettrait un mode de console d'une autre fois.
static CAPTUREE: AtomicBool = AtomicBool::new(false);

/// Les clics, le survol et la roulette envoyés au programme. Après le mode clavier : sous Windows, le mode de la
/// console retenu à la première capture est alors celui du mode clavier, que `rendre` remet avant que le mode clavier
/// ne rende le reste.
pub(crate) fn capturer() {
    if CAPTUREE.load(Ordering::Relaxed) {
        return;
    }
    let mut sortie = std::io::stdout();
    if crossterm::execute!(sortie, crossterm::event::EnableMouseCapture).is_ok() {
        CAPTUREE.store(true, Ordering::Relaxed);
    }
    let _ = sortie.flush();
}

/// La souris rendue au terminal (sélection du texte au glisser), avant le mode clavier.
pub(crate) fn rendre() {
    if CAPTUREE.swap(false, Ordering::Relaxed) {
        let mut sortie = std::io::stdout();
        let _ = crossterm::execute!(sortie, crossterm::event::DisableMouseCapture);
        let _ = sortie.flush();
    }
}

/// Ce qu'un clic vise : une ligne de la liste (son rang, selon l'écran : ligne du menu, ligne trouvée, case), une
/// touche, ou une lettre de raccourci (« s réglages ») que le menu valide aussitôt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cible {
    Ligne(usize),
    Touche(KeyCode),
    Lettre(char),
}

/// Un endroit de l'écran qui répond à la souris : une rangée (0 en haut de la fenêtre), des colonnes, une cible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Zone {
    pub rangee: usize,
    pub colonnes: Range<usize>,
    pub cible: Cible,
}

impl Zone {
    /// Une ligne de liste : de la marge jusqu'au bout du menu (`LARGEUR`), pas dans le panneau d'aperçu à droite.
    pub(crate) fn ligne(rangee: usize, rang: usize) -> Self {
        Zone {
            rangee,
            colonnes: 0..crate::ui::LARGEUR.saturating_add(1),
            cible: Cible::Ligne(rang),
        }
    }
}

/// Ce que devient un geste de la souris.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Une touche, traitée comme si elle venait du clavier.
    Touche(KeyEvent),
    /// La souris passe sur une ligne : elle passe en surbrillance, rien ne se lance.
    Viser(usize),
    /// Un clic sur une ligne : l'ouvrir (la cocher, dans une liste).
    Ouvrir(usize),
    /// Un clic sur une lettre de raccourci de l'aide.
    Lettre(char),
}

/// Une touche sans modificateur, comme le clavier l'enverrait.
pub(crate) fn touche(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn sous(m: MouseEvent, zones: &[Zone]) -> Option<Cible> {
    let (colonne, rangee) = (usize::from(m.column), usize::from(m.row));
    zones
        .iter()
        .find(|z| z.rangee == rangee && z.colonnes.contains(&colonne))
        .map(|z| z.cible)
}

/// L'action d'un geste sur un écran fait de `zones`, ou `None` : rien à faire, ni à redessiner. Le clic agit à
/// l'appui ; le glisser, bouton tenu, vise comme le survol. La roulette est ↑ ou ↓, le clic droit ← (revenir : au
/// menu principal, ← ne quitte pas Vanguard).
pub(crate) fn action(m: MouseEvent, zones: &[Zone]) -> Option<Action> {
    match m.kind {
        MouseEventKind::ScrollUp => Some(Action::Touche(touche(KeyCode::Up))),
        MouseEventKind::ScrollDown => Some(Action::Touche(touche(KeyCode::Down))),
        MouseEventKind::Down(MouseButton::Right) => Some(Action::Touche(touche(KeyCode::Left))),
        MouseEventKind::Down(MouseButton::Left) => Some(match sous(m, zones)? {
            Cible::Ligne(n) => Action::Ouvrir(n),
            Cible::Touche(code) => Action::Touche(touche(code)),
            Cible::Lettre(c) => Action::Lettre(c),
        }),
        MouseEventKind::Moved | MouseEventKind::Drag(MouseButton::Left) => match sous(m, zones)? {
            Cible::Ligne(n) => Some(Action::Viser(n)),
            Cible::Touche(_) | Cible::Lettre(_) => None,
        },
        _ => None,
    }
}

/// La touche que nomme un mot de l'aide (« Entrée/→ » : le premier nom), ou `None` : un mot qui n'en est pas une
/// (« choisir », « un mot : chercher »).
fn touche_nommee(mot: &str, lettres: bool) -> Option<Cible> {
    // « / » seul est la touche « / », pas une coupure.
    let nom = if mot == "/" {
        mot
    } else {
        mot.split('/').next().unwrap_or(mot)
    };
    let code = match nom {
        "↑" => KeyCode::Up,
        "↓" => KeyCode::Down,
        "Entrée" | "Enter" => KeyCode::Enter,
        "Échap" | "Esc" => KeyCode::Esc,
        "Tab" => KeyCode::Tab,
        "Espace" | "Space" => KeyCode::Char(' '),
        "/" => KeyCode::Char('/'),
        _ => {
            let mut c = nom.chars();
            return match (c.next(), c.next()) {
                (Some(l), None) if lettres && l.is_ascii_alphabetic() => Some(Cible::Lettre(l.to_ascii_lowercase())),
                _ => None,
            };
        }
    };
    Some(Cible::Touche(code))
}

/// Les boutons d'une ligne d'aide (« ↑ ↓ choisir · Entrée ouvrir · un mot : chercher · q quitter ») montrée à la
/// rangée `rangee` : chaque partie entre deux « · » qui commence par une touche se clique en entier ; ↑ et ↓ chacune
/// pour soi. Une lettre seule n'est une touche que dans une partie sans « : » : « a word: search » n'est pas « a ».
pub(crate) fn zones_de_l_aide(aide: &str, rangee: usize) -> Vec<Zone> {
    let texte = super::simplement_affiche(aide);
    let mut zones = Vec::new();
    let mut colonne = 0usize;
    for (i, partie) in texte.split(" · ").enumerate() {
        if i > 0 {
            colonne = colonne.saturating_add(3);
        }
        let fin = colonne.saturating_add(largeur_affichee(partie));
        let lettres = !partie.contains(':');
        // La marge de gauche, puis les flèches, chacune son bouton, puis le premier mot qui nomme le reste.
        let mut debut =
            colonne.saturating_add(largeur_affichee(partie).saturating_sub(largeur_affichee(partie.trim_start())));
        let mut reste = partie.trim_start();
        while let Some(f) = reste.strip_prefix('↑').or_else(|| reste.strip_prefix('↓')) {
            let fleche = if reste.starts_with('↑') {
                KeyCode::Up
            } else {
                KeyCode::Down
            };
            zones.push(Zone {
                rangee,
                colonnes: debut..debut.saturating_add(1),
                cible: Cible::Touche(fleche),
            });
            let suite = f.trim_start();
            debut = debut
                .saturating_add(1)
                .saturating_add(largeur_affichee(f).saturating_sub(largeur_affichee(suite)));
            reste = suite;
        }
        if let Some(cible) = reste.split_whitespace().next().and_then(|m| touche_nommee(m, lettres)) {
            zones.push(Zone {
                rangee,
                colonnes: debut..fin,
                cible,
            });
        }
        colonne = fin;
    }
    zones
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::MouseEvent;

    fn souris(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn cible_a(zones: &[Zone], colonne: usize) -> Option<Cible> {
        zones.iter().find(|z| z.colonnes.contains(&colonne)).map(|z| z.cible)
    }

    #[test]
    fn l_aide_du_menu_principal_se_clique() {
        let aide = "  \x1b[90m↑ ↓ choisir · Entrée ouvrir · un mot : chercher · s réglages · q quitter\x1b[0m";
        let z = zones_de_l_aide(aide, 7);
        assert!(z.iter().all(|z| z.rangee == 7));
        // « ↑ » en colonne 2, « ↓ » en colonne 4 ; « choisir » n'est pas une touche.
        assert_eq!(cible_a(&z, 2), Some(Cible::Touche(KeyCode::Up)));
        assert_eq!(cible_a(&z, 4), Some(Cible::Touche(KeyCode::Down)));
        assert_eq!(cible_a(&z, 7), None);
        let texte = super::super::simplement_affiche(aide);
        let colonne_de = |mot: &str| largeur_affichee(&texte[..texte.find(mot).unwrap()]);
        assert_eq!(cible_a(&z, colonne_de("Entrée")), Some(Cible::Touche(KeyCode::Enter)));
        assert_eq!(cible_a(&z, colonne_de("ouvrir")), Some(Cible::Touche(KeyCode::Enter)));
        assert_eq!(cible_a(&z, colonne_de("un mot")), None);
        assert_eq!(cible_a(&z, colonne_de("réglages")), Some(Cible::Lettre('s')));
        assert_eq!(cible_a(&z, colonne_de("q quitter")), Some(Cible::Lettre('q')));
        // Le séparateur ne se clique pas.
        assert_eq!(cible_a(&z, colonne_de("· q")), None);
    }

    #[test]
    fn l_aide_en_anglais_et_celle_des_listes() {
        let z = zones_de_l_aide("  ↑ ↓ select · Enter/→ run · a word: search · Esc/← back", 0);
        let cibles: Vec<Cible> = z.iter().map(|z| z.cible).collect();
        assert_eq!(
            cibles,
            [
                Cible::Touche(KeyCode::Up),
                Cible::Touche(KeyCode::Down),
                Cible::Touche(KeyCode::Enter),
                Cible::Touche(KeyCode::Esc)
            ],
            "« a word: search » n'est pas la lettre a"
        );
        let z = zones_de_l_aide(
            "  ↑ ↓  Espace cocher · R recommandés · / chercher · Entrée OK · Échap retour",
            0,
        );
        let cibles: Vec<Cible> = z.iter().map(|z| z.cible).collect();
        assert_eq!(
            cibles,
            [
                Cible::Touche(KeyCode::Up),
                Cible::Touche(KeyCode::Down),
                Cible::Touche(KeyCode::Char(' ')),
                Cible::Lettre('r'),
                Cible::Touche(KeyCode::Char('/')),
                Cible::Touche(KeyCode::Enter),
                Cible::Touche(KeyCode::Esc)
            ]
        );
        // « Espace cocher » commence après les deux espaces qui suivent ↓ (colonnes 2 et 4).
        assert_eq!(cible_a(&z, 6), None);
        assert_eq!(cible_a(&z, 7), Some(Cible::Touche(KeyCode::Char(' '))));
    }

    #[test]
    fn les_gestes() {
        let zones = [
            Zone::ligne(3, 0),
            Zone {
                rangee: 9,
                colonnes: 10..20,
                cible: Cible::Touche(KeyCode::Enter),
            },
        ];
        let gauche = MouseEventKind::Down(MouseButton::Left);
        assert_eq!(action(souris(gauche, 5, 3), &zones), Some(Action::Ouvrir(0)));
        assert_eq!(
            action(souris(MouseEventKind::Moved, 5, 3), &zones),
            Some(Action::Viser(0))
        );
        assert_eq!(
            action(souris(gauche, 12, 9), &zones),
            Some(Action::Touche(touche(KeyCode::Enter)))
        );
        // Le survol d'un bouton ne fait rien ; un clic à côté de tout non plus.
        assert_eq!(action(souris(MouseEventKind::Moved, 12, 9), &zones), None);
        assert_eq!(action(souris(gauche, 5, 4), &zones), None);
        // Le panneau d'aperçu, à droite du menu, n'est pas la ligne.
        let loin = u16::try_from(crate::ui::LARGEUR + 3).unwrap();
        assert_eq!(action(souris(gauche, loin, 3), &zones), None);
        assert_eq!(
            action(souris(MouseEventKind::ScrollDown, 0, 0), &[]),
            Some(Action::Touche(touche(KeyCode::Down)))
        );
        assert_eq!(
            action(souris(MouseEventKind::Down(MouseButton::Right), 0, 0), &[]),
            Some(Action::Touche(touche(KeyCode::Left)))
        );
        assert_eq!(
            action(souris(MouseEventKind::Up(MouseButton::Left), 5, 3), &zones),
            None
        );
    }
}
