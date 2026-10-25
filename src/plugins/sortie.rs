//! Ce qu'un plugin écrit : des lignes ordinaires, montrées telles quelles (filtrées), et, s'il le veut, des constats.
//! Protocole : une ligne qui est un objet JSON `{"vanguard":1,"niveau":"info|moyen|eleve|critique|ok",
//! "categorie":"…","message":"…"}` devient un constat, affiché comme ceux du bilan et marqué « plugin `<nom>` ». Un
//! constat de plugin ne compte jamais dans la note : il n'entre ni dans l'audit ni dans l'historique.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::manifeste::Manifeste;
use crate::commande::Borne;
use crate::risk::Niveau;
use crate::ui::*;
use crate::{trf, trp};

/// Bornes de ce qui est montré : un plugin bavard ne noie pas l'écran, un message ne dépasse pas quelques lignes.
const CONSTATS_MAX: usize = 100;
const CATEGORIE_MAX: usize = 40;
const MESSAGE_MAX: usize = 300;
const LIGNES_MAX: usize = 400;
const LIGNE_MAX: usize = 300;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConstatPlugin {
    /// « ok », « info », « moyen », « eleve » ou « critique ».
    pub niveau: String,
    pub categorie: String,
    pub message: String,
}

impl ConstatPlugin {
    /// Le niveau du bilan : `None` pour « ok », comme un constat sans problème.
    pub fn probleme(&self) -> Option<Niveau> {
        match self.niveau.as_str() {
            "info" => Some(Niveau::Info),
            "moyen" => Some(Niveau::Moyen),
            "eleve" => Some(Niveau::Eleve),
            "critique" => Some(Niveau::Critique),
            _ => None,
        }
    }
}

/// Un texte du plugin prêt à montrer : sur une ligne, sans caractère qui piloterait le terminal, borné.
fn propre(texte: &str, max: usize) -> String {
    let une_ligne: String = texte
        .chars()
        .map(|c| if matches!(c, '\n' | '\r' | '\t') { ' ' } else { c })
        .collect();
    couper(affichable(une_ligne.trim()).as_str(), max)
}

/// Le constat d'une ligne, si elle suit le protocole.
fn constat(ligne: &str) -> Option<ConstatPlugin> {
    let ligne = ligne.trim();
    if !ligne.starts_with('{') {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(ligne).ok()?;
    if v.get("vanguard")?.as_u64()? != 1 {
        return None;
    }
    let niveau = v.get("niveau")?.as_str()?;
    if !matches!(niveau, "ok" | "info" | "moyen" | "eleve" | "critique") {
        return None;
    }
    let categorie = propre(v.get("categorie")?.as_str()?, CATEGORIE_MAX);
    let message = propre(v.get("message")?.as_str()?, MESSAGE_MAX);
    (!categorie.is_empty() && !message.is_empty()).then(|| ConstatPlugin {
        niveau: niveau.to_string(),
        categorie,
        message,
    })
}

/// La sortie d'un plugin, triée.
#[derive(Debug, Default)]
pub struct Lu {
    pub lignes: Vec<String>,
    /// Lignes au-delà de `LIGNES_MAX`, non montrées.
    pub lignes_en_trop: usize,
    pub constats: Vec<ConstatPlugin>,
    /// Constats au-delà de `CONSTATS_MAX`, ignorés.
    pub constats_en_trop: usize,
}

pub fn analyser(sortie: &str) -> Lu {
    let mut lu = Lu::default();
    for ligne in sortie.lines() {
        if let Some(c) = constat(ligne) {
            if lu.constats.len() < CONSTATS_MAX {
                lu.constats.push(c);
            } else {
                lu.constats_en_trop += 1;
            }
        } else if lu.lignes.len() < LIGNES_MAX {
            lu.lignes.push(propre(ligne, LIGNE_MAX));
        } else {
            lu.lignes_en_trop += 1;
        }
    }
    lu
}

/// Montre ce que le plugin a écrit, ses erreurs, ses constats (comme ceux du bilan, marqués `marque` : « plugin
/// `<nom>` », « labo `<fichier>` »), puis comment il a fini.
pub fn afficher(marque: &str, titre_de: &str, delai: u64, b: &Borne, lu: &Lu) {
    if !lu.lignes.is_empty() {
        println!();
    }
    for l in &lu.lignes {
        afficher_aligne("  │ ", l, 4, "");
    }
    if lu.lignes_en_trop > 0 {
        trp!(
            "  {GRIS}… {} ligne(s) de plus, non montrées{RESET}",
            "  {GRIS}… {} more line(s), not shown{RESET}",
            lu.lignes_en_trop
        );
    }
    let erreurs = analyser(&b.erreurs);
    for l in erreurs.lignes.iter().take(40) {
        afficher_aligne("  │ ", l, 4, GRIS);
    }
    afficher_constats(marque, titre_de, &lu.constats);
    if lu.constats_en_trop > 0 {
        trp!(
            "  {GRIS}… {} constat(s) de plus, ignorés{RESET}",
            "  {GRIS}… {} more finding(s), ignored{RESET}",
            lu.constats_en_trop
        );
    }
    fin(delai, b);
}

/// Les constats d'une extension, comme ceux du bilan, marqués `marque`, et le rappel qu'ils ne comptent pas.
pub fn afficher_constats(marque: &str, titre_de: &str, constats: &[ConstatPlugin]) {
    if !constats.is_empty() {
        titre(&trf!("Constats de « {} »", "Findings of “{}”", affichable(titre_de)));
        for c in constats {
            let (icone, etiquette) = match c.probleme() {
                None => (format!("{VERT}✔{RESET}"), String::new()),
                Some(Niveau::Info) => (format!("{}ℹ{RESET}", couleur(Niveau::Info)), String::new()),
                Some(n) => (
                    format!("{}✖{RESET}", couleur(n)),
                    format!(" {}[{}]{RESET}", couleur(n), n.libelle()),
                ),
            };
            let cat = couper(&c.categorie, 16);
            afficher_aligne(
                &format!("  {icone} {GRAS}{cat:<16}{RESET}{etiquette} "),
                &c.message,
                21,
                "",
            );
            afficher_aligne(&format!("  {:18} ", ""), &affichable(marque), 21, GRIS);
        }
        trp!(
            "  {GRIS}Ces constats ne viennent pas de Vanguard : ils ne comptent pas dans la note.{RESET}",
            "  {GRIS}These findings do not come from Vanguard: they do not count in the grade.{RESET}"
        );
    }
}

/// Comment l'extension a fini.
fn fin(delai: u64, b: &Borne) {
    println!();
    if b.delai {
        trp!(
            "  {}⚠{RESET} Délai de {} s passé : arrêté.",
            "  {}⚠{RESET} {} s time limit reached: stopped.",
            couleur(Niveau::Moyen),
            delai
        );
    } else if b.tronque {
        trp!(
            "  {}⚠{RESET} Sortie trop longue : arrêté.",
            "  {}⚠{RESET} Output too long: stopped.",
            couleur(Niveau::Moyen)
        );
    } else {
        match b.code {
            Some(0) => trp!("  {VERT}✔{RESET} Terminé.", "  {VERT}✔{RESET} Finished."),
            Some(c) => trp!(
                "  {}✖{RESET} Terminé avec le code {c}.",
                "  {}✖{RESET} Finished with code {c}.",
                couleur(Niveau::Moyen)
            ),
            None => trp!(
                "  {}✖{RESET} Arrêté par un signal.",
                "  {}✖{RESET} Stopped by a signal.",
                couleur(Niveau::Moyen)
            ),
        }
    }
}

/// Les constats d'un plugin gardés pour le rapport HTML.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Gardes {
    pub nom: String,
    /// Titre en français puis en anglais.
    pub titre: [String; 2],
    pub le: String,
    pub constats: Vec<ConstatPlugin>,
}

impl Gardes {
    pub fn titre(&self) -> &str {
        &self.titre[usize::from(crate::langue::anglais())]
    }
}

/// Garde les constats de la dernière fois (`--rapport`), à la place des précédents.
pub fn garder(racine: &Path, m: &Manifeste, constats: &[ConstatPlugin]) -> Result<(), String> {
    let g = Gardes {
        nom: m.nom.clone(),
        titre: m.titre.clone(),
        le: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        constats: constats.to_vec(),
    };
    let d = racine.join(super::CONSTATS);
    super::creer_prive(&d).map_err(|e| e.to_string())?;
    let texte = serde_json::to_string_pretty(&g).map_err(|e| e.to_string())?;
    crate::socle::ecrire_atomique(&d.join(format!("{}.json", m.nom)), texte).map_err(|e| {
        trf!(
            "Constats impossibles à garder : {e}",
            "Could not keep the findings: {e}"
        )
    })
}

/// Les constats gardés de chaque plugin (50 plugins au plus), pour le rapport. Relus et refiltrés : le fichier a pu
/// changer depuis.
pub fn gardes() -> Vec<Gardes> {
    let d = crate::socle::dossier_local().join("plugins").join(super::CONSTATS);
    gardes_de(&d)
}

pub(crate) fn gardes_de(d: &Path) -> Vec<Gardes> {
    let mut chemins: Vec<_> = std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    chemins.sort();
    chemins
        .into_iter()
        .take(50)
        .filter_map(|p| {
            let octets = super::lire_sur(&p, 256 << 10).ok()?;
            let mut g: Gardes = serde_json::from_slice(&octets).ok()?;
            if !super::manifeste::nom_valide(&g.nom) {
                return None;
            }
            g.titre = g.titre.map(|t| propre(&t, 60));
            g.le = propre(&g.le, 20);
            g.constats.truncate(CONSTATS_MAX);
            for c in &mut g.constats {
                c.categorie = propre(&c.categorie, CATEGORIE_MAX);
                c.message = propre(&c.message, MESSAGE_MAX);
            }
            Some(g)
        })
        .collect()
}

/// Le nom à montrer d'un niveau, pour le rapport texte.
pub fn libelle(c: &ConstatPlugin) -> &'static str {
    c.probleme().map_or("OK", Niveau::libelle)
}
