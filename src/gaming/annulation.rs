//! Les notes des réglages pour jouer d'avant la reprise par Optimiser : jeux.json, jamais scellé, où chaque réglage
//! gardait ses valeurs d'avant (nom, valeur). Elles sont reprises une fois dans reglages.json, scellé
//! (`optimiser::annulables::reprendre_jeux`), qui note désormais les réglages pour jouer comme le reste ; ce qui ne se
//! reprend pas reste ici, intact. Une valeur de jeux.json n'est jamais remise telle quelle : tout programme du compte
//! pouvait l'écrire, et elle repartait en administrateur.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::optimiser::Geste;
use crate::ui::*;

/// Une valeur notée : son nom (valeur du registre, fichier, réglage du noyau) et ce qu'elle valait (`None` : absente).
pub(crate) type Valeur = (String, Option<String>);

/// Le fichier des notes d'avant, dans les données de cet ordinateur.
pub(crate) const FICHIER: &str = "jeux.json";

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub(crate) struct Notes {
    pub(crate) reglages: BTreeMap<String, Avant>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Avant {
    pub(crate) titre: String,
    pub(crate) date: String,
    pub(crate) valeurs: Vec<Valeur>,
}

/// Les notes d'avant de ce dossier ; `None` sans fichier. Illisible : mis de côté, intact, et dit (jamais écrasé).
pub(crate) fn lire(dossier: &Path) -> Option<Notes> {
    let chemin = dossier.join(FICHIER);
    // Un simple fichier, borné : un tube ou un lien vers /dev/zero à sa place ne fige ni ne remplit rien.
    let texte = crate::socle::lire_texte_ordinaire(&chemin, 16 << 20).ok()?;
    match serde_json::from_str(texte.trim_start_matches('\u{feff}')) {
        Ok(n) => Some(n),
        Err(e) => {
            let copie = chemin.with_extension(format!(
                "illisible-{}.json",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            ));
            if crate::socle::ecrire_atomique(&copie, &texte).is_ok() {
                let _ = std::fs::remove_file(&chemin);
            }
            tre!(
                "Attention : valeurs d'avant des réglages pour jouer illisibles ({e}). Copie gardée : {}",
                "Warning: previous gaming setting values unreadable ({e}). Copy kept: {}",
                copie.display()
            );
            None
        }
    }
}

/// Réécrit ce qui reste à reprendre, d'un bloc ; sans rien, le fichier part.
pub(crate) fn garder(dossier: &Path, reste: &Notes) {
    let chemin = dossier.join(FICHIER);
    let ecrit = if reste.reglages.is_empty() {
        match std::fs::remove_file(&chemin) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    } else {
        serde_json::to_string_pretty(reste)
            .map_err(std::io::Error::other)
            .and_then(|texte| crate::socle::ecrire_atomique(&chemin, &texte))
    };
    if let Err(e) = ecrit {
        tre!(
            "Attention : jeux.json non réécrit ({e}).",
            "Warning: jeux.json not rewritten ({e})."
        );
    }
}

/// Une note d'avant dans la forme d'Optimiser : chaque valeur avec son geste. `None` si l'une ne se convertit pas.
pub(crate) fn convertir(id: &str, valeurs: &[Valeur]) -> Option<Vec<(Geste, Option<String>)>> {
    valeurs
        .iter()
        .map(|(nom, v)| convertir_une(id, nom, v.as_deref()))
        .collect()
}

#[cfg(target_os = "linux")]
fn convertir_une(_id: &str, nom: &str, v: Option<&str>) -> Option<(Geste, Option<String>)> {
    super::linux::convertir(nom, v)
}

#[cfg(windows)]
fn convertir_une(id: &str, nom: &str, v: Option<&str>) -> Option<(Geste, Option<String>)> {
    super::windows::convertir(id, nom, v)
}

/// macOS n'a jamais noté de réglage pour jouer.
#[cfg(target_os = "macos")]
fn convertir_une(_id: &str, _nom: &str, _v: Option<&str>) -> Option<(Geste, Option<String>)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier(nom: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-jeux-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn notes_relues_puis_retirees() {
        let d = dossier("notes");
        let mut n = Notes::default();
        n.reglages.insert(
            "souris".into(),
            Avant {
                titre: "Souris".into(),
                date: "2026-10-20 10:00".into(),
                valeurs: vec![("valeur".into(), Some("1".into()))],
            },
        );
        garder(&d, &n);
        assert_eq!(lire(&d), Some(n));
        // Plus rien à reprendre : le fichier part.
        garder(&d, &Notes::default());
        assert!(!d.join(FICHIER).exists());
        assert_eq!(lire(&d), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn note_illisible_mise_de_cote() {
        let d = dossier("illisible");
        std::fs::write(d.join(FICHIER), "{ pas du json").unwrap();
        assert_eq!(lire(&d), None);
        let copies = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .filter(|f| f.file_name().to_string_lossy().contains("illisible-"))
            .count();
        assert_eq!(copies, 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
