//! Sauvegarde et restauration des données de Vanguard dans un seul fichier : base des appareils (surnoms,
//! historique de chaque réseau) et état de la surveillance. Sert à passer d'un ordinateur à l'autre sans la clé,
//! ou à garder une copie avant d'effacer la clé.
//! La quarantaine de l'antivirus n'y va jamais : on ne transporte pas de malware.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::reseau::surveillance;
use crate::reseau::{self, Contenu};
use crate::ui::*;

const FORMAT: &str = "vanguard-sauvegarde";

#[derive(Serialize, Deserialize)]
struct Sauvegarde {
    format: String,
    #[serde(default)]
    version_vanguard: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    surveillance: Option<bool>,
    base: serde_json::Value,
}

/// Dossier proposé : Documents sous Windows, le dossier personnel sous Linux.
pub(crate) fn dossier_par_defaut() -> PathBuf {
    #[cfg(windows)]
    {
        let profil = PathBuf::from(std::env::var_os("USERPROFILE").unwrap_or_default());
        let documents = profil.join("Documents");
        if documents.is_dir() { documents } else { profil }
    }
    #[cfg(not(windows))]
    crate::socle::maison()
}

fn chemin_par_defaut() -> PathBuf {
    dossier_par_defaut().join(format!(
        "vanguard-sauvegarde-{}.json",
        chrono::Local::now().format("%Y-%m-%d")
    ))
}

/// Chemin tapé ou collé : sans guillemets (« Copier en tant que chemin » de Windows en ajoute), « ~/ » développé.
fn chemin_saisi(texte: &str) -> Option<PathBuf> {
    let t = texte.trim().trim_matches('"').trim_matches('\'');
    if t.is_empty() {
        return None;
    }
    Some(match t.strip_prefix("~/") {
        Some(reste) => crate::socle::maison().join(reste),
        None => PathBuf::from(t),
    })
}

/// Lit une sauvegarde Vanguard, ou directement un appareils.json (la base copiée à la main depuis la clé).
/// Rend la base et l'état de la surveillance s'il est connu.
fn lire_sauvegarde(texte: &str) -> Result<(serde_json::Value, Option<bool>), String> {
    let mut valeur: serde_json::Value = serde_json::from_str(texte.trim_start_matches('\u{feff}')).map_err(|e| {
        trf!(
            "ce n'est pas un fichier JSON lisible ({e})",
            "this is not a readable JSON file ({e})"
        )
    })?;
    // Sauvegarde faite avant le changement de nom (`passage`).
    crate::passage::reprendre_format(&mut valeur, FORMAT);
    if valeur
        .get("format")
        .and_then(|f| f.as_str())
        .is_some_and(|f| f == FORMAT)
    {
        let s: Sauvegarde =
            serde_json::from_value(valeur).map_err(|e| trf!("sauvegarde abîmée ({e})", "damaged backup ({e})"))?;
        return Ok((s.base, s.surveillance));
    }
    if valeur.get("reseaux").is_some_and(serde_json::Value::is_object) {
        return Ok((valeur, None));
    }
    Err(tr!(
        "ce fichier n'est ni une sauvegarde Vanguard ni une base appareils.json",
        "this file is neither a Vanguard backup nor an appareils.json database"
    )
    .into())
}

fn decrire(c: &Contenu) -> String {
    trf!(
        "{} réseau(x), {} appareil(s), dont {} avec un surnom",
        "{} network(s), {} device(s), {} of them with a nickname",
        c.reseaux,
        c.appareils,
        c.surnoms
    )
}

pub fn sauvegarder(fichier: Option<PathBuf>) {
    let fichier = fichier.unwrap_or_else(chemin_par_defaut);
    let (base, contenu) = reseau::base_pour_sauvegarde();
    let sauvegarde = Sauvegarde {
        format: FORMAT.into(),
        version_vanguard: env!("CARGO_PKG_VERSION").into(),
        date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        surveillance: Some(surveillance::active()),
        base,
    };
    let json = serde_json::to_string_pretty(&sauvegarde).unwrap_or_default();
    match crate::socle::ecrire_atomique(&fichier, &json) {
        Ok(()) => trp!(
            "  {VERT}✔{RESET} Sauvegarde écrite : {}\n  {}.",
            "  {VERT}✔{RESET} Backup written: {}\n  {}.",
            fichier.display(),
            decrire(&contenu)
        ),
        Err(e) => trp!(
            "  ✖ Impossible d'écrire {} ({e}).",
            "  ✖ Could not write {} ({e}).",
            fichier.display()
        ),
    }
}

pub fn restaurer(fichier: &Path) {
    let texte = match std::fs::read_to_string(fichier) {
        Ok(t) => t,
        Err(e) => {
            trp!(
                "  ✖ Impossible de lire {} ({e}).",
                "  ✖ Could not read {} ({e}).",
                fichier.display()
            );
            return;
        }
    };
    let (base, surveillance_avant) = match lire_sauvegarde(&texte) {
        Ok(r) => r,
        Err(e) => {
            trp!("  ✖ Rien de restauré : {e}.", "  ✖ Nothing restored: {e}.");
            return;
        }
    };
    match reseau::restaurer_base(base) {
        Ok(c) => trp!(
            "  {VERT}✔{RESET} Ajouté à la base actuelle : {}.\n  {GRIS}Rien n'a été effacé : les fiches communes ont été fusionnées (le surnom le plus récent gagne).{RESET}",
            "  {VERT}✔{RESET} Added to the current database: {}.\n  {GRIS}Nothing was erased: shared entries were merged (the most recent nickname wins).{RESET}",
            decrire(&c)
        ),
        Err(e) => {
            trp!("  ✖ Rien de restauré : {e}.", "  ✖ Nothing restored: {e}.");
            return;
        }
    }
    if surveillance_avant == Some(true)
        && !surveillance::active()
        && demander(tr!(
            "  La surveillance horaire était activée : la réactiver ici ? [o/N] : ",
            "  Hourly monitoring was on: turn it on here too? [y/N]: "
        ))
        .oui()
    {
        surveillance::activer(true);
    }
}

pub fn menu() {
    titre(tr!("Données de Vanguard", "Vanguard data"));
    trp!(
        "  Base des appareils (surnoms, historique de chaque réseau) et état de la surveillance.",
        "  Device database (nicknames, history of each network) and monitoring state."
    );
    trp!(
        "  {GRIS}La quarantaine de l'antivirus n'est jamais sauvegardée.{RESET}\n",
        "  {GRIS}The antivirus quarantine is never backed up.{RESET}\n"
    );
    trp!("  1. Sauvegarder dans un fichier", "  1. Back up to a file");
    trp!(
        "  2. Restaurer depuis un fichier (ajouté à la base actuelle, rien n'est effacé)",
        "  2. Restore from a file (added to the current database, nothing is erased)"
    );
    match crate::selection::demander_ou_revenir(tr!(
        "\nChoix (Entrée pour revenir) : ",
        "\nChoice (Enter to go back): "
    ))
    .as_str()
    {
        "1" => {
            let defaut = chemin_par_defaut();
            let saisi = demander(&trf!(
                "  Fichier (Entrée pour {}) : ",
                "  File (Enter for {}): ",
                defaut.display()
            ));
            let fichier = chemin_saisi(&saisi).unwrap_or(defaut);
            if fichier.exists()
                && !demander(&trf!(
                    "  {} existe déjà : le remplacer ? [o/N] : ",
                    "  {} already exists: replace it? [y/N]: ",
                    fichier.display()
                ))
                .oui()
            {
                trp!("  Annulé.", "  Cancelled.");
                return;
            }
            sauvegarder(Some(fichier));
        }
        "2" => match chemin_saisi(&demander(tr!(
            "  Fichier à restaurer (vous pouvez le glisser dans la fenêtre) : ",
            "  File to restore (you can drag it into the window): "
        ))) {
            Some(f) => restaurer(&f),
            None => trp!("  Annulé.", "  Cancelled."),
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_acceptes() {
        let s = format!(
            "\u{feff}{{\"format\":\"{FORMAT}\",\"version_vanguard\":\"0.9.13\",\"date\":\"2026-10-17\",\"surveillance\":true,\"base\":{{\"reseaux\":{{}}}}}}"
        );
        let (base, surv) = lire_sauvegarde(&s).unwrap();
        assert_eq!((base["reseaux"].is_object(), surv), (true, Some(true)));
        // Une base appareils.json copiée telle quelle.
        let (base, surv) = lire_sauvegarde("{\"reseaux\":{\"box\":{\"nom\":null,\"appareils\":{}}}}").unwrap();
        assert_eq!((base["reseaux"]["box"].is_object(), surv), (true, None));
        assert!(lire_sauvegarde("{\"autre\":1}").is_err());
        assert!(lire_sauvegarde("pas du json").is_err());
        assert!(lire_sauvegarde(&format!("{{\"format\":\"{FORMAT}\"}}")).is_err());
    }

    #[test]
    fn chemins_saisis() {
        assert_eq!(chemin_saisi("  "), None);
        assert_eq!(
            chemin_saisi("\"C:\\Users\\moi\\sauvegarde.json\""),
            Some(PathBuf::from("C:\\Users\\moi\\sauvegarde.json"))
        );
        assert_eq!(chemin_saisi("'/tmp/a b.json' "), Some(PathBuf::from("/tmp/a b.json")));
    }
}
