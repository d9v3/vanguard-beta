//! L'interrupteur « Restrictions » des extensions. Actives par défaut (approbation par empreinte, analyse, bornes,
//! environnement minimal, jamais en administrateur, jamais dans le bilan ni la surveillance). Coupées, pour tout ou
//! pour un élément (`confiance = "totale"` dans un plugin.toml, ou l'élément marqué « à moi » au menu), l'extension
//! tourne comme un programme de la personne : sans accord, sans contrôle d'empreinte ni analyse, avec de très larges
//! bornes, tout l'environnement, en administrateur si Vanguard l'est, et dans le bilan ou la surveillance si son
//! manifeste le demande. Ses constats restent marqués et hors de la note.
//!
//! Une seule chose reste, même coupées : le dossier des extensions doit être à la personne et fermé aux autres comptes
//! (`dossier`), sinon un programme d'un autre compte pourrait y poser du code qui tournerait comme elle sans rien
//! demander. Ce contrôle échoue : rien ne tourne, et Vanguard dit pourquoi.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ui::{GRIS, RESET, chemin_affichable};
use crate::{tr, trf, trp};

const FICHIER: &str = "reglages.json";

/// Bornes très larges des extensions sans restrictions : elles ne servent qu'à ne jamais figer Vanguard pour de bon.
pub const DELAI_LIBRE: u64 = 6 * 3600;
pub const SORTIE_LIBRE: usize = 64 << 20;

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Reglages {
    /// Les restrictions coupées pour toutes les extensions.
    #[serde(default)]
    pub sans_restrictions: bool,
    /// La confirmation de la coupure a déjà été donnée une fois : on ne la redemande plus.
    #[serde(default)]
    pub coupure_confirmee: bool,
    /// Les éléments marqués « à moi » : restrictions coupées pour eux seuls, tels qu'ils étaient quand la personne
    /// l'a décidé (leur empreinte) ; changés, ils redeviennent restreints.
    #[serde(default)]
    pub plugins_a_moi: Vec<Confiance>,
    #[serde(default)]
    pub labo_a_moi: Vec<Confiance>,
}

/// La confiance accordée à un élément : son nom, l'empreinte de ce que la personne a vu (le dossier entier d'un
/// plugin, le script du labo), et s'il peut tourner tout seul avec le bilan ou la surveillance.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Confiance {
    pub nom: String,
    pub empreinte: String,
    #[serde(default)]
    pub bilan: bool,
    #[serde(default)]
    pub surveillance: bool,
}

/// Les réglages ; absent, ceux par défaut ; `Err` (la raison) si le fichier est là mais ne se lit plus.
pub fn lire(racine: &Path) -> Result<Reglages, String> {
    let chemin = racine.join(FICHIER);
    if std::fs::symlink_metadata(&chemin).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(Reglages::default());
    }
    serde_json::from_slice(&super::lire_sur(&chemin, 64 << 10)?).map_err(|e| e.to_string())
}

/// Les réglages ; un fichier illisible laisse les restrictions actives.
pub fn charger(racine: &Path) -> Reglages {
    lire(racine).unwrap_or_default()
}

/// Écrit les réglages. Un fichier qui ne se lit plus n'est jamais écrasé en silence (les confiances « à moi » y sont,
/// et `charger` en a rendu les défauts) : il est d'abord mis de côté, tel quel, et c'est dit ; s'il ne peut pas
/// l'être, rien n'est écrit.
pub fn enregistrer(racine: &Path, r: &Reglages) -> Result<(), String> {
    let chemin = racine.join(FICHIER);
    if lire(racine).is_err() {
        let copie = chemin.with_extension(format!(
            "illisible-{}.json",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        ));
        // Renommé, pas copié : un lien reste un lien, rien n'est suivi ni relu.
        std::fs::rename(&chemin, &copie).map_err(|e| {
            trf!(
                "Réglage non écrit : l'ancien fichier, illisible, n'a pas pu être mis de côté ({e}).",
                "Setting not written: the old, unreadable file could not be set aside ({e})."
            )
        })?;
        trp!(
            "  {GRIS}Ancien fichier des réglages, illisible, gardé : {}{RESET}",
            "  {GRIS}Old settings file, unreadable, kept: {}{RESET}",
            chemin_affichable(&copie)
        );
    }
    let texte = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
    crate::socle::ecrire_atomique(&chemin, texte)
        .map_err(|e| trf!("Réglage impossible à écrire : {e}", "Could not write the setting: {e}"))
}

impl Reglages {
    /// La confiance accordée à ce plugin, s'il est encore exactement ce qu'il était.
    pub fn plugin_a_moi(&self, nom: &str, empreinte: &str) -> Option<&Confiance> {
        self.plugins_a_moi
            .iter()
            .find(|k| k.nom == nom && k.empreinte == empreinte)
    }

    pub fn labo_a_moi(&self, fichier: &str, empreinte: &str) -> bool {
        self.labo_a_moi
            .iter()
            .any(|k| k.nom == fichier && k.empreinte == empreinte)
    }
}

/// Accorde la confiance à un élément tel qu'il est (`empreinte`), à la place d'une confiance d'avant.
pub fn accorder(
    racine: &Path,
    labo: bool,
    nom: &str,
    empreinte: &str,
    bilan: bool,
    surveillance: bool,
) -> Result<(), String> {
    let mut r = charger(racine);
    let liste = if labo { &mut r.labo_a_moi } else { &mut r.plugins_a_moi };
    liste.retain(|k| k.nom != nom);
    liste.push(Confiance {
        nom: nom.to_string(),
        empreinte: empreinte.to_string(),
        bilan,
        surveillance,
    });
    enregistrer(racine, &r)
}

/// Oublie la confiance d'un élément retiré ou remplacé.
pub fn oublier(racine: &Path, labo: bool, nom: &str) -> Result<(), String> {
    let mut r = charger(racine);
    let liste = if labo { &mut r.labo_a_moi } else { &mut r.plugins_a_moi };
    let avant = liste.len();
    liste.retain(|k| k.nom != nom);
    if liste.len() == avant {
        return Ok(());
    }
    enregistrer(racine, &r)
}

/// Ce que dit l'interrupteur, et la phrase qui explique ce qui reste.
pub fn ce_qui_reste() -> &'static str {
    tr!(
        "Même sans restrictions, le dossier des extensions doit être à vous et fermé aux autres comptes : sinon un programme d'un autre compte pourrait y poser du code qui tournerait comme vous, sans rien demander.",
        "Even without restrictions, the extensions folder must be yours and closed to other accounts: otherwise a program of another account could drop code there that would run as you, without asking anything."
    )
}

/// Bascule l'interrupteur général. Couper demande l'accord une seule fois (puis plus jamais) ; remettre est immédiat.
/// Rend le nouvel état (vrai : sans restrictions).
pub fn basculer(racine: &Path, accord: impl FnOnce(&str) -> bool) -> Result<bool, String> {
    let mut r = charger(racine);
    if r.sans_restrictions {
        r.sans_restrictions = false;
    } else {
        if !r.coupure_confirmee {
            if !accord(tr!(
                "  Les extensions tourneront sans contrôle, avec tous vos droits. Activer ? [o/N] : ",
                "  Extensions will run without any check, with all your rights. Turn on? [y/N]: "
            )) {
                return Ok(false);
            }
            r.coupure_confirmee = true;
        }
        r.sans_restrictions = true;
    }
    enregistrer(racine, &r)?;
    Ok(r.sans_restrictions)
}

/// Met l'interrupteur général à `sans` (vrai : coupées) par `basculer`, le seul chemin, avec son accord ; déjà ainsi,
/// rien ne change et rien n'est demandé. Rend (avant, après) ; refusé, après vaut avant.
pub fn regler(racine: &Path, sans: bool, accord: impl FnOnce(&str) -> bool) -> Result<(bool, bool), String> {
    let avant = charger(racine).sans_restrictions;
    if avant == sans {
        return Ok((avant, avant));
    }
    Ok((avant, basculer(racine, accord)?))
}

/// Bascule un élément « à moi » tel qu'il est maintenant (`empreinte`), même accord unique que l'interrupteur
/// général. Rend le nouvel état de l'élément.
pub fn basculer_element(
    racine: &Path,
    labo: bool,
    nom: &str,
    empreinte: &str,
    accord: impl FnOnce(&str) -> bool,
) -> Result<bool, String> {
    let r = charger(racine);
    let deja = if labo {
        r.labo_a_moi(nom, empreinte)
    } else {
        r.plugin_a_moi(nom, empreinte).is_some()
    };
    if deja {
        oublier(racine, labo, nom)?;
        return Ok(false);
    }
    if !r.coupure_confirmee {
        if !accord(tr!(
            "  Cet élément tournera sans contrôle, avec tous vos droits. Activer ? [o/N] : ",
            "  This item will run without any check, with all your rights. Turn on? [y/N]: "
        )) {
            return Ok(false);
        }
        let mut r = charger(racine);
        r.coupure_confirmee = true;
        enregistrer(racine, &r)?;
    }
    accorder(racine, labo, nom, empreinte, false, false)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn couper_demande_une_fois_remettre_jamais() {
        let d = std::env::temp_dir().join(format!("vanguard-reglages-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        super::super::creer_prive(&d).unwrap();
        // Refusé : rien ne change.
        assert!(!basculer(&d, |_| false).unwrap());
        assert_eq!(charger(&d), Reglages::default());
        assert!(basculer(&d, |_| true).unwrap());
        // Remettre : sans question ; recouper : plus de question non plus.
        assert!(!basculer(&d, |_| panic!("aucune question")).unwrap());
        assert!(basculer(&d, |_| panic!("aucune question")).unwrap());
        basculer(&d, |_| true).unwrap();
        assert!(basculer_element(&d, true, "essai.sh", "e1", |_| panic!("déjà confirmé")).unwrap());
        let r = charger(&d);
        assert!(r.labo_a_moi("essai.sh", "e1") && !r.labo_a_moi("autre.sh", "e1"));
        // Une autre empreinte (le script a changé) : plus à moi.
        assert!(!r.labo_a_moi("essai.sh", "e2"));
        assert!(!basculer_element(&d, true, "essai.sh", "e1", |_| true).unwrap());
        assert!(!charger(&d).labo_a_moi("essai.sh", "e1"));
        accorder(&d, false, "salon", "a1", true, false).unwrap();
        assert!(
            charger(&d)
                .plugin_a_moi("salon", "a1")
                .is_some_and(|k| k.bilan && !k.surveillance)
        );
        oublier(&d, false, "salon").unwrap();
        assert!(charger(&d).plugin_a_moi("salon", "a1").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un fichier qui ne se lit plus n'est jamais écrasé en silence : couper (menu Extensions, Paramètres,
    /// --sans-restrictions) le met de côté tel quel, avec les confiances « à moi » qu'il gardait. Tant qu'il est
    /// illisible, les restrictions restent actives, et couper redemande l'accord.
    #[test]
    fn fichier_illisible_mis_de_cote() {
        let d = std::env::temp_dir().join(format!("vanguard-reglages-illisible-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        super::super::creer_prive(&d).unwrap();
        assert_eq!(lire(&d), Ok(Reglages::default()), "absent : les défauts, sans erreur");
        let abime = r#"{"coupure_confirmee": true, "plugins_a_moi": [{"nom": "salon", "empreinte": "a1"}] pas du json"#;
        std::fs::write(d.join(FICHIER), abime).unwrap();
        assert!(lire(&d).is_err());
        assert_eq!(charger(&d), Reglages::default(), "illisible : restrictions actives");
        let mis_de_cote = || -> Vec<std::path::PathBuf> {
            std::fs::read_dir(&d)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("reglages.illisible-"))
                .map(|e| e.path())
                .collect()
        };
        // Refusé : rien n'est écrit, le fichier reste à sa place.
        assert!(!basculer(&d, |_| false).unwrap());
        assert_eq!(std::fs::read_to_string(d.join(FICHIER)).unwrap(), abime);
        assert_eq!(mis_de_cote(), Vec::<std::path::PathBuf>::new());
        // Accepté (l'accord redemandé) : l'ancien fichier est gardé à côté, intact, et le nouveau se lit.
        let mut demande = false;
        assert!(
            basculer(&d, |_| {
                demande = true;
                true
            })
            .unwrap()
        );
        assert!(demande, "l'accord d'un fichier illisible ne compte pas");
        assert!(lire(&d).is_ok_and(|r| r.sans_restrictions && r.coupure_confirmee));
        let gardes = mis_de_cote();
        assert_eq!(gardes.len(), 1, "{gardes:?}");
        assert_eq!(std::fs::read_to_string(&gardes[0]).unwrap(), abime);
        // Lisible à nouveau : les écritures suivantes ne mettent plus rien de côté.
        accorder(&d, false, "salon", "a1", false, false).unwrap();
        assert!(!basculer(&d, |_| panic!("remettre ne demande rien")).unwrap());
        assert_eq!(charger(&d).plugins_a_moi.len(), 1);
        assert_eq!(mis_de_cote(), gardes);
        let _ = std::fs::remove_dir_all(&d);
    }
}
