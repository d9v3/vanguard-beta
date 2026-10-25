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

pub(super) const FICHIER: &str = "reglages.json";

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

/// Le nom scellé du fichier sous le dossier de Vanguard (`modele::inventaire`, `sceau`).
pub(crate) const SCELLE: &str = "plugins/reglages.json";

/// Les réglages ; absent, ceux par défaut ; `Err` (la raison) si le fichier est là mais ne se lit plus. Changé hors
/// de Vanguard ou accepté tel quel par les sceaux : les défauts aussi (`lire_juge`).
pub fn lire(racine: &Path) -> Result<Reglages, String> {
    lire_juge(racine).map(|(r, _)| r).map_err(String::from)
}

/// Les réglages relus sous leur sceau, et pourquoi ceux du fichier ont été ignorés quand ils levaient quelque chose.
/// Un programme du compte qui écrivait `{"sans_restrictions":true}`, ou une confiance « à moi » avec le bilan et la
/// surveillance pour son propre plugin, faisait tourner son code sans accord, chaque heure, sous le nom de Vanguard.
/// Changé hors de Vanguard, ou accepté tel quel (après des sceaux refaits, ou repris d'une version d'avant le sceau :
/// rien ne prouve que la personne l'a décidé), le fichier ne vaut que les défauts, les plus protecteurs : restrictions
/// actives, aucune confiance, l'accord de la coupure redemandé. Comme `parametres::charger_juge`, du côté qui ne coupe
/// rien, et dit (`douteux`, et au bilan par le sceau).
pub(crate) fn lire_juge(racine: &Path) -> Result<(Reglages, Option<super::Douteux>), crate::modele::Echec> {
    let Some((octets, douteux)) = super::lire_scelle(racine, FICHIER, 64 << 10)? else {
        return Ok((Reglages::default(), None));
    };
    let r: Reglages = serde_json::from_slice(&octets)
        .map_err(|e| crate::modele::Echec::new("plugins/reglages", crate::modele::Raison::Illisible(e.to_string())))?;
    let Some(d) = douteux else {
        return Ok((r, None));
    };
    Ok((Reglages::default(), r.accorde().then_some(d)))
}

/// Pourquoi les réglages du fichier sont ignorés, s'ils levaient quelque chose.
pub(crate) fn douteux(racine: &Path) -> Option<super::Douteux> {
    lire_juge(racine).ok().and_then(|(_, d)| d)
}

/// Les réglages ; un fichier illisible laisse les restrictions actives.
pub fn charger(racine: &Path) -> Reglages {
    lire(racine).unwrap_or_default()
}

/// Écrit les réglages, scellés. Un fichier qui ne se lit plus, ou ignoré (changé hors de Vanguard, accepté tel quel),
/// n'est jamais écrasé en silence (des confiances « à moi » y sont peut-être, et `charger` en a rendu les défauts) :
/// il est d'abord mis de côté, tel quel, et c'est dit ; s'il ne peut pas l'être, rien n'est écrit.
pub fn enregistrer(racine: &Path, r: &Reglages) -> Result<(), String> {
    let chemin = racine.join(FICHIER);
    if lire_juge(racine).is_err() || douteux(racine).is_some() {
        let copie = chemin.with_extension(format!(
            "illisible-{}.json",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        ));
        // Renommé, pas copié : un lien reste un lien, rien n'est suivi ni relu.
        std::fs::rename(&chemin, &copie).map_err(|e| {
            trf!(
                "Réglage non écrit : l'ancien fichier, illisible ou ignoré, n'a pas pu être mis de côté ({e}).",
                "Setting not written: the old, unreadable or ignored file could not be set aside ({e})."
            )
        })?;
        trp!(
            "  {GRIS}Ancien fichier des réglages, illisible ou ignoré, gardé : {}{RESET}",
            "  {GRIS}Old settings file, unreadable or ignored, kept: {}{RESET}",
            chemin_affichable(&copie)
        );
    }
    let texte = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
    super::ecrire_scelle(racine, FICHIER, texte.as_bytes())
        .map_err(|e| trf!("Réglage impossible à écrire : {e}", "Could not write the setting: {e}"))
}

/// reglages.json et approuves.json d'une version d'avant le sceau, acceptés tels quels à la mise à jour : réécrits,
/// scellés, s'ils n'accordent rien ; sinon ils restent ignorés, et le bilan dit quoi refaire. Réécrit à ses défauts,
/// pas tel quel : la confirmation de la coupure qu'il porte peut-être (la personne a coupé puis remis les
/// restrictions) n'est pas prouvée, elle sera redemandée. Jamais après l'effacement des sceaux.
pub(crate) fn resceller_d_avant() {
    resceller_dans(&crate::socle::dossier_local());
}

/// `resceller_d_avant` dans `dossier` (celui des sceaux, parent du dossier des extensions).
pub(crate) fn resceller_dans(dossier: &Path) {
    if !crate::sceau::refaits_dans(dossier)
        && let crate::sceau::Lecture::Adopte(o) = crate::sceau::lire_dans(dossier, SCELLE)
        && serde_json::from_slice::<Reglages>(&o).is_ok_and(|r| !r.accorde())
        && let Ok(texte) = serde_json::to_string_pretty(&Reglages::default())
    {
        let _ = crate::sceau::ecrire_dans(dossier, SCELLE, texte.as_bytes());
    }
    super::resceller_dans(dossier);
}

impl Reglages {
    /// Ces réglages accordent-ils quelque chose (les restrictions coupées, un élément « à moi ») ? La confirmation de
    /// la coupure seule n'accorde rien : elle évite seulement une question.
    pub(crate) fn accorde(&self) -> bool {
        self.sans_restrictions || !self.plugins_a_moi.is_empty() || !self.labo_a_moi.is_empty()
    }

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

    /// Un dossier des extensions jetable : « plugins » sous un dossier à lui, qui garde les sceaux comme celui de
    /// Vanguard.
    fn jetable(nom: &str) -> std::path::PathBuf {
        let parent = std::env::temp_dir().join(format!("vanguard-reglages-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        let d = parent.join("plugins");
        super::super::creer_prive(&d).unwrap();
        d
    }

    #[test]
    fn couper_demande_une_fois_remettre_jamais() {
        let d = jetable("bascule");
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
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
    }

    /// Un fichier qui ne se lit plus n'est jamais écrasé en silence : couper (menu Extensions, Paramètres,
    /// --sans-restrictions) le met de côté tel quel, avec les confiances « à moi » qu'il gardait. Tant qu'il est
    /// illisible, les restrictions restent actives, et couper redemande l'accord.
    #[test]
    fn fichier_illisible_mis_de_cote() {
        let d = jetable("illisible");
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
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
    }
}
