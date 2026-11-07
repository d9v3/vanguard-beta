//! Le fichier des formules de Homebrew (licence BSD-2-Clause), pris en entier par HTTPS sans vérifier sa signature
//! (décision de l'auteur) : `formula.json` (32 Mo, 5 Mo en gzip). Jamais l'adresse d'une formule en particulier, qui
//! dirait le logiciel cherché ; `formula.json` est pris par tous ou par personne, jamais selon que Homebrew est
//! installé. Lu en structures typées : seuls le nom et la version de chaque entrée, le reste (dépendances,
//! variations par système) ignoré sans être gardé.

use std::collections::HashMap;

use serde::Deserialize;

use super::{Choisis, Choix, Souple};

/// Au-dessous, ce n'est pas le fichier complet (8 667 formules le 23 oct. 2026).
const FORMULES_MIN: usize = 1000;
/// Les formules dont la version est gardée : celles qui suivent l'amont d'un logiciel suivi sous Windows (7-Zip,
/// PuTTY, mesurées égales à 7-zip.org et au site de PuTTY le 23 oct. 2026). Les autres sont lues pour être comptées,
/// puis oubliées.
pub(crate) const FORMULES_SUIVIES: &[&str] = &["sevenzip", "putty"];

#[derive(Deserialize)]
struct FormuleBrute {
    #[serde(default)]
    name: Option<Souple<String>>,
    #[serde(default)]
    versions: Option<Souple<VersionsBrutes>>,
    #[serde(default)]
    deprecated: Option<Souple<bool>>,
    #[serde(default)]
    disabled: Option<Souple<bool>>,
}

#[derive(Deserialize)]
struct VersionsBrutes {
    #[serde(default)]
    stable: Option<Souple<String>>,
}

super::forme_objet!(VersionsBrutes);

/// Les versions stables des formules suivies (`FORMULES_SUIVIES`), par nom, telles que Homebrew les écrit
/// (« 26.05 ») ; une formule absente, sans version stable, désactivée ou obsolète n'y est pas. `None` : pas le fichier attendu (moins de
/// 1 000 formules, JSON illisible).
pub(crate) fn formules(octets: &[u8]) -> Option<HashMap<String, String>> {
    formules_au_moins(octets, FORMULES_MIN)
}

/// Seules les formules suivies sont gardées ; les autres sont comptées puis oubliées dès qu'elles sont lues.
impl Choix for FormuleBrute {
    fn garder(&self) -> bool {
        matches!(&self.name, Some(Souple::Bon(n)) if FORMULES_SUIVIES.contains(&n.as_str()))
    }
}

fn formules_au_moins(octets: &[u8], minimum: usize) -> Option<HashMap<String, String>> {
    // En flux et plafonné (`Choisis`) : un fichier de millions d'entrées vides ne les fait plus toutes allouer.
    let Choisis(bruts, n) = serde_json::from_slice::<Choisis<FormuleBrute>>(octets).ok()?;
    if n < minimum {
        return None;
    }
    Some(
        bruts
            .into_iter()
            .filter_map(|f| {
                let nom = f.name.and_then(Souple::bon)?;
                if !FORMULES_SUIVIES.contains(&nom.as_str()) {
                    return None;
                }
                // Une formule désactivée ou obsolète n'est plus relevée : sa version peut être figée depuis des
                // mois. Elle est traitée comme absente, ce qui donne « non vérifié ».
                let oui = |b: Option<Souple<bool>>| b.and_then(Souple::bon).unwrap_or(false);
                if oui(f.disabled) || oui(f.deprecated) {
                    return None;
                }
                let stable = f.versions.and_then(Souple::bon)?.stable.and_then(Souple::bon)?;
                let stable = stable.trim();
                // Bornée : une version n'a pas 64 caractères.
                (!stable.is_empty() && stable.len() <= 64).then(|| (nom, stable.to_string()))
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Formules inventées, à la forme réelle de formula.json (vue le 23 oct. 2026) : seules les suivies sont gardées,
    /// une version d'un autre type ou absente est ignorée sans rendre le fichier illisible.
    #[test]
    fn formules_suivies() {
        let json = br#"[
            {"name": "sevenzip", "full_name": "sevenzip", "tap": "homebrew/core", "revision": 0,
             "versions": {"stable": "26.05", "head": "HEAD", "bottle": true}, "deprecated": false},
            {"name": "putty", "versions": {"stable": " 0.85 ", "head": null}},
            {"name": "p7zip", "versions": {"stable": "17.06"}},
            {"name": "git", "versions": {"stable": 3}},
            {"name": 7, "versions": {"stable": "1.0"}},
            {"versions": {"stable": "1.0"}}
        ]"#;
        assert_eq!(formules(json), None, "trop peu de formules pour le vrai fichier");
        let lues = formules_au_moins(json, 1).unwrap();
        assert_eq!(lues.len(), 2, "{lues:?}");
        assert_eq!((lues["sevenzip"].as_str(), lues["putty"].as_str()), ("26.05", "0.85"));
        // Une formule suivie sans version stable, ou d'une forme démesurée : absente, le reste lu.
        let sans = br#"[{"name": "sevenzip", "versions": {"head": "HEAD"}}, {"name": "putty", "versions": 3}]"#;
        assert!(formules_au_moins(sans, 1).unwrap().is_empty());
        let longue = format!(
            r#"[{{"name": "putty", "versions": {{"stable": "{}"}}}}]"#,
            "1".repeat(65)
        );
        assert!(formules_au_moins(longue.as_bytes(), 1).unwrap().is_empty());
        assert_eq!(formules_au_moins(b"{}", 1), None);
        assert_eq!(formules_au_moins(b"<html>Portail</html>", 1), None);
        // Un nom ou des versions d'une autre forme : cette formule ignorée, les autres lues.
        let autres = br#"[{"name": "putty", "versions": [0, 0, 0]}, {"name": [1], "versions": {"stable": "1.0"}},
            {"name": "sevenzip", "versions": {"stable": "26.05"}}]"#;
        let lues = formules_au_moins(autres, 1).unwrap();
        assert_eq!(lues.len(), 1, "{lues:?}");
        assert_eq!(lues["sevenzip"], "26.05");
    }

    /// Une formule désactivée ou obsolète n'est plus relevée par Homebrew : sa version peut rester figée. Elle est
    /// traitée comme absente (« non vérifié »), jamais comme la dernière version.
    #[test]
    fn formules_abandonnees() {
        let json = br#"[{"name": "putty", "versions": {"stable": "0.80"}, "disabled": true},
            {"name": "sevenzip", "versions": {"stable": "23.01"}, "deprecated": true}]"#;
        assert!(formules_au_moins(json, 1).unwrap().is_empty());
        let json = br#"[{"name": "putty", "versions": {"stable": "0.85"}, "disabled": null, "deprecated": false},
            {"name": "sevenzip", "versions": {"stable": "26.05"}, "disabled": "peut-etre"}]"#;
        assert_eq!(formules_au_moins(json, 1).unwrap().len(), 2);
    }

    /// Un champ démesuré d'une autre forme (ici un tableau de 500 000 zéros, 1 Mo de JSON) est lu en flux et
    /// oublié : il n'est pas copié en mémoire avant d'être reconnu (avec une copie, 16 Mo et plus).
    #[test]
    fn champ_demesure_lu_en_flux() {
        let zeros = vec!["0"; 500_000].join(",");
        for gros in [
            format!(r#"[{{"name": "putty", "versions": [{zeros}]}}]"#),
            format!(r#"[{{"name": [{zeros}], "versions": {{"stable": "1.0"}}}}]"#),
            format!(r#"[{{"name": "putty", "versions": {{"stable": [{zeros}]}}}}]"#),
            format!(r#"[{{"name": "putty", "versions": {{"stable": "0.85"}}, "disabled": [{zeros}]}}]"#),
        ] {
            let (lues, alloue) = super::super::tests::allocations(|| formules_au_moins(gros.as_bytes(), 1));
            assert!(lues.is_some());
            assert!(alloue < 4 << 20, "{alloue} octets alloués");
        }
    }

    /// Beaucoup de petites entrées (des `{}` par millions tiennent dans 100 Kio de gzip) : lues en flux, les formules
    /// non suivies ne sont pas gardées, et au-delà du plafond le fichier est refusé, jamais tronqué.
    #[test]
    fn beaucoup_de_petites_entrees() {
        let tableau = |n: usize| format!("[{}]", vec!["{}"; n].join(","));
        let sous = tableau(20_000);
        let (lues, alloue) = super::super::tests::allocations(|| formules_au_moins(sous.as_bytes(), 1));
        assert_eq!(lues, Some(HashMap::new()));
        assert!(alloue < 1 << 20, "{alloue} octets alloués");
        let trop = tableau(super::super::ENTREES_MAX + 1);
        let (lues, alloue) = super::super::tests::allocations(|| formules_au_moins(trop.as_bytes(), 1));
        assert_eq!(lues, None);
        assert!(alloue < 1 << 20, "{alloue} octets alloués");
    }

    /// Sur la vraie copie gardée par un essai à la main, si `VANGUARD_ESSAI_PERIMES` donne son dossier
    /// (`formula.json`, décompressé) : les deux formules suivies y sont, à deux champs.
    #[test]
    fn vraie_copie_si_presente() {
        let Some(dossier) = std::env::var_os("VANGUARD_ESSAI_PERIMES").map(std::path::PathBuf::from) else {
            return crate::essais::saute("VANGUARD_ESSAI_PERIMES non donné");
        };
        let Ok(octets) = std::fs::read(dossier.join("formula.json")) else {
            return crate::essais::saute("pas de formula.json dans VANGUARD_ESSAI_PERIMES");
        };
        let lues = formules(&octets).unwrap();
        for nom in FORMULES_SUIVIES {
            let v = crate::protection::perimes::version::Version::lire(&lues[*nom]).unwrap();
            assert_eq!(v.longueur(), 2, "{nom} {v}");
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 500, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..300)) {
            let _ = formules_au_moins(&octets, 0);
        }
    }
}
