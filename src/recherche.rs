//! La recherche de Vanguard : un score par ligne, des synonymes et les fautes de frappe corrigées. Sans entrée ni
//! sortie : le menu (`selection`), `vanguard chercher` et leurs tests lui donnent les lignes, simplifiées
//! (`selection::simplifier` : minuscules, sans accents).
//!
//! Score d'une ligne, mot tapé par mot tapé (le meilleur de ses formes) : mot exact du titre 100, début d'un mot du
//! titre 80, ailleurs dans le titre 60, dans le chemin, la précision ou les mots cachés 40 ; ×0,8 pour un synonyme,
//! ×0,6 pour un mot corrigé. Tous les mots tapés doivent se trouver ; sinon la ligne n'est que « partielle ».

use crate::selection::simplifier;

/// Des mots qui disent la même chose, en français et en anglais. Vocabulaire seulement : « box » se cherche encore
/// alors que plus rien ne l'affiche. Un mot n'est que dans un groupe (test).
pub const SYNONYMES: &[&[&str]] = &[
    &["wifi", "sans fil", "wireless"],
    &["mot de passe", "mots de passe", "mdp", "password", "passwords"],
    &["lent", "lenteur", "rame", "slow", "lag"],
    &["imprimante", "impression", "printer", "cups"],
    &["rancongiciel", "ransomware"],
    &["vpn", "wireguard", "tunnel"],
    &["virus", "malware", "logiciel malveillant", "cheval de troie", "trojan"],
    &["espion", "espions", "spyware", "stalkerware", "keylogger"],
    &["routeur", "router", "box", "modem"],
    &["son", "audio", "sound"],
    &["mise a jour", "mises a jour", "maj", "update", "updates"],
];

/// Un mot (ou une expression) de la requête et ses formes cherchées, avec leur poids.
#[derive(Debug, Clone, PartialEq)]
pub struct Terme {
    pub tape: String,
    /// Chaque forme et son poids, en pour cent : 100 pour le mot tapé, 80 pour un synonyme, 60 après une faute.
    pub formes: Vec<(String, u32)>,
}

/// La requête découpée en termes : une expression des synonymes (« mot de passe ») reste d'un seul tenant, et chaque
/// terme reçoit ses synonymes.
pub fn termes(requete: &str) -> Vec<Terme> {
    let mots: Vec<String> = simplifier(requete)
        .split(|c: char| !c.is_alphanumeric())
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .collect();
    let mut termes = Vec::new();
    let mut i = 0;
    while i < mots.len() {
        // L'expression la plus longue d'un groupe qui commence ici.
        let mut pris = 1;
        let mut groupe: Option<&[&str]> = None;
        for g in SYNONYMES {
            for forme in *g {
                let n = forme.split([' ', '-']).count();
                if n >= pris && i + n <= mots.len() && mots[i..i + n].join(" ") == forme.replace('-', " ") {
                    pris = n;
                    groupe = Some(g);
                }
            }
        }
        let tape = mots[i..i + pris].join(" ");
        let mut formes = vec![(tape.clone(), 100)];
        if let Some(g) = groupe {
            for forme in g {
                let f = forme.replace('-', " ");
                if f != tape {
                    formes.push((f, 80));
                }
            }
        }
        termes.push(Terme { tape, formes });
        i += pris;
    }
    termes
}

/// Le score d'une forme dans une ligne : `nom` (le titre seul) et `tout` (chemin, titre, précision, mots cachés),
/// tous deux simplifiés.
fn score_forme(forme: &str, nom: &str, tout: &str) -> u32 {
    let entier = score_exact(forme, nom, tout);
    if entier > 0 || forme.contains(' ') {
        return entier;
    }
    // La racine, comme `selection::correspond` avant ce score : au moins quatre lettres gardées (cinq quand on en
    // retire deux), pour que « vider » trouve « vide » et « disques » « disque », sans que « réseau » trouve « reset ».
    let n = forme.chars().count();
    let racine = |retire: usize| forme.chars().take(n - retire).collect::<String>();
    [(5, 1), (7, 2)]
        .into_iter()
        .filter(|(minimum, _)| n >= *minimum)
        .map(|(_, retire)| score_exact(&racine(retire), nom, tout) * 90 / 100)
        .max()
        .unwrap_or(0)
}

/// Le score d'une forme telle quelle (voir `score_forme`).
fn score_exact(forme: &str, nom: &str, tout: &str) -> u32 {
    let mots_du_nom: Vec<&str> = nom
        .split(|c: char| !c.is_alphanumeric())
        .filter(|m| !m.is_empty())
        .collect();
    let une_expression = forme.contains(' ');
    if !une_expression && mots_du_nom.contains(&forme) || une_expression && contient_mots(nom, forme) {
        100
    } else if !une_expression && mots_du_nom.iter().any(|m| m.starts_with(forme)) {
        80
    } else if forme.chars().count() >= 4 && nom.contains(forme) {
        // Au milieu d'un mot, à partir de quatre lettres : « box » ne trouve ni « xbox » ni « toolbox ».
        60
    } else if contient_mots(tout, forme) || forme.chars().count() >= 4 && tout.contains(forme) {
        40
    } else if !une_expression && forme.chars().count() >= 3 && debut_d_un_mot(tout, forme) {
        30
    } else {
        0
    }
}

/// `texte` contient-il `expression` mot pour mot (« mot de passe » dans « mots de passe » non, dans « le mot de
/// passe » oui) ?
fn contient_mots(texte: &str, expression: &str) -> bool {
    let voulus: Vec<&str> = expression.split(' ').collect();
    let mots: Vec<&str> = texte
        .split(|c: char| !c.is_alphanumeric())
        .filter(|m| !m.is_empty())
        .collect();
    mots.windows(voulus.len()).any(|w| w == voulus.as_slice())
}

/// Un mot de `texte` commence-t-il par `debut` ? (« ip » ne trouve pas « description »)
fn debut_d_un_mot(texte: &str, debut: &str) -> bool {
    texte
        .split(|c: char| !c.is_alphanumeric())
        .any(|m| m.starts_with(debut))
}

/// Le score d'une ligne pour ces termes : (score, tous les termes trouvés ?). `None` : aucun terme trouvé.
pub fn score(termes: &[Terme], nom: &str, tout: &str) -> Option<(u32, bool)> {
    let mut total = 0;
    let mut complet = true;
    for t in termes {
        let meilleur = t
            .formes
            .iter()
            .map(|(f, poids)| score_forme(f, nom, tout) * poids / 100)
            .max()
            .unwrap_or(0);
        if meilleur == 0 {
            complet = false;
        }
        total += meilleur;
    }
    (total > 0).then_some((total, complet))
}

/// Distance de Damerau-Levenshtein (une transposition compte pour une faute), arrêtée au-delà de `borne`.
pub fn distance_bornee(a: &str, b: &str, borne: usize) -> Option<usize> {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > borne {
        return None;
    }
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, ligne) in d.iter_mut().enumerate() {
        ligne[0] = i;
    }
    for (j, case) in d[0].iter_mut().enumerate() {
        *case = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cout = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cout);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    let n = d[a.len()][b.len()];
    (n <= borne).then_some(n)
}

/// Les fautes tolérées pour un mot : aucune sous 5 lettres, 1 de 5 à 7, 2 à partir de 8.
fn fautes_permises(mot: &str) -> usize {
    match mot.chars().count() {
        0..=4 => 0,
        5..=7 => 1,
        _ => 2,
    }
}

/// Le mot le plus proche de `mot` dans `vocabulaire` (simplifié), dans les fautes permises ; à égalité, le premier.
pub fn corriger<'a>(mot: &str, vocabulaire: &'a [String]) -> Option<&'a str> {
    let borne = fautes_permises(mot);
    if borne == 0 {
        return None;
    }
    vocabulaire
        .iter()
        .filter(|v| v.as_str() != mot)
        .filter_map(|v| distance_bornee(mot, v, borne).map(|d| (d, v.as_str())))
        // À égalité, une lettre oubliée (« internt » → « internet ») plutôt qu'une lettre changée (« interne »).
        .min_by_key(|(d, v)| (*d, !sous_suite(mot, v)))
        .map(|(_, v)| v)
}

/// Les lettres de `mot` se trouvent-elles dans `v`, dans l'ordre ?
fn sous_suite(mot: &str, v: &str) -> bool {
    let mut lettres = v.chars();
    mot.chars().all(|c| lettres.any(|l| l == c))
}

/// Les termes d'une requête, avec une faute corrigée pour chaque mot simple que rien ne trouve dans `toutes` les
/// lignes (`trouve` dit si une forme trouve quelque chose) : (termes, corrections faites « tapé → corrigé »).
pub fn termes_corriges(
    requete: &str,
    vocabulaire: &[String],
    trouve: impl Fn(&str) -> bool,
) -> (Vec<Terme>, Vec<(String, String)>) {
    let mut corrections = Vec::new();
    let termes = termes(requete)
        .into_iter()
        .map(|mut t| {
            if t.formes.iter().any(|(f, _)| trouve(f)) || t.tape.contains(' ') {
                return t;
            }
            if let Some(bon) = corriger(&t.tape, vocabulaire) {
                corrections.push((t.tape.clone(), bon.to_string()));
                // Le mot corrigé, et ses synonymes s'il en a, à 0,6.
                let corrige = termes(bon);
                t.formes = corrige
                    .into_iter()
                    .flat_map(|c| c.formes)
                    .map(|(f, p)| (f, p * 60 / 100))
                    .collect();
            }
            t
        })
        .collect();
    (termes, corrections)
}

/// Le vocabulaire des lignes (leurs mots simplifiés d'au moins 4 lettres, sans doublon) : les mots vers lesquels
/// une faute se corrige.
pub fn vocabulaire<'a>(textes: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut mots: Vec<String> = textes
        .into_iter()
        .flat_map(|t| t.split(|c: char| !c.is_alphanumeric()))
        .filter(|m| m.chars().count() >= 4)
        .map(str::to_string)
        .collect();
    mots.sort();
    mots.dedup();
    mots
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(requete: &str, nom: &str, tout: &str) -> Option<(u32, bool)> {
        score(&termes(requete), &simplifier(nom), &simplifier(tout))
    }

    #[test]
    fn le_titre_passe_devant_les_mots_caches() {
        let titre = note("lien", "Ce lien est-il dangereux ?", "").unwrap().0;
        let cache = note("lien", "Analyse antivirus", "url lien").unwrap().0;
        assert!(titre > cache, "{titre} {cache}");
        assert_eq!(
            note("ip", "Nommer un appareil", "description"),
            None,
            "« ip » ne trouve pas « description »"
        );
        assert_eq!(
            note("box", "Manettes xbox", ""),
            None,
            "pas au milieu d'un mot sous 4 lettres"
        );
        assert_eq!(note("lag", "Réglages", ""), None);
        // La racine : « vider » trouve « Vide le cache », « disques » « Vérifier un disque ».
        assert!(note("vider", "Vide le cache", "").is_some());
        assert!(note("disques", "Vérifier une clé USB ou un disque", "").is_some());
    }

    #[test]
    fn synonymes_et_expressions() {
        assert!(note("box", "Routeur et objets connectés", "").is_some_and(|(_, tous)| tous));
        assert!(note("password", "Mots de passe des navigateurs", "").is_some());
        assert!(note("mot de passe", "Mots de passe : ont-ils fuité ?", "").is_some());
        assert_eq!(termes("mot de passe fuite").len(), 2);
        // Accents et tirets indifférents.
        assert!(note("rancongiciel", "Fichiers-pièges anti-rançongiciel", "").is_some());
        assert!(note("Wi-Fi", "Mode Wi-Fi public", "").is_some_and(|(n, _)| n == 100));
    }

    #[test]
    fn tous_les_mots_ou_partiel() {
        assert_eq!(note("wifi public", "Mode Wi-Fi public", "").map(|n| n.1), Some(true));
        assert_eq!(
            note("wifi imprimante", "Mode Wi-Fi public", "").map(|n| n.1),
            Some(false)
        );
    }

    #[test]
    fn fautes_de_frappe() {
        let vocabulaire = vocabulaire(["imprimante ne fonctionne pas", "disque plein"]);
        assert_eq!(corriger("imprimnte", &vocabulaire), Some("imprimante"));
        assert_eq!(corriger("dsique", &vocabulaire), Some("disque"));
        assert_eq!(corriger("son", &vocabulaire), None, "rien sous 5 lettres");
        assert_eq!(distance_bornee("abcdef", "badcfe", 2), None);
        assert_eq!(distance_bornee("ab", "ba", 1), Some(1));
        let proches = super::vocabulaire(["interne", "internet"]);
        assert_eq!(corriger("internt", &proches), Some("internet"));
        let (t, corrections) = termes_corriges("imprimnte", &vocabulaire, |f| f == "imprimante");
        assert_eq!(corrections, [("imprimnte".to_string(), "imprimante".to_string())]);
        assert!(t[0].formes.iter().any(|(f, p)| f == "imprimante" && *p == 60));
    }

    /// Aucun mot dans deux groupes, et chaque forme est déjà simplifiée (sinon elle ne trouverait rien).
    #[test]
    fn synonymes_sans_doublon_ni_forme_morte() {
        let mut vus = std::collections::HashSet::new();
        for g in SYNONYMES {
            for f in *g {
                assert!(vus.insert(*f), "« {f} » dans deux groupes");
                assert_eq!(simplifier(f), *f, "« {f} » doit être écrit simplifié");
            }
        }
    }
}
