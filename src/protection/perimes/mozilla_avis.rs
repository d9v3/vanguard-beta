//! Les avis de sécurité de Mozilla (licence MPL-2.0, lus sans être redistribués) : pour chaque CVE, les versions de
//! Firefox et de Firefox ESR qui la corrigent. C'est ce qui permet un verdict exact pour Firefox : une faille
//! exploitée (catalogue de la CISA) corrigée dans une version plus récente que la tienne. On ne connaît pas la
//! version où la faille est apparue : le verdict dit « ta version est antérieure au correctif », jamais « touchée ».
//!
//! Deux formats, lus sans bibliothèque YAML : les `.yml` (depuis 2017) et l'en-tête des `.md` (avant). Seuls
//! comptent `fixed_in` (une liste, par avis et non par CVE) et les CVE : clés de `advisories` dans un `.yml`, cherchées
//! dans le texte d'un `.md`. Une même CVE est souvent dans plusieurs avis (Firefox, Thunderbird) : les correctifs se
//! réunissent. Seuls « Firefox N » et « Firefox ESR N » comptent ; « Firefox OS », « Firefox for iOS », Thunderbird,
//! jamais.
//!
//! Lecteur pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin. Borné : 1 Mio et 20 000 lignes par
//! fichier, 4 Kio par ligne, 1 000 CVE par avis, 10 000 avis, 100 000 CVE en tout, 64 branches ESR par CVE.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::HashMap;

use super::version::Version;

/// Taille d'un avis lu au plus ; les vrais font moins de 100 Kio.
pub(crate) const AVIS_MAX: usize = 1 << 20;
const LIGNES_MAX: usize = 20_000;
/// Une ligne plus longue (une description) n'a rien de ce qu'on cherche : sautée.
const LIGNE_MAX: usize = 4096;
const CVE_PAR_AVIS: usize = 1000;
/// Avis réunis au plus ; il y en a 1 622 le 23 oct. 2026.
pub(crate) const AVIS_TOUS: usize = 10_000;

/// Ce qu'un avis dit : les versions qui corrigent, et ses CVE.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Avis {
    pub firefox: Vec<Version>,
    pub esr: Vec<Version>,
    pub cves: Vec<String>,
}

/// Branches ESR gardées au plus pour une CVE ; une vraie en a deux ou trois.
const ESR_PAR_CVE: usize = 64;
/// CVE distinctes gardées au plus ; il y en a quelques milliers le 23 oct. 2026.
const CVES_TOUTES: usize = 100_000;

/// Les versions qui corrigent une CVE, réunies sur tous ses avis. Seul ce que `juger` regarde est gardé : le plus
/// petit correctif de Firefox, et le plus petit de chaque branche ESR. Garder toutes les versions rendait la fusion
/// quadratique : une archive hostile (10 000 avis, la même CVE, 64 versions chacun) bloquait le bilan des heures.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Correctifs {
    /// Zéro ou une version.
    pub firefox: Vec<Version>,
    /// Une version par majeur ESR, `ESR_PAR_CVE` au plus.
    pub esr: Vec<Version>,
}

/// L'index : CVE (en majuscules) → correctifs, et le nombre d'avis lus.
#[derive(Debug, Default)]
pub(crate) struct Index {
    pub cves: HashMap<String, Correctifs>,
    pub avis: usize,
}

/// Un élément de `fixed_in` : « Firefox 131.0.2 », « Firefox ESR 115.16.1 » ; le reste (Thunderbird, Firefox OS,
/// Firefox for iOS, SeaMonkey) ne dit rien de Firefox pour ordinateur. `Some((esr, version))`.
fn produit_corrige(element: &str) -> Option<(bool, Version)> {
    let element = element.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    if let Some(reste) = element.strip_prefix("Firefox ESR ") {
        return Some((true, Version::lire(reste)?));
    }
    Some((false, Version::lire(element.strip_prefix("Firefox ")?)?))
}

/// Une CVE de la forme `CVE-AAAA-NNNN…` (4 à 7 chiffres) au début de `octets` : sa longueur.
fn longueur_cve(octets: &[u8]) -> Option<usize> {
    let reste = octets.strip_prefix(b"CVE-")?;
    let (annee, suite) = reste.split_first_chunk::<5>()?;
    let [chiffres @ .., b'-'] = annee else {
        return None;
    };
    if !chiffres.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = suite.iter().take(8).take_while(|o| o.is_ascii_digit()).count();
    (4..=7).contains(&n).then_some(n)?.checked_add(4 + 5)
}

/// Les CVE écrites dans un texte (le corps d'un ancien avis `.md`), par un simple parcours d'octets : un nombre qui
/// suit sans séparateur (« CVE-2016-12345678 ») n'en est pas une.
fn cves_du_texte(texte: &str, cves: &mut Vec<String>) {
    let octets = texte.as_bytes();
    let mut i = 0;
    while let Some(pos) = octets.get(i..).and_then(|r| r.windows(4).position(|w| w == b"CVE-")) {
        let Some(debut) = i.checked_add(pos) else {
            return;
        };
        let precede = debut
            .checked_sub(1)
            .and_then(|k| octets.get(k))
            .is_some_and(u8::is_ascii_alphanumeric);
        if !precede
            && let Some(fin) = octets
                .get(debut..)
                .and_then(longueur_cve)
                .and_then(|n| debut.checked_add(n))
            && !octets.get(fin).is_some_and(u8::is_ascii_digit)
        {
            ajouter_cve(cves, &texte[debut..fin]);
            i = fin;
        } else {
            let Some(suite) = debut.checked_add(4) else {
                return;
            };
            i = suite;
        }
        if cves.len() >= CVE_PAR_AVIS {
            return;
        }
    }
}

fn ajouter_cve(cves: &mut Vec<String>, cve: &str) {
    if cves.len() < CVE_PAR_AVIS && !cves.iter().any(|c| c == cve) {
        cves.push(cve.to_string());
    }
}

/// Les lignes d'un en-tête YAML qui comptent : clés de premier niveau ; éléments `- …` de `fixed_in`, à n'importe
/// quel retrait ; dans `advisories`, les clés à deux espaces de la forme `CVE-…:`. Tout le reste est ignoré.
fn lire_entete(lignes: &[&str], avis: &mut Avis) {
    let mut cle = "";
    for ligne in lignes {
        if ligne.len() > LIGNE_MAX {
            continue;
        }
        let ligne = ligne.trim_end_matches('\r');
        if ligne.trim().is_empty() || ligne.trim_start().starts_with('#') {
            continue;
        }
        if !ligne.starts_with(' ') && !ligne.starts_with('-') {
            cle = ligne.split_once(':').map_or("", |(c, _)| c.trim());
            continue;
        }
        match cle {
            "fixed_in" => {
                if let Some(element) = ligne.trim_start().strip_prefix('-')
                    && let Some((esr, v)) = produit_corrige(element)
                {
                    let liste = if esr { &mut avis.esr } else { &mut avis.firefox };
                    if liste.len() < 64 && !liste.contains(&v) {
                        liste.push(v);
                    }
                }
            }
            "advisories" => {
                if let Some(reste) = ligne.strip_prefix("  ")
                    && !reste.starts_with(' ')
                    && let Some(cve) = reste.trim_end().strip_suffix(':')
                    && longueur_cve(cve.as_bytes()) == Some(cve.len())
                {
                    ajouter_cve(&mut avis.cves, cve);
                }
            }
            _ => {}
        }
    }
}

/// Le format d'un avis, d'après l'extension de son fichier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    /// Depuis 2017 : tout est en YAML.
    Yml,
    /// Avant : un en-tête YAML entre deux « --- », puis le texte.
    Md,
}

pub(crate) fn format(nom: &str) -> Option<Format> {
    let extension = std::path::Path::new(nom).extension()?;
    if extension.eq_ignore_ascii_case("yml") {
        Some(Format::Yml)
    } else if extension.eq_ignore_ascii_case("md") {
        Some(Format::Md)
    } else {
        None
    }
}

/// Un avis, d'après le nom de son fichier (`.yml` ou `.md`) et son contenu. `None` : trop gros, pas en UTF-8, autre
/// extension, ou sans CVE ni correctif de Firefox (rien à en tirer).
pub(crate) fn avis(nom: &str, octets: &[u8]) -> Option<Avis> {
    if octets.len() > AVIS_MAX {
        return None;
    }
    let texte = std::str::from_utf8(octets).ok()?;
    let lignes: Vec<&str> = texte.split('\n').take(LIGNES_MAX + 1).collect();
    if lignes.len() > LIGNES_MAX {
        return None;
    }
    let mut a = Avis::default();
    match format(nom)? {
        Format::Yml => lire_entete(&lignes, &mut a),
        Format::Md => {
            // L'en-tête entre deux lignes « --- », puis le corps où les CVE sont citées.
            if lignes.first().map(|l| l.trim_end()) != Some("---") {
                return None;
            }
            let fin = lignes
                .iter()
                .skip(1)
                .position(|l| l.trim_end() == "---")?
                .checked_add(1)?;
            lire_entete(lignes.get(1..fin)?, &mut a);
            cves_du_texte(texte, &mut a.cves);
        }
    }
    let utile = !a.cves.is_empty() && (!a.firefox.is_empty() || !a.esr.is_empty());
    utile.then_some(a)
}

impl Index {
    /// Réunit un avis : chaque CVE gagne ses correctifs.
    pub(crate) fn ajouter(&mut self, avis: &Avis) {
        if self.avis >= AVIS_TOUS {
            return;
        }
        self.avis = self.avis.saturating_add(1);
        for cve in &avis.cves {
            let cle = cve.to_ascii_uppercase();
            if self.cves.len() >= CVES_TOUTES && !self.cves.contains_key(&cle) {
                // Au-delà, la CVE reste absente : `juger` dit « on ne sait pas », jamais « corrigée ».
                continue;
            }
            let c = self.cves.entry(cle).or_default();
            for &v in &avis.firefox {
                match c.firefox.first_mut() {
                    Some(z) => *z = (*z).min(v),
                    None => c.firefox.push(v),
                }
            }
            for &v in &avis.esr {
                if let Some(z) = c.esr.iter_mut().find(|z| z.majeur() == v.majeur()) {
                    *z = (*z).min(v);
                } else if c.esr.len() < ESR_PAR_CVE {
                    c.esr.push(v);
                }
            }
        }
    }
}

/// La branche de Firefox installée, pour juger une CVE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrancheFx {
    Release,
    /// ESR de ce majeur.
    Esr(u32),
    /// Pas sue (ni `channel-prefs.js`, ni la liste des ESR de Mozilla) : antérieure seulement si elle l'est pour
    /// les deux.
    Inconnue,
}

/// Ce qu'on peut dire d'une version installée pour une CVE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Jugement {
    /// Antérieure au correctif, qui est dans cette version.
    Anterieure(Version),
    /// Corrigée chez toi (ou corrigée avant la naissance de ta branche ESR).
    Corrigee,
    /// Les avis ne permettent pas de conclure (CVE absente, corrigée seulement sur l'autre branche).
    Inconnu,
}

fn jugement_release(c: &Correctifs, v: Version) -> Jugement {
    match c.firefox.iter().min() {
        Some(&z) if v < z => Jugement::Anterieure(z),
        Some(_) => Jugement::Corrigee,
        None => Jugement::Inconnu,
    }
}

fn jugement_esr(c: &Correctifs, v: Version, majeur: u32) -> Jugement {
    if let Some(&z) = c.esr.iter().filter(|z| z.majeur() == majeur).min() {
        return if v < z {
            Jugement::Anterieure(z)
        } else {
            Jugement::Corrigee
        };
    }
    // Corrigée dans un Firefox dont le majeur ne dépasse pas celui de la branche : la branche est née corrigée.
    if c.firefox.iter().any(|z| z.majeur() <= majeur) {
        return Jugement::Corrigee;
    }
    Jugement::Inconnu
}

/// La version `v` de la branche `branche` face à la CVE `cve` de l'index.
pub(crate) fn juger(index: &Index, cve: &str, v: Version, branche: BrancheFx) -> Jugement {
    let Some(c) = index.cves.get(&cve.to_ascii_uppercase()) else {
        return Jugement::Inconnu;
    };
    match branche {
        BrancheFx::Release => jugement_release(c, v),
        BrancheFx::Esr(m) => jugement_esr(c, v, m),
        BrancheFx::Inconnue => match (jugement_release(c, v), jugement_esr(c, v, v.majeur())) {
            (Jugement::Anterieure(z), Jugement::Anterieure(_)) => Jugement::Anterieure(z),
            (Jugement::Corrigee, _) | (_, Jugement::Corrigee) => Jugement::Corrigee,
            _ => Jugement::Inconnu,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(t: &str) -> Version {
        Version::lire(t).unwrap()
    }

    /// Un avis récent inventé, au format des vrais : `fixed_in` en tête, CVE en clés de `advisories`.
    const YML: &str = "## mfsa2099-51.yml
announced: October 9, 2099
impact: critical
fixed_in:
- Firefox 131.0.2
- Firefox ESR 128.3.1
- Firefox ESR 115.16.1
- Firefox for iOS 131.2
title: Security Vulnerability fixed in Firefox 131.0.2
advisories:
  CVE-2099-9680:
    title: Use-after-free in an invented component
    impact: critical
    description: |
      CVE-2099-0001 is only cited here, and is not a key.
    bugs:
      - url: 1923344
  MFSA-RESERVE-2099-0001:
    title: not a CVE
";

    /// Un ancien avis inventé (`.md`) : `fixed_in` en retrait, CVE dans le corps.
    const MD: &str = "---
announced: August 6, 2015
fixed_in:
  - \"Firefox 39.0.3\"
  - Firefox ESR 38.1.1
  - Firefox OS 2.2
  - Firefox Mobile 39.0.3
impact: Critical
title: Invented PDF viewer flaw
---

<p>Reported as <a href=\"https://example.com/CVE-2015-4495\">CVE-2015-4495</a>, not CVE-2015-44951234 nor
XCVE-2015-1111.</p>
";

    #[test]
    fn les_deux_formats() {
        let a = avis("announce/2099/mfsa2099-51.yml", YML.as_bytes()).unwrap();
        assert_eq!(a.firefox, vec![v("131.0.2")]);
        assert_eq!(a.esr, vec![v("128.3.1"), v("115.16.1")]);
        assert_eq!(a.cves, vec!["CVE-2099-9680"]);
        let b = avis("announce/2015/mfsa2015-78.md", MD.as_bytes()).unwrap();
        assert_eq!(b.firefox, vec![v("39.0.3")]);
        assert_eq!(b.esr, vec![v("38.1.1")]);
        assert_eq!(b.cves, vec!["CVE-2015-4495"]);
        // Rien de Firefox, autre extension, en-tête non fermé : rien à en tirer.
        let thunderbird = YML.replace("- Firefox", "- Thunderbird");
        assert!(avis("a.yml", thunderbird.as_bytes()).is_none());
        assert!(avis("a.txt", YML.as_bytes()).is_none());
        assert!(avis("a.md", MD.replacen("\n---\n", "\n", 1).as_bytes()).is_none());
        assert!(avis("a.md", YML.as_bytes()).is_none());
        assert!(avis("a.yml", &[0xff, 0xfe]).is_none());
        assert!(avis("a.yml", &vec![b'\n'; LIGNES_MAX + 2]).is_none());
        assert!(avis("a.yml", &vec![b' '; AVIS_MAX + 1]).is_none());
    }

    /// Une CVE dans un avis Firefox et un avis Thunderbird : les correctifs se réunissent ; la branche décide.
    #[test]
    fn index_et_jugements() {
        use BrancheFx::*;
        let mut index = Index::default();
        index.ajouter(&avis("a.yml", YML.as_bytes()).unwrap());
        let thunderbird = YML
            .replace("- Firefox 131.0.2\n", "- Thunderbird 128.3.1\n")
            .replace("- Firefox ESR 128.3.1\n", "");
        index.ajouter(&avis("b.yml", thunderbird.as_bytes()).unwrap());
        index.ajouter(&avis("c.md", MD.as_bytes()).unwrap());
        assert_eq!(index.avis, 3);
        let c = &index.cves["CVE-2099-9680"];
        assert_eq!(c.firefox, vec![v("131.0.2")]);
        assert_eq!(c.esr.len(), 2);
        let cve = "cve-2099-9680";
        assert_eq!(
            juger(&index, cve, v("131.0.1"), Release),
            Jugement::Anterieure(v("131.0.2"))
        );
        assert_eq!(juger(&index, cve, v("131.0.2"), Release), Jugement::Corrigee);
        assert_eq!(juger(&index, cve, v("158.0"), Release), Jugement::Corrigee);
        assert_eq!(
            juger(&index, cve, v("115.16.0"), Esr(115)),
            Jugement::Anterieure(v("115.16.1"))
        );
        assert_eq!(juger(&index, cve, v("128.4"), Esr(128)), Jugement::Corrigee);
        // ESR née après le correctif : corrigée ; ESR plus ancienne sans correctif publié : on ne sait pas.
        assert_eq!(juger(&index, cve, v("140.1"), Esr(140)), Jugement::Corrigee);
        assert_eq!(juger(&index, cve, v("102.15"), Esr(102)), Jugement::Inconnu);
        // Branche inconnue : antérieure seulement si elle l'est pour les deux lectures.
        assert_eq!(
            juger(&index, cve, v("115.16.0"), Inconnue),
            Jugement::Anterieure(v("131.0.2"))
        );
        assert_eq!(juger(&index, cve, v("115.17"), Inconnue), Jugement::Corrigee);
        assert_eq!(juger(&index, cve, v("102.1"), Inconnue), Jugement::Inconnu);
        assert_eq!(juger(&index, "CVE-2000-0001", v("1.0"), Release), Jugement::Inconnu);
        // Corrigée seulement en ESR : rien à dire d'une version release.
        let mut seule = Index::default();
        seule.ajouter(&avis("d.yml", YML.replace("- Firefox 131.0.2\n", "").as_bytes()).unwrap());
        assert_eq!(juger(&seule, cve, v("100.0"), Release), Jugement::Inconnu);
    }

    /// Une archive hostile : 10 000 avis, la même CVE, 64 versions différentes chacun. La fusion reste linéaire et
    /// ne garde que le plus petit correctif (et un par branche ESR, bornées).
    #[test]
    fn fusion_bornee() {
        let debut = std::time::Instant::now();
        let mut index = Index::default();
        for i in 0..u32::try_from(AVIS_TOUS).unwrap() {
            let versions = |base: u32| -> Vec<Version> {
                (0..64)
                    .map(|j| Version::lire(&format!("{}.{i}.{j}", base + j)).unwrap())
                    .collect()
            };
            index.ajouter(&Avis {
                firefox: versions(200),
                esr: versions(i * 64 + 1000),
                cves: vec!["CVE-2099-0001".into()],
            });
        }
        let c = &index.cves["CVE-2099-0001"];
        assert_eq!(c.firefox, vec![v("200.0.0")]);
        assert_eq!(c.esr.len(), ESR_PAR_CVE);
        // Une fusion quadratique prendrait des heures ; 60 s laisse de la marge à une machine chargée (verifier.sh lance
        // ses étapes en parallèle, et d'autres compilations peuvent tourner), où 10 s faisait tomber le test pour rien.
        assert!(debut.elapsed() < std::time::Duration::from_secs(60));
        // Le plus petit correctif gagne, quel que soit l'ordre des avis.
        let mut index = Index::default();
        for t in ["131.0.2", "130.0", "132.0"] {
            index.ajouter(&Avis {
                firefox: vec![v(t)],
                esr: vec![v(&t.replace("13", "11"))],
                cves: vec!["cve-2099-0002".into()],
            });
        }
        let c = &index.cves["CVE-2099-0002"];
        assert_eq!(
            (c.firefox.clone(), c.esr.clone()),
            (vec![v("130.0")], vec![v("111.0.2"), v("110.0"), v("112.0")])
        );
        // Trop de CVE distinctes : les dernières restent absentes, donc « on ne sait pas ».
        let mut index = Index::default();
        let cves = (0..=CVES_TOUTES).map(|n| format!("CVE-2099-{n:06}")).collect();
        index.ajouter(&Avis {
            firefox: vec![v("1.0")],
            esr: Vec::new(),
            cves,
        });
        assert_eq!(index.cves.len(), CVES_TOUTES);
        assert_eq!(
            juger(
                &index,
                &format!("CVE-2099-{CVES_TOUTES:06}"),
                v("0.1"),
                BrancheFx::Release
            ),
            Jugement::Inconnu
        );
    }

    #[test]
    fn cves_du_corps() {
        let mut cves = Vec::new();
        cves_du_texte(
            "CVE-2016-9079, (CVE-2016-12345) CVE-2016-1 CVE-20x6-1234 aCVE-2016-1111 CVE-2016-123456789 CVE-",
            &mut cves,
        );
        assert_eq!(cves, vec!["CVE-2016-9079", "CVE-2016-12345"]);
        let beaucoup = (0..2000)
            .map(|i| format!("CVE-2099-{i:05}"))
            .collect::<Vec<_>>()
            .join(" ");
        let mut cves = Vec::new();
        cves_du_texte(&beaucoup, &mut cves);
        assert_eq!(cves.len(), CVE_PAR_AVIS);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2000)) {
            let _ = avis("x.yml", &octets);
            let _ = avis("x.md", &octets);
        }

        /// Des avis valides abîmés ligne à ligne : jamais de panique.
        #[test]
        fn avis_mutes(coupe in 0usize..400, ajout in "[ -~\n]{0,80}") {
            for base in [YML, MD] {
                let coupe = coupe.min(base.len());
                let coupe = (0..=coupe).rev().find(|&i| base.is_char_boundary(i)).unwrap_or(0);
                let texte = format!("{}{ajout}{}", &base[..coupe], &base[coupe..]);
                let _ = avis("x.yml", texte.as_bytes());
                let _ = avis("x.md", texte.as_bytes());
            }
        }
    }
}
