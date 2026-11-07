//! Les fichiers des éditeurs (Mozilla, Google, Microsoft, Adobe, Brave, Slack) : des numéros de version, pris comme des
//! faits. Aucun n'a de licence publiée ni de format documenté : une forme qui change donne `None`, et le logiciel
//! est « non vérifié », jamais comparé de travers. JSON lu en structures typées (champs inconnus ignorés).

use std::collections::BTreeMap;

use chrono::{NaiveDate, NaiveDateTime};
use serde::Deserialize;

use super::Souple;
use crate::protection::perimes::version::{self, Version};

// ───────────────────────────── Mozilla ─────────────────────────────

/// product-details de Mozilla : la dernière Firefox et chaque ESR suivie (aujourd'hui 153 et 115), de la plus
/// récente à la plus ancienne.
#[derive(Debug, PartialEq)]
pub(crate) struct Firefox {
    pub release: Version,
    pub esr: Vec<Version>,
}

/// `firefox_versions.json` : « LATEST_FIREFOX_VERSION », et les clés « FIREFOX_ESR », « FIREFOX_ESR115 »,
/// « FIREFOX_ESR_NEXT »… non vides. Une ESR illisible rend tout le fichier illisible : une ESR oubliée ferait dire
/// « dépassée » à ceux qui la suivent.
pub(crate) fn firefox(octets: &[u8]) -> Option<Firefox> {
    let champs: BTreeMap<String, Souple<String>> = serde_json::from_slice(octets).ok()?;
    let mut release = None;
    let mut esr = Vec::new();
    for (cle, valeur) in champs {
        let Some(valeur) = valeur.bon() else { continue };
        if cle == "LATEST_FIREFOX_VERSION" {
            release = Some(version::firefox(&valeur)?);
        } else if let Some(suite) = cle.strip_prefix("FIREFOX_ESR")
            && (suite.is_empty() || suite == "_NEXT" || suite.bytes().all(|o| o.is_ascii_digit()))
            && !valeur.trim().is_empty()
        {
            esr.push(version::firefox(&valeur)?);
        }
    }
    esr.sort_unstable_by(|a, b| b.cmp(a));
    esr.dedup();
    Some(Firefox {
        release: release?,
        esr: (!esr.is_empty()).then_some(esr)?,
    })
}

// ───────────────────────────── Google Chrome ─────────────────────────────

#[derive(Deserialize)]
struct Sorties {
    releases: Vec<Sortie>,
}

#[derive(Deserialize)]
struct Sortie {
    name: String,
    version: String,
    #[serde(default)]
    fraction: f64,
}

/// versionhistory : les versions servies en ce moment (`fraction` > 0 ; plusieurs pendant un déploiement par
/// étapes), de la plus ancienne à la plus récente. Chaque entrée doit être celle de `plateforme` et `canal` : une
/// réponse d'une autre adresse n'est pas prise pour celle-ci.
pub(crate) fn chrome(octets: &[u8], plateforme: &str, canal: &str) -> Option<Vec<Version>> {
    let sorties: Sorties = serde_json::from_slice(octets).ok()?;
    let attendu = format!("platforms/{plateforme}/channels/{canal}/");
    if sorties.releases.iter().any(|s| !s.name.contains(&attendu)) {
        return None;
    }
    let mut servies = sorties
        .releases
        .iter()
        .filter(|s| s.fraction > 0.0)
        .map(|s| version::chrome_edge(&s.version))
        .collect::<Option<Vec<_>>>()?;
    servies.sort_unstable();
    servies.dedup();
    (!servies.is_empty()).then_some(servies)
}

// ───────────────────────────── Microsoft Edge ─────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProduitEdge {
    product: String,
    #[serde(default)]
    releases: Vec<SortieEdge>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SortieEdge {
    platform: String,
    architecture: String,
    product_version: String,
    published_time: Option<Souple<String>>,
    #[serde(rename = "CVEs", default)]
    cves: Option<Souple<Vec<Souple<String>>>>,
}

/// CVE gardées au plus pour une version d'Edge (354 le 23 oct. 2026, une version de Chromium entière) : au-delà, la
/// liste n'est pas celle attendue et ne sert pas. La lecture refuse déjà un tableau plus long que
/// `SOUS_ENTREES_MAX` : une borne plus haute ici ne serait jamais atteinte et ferait croire à une autre limite.
const CVES_PAR_VERSION_MAX: usize = super::SOUS_ENTREES_MAX;
/// Versions Stable gardées au plus par plateforme et architecture (une ou deux le 23 oct. 2026).
const CORRECTIFS_MAX: usize = 64;

/// Une version Edge Stable et les CVE qu'elle corrige, selon Microsoft ; `cves` à `None` : liste absente, d'une
/// autre forme ou démesurée, rien ne se juge faille par faille pour cette version.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CorrectifEdge {
    pub version: Version,
    pub cves: Option<Vec<String>>,
}

/// La dernière Edge Stable d'une plateforme et d'une architecture, quand elle a été publiée, et chaque version
/// Stable de la liste avec les CVE qu'elle corrige (la liste de Microsoft ne garde que les dernières).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EdgeStable {
    /// « Windows », « MacOS »…
    pub plateforme: String,
    /// « x64 », « x86 », « arm64 », « universal ».
    pub architecture: String,
    pub version: Version,
    pub publiee: Option<NaiveDateTime>,
    pub correctifs: Vec<CorrectifEdge>,
}

/// « CVE-2026-12345 » : quatre chiffres d'année, quatre à sept de numéro ; écrit en majuscules.
pub(crate) fn cve(texte: &str) -> Option<String> {
    let t = texte.trim().to_ascii_uppercase();
    let reste = t.strip_prefix("CVE-")?;
    let (annee, numero) = reste.split_once('-')?;
    let chiffres =
        |s: &str, n: std::ops::RangeInclusive<usize>| n.contains(&s.len()) && s.bytes().all(|o| o.is_ascii_digit());
    (chiffres(annee, 4..=4) && chiffres(numero, 4..=7)).then_some(t)
}

/// Les CVE d'une version : `None` si la liste manque, a une autre forme, dépasse la borne ou contient une seule
/// entrée qui n'est pas une CVE. Les vraies listes n'en ont aucune : une entrée d'une autre forme veut dire que le
/// format a changé, et ignorer les entrées une à une rendrait une liste vide, prise pour « aucune faille corrigée ».
fn cves_de(brutes: Option<Souple<Vec<Souple<String>>>>) -> Option<Vec<String>> {
    let brutes = brutes?.bon()?;
    if brutes.len() > CVES_PAR_VERSION_MAX {
        return None;
    }
    brutes.into_iter().map(|c| cve(&c.bon()?)).collect()
}

/// `edgeupdates.microsoft.com/api/products` : pour le produit « Stable », la plus haute version de chaque
/// plateforme et architecture (la liste n'est pas triée), et les CVE corrigées par chaque version. Le canal
/// Extended Stable n'y est pas.
pub(crate) fn edge(octets: &[u8]) -> Option<Vec<EdgeStable>> {
    let produits: Vec<ProduitEdge> = serde_json::from_slice(octets).ok()?;
    let stable = produits.into_iter().find(|p| p.product == "Stable")?;
    let mut dernieres: Vec<EdgeStable> = Vec::new();
    for s in stable.releases {
        let version = version::chrome_edge(&s.product_version)?;
        let publiee = s
            .published_time
            .and_then(Souple::bon)
            .and_then(|t| NaiveDateTime::parse_from_str(t.get(..19)?, "%Y-%m-%dT%H:%M:%S").ok());
        let correctif = CorrectifEdge {
            version,
            cves: cves_de(s.cves),
        };
        let Some(d) = dernieres
            .iter_mut()
            .find(|d| d.plateforme == s.platform && d.architecture == s.architecture)
        else {
            dernieres.push(EdgeStable {
                plateforme: s.platform,
                architecture: s.architecture,
                version,
                publiee,
                correctifs: vec![correctif],
            });
            continue;
        };
        if d.correctifs.len() >= CORRECTIFS_MAX {
            return None;
        }
        d.correctifs.push(correctif);
        if version > d.version {
            d.version = version;
            d.publiee = publiee;
        }
    }
    (!dernieres.is_empty()).then_some(dernieres)
}

// ───────────────────────────── Office (Windows) ─────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanalBrut {
    channel_id: String,
    #[serde(default)]
    channel: Option<Souple<String>>,
    #[serde(default)]
    alternate_names: Option<Souple<Vec<String>>>,
    latest_version: String,
    #[serde(default)]
    office_versions: Vec<VersionBrute>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionBrute {
    legacy_version: String,
    #[serde(default)]
    availability_date: Option<Souple<String>>,
    end_of_support_date: Option<Souple<String>>,
    cdn_base_url: Option<Souple<String>>,
}

/// Un canal d'Office Click-to-Run, tel que OfficeReleases le décrit.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanalOffice {
    /// « Current », « MonthlyEnterprise », « SemiAnnual », « PerpetualVL2024 »…
    pub id: String,
    /// Le nom court (« Monthly », « SAC »), puis les autres noms (« Deferred », « Broad »).
    pub noms: Vec<String>,
    pub derniere: Version,
    pub versions: Vec<VersionOffice>,
    /// Les GUID de ses adresses (`cdnBaseUrl`), en minuscules : c'est par eux qu'un canal réglé dans le registre se
    /// reconnaît, d'après la source elle-même.
    pub guids: Vec<String>,
}

/// Une version encore servie d'un canal, le jour où elle l'a été (un déploiement prend quelques jours) et la fin de
/// son support (`None` : aucune annoncée).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct VersionOffice {
    pub version: Version,
    pub disponible: Option<NaiveDate>,
    pub fin: Option<NaiveDate>,
}

/// `OfficeReleases` : chaque canal, au moins trois (sinon ce n'est pas la liste attendue).
pub(crate) fn office(octets: &[u8]) -> Option<Vec<CanalOffice>> {
    let bruts: Vec<CanalBrut> = serde_json::from_slice(octets).ok()?;
    let mut canaux = Vec::new();
    for c in bruts {
        let mut noms: Vec<String> = c.channel.and_then(Souple::bon).into_iter().collect();
        noms.extend(c.alternate_names.and_then(Souple::bon).unwrap_or_default());
        let mut versions = Vec::new();
        let mut guids: Vec<String> = Vec::new();
        for v in c.office_versions {
            versions.push(VersionOffice {
                version: version::chrome_edge(&v.legacy_version)?,
                disponible: v
                    .availability_date
                    .and_then(Souple::bon)
                    .and_then(|d| fin_de_support(&d)),
                fin: v
                    .end_of_support_date
                    .and_then(Souple::bon)
                    .and_then(|d| fin_de_support(&d)),
            });
            if let Some(guid) = v.cdn_base_url.and_then(Souple::bon).and_then(|u| guid_de(&u))
                && !guids.contains(&guid)
            {
                guids.push(guid);
            }
        }
        canaux.push(CanalOffice {
            id: c.channel_id,
            noms,
            derniere: version::chrome_edge(&c.latest_version)?,
            versions,
            guids,
        });
    }
    (canaux.len() >= 3).then_some(canaux)
}

/// « 2027-04-13T00:00:00Z » ; « 0001-01-01… » veut dire aucune fin annoncée.
fn fin_de_support(texte: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(texte.get(..10)?, "%Y-%m-%d")
        .ok()
        .filter(|d| *d > NaiveDate::from_ymd_opt(1, 1, 1).unwrap_or_default())
}

/// Le GUID qui termine une adresse de canal (« http://officecdn.microsoft.com/pr/492350f6-3a01-… »), en minuscules,
/// s'il a la forme d'un GUID (8-4-4-4-12 chiffres hexadécimaux).
pub(crate) fn guid_de(adresse: &str) -> Option<String> {
    let dernier = adresse.trim_end_matches('/').rsplit('/').next()?.to_ascii_lowercase();
    let groupes: Vec<&str> = dernier.split('-').collect();
    let forme = groupes.len() == 5
        && groupes
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|o| o.is_ascii_hexdigit()));
    forme.then_some(dernier)
}

// ───────────────────────────── Slack ─────────────────────────────

#[derive(Deserialize)]
struct SlackBrut {
    ok: bool,
    #[serde(default)]
    version: Option<Souple<String>>,
    #[serde(default)]
    platform: Option<Souple<String>>,
}

/// `slack.com/api/desktop.latestRelease` (adresse fixe, la même pour tous ; API non documentée) :
/// `{"ok": true, "version": "4.52.182", "platform": "win32", …}`. La réponse doit être celle de `plateforme`
/// (« win32 », « darwin ») et dire `ok` ; une autre forme, une erreur ou une version d'un autre nombre de champs
/// donnent `None`, et Slack est « non vérifié ».
pub(crate) fn slack(octets: &[u8], plateforme: &str) -> Option<Version> {
    let brut: SlackBrut = serde_json::from_slice(octets).ok()?;
    if !brut.ok || brut.platform.and_then(Souple::bon)? != plateforme {
        return None;
    }
    Version::lire(&brut.version.and_then(Souple::bon)?).filter(|v| v.longueur() == 3)
}

// ───────────────────────────── Adobe, Brave ─────────────────────────────

/// Un petit fichier texte : une seule ligne.
fn ligne(octets: &[u8]) -> Option<&str> {
    let texte = std::str::from_utf8(octets).ok()?.trim();
    (!texte.contains('\n')).then_some(texte)
}

/// `current_version.txt` d'Adobe : « 26.002.22031 » (piste Continuous).
pub(crate) fn adobe(octets: &[u8]) -> Option<Version> {
    version::adobe(ligne(octets)?)
}

/// `release-<plateforme>.version` de Brave : « 1.98.60 ».
pub(crate) fn brave(octets: &[u8]) -> Option<Version> {
    Version::lire(ligne(octets)?).filter(|v| v.longueur() == 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(texte: &str) -> Version {
        Version::lire(texte).unwrap()
    }

    // Les fichiers des éditeurs n'ont pas de licence publiée : fixtures inventées, à leur forme réelle (vue le
    // 23 oct. 2026), jamais des copies.

    const FIREFOX: &str = r#"{
        "FIREFOX_AURORA": "",
        "FIREFOX_DEVEDITION": "159.0b5",
        "FIREFOX_ESR": "153.5.1esr",
        "FIREFOX_ESR115": "115.43.1esr",
        "FIREFOX_ESR_NEXT": "",
        "FIREFOX_NIGHTLY": "161.0a1",
        "LAST_RELEASE_DATE": "2026-10-23",
        "LATEST_FIREFOX_OLDER_VERSION": "3.6.28",
        "LATEST_FIREFOX_VERSION": "158.0.1"
    }"#;

    #[test]
    fn firefox_et_ses_esr() {
        let f = firefox(FIREFOX.as_bytes()).unwrap();
        assert_eq!(f.release, v("158.0.1"));
        assert_eq!(f.esr, vec![v("153.5.1"), v("115.43.1")]);
        // Une ESR de plus, suivie sans changer le code ; une valeur d'un autre type est ignorée.
        let plus = FIREFOX.replace(
            "\"FIREFOX_ESR_NEXT\": \"\"",
            "\"FIREFOX_ESR_NEXT\": \"165.0esr\", \"X\": 3",
        );
        assert_eq!(firefox(plus.as_bytes()).unwrap().esr.len(), 3);
        // Sans la dernière version, ou une ESR illisible : rien.
        assert_eq!(
            firefox(FIREFOX.replace("LATEST_FIREFOX_VERSION", "AUTRE").as_bytes()),
            None
        );
        assert_eq!(firefox(FIREFOX.replace("153.5.1esr", "153.5.1-esr").as_bytes()), None);
        assert_eq!(firefox(b"<html>Portail</html>"), None);
        assert_eq!(firefox(b"{}"), None);
    }

    fn versionhistory(plateforme: &str, canal: &str, sorties: &[(&str, f64)]) -> String {
        let entrees: Vec<String> = sorties
            .iter()
            .map(|(version, fraction)| {
                format!(
                    r#"{{"name": "chrome/platforms/{plateforme}/channels/{canal}/versions/{version}/releases/1792700197",
                        "serving": {{"startTime": "2026-10-22T20:16:37.163276Z"}}, "fraction": {fraction},
                        "version": "{version}", "fractionGroup": "0", "pinnable": true, "rolloutData": []}}"#
                )
            })
            .collect();
        format!(r#"{{"releases": [{}], "nextPageToken": ""}}"#, entrees.join(","))
    }

    #[test]
    fn chrome_versions_servies() {
        let extended = versionhistory(
            "win64",
            "extended",
            &[("152.0.7977.169", 0.75), ("156.0.8078.48", 0.25)],
        );
        assert_eq!(
            chrome(extended.as_bytes(), "win64", "extended"),
            Some(vec![v("152.0.7977.169"), v("156.0.8078.48")])
        );
        // La réponse d'une autre plateforme ou d'un autre canal n'est pas prise pour celle-ci.
        assert_eq!(chrome(extended.as_bytes(), "win64", "stable"), None);
        assert_eq!(chrome(extended.as_bytes(), "win", "extended"), None);
        // Une version qui ne sert plus (fraction 0) est écartée ; aucune servie : rien.
        let stable = versionhistory("mac", "stable", &[("155.0.8059.85", 0.0), ("156.0.8078.47", 1.0)]);
        assert_eq!(
            chrome(stable.as_bytes(), "mac", "stable"),
            Some(vec![v("156.0.8078.47")])
        );
        let aucune = versionhistory("mac", "stable", &[("155.0.8059.85", 0.0)]);
        assert_eq!(chrome(aucune.as_bytes(), "mac", "stable"), None);
        let trois_champs = versionhistory("mac", "stable", &[("156.0.8078", 1.0)]);
        assert_eq!(chrome(trois_champs.as_bytes(), "mac", "stable"), None);
        assert_eq!(chrome(b"{\"releases\": []}", "mac", "stable"), None);
    }

    const EDGE: &str = r#"[
        {"Product": "Stable", "Releases": [
            {"ReleaseId": 1, "Platform": "Windows", "Architecture": "x64", "CVEs": ["CVE-2026-0001"],
             "ProductVersion": "155.0.4283.61", "PublishedTime": "2026-10-10T10:00:00", "Artifacts": []},
            {"ReleaseId": 2, "Platform": "Windows", "Architecture": "x64", "CVEs": [],
             "ProductVersion": "156.0.4314.42", "PublishedTime": "2026-10-22T19:20:00", "Artifacts": []},
            {"ReleaseId": 3, "Platform": "MacOS", "Architecture": "universal",
             "ProductVersion": "156.0.4314.42", "PublishedTime": null}
        ]},
        {"Product": "Beta", "Releases": [
            {"ReleaseId": 4, "Platform": "Windows", "Architecture": "x64",
             "ProductVersion": "157.0.4330.10", "PublishedTime": "2026-10-21T10:00:00"}
        ]}
    ]"#;

    #[test]
    fn edge_stable_par_plateforme() {
        let e = edge(EDGE.as_bytes()).unwrap();
        assert_eq!(e.len(), 2);
        let windows = e.iter().find(|s| s.plateforme == "Windows").unwrap();
        assert_eq!(windows.version, v("156.0.4314.42"));
        assert_eq!(
            windows.publiee.map(|t| t.to_string()).as_deref(),
            Some("2026-10-22 19:20:00")
        );
        let mac = e.iter().find(|s| s.plateforme == "MacOS").unwrap();
        assert_eq!((mac.architecture.as_str(), mac.publiee), ("universal", None));
        // Chaque version Stable garde ses CVE ; une liste absente ne vaut pas une liste vide.
        assert_eq!(
            windows.correctifs,
            [
                CorrectifEdge {
                    version: v("155.0.4283.61"),
                    cves: Some(vec!["CVE-2026-0001".into()])
                },
                CorrectifEdge {
                    version: v("156.0.4314.42"),
                    cves: Some(vec![])
                }
            ]
        );
        assert_eq!(mac.correctifs[0].cves, None);
        // Pas de Stable : rien (la Beta n'est jamais prise à sa place).
        assert_eq!(edge(EDGE.replace("\"Stable\"", "\"Autre\"").as_bytes()), None);
        assert_eq!(edge(b"[]"), None);
    }

    const OFFICE: &str = r#"[
        {"channel": "Monthly", "channelId": "Current", "alternateNames": ["Monthly"],
         "latestVersion": "16.0.20527.20088", "officeVersions": [
            {"legacyVersion": "16.0.20527.20088", "releaseVersion": "2610", "buildVersion": "20527.20088",
             "availabilityDate": "2026-10-14T00:00:00Z", "endOfSupportDate": "0001-01-01T00:00:00Z",
             "cdnBaseUrl": "http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60"}]},
        {"channel": "SAC", "channelId": "SemiAnnual", "alternateNames": ["Deferred", "Broad"],
         "latestVersion": "16.0.20430.20178", "officeVersions": [
            {"legacyVersion": "16.0.20430.20178", "endOfSupportDate": "2027-04-13T00:00:00Z",
             "cdnBaseUrl": "http://officecdn.microsoft.com/pr/7FFBC6BF-BC32-4F92-8982-F9DD17FD3114"},
            {"legacyVersion": "16.0.20326.20230", "endOfSupportDate": "2027-03-09T00:00:00Z",
             "cdnBaseUrl": "http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"}]},
        {"channel": "LTSB2024", "channelId": "PerpetualVL2024", "alternateNames": ["Perpetual2024"],
         "latestVersion": "16.0.17932.21056", "officeVersions": []}
    ]"#;

    #[test]
    fn office_canaux_et_guids() {
        let canaux = office(OFFICE.as_bytes()).unwrap();
        assert_eq!(canaux.len(), 3);
        let sac = &canaux[1];
        assert_eq!(sac.id, "SemiAnnual");
        assert_eq!(sac.noms, ["SAC", "Deferred", "Broad"]);
        assert_eq!(sac.derniere, v("16.0.20430.20178"));
        assert_eq!(sac.guids, ["7ffbc6bf-bc32-4f92-8982-f9dd17fd3114"]);
        assert_eq!(sac.versions[1].fin, NaiveDate::from_ymd_opt(2027, 3, 9));
        assert_eq!(canaux[0].versions[0].fin, None, "0001-01-01 : aucune fin annoncée");
        assert_eq!(canaux[0].versions[0].disponible, NaiveDate::from_ymd_opt(2026, 10, 14));
        assert_eq!(sac.versions[0].disponible, None);
        // Moins de trois canaux, ou une version illisible : rien.
        let mut deux: serde_json::Value = serde_json::from_str(OFFICE).unwrap();
        deux.as_array_mut().unwrap().truncate(2);
        assert_eq!(office(deux.to_string().as_bytes()), None);
        assert_eq!(
            office(
                OFFICE
                    .replace("16.0.20527.20088\", \"releaseVersion", "16.0.x\", \"releaseVersion")
                    .as_bytes()
            ),
            None
        );
        assert_eq!(guid_de("http://officecdn.microsoft.com/pr/wsus"), None);
        assert_eq!(guid_de("\\\\serveur\\partage"), None);
    }

    /// Les CVE d'Edge : forme vérifiée, majuscules, entrées étrangères ignorées, liste démesurée ou d'un autre type
    /// refusée (sans rendre la version illisible).
    #[test]
    fn edge_cves_bornees() {
        assert_eq!(cve(" cve-2026-112992 ").as_deref(), Some("CVE-2026-112992"));
        for faux in [
            "CVE-26-1234",
            "CVE-2026-123",
            "CVE-2026-12345678",
            "CVE-2026",
            "XSA-2026-1234",
            "CVE-2026-12a4",
        ] {
            assert_eq!(cve(faux), None, "{faux}");
        }
        let avec = |cves: &str| {
            let json = format!(
                r#"[{{"Product": "Stable", "Releases": [{{"Platform": "Windows", "Architecture": "x64",
                    "ProductVersion": "156.0.4314.42", "PublishedTime": "2026-10-22T19:20:00", "CVEs": {cves}}}]}}]"#
            );
            edge(json.as_bytes()).unwrap()[0].correctifs[0].cves.clone()
        };
        assert_eq!(
            avec(r#"["CVE-2026-0001", "cve-2026-0002"]"#),
            Some(vec!["CVE-2026-0001".into(), "CVE-2026-0002".into()])
        );
        assert_eq!(avec("[]"), Some(vec![]));
        // Un seul élément qui n'est pas une CVE : toute la liste est refusée. Une liste abîmée qui deviendrait vide
        // passerait pour « aucune faille corrigée ».
        for abimee in [
            r#"["CVE-2026-0001", 3]"#,
            r#"["CVE-2026-0001", null]"#,
            r#"["CVE-2026-0001", "pas une CVE"]"#,
            r#"[{"id": "CVE-2026-0001"}]"#,
            r#"["CVE-2026-112992 (Chromium)"]"#,
        ] {
            assert_eq!(avec(abimee), None, "{abimee}");
        }
        assert_eq!(avec("null"), None);
        assert_eq!(avec(r#""CVE-2026-0001""#), None);
        let trop: Vec<String> = (0..=CVES_PAR_VERSION_MAX)
            .map(|i| format!("\"CVE-2026-{i:05}\""))
            .collect();
        assert_eq!(avec(&format!("[{}]", trop.join(","))), None);
        // Pile à la borne : la liste est gardée en entier.
        let juste = trop[..CVES_PAR_VERSION_MAX].join(",");
        assert_eq!(avec(&format!("[{juste}]")).map(|c| c.len()), Some(CVES_PAR_VERSION_MAX));
        // Trop de versions pour une même plateforme : pas la liste attendue.
        let sorties: Vec<String> = (0..=CORRECTIFS_MAX)
            .map(|i| format!(r#"{{"Platform": "Windows", "Architecture": "x64", "ProductVersion": "156.0.1.{i}"}}"#))
            .collect();
        let json = format!(r#"[{{"Product": "Stable", "Releases": [{}]}}]"#, sorties.join(","));
        assert_eq!(edge(json.as_bytes()), None);
    }

    #[test]
    fn slack_par_plateforme() {
        let windows = br#"{"ok":true,"version":"4.52.182","download_url":"https:\/\/downloads.example.com\/windows\/x64\/4.52.182\/slack-standalone-4.52.182.0.msi","platform":"win32","arch":"x64"}"#;
        assert_eq!(slack(windows, "win32"), Some(v("4.52.182")));
        // La réponse d'une autre plateforme n'est pas prise pour celle-ci.
        assert_eq!(slack(windows, "darwin"), None);
        let mac = br#"{"ok":true,"version":"4.52.182","platform":"darwin","arch":"universal"}"#;
        assert_eq!(slack(mac, "darwin"), Some(v("4.52.182")));
        // Une erreur, une forme inattendue : rien (Slack sera « non vérifié »).
        for faux in [
            &br#"{"ok":false,"error":"desktop_variant_arch_mismatch"}"#[..],
            br#"{"ok":true,"version":"4.52","platform":"win32"}"#,
            br#"{"ok":true,"version":4,"platform":"win32"}"#,
            br#"{"ok":true,"platform":"win32"}"#,
            br#"{"ok":"true","version":"4.52.182","platform":"win32"}"#,
            br#"{"version":"4.52.182","platform":"win32"}"#,
            b"<html>Portail</html>",
        ] {
            assert_eq!(slack(faux, "win32"), None, "{}", String::from_utf8_lossy(faux));
        }
    }

    #[test]
    fn fichiers_texte() {
        assert_eq!(adobe(b"26.002.22031"), Some(v("26.2.22031")));
        assert_eq!(adobe(b"26.002.22031\n"), Some(v("26.2.22031")));
        assert_eq!(adobe(b"26.002.22031\n26.001.1"), None);
        assert_eq!(adobe(b"<html>"), None);
        assert_eq!(brave(b"1.98.60"), Some(v("1.98.60")));
        assert_eq!(brave(b"156.1.98.60"), None);
        assert_eq!(brave(b"\xff\xfe"), None);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 500, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..300)) {
            let _ = firefox(&octets);
            let _ = chrome(&octets, "win", "stable");
            let _ = edge(&octets);
            let _ = office(&octets);
            let _ = adobe(&octets);
            let _ = brave(&octets);
            let _ = slack(&octets, "win32");
            let _ = cve(&String::from_utf8_lossy(&octets));
        }
    }
}
