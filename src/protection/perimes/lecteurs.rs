//! Les petits fichiers texte qu'un logiciel installé pose à côté de lui et qui disent sa version mieux que le
//! registre : `release` de Java, `application.ini` et `channel-prefs.js` de Firefox. N'importe quel programme du
//! compte peut les réécrire : lus en une fois (64 Kio, 1 000 lignes au plus, fichier ordinaire seulement), chaque
//! valeur bornée, et ce qui sort de la forme attendue est ignoré, jamais deviné.
//!
//! Lecteurs purs, sans `crate::`.

use std::io::Read;
use std::path::Path;

/// Taille d'un fichier lu ; les vrais font moins de 2 Kio.
const TAILLE_MAX: usize = 64 << 10;
const LIGNES_MAX: usize = 1000;
/// Une valeur plus longue n'est pas celle qu'on cherche.
const VALEUR_MAX: usize = 256;

/// Le texte d'un petit fichier : `None` s'il est absent, pas un fichier ordinaire (un tube nommé bloquerait la
/// lecture), trop gros, trop long ou pas en UTF-8.
pub(crate) fn texte_borne(chemin: &Path) -> Option<String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let fichier = options.open(chemin).ok()?;
    if !fichier.metadata().ok()?.is_file() {
        return None;
    }
    let mut octets = Vec::new();
    fichier.take(TAILLE_MAX as u64 + 1).read_to_end(&mut octets).ok()?;
    texte(&octets).map(str::to_string)
}

/// Le texte de ces octets, sous les mêmes bornes (une marque d'ordre UTF-8 en tête est retirée).
pub(crate) fn texte(octets: &[u8]) -> Option<&str> {
    if octets.len() > TAILLE_MAX {
        return None;
    }
    let texte = std::str::from_utf8(octets).ok()?;
    let texte = texte.strip_prefix('\u{feff}').unwrap_or(texte);
    (texte.lines().count() <= LIGNES_MAX).then_some(texte)
}

/// Ce que dit le fichier `release` d'une installation de Java.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Release {
    /// `JAVA_VERSION`, telle quelle (« 21.0.13 », « 1.8.0_511 »).
    pub version: String,
    /// `IMPLEMENTOR` (« Eclipse Adoptium ») ; absent chez certains éditeurs.
    pub implementor: Option<String>,
    /// `OS_ARCH` (« amd64 », « aarch64 »).
    pub arch: Option<String>,
}

/// Les lignes `CLE="valeur"` d'un fichier `release` ; la première occurrence d'une clé compte. `None` sans
/// `JAVA_VERSION` : ce n'est pas un fichier de Java.
pub(crate) fn release(texte: &str) -> Option<Release> {
    let valeur = |cle: &str| {
        texte.lines().find_map(|ligne| {
            let (k, v) = ligne.trim().split_once('=')?;
            if k.trim() != cle {
                return None;
            }
            let v = v.trim();
            let v = v.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(v);
            (!v.is_empty() && v.len() <= VALEUR_MAX && !v.contains('"')).then(|| v.to_string())
        })
    };
    Some(Release {
        version: valeur("JAVA_VERSION")?,
        implementor: valeur("IMPLEMENTOR"),
        arch: valeur("OS_ARCH"),
    })
}

#[cfg_attr(target_os = "macos", allow(dead_code))] // lu par l'inventaire de Windows
/// La version écrite dans `application.ini` de Firefox : clé `Version` de la section `[App]` (une autre section,
/// `[Gecko]`, a aussi des versions, qui ne sont pas celle de Firefox).
pub(crate) fn application_ini(texte: &str) -> Option<String> {
    let mut section = "";
    for ligne in texte.lines() {
        let ligne = ligne.trim();
        if ligne.starts_with(';') || ligne.starts_with('#') {
            continue;
        }
        if let Some(nom) = ligne.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = nom.trim();
            continue;
        }
        if section != "App" {
            continue;
        }
        if let Some((cle, valeur)) = ligne.split_once('=')
            && cle.trim() == "Version"
        {
            let valeur = valeur.trim();
            return (!valeur.is_empty() && valeur.len() <= 64).then(|| valeur.to_string());
        }
    }
    None
}

/// Une chaîne JavaScript en tête de `texte` (guillemets doubles ou simples, sans échappement), et ce qui la suit.
fn chaine(texte: &str) -> Option<(&str, &str)> {
    let texte = texte.trim_start();
    let guillemet = texte.chars().next().filter(|c| matches!(c, '"' | '\''))?;
    let reste = &texte[1..];
    let fin = reste.find(guillemet)?;
    let contenu = &reste[..fin];
    (!contenu.contains('\\')).then_some((contenu, &reste[fin + 1..]))
}

/// Le canal de mise à jour de Firefox écrit dans `defaults/pref/channel-prefs.js` :
/// `pref("app.update.channel", "esr");`. Un nom fait de lettres, chiffres et tirets seulement.
pub(crate) fn canal_prefs(texte: &str) -> Option<String> {
    for ligne in texte.lines() {
        let ligne = ligne.trim();
        let Some(reste) = ligne.strip_prefix("pref(").or_else(|| ligne.strip_prefix("lockPref(")) else {
            continue;
        };
        let Some((cle, reste)) = chaine(reste) else {
            continue;
        };
        if cle != "app.update.channel" {
            continue;
        }
        let (canal, reste) = chaine(reste.trim_start().strip_prefix(',')?)?;
        let bon = !canal.is_empty()
            && canal.len() <= 32
            && canal
                .bytes()
                .all(|o| o.is_ascii_alphanumeric() || o == b'-' || o == b'_')
            && reste.trim_start().starts_with(')');
        return bon.then(|| canal.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_de_java() {
        let temurin = "IMPLEMENTOR=\"Eclipse Adoptium\"\nIMPLEMENTOR_VERSION=\"Temurin-21.0.13+9\"\n\
                       JAVA_RUNTIME_VERSION=\"21.0.13+9-LTS\"\nJAVA_VERSION=\"21.0.13\"\n\
                       JAVA_VERSION_DATE=\"2026-10-20\"\nOS_ARCH=\"x86_64\"\nOS_NAME=\"Windows\"\n";
        let r = release(temurin).unwrap();
        assert_eq!(r.version, "21.0.13");
        assert_eq!(r.implementor.as_deref(), Some("Eclipse Adoptium"));
        assert_eq!(r.arch.as_deref(), Some("x86_64"));
        // Java 8 d'Oracle : pas d'IMPLEMENTOR.
        let r = release("JAVA_VERSION=\"1.8.0_511\"\r\nOS_ARCH=\"amd64\"\r\n").unwrap();
        assert_eq!((r.version.as_str(), r.implementor), ("1.8.0_511", None));
        assert!(release("IMPLEMENTOR=\"Eclipse Adoptium\"\n").is_none());
        assert!(release("JAVA_VERSION=\"\"\n").is_none());
        assert!(release(&format!("JAVA_VERSION=\"{}\"\n", "1".repeat(300))).is_none());
        // La première occurrence compte.
        assert_eq!(
            release("JAVA_VERSION=\"17\"\nJAVA_VERSION=\"99\"").unwrap().version,
            "17"
        );
    }

    #[test]
    fn version_de_firefox() {
        let ini = "[App]\nVendor=Mozilla\nName=Firefox\nVersion=158.0.1\nBuildID=20261020000000\n\
                   [Gecko]\nMinVersion=158.0.1\nMaxVersion=158.0.1\n";
        assert_eq!(application_ini(ini).as_deref(), Some("158.0.1"));
        assert_eq!(
            application_ini("[Gecko]\nVersion=1.0\n[App]\n; Version=2\nVersion = 153.5.1esr\n").as_deref(),
            Some("153.5.1esr")
        );
        assert_eq!(application_ini("[Gecko]\nVersion=1.0\n"), None);
        assert_eq!(application_ini("Version=1.0\n"), None);
        assert_eq!(application_ini("[App]\nVersion=\n"), None);
    }

    #[test]
    fn canal_de_firefox() {
        assert_eq!(
            canal_prefs("// commentaire\npref(\"app.update.channel\", \"esr\");\n").as_deref(),
            Some("esr")
        );
        assert_eq!(
            canal_prefs("pref('app.update.channel','release');").as_deref(),
            Some("release")
        );
        assert_eq!(canal_prefs("//pref(\"app.update.channel\", \"esr\");"), None);
        assert_eq!(canal_prefs("pref(\"app.update.other\", \"esr\");"), None);
        assert_eq!(canal_prefs("pref(\"app.update.channel\", \"e\\\"sr\");"), None);
        assert_eq!(canal_prefs("pref(\"app.update.channel\", \"esr; rm\");"), None);
        assert_eq!(canal_prefs("pref(\"app.update.channel\", \"esr\""), None);
        assert_eq!(canal_prefs("pref(\"app.update.channel\""), None);
    }

    #[test]
    fn bornes_du_texte() {
        assert_eq!(texte(b"\xef\xbb\xbfJAVA_VERSION=\"17\""), Some("JAVA_VERSION=\"17\""));
        assert!(texte(&vec![b'a'; TAILLE_MAX + 1]).is_none());
        assert!(texte("a\n".repeat(LIGNES_MAX + 1).as_bytes()).is_none());
        assert!(texte(b"\xff\xfe").is_none());
        let d = crate::essais::temporaire().join(format!("vanguard-lecteurs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("release");
        std::fs::write(&f, "JAVA_VERSION=\"17\"\n").unwrap();
        assert_eq!(texte_borne(&f).as_deref(), Some("JAVA_VERSION=\"17\"\n"));
        assert!(texte_borne(&d).is_none(), "un dossier n'est pas lu");
        assert!(texte_borne(&d.join("absent")).is_none());
        std::fs::write(&f, vec![b'a'; TAILLE_MAX + 10]).unwrap();
        assert!(texte_borne(&f).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..400)) {
            let s = String::from_utf8_lossy(&octets);
            let _ = texte(&octets);
            let _ = release(&s);
            let _ = application_ini(&s);
            let _ = canal_prefs(&s);
        }

        #[test]
        fn formes_proches(s in "(\\[App\\]|Version|=|pref\\(|lockPref\\(|\"|'|,|\\)|app\\.update\\.channel|JAVA_VERSION|\\n| |é|\\\\){0,40}") {
            let _ = release(&s);
            let _ = application_ini(&s);
            let _ = canal_prefs(&s);
        }
    }
}
