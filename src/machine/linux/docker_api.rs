//! Docker par son API locale (/var/run/docker.sock, lecture seule) au lieu de la CLI : les conteneurs actifs et leurs
//! ports publiés (GET /containers/json), les images (GET /images/json).
//!
//! La CLI de la personne suit DOCKER_HOST et les contextes (Docker sans root, hôte distant) : lire la prise par défaut
//! quand le démon est ailleurs dirait « aucun conteneur exposé » à tort. Un démon désigné par une variable
//! (DOCKER_HOST, DOCKER_CONTEXT, DOCKER_CONFIG) ou par le config.json de la maison (un contexte choisi) n'est pas lu :
//! il est dit non vérifié (`demon_designe`, E-4 et N-2 des recontrôles 0.95). Vanguard ne le suit pas, ni par l'API ni
//! par sa CLI, lancée sans les variables du compte (`commande::par_le_systeme`) et sur la prise par défaut.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::http_unix::get_json;
use crate::modele::Echec;

pub(crate) const PRISE: &str = "/var/run/docker.sock";

/// Ce qui désigne un autre démon que celui de la prise par défaut, nommé dans le non vérifié : une variable de
/// Vanguard (DOCKER_HOST ; DOCKER_CONTEXT autre que « default » ; DOCKER_CONFIG dont le config.json choisit un autre
/// contexte, est illisible ou relatif) ou, sans DOCKER_CONFIG, le config.json de la maison (`CONFIG_DE_LA_MAISON` :
/// un `currentContext`, clé lue sans la casse comme la CLI, autre que « default », un fichier illisible, ou pas de
/// maison connue : HOME relatif, ou base des comptes muette). La CLI de la personne lirait ce démon-là. Vanguard ne
/// le suit pas, c'est voulu : une variable ou un fichier que le compte écrit choisirait le démon qui répond, et un faux
/// démon dirait « rien d'exposé » (G-1). Il est dit non vérifié, jamais remplacé par la lecture d'un autre démon
/// (E-4, recontrôle 0.95). Le fichier de la maison passait par la CLI, qui suivait son contexte : la même porte que
/// les variables (N-2, recontrôle 2 de la 0.95).
pub(crate) fn demon_designe() -> Option<&'static str> {
    demon_designe_dans(
        &|n| std::env::var_os(n),
        crate::socle::personnel::dossier_personnel_de(crate::socle::uid()),
    )
}

/// Le config.json de la maison, tel que le non vérifié le nomme.
pub(crate) const CONFIG_DE_LA_MAISON: &str = "~/.docker/config.json";

/// `demon_designe`, les variables lues par `lire` (HOME compris), `compte` la maison de la base des comptes.
fn demon_designe_dans(lire: Lire<'_>, compte: Option<PathBuf>) -> Option<&'static str> {
    if let Some(variable) = designe_par_variable(lire) {
        return Some(variable);
    }
    if reglee(lire, "DOCKER_CONFIG").is_some() {
        // Son config.json laisse le contexte par défaut (`designe_par_variable`) : la CLI de la personne ne lit pas
        // celui de la maison.
        return None;
    }
    maison_de_la_cli(lire, compte)
        .is_none_or(|m| !config_par_defaut(&m.join(".docker")))
        .then_some(CONFIG_DE_LA_MAISON)
}

/// La maison où la CLI de la personne cherche ~/.docker : HOME tel qu'il est dès qu'il n'est pas vide
/// (`os.UserHomeDir`), sinon celle de la base des comptes (`user.Current`). Un HOME relatif se lit depuis le dossier
/// courant de la CLI, inconnu ici : aucune maison connue. `dossier_personnel` prenait alors la base des comptes, et
/// Vanguard lisait un autre config.json que la CLI (V-1, relecture du sous-lot c2 de la 0.95).
fn maison_de_la_cli(lire: Lire<'_>, compte: Option<PathBuf>) -> Option<PathBuf> {
    match reglee(lire, "HOME") {
        Some(home) => Some(PathBuf::from(home)),
        None => compte,
    }
    .filter(|m| m.is_absolute())
}

/// Une variable de Docker lue par `lire` (l'environnement, ou celui d'un essai).
type Lire<'a> = &'a dyn Fn(&str) -> Option<OsString>;

/// La variable réglée, ou `None` : comme la CLI (`os.Getenv(…) != ""`), toute valeur non vide compte, même non UTF-8 ou
/// faite de blancs (N-6, recontrôle 2 de la 0.95). Lue par `std::env::var` puis `trim`, elle passait pour absente, et
/// le démon désigné pour celui de la prise par défaut.
fn reglee(lire: Lire<'_>, nom: &str) -> Option<OsString> {
    lire(nom).filter(|v| !v.is_empty())
}

/// Le config.json du dossier que nomme DOCKER_CONFIG laisse-t-il le contexte par défaut ? Un chemin relatif (des
/// blancs, « docker-conf ») se lit depuis le dossier courant de la CLI de la personne, qu'on ne connaît pas : non plus.
fn config_reglee_par_defaut(config: &OsString) -> bool {
    let config = Path::new(config);
    config.is_absolute() && config_par_defaut(config)
}

/// La variable de Docker qui désigne un autre démon (`demon_designe`), lue par `lire`.
fn designe_par_variable(lire: Lire<'_>) -> Option<&'static str> {
    if reglee(lire, "DOCKER_HOST").is_some() {
        return Some("DOCKER_HOST");
    }
    if reglee(lire, "DOCKER_CONTEXT").is_some_and(|c| c != "default") {
        return Some("DOCKER_CONTEXT");
    }
    reglee(lire, "DOCKER_CONFIG")
        .is_some_and(|c| !config_reglee_par_defaut(&c))
        .then_some("DOCKER_CONFIG")
}

/// Le démon que la CLI de la personne viserait est-il celui de la prise par défaut ? Seulement si rien n'en désigne un
/// autre (`demon_designe`) ; config.json illisible (mais présent) : on ne sait pas, non.
pub(crate) fn hote_par_defaut() -> bool {
    demon_designe().is_none()
}

/// Le config.json du dossier `config` laisse-t-il le contexte par défaut ? Absent : oui. Lu comme un simple fichier,
/// borné : un tube nommé posé à sa place figeait la lecture ; illisible, c'est « on ne sait pas ».
fn config_par_defaut(config: &std::path::Path) -> bool {
    match crate::socle::lire_texte_ordinaire(&config.join("config.json"), 1 << 20) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
        Ok(t) => contexte_par_defaut(&t),
    }
}

/// config.json sans contexte courant, ou avec « default ». La CLI (Go, `encoding/json`) prend la clé sans tenir compte
/// de la casse (« currentcontext », « CURRENTCONTEXT »), garde la dernière valeur texte d'un doublon et passe un
/// `null` ; serde_json, lui, ne garde que la dernière clé exacte. Chaque clé, doublons compris, est donc lue : une
/// seule qui ne vaut ni `null`, ni « », ni « default » (un autre type compris : on ne sait pas ce que la CLI en
/// garde) désigne le démon (V-1, relecture du sous-lot c2 de la 0.95). Les lettres de « currentcontext » n'ont pas
/// d'équivalent hors ASCII dans le pliage de Go (seuls k, s et i en ont) : la casse ASCII suffit. JSON illisible : on
/// ne sait pas, non ; un JSON qui n'est pas un objet, la CLI le refuse et garde le contexte par défaut.
fn contexte_par_defaut(config: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(config) {
        Ok(v) if !v.is_object() => true,
        Ok(_) => serde_json::from_str::<Paires>(config).is_ok_and(|Paires(paires)| {
            paires
                .iter()
                .filter(|(cle, _)| cle.eq_ignore_ascii_case("currentContext"))
                .all(|(_, c)| c.is_null() || c.as_str().is_some_and(|c| c.is_empty() || c == "default"))
        }),
        Err(_) => false,
    }
}

/// Les paires d'un objet JSON dans l'ordre, doublons compris, que `serde_json::Value` fond en une seule.
struct Paires(Vec<(String, serde_json::Value)>);

impl<'de> serde::Deserialize<'de> for Paires {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visiteur;
        impl<'de> serde::de::Visitor<'de> for Visiteur {
            type Value = Paires;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("un objet JSON")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut objet: A) -> Result<Paires, A::Error> {
                let mut paires = Vec::new();
                while let Some(paire) = objet.next_entry()? {
                    paires.push(paire);
                }
                Ok(Paires(paires))
            }
        }
        d.deserialize_map(Visiteur)
    }
}

/// Le préfixe de version de l'API (« /v1.47 ») d'après GET /version ; les chemins sans version sont dépréciés.
fn version(prise: &Path) -> Result<String, Echec> {
    let v = get_json(prise, "/version")?;
    let n = v
        .get("ApiVersion")
        .and_then(serde_json::Value::as_str)
        .filter(|n| !n.is_empty() && n.len() <= 10 && n.bytes().all(|o| o.is_ascii_digit() || o == b'.'))
        .ok_or_else(|| Echec::echoue("docker", "ApiVersion"))?;
    Ok(format!("/v{n}"))
}

/// Les ports publiés d'un conteneur (PortSummary) joignables depuis le réseau : tout sauf la boucle locale
/// (127.x, ::1) ; sans adresse, publié sur toutes. « 8080/tcp », prêts à montrer, sans doublon.
fn ports_exposes(ports: &serde_json::Value) -> Vec<String> {
    let mut v: Vec<String> = ports
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| {
            let public = p.get("PublicPort")?.as_u64()?;
            let ip = p.get("IP").and_then(serde_json::Value::as_str).unwrap_or("");
            let locale = ip.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback());
            let proto = p.get("Type").and_then(serde_json::Value::as_str).unwrap_or("tcp");
            (!locale).then(|| crate::ui::affichable(&format!("{public}/{proto}")))
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Les conteneurs actifs : (nom, ports exposés au réseau).
pub(crate) fn conteneurs_sur(prise: &Path) -> Result<Vec<(String, Vec<String>)>, Echec> {
    let prefixe = version(prise)?;
    let liste = get_json(prise, &format!("{prefixe}/containers/json"))?;
    let liste = liste
        .as_array()
        .ok_or_else(|| Echec::echoue("docker", "liste attendue"))?;
    Ok(liste
        .iter()
        .map(|c| {
            let nom = c
                .get("Names")
                .and_then(|n| n.get(0))
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || {
                        c.get("Id")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("?")
                            .chars()
                            .take(12)
                            .collect()
                    },
                    |n| n.trim_start_matches('/').to_string(),
                );
            (
                crate::ui::affichable(&nom),
                ports_exposes(c.get("Ports").unwrap_or(&serde_json::Value::Null)),
            )
        })
        .collect())
}

/// Les images étiquetées (« dépôt:étiquette »), comme `docker image ls --format {{.Repository}}:{{.Tag}}` sans
/// les « `<none>` ».
pub(crate) fn images_sur(prise: &Path) -> Result<Vec<String>, Echec> {
    let prefixe = version(prise)?;
    let liste = get_json(prise, &format!("{prefixe}/images/json"))?;
    let mut images: Vec<String> = liste
        .as_array()
        .ok_or_else(|| Echec::echoue("docker", "liste attendue"))?
        .iter()
        .flat_map(|i| {
            i.get("RepoTags")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|t| t.as_str().map(String::from))
        .filter(|t| !t.contains("<none>"))
        .collect();
    images.sort();
    images.dedup();
    Ok(images)
}

#[cfg(test)]
mod tests {
    use super::super::http_unix::essais::faux_demon;
    use super::*;

    /// Un tube nommé à la place de config.json : la lecture ne se fige pas, et le démon n'est pas dit « par défaut ».
    #[test]
    fn config_en_tube_ne_fige_pas() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        assert!(config_par_defaut(&d));
        crate::essais::tube_nomme(&d.join("config.json")).unwrap();
        assert!(!config_par_defaut(&d));
        let _ = std::fs::remove_dir_all(&d);
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::write(d.join("config.json"), br#"{"currentContext":"distant"}"#).unwrap();
        assert!(!config_par_defaut(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    fn reponse(json: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{json}", json.len()).into_bytes()
    }

    #[test]
    fn conteneurs_et_images_par_un_faux_demon() {
        let conteneurs = r#"[{"Id":"0123456789abcdef","Names":["/salon"],"Ports":[
            {"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},
            {"IP":"::","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},
            {"IP":"127.0.0.1","PrivatePort":3389,"PublicPort":3389,"Type":"tcp"},
            {"PrivatePort":53,"Type":"udp"}]},
            {"Id":"fedcba9876543210ff","Ports":[{"PrivatePort":1,"PublicPort":5353,"Type":"udp"}]}]"#;
        let images = r#"[{"RepoTags":["nginx:1.27","nginx:latest"]},{"RepoTags":["<none>:<none>"]},{"RepoTags":null}]"#;
        let (prise, fil) = faux_demon(
            "docker",
            vec![
                reponse(r#"{"ApiVersion":"1.47"}"#),
                reponse(conteneurs),
                reponse(r#"{"ApiVersion":"1.47"}"#),
                reponse(images),
            ],
        );
        let c = conteneurs_sur(&prise).unwrap();
        assert_eq!(
            c,
            [
                ("salon".to_string(), vec!["8080/tcp".to_string()]),
                ("fedcba987654".to_string(), vec!["5353/udp".to_string()])
            ]
        );
        assert_eq!(images_sur(&prise).unwrap(), ["nginx:1.27", "nginx:latest"]);
        let demandes = fil.join().unwrap();
        assert!(
            demandes[1].starts_with("GET /v1.47/containers/json "),
            "{}",
            demandes[1]
        );
        // Une version piégée n'entre pas dans le chemin.
        let (prise, _) = faux_demon("docker-piege", vec![reponse(r#"{"ApiVersion":"1.4/../x"}"#)]);
        assert!(conteneurs_sur(&prise).is_err());
        // Pas de démon : une erreur, jamais une liste vide.
        assert!(conteneurs_sur(Path::new("/nonexistent/docker.sock")).is_err());
    }

    /// N-6 (recontrôle 2 de la 0.95) : la CLI tient une variable pour réglée dès qu'elle n'est pas vide
    /// (`os.Getenv(…) != ""`). Lue par `std::env::var` puis `trim`, une valeur non UTF-8 ou faite de blancs passait
    /// pour absente : le démon désigné était lu comme celui de la prise par défaut.
    #[test]
    fn variable_reglee_des_qu_elle_n_est_pas_vide() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let env = |paires: Vec<(&'static str, OsString)>| {
            move |n: &str| paires.iter().find(|(k, _)| *k == n).map(|(_, v)| v.clone())
        };
        let non_utf8 = || OsString::from_vec(b"unix:///run/user/1000/docker\xff.sock".to_vec());
        assert_eq!(designe_par_variable(&env(vec![])), None);
        // Vide : absente, pour la CLI comme ici.
        for nom in ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"] {
            assert_eq!(designe_par_variable(&env(vec![(nom, OsString::new())])), None, "{nom}");
        }
        assert_eq!(
            designe_par_variable(&env(vec![("DOCKER_CONTEXT", "default".into())])),
            None
        );
        for v in [non_utf8(), "  ".into(), "\t".into()] {
            assert_eq!(
                designe_par_variable(&env(vec![("DOCKER_HOST", v.clone())])),
                Some("DOCKER_HOST"),
                "{v:?}"
            );
            assert_eq!(
                designe_par_variable(&env(vec![("DOCKER_CONTEXT", v.clone())])),
                Some("DOCKER_CONTEXT"),
                "{v:?}"
            );
            assert!(
                demon_designe_dans(&env(vec![("DOCKER_HOST", v.clone())]), None) == Some("DOCKER_HOST"),
                "{v:?}"
            );
            assert!(
                demon_designe_dans(&env(vec![("DOCKER_CONTEXT", v.clone())]), None) == Some("DOCKER_CONTEXT"),
                "{v:?}"
            );
        }
        // DOCKER_CONFIG au nom non UTF-8 : son config.json est lu quand même.
        let d = crate::essais::Jetable::nouveau("n6-docker-config");
        let config = d.join(std::ffi::OsStr::from_bytes(b"config\xff"));
        std::fs::create_dir(&config).unwrap();
        let reglage = || vec![("DOCKER_CONFIG", config.clone().into_os_string())];
        assert_eq!(designe_par_variable(&env(reglage())), None);
        assert_eq!(demon_designe_dans(&env(reglage()), None), None);
        std::fs::write(config.join("config.json"), br#"{"currentContext":"temoin"}"#).unwrap();
        assert_eq!(designe_par_variable(&env(reglage())), Some("DOCKER_CONFIG"));
        assert_eq!(demon_designe_dans(&env(reglage()), None), Some("DOCKER_CONFIG"));
        // Relatif (blancs compris) : la CLI de la personne le lit depuis son dossier courant, inconnu ici.
        for v in ["  ", "docker-conf"] {
            assert_eq!(
                designe_par_variable(&env(vec![("DOCKER_CONFIG", v.into())])),
                Some("DOCKER_CONFIG"),
                "{v:?}"
            );
            assert!(
                demon_designe_dans(&env(vec![("DOCKER_CONFIG", v.into())]), None) == Some("DOCKER_CONFIG"),
                "{v:?}"
            );
        }
    }

    /// N-2 (recontrôle 2 de la 0.95) : sans DOCKER_CONFIG, la CLI de la personne prend son contexte dans le config.json
    /// de la maison, un fichier que le compte écrit. Un contexte autre que « default », un fichier illisible ou pas de
    /// maison connue : le démon est désigné, nommé dans le non vérifié, comme pour une variable.
    #[test]
    fn config_de_la_maison_designe_le_demon() {
        let rien = |_: &str| None;
        let m = crate::essais::Jetable::nouveau("n2-docker-maison");
        let maison = || Some(m.to_path_buf());
        assert_eq!(demon_designe_dans(&rien, maison()), None, "sans config.json");
        std::fs::create_dir(m.join(".docker")).unwrap();
        let config = m.join(".docker").join("config.json");
        for (texte, attendu) in [
            ("{}", None),
            (r#"{"currentContext":"default"}"#, None),
            (r#"{"currentContext":""}"#, None),
            (r#"{"currentContext":"temoin"}"#, Some(CONFIG_DE_LA_MAISON)),
            ("{pas du json", Some(CONFIG_DE_LA_MAISON)),
        ] {
            std::fs::write(&config, texte).unwrap();
            assert_eq!(demon_designe_dans(&rien, maison()), attendu, "{texte}");
        }
        // Une variable passe avant, et se nomme elle-même.
        let hote = |n: &str| (n == "DOCKER_HOST").then(|| OsString::from("unix:///run/temoin.sock"));
        assert_eq!(demon_designe_dans(&hote, maison()), Some("DOCKER_HOST"));
        // DOCKER_CONFIG nomme un dossier au contexte par défaut : c'est lui que la CLI de la personne lit, pas la maison.
        let vide = crate::essais::Jetable::nouveau("n2-docker-config");
        let config_vide = |n: &str| (n == "DOCKER_CONFIG").then(|| vide.as_os_str().to_os_string());
        assert_eq!(demon_designe_dans(&config_vide, maison()), None);
        // Pas de maison connue : on ne sait pas quel fichier la CLI lirait.
        assert_eq!(demon_designe_dans(&rien, None), Some(CONFIG_DE_LA_MAISON));
        // Un tube nommé à la place du fichier : illisible, jamais attendu, et on ne sait pas.
        std::fs::remove_file(&config).unwrap();
        crate::essais::tube_nomme(&config).unwrap();
        assert_eq!(demon_designe_dans(&rien, maison()), Some(CONFIG_DE_LA_MAISON));
    }

    /// V-1 (relecture du sous-lot c2 de la 0.95) : la CLI (Go, `encoding/json`) prend la clé du contexte sans la casse,
    /// garde la dernière valeur texte et passe un `null` ; elle cherche ~/.docker dans HOME tel qu'il est, même
    /// relatif (depuis son dossier courant). Vanguard lisait la seule clé exacte, la dernière d'un doublon, et la
    /// maison de la base des comptes : il croyait le contexte par défaut, et le démon de la personne était lu comme sain.
    #[test]
    fn cle_et_maison_lues_comme_la_cli() {
        for (texte, defaut) in [
            // Ce que la CLI 29.9 lit « temoin » (rejoué à la main avec `docker context show`).
            (r#"{"currentcontext":"temoin"}"#, false),
            (r#"{"currentContext":"default","CURRENTCONTEXT":"temoin"}"#, false),
            (r#"{"currentContext":"temoin","currentContext":null}"#, false),
            (r#"{"currentContext":5,"CurrentContext":"temoin"}"#, false),
            (r#"{"currentContext":"temoin"}"#, false),
            // Une valeur qui n'est pas du texte : on ne sait pas ce que la CLI en garde.
            (r#"{"CurrentContext":["temoin"]}"#, false),
            // Ce qu'elle lit « default ».
            (r#"{"currentContext":null}"#, true),
            (r#"{"CURRENTCONTEXT":"default","currentcontext":""}"#, true),
            (r#"{"autre":"temoin","currentContextX":"temoin"}"#, true),
        ] {
            assert_eq!(contexte_par_defaut(texte), defaut, "{texte}");
        }
        let vide = crate::essais::Jetable::nouveau("v1-docker-compte");
        let choisie = crate::essais::Jetable::nouveau("v1-docker-home");
        std::fs::create_dir(choisie.join(".docker")).unwrap();
        std::fs::write(
            choisie.join(".docker").join("config.json"),
            br#"{"currentContext":"temoin"}"#,
        )
        .unwrap();
        let avec_home = |home: OsString| move |n: &str| (n == "HOME").then(|| home.clone());
        let compte = |d: &crate::essais::Jetable| Some(d.to_path_buf());
        // HOME relatif : la CLI lit « rel/.docker » depuis un dossier courant inconnu ici, jamais la base des comptes.
        assert_eq!(
            demon_designe_dans(&avec_home("rel".into()), compte(&vide)),
            Some(CONFIG_DE_LA_MAISON)
        );
        // HOME complet : c'est lui que la CLI lit, pas la maison de la base des comptes.
        assert_eq!(
            demon_designe_dans(&avec_home(choisie.as_os_str().to_os_string()), compte(&vide)),
            Some(CONFIG_DE_LA_MAISON)
        );
        assert_eq!(
            demon_designe_dans(&avec_home(vide.as_os_str().to_os_string()), compte(&choisie)),
            None
        );
        // HOME vide ou absent : la CLI prend la maison de la base des comptes, comme ici.
        assert_eq!(demon_designe_dans(&avec_home(OsString::new()), compte(&vide)), None);
        assert_eq!(
            demon_designe_dans(&avec_home(OsString::new()), compte(&choisie)),
            Some(CONFIG_DE_LA_MAISON)
        );
    }

    #[test]
    fn contexte_de_la_cli() {
        assert!(contexte_par_defaut("{}"));
        assert!(contexte_par_defaut(r#"{"currentContext":"default"}"#));
        assert!(!contexte_par_defaut(r#"{"currentContext":"rootless"}"#));
        assert!(!contexte_par_defaut("pas du json"));
    }
}
