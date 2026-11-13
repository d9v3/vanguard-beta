//! Docker par son API locale (/var/run/docker.sock, lecture seule) au lieu de la CLI : les conteneurs actifs et leurs
//! ports publiés (GET /containers/json), les images (GET /images/json).
//!
//! La CLI suit DOCKER_HOST et les contextes (Docker sans root, hôte distant) : lire la prise par défaut quand le
//! démon est ailleurs dirait « aucun conteneur exposé » à tort. Un contexte choisi dans ~/.docker/config.json : la
//! CLI reste la source (`hote_par_defaut`), elle le lit par HOME. Un démon désigné par une variable (DOCKER_HOST,
//! DOCKER_CONTEXT, DOCKER_CONFIG) : la CLI, lancée sans les variables du compte (`commande::par_le_systeme`), ne le
//! verrait pas ; il est dit non vérifié (`demon_designe_par_variable`, E-4 du recontrôle 0.95).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::http_unix::get_json;
use crate::modele::Echec;

pub(crate) const PRISE: &str = "/var/run/docker.sock";

/// La variable de Vanguard qui désigne un autre démon que celui de la prise par défaut : DOCKER_HOST, DOCKER_CONTEXT
/// autre que « default », ou DOCKER_CONFIG dont le config.json choisit un autre contexte (ou est illisible). La CLI,
/// lancée sans les variables du compte, lirait alors un autre démon que celui de la personne : à dire non vérifié,
/// jamais à remplacer par la lecture d'un autre démon (E-4, recontrôle 0.95). Ne pas les passer à la CLI est voulu :
/// une variable posée par un programme du compte choisirait le démon qui répond, et un faux démon dirait « rien
/// d'exposé » (G-1).
pub(crate) fn demon_designe_par_variable() -> Option<&'static str> {
    designe_par_variable(&|n| std::env::var_os(n))
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

/// `demon_designe_par_variable`, les variables lues par `lire`.
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

/// Le démon que la CLI viserait est-il celui de la prise par défaut ? Non dès que DOCKER_HOST, DOCKER_CONTEXT ou un
/// contexte courant (`currentContext` de config.json) autre que « default » est réglé ; config.json illisible (mais
/// présent) : on ne sait pas, non plus.
pub(crate) fn hote_par_defaut() -> bool {
    hote_par_defaut_dans(&|n| std::env::var_os(n), crate::socle::personnel::dossier_personnel())
}

/// `hote_par_defaut`, les variables lues par `lire`, `maison` le dossier personnel.
fn hote_par_defaut_dans(lire: Lire<'_>, maison: Option<PathBuf>) -> bool {
    if reglee(lire, "DOCKER_HOST").is_some() || reglee(lire, "DOCKER_CONTEXT").is_some_and(|c| c != "default") {
        return false;
    }
    match reglee(lire, "DOCKER_CONFIG") {
        Some(config) => config_reglee_par_defaut(&config),
        None => maison.is_none_or(|m| config_par_defaut(&m.join(".docker"))),
    }
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

/// config.json sans contexte courant, ou avec « default ».
fn contexte_par_defaut(config: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(config) {
        Ok(v) => v
            .get("currentContext")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|c| c.is_empty() || c == "default"),
        Err(_) => false,
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
                !hote_par_defaut_dans(&env(vec![("DOCKER_HOST", v.clone())]), None),
                "{v:?}"
            );
            assert!(
                !hote_par_defaut_dans(&env(vec![("DOCKER_CONTEXT", v.clone())]), None),
                "{v:?}"
            );
        }
        // DOCKER_CONFIG au nom non UTF-8 : son config.json est lu quand même.
        let d = crate::essais::Jetable::nouveau("n6-docker-config");
        let config = d.join(std::ffi::OsStr::from_bytes(b"config\xff"));
        std::fs::create_dir(&config).unwrap();
        let reglage = || vec![("DOCKER_CONFIG", config.clone().into_os_string())];
        assert_eq!(designe_par_variable(&env(reglage())), None);
        assert!(hote_par_defaut_dans(&env(reglage()), None));
        std::fs::write(config.join("config.json"), br#"{"currentContext":"temoin"}"#).unwrap();
        assert_eq!(designe_par_variable(&env(reglage())), Some("DOCKER_CONFIG"));
        assert!(!hote_par_defaut_dans(&env(reglage()), None));
        // Relatif (blancs compris) : la CLI de la personne le lit depuis son dossier courant, inconnu ici.
        for v in ["  ", "docker-conf"] {
            assert_eq!(
                designe_par_variable(&env(vec![("DOCKER_CONFIG", v.into())])),
                Some("DOCKER_CONFIG"),
                "{v:?}"
            );
            assert!(
                !hote_par_defaut_dans(&env(vec![("DOCKER_CONFIG", v.into())]), None),
                "{v:?}"
            );
        }
    }

    #[test]
    fn contexte_de_la_cli() {
        assert!(contexte_par_defaut("{}"));
        assert!(contexte_par_defaut(r#"{"currentContext":"default"}"#));
        assert!(!contexte_par_defaut(r#"{"currentContext":"rootless"}"#));
        assert!(!contexte_par_defaut("pas du json"));
    }
}
