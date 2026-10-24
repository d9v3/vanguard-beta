//! Extensions de navigateur : une extension qui lit tous les sites voit tes mots de passe tapés, tes courriels et
//! ta banque. Beaucoup de vols de comptes passent par une extension rachetée ou installée en douce.
//! Navigateurs lus : famille Firefox (Firefox, Zen, LibreWolf, Floorp, Waterfox) et famille Chromium (Chrome,
//! Chromium, Brave, Edge, Vivaldi).

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::ui::affichable;
use crate::{tr, trf};

const CAT: &str = "Extensions";

/// Une extension installée et active.
#[derive(Debug, Default)]
struct Extension {
    /// Identifiant de l'extension dans le navigateur : la même extension peut figurer dans deux fichiers.
    id: String,
    nom: String,
    /// Accès à tous les sites.
    partout: bool,
    /// Pouvoirs particuliers : piloter les pages (debugger), parler aux programmes de l'ordinateur (nativeMessaging)…
    pouvoirs: Vec<&'static str>,
    /// Pourquoi son installation est inhabituelle (hors boutique, par un programme, non signée).
    origine_suspecte: Option<&'static str>,
}

fn acces_partout(motif: &str) -> bool {
    matches!(
        motif,
        "<all_urls>" | "*://*/*" | "http://*/*" | "https://*/*" | "*://*/" | "http://*/" | "https://*/"
    )
}

fn pouvoirs(permissions: &[&str]) -> Vec<&'static str> {
    let mut p = Vec::new();
    if permissions.contains(&"debugger") {
        p.push(tr!("piloter les pages", "control web pages"));
    }
    if permissions.contains(&"nativeMessaging") {
        p.push(tr!(
            "parler aux programmes de l'ordinateur",
            "talk to programs on the computer"
        ));
    }
    if permissions.contains(&"proxy") {
        p.push(tr!("détourner le trafic (proxy)", "reroute traffic (proxy)"));
    }
    if permissions.contains(&"management") {
        p.push(tr!("gérer les autres extensions", "manage other extensions"));
    }
    p
}

fn chaines(v: &Value) -> Vec<&str> {
    v.as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Extensions actives d'un `extensions.json` de la famille Firefox (installées par l'utilisateur seulement :
/// thèmes, dictionnaires et modules du navigateur exclus). Le nom, choisi par l'auteur de l'extension, est lu prêt
/// à montrer, comme dans la famille Chromium.
fn lire_firefox(texte: &str) -> Vec<Extension> {
    let Ok(json) = serde_json::from_str::<Value>(texte) else {
        return Vec::new();
    };
    let mut extensions = Vec::new();
    for a in json["addons"].as_array().into_iter().flatten() {
        if a["location"] != "app-profile" || a["type"] != "extension" || a["active"] != true {
            continue;
        }
        let permissions = chaines(&a["userPermissions"]["permissions"]);
        let origines = chaines(&a["userPermissions"]["origins"]);
        let origine_suspecte = if a["installTelemetryInfo"]["method"] == "sideload" {
            Some(tr!(
                "installée par un programme, sans passer par vous",
                "installed by a program, without going through you"
            ))
        } else if a["signedState"].as_i64().is_some_and(|s| s <= 0) {
            Some(tr!("non signée par Mozilla", "not signed by Mozilla"))
        } else {
            None
        };
        extensions.push(Extension {
            id: a["id"].as_str().unwrap_or_default().to_string(),
            nom: affichable(a["defaultLocale"]["name"].as_str().or(a["id"].as_str()).unwrap_or("?")),
            partout: origines.iter().any(|o| acces_partout(o)),
            pouvoirs: pouvoirs(&permissions),
            origine_suspecte,
        });
    }
    extensions
}

/// Nom affiché d'une extension Chromium : « __MSG_extName__ » se lit dans `_locales/<langue>/messages.json`. Prêt à
/// montrer : son auteur le choisit.
fn nom_chromium(manifeste: &Value, dossier: Option<&Path>) -> String {
    let brut = manifeste["name"].as_str().unwrap_or("?");
    let Some(cle) = brut.strip_prefix("__MSG_").and_then(|r| r.strip_suffix("__")) else {
        return affichable(brut);
    };
    let langue = manifeste["default_locale"].as_str().unwrap_or("en");
    dossier
        .and_then(|d| std::fs::read_to_string(d.join("_locales").join(langue).join("messages.json")).ok())
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|m| {
            m.as_object()?
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(cle))
                .and_then(|(_, v)| v["message"].as_str().map(affichable))
        })
        .unwrap_or_else(|| affichable(brut))
}

/// Extensions actives de `extensions.settings` (Preferences ou Secure Preferences d'un profil Chromium).
/// Emplacements : 1 boutique, 2-3 et 6 posées par un programme, 4 décompressée (mode développeur), 5 et 10
/// composants du navigateur, 7 et 9 politique d'entreprise, 8 ligne de commande.
fn lire_chromium(texte: &str, profil: &Path) -> Vec<Extension> {
    let Ok(json) = serde_json::from_str::<Value>(texte) else {
        return Vec::new();
    };
    let mut extensions = Vec::new();
    for (id, e) in json["extensions"]["settings"].as_object().into_iter().flatten() {
        let manifeste = &e["manifest"];
        let emplacement = e["location"].as_i64().unwrap_or(0);
        let desactivee = e["disable_reasons"].as_array().is_some_and(|r| !r.is_empty())
            || e["disable_reasons"].as_i64().is_some_and(|r| r != 0)
            || e["state"].as_i64() == Some(0);
        if manifeste.is_null() || matches!(emplacement, 5 | 10) || desactivee || manifeste["theme"].is_object() {
            continue;
        }
        let mut permissions = chaines(&manifeste["permissions"]);
        permissions.extend(chaines(&manifeste["host_permissions"]));
        let scripts_partout = manifeste["content_scripts"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|c| chaines(&c["matches"]).iter().any(|m| acces_partout(m)));
        let chemin = e["path"].as_str().map(|p| {
            let p = Path::new(p);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                profil.join("Extensions").join(p)
            }
        });
        let de_la_boutique = e["from_webstore"] == true;
        let origine_suspecte = match emplacement {
            4 => Some(tr!(
                "chargée hors boutique (mode développeur)",
                "loaded outside the store (developer mode)"
            )),
            8 => Some(tr!("chargée par la ligne de commande", "loaded from the command line")),
            2 | 3 | 6 if !de_la_boutique => Some(tr!(
                "installée par un programme, hors boutique",
                "installed by a program, outside the store"
            )),
            _ => None,
        };
        extensions.push(Extension {
            id: id.clone(),
            nom: nom_chromium(manifeste, chemin.as_deref()),
            partout: scripts_partout || permissions.iter().any(|p| acces_partout(p)),
            pouvoirs: pouvoirs(&permissions),
            origine_suspecte,
        });
    }
    extensions.sort_by_key(|e| e.nom.to_lowercase());
    extensions
}

/// Une seule fois chaque extension (par identifiant), triées par nom.
fn sans_doublons(mut extensions: Vec<Extension>) -> Vec<Extension> {
    extensions.sort_by(|a, b| a.id.cmp(&b.id));
    extensions.dedup_by(|a, b| a.id == b.id);
    extensions.sort_by_key(|e| e.nom.to_lowercase());
    extensions
}

/// Constats pour les extensions d'un profil.
fn juger(navigateur: &str, extensions: &[Extension]) -> Vec<Constat> {
    use crate::modele::Objet;
    let mut constats = Vec::new();
    for e in extensions {
        if let Some(raison) = e.origine_suspecte {
            let niveau = if e.partout { Niveau::Eleve } else { Niveau::Moyen };
            constats.push(
                alerte(
                    CAT,
                    niveau,
                    trf!(
                        "{navigateur} : extension « {} » {raison}{}. Retirez-la si vous ne l'avez pas installée vous-même.",
                        "{navigateur}: extension “{}” {raison}{}. Remove it if you did not install it yourself.",
                        e.nom,
                        if e.partout {
                            tr!(", avec accès à tous les sites", ", with access to every site")
                        } else {
                            ""
                        }
                    ),
                )
                // L'identifiant de l'extension, pas son nom (qu'elle choisit, et traduit) : une autre extension au même
                // nom reste un autre objet.
                .avec_objet(Objet::de("extension", &format!("{navigateur}/{}", e.id))),
            );
        }
    }
    let partout: Vec<&Extension> = extensions.iter().filter(|e| e.partout).collect();
    if partout.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "{navigateur} : {} extension(s), aucune n'a accès à tous les sites.",
                "{navigateur}: {} extension(s), none can access every site.",
                extensions.len()
            ),
        ));
        return constats;
    }
    let noms = partout
        .iter()
        .map(|e| {
            if e.pouvoirs.is_empty() {
                e.nom.clone()
            } else {
                format!("{} [{}]", e.nom, e.pouvoirs.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut ids: Vec<&str> = partout.iter().map(|e| e.id.as_str()).collect();
    ids.sort_unstable();
    constats.push(alerte(
        CAT,
        Niveau::Info,
        trf!(
            "{navigateur} : {} extension(s), dont {} avec accès à tous les sites : {noms}. Gardez seulement celles que vous utilisez et dont vous connaissez l'éditeur.",
            "{navigateur}: {} extension(s), {} of them with access to every site: {noms}. Keep only the ones you use and whose publisher you know.",
            extensions.len(),
            partout.len()
        ),
    )
    .avec_objet(Objet::de("partout", &format!("{navigateur}/{}", ids.join(",")))));
    constats
}

/// Dossiers racine des navigateurs : (nom, dossier, famille Firefox).
pub(crate) fn racines() -> Vec<(&'static str, PathBuf, bool)> {
    let mut r = Vec::new();
    #[cfg(target_os = "linux")]
    {
        let maison = crate::socle::maison();
        let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
        for (nom, d) in [
            ("Firefox", maison.join(".mozilla/firefox")),
            ("Firefox", config.join("mozilla/firefox")),
            ("Firefox", maison.join(".var/app/org.mozilla.firefox/.mozilla/firefox")),
            ("Zen", maison.join(".zen")),
            ("Zen", config.join("zen")),
            ("Zen", maison.join(".var/app/app.zen_browser.zen/.zen")),
            ("LibreWolf", maison.join(".librewolf")),
            ("Floorp", maison.join(".floorp")),
            ("Waterfox", maison.join(".waterfox")),
        ] {
            r.push((nom, d, true));
        }
        for (nom, d) in [
            ("Chrome", config.join("google-chrome")),
            ("Chrome", maison.join(".var/app/com.google.Chrome/config/google-chrome")),
            ("Chromium", config.join("chromium")),
            (
                "Chromium",
                maison.join(".var/app/org.chromium.Chromium/config/chromium"),
            ),
            ("Brave", config.join("BraveSoftware/Brave-Browser")),
            (
                "Brave",
                maison.join(".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"),
            ),
            ("Edge", config.join("microsoft-edge")),
            ("Vivaldi", config.join("vivaldi")),
        ] {
            r.push((nom, d, false));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let support = crate::socle::maison().join("Library/Application Support");
        for (nom, d) in [
            ("Firefox", support.join("Firefox/Profiles")),
            ("Zen", support.join("zen/Profiles")),
            ("LibreWolf", support.join("librewolf/Profiles")),
            ("Floorp", support.join("Floorp/Profiles")),
            ("Waterfox", support.join("Waterfox/Profiles")),
        ] {
            r.push((nom, d, true));
        }
        for (nom, d) in [
            ("Chrome", support.join("Google/Chrome")),
            ("Chromium", support.join("Chromium")),
            ("Brave", support.join("BraveSoftware/Brave-Browser")),
            ("Edge", support.join("Microsoft Edge")),
            ("Vivaldi", support.join("Vivaldi")),
        ] {
            r.push((nom, d, false));
        }
    }
    #[cfg(windows)]
    {
        let appdata = PathBuf::from(std::env::var_os("APPDATA").unwrap_or_default());
        let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default());
        for (nom, d) in [
            ("Firefox", appdata.join("Mozilla\\Firefox\\Profiles")),
            ("Zen", appdata.join("zen\\Profiles")),
            ("LibreWolf", appdata.join("librewolf\\Profiles")),
            ("Floorp", appdata.join("Floorp\\Profiles")),
            ("Waterfox", appdata.join("Waterfox\\Profiles")),
        ] {
            r.push((nom, d, true));
        }
        for (nom, d) in [
            ("Chrome", local.join("Google\\Chrome\\User Data")),
            ("Chromium", local.join("Chromium\\User Data")),
            ("Brave", local.join("BraveSoftware\\Brave-Browser\\User Data")),
            ("Edge", local.join("Microsoft\\Edge\\User Data")),
            ("Vivaldi", local.join("Vivaldi\\User Data")),
        ] {
            r.push((nom, d, false));
        }
    }
    r
}

/// Profils d'une racine : (nom du dossier, prêt à montrer ; chemin, tel quel), ceux qui contiennent le fichier
/// attendu.
pub(super) fn profils(racine: &Path, firefox: bool) -> Vec<(String, PathBuf)> {
    let mut p: Vec<(String, PathBuf)> = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| (affichable(&e.file_name().to_string_lossy()), e.path()))
        .filter(|(nom, chemin)| {
            if firefox {
                chemin.join("extensions.json").is_file()
            } else {
                (nom == "Default" || nom.starts_with("Profile ")) && chemin.join("Preferences").is_file()
            }
        })
        .collect();
    p.sort();
    p
}

pub fn extensions() -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut vus = Vec::new();
    for (nom, racine, firefox) in racines() {
        let liste = profils(&racine, firefox);
        let plusieurs = liste.len() > 1;
        for (dossier, chemin) in liste {
            // Le même profil peut être atteint par deux chemins (lien de ~/.zen vers ~/.config/zen).
            let reel = chemin.canonicalize().unwrap_or_else(|_| chemin.clone());
            if vus.contains(&reel) {
                continue;
            }
            vus.push(reel);
            let extensions = if firefox {
                lire_firefox(&std::fs::read_to_string(chemin.join("extensions.json")).unwrap_or_default())
            } else {
                // Windows range les extensions dans Secure Preferences, Linux dans Preferences. Une extension
                // inscrite dans les deux ne compte qu'une fois.
                let mut e = Vec::new();
                for f in ["Preferences", "Secure Preferences"] {
                    e.extend(lire_chromium(
                        &std::fs::read_to_string(chemin.join(f)).unwrap_or_default(),
                        &chemin,
                    ));
                }
                sans_doublons(e)
            };
            if extensions.is_empty() {
                continue;
            }
            // Profil nommé seulement s'il y en a plusieurs ; « ippds1dt.Default (release) » → « Default (release) ».
            let navigateur = if plusieurs {
                let court = dossier
                    .split_once('.')
                    .filter(|_| firefox)
                    .map_or(dossier.as_str(), |(_, n)| n);
                format!("{nom} ({court})")
            } else {
                nom.to_string()
            };
            constats.extend(juger(&navigateur, &extensions));
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucune extension de navigateur installée.",
                "No browser extension installed."
            ),
        ));
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_firefox() {
        let json = r#"{"addons":[
            {"id":"uBlock0@raymondhill.net","type":"extension","location":"app-profile","active":true,"signedState":2,
             "defaultLocale":{"name":"uBlock Origin"},"userPermissions":{"permissions":["storage"],"origins":["<all_urls>"]},
             "installTelemetryInfo":{"source":"amo"}},
            {"id":"x@y","type":"extension","location":"app-profile","active":true,"signedState":2,
             "defaultLocale":{"name":"Espion"},"userPermissions":{"permissions":["nativeMessaging"],"origins":["*://*/*"]},
             "installTelemetryInfo":{"source":"app-profile","method":"sideload"}},
            {"id":"fr@dict","type":"dictionary","location":"app-profile","active":true},
            {"id":"off@x","type":"extension","location":"app-profile","active":false},
            {"id":"sys@mozilla","type":"extension","location":"app-builtin","active":true}
        ]}"#;
        let e = lire_firefox(json);
        assert_eq!(e.len(), 2);
        assert!(e[0].partout && e[0].origine_suspecte.is_none());
        assert!(e[1].origine_suspecte.is_some() && e[1].pouvoirs.len() == 1);
        let c = juger("Zen", &e);
        assert_eq!(
            c.iter().map(|c| c.probleme).collect::<Vec<_>>(),
            [Some(Niveau::Eleve), Some(Niveau::Info)]
        );
        assert!(c[1].message.contains("Espion ["));
        assert!(lire_firefox("pas du json").is_empty());
    }

    #[test]
    fn extensions_chromium() {
        let json = r#"{"extensions":{"settings":{
            "a":{"location":1,"from_webstore":true,"disable_reasons":[],"path":"a/1.0_0",
                 "manifest":{"name":"Bitwarden","permissions":["tabs"],"host_permissions":["https://*/*"]}},
            "b":{"location":4,"path":"/home/alice/dev/ext","manifest":{"name":"Outil local","permissions":["storage"]}},
            "c":{"location":5,"manifest":{"name":"Chrome PDF Viewer"}},
            "d":{"location":1,"disable_reasons":[1],"manifest":{"name":"Désactivée","host_permissions":["<all_urls>"]}},
            "e":{"location":1,"manifest":{"name":"YouTube","content_scripts":[{"matches":["*://www.youtube.com/*"]}]}},
            "f":{"location":2,"from_webstore":false,"manifest":{"name":"Barre d'outils","content_scripts":[{"matches":["<all_urls>"]}]}},
            "g":{"location":1}
        }}}"#;
        let e = lire_chromium(json, Path::new("/profil"));
        let noms: Vec<&str> = e.iter().map(|e| e.nom.as_str()).collect();
        assert_eq!(noms, ["Barre d'outils", "Bitwarden", "Outil local", "YouTube"]);
        let c = juger("Chrome", &e);
        assert_eq!(
            c.iter().map(|c| c.probleme).collect::<Vec<_>>(),
            [Some(Niveau::Eleve), Some(Niveau::Moyen), Some(Niveau::Info)]
        );
        // La même extension dans Preferences et dans Secure Preferences : comptée une seule fois.
        let mut deux_fois = lire_chromium(json, Path::new("/profil"));
        deux_fois.extend(lire_chromium(json, Path::new("/profil")));
        let uniques: Vec<String> = sans_doublons(deux_fois).into_iter().map(|e| e.nom).collect();
        assert_eq!(uniques, noms);
        // Nom à traduire sans dossier de langues : le nom brut reste, sans planter.
        let m: Value = serde_json::from_str(r#"{"name":"__MSG_extName__"}"#).unwrap();
        assert_eq!(nom_chromium(&m, None), "__MSG_extName__");
    }

    /// Le nom d'une extension est choisi par son auteur, et celui d'un profil par qui l'a créé : piégés, ils arrivent
    /// inoffensifs dans les constats.
    #[test]
    fn noms_pieges() {
        let firefox = r#"{"addons":[{"id":"x@y","type":"extension","location":"app-profile","active":true,"signedState":2,
            "defaultLocale":{"name":"Espion\u001b]52;c;eA==\u0007\u001b[2K\r\u202e"},"userPermissions":{"origins":["<all_urls>"]},
            "installTelemetryInfo":{"method":"sideload"}}]}"#;
        let e = lire_firefox(firefox);
        assert_eq!(e[0].nom, "Espion�]52;c;eA==��[2K��");
        for c in juger("Firefox", &e) {
            assert!(!crate::ui::contient_un_piege(&c.message), "{}", c.message);
        }
        let chromium = r#"{"extensions":{"settings":{"a":{"location":4,"manifest":{"name":"Outil\u001b[8m\u2066"}}}}}"#;
        assert_eq!(lire_chromium(chromium, Path::new("/profil"))[0].nom, "Outil�[8m�");
    }

    /// Le nom d'un dossier de profil, montré quand il y en a plusieurs : inoffensif, le chemin restant le vrai. Windows
    /// refuse les caractères de contrôle dans un nom de fichier : essayé sous Linux et macOS.
    #[cfg(unix)]
    #[test]
    fn nom_de_profil_piege() {
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let profil = dossier.join("ab12.P\x1b]0;t\x07rofil\u{202e}");
        std::fs::create_dir_all(&profil).unwrap();
        std::fs::write(profil.join("extensions.json"), "{}").unwrap();
        let profils = profils(&dossier, true);
        assert_eq!(profils[0].0, "ab12.P�]0;t�rofil�");
        assert_eq!(profils[0].1, profil);
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// T4 : les mêmes clés en français et en anglais, une par extension suspecte et une pour l'accès partout.
    #[test]
    fn cles_sans_langue() {
        let json = r#"{"addons":[
            {"id":"x@y","type":"extension","location":"app-profile","active":true,"signedState":2,
             "defaultLocale":{"name":"Espion"},"userPermissions":{"permissions":["nativeMessaging"],"origins":["*://*/*"]},
             "installTelemetryInfo":{"source":"app-profile","method":"sideload"}},
            {"id":"uBlock0@raymondhill.net","type":"extension","location":"app-profile","active":true,"signedState":2,
             "defaultLocale":{"name":"uBlock Origin"},"userPermissions":{"permissions":["storage"],"origins":["<all_urls>"]},
             "installTelemetryInfo":{"source":"amo"}}
        ]}"#;
        let cles = crate::machine::controler_regle("COM-NAV-001", || juger("Zen", &lire_firefox(json)));
        assert_eq!(
            cles,
            [
                "COM-NAV-001|extension:Zen/x@y",
                "COM-NAV-001|partout:Zen/uBlock0@raymondhill.net,x@y"
            ]
        );
    }
}
