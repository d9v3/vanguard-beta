//! Réglages de sécurité des navigateurs : protection contre les sites frauduleux (Safe Browsing), cookies tiers,
//! DNS chiffré. Un navigateur n'écrit un réglage que s'il a été changé : sans valeur écrite, on retient sa valeur
//! par défaut. Une stratégie imposée (fichier de /etc sous Linux, registre sous Windows, policies.json de Firefox)
//! passe avant les Paramètres : un logiciel indésirable s'en sert pour couper la protection sans qu'on puisse la
//! rallumer. Celles de macOS (profils gérés) ne sont pas lues. À part (COM-NAV-004) : l'échange de clés
//! post-quantique (X25519MLKEM768) coupé par une préférence ou une stratégie, pour ne pas mêler sa clé à celles
//! des réglages ci-dessus.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{Constat, alerte, impossible, ok, sans_objet};
use crate::modele::{Absence, Objet};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Navigateur";

#[derive(Debug, PartialEq)]
struct Reglages {
    /// Protection contre les sites frauduleux et les téléchargements dangereux.
    anti_hameconnage: bool,
    /// Tous les cookies tiers acceptés (suivi d'un site à l'autre).
    cookies_ouverts: bool,
    /// DNS chiffré du navigateur : `None` quand le navigateur décide seul (valeur par défaut).
    dns_chiffre: Option<bool>,
}

/// Valeur d'une préférence Firefox (`user_pref("nom", valeur);`) ; la dernière écrite gagne.
fn pref(texte: &str, nom: &str) -> Option<String> {
    let debut = format!("user_pref(\"{nom}\",");
    texte
        .lines()
        .filter_map(|l| l.trim().strip_prefix(debut.as_str()))
        .filter_map(|r| r.trim().strip_suffix(");"))
        .map(|v| v.trim().trim_matches('"').to_string())
        .next_back()
}

fn lire_firefox(prefs: &str) -> Reglages {
    let coupe = |nom: &str| pref(prefs, nom).as_deref() == Some("false");
    Reglages {
        anti_hameconnage: !coupe("browser.safebrowsing.malware.enabled")
            && !coupe("browser.safebrowsing.phishing.enabled"),
        // network.cookie.cookieBehavior : 0 = tout accepter ; sans valeur, protection totale des cookies.
        cookies_ouverts: pref(prefs, "network.cookie.cookieBehavior").as_deref() == Some("0"),
        // network.trr.mode : 2 ou 3 = DNS chiffré, 5 = coupé.
        dns_chiffre: match pref(prefs, "network.trr.mode").as_deref() {
            Some("2" | "3") => Some(true),
            Some("5") => Some(false),
            _ => None,
        },
    }
}

/// La valeur au bout des clés, ou Null dès qu'une manque (ou qu'un maillon n'est pas un objet) : ce que rendait
/// l'index de serde_json (`v["a"]["b"]`), écrit sans index. Les lectures qui suivent tiennent déjà Null pour « pas
/// écrit », la valeur par défaut du navigateur.
fn champ<'a>(v: &'a Value, cles: &[&str]) -> &'a Value {
    static NUL: Value = Value::Null;
    cles.iter().try_fold(v, |v, c| v.get(c)).unwrap_or(&NUL)
}

/// Une préférence de stratégie Firefox mise à false et imposée : valeur nue (ancienne forme, verrouillée) ou
/// `"Status": "locked"`.
fn pref_coupee_imposee(prefs: &Value, n: &str) -> bool {
    *champ(prefs, &[n]) == false || (*champ(prefs, &[n, "Value"]) == false && *champ(prefs, &[n, "Status"]) == "locked")
}

/// Une préférence de stratégie Firefox mise à false seulement par défaut (« default », « user », sans Status).
fn pref_coupee_par_defaut(prefs: &Value, n: &str) -> bool {
    *champ(prefs, &[n, "Value"]) == false && *champ(prefs, &[n, "Status"]) != "locked"
}

/// `None` : Preferences n'est pas un objet JSON (abîmé, en cours d'écriture) ; rien n'est conclu, jamais « active ».
fn lire_chromium(preferences: &str, etat_local: &str) -> Option<Reglages> {
    let p: Value = serde_json::from_str(preferences).ok().filter(Value::is_object)?;
    let l: Value = serde_json::from_str(etat_local).unwrap_or_default();
    Some(Reglages {
        anti_hameconnage: *champ(&p, &["safebrowsing", "enabled"]) != false,
        // cookie_controls_mode 0 = cookies tiers autorisés partout (le défaut les bloque en navigation privée).
        cookies_ouverts: *champ(&p, &["profile", "cookie_controls_mode"]) == 0
            && *champ(&p, &["profile", "block_third_party_cookies"]) != true,
        dns_chiffre: match champ(&l, &["dns_over_https", "mode"]).as_str() {
            Some("secure") => Some(true),
            Some("off") => Some(false),
            _ => None,
        },
    })
}

/// Les stratégies d'un navigateur, fusionnées comme il les applique : pour chaque clé, sa valeur et l'endroit d'où
/// elle vient. Imposées (« managed », Policies) ou recommandées (« recommended », …\Recommended : la valeur par défaut
/// tant que la personne n'a pas choisi). Firefox : son policies.json, et où il est. `illisibles` : fichiers présents
/// que même le JSON de Chrome (commentaires, virgules en trop) ne lit pas ; rien n'est conclu pour eux.
#[derive(Default)]
struct Strategies {
    imposees: BTreeMap<String, (Value, String)>,
    recommandees: BTreeMap<String, (Value, String)>,
    firefox: Option<(Value, String)>,
    illisibles: Vec<String>,
}

/// Le JSON des stratégies tel que Chrome le lit : commentaires `//` et `/* */`, virgule avant `}` ou `]` permis, par
/// le lecteur commun (`socle::jsonc`).
#[cfg(any(target_os = "linux", windows, test))]
fn json_souple(texte: &str) -> Option<Value> {
    crate::socle::jsonc::lire_json(texte.as_bytes())
}

/// Une valeur de stratégie lue comme un nombre : booléen, nombre, ou chiffres d'une chaîne (registre REG_SZ).
fn nombre(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_bool().map(i64::from))
        .or_else(|| v.as_str()?.trim().parse().ok())
}

/// La règle Safe Browsing qui coupe la protection, et son origine. SafeBrowsingProtectionLevel, présent, passe avant
/// SafeBrowsingEnabled, comme dans Chrome.
fn safe_browsing_coupe(s: &BTreeMap<String, (Value, String)>) -> Option<(String, String)> {
    if let Some((v, ou)) = s.get("SafeBrowsingProtectionLevel") {
        return (nombre(v) == Some(0)).then(|| ("SafeBrowsingProtectionLevel = 0".to_string(), ou.clone()));
    }
    let (v, ou) = s.get("SafeBrowsingEnabled")?;
    (nombre(v) == Some(0)).then(|| ("SafeBrowsingEnabled = false".to_string(), ou.clone()))
}

const PREFS_SAFE_BROWSING: [&str; 2] = [
    "browser.safebrowsing.malware.enabled",
    "browser.safebrowsing.phishing.enabled",
];

/// Firefox : (préférence imposée qui coupe, préférence seulement par défaut qui coupe). Imposée : valeur nue (ancienne
/// forme, verrouillée) ou `"Status": "locked"` ; sinon (« default », « user », sans Status), la personne garde la main.
fn firefox_coupe(politiques: &Value) -> (Option<&'static str>, Option<&'static str>) {
    let prefs = &politiques["Preferences"];
    let imposee = PREFS_SAFE_BROWSING.into_iter().find(|n| pref_coupee_imposee(prefs, n));
    let par_defaut = PREFS_SAFE_BROWSING
        .into_iter()
        .find(|n| pref_coupee_par_defaut(prefs, n));
    (imposee, par_defaut)
}

/// Les stratégies du navigateur `nom` (celui de `extensions::racines`). Pas lues : celles de macOS (profils gérés),
/// des navigateurs en Flatpak (extensions de politiques). Firefox sous Windows : le registre (la stratégie
/// post-quantique et les Preferences), sinon distribution\policies.json.
#[cfg(target_os = "linux")]
fn strategies(nom: &str) -> Strategies {
    use std::path::Path;
    let mut s = Strategies::default();
    if nom == "Firefox" {
        // Le premier qui existe masque l'autre, comme dans Firefox.
        if let Some(c) = [
            "/etc/firefox/policies/policies.json",
            "/usr/lib/firefox/distribution/policies.json",
        ]
        .into_iter()
        .find(|c| Path::new(c).exists())
        {
            match std::fs::read_to_string(c).ok().as_deref().and_then(json_souple) {
                Some(v) => s.firefox = Some((champ(&v, &["policies"]).clone(), c.to_string())),
                None => s.illisibles.push(c.to_string()),
            }
        }
        return s;
    }
    let bases: &[&str] = match nom {
        "Chrome" => &["/etc/opt/chrome/policies"],
        "Chromium" => &["/etc/chromium/policies", "/etc/chromium-browser/policies"],
        "Brave" => &["/etc/brave/policies"],
        "Edge" => &["/etc/opt/edge/policies"],
        _ => &[],
    };
    for base in bases {
        for (sous, cible) in [("managed", &mut s.imposees), ("recommended", &mut s.recommandees)] {
            // Tous les fichiers du dossier, quel que soit leur nom, dans l'ordre : le dernier gagne.
            let mut fichiers: Vec<_> = std::fs::read_dir(Path::new(base).join(sous))
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|c| c.is_file())
                .collect();
            fichiers.sort();
            for c in fichiers {
                let ou = c.display().to_string();
                match std::fs::read_to_string(&c).ok().as_deref().and_then(json_souple) {
                    Some(Value::Object(o)) => cible.extend(o.into_iter().map(|(k, v)| (k, (v, ou.clone())))),
                    _ => s.illisibles.push(ou),
                }
            }
        }
    }
    s
}

#[cfg(windows)]
fn strategies(nom: &str) -> Strategies {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let mut s = Strategies::default();
    let cle = match nom {
        "Chrome" => r"SOFTWARE\Policies\Google\Chrome",
        "Chromium" => r"SOFTWARE\Policies\Chromium",
        "Brave" => r"SOFTWARE\Policies\BraveSoftware\Brave",
        "Edge" => r"SOFTWARE\Policies\Microsoft\Edge",
        "Firefox" => {
            // Le registre passe avant distribution\policies.json, et HKLM avant HKCU, comme dans Firefox.
            let cle = r"SOFTWARE\Policies\Mozilla\Firefox";
            for (racine, court) in [(HKEY_LOCAL_MACHINE, "HKLM"), (HKEY_CURRENT_USER, "HKCU")] {
                let Ok(k) = RegKey::predef(racine).open_subkey(cle) else {
                    continue;
                };
                let pq = k.get_value::<u32, _>("PostQuantumKeyAgreementEnabled").ok();
                // REG_SZ ou REG_MULTI_SZ (lignes jointes par winreg) : le JSON de la stratégie Preferences.
                let texte = k.get_value::<String, _>("Preferences").ok();
                let anciennes: Vec<(String, u32)> = k
                    .open_subkey("Preferences")
                    .map(|p| {
                        PREFS_PQ
                            .into_iter()
                            .filter_map(|n| Some((n.to_string(), p.get_value::<u32, _>(n).ok()?)))
                            .collect()
                    })
                    .unwrap_or_default();
                let (objet, illisible) = firefox_du_registre(pq, texte.as_deref(), &anciennes);
                if illisible {
                    s.illisibles.push(format!(r"{court}\{cle}\Preferences"));
                }
                if let Some(objet) = objet {
                    s.firefox = Some((objet, format!(r"{court}\{cle}")));
                    break;
                }
            }
            if s.firefox.is_none() {
                for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
                    let Some(base) = std::env::var_os(variable) else {
                        continue;
                    };
                    let c = std::path::Path::new(&base).join(r"Mozilla Firefox\distribution\policies.json");
                    if !c.exists() {
                        continue;
                    }
                    let ou = c.display().to_string();
                    match std::fs::read_to_string(&c).ok().as_deref().and_then(json_souple) {
                        Some(v) => s.firefox = Some((champ(&v, &["policies"]).clone(), ou)),
                        None => s.illisibles.push(ou),
                    }
                    break;
                }
            }
            return s;
        }
        _ => return s,
    };
    // HKLM lu en dernier : il passe avant HKCU.
    for (racine, court) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
        for (sous, cible) in [("", &mut s.imposees), (r"\Recommended", &mut s.recommandees)] {
            let chemin = format!("{cle}{sous}");
            let Ok(k) = RegKey::predef(racine).open_subkey(&chemin) else {
                continue;
            };
            for v in [
                "SafeBrowsingProtectionLevel",
                "SafeBrowsingEnabled",
                "PostQuantumKeyAgreementEnabled",
            ] {
                // DWORD, ou chiffres en REG_SZ : Chrome applique les deux.
                let valeur = k
                    .get_value::<u32, _>(v)
                    .ok()
                    .map(Value::from)
                    .or_else(|| k.get_value::<String, _>(v).ok().map(Value::from));
                if let Some(valeur) = valeur {
                    cible.insert(v.to_string(), (valeur, format!(r"{court}\{chemin}\{v}")));
                }
            }
        }
    }
    s
}

#[cfg(target_os = "macos")]
fn strategies(_nom: &str) -> Strategies {
    Strategies::default()
}

/// Les stratégies de Firefox lues dans une racine du registre, mises sous la forme de policies.json pour être
/// jugées pareil : la valeur PostQuantumKeyAgreementEnabled, le JSON de la valeur Preferences, et l'ancienne
/// forme (une valeur DWORD par préférence sous la clé Preferences, verrouillée comme une valeur nue). `None` :
/// rien de lu ; le booléen : un texte Preferences présent mais illisible, dont rien n'est conclu.
#[cfg(any(windows, test))]
fn firefox_du_registre(pq: Option<u32>, texte: Option<&str>, anciennes: &[(String, u32)]) -> (Option<Value>, bool) {
    let mut objet = serde_json::Map::new();
    if let Some(v) = pq {
        objet.insert("PostQuantumKeyAgreementEnabled".into(), Value::from(v != 0));
    }
    let mut prefs: serde_json::Map<String, Value> = anciennes
        .iter()
        .map(|(n, v)| (n.clone(), Value::from(*v != 0)))
        .collect();
    let mut illisible = false;
    if let Some(t) = texte {
        match json_souple(t) {
            Some(Value::Object(o)) => prefs.extend(o),
            _ => illisible = true,
        }
    }
    if !prefs.is_empty() {
        objet.insert("Preferences".into(), Value::Object(prefs));
    }
    ((!objet.is_empty()).then_some(Value::Object(objet)), illisible)
}

/// Une stratégie qui coupe la protection : les Paramètres ne peuvent pas la rallumer.
fn juger_strategie(navigateur: &str, ou: &str, regle: &str) -> Constat {
    alerte(
        CAT,
        Niveau::Moyen,
        trf!(
            "{navigateur} : protection contre les sites frauduleux coupée par une stratégie imposée ({regle}), que les Paramètres ne peuvent pas rallumer. Si personne ne gère cet ordinateur (école, travail), un logiciel indésirable l'a sans doute posée.",
            "{navigateur}: protection against fraudulent sites turned off by an enforced policy ({regle}), which Settings cannot turn back on. If nobody manages this computer (school, work), unwanted software probably set it."
        ),
    )
    .manuel(
        trf!(
            "Retirer la stratégie (droits d'administrateur) : {ou} ; puis un examen antivirus",
            "Remove the policy (administrator rights): {ou}; then an antivirus scan"
        ),
        &[],
    )
}

fn juger(navigateur: &str, r: &Reglages) -> Constat {
    let dns = match r.dns_chiffre {
        Some(true) => tr!("DNS chiffré activé", "encrypted DNS on"),
        Some(false) => tr!("DNS chiffré coupé", "encrypted DNS off"),
        None => tr!("DNS chiffré par défaut", "default encrypted DNS"),
    };
    if !r.anti_hameconnage {
        return alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "{navigateur} : protection contre les sites frauduleux désactivée ({dns}).",
                "{navigateur}: protection against fraudulent sites turned off ({dns})."
            ),
        )
        .manuel(
            tr!(
                "La réactiver : Paramètres > Vie privée et sécurité > Sécurité",
                "Turn it back on: Settings > Privacy and security > Security"
            ),
            &[],
        );
    }
    if r.cookies_ouverts {
        return alerte(
            CAT,
            Niveau::Info,
            trf!(
                "{navigateur} : protection contre les sites frauduleux active, mais tous les cookies tiers sont acceptés : les publicitaires vous suivent de site en site ({dns}).",
                "{navigateur}: protection against fraudulent sites on, but all third-party cookies are accepted: advertisers follow you from site to site ({dns})."
            ),
        );
    }
    ok(
        CAT,
        trf!(
            "{navigateur} : protection contre les sites frauduleux active, cookies tiers limités, {dns}.",
            "{navigateur}: protection against fraudulent sites on, third-party cookies limited, {dns}."
        ),
    )
}

pub fn navigateurs() -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut vus = Vec::new();
    // Par navigateur, lu une fois : la stratégie recommandée qui coupe (Firefox : la préférence en cause).
    let mut recommandees: Vec<(&str, Option<&str>)> = Vec::new();
    for (nom, racine, firefox) in super::extensions::racines() {
        let profils = super::extensions::profils(&racine, firefox);
        if !profils.is_empty() && !recommandees.iter().any(|(n, _)| *n == nom) {
            let s = strategies(nom);
            let (imposee, recommandee) = if firefox {
                let (imposee, defaut) = s.firefox.as_ref().map_or((None, None), |(v, _)| firefox_coupe(v));
                let ou = s.firefox.as_ref().map(|(_, ou)| ou.clone()).unwrap_or_default();
                (imposee.map(|p| (format!("Preferences : {p} = false"), ou)), defaut)
            } else {
                let recommandee = safe_browsing_coupe(&s.recommandees).map(|_| "safebrowsing.enabled");
                (safe_browsing_coupe(&s.imposees), recommandee)
            };
            if let Some((regle, ou)) = imposee {
                constats.push(juger_strategie(nom, &ou, &regle));
            }
            if !s.illisibles.is_empty() {
                constats.push(impossible(
                    CAT,
                    &trf!(
                        "stratégies de {nom} illisibles : {}",
                        "{nom} policies unreadable: {}",
                        s.illisibles.join(", ")
                    ),
                ));
            }
            recommandees.push((nom, recommandee));
        }
        let recommandee = recommandees.iter().find(|(n, _)| *n == nom).and_then(|(_, r)| *r);
        let plusieurs = profils.len() > 1;
        for (dossier, chemin) in profils {
            let reel = chemin.canonicalize().unwrap_or_else(|_| chemin.clone());
            if vus.contains(&reel) {
                continue;
            }
            vus.push(reel);
            // Absent : un profil neuf, valeurs par défaut. Illisible : rien n'est conclu.
            let lire = |f: &str| match std::fs::read_to_string(chemin.join(f)) {
                Ok(t) => Ok(t),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
                Err(e) => Err(format!("{f} : {e}")),
            };
            let reglages = if firefox {
                lire("prefs.js").and_then(|p| Ok(p + &lire("user.js")?)).map(|prefs| {
                    let mut r = lire_firefox(&prefs);
                    // Une stratégie par défaut qui coupe vaut tant que la personne n'a rien écrit elle-même.
                    if recommandee.is_some_and(|n| pref(&prefs, n).is_none()) {
                        r.anti_hameconnage = false;
                    }
                    r
                })
            } else {
                let etat_local = std::fs::read_to_string(racine.join("Local State")).unwrap_or_default();
                lire("Preferences").and_then(|p| {
                    let mut r = lire_chromium(&p, &etat_local).ok_or_else(|| "Preferences".to_string())?;
                    let lu = serde_json::from_str::<Value>(&p).unwrap_or_default();
                    let choisi = champ(&lu, &["safebrowsing", "enabled"]).is_boolean();
                    if recommandee.is_some() && !choisi {
                        r.anti_hameconnage = false;
                    }
                    Ok(r)
                })
            };
            let navigateur = if plusieurs {
                let court = dossier
                    .split_once('.')
                    .filter(|_| firefox)
                    .map_or(dossier.as_str(), |(_, n)| n);
                format!("{nom} ({court})")
            } else {
                nom.to_string()
            };
            constats.push(match reglages {
                Ok(r) => juger(&navigateur, &r),
                Err(raison) => impossible(
                    CAT,
                    &trf!(
                        "réglages de {navigateur} illisibles ({raison})",
                        "{navigateur} settings unreadable ({raison})"
                    ),
                ),
            });
        }
    }
    constats
}

// ── Échange de clés post-quantique (COM-NAV-004) ──

/// Les préférences de Firefox qui coupent l'échange post-quantique : TLS, HTTP/3, WebRTC. La stratégie
/// PostQuantumKeyAgreementEnabled les verrouille toutes les trois.
const PREFS_PQ: [&str; 3] = [
    "security.tls.enable_kyber",
    "network.http.http3.enable_kyber",
    "media.webrtc.enable_pq_hybrid_kex",
];

/// La dernière version de Chrome et d'Edge qui applique la stratégie PostQuantumKeyAgreementEnabled : Chromium la
/// marque « deprecated », supported_on chrome.*:116-146, et Microsoft la dit sans effet après Edge 146.
const DERNIERE_VERSION_STRATEGIE_PQ: u32 = 146;

/// La préférence de Firefox (prefs.js et user.js d'un profil) qui coupe l'échange post-quantique.
fn pq_coupe_firefox(prefs: &str) -> Option<&'static str> {
    PREFS_PQ
        .into_iter()
        .find(|n| pref(prefs, n).as_deref() == Some("false"))
}

/// Ce qui coupe l'échange post-quantique d'un profil Firefox : une préférence du profil, sinon la valeur par
/// défaut de la stratégie (`defaut` : la préférence et l'endroit). Le profil garde la main sur celle-ci : s'il
/// écrit true, il gagne ; s'il n'écrit rien, le false de la stratégie compte.
fn coupure_profil(prefs: &str, defaut: Option<&(&'static str, String)>) -> Option<CoupurePq> {
    pq_coupe_firefox(prefs).map(CoupurePq::Preference).or_else(|| {
        defaut
            .filter(|(n, _)| pref(prefs, n).is_none())
            .map(|(n, ou)| CoupurePq::DefautStrategie {
                pref: n,
                ou: ou.clone(),
            })
    })
}

/// Le TLS post-quantique allumé à la main dans le profil : actif même sur une version qui ne l'a pas par défaut.
fn pq_allume_firefox(prefs: &str) -> bool {
    pref(prefs, "security.tls.enable_kyber").as_deref() == Some("true")
}

/// Celles que la stratégie Preferences de Firefox accepte. Firefox y refuse security.tls.enable_kyber (absente de
/// sa liste des security.* permis) : seule PostQuantumKeyAgreementEnabled la verrouille.
fn prefs_pq_de_strategie() -> impl Iterator<Item = &'static str> {
    PREFS_PQ.into_iter().filter(|n| !n.starts_with("security."))
}

/// Firefox : la stratégie qui coupe l'échange post-quantique (PostQuantumKeyAgreementEnabled, ou une des
/// préférences verrouillée à false), comme elle s'écrit.
fn firefox_pq_impose(politiques: &Value) -> Option<String> {
    if politiques["PostQuantumKeyAgreementEnabled"] == false {
        return Some("PostQuantumKeyAgreementEnabled = false".into());
    }
    let prefs = &politiques["Preferences"];
    prefs_pq_de_strategie()
        .find(|n| pref_coupee_imposee(prefs, n))
        .map(|n| format!("Preferences : {n} = false"))
}

/// Firefox : la préférence que la stratégie met à false seulement par défaut (« default », « user », sans
/// Status). Jamais écrite dans prefs.js, elle vaut tant que le profil n'écrit rien lui-même.
fn firefox_pq_par_defaut(politiques: &Value) -> Option<&'static str> {
    let prefs = &politiques["Preferences"];
    prefs_pq_de_strategie().find(|n| pref_coupee_par_defaut(prefs, n))
}

/// Famille Chromium : la stratégie imposée qui coupe l'échange post-quantique, et son origine.
fn chromium_pq_coupe(s: &BTreeMap<String, (Value, String)>) -> Option<(String, String)> {
    let (v, ou) = s.get("PostQuantumKeyAgreementEnabled")?;
    (nombre(v) == Some(0)).then(|| ("PostQuantumKeyAgreementEnabled = false".to_string(), ou.clone()))
}

/// La version majeure d'un navigateur de la famille Chromium, d'après le fichier « Last Version » de son dossier
/// (« 141.0.7390.54 »). Brave et Vivaldi numérotent à leur façon : leur version n'est pas crue.
fn version_majeure(nom: &str, contenu: &str) -> Option<u32> {
    if !matches!(nom, "Chrome" | "Chromium" | "Edge") {
        return None;
    }
    contenu.trim().split('.').next()?.parse().ok().filter(|v| *v > 0)
}

/// La version majeure de Firefox, d'après compatibility.ini du profil (« LastVersion=128.0_20240101/… »). Zen,
/// Floorp et Waterfox numérotent à leur façon : leur version n'est pas crue.
fn version_firefox(nom: &str, compatibilite: &str) -> Option<u32> {
    if !matches!(nom, "Firefox" | "LibreWolf") {
        return None;
    }
    compatibilite
        .lines()
        .find_map(|l| l.trim().strip_prefix("LastVersion="))?
        .split('.')
        .next()?
        .parse()
        .ok()
        .filter(|v| *v > 0)
}

/// Les premières versions qui proposent l'échange post-quantique sans réglage : Firefox 132 (X25519MLKEM768),
/// Chrome 124 (X25519Kyber768, remplacé par X25519MLKEM768 en 131).
const FIREFOX_PQ_PAR_DEFAUT: u32 = 132;
const CHROMIUM_KYBER: u32 = 124;
const CHROMIUM_MLKEM: u32 = 131;

/// La version d'un navigateur, quand la stratégie en dépend.
#[derive(Debug, PartialEq)]
enum Version {
    /// Firefox : la stratégie vaut quelle que soit la version.
    SansObjet,
    /// Famille Chromium : la version majeure.
    Lue(u32),
    Illisible,
}

/// Ce qui coupe l'échange post-quantique d'un navigateur.
#[derive(Debug, PartialEq)]
enum CoupurePq {
    /// Une stratégie imposée : la règle, l'endroit, et la version du navigateur si elle compte.
    Strategie {
        regle: String,
        ou: String,
        version: Version,
    },
    /// Une préférence du profil, écrite à la main ou par un logiciel.
    Preference(&'static str),
    /// Une préférence mise à false par défaut par la stratégie (le profil garde la main), et l'endroit.
    DefautStrategie { pref: &'static str, ou: String },
}

/// Un navigateur dont rien ne coupe l'échange post-quantique : sa famille, sa version, et si une préférence du
/// profil l'allume (Firefox avant 132).
#[derive(Debug)]
struct SansCoupure {
    firefox: bool,
    version: Version,
    allume: bool,
}

/// COM-NAV-004 pour un navigateur (ou un profil). Sans coupure, la version dit si l'échange est là par défaut.
fn juger_pq(navigateur: &str, coupure: Option<&CoupurePq>, sans: &SansCoupure) -> Constat {
    let pourquoi = |regle: &str| {
        trf!(
            "{navigateur} : échange de clés post-quantique coupé ({regle}). Le trafic HTTPS enregistré aujourd'hui serait lisible demain. Si personne ne gère cet ordinateur, la cause peut être un logiciel qui inspecte le HTTPS, ou un réglage fait à la main contre une panne de réseau.",
            "{navigateur}: post-quantum key exchange turned off ({regle}). HTTPS traffic recorded today would be readable tomorrow. If nobody manages this computer, the cause may be software that inspects HTTPS, or a manual workaround for a network failure."
        )
    };
    match coupure {
        None => juger_sans_coupure(navigateur, sans),
        Some(CoupurePq::Strategie { regle, version: Version::Lue(v), .. }) if *v > DERNIERE_VERSION_STRATEGIE_PQ => ok(
            CAT_PQ,
            trf!(
                "{navigateur} : stratégie {regle} présente, mais sans effet depuis la version 147 (version {v} ici) : l'échange post-quantique ne se coupe plus.",
                "{navigateur}: policy {regle} present, but without effect since version 147 (version {v} here): post-quantum key exchange can no longer be turned off."
            ),
        ),
        Some(CoupurePq::Strategie { regle, version: Version::Illisible, .. }) => alerte(
            CAT_PQ,
            Niveau::Info,
            trf!(
                "{navigateur} : stratégie {regle} présente, probablement sans effet (ignorée depuis la version 147 ; version de ce navigateur illisible).",
                "{navigateur}: policy {regle} present, probably without effect (ignored since version 147; this browser's version unreadable)."
            ),
        ),
        Some(CoupurePq::Strategie { regle, ou, .. }) => alerte(CAT_PQ, Niveau::Moyen, pourquoi(regle)).manuel(
            trf!(
                "Retirer la stratégie (droits d'administrateur) : {ou} ; puis chercher le logiciel qui l'a posée",
                "Remove the policy (administrator rights): {ou}; then look for the software that set it"
            ),
            &[],
        ),
        Some(CoupurePq::Preference(p)) => alerte(CAT_PQ, Niveau::Info, pourquoi(p)).manuel(
            trf!(
                "Remettre {p} à sa valeur par défaut (about:config, Réinitialiser), puis vérifier que les sites s'ouvrent",
                "Reset {p} to its default value (about:config, Reset), then check that sites open"
            ),
            &[],
        ),
        Some(CoupurePq::DefautStrategie { pref, ou }) => {
            alerte(CAT_PQ, Niveau::Info, pourquoi(&format!("Preferences : {pref} = false"))).manuel(
                trf!(
                    "Retirer {pref} de la stratégie (droits d'administrateur) : {ou} ; ou le mettre à true dans about:config",
                    "Remove {pref} from the policy (administrator rights): {ou}; or set it to true in about:config"
                ),
                &[],
            )
        }
    }
}

/// Rien ne coupe l'échange : encore faut-il que la version le propose. Une version illisible ne conclut rien.
fn juger_sans_coupure(navigateur: &str, sans: &SansCoupure) -> Constat {
    let actif = |groupe: &str| {
        ok(
            CAT_PQ,
            trf!(
                "{navigateur} : échange de clés post-quantique ({groupe}) laissé actif.",
                "{navigateur}: post-quantum key exchange ({groupe}) left on."
            ),
        )
    };
    let premiere = if sans.firefox {
        FIREFOX_PQ_PAR_DEFAUT
    } else {
        CHROMIUM_KYBER
    };
    match sans.version {
        _ if sans.allume => ok(
            CAT_PQ,
            trf!(
                "{navigateur} : échange de clés post-quantique allumé dans les préférences du profil.",
                "{navigateur}: post-quantum key exchange turned on in the profile preferences."
            ),
        ),
        Version::Lue(v) if v < premiere => alerte(
            CAT_PQ,
            Niveau::Info,
            trf!(
                "{navigateur} : version {v}, qui ne propose pas d'échange de clés post-quantique par défaut (il l'est depuis la {premiere}). Le trafic HTTPS enregistré aujourd'hui serait lisible demain.",
                "{navigateur}: version {v}, which does not offer post-quantum key exchange by default (it does since {premiere}). HTTPS traffic recorded today would be readable tomorrow."
            ),
        )
        .manuel(
            tr!(
                "Mettre le navigateur à jour (ou passer à sa version la plus récente)",
                "Update the browser (or switch to its latest release)"
            ),
            &[],
        ),
        Version::Lue(v) if !sans.firefox && v < CHROMIUM_MLKEM => actif("X25519Kyber768"),
        Version::Lue(_) | Version::SansObjet => actif("X25519MLKEM768"),
        Version::Illisible => impossible(
            CAT_PQ,
            &trf!(
                "{navigateur} : version illisible, échange de clés post-quantique par défaut non vérifié",
                "{navigateur}: version unreadable, default post-quantum key exchange not checked"
            ),
        ),
    }
}

const CAT_PQ: &str = "Post-quantique";

/// COM-NAV-004 : un constat par navigateur de la famille Chromium, un par profil de la famille Firefox (ou un seul
/// quand une stratégie les verrouille tous).
pub fn post_quantique() -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut vus: Vec<&str> = Vec::new();
    let mut profils_vus = Vec::new();
    for (nom, racine, firefox) in super::extensions::racines() {
        let profils = super::extensions::profils(&racine, firefox);
        if profils.is_empty() {
            continue;
        }
        let premier = !vus.contains(&nom);
        vus.push(nom);
        if !firefox {
            if !premier {
                continue;
            }
            let s = strategies(nom);
            let version = std::fs::read_to_string(racine.join("Last Version"))
                .ok()
                .and_then(|t| version_majeure(nom, &t));
            let lue = || version.map_or(Version::Illisible, Version::Lue);
            let coupure = chromium_pq_coupe(&s.imposees).map(|(regle, ou)| CoupurePq::Strategie {
                regle,
                ou,
                version: lue(),
            });
            let sans = SansCoupure {
                firefox: false,
                version: lue(),
                allume: false,
            };
            constats.push(juger_pq(nom, coupure.as_ref(), &sans).avec_objet(Objet::de("pq", nom)));
            continue;
        }
        let s = strategies(nom);
        if let Some((politiques, ou)) = &s.firefox
            && let Some(regle) = firefox_pq_impose(politiques)
        {
            if premier {
                let c = CoupurePq::Strategie {
                    regle,
                    ou: ou.clone(),
                    version: Version::SansObjet,
                };
                let sans = SansCoupure {
                    firefox: true,
                    version: Version::SansObjet,
                    allume: false,
                };
                constats.push(juger_pq(nom, Some(&c), &sans).avec_objet(Objet::de("pq", nom)));
            }
            continue;
        }
        let defaut = s
            .firefox
            .as_ref()
            .and_then(|(v, ou)| Some((firefox_pq_par_defaut(v)?, ou.clone())));
        let plusieurs = profils.len() > 1;
        for (dossier, chemin) in profils {
            let reel = chemin.canonicalize().unwrap_or_else(|_| chemin.clone());
            if profils_vus.contains(&reel) {
                continue;
            }
            profils_vus.push(reel);
            let court = dossier.split_once('.').map_or(dossier.as_str(), |(_, n)| n).to_string();
            let navigateur = if plusieurs {
                format!("{nom} ({court})")
            } else {
                nom.to_string()
            };
            let lire = |f: &str| match std::fs::read_to_string(chemin.join(f)) {
                Ok(t) => Ok(t),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
                Err(e) => Err(format!("{f} : {e}")),
            };
            let objet = Objet::de("pq", &format!("{nom}/{court}"));
            constats.push(
                match lire("prefs.js").and_then(|p| Ok(p + &lire("user.js")?)) {
                    Ok(prefs) => {
                        let coupure = coupure_profil(&prefs, defaut.as_ref());
                        let compatibilite =
                            std::fs::read_to_string(chemin.join("compatibility.ini")).unwrap_or_default();
                        let sans = SansCoupure {
                            firefox: true,
                            version: version_firefox(nom, &compatibilite).map_or(Version::Illisible, Version::Lue),
                            allume: pq_allume_firefox(&prefs),
                        };
                        juger_pq(&navigateur, coupure.as_ref(), &sans)
                    }
                    Err(raison) => impossible(
                        CAT_PQ,
                        &trf!(
                            "réglages de {navigateur} illisibles ({raison})",
                            "{navigateur} settings unreadable ({raison})"
                        ),
                    ),
                }
                .avec_objet(objet),
            );
        }
    }
    if constats.is_empty() {
        constats.push(
            sans_objet(
                CAT_PQ,
                Absence::Logiciel,
                tr!(
                    "Aucun navigateur avec un profil trouvé : rien à juger pour l'échange post-quantique.",
                    "No browser with a profile found: nothing to judge for post-quantum key exchange."
                ),
            )
            .avec_objet(Objet::Seul),
        );
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reglages_firefox() {
        let defaut = lire_firefox("user_pref(\"browser.contentblocking.category\", \"strict\");\n");
        assert_eq!(
            defaut,
            Reglages {
                anti_hameconnage: true,
                cookies_ouverts: false,
                dns_chiffre: None
            }
        );
        let r = lire_firefox(
            "user_pref(\"browser.safebrowsing.phishing.enabled\", false);\nuser_pref(\"network.cookie.cookieBehavior\", 0);\nuser_pref(\"network.trr.mode\", 3);\n",
        );
        assert_eq!(
            r,
            Reglages {
                anti_hameconnage: false,
                cookies_ouverts: true,
                dns_chiffre: Some(true)
            }
        );
        assert_eq!(juger("Firefox", &r).probleme, Some(Niveau::Moyen));
        assert_eq!(juger("Firefox", &defaut).probleme, None);
    }

    #[test]
    fn reglages_chromium() {
        let r = lire_chromium(r#"{"safebrowsing":{"enabled":true,"enhanced":true}}"#, "{}").unwrap();
        assert_eq!(
            r,
            Reglages {
                anti_hameconnage: true,
                cookies_ouverts: false,
                dns_chiffre: None
            }
        );
        let r = lire_chromium(
            r#"{"safebrowsing":{"enabled":false},"profile":{"cookie_controls_mode":0}}"#,
            r#"{"dns_over_https":{"mode":"secure"}}"#,
        )
        .unwrap();
        assert_eq!(
            r,
            Reglages {
                anti_hameconnage: false,
                cookies_ouverts: true,
                dns_chiffre: Some(true)
            }
        );
    }

    #[test]
    fn preferences_illisibles_jamais_actives() {
        // Abîmé, vide ou en cours d'écriture : rien n'est conclu (avant, la protection passait pour active).
        for texte in ["", "{\"safebrowsing\":", "[]", "null"] {
            assert_eq!(lire_chromium(texte, "{}"), None, "{texte}");
        }
    }

    #[test]
    fn strategies_qui_coupent() {
        let fusion = |t: &str| -> BTreeMap<String, (Value, String)> {
            serde_json::from_str::<serde_json::Map<String, Value>>(t)
                .unwrap()
                .into_iter()
                .map(|(k, v)| (k, (v, "ici".to_string())))
                .collect()
        };
        // Coupée : niveau 0, ou Enabled faux sans niveau ; booléen, nombre ou chiffres en REG_SZ.
        for t in [
            r#"{"SafeBrowsingProtectionLevel":0}"#,
            r#"{"SafeBrowsingProtectionLevel":"0"}"#,
            r#"{"SafeBrowsingEnabled":false}"#,
            r#"{"SafeBrowsingEnabled":0}"#,
            r#"{"SafeBrowsingEnabled":"0"}"#,
        ] {
            assert!(safe_browsing_coupe(&fusion(t)).is_some(), "{t}");
        }
        // Le niveau passe avant Enabled ; SmartScreenEnabled (sans effet hors d'un Windows géré) ne compte pas.
        for t in [
            r#"{"SafeBrowsingProtectionLevel":1,"SafeBrowsingEnabled":false}"#,
            r#"{"SafeBrowsingProtectionLevel":2}"#,
            r#"{"SmartScreenEnabled":false}"#,
            r#"{"HomepageLocation":"https://exemple.org"}"#,
            "{}",
        ] {
            assert_eq!(safe_browsing_coupe(&fusion(t)), None, "{t}");
        }
        let json = |t: &str| serde_json::from_str::<Value>(t).unwrap();
        // Firefox : verrouillée (ou valeur nue) = imposée ; sinon seulement par défaut.
        let p = "browser.safebrowsing.phishing.enabled";
        assert_eq!(
            firefox_coupe(&json(&format!(r#"{{"Preferences":{{"{p}":false}}}}"#))),
            (Some(p), None)
        );
        assert_eq!(
            firefox_coupe(&json(&format!(
                r#"{{"Preferences":{{"{p}":{{"Value":false,"Status":"locked"}}}}}}"#
            ))),
            (Some(p), None)
        );
        for statut in ["", r#","Status":"default""#, r#","Status":"user""#] {
            assert_eq!(
                firefox_coupe(&json(&format!(
                    r#"{{"Preferences":{{"{p}":{{"Value":false{statut}}}}}}}"#
                ))),
                (None, Some(p)),
                "{statut}"
            );
        }
        assert_eq!(
            firefox_coupe(&json(&format!(r#"{{"Preferences":{{"{p}":{{"Value":true}}}}}}"#))),
            (None, None)
        );
        let c = juger_strategie(
            "Chrome",
            "/etc/opt/chrome/policies/managed/x",
            "SafeBrowsingEnabled = false",
        );
        assert!(c.probleme == Some(Niveau::Moyen) && c.message.contains("SafeBrowsingEnabled"));
    }

    #[test]
    fn json_comme_chrome() {
        // Commentaires et virgules en trop : Chrome applique le fichier, il doit se lire.
        let v =
            json_souple("{\n  // coupé\n  \"SafeBrowsingEnabled\": false, /* là */\n  \"A\": [1, 2,],\n}\n").unwrap();
        assert_eq!(v["SafeBrowsingEnabled"], false);
        assert_eq!(v["A"], serde_json::json!([1, 2]));
        // Dans une chaîne, « // » et « ,} » restent du texte.
        let v = json_souple(r#"{"U": "https://exemple.org/a,}", "B": 1,}"#).unwrap();
        assert_eq!(v["U"], "https://exemple.org/a,}");
        assert!(json_souple("{\"A\": ").is_none() && json_souple("pas du json").is_none());
    }
    /// Un navigateur sans coupure, de version récente.
    fn recent(firefox: bool) -> SansCoupure {
        SansCoupure {
            firefox,
            version: Version::Lue(141),
            allume: false,
        }
    }

    #[test]
    fn post_quantique_coupe() {
        // Préférences du profil : false coupe ; absente ou true, non.
        assert_eq!(
            pq_coupe_firefox("user_pref(\"security.tls.enable_kyber\", false);\n"),
            Some("security.tls.enable_kyber")
        );
        assert_eq!(
            pq_coupe_firefox("user_pref(\"media.webrtc.enable_pq_hybrid_kex\", false);\n"),
            Some("media.webrtc.enable_pq_hybrid_kex")
        );
        assert_eq!(
            pq_coupe_firefox("user_pref(\"security.tls.enable_kyber\", true);\n"),
            None
        );
        assert_eq!(pq_coupe_firefox(""), None);
        let c = juger_pq(
            "Firefox",
            Some(&CoupurePq::Preference("security.tls.enable_kyber")),
            &recent(true),
        );
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("security.tls.enable_kyber"));
        assert_eq!(juger_pq("Firefox", None, &recent(true)).probleme, None);
        // policies.json : la stratégie, ou une préférence verrouillée (forme nue et « Status: locked »).
        let json = |t: &str| serde_json::from_str::<Value>(t).unwrap();
        assert!(firefox_pq_impose(&json(r#"{"PostQuantumKeyAgreementEnabled":false}"#)).is_some());
        assert!(firefox_pq_impose(&json(r#"{"PostQuantumKeyAgreementEnabled":true}"#)).is_none());
        // Firefox refuse security.tls.enable_kyber dans Preferences : elle ne coupe rien.
        assert!(firefox_pq_impose(&json(r#"{"Preferences":{"security.tls.enable_kyber":false}}"#)).is_none());
        assert!(
            firefox_pq_impose(&json(
                r#"{"Preferences":{"network.http.http3.enable_kyber":{"Value":false,"Status":"locked"}}}"#
            ))
            .is_some()
        );
        assert!(
            firefox_pq_impose(&json(
                r#"{"Preferences":{"network.http.http3.enable_kyber":{"Value":false,"Status":"default"}}}"#
            ))
            .is_none()
        );
        let imposee = |version| CoupurePq::Strategie {
            regle: "PostQuantumKeyAgreementEnabled = false".into(),
            ou: "/etc/opt/chrome/policies/managed/x.json".into(),
            version,
        };
        // Firefox (sans version) et Chromium ≤ 146 : Moyen ; ≥ 147 : sans effet ; version illisible : Info.
        assert_eq!(
            juger_pq("Firefox", Some(&imposee(Version::SansObjet)), &recent(true)).probleme,
            Some(Niveau::Moyen)
        );
        assert_eq!(
            juger_pq("Chrome", Some(&imposee(Version::Lue(140))), &recent(false)).probleme,
            Some(Niveau::Moyen)
        );
        assert_eq!(
            juger_pq("Chrome", Some(&imposee(Version::Lue(146))), &recent(false)).probleme,
            Some(Niveau::Moyen)
        );
        let c = juger_pq("Edge", Some(&imposee(Version::Lue(147))), &recent(false));
        assert!(c.probleme.is_none() && c.verifie && c.message.contains("147"));
        assert_eq!(
            juger_pq("Brave", Some(&imposee(Version::Illisible)), &recent(false)).probleme,
            Some(Niveau::Info)
        );
        // Stratégies Chromium : booléen, nombre ou chiffres d'un REG_SZ.
        for v in ["false", "0", r#""0""#] {
            let s: BTreeMap<String, (Value, String)> = [(
                "PostQuantumKeyAgreementEnabled".to_string(),
                (json(v), "ici".to_string()),
            )]
            .into();
            assert!(chromium_pq_coupe(&s).is_some(), "{v}");
        }
        let s: BTreeMap<String, (Value, String)> = [(
            "PostQuantumKeyAgreementEnabled".to_string(),
            (json("true"), "ici".to_string()),
        )]
        .into();
        assert!(chromium_pq_coupe(&s).is_none());
        assert_eq!(version_majeure("Chrome", "141.0.7390.54\n"), Some(141));
        assert_eq!(version_majeure("Edge", "147.0.1.2"), Some(147));
        assert_eq!(version_majeure("Brave", "141.1.83.118"), None);
        assert_eq!(version_majeure("Vivaldi", "7.6.3797.52"), None);
        assert_eq!(version_majeure("Chrome", "abîmé"), None);
    }

    #[test]
    fn post_quantique_par_defaut_de_la_strategie() {
        let json = |t: &str| serde_json::from_str::<Value>(t).unwrap();
        // « default », « user » ou sans Status : la valeur de départ, que Firefox n'écrit jamais dans prefs.js.
        for n in ["network.http.http3.enable_kyber", "media.webrtc.enable_pq_hybrid_kex"] {
            for statut in ["", r#","Status":"default""#, r#","Status":"user""#] {
                let p = json(&format!(r#"{{"Preferences":{{"{n}":{{"Value":false{statut}}}}}}}"#));
                assert_eq!(firefox_pq_par_defaut(&p), Some(n), "{n}{statut}");
                assert!(firefox_pq_impose(&p).is_none());
            }
            let verrouillee = json(&format!(
                r#"{{"Preferences":{{"{n}":{{"Value":false,"Status":"locked"}}}}}}"#
            ));
            assert_eq!(firefox_pq_par_defaut(&verrouillee), None);
            let vraie = json(&format!(r#"{{"Preferences":{{"{n}":{{"Value":true}}}}}}"#));
            assert_eq!(firefox_pq_par_defaut(&vraie), None);
        }
        // Firefox refuse security.tls.enable_kyber dans Preferences, sous toutes ses formes.
        let refusee = json(r#"{"Preferences":{"security.tls.enable_kyber":{"Value":false}}}"#);
        assert_eq!(firefox_pq_par_defaut(&refusee), None);
        // Le jugement d'un profil : la valeur par défaut compte tant que le profil n'écrit rien lui-même.
        let n = "network.http.http3.enable_kyber";
        let defaut = Some((n, "/etc/firefox/policies/policies.json".to_string()));
        let coupure = |prefs: &str| coupure_profil(prefs, defaut.as_ref());
        let c = coupure("");
        assert!(matches!(c, Some(CoupurePq::DefautStrategie { .. })));
        let j = juger_pq("Firefox", c.as_ref(), &recent(true));
        assert!(
            j.probleme == Some(Niveau::Info) && j.message.contains(n),
            "{}",
            j.message
        );
        assert!(j.correctif.as_ref().unwrap().action.contains("policies.json"));
        assert_eq!(coupure(&format!("user_pref(\"{n}\", true);\n")), None);
    }

    #[test]
    fn post_quantique_selon_la_version() {
        let sans = |firefox, version, allume| SansCoupure {
            firefox,
            version,
            allume,
        };
        // Firefox avant 132 : pas actif par défaut ; allumé à la main, si.
        let c = juger_pq("Firefox", None, &sans(true, Version::Lue(128), false));
        assert!(c.verifie && c.probleme == Some(Niveau::Info), "{}", c.message);
        assert_eq!(
            juger_pq("Firefox", None, &sans(true, Version::Lue(128), true)).probleme,
            None
        );
        assert_eq!(
            juger_pq("Firefox", None, &sans(true, Version::Lue(132), false)).probleme,
            None
        );
        // Chrome : rien avant 124, Kyber de 124 à 130, ML-KEM ensuite.
        assert_eq!(
            juger_pq("Chrome", None, &sans(false, Version::Lue(120), false)).probleme,
            Some(Niveau::Info)
        );
        let c = juger_pq("Chrome", None, &sans(false, Version::Lue(127), false));
        assert!(
            c.probleme.is_none() && c.message.contains("X25519Kyber768"),
            "{}",
            c.message
        );
        let c = juger_pq("Chrome", None, &sans(false, Version::Lue(141), false));
        assert!(
            c.probleme.is_none() && c.message.contains("X25519MLKEM768"),
            "{}",
            c.message
        );
        // Version illisible : rien n'est conclu, jamais « actif ».
        let c = juger_pq("Brave", None, &sans(false, Version::Illisible, false));
        assert!(!c.verifie && c.coherent());
        // compatibility.ini : Firefox et LibreWolf seulement.
        let ini = "[Compatibility]\nLastVersion=128.0_20240101000000/20240101000000\nLastOSABI=Linux_x86_64-gcc3\n";
        assert_eq!(version_firefox("Firefox", ini), Some(128));
        assert_eq!(version_firefox("LibreWolf", ini), Some(128));
        assert_eq!(version_firefox("Zen", ini), None);
        assert_eq!(version_firefox("Firefox", ""), None);
        assert!(pq_allume_firefox("user_pref(\"security.tls.enable_kyber\", true);\n"));
        assert!(!pq_allume_firefox(""));
    }

    #[test]
    fn firefox_dans_le_registre() {
        // La valeur Preferences telle qu'elle sort du registre (REG_MULTI_SZ joint) : jugée comme policies.json.
        let texte = "{\n\"network.http.http3.enable_kyber\": false\n}";
        let (v, illisible) = firefox_du_registre(None, Some(texte), &[]);
        assert!(!illisible && firefox_pq_impose(&v.unwrap()).is_some());
        let (v, _) = firefox_du_registre(Some(0), None, &[]);
        assert!(firefox_pq_impose(&v.unwrap()).is_some());
        // L'ancienne forme, une valeur DWORD par préférence : verrouillée.
        let (v, _) = firefox_du_registre(None, None, &[("media.webrtc.enable_pq_hybrid_kex".into(), 0)]);
        assert!(firefox_pq_impose(&v.unwrap()).is_some());
        // Une valeur par défaut, et security.tls.enable_kyber, que Firefox refuse.
        let texte = r#"{"network.http.http3.enable_kyber":{"Value":false,"Status":"default"}}"#;
        let (v, _) = firefox_du_registre(None, Some(texte), &[]);
        let v = v.unwrap();
        assert!(firefox_pq_impose(&v).is_none() && firefox_pq_par_defaut(&v).is_some());
        let (v, _) = firefox_du_registre(None, Some(r#"{"security.tls.enable_kyber":false}"#), &[]);
        assert!(firefox_pq_impose(&v.unwrap()).is_none());
        // Rien : pas de stratégie ; texte abîmé : dit illisible.
        assert_eq!(firefox_du_registre(None, None, &[]), (None, false));
        assert_eq!(firefox_du_registre(None, Some("{\"a\":"), &[]), (None, true));
    }

    /// La vraie règle sur cet ordinateur, en lecture seule : jamais vide, toujours cohérente.
    #[test]
    fn post_quantique_reel() {
        let c = post_quantique();
        assert!(!c.is_empty());
        assert!(c.iter().all(Constat::coherent));
    }
}
