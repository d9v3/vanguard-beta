//! Les agents d'IA de cet ordinateur, en lecture seule. Un agent malveillant ne se reconnaît pas à coup sûr : il
//! utilise les mêmes outils qu'un agent honnête. Ce qui se vérifie, ce sont les portes par lesquelles un agent, honnête
//! mais détourné (injection de prompt dans une page ou un fichier) ou piégé par un outil, ferait des dégâts :
//! - un serveur d'IA local (Ollama, LM Studio, ComfyUI, interfaces Gradio) ouvert au réseau sans mot de passe ;
//! - un agent réglé pour tout faire sans demander (Claude Code : mode « bypassPermissions », toute commande permise) ;
//! - un serveur MCP lancé par `npx`, `uvx`… sans version fixée (la prochaine version publiée, piégée ou non,
//!   s'exécute avec les droits de la personne), joint en HTTP sans chiffrement, ou avec une clé écrite en clair.
//!
//! Les fichiers lus : réglages de Claude Code (~/.claude), de Claude Desktop, de Cursor, de VS Code, de Windsurf et
//! de Gemini CLI, en JSON ou en JSONC (commentaires et virgules finales, que VS Code accepte) ; un fichier présent
//! mais illisible rend l'outil « non vérifié », jamais « aucun agent ». Aucune valeur secrète n'est affichée ni
//! gardée : seulement le nom du serveur et celui de la clé. Rien ne se corrige tout seul.

#[cfg(test)]
use crate::socle::jsonc::json_sans_jsonc;
use crate::socle::jsonc::lire_json;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::{affichable, couper, tr, trf};

const CAT: &str = "Agents d'IA";

/// Les serveurs d'IA locaux connus par leur port d'origine : sans mot de passe, ils doivent rester sur 127.0.0.1.
const PORTS_IA: [(u16, &str); 4] = [
    (11434, "Ollama"),
    (1234, "LM Studio"),
    (8188, "ComfyUI"),
    (7860, "Gradio (Stable Diffusion WebUI, text-generation-webui)"),
];

/// Les programmes d'IA reconnus par leur nom, quel que soit leur port.
const PROGRAMMES_IA: [&str; 5] = ["ollama", "llama-server", "koboldcpp", "comfyui", "lm studio"];

/// Un port en écoute : adresse locale, port, programme (vide s'il est inconnu).
pub(crate) struct Prise {
    pub adresse: String,
    pub port: u16,
    pub programme: String,
}

pub(crate) fn serveur_ia(p: &Prise) -> Option<String> {
    if let Some((_, nom)) = PORTS_IA.iter().find(|(port, _)| *port == p.port) {
        return Some((*nom).to_string());
    }
    let programme = p.programme.to_lowercase();
    PROGRAMMES_IA
        .iter()
        .any(|n| programme.contains(n))
        .then(|| p.programme.clone())
}

/// Les ports que Vanguard a fermés en entrée : sa note (« 11434/tcp », ufw) et, sous Windows, ses règles « Vanguard :
/// bloquer `<port>` » relues dans le pare-feu.
pub(crate) fn ports_fermes() -> HashSet<u16> {
    let notes = super::ports_bloques();
    let fermes = notes.iter().filter_map(|p| p.strip_suffix("/tcp")?.parse::<u16>().ok());
    #[cfg(windows)]
    let fermes = fermes.chain(super::windows::ecoute::ports_bloques().unwrap_or_default());
    fermes.collect()
}

/// Ce que le système dit des programmes derrière les prises.
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // chaque système n'en construit qu'une partie
pub(crate) enum Noms {
    /// Les noms que le système donne sans réserve propre au contrôle : Windows nomme chaque prise ; Linux nomme les
    /// services (root compris, par leur groupe de contrôle) et les programmes du compte, comme le bilan des ports.
    Complets,
    /// Seulement ceux du compte en cours (lsof sans droits admin, macOS).
    CompteSeul,
    /// Aucun nom (lsof absent ou en échec) : seuls les ports connus des serveurs d'IA se reconnaissent.
    Aucun,
}

/// `fermes` : les ports que Vanguard a fermés au réseau (blocage) ; un serveur derrière l'un d'eux n'est plus ouvert.
/// `noms` : sans noms complets, « aucun serveur » se dit avec sa réserve, et sans aucun nom il n'est pas vérifié.
fn juger_exposition(prises: &[Prise], fermes: &HashSet<u16>, noms: Noms) -> Constat {
    let mut ouverts: Vec<String> = Vec::new();
    let mut proteges: Vec<String> = Vec::new();
    for p in prises.iter().filter(|p| {
        !p.adresse
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|a| a.is_loopback())
    }) {
        if let Some(nom) = serveur_ia(p) {
            let ligne = format!("{nom} ({}:{})", p.adresse, p.port);
            if fermes.contains(&p.port) {
                proteges.push(ligne);
            } else {
                ouverts.push(ligne);
            }
        }
    }
    ouverts.sort();
    ouverts.dedup();
    proteges.sort();
    proteges.dedup();
    let reserve = match noms {
        Noms::Complets => String::new(),
        Noms::CompteSeul => tr!(
            " (seuls les programmes du compte en cours sont nommés sans droits d'administrateur : un serveur d'IA d'un autre compte ne se reconnaît qu'à ses ports connus)",
            " (without administrator rights, only the current account's programs are named: an AI server from another account is only recognized by its known ports)"
        )
        .to_string(),
        Noms::Aucun => tr!(
            " (lsof n'a pas nommé les programmes en écoute : seuls les ports connus des serveurs d'IA ont été regardés)",
            " (lsof did not name the listening programs: only the known ports of AI servers were checked)"
        )
        .to_string(),
    };
    // Sans aucun nom, un serveur sur un autre port reste invisible, qu'un autre soit fermé par Vanguard ou non.
    if ouverts.is_empty() && noms == Noms::Aucun {
        return impossible(
            CAT,
            tr!(
                "serveurs d'IA ouverts au réseau : lsof n'a pas nommé les programmes en écoute, seuls les ports connus des serveurs d'IA ont été regardés",
                "AI servers open to the network: lsof did not name the listening programs, only the known ports of AI servers were checked"
            ),
        );
    }
    if ouverts.is_empty() && !proteges.is_empty() {
        let liste = couper(&affichable(&proteges.join(", ")), 200);
        return ok(
            CAT,
            trf!(
                "Serveur d'IA fermé au réseau par une règle de pare-feu de Vanguard : {liste}{reserve}",
                "AI server closed to the network by a Vanguard firewall rule: {liste}{reserve}"
            ),
        );
    }
    if ouverts.is_empty() {
        return ok(
            CAT,
            trf!(
                "Aucun serveur d'IA local ouvert au réseau{reserve}",
                "No local AI server open to the network{reserve}"
            ),
        );
    }
    let liste = couper(&affichable(&ouverts.join(", ")), 200);
    alerte(
        CAT,
        Niveau::Eleve,
        trf!(
            "Serveur d'IA ouvert au réseau, sans mot de passe : {liste}. N'importe quel appareil du Wi-Fi peut s'en servir (et, selon l'outil, lire ou écrire des fichiers). Faites-le écouter sur 127.0.0.1 seulement (Ollama : OLLAMA_HOST=127.0.0.1).",
            "AI server open to the network, without a password: {liste}. Any device on the Wi-Fi can use it (and, depending on the tool, read or write files). Make it listen on 127.0.0.1 only (Ollama: OLLAMA_HOST=127.0.0.1)."
        ),
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn prises() -> Option<Vec<Prise>> {
    Some(
        super::linux::ecoute::prises_ou_ss()?
            .into_iter()
            .filter(|e| !e.udp)
            .map(|e| Prise {
                adresse: e.adresse.to_string(),
                port: e.port,
                programme: e.nom().unwrap_or_default(),
            })
            .collect(),
    )
}

#[cfg(windows)]
pub(crate) fn prises() -> Option<Vec<Prise>> {
    Some(
        super::windows::ecoute::ecoutes()?
            .into_iter()
            .filter(|e| e.tcp)
            .map(|e| Prise {
                adresse: e.adresse,
                port: e.port,
                programme: e.nom,
            })
            .collect(),
    )
}

/// macOS : `netstat -an -p tcp`, lu comme pour le bilan des ports (netstat fait foi pour les prises de tous les
/// comptes : leurs structures du noyau, xinpcb_n, sont privées) ; les noms viennent du noyau (libproc, lsof en
/// secours), qui sans droits admin ne nomme que les programmes du compte en cours (`Noms::CompteSeul`), et pas du tout
/// s'il échoue (`Noms::Aucun`).
#[cfg(target_os = "macos")]
pub(crate) fn prises_et_noms() -> Option<(Vec<Prise>, Noms)> {
    let netstat = super::sortie("netstat", &["-an", "-p", "tcp"])?;
    Some(match super::prises_du_compte() {
        Some(lsof) => (prises_netstat(&netstat, &lsof), Noms::CompteSeul),
        None => (prises_netstat(&netstat, &[]), Noms::Aucun),
    })
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn prises_et_noms() -> Option<(Vec<Prise>, Noms)> {
    prises().map(|p| (p, Noms::Complets))
}

/// Les ports TCP en écoute du netstat des BSD, dans la forme que `juger_exposition` attend. « * » (toutes les
/// adresses, tcp4 comme tcp6) devient 0.0.0.0 : la même ligne pour les deux, ouverte au réseau. Une adresse de lien
/// de la boucle (« fe80::1%lo0 ») devient ::1, pour rester locale ; celle d'une vraie interface (« %en0 ») garde sa
/// zone, que l'analyse d'adresse refuse : ouverte, puisque les voisins du Wi-Fi la joignent.
/// `lsof` : (adresse, port, programme) ; chaque prise prend les noms de la même adresse et du même port, sinon ceux
/// de tous les programmes du port : un serveur d'IA parmi eux reste reconnu plutôt que caché derrière un autre. Tous
/// les noms, pas le premier : « * » vaut pour tcp4 comme pour tcp6, et une prise héritée a plusieurs programmes.
#[cfg(unix)]
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn prises_netstat(netstat: &str, lsof: &[(String, u16, String)]) -> Vec<Prise> {
    let programme = |adresse: &str, port: u16| {
        let noms = |meme_adresse: bool| {
            let mut noms: Vec<&str> = lsof
                .iter()
                .filter(|(a, p, _)| *p == port && (!meme_adresse || a == adresse))
                .map(|(_, _, nom)| nom.as_str())
                .collect();
            noms.sort_unstable();
            noms.dedup();
            noms.join(", ")
        };
        Some(noms(true))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| noms(false))
    };
    super::unix::lire_netstat(netstat, true)
        .into_iter()
        .map(|(adresse, port)| Prise {
            programme: programme(&adresse, port),
            adresse: if adresse == "*" {
                "0.0.0.0".to_string()
            } else if adresse.split_once('%').is_some_and(|(_, zone)| zone.starts_with("lo")) {
                "::1".to_string()
            } else {
                adresse
            },
            port,
        })
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn prises() -> Option<Vec<Prise>> {
    None
}

pub(crate) fn exposition() -> Vec<Constat> {
    match prises_et_noms() {
        Some((p, noms)) => vec![juger_exposition(&p, &ports_fermes(), noms)],
        None => vec![impossible(
            CAT,
            tr!(
                "serveurs d'IA ouverts au réseau : ports en écoute illisibles ici",
                "AI servers open to the network: listening ports unreadable here"
            ),
        )],
    }
}

// --------------------------------------------------------------------------------------------- réglages des agents

/// Ce qu'un fichier de réglages apprend : (outil, problème trouvé).
#[derive(Default)]
struct Trouvailles {
    tout_permis: Vec<String>,
    commandes_permises: Vec<String>,
    non_epingles: Vec<String>,
    sans_chiffrement: Vec<String>,
    cles_en_clair: Vec<String>,
    serveurs: usize,
}

/// Les options d'un lanceur suivies d'une valeur (« --python 3.12 ») : sautées avec elle, pour que la valeur ne passe
/// pas pour le paquet. Le second groupe nomme le paquet lui-même (« uvx --from paquet==1.0 commande », « npx -p paquet
/// commande ») : c'est lui qui est jugé, et non la commande qui suit.
const OPTIONS_PYTHON: [&str; 5] = ["--python", "-p", "--with", "--index-url", "--pip-args"];
const PAQUET_PYTHON: [&str; 2] = ["--from", "--spec"];
const PAQUET_JS: [&str; 2] = ["--package", "-p"];

/// Le nom d'un lanceur, sans dossier ni extension, en minuscules : « /usr/bin/npx », « NPX.cmd » → « npx ».
fn nom_du_lanceur(commande: &str) -> String {
    Path::new(commande)
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Le paquet lancé par un lanceur (`npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx run`), s'il n'a pas de version fixée.
/// « cmd /c npx -y paquet », la forme de Claude Desktop sous Windows, est jugée comme « npx -y paquet ».
fn paquet_non_epingle(commande: &str, args: &[&str]) -> Option<String> {
    let lanceur = nom_du_lanceur(commande);
    if lanceur == "cmd" {
        // cmd relit la ligne qui suit /c (ou /k) : un mot peut en porter plusieurs. Les « cmd /c » imbriqués se
        // déroulent en boucle, sur des mots découpés une seule fois : en récursion, « cmd /c » répété cinquante mille
        // fois (un fichier de réglages piégé, 350 Ko) faisait déborder la pile, ce qui arrête tout le programme.
        let barre = |a: &&str| a.eq_ignore_ascii_case("/c") || a.eq_ignore_ascii_case("/k");
        let i = args.iter().position(barre)?;
        let mots: Vec<&str> = args[i + 1..].iter().flat_map(|a| a.split_whitespace()).collect();
        let mut reste = &mots[..];
        loop {
            let (commande, suite) = reste.split_first()?;
            if nom_du_lanceur(commande) != "cmd" {
                return paquet_non_epingle(commande, suite);
            }
            reste = &suite[suite.iter().position(barre)? + 1..];
        }
    }
    let mut reste = args.iter().copied();
    match lanceur.as_str() {
        "npx" | "bunx" | "uvx" => {}
        "pnpm" | "yarn" => {
            reste.find(|a| *a == "dlx")?;
        }
        "pipx" => {
            reste.find(|a| *a == "run")?;
        }
        _ => return None,
    }
    let pyth = lanceur == "uvx" || lanceur == "pipx";
    let (avec_valeur, nomment): (&[&str], &[&str]) = if pyth {
        (&OPTIONS_PYTHON, &PAQUET_PYTHON)
    } else {
        (&[], &PAQUET_JS)
    };
    let mut nommes = Vec::new();
    let mut premier = None;
    while let Some(a) = reste.next() {
        let (option, valeur) = match a.split_once('=') {
            Some((o, v)) if a.starts_with('-') => (o, Some(v)),
            _ => (a, None),
        };
        if nomment.contains(&option) {
            nommes.extend(valeur.or_else(|| reste.next()));
        } else if avec_valeur.contains(&option) {
            if valeur.is_none() {
                reste.next();
            }
        } else if premier.is_none() && !a.is_empty() && !a.starts_with('-') {
            premier = Some(a);
        }
    }
    let candidats = if nommes.is_empty() {
        Vec::from_iter(premier)
    } else {
        nommes
    };
    let non_epingle = |paquet: &&str| {
        let epingle = if pyth {
            paquet.contains("==") || paquet.contains('@')
        } else {
            // « @portee/nom@1.2.3 » ou « nom@1.2.3 » : le @ de la version vient après le premier caractère.
            paquet.chars().skip(1).any(|c| c == '@')
        };
        let flottant = paquet.ends_with("@latest") || paquet.ends_with("@next");
        !epingle || flottant
    };
    candidats.into_iter().find(non_epingle).map(str::to_string)
}

/// Les mots d'un nom qui désignent un secret, comparés entiers : « TOKENIZERS » n'est pas « TOKEN », ni « MONKEY »
/// « KEY ».
const MOTS_SECRETS: [&str; 14] = [
    "KEY",
    "KEYS",
    "APIKEY",
    "TOKEN",
    "TOKENS",
    "SECRET",
    "SECRETS",
    "PASSWORD",
    "PASSWORDS",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "CREDENTIALS",
    "AUTHORIZATION",
];

/// Le dernier mot d'un nom qui dit où est le secret, ou comment il s'appelle, et non le secret lui-même :
/// PASSWORD_STORE_DIR, API_KEY_FILE, TOKEN_URL, AWS_ACCESS_KEY_ID.
const MOTS_HORS_SECRET: [&str; 14] = [
    "DIR",
    "DIRECTORY",
    "PATH",
    "FILE",
    "STORE",
    "URL",
    "URI",
    "HOST",
    "PORT",
    "ENDPOINT",
    "ID",
    "NAME",
    "TYPE",
    "HEADER",
];

/// Les mots d'un nom, en majuscules : coupé aux « _ », « - » et « . », et entre une minuscule et une majuscule
/// (« apiKey », « accessToken »).
fn mots(nom: &str) -> Vec<String> {
    let mut mots = Vec::new();
    let mut mot = String::new();
    let mut apres_minuscule = false;
    for c in nom.chars() {
        let separateur = matches!(c, '_' | '-' | '.');
        if (separateur || (apres_minuscule && c.is_uppercase())) && !mot.is_empty() {
            mots.push(std::mem::take(&mut mot));
        }
        if !separateur {
            mot.extend(c.to_uppercase());
        }
        apres_minuscule = c.is_lowercase();
    }
    if !mot.is_empty() {
        mots.push(mot);
    }
    mots
}

fn ressemble_a_un_secret(nom: &str) -> bool {
    let mots = mots(nom);
    mots.iter().any(|m| MOTS_SECRETS.contains(&m.as_str()))
        && mots.last().is_some_and(|m| !MOTS_HORS_SECRET.contains(&m.as_str()))
}

/// Les schémas d'authentification écrits devant le secret dans un en-tête (« Bearer jeton », « Basic base64 »).
const SCHEMAS: [&str; 3] = ["Bearer", "Basic", "Token"];

/// Une valeur écrite en clair, et non une référence à un secret gardé ailleurs : variable (« ${VAR} », « $VAR »,
/// « ${env:VAR} », « env:VAR »), invite de VS Code (« ${input:jeton} »), y compris derrière un schéma
/// d'authentification (« Bearer ${API_KEY} », « Basic ${IDENTIFIANTS} »).
fn en_clair(valeur: &Value) -> bool {
    let Some(v) = valeur.as_str().map(str::trim) else {
        return false;
    };
    let v = match v.split_once(char::is_whitespace) {
        Some((schema, reste)) if SCHEMAS.iter().any(|s| s.eq_ignore_ascii_case(schema)) => reste.trim(),
        _ => v,
    };
    !v.is_empty() && !v.starts_with('$') && !v.starts_with("env:") && !v.starts_with("{env:")
}

fn lire_serveurs(outil: &str, serveurs: &serde_json::Map<String, Value>, t: &mut Trouvailles) {
    for (nom, s) in serveurs {
        t.serveurs += 1;
        let qui = format!("{outil} › {nom}");
        if let Some(commande) = s.get("command").and_then(Value::as_str) {
            let args: Vec<&str> = s
                .get("args")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if let Some(paquet) = paquet_non_epingle(commande, &args) {
                t.non_epingles.push(format!("{qui} ({paquet})"));
            }
        }
        for champ in ["url", "serverUrl", "httpUrl"] {
            if let Some(url) = s.get(champ).and_then(Value::as_str)
                && let Some(reste) = url.trim().strip_prefix("http://")
            {
                let hote = match reste.strip_prefix('[') {
                    Some(v6) => v6.split(']').next().unwrap_or_default(),
                    None => reste.split(['/', ':']).next().unwrap_or_default(),
                };
                let local = hote == "localhost" || hote.parse::<IpAddr>().is_ok_and(|a| a.is_loopback());
                if !local {
                    t.sans_chiffrement.push(qui.clone());
                }
            }
        }
        for champ in ["env", "headers"] {
            if let Some(valeurs) = s.get(champ).and_then(Value::as_object) {
                for (cle, v) in valeurs {
                    if ressemble_a_un_secret(cle) && en_clair(v) {
                        t.cles_en_clair.push(format!("{qui} ({cle})"));
                    }
                }
            }
        }
    }
}

/// Un agent y est-il réglé pour tout faire sans demander (« defaultMode » à « bypassPermissions », dans les
/// permissions ou dans un projet de ~/.claude.json) ? Ce que le blocage remet aux demandes de permission.
pub(crate) fn tout_permis(json: &Value) -> bool {
    let mut t = Trouvailles::default();
    lire_reglages("", json, &mut t);
    !t.tout_permis.is_empty()
}

/// Les permissions de Claude Code : le mode par défaut et la liste des outils permis sans demander.
fn lire_permissions(outil: &str, permissions: &Value, t: &mut Trouvailles) {
    if permissions.get("defaultMode").and_then(Value::as_str) == Some("bypassPermissions") {
        t.tout_permis.push(outil.to_string());
    }
    let permis = permissions
        .get("allow")
        .or_else(|| permissions.get("allowedTools"))
        .and_then(Value::as_array);
    if permis.is_some_and(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .any(|p| matches!(p.trim(), "Bash" | "Bash(*)" | "Bash(:*)" | "Bash(**)"))
    }) {
        t.commandes_permises.push(outil.to_string());
    }
}

/// Ce que dit un fichier de réglages d'un outil, quelle que soit sa forme : serveurs MCP (« mcpServers », « servers »,
/// « mcp.servers »), permissions de Claude Code, et pour ~/.claude.json, les mêmes par projet.
fn lire_reglages(outil: &str, json: &Value, t: &mut Trouvailles) {
    for serveurs in [
        json.get("mcpServers"),
        json.get("servers"),
        json.get("mcp").and_then(|m| m.get("servers")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_object)
    {
        lire_serveurs(outil, serveurs, t);
    }
    if let Some(p) = json.get("permissions") {
        lire_permissions(outil, p, t);
    }
    if let Some(projets) = json.get("projects").and_then(Value::as_object) {
        for (chemin, projet) in projets {
            let nom = Path::new(chemin)
                .file_name()
                .map_or_else(|| chemin.clone(), |n| n.to_string_lossy().into_owned());
            let ici = format!("{outil} ({nom})");
            if let Some(serveurs) = projet.get("mcpServers").and_then(Value::as_object) {
                lire_serveurs(&ici, serveurs, t);
            }
            lire_permissions(&ici, projet, t);
        }
    }
}

/// `fichiers` : les fichiers lus ; `illisibles` : les outils dont le fichier est là mais n'a pas pu être lu, avec la
/// raison (« Cursor (JSON invalide) »).
fn juger_reglages(t: &Trouvailles, fichiers: usize, illisibles: &[String]) -> Vec<Constat> {
    let liste = |v: &[String]| couper(&affichable(&v.join(", ")), 200);
    let mut constats = Vec::new();
    if !t.tout_permis.is_empty() {
        let l = liste(&t.tout_permis);
        constats.push(alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "Agent d'IA réglé pour tout faire sans demander (bypassPermissions) : {l}. Une page ou un fichier piégé qu'il lit peut lui faire lancer n'importe quelle commande. Remettez les demandes de permission (defaultMode « default » ou « acceptEdits »).",
                "AI agent set to do everything without asking (bypassPermissions): {l}. A booby-trapped page or file it reads can make it run any command. Turn permission prompts back on (defaultMode “default” or “acceptEdits”)."
            ),
        ));
    }
    if !t.commandes_permises.is_empty() {
        let l = liste(&t.commandes_permises);
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Agent d'IA autorisé à lancer toute commande sans demander (Bash) : {l}. Ne permets que des commandes précises (par exemple « Bash(git status) »).",
                "AI agent allowed to run any command without asking (Bash): {l}. Only allow precise commands (for example “Bash(git status)”)."
            ),
        ));
    }
    if !t.non_epingles.is_empty() {
        let l = liste(&t.non_epingles);
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Serveur MCP lancé sans version fixée : {l}. Chaque lancement prend la dernière version publiée ; si elle est piégée, elle s'exécute avec vos droits. Fixez la version (« paquet@1.2.3 »).",
                "MCP server started without a pinned version: {l}. Each start takes the latest published version; if it is booby-trapped, it runs with your rights. Pin the version (“package@1.2.3”)."
            ),
        ));
    }
    if !t.sans_chiffrement.is_empty() {
        let l = liste(&t.sans_chiffrement);
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Serveur MCP joint sans chiffrement (http://) : {l}. Sur le réseau, ses réponses peuvent être lues ou changées, et un agent obéit à ce qu'il reçoit. Utilisez https.",
                "MCP server reached without encryption (http://): {l}. On the network its answers can be read or changed, and an agent obeys what it receives. Use https."
            ),
        ));
    }
    if !t.cles_en_clair.is_empty() {
        let l = liste(&t.cles_en_clair);
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Clé ou jeton écrit en clair dans les réglages d'un serveur MCP : {l}. Tout programme de votre compte peut le lire. Passez-le par une variable d'environnement (« ${{NOM}} ») ou le trousseau.",
                "Key or token written in clear text in an MCP server's settings: {l}. Any program of your account can read it. Pass it through an environment variable (“${{NAME}}”) or the keychain."
            ),
        ));
    }
    if constats.is_empty() {
        let n = t.serveurs;
        if fichiers > 0 {
            constats.push(ok(
                CAT,
                trf!(
                    "Agents d'IA : {fichiers} fichier(s) de réglages, {n} serveur(s) MCP, rien de risqué",
                    "AI agents: {fichiers} settings file(s), {n} MCP server(s), nothing risky"
                ),
            ));
        } else if illisibles.is_empty() {
            constats.push(ok(CAT, tr!("Aucun agent d'IA configuré", "No AI agent configured")));
        }
    }
    if !illisibles.is_empty() {
        let l = liste(illisibles);
        constats.push(impossible(
            CAT,
            &trf!(
                "réglages d'agents d'IA présents mais illisibles : {l}",
                "AI agent settings present but unreadable: {l}"
            ),
        ));
    }
    constats
}

/// Les fichiers de réglages connus : (outil, chemin).
pub(crate) fn fichiers_de_reglages() -> Vec<(&'static str, PathBuf)> {
    let maison =
        PathBuf::from(std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).unwrap_or_default());
    if maison.as_os_str().is_empty() {
        return Vec::new();
    }
    let config = if cfg!(windows) {
        PathBuf::from(std::env::var_os("APPDATA").unwrap_or_default())
    } else if cfg!(target_os = "macos") {
        maison.join("Library/Application Support")
    } else {
        std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from)
    };
    vec![
        ("Claude Code", maison.join(".claude/settings.json")),
        ("Claude Code", maison.join(".claude/settings.local.json")),
        ("Claude Code", maison.join(".claude.json")),
        ("Claude Desktop", config.join("Claude/claude_desktop_config.json")),
        ("Cursor", maison.join(".cursor/mcp.json")),
        ("VS Code", config.join("Code/User/mcp.json")),
        ("Windsurf", maison.join(".codeium/windsurf/mcp_config.json")),
        ("Gemini CLI", maison.join(".gemini/settings.json")),
    ]
}

/// Au-delà, ce n'est pas un fichier de réglages (~/.claude.json grossit avec l'historique des projets) : il n'est
/// pas lu, et l'outil est dit non vérifié.
const REGLAGES_MAX: u64 = 64 << 20;

/// Les réglages d'un fichier : `Ok(None)` s'il n'existe pas (l'outil n'est pas installé), `Err` avec la raison s'il
/// est là mais ne se lit pas (droits, trop gros, ni JSON ni JSONC).
fn lire_fichier(chemin: &Path) -> Result<Option<Value>, String> {
    use std::io::ErrorKind::NotFound;
    let illisible = || tr!("illisible", "unreadable").to_string();
    let taille = match std::fs::metadata(chemin) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == NotFound => return Ok(None),
        Err(_) => return Err(illisible()),
    };
    if taille > REGLAGES_MAX {
        return Err(trf!("plus de {} Mio", "over {} MiB", REGLAGES_MAX >> 20));
    }
    let octets = match std::fs::read(chemin) {
        Ok(o) => o,
        Err(e) if e.kind() == NotFound => return Ok(None),
        Err(_) => return Err(illisible()),
    };
    lire_json(&octets)
        .map(Some)
        .ok_or_else(|| tr!("JSON invalide", "invalid JSON").to_string())
}

pub(crate) fn reglages() -> Vec<Constat> {
    let mut t = Trouvailles::default();
    let mut lus = 0;
    let mut illisibles = Vec::new();
    for (outil, chemin) in fichiers_de_reglages() {
        match lire_fichier(&chemin) {
            Ok(None) => {}
            Ok(Some(json)) => {
                lus += 1;
                lire_reglages(outil, &json, &mut t);
            }
            Err(raison) => illisibles.push(format!("{outil} ({raison})")),
        }
    }
    juger_reglages(&t, lus, &illisibles)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prise(adresse: &str, port: u16, programme: &str) -> Prise {
        Prise {
            adresse: adresse.into(),
            port,
            programme: programme.into(),
        }
    }

    #[test]
    fn serveurs_d_ia_exposes() {
        let locaux = [
            prise("127.0.0.1", 11434, "ollama"),
            prise("::1", 1234, ""),
            prise("0.0.0.0", 22, "sshd"),
        ];
        let aucun = HashSet::new();
        assert!(juger_exposition(&locaux, &aucun, Noms::Complets).probleme.is_none());
        let ouvert = [prise("0.0.0.0", 11434, "ollama"), prise("[::]", 8188, "python3")];
        let c = juger_exposition(&ouvert, &aucun, Noms::Complets);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("Ollama (0.0.0.0:11434)") && c.message.contains("ComfyUI"));
        // Reconnu par son nom, sur un autre port.
        assert!(
            juger_exposition(&[prise("192.168.1.20", 9000, "llama-server")], &aucun, Noms::Complets)
                .probleme
                .is_some()
        );
        // Fermé au réseau par une règle de Vanguard (blocage) : plus une alerte, mais dit.
        let un_ferme = juger_exposition(&ouvert, &[11434].into(), Noms::Complets);
        assert!(un_ferme.probleme.is_some() && !un_ferme.message.contains("11434"));
        let fermes = juger_exposition(&ouvert, &[11434, 8188].into(), Noms::Complets);
        assert!(fermes.probleme.is_none() && fermes.message.contains("Ollama (0.0.0.0:11434)"));
    }

    /// macOS : netstat → prises, jugées comme sous Linux et Windows.
    #[cfg(unix)]
    #[test]
    fn prises_du_netstat_des_bsd() {
        let netstat = "Active Internet connections (including servers)\n\
                       Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n\
                       tcp46      0      0  *.11434                *.*                    LISTEN\n\
                       tcp6       0      0  *.11434                *.*                    LISTEN\n\
                       tcp4       0      0  127.0.0.1.1234         *.*                    LISTEN\n\
                       tcp6       0      0  ::1.8188               *.*                    LISTEN\n\
                       tcp6       0      0  fe80::1%lo0.7860       *.*                    LISTEN\n\
                       tcp4       0      0  192.168.1.20.9000      *.*                    LISTEN\n\
                       tcp4       0      0  10.0.0.20.51234        17.57.146.20.443       ESTABLISHED\n";
        let programmes = [
            ("*".to_string(), 11434, "ollama".to_string()),
            ("192.168.1.20".to_string(), 9000, "llama-server".to_string()),
        ];
        let p = prises_netstat(netstat, &programmes);
        let vues: Vec<(&str, u16, &str)> = p
            .iter()
            .map(|p| (p.adresse.as_str(), p.port, p.programme.as_str()))
            .collect();
        assert_eq!(
            vues,
            [
                ("0.0.0.0", 11434, "ollama"),
                ("0.0.0.0", 11434, "ollama"),
                ("127.0.0.1", 1234, ""),
                ("::1", 8188, ""),
                ("::1", 7860, ""),
                ("192.168.1.20", 9000, "llama-server"),
            ]
        );
        // Ollama sur toutes les adresses (une seule ligne pour tcp46 et tcp6) et llama-server sur le Wi-Fi : ouverts ;
        // les trois autres restent sur la boucle.
        let c = juger_exposition(&p, &HashSet::new(), Noms::CompteSeul);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert_eq!(c.message.matches("Ollama (0.0.0.0:11434)").count(), 1);
        assert!(c.message.contains("llama-server (192.168.1.20:9000)"));
        assert!(!c.message.contains("LM Studio") && !c.message.contains("ComfyUI") && !c.message.contains("Gradio"));
        // Zone d'une vraie interface : ouverte.
        let lien = prises_netstat("tcp6  0  0  fe80::1c2:3%en0.11434  *.*  LISTEN\n", &programmes);
        assert!(
            juger_exposition(&lien, &HashSet::new(), Noms::CompteSeul)
                .probleme
                .is_some()
        );
    }

    /// macOS : le même port sur deux adresses. Chaque prise prend le programme de son adresse : llama-server ouvert au
    /// Wi-Fi n'est pas caché par nginx sur la boucle, et l'inverse ne donne pas de fausse alerte. Sans adresse
    /// correspondante, tous les noms du port.
    #[cfg(unix)]
    #[test]
    fn meme_port_deux_adresses() {
        let netstat = "tcp4  0  0  127.0.0.1.8080  *.*  LISTEN\n\
                       tcp4  0  0  192.168.1.20.8080  *.*  LISTEN\n";
        let ia_ouvert = [
            ("192.168.1.20".to_string(), 8080, "llama-server".to_string()),
            ("127.0.0.1".to_string(), 8080, "nginx".to_string()),
        ];
        let c = juger_exposition(&prises_netstat(netstat, &ia_ouvert), &HashSet::new(), Noms::CompteSeul);
        assert!(c.message.contains("llama-server (192.168.1.20:8080)"), "{}", c.message);
        let ia_local = [
            ("127.0.0.1".to_string(), 8080, "llama-server".to_string()),
            ("192.168.1.20".to_string(), 8080, "nginx".to_string()),
        ];
        let c = juger_exposition(&prises_netstat(netstat, &ia_local), &HashSet::new(), Noms::CompteSeul);
        assert!(c.probleme.is_none(), "{}", c.message);
        // nginx en IPv4 et llama-server en IPv6 seul, tous deux sur « * » : les deux noms, le serveur d'IA vu.
        let deux_familles = [
            ("*".to_string(), 8080, "nginx".to_string()),
            ("*".to_string(), 8080, "llama-server".to_string()),
        ];
        let p = prises_netstat(
            "tcp4  0  0  *.8080  *.*  LISTEN\ntcp6  0  0  *.8080  *.*  LISTEN\n",
            &deux_familles,
        );
        assert!(p.iter().all(|p| p.programme == "llama-server, nginx"));
        assert!(
            juger_exposition(&p, &HashSet::new(), Noms::CompteSeul)
                .probleme
                .is_some()
        );
        let ailleurs = [("10.0.0.5".to_string(), 8080, "llama-server".to_string())];
        let p = prises_netstat("tcp4  0  0  *.8080  *.*  LISTEN\n", &ailleurs);
        assert_eq!(p[0].programme, "llama-server");
    }

    /// Sans noms complets, « aucun serveur » porte sa réserve ; sans aucun nom, il n'est pas vérifié. Un serveur sur un
    /// port connu reste vu dans les deux cas.
    #[test]
    fn reserve_sans_noms_complets() {
        let inconnu = [prise("0.0.0.0", 8080, "")];
        let complets = juger_exposition(&inconnu, &HashSet::new(), Noms::Complets);
        assert!(complets.verifie && !complets.message.contains('('));
        let compte = juger_exposition(&inconnu, &HashSet::new(), Noms::CompteSeul);
        assert!(compte.probleme.is_none() && compte.verifie && compte.message.len() > complets.message.len());
        let aucun = juger_exposition(&inconnu, &HashSet::new(), Noms::Aucun);
        assert!(!aucun.verifie && aucun.message.contains("lsof"), "{}", aucun.message);
        let connu = juger_exposition(&[prise("0.0.0.0", 11434, "")], &HashSet::new(), Noms::Aucun);
        assert_eq!(connu.probleme, Some(Niveau::Eleve));
        // Un serveur fermé par Vanguard ne rend pas vert ce qui n'a pas pu être nommé.
        let ferme = juger_exposition(
            &[prise("0.0.0.0", 11434, ""), prise("0.0.0.0", 9000, "")],
            &[11434].into(),
            Noms::Aucun,
        );
        assert!(!ferme.verifie, "{}", ferme.message);
    }

    #[test]
    fn paquets_epingles_ou_non() {
        assert_eq!(
            paquet_non_epingle("npx", &["-y", "@outils/serveur-mcp"]),
            Some("@outils/serveur-mcp".into())
        );
        assert_eq!(paquet_non_epingle("npx", &["-y", "@outils/serveur-mcp@1.4.2"]), None);
        assert_eq!(
            paquet_non_epingle("npx", &["serveur@latest"]),
            Some("serveur@latest".into())
        );
        assert_eq!(paquet_non_epingle("/usr/bin/npx", &["serveur@2.0.0"]), None);
        assert_eq!(paquet_non_epingle("uvx", &["mcp-serveur"]), Some("mcp-serveur".into()));
        assert_eq!(paquet_non_epingle("uvx", &["mcp-serveur==0.3.1"]), None);
        assert_eq!(paquet_non_epingle("pnpm", &["dlx", "outil"]), Some("outil".into()));
        assert_eq!(paquet_non_epingle("node", &["serveur.js"]), None);
        assert_eq!(paquet_non_epingle("npx.cmd", &["-y", "outil"]), Some("outil".into()));
    }

    /// Une option suivie de sa valeur n'est pas le paquet ; une option qui nomme le paquet le donne à juger.
    #[test]
    fn options_avant_le_paquet() {
        assert_eq!(paquet_non_epingle("uvx", &["--python", "3.12", "paquet==1.0"]), None);
        assert_eq!(
            paquet_non_epingle("uvx", &["--python", "3.12", "paquet"]),
            Some("paquet".into())
        );
        assert_eq!(
            paquet_non_epingle("uvx", &["-p", "3.12", "--with", "outil-b", "paquet==2.1"]),
            None
        );
        assert_eq!(paquet_non_epingle("uvx", &["--python=3.12", "paquet==1.0"]), None);
        assert_eq!(
            paquet_non_epingle("uvx", &["--index-url", "https://depot.exemple/simple", "paquet"]),
            Some("paquet".into())
        );
        // « --from » nomme le paquet ; ce qui suit est la commande qu'il fournit.
        assert_eq!(
            paquet_non_epingle("uvx", &["--from", "serveur-git==0.6.2", "serveur-git"]),
            None
        );
        assert_eq!(
            paquet_non_epingle("uvx", &["--from", "serveur-git", "serveur-git"]),
            Some("serveur-git".into())
        );
        assert_eq!(
            paquet_non_epingle("uvx", &["--from=serveur-git==0.6.2", "serveur-git"]),
            None
        );
        assert_eq!(
            paquet_non_epingle("pipx", &["run", "--python", "3.11", "outil==3.0"]),
            None
        );
        assert_eq!(
            paquet_non_epingle("pipx", &["run", "--spec", "outil==3.0", "outil"]),
            None
        );
        assert_eq!(paquet_non_epingle("npx", &["-p", "@exemple/cli@1.2.0", "cli"]), None);
        assert_eq!(
            paquet_non_epingle("npx", &["--package", "@exemple/cli", "cli"]),
            Some("@exemple/cli".into())
        );
        assert_eq!(
            paquet_non_epingle("npx", &["--package=@exemple/cli@1.2.0", "cli"]),
            None
        );
        assert_eq!(
            paquet_non_epingle("npx", &["-y", "-p", "a@1.0.0", "-p", "b", "cli"]),
            Some("b".into())
        );
    }

    /// « cmd /c npx -y paquet » (Claude Desktop sous Windows) se juge comme « npx -y paquet ».
    #[test]
    fn cmd_avant_le_lanceur() {
        assert_eq!(
            paquet_non_epingle("cmd", &["/c", "npx", "-y", "@exemple/fichiers"]),
            Some("@exemple/fichiers".into())
        );
        assert_eq!(
            paquet_non_epingle("cmd.exe", &["/C", "npx", "-y", "@exemple/fichiers@1.4.2"]),
            None
        );
        assert_eq!(
            paquet_non_epingle("CMD.EXE", &["/s", "/k", "uvx", "--python", "3.12", "outil"]),
            Some("outil".into())
        );
        // cmd relit la ligne : un seul mot peut porter la commande entière.
        assert_eq!(
            paquet_non_epingle("cmd", &["/c", "npx -y @exemple/fichiers"]),
            Some("@exemple/fichiers".into())
        );
        assert_eq!(paquet_non_epingle("cmd", &["/c", "node", "serveur.js"]), None);
        assert_eq!(paquet_non_epingle("cmd", &["/c"]), None);
        assert_eq!(paquet_non_epingle("cmd", &["npx", "-y", "outil"]), None);
        // Imbriqués, en mots séparés ou dans un seul : déroulés. Trouvé en écrivant les tests d'entrées hostiles : cinquante
        // mille « cmd /c » faisaient déborder la pile (récursion), ce qui arrêtait tout le programme.
        assert_eq!(
            paquet_non_epingle("cmd", &["/c", "cmd", "/k", "CMD.EXE", "/c", "npx", "outil"]),
            Some("outil".into())
        );
        let imbriques = "cmd /c ".repeat(50_000) + "npx outil";
        assert_eq!(paquet_non_epingle("cmd", &["/c", &imbriques]), Some("outil".into()));
        assert_eq!(paquet_non_epingle("cmd", &["/c", &"cmd /c ".repeat(50_000)]), None);
        let json: Value = serde_json::from_str(
            r#"{ "mcpServers": { "fichiers": { "command": "cmd", "args": ["/c", "npx", "-y", "@exemple/fichiers", "C:\\Users\\alice"] } } }"#,
        )
        .unwrap();
        let mut t = Trouvailles::default();
        lire_reglages("Claude Desktop", &json, &mut t);
        assert_eq!(t.non_epingles, ["Claude Desktop › fichiers (@exemple/fichiers)"]);
    }

    #[test]
    fn reglages_risques() {
        let json: Value = serde_json::from_str(
            r#"{
              "permissions": { "defaultMode": "bypassPermissions", "allow": ["Bash", "Read"] },
              "mcpServers": {
                "fichiers": { "command": "npx", "args": ["-y", "@exemple/fichiers"], "env": { "API_KEY": "abc123", "CHEMIN": "/tmp" } },
                "distant": { "type": "http", "url": "http://serveur.exemple:8000/mcp", "headers": { "Authorization": "${JETON}" } },
                "local": { "url": "http://localhost:3000/mcp" },
                "sur": { "command": "npx", "args": ["@exemple/sur@1.0.0"], "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" } }
              },
              "projects": { "/home/alice/projet": { "allowedTools": ["Bash(*)"], "mcpServers": {} } }
            }"#,
        )
        .unwrap();
        let mut t = Trouvailles::default();
        lire_reglages("Claude Code", &json, &mut t);
        assert_eq!(t.serveurs, 4);
        assert_eq!(t.tout_permis, ["Claude Code"]);
        assert_eq!(t.commandes_permises, ["Claude Code", "Claude Code (projet)"]);
        assert_eq!(t.non_epingles, ["Claude Code › fichiers (@exemple/fichiers)"]);
        assert_eq!(t.sans_chiffrement, ["Claude Code › distant"]);
        let mut v6 = Trouvailles::default();
        let json6: Value = serde_json::from_str(
            r#"{ "mcpServers": { "a": { "url": "http://[::1]:3000/mcp" }, "b": { "url": "http://[2001:db8::5]/mcp" } } }"#,
        )
        .unwrap();
        lire_reglages("Cursor", &json6, &mut v6);
        assert_eq!(v6.sans_chiffrement, ["Cursor › b"]);
        assert_eq!(t.cles_en_clair, ["Claude Code › fichiers (API_KEY)"]);
        let c = juger_reglages(&t, 1, &[]);
        assert_eq!(c.len(), 5);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        // Aucune valeur secrète dans les messages.
        assert!(c.iter().all(|c| !c.message.contains("abc123")));
    }

    #[test]
    fn reglages_sains_ou_absents() {
        let json: Value = serde_json::from_str(
            r#"{ "servers": { "doc": { "command": "uvx", "args": ["doc-mcp==1.2.0"] } }, "permissions": { "allow": ["Bash(git status)"] } }"#,
        )
        .unwrap();
        let mut t = Trouvailles::default();
        lire_reglages("VS Code", &json, &mut t);
        let c = juger_reglages(&t, 1, &[]);
        assert!(c.len() == 1 && c[0].probleme.is_none() && c[0].message.contains("1 serveur"));
        assert!(
            juger_reglages(&Trouvailles::default(), 0, &[])[0]
                .message
                .contains("Aucun agent")
        );
    }

    /// Un fichier présent mais illisible n'est jamais « aucun agent » : l'outil est dit non vérifié, à côté de ce
    /// qui a pu être lu.
    #[test]
    fn reglages_illisibles_non_verifies() {
        let illisible = ["VS Code (JSON invalide)".to_string()];
        let c = juger_reglages(&Trouvailles::default(), 0, &illisible);
        assert_eq!(c.len(), 1);
        assert!(!c[0].verifie && c[0].message.contains("VS Code (JSON invalide)"));
        assert!(c.iter().all(|c| !c.message.contains("Aucun agent")));
        let t = Trouvailles {
            serveurs: 2,
            ..Trouvailles::default()
        };
        let c = juger_reglages(&t, 1, &illisible);
        assert_eq!(c.len(), 2);
        assert!(c[0].verifie && c[0].message.contains("2 serveur"));
        assert!(!c[1].verifie);
    }

    /// Le JSONC de VS Code : commentaires et virgules finales retirés, jamais dans une chaîne.
    #[test]
    fn jsonc_de_vs_code() {
        let jsonc = r#"{
          // Serveurs de l'équipe
          "servers": {
            /* documentation */ "doc": { "command": "npx", "args": ["-y", "doc-mcp",], },
            "web": { "url": "http://exemple.test/a//b/*c*/", "headers": { "Authorization": "Bearer jeton-essai" } },
          },
        }"#;
        let json = lire_json(jsonc.as_bytes()).expect("JSONC lisible");
        assert_eq!(json["servers"]["doc"]["args"], serde_json::json!(["-y", "doc-mcp"]));
        // Les « // » et « /* */ » d'une chaîne y restent.
        assert_eq!(json["servers"]["web"]["url"], "http://exemple.test/a//b/*c*/");
        let mut t = Trouvailles::default();
        lire_reglages("VS Code", &json, &mut t);
        assert_eq!(t.serveurs, 2);
        assert_eq!(t.non_epingles, ["VS Code › doc (doc-mcp)"]);
        assert_eq!(t.cles_en_clair, ["VS Code › web (Authorization)"]);
        // Une virgule dans une chaîne, un guillemet échappé, un commentaire collé : rien de changé à tort.
        let json = lire_json(br#"{"a": "x, }", "b": "y\"//z", /**/"c": [1,/* , */2,]}"#).unwrap();
        assert_eq!(json, serde_json::json!({"a": "x, }", "b": "y\"//z", "c": [1, 2]}));
        // Le BOM d'un éditeur de Windows, puis du JSON ordinaire, lu tel quel.
        assert!(lire_json("\u{feff}{\"a\": 1, // b\n}".as_bytes()).is_some());
        assert_eq!(lire_json(br#"{"a": [1, 2]}"#), Some(serde_json::json!({"a": [1, 2]})));
        // Ni JSON ni JSONC : refusé.
        for mauvais in [
            &b"{\"a\": 1"[..],
            b"{\"a\": /* sans fin",
            b"\xff\xfe{}",
            b"servers = 1",
            b"",
        ] {
            assert!(lire_json(mauvais).is_none(), "{mauvais:?}");
        }
    }

    /// Absent : rien à dire ; présent mais illisible, trop gros ou invalide : la raison.
    #[test]
    fn fichiers_absents_ou_illisibles() {
        let dossier = std::env::temp_dir().join(format!("vanguard-agents-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        assert_eq!(lire_fichier(&dossier.join("absent.json")), Ok(None));
        let bon = dossier.join("mcp.json");
        std::fs::write(&bon, "{ \"servers\": {}, // VS Code\n }").unwrap();
        assert_eq!(lire_fichier(&bon), Ok(Some(serde_json::json!({"servers": {}}))));
        let casse = dossier.join("casse.json");
        std::fs::write(&casse, "{ \"servers\": ").unwrap();
        assert!(lire_fichier(&casse).is_err());
        let gros = dossier.join("gros.json");
        std::fs::File::create(&gros).unwrap().set_len(REGLAGES_MAX + 1).unwrap();
        assert!(lire_fichier(&gros).unwrap_err().contains("64"));
        // Un dossier à la place du fichier : là, mais illisible.
        let dossier_a_la_place = dossier.join("settings.json");
        std::fs::create_dir_all(&dossier_a_la_place).unwrap();
        assert!(lire_fichier(&dossier_a_la_place).is_err());
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// Une référence reste une référence derrière « Bearer » ou « Basic » ; des noms qui contiennent « TOKEN » ou
    /// « PASSWORD » sans désigner un secret ne sont pas des clés.
    #[test]
    fn cles_en_clair_ou_references() {
        let json: Value = serde_json::from_str(
            r#"{ "mcpServers": {
              "a": { "url": "https://a.exemple/mcp", "headers": { "Authorization": "Bearer ${API_KEY}" } },
              "b": { "url": "https://b.exemple/mcp", "headers": { "Authorization": "bearer ${input:jeton}", "X-Api-Key": "${input:cle}" } },
              "c": { "url": "https://c.exemple/mcp", "headers": { "Authorization": "Basic ${IDENTIFIANTS}" } },
              "d": { "command": "uvx", "args": ["d==1.0"], "env": { "TOKENIZERS_PARALLELISM": "false", "PASSWORD_STORE_DIR": "/home/alice/.password-store", "API_KEY_FILE": "/home/alice/cle" } },
              "e": { "url": "https://e.exemple/mcp", "headers": { "Authorization": "Bearer sk-essai-123" } },
              "f": { "url": "https://f.exemple/mcp", "headers": { "Authorization": "Basic YWxpY2U6c2Fsb24=" } },
              "g": { "command": "uvx", "args": ["g==1.0"], "env": { "apiKey": "essai", "CLIENT_SECRET": "essai" } }
            } }"#,
        )
        .unwrap();
        let mut t = Trouvailles::default();
        lire_reglages("Cursor", &json, &mut t);
        assert_eq!(
            t.cles_en_clair,
            [
                "Cursor › e (Authorization)",
                "Cursor › f (Authorization)",
                "Cursor › g (apiKey)",
                "Cursor › g (CLIENT_SECRET)"
            ]
        );
    }

    #[test]
    fn noms_de_secrets() {
        for secret in [
            "API_KEY",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "CLIENT_SECRET",
            "DB_PASSWORD",
            "Authorization",
            "X-Api-Key",
            "x-goog-api-key",
            "apiKey",
            "accessToken",
            "AWS_SECRET_ACCESS_KEY",
            "SECRET_KEY_BASE",
            "api.key",
            "APIKEY",
            "SMTP_PASSWD",
            "GOOGLE_CREDENTIALS",
        ] {
            assert!(ressemble_a_un_secret(secret), "{secret}");
        }
        for ordinaire in [
            "TOKENIZERS_PARALLELISM",
            "PASSWORD_STORE_DIR",
            "KEYBOARD_LAYOUT",
            "MONKEY",
            "CHEMIN",
            "AWS_ACCESS_KEY_ID",
            "API_KEY_FILE",
            "TOKEN_URL",
            "SECRETARY",
            "KEYCLOAK_URL",
            "",
        ] {
            assert!(!ressemble_a_un_secret(ordinaire), "{ordinaire}");
        }
        assert_eq!(mots("x-goog-api.KEY_id"), ["X", "GOOG", "API", "KEY", "ID"]);
        assert_eq!(mots("accessToken"), ["ACCESS", "TOKEN"]);
    }
}

/// Les fichiers de réglages des outils d'IA s'écrivent à la main ou par n'importe quel programme (une extension, un
/// installeur de serveur MCP) : jamais de panique, et le JSONC ramené au JSON garde exactement la valeur.
#[cfg(test)]
mod entrees_hostiles {
    use super::*;
    use proptest::prelude::*;

    /// Un texte qui ressemble à du JSONC sans en être forcément : délimiteurs, commentaires ouverts ou non, guillemets
    /// et barres obliques inverses, multi-octets.
    fn presque_jsonc() -> impl Strategy<Value = String> {
        let bout = prop_oneof![
            prop::sample::select(vec![
                "{",
                "}",
                "[",
                "]",
                ",",
                ":",
                "\"",
                "\\",
                "\\\"",
                "//",
                "/*",
                "*/",
                "/",
                "*",
                "\n",
                " ",
                "\u{feff}",
                "é",
                "😀",
                "\"mcpServers\"",
                "null",
                "1",
            ])
            .prop_map(str::to_string),
            any::<String>(),
        ];
        prop::collection::vec(bout, 0..40).prop_map(|b| b.concat())
    }

    /// Une clé : connue des lecteurs de réglages, ou quelconque.
    fn cle() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                "mcpServers",
                "servers",
                "mcp",
                "command",
                "args",
                "url",
                "serverUrl",
                "httpUrl",
                "env",
                "headers",
                "permissions",
                "defaultMode",
                "allow",
                "allowedTools",
                "projects",
                "API_KEY",
                "apiToken",
                "PASSWORD_FILE",
            ])
            .prop_map(str::to_string),
            any::<String>(),
        ]
    }

    /// Une valeur JSON quelconque, imbriquée (sans réels : leur relecture peut différer d'un bit, sans rapport avec le
    /// JSONC), aux textes pleins de « // », « /* », « , » et de multi-octets.
    fn json() -> impl Strategy<Value = Value> {
        let feuille = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(Value::from),
            prop_oneof![
                any::<String>(),
                "[ -~é😀/*,\\\\\"]{0,20}",
                prop::sample::select(vec![
                    "npx",
                    "cmd",
                    "uvx",
                    "/c",
                    "-y",
                    "paquet@latest",
                    "x==1",
                    "${API_KEY}",
                    "Bearer abc",
                    "bypassPermissions",
                    "Bash(*)",
                    "http://192.0.2.10/mcp",
                    "http://[::1]:8080/"
                ])
                .prop_map(str::to_string),
            ]
            .prop_map(Value::String),
        ];
        feuille.prop_recursive(4, 48, 6, |interieur| {
            prop_oneof![
                prop::collection::vec(interieur.clone(), 0..6).prop_map(Value::Array),
                prop::collection::vec((cle(), interieur), 0..6).prop_map(|v| Value::Object(v.into_iter().collect())),
            ]
        })
    }

    /// Des réglages bien formés aux valeurs quelconques : serveurs MCP (lanceurs, arguments, adresses, variables et
    /// en-têtes), permissions, et les mêmes par projet.
    fn reglages() -> impl Strategy<Value = Value> {
        fn serveurs() -> impl Strategy<Value = Value> {
            let mot = || {
                prop_oneof![
                    prop::sample::select(vec![
                        "npx",
                        "cmd",
                        "CMD.EXE",
                        "uvx",
                        "pipx",
                        "pnpm",
                        "yarn",
                        "bunx",
                        "/c",
                        "/K",
                        "-y",
                        "dlx",
                        "run",
                        "--from",
                        "--spec",
                        "--package",
                        "-p",
                        "--python",
                        "--with=x",
                        "paquet",
                        "paquet@latest",
                        "@portee/nom@1.2.3",
                        "x==1",
                        "npx -y outil",
                        "cmd /c npx outil",
                    ])
                    .prop_map(|m| Value::String(m.to_string())),
                    json(),
                ]
            };
            let args = prop_oneof![prop::collection::vec(mot(), 0..8).prop_map(Value::Array), json()];
            let serveur = (mot(), args, json(), json(), json()).prop_map(|(command, args, url, env, headers)| {
                serde_json::json!({ "command": command, "args": args, "url": url, "env": env, "headers": headers })
            });
            prop::collection::vec((cle(), serveur), 0..4).prop_map(|v| Value::Object(v.into_iter().collect()))
        }
        (serveurs(), json(), serveurs(), json()).prop_map(|(mcp, permissions, projet, allow)| {
            serde_json::json!({
                "mcpServers": mcp,
                "permissions": permissions,
                "projects": { "/home/alice/projet": { "mcpServers": projet, "allowedTools": allow } },
            })
        })
    }

    /// La valeur écrite en JSONC, comme VS Code le permet : à la fin de certaines lignes, un commentaire « // » ou
    /// « /* */ » au texte quelconque, ou une virgule finale avant « } » ou « ] » ; et parfois une marque d'ordre des
    /// octets en tête.
    fn en_jsonc(v: &Value, choix: &[(u8, String)], bom: bool) -> String {
        let joli = serde_json::to_string_pretty(v).unwrap();
        let lignes: Vec<&str> = joli.lines().collect();
        let mut sortie = String::from(if bom { "\u{feff}" } else { "" });
        for (i, ligne) in lignes.iter().enumerate() {
            sortie.push_str(ligne);
            let ferme = lignes
                .get(i + 1)
                .is_some_and(|l| l.trim_start().starts_with(['}', ']']));
            match choix.get(i) {
                Some((1, t)) => {
                    sortie.push_str(" // ");
                    sortie.push_str(&t.replace('\n', " "));
                }
                Some((2, t)) => {
                    sortie.push_str(" /* ");
                    sortie.push_str(&t.replace("*/", "* /"));
                    sortie.push_str(" */");
                }
                Some((3, _)) if ferme && !ligne.ends_with(['{', '[']) => sortie.push(','),
                _ => {}
            }
            sortie.push('\n');
        }
        sortie
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn jsonc_quelconque(t in prop_oneof![presque_jsonc(), any::<String>()], octets in prop::collection::vec(any::<u8>(), 0..200)) {
            prop_assert!(json_sans_jsonc(&t).len() <= t.len());
            let _ = lire_json(t.as_bytes());
            let _ = lire_json(&octets);
        }

        /// Du JSON reste tel quel ; écrit en JSONC, il se relit à la même valeur.
        #[test]
        fn jsonc_ramene_au_json(v in json(), choix in prop::collection::vec((0u8..4, any::<String>()), 0..80), bom: bool) {
            let compact = serde_json::to_string(&v).unwrap();
            prop_assert_eq!(json_sans_jsonc(&compact), compact);
            let jsonc = en_jsonc(&v, &choix, bom);
            prop_assert_eq!(lire_json(jsonc.as_bytes()), Some(v), "{}", jsonc);
        }

        #[test]
        fn reglages_quelconques(v in prop_oneof![json(), reglages()]) {
            let mut t = Trouvailles::default();
            lire_reglages("Outil", &v, &mut t);
            prop_assert!(t.non_epingles.len() <= t.serveurs);
            prop_assert!(t.sans_chiffrement.len() <= 3 * t.serveurs);
            let _ = juger_reglages(&t, 1, &[]);
        }
    }
}
