//! Secrets dans les projets git : Vanguard relit l'historique des dépôts git du dossier personnel (par `git log -p`)
//! et y cherche les mots de passe, clés d'API et jetons écrits un jour, avec ses propres règles. Un secret effacé d'un
//! fichier reste dans l'historique, lisible par quiconque a une copie du dépôt (GitHub, une sauvegarde, une clé USB).
//! Lecture seule ; aucun secret n'est affiché ni gardé : seuls le fichier, la ligne, le genre de secret et le commit
//! sont montrés. gitleaks (libre, licence MIT), s'il est installé, ajoute ses propres règles : ce qu'il trouve en plus
//! s'ajoute, sans doublon ; son rapport, qui nomme aussi les auteurs des commits, est lu puis effacé.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::protection::outil;
use crate::ui::*;

/// Dossiers où un dépôt n'est pas cherché : copies de dépendances, environnements et caches, souvent énormes.
const SAUTES: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    "venv",
    "__pycache__",
    "Library",
    "AppData",
];

/// Jusqu'où descendre sous le dossier personnel (~/a/b/c/d), et combien de dépôts au plus : de quoi trouver les
/// projets sans parcourir tout le disque.
const PROFONDEUR: usize = 4;
const DEPOTS_MAX: usize = 200;

/// Les dépôts git sous `racine`. Les dossiers cachés (réglages, caches) et les liens sont sautés ; un dépôt n'est pas
/// fouillé plus loin, ses sous-modules étant d'autres dépôts. La racine elle-même peut être un dépôt (fichiers de
/// configuration suivis par git) sans cacher ceux qui sont dessous.
pub(crate) fn depots(racine: &Path) -> Vec<PathBuf> {
    let mut trouves = Vec::new();
    let mut a_voir = vec![(racine.to_path_buf(), 0)];
    while let Some((dossier, profondeur)) = a_voir.pop() {
        if trouves.len() >= DEPOTS_MAX {
            break;
        }
        // « .git » est un dossier, ou un fichier pour un arbre de travail lié (git worktree).
        if dossier.join(".git").exists() {
            trouves.push(dossier.clone());
            if profondeur > 0 {
                continue;
            }
        }
        if profondeur >= PROFONDEUR {
            continue;
        }
        let Ok(entrees) = std::fs::read_dir(&dossier) else {
            continue;
        };
        for e in entrees.flatten() {
            let nom = e.file_name().to_string_lossy().into_owned();
            if nom.starts_with('.') || SAUTES.contains(&nom.as_str()) {
                continue;
            }
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                a_voir.push((e.path(), profondeur + 1));
            }
        }
    }
    trouves.sort();
    trouves
}

/// Les arguments de gitleaks pour un dépôt : la commande « git » depuis la 8.19, « detect --source » avant (Debian 12
/// et Ubuntu 24.04 ont la 8.16), reconnue dans son aide. Le rapport en JSON, les secrets masqués, le code de retour à 0
/// même quand il trouve : seul un vrai échec (pas un dépôt, git absent) laisse le rapport vide.
pub(crate) fn arguments(aide: &str, depot: &Path, rapport: &Path) -> Vec<OsString> {
    let recent = aide.lines().any(|l| l.trim_start().starts_with("git "));
    let mut a: Vec<OsString> = if recent {
        vec!["git".into()]
    } else {
        vec!["detect".into(), "--source".into(), depot.into()]
    };
    a.extend(
        [
            "--no-banner",
            "--redact",
            "--report-format",
            "json",
            "--log-level",
            "error",
            "--exit-code",
            "0",
            "--report-path",
        ]
        .map(OsString::from),
    );
    a.push(rapport.into());
    if recent {
        a.push(depot.into());
    }
    a
}

/// Une règle : le genre de secret, les débuts qui l'annoncent, les caractères de sa suite et la longueur de celle-ci.
/// Écrites pour Vanguard d'après la forme que chaque service donne à ses clés.
struct Regle {
    nom: (&'static str, &'static str),
    prefixes: &'static [&'static str],
    caractere: fn(char) -> bool,
    longueur: (usize, usize),
}

fn alphanumerique(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

fn majuscule_ou_chiffre(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit()
}

fn jeton(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Les secrets qui se reconnaissent à leur forme.
const REGLES: &[Regle] = &[
    Regle {
        nom: ("clé d'accès AWS", "AWS access key"),
        prefixes: &["AKIA", "ASIA"],
        caractere: majuscule_ou_chiffre,
        longueur: (16, 16),
    },
    Regle {
        nom: ("jeton GitHub", "GitHub token"),
        prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        caractere: alphanumerique,
        longueur: (36, 255),
    },
    Regle {
        nom: ("jeton GitHub", "GitHub token"),
        prefixes: &["github_pat_"],
        caractere: jeton,
        longueur: (50, 255),
    },
    Regle {
        nom: ("jeton GitLab", "GitLab token"),
        prefixes: &["glpat-"],
        caractere: jeton,
        longueur: (20, 255),
    },
    Regle {
        nom: ("jeton Slack", "Slack token"),
        prefixes: &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"],
        caractere: jeton,
        longueur: (10, 255),
    },
    Regle {
        nom: ("clé Stripe", "Stripe key"),
        prefixes: &["sk_live_", "rk_live_"],
        caractere: alphanumerique,
        longueur: (20, 255),
    },
    Regle {
        nom: ("clé d'API Google", "Google API key"),
        prefixes: &["AIza"],
        caractere: jeton,
        longueur: (35, 35),
    },
    Regle {
        nom: ("clé d'API Anthropic", "Anthropic API key"),
        prefixes: &["sk-ant-"],
        caractere: jeton,
        longueur: (32, 255),
    },
    Regle {
        nom: ("clé d'API OpenAI", "OpenAI API key"),
        prefixes: &["sk-proj-"],
        caractere: jeton,
        longueur: (32, 255),
    },
    Regle {
        nom: ("jeton npm", "npm token"),
        prefixes: &["npm_"],
        caractere: alphanumerique,
        longueur: (36, 36),
    },
    Regle {
        nom: ("jeton PyPI", "PyPI token"),
        prefixes: &["pypi-AgE"],
        caractere: jeton,
        longueur: (50, 255),
    },
];

/// Les noms qui annoncent un secret dans une affectation (« password = "…" »).
const NOMS_DE_SECRETS: &[&str] = &[
    "password",
    "passwd",
    "mot_de_passe",
    "secret",
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "auth_token",
    "private_key",
];

/// Une valeur d'exemple, de documentation ou à remplacer : pas un vrai secret.
fn exemple(valeur: &str) -> bool {
    let v = valeur.to_ascii_lowercase();
    [
        "example",
        "exemple",
        "xxxx",
        "changeme",
        "password",
        "passwd",
        "motdepasse",
        "mot_de_passe",
        "your",
        "votre",
        "<",
        ">",
        "${",
        "{{",
        "%s",
        "****",
        "dummy",
        "fake",
        "placeholder",
        "sample",
        "redacted",
        "test",
    ]
    .iter()
    .any(|m| v.contains(m))
}

/// Une clé reconnue à sa forme : un préfixe en début de mot, suivi d'assez de caractères permis, et rien de permis
/// après (une suite plus longue serait un autre mot).
fn forme(ligne: &str) -> Option<&'static Regle> {
    REGLES.iter().find(|r| {
        r.prefixes.iter().any(|p| {
            ligne.match_indices(p).any(|(position, _)| {
                let en_debut = ligne[..position]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !c.is_ascii_alphanumeric());
                let suite = &ligne[position + p.len()..];
                // Les caractères permis sont tous ASCII : leur nombre est aussi leur longueur en octets.
                let n = suite.chars().take_while(|c| (r.caractere)(*c)).count();
                en_debut && (r.longueur.0..=r.longueur.1).contains(&n) && !exemple(&suite[..n])
            })
        })
    })
}

/// Une clé privée : son marqueur seul sur la ligne (un fichier .pem, id_rsa), ou suivi, dans un texte qui l'a mise
/// sur une ligne (JSON d'un compte de service), d'un « \n » puis du corps de la clé. Du code qui cite le marqueur
/// pour reconnaître les clés (« "-----BEGIN RSA PRIVATE KEY-----" => … ») n'en est pas une.
fn cle_privee(ligne: &str) -> bool {
    let l = ligne.trim();
    let Some(position) = l.find("-----BEGIN ") else {
        return false;
    };
    let Some(fin) = l[position..]
        .find("PRIVATE KEY-----")
        .map(|f| position + f + "PRIVATE KEY-----".len())
    else {
        return false;
    };
    let seule = position == 0 && fin == l.len();
    let corps = l[fin..].strip_prefix("\\n").is_some_and(|c| {
        c.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || "+/".contains(*c))
            .count()
            >= 40
    });
    seule || corps
}

/// Un mot de passe dans une adresse : « https://alice:motdepasse@serveur ».
fn mot_de_passe_dans_une_adresse(ligne: &str) -> bool {
    ligne.match_indices("://").any(|(i, _)| {
        let reste = &ligne[i + 3..];
        let fin = reste
            .find(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(reste.len());
        let Some((identite, _)) = reste[..fin].rsplit_once('@') else {
            return false;
        };
        let Some((_, mot)) = identite.split_once(':') else {
            return false;
        };
        mot.len() >= 3 && !exemple(mot) && !mot.starts_with(['$', '{', '%'])
    })
}

/// Une valeur qui ressemble à un vrai secret : assez longue, d'un seul tenant, avec des lettres et des chiffres.
fn plausible(valeur: &str) -> bool {
    (8..=200).contains(&valeur.len())
        && !valeur.contains(char::is_whitespace)
        && valeur.chars().any(|c| c.is_ascii_alphabetic())
        && valeur.chars().any(|c| c.is_ascii_digit())
        && !exemple(valeur)
}

/// « password = "…" », « api_key: '…' » : un nom de secret, « = » ou « : », puis une valeur entre guillemets. Les
/// valeurs sans guillemets (variables, appels) sont laissées : trop de code ordinaire leur ressemble.
fn affectation(ligne: &str) -> bool {
    // En minuscules ASCII, les positions restent celles de la ligne d'origine.
    let bas = ligne.to_ascii_lowercase();
    NOMS_DE_SECRETS.iter().any(|nom| {
        bas.match_indices(nom).any(|(i, _)| {
            let reste = ligne[i + nom.len()..].trim_start_matches(['"', '\'', ' ', '\t']);
            let Some(reste) = reste.strip_prefix(['=', ':']) else {
                return false;
            };
            let reste = reste.trim_start_matches(['=', '>', ' ', '\t']);
            let Some(guillemet) = reste.chars().next().filter(|c| matches!(c, '"' | '\'')) else {
                return false;
            };
            let valeur = &reste[1..];
            valeur.find(guillemet).is_some_and(|fin| plausible(&valeur[..fin]))
        })
    })
}

/// Le genre de secret d'une ligne ajoutée, dans la langue de l'interface ; `None` s'il n'y en a pas.
pub(crate) fn secret(ligne: &str) -> Option<&'static str> {
    let langue = |(fr, en): (&'static str, &'static str)| if crate::langue::anglais() { en } else { fr };
    if let Some(r) = forme(ligne) {
        return Some(langue(r.nom));
    }
    if cle_privee(ligne) {
        return Some(langue(("clé privée", "private key")));
    }
    if mot_de_passe_dans_une_adresse(ligne) {
        return Some(langue(("mot de passe dans une adresse", "password in an address")));
    }
    affectation(ligne).then(|| langue(("mot de passe ou clé dans le code", "password or key in the code")))
}

/// La ligne où commence la partie ajoutée d'un morceau de différence (« @@ -3,0 +4,2 @@ »).
fn debut_du_morceau(entete: &str) -> Option<u64> {
    let ajout = entete.split_whitespace().find(|m| m.starts_with('+'))?;
    ajout[1..].split(',').next()?.parse().ok()
}

/// Les secrets des lignes ajoutées par chaque commit, dans la sortie de `git log -p --unified=0 --format=%x1e%H`.
/// Un commit commence par le séparateur \x1e ; le nom d'un fichier se lit dans l'en-tête de sa différence (après
/// « diff --git », jusqu'au premier « @@ »), et seulement là : une ligne ajoutée qui commencerait par « ++ » donnerait
/// « +++ » elle aussi. Un même secret recopié d'un commit à l'autre n'est compté qu'une fois.
pub(crate) fn lire_historique(sortie: &str) -> Vec<Fuite> {
    let mut fuites: Vec<Fuite> = Vec::new();
    let (mut commit, mut fichier, mut ligne, mut entete) = (String::new(), String::new(), 0u64, false);
    for l in sortie.lines() {
        if let Some(c) = l.strip_prefix('\u{1e}') {
            commit = c.chars().take(7).collect();
            entete = false;
        } else if l.starts_with("diff --git ") {
            entete = true;
            fichier.clear();
        } else if entete && let Some(f) = l.strip_prefix("+++ ") {
            fichier = if f == "/dev/null" {
                String::new()
            } else {
                affichable(f.strip_prefix("b/").unwrap_or(f))
            };
        } else if l.starts_with("@@") {
            entete = false;
            ligne = debut_du_morceau(l).unwrap_or(0);
        } else if !entete && let Some(ajout) = l.strip_prefix('+') {
            if let Some(regle) = secret(ajout).filter(|_| !fichier.is_empty())
                && !fuites
                    .iter()
                    .any(|f| f.fichier == fichier && f.regle == regle && f.ligne == ligne)
            {
                fuites.push(Fuite {
                    regle: regle.to_string(),
                    fichier: fichier.clone(),
                    ligne,
                    commit: commit.clone(),
                });
            }
            ligne += 1;
        }
    }
    fuites
}

/// L'historique d'un dépôt, relu par git sans rien qu'un dépôt piégé puisse faire exécuter : ni programme de
/// différence externe, ni conversion de texte, ni surveillance de fichiers, ni pager. Les 2 000 derniers commits de
/// toutes les branches. `None` si git ne l'a pas lu (dépôt d'un autre compte, abîmé) ; un dépôt sans commit est sain.
fn historique(git: &Path, depot: &Path) -> Option<Vec<Fuite>> {
    // En anglais, sur les trois systèmes : le message d'un dépôt sans commit est lu tel quel.
    let r = crate::commande::lancer(
        Command::new(git)
            .env("LC_ALL", "C.UTF-8")
            .env_remove("LANGUAGE")
            .args([
                "--no-pager",
                "-c",
                "core.quotePath=false",
                "-c",
                "core.fsmonitor=false",
                "-C",
            ])
            .arg(depot)
            .args([
                "log",
                "--all",
                "-p",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--unified=0",
                "--format=%x1e%H",
                "--max-count=2000",
            ]),
        120,
    )?;
    if r.code == Some(0) {
        Some(lire_historique(&r.sortie))
    } else if r.erreurs.contains("does not have any commits") {
        Some(Vec::new())
    } else {
        None
    }
}

/// Un secret trouvé : son genre, le fichier et la ligne, le commit abrégé.
#[derive(Debug, PartialEq)]
pub(crate) struct Fuite {
    pub regle: String,
    pub fichier: String,
    pub ligne: u64,
    pub commit: String,
}

/// Le rapport de gitleaks ; `None` s'il ne se lit pas. Ni le secret, ni l'auteur, ni son adresse ne sont gardés.
pub(crate) fn lire_rapport(json: &str) -> Option<Vec<Fuite>> {
    let valeur: serde_json::Value = serde_json::from_str(json).ok()?;
    Some(
        valeur
            .as_array()?
            .iter()
            .map(|f| Fuite {
                regle: affichable(f["RuleID"].as_str().unwrap_or("?")),
                fichier: affichable(f["File"].as_str().unwrap_or("?")),
                ligne: f["StartLine"].as_u64().unwrap_or(0),
                commit: f["Commit"].as_str().unwrap_or("").chars().take(7).collect(),
            })
            .collect(),
    )
}

/// Ce qu'il advient d'un dépôt.
enum Issue {
    Sain,
    Fuites(Vec<Fuite>),
    Illisible,
}

/// gitleaks, en complément : le programme, son aide (pour sa version), le dossier de ses rapports.
struct Complement {
    gitleaks: PathBuf,
    aide: String,
    rapports: PathBuf,
}

fn par_gitleaks(c: &Complement, depot: &Path, rapport: &Path) -> Option<Vec<Fuite>> {
    let lance = crate::commande::lancer(Command::new(&c.gitleaks).args(arguments(&c.aide, depot, rapport)), 300);
    let lu = std::fs::read_to_string(rapport).ok().and_then(|t| lire_rapport(&t));
    let _ = std::fs::remove_file(rapport);
    lance.and(lu)
}

/// Les deux recherches réunies : ce que gitleaks trouve en plus s'ajoute (même commit, fichier et ligne : un seul).
/// Illisible seulement si aucune des deux n'a pu lire le dépôt.
fn examiner(git: &Path, complement: Option<&Complement>, depot: &Path, rapport: &Path) -> Issue {
    let natif = historique(git, depot);
    let autre = complement.and_then(|c| par_gitleaks(c, depot, rapport));
    if natif.is_none() && autre.is_none() {
        return Issue::Illisible;
    }
    let mut fuites = natif.unwrap_or_default();
    for f in autre.unwrap_or_default() {
        if !fuites
            .iter()
            .any(|g| g.commit == f.commit && g.fichier == f.fichier && g.ligne == f.ligne)
        {
            fuites.push(f);
        }
    }
    if fuites.is_empty() {
        Issue::Sain
    } else {
        Issue::Fuites(fuites)
    }
}

/// Menu Antivirus et protection › Secrets dans les projets git, et « vanguard secrets ».
pub fn analyser() {
    use std::io::Write;
    titre(tr!("Secrets dans les projets git", "Secrets in git projects"));
    let Some(git) = outil::trouver("git") else {
        trp!(
            "  git n'est pas installé : il n'y a pas de projet git à relire ici.",
            "  git is not installed: there is no git project to read here."
        );
        return;
    };
    let maison = crate::socle::maison();
    let depots = depots(&maison);
    if depots.is_empty() {
        trp!(
            "  Aucun projet git dans votre dossier personnel.",
            "  No git project in your home folder."
        );
        return;
    }
    println!(
        "  {}",
        trf!(
            "{} projet(s) git : l'historique de chacun est relu, rien n'est modifié.",
            "{} git project(s): each one's history is read, nothing is changed.",
            depots.len()
        )
    );
    // gitleaks, s'il est là ; ses rapports, dans un dossier réservé au compte : ils nomment les auteurs des commits.
    let complement = outil::trouver("gitleaks").and_then(|gitleaks| {
        let aide = crate::commande::lancer(Command::new(&gitleaks).arg("--help"), 10)
            .map(|r| r.sortie + &r.erreurs)
            .unwrap_or_default();
        let rapports = crate::protection::isoler::dossier_jetable().ok()?;
        Some(Complement {
            gitleaks,
            aide,
            rapports,
        })
    });
    if complement.is_some() {
        trp!(
            "  gitleaks est installé : ses règles s'ajoutent à celles de Vanguard.",
            "  gitleaks is installed: its rules add to Vanguard's."
        );
    }
    let mut sains = 0;
    let mut illisibles = Vec::new();
    let mut avec = Vec::new();
    // Le compteur seulement dans un terminal : lu par un script (test de la VM), il ne ferait que du bruit.
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stdout());
    for (i, depot) in depots.iter().enumerate() {
        if terminal {
            print!("\r  {}/{}", i + 1, depots.len());
            let _ = std::io::stdout().flush();
        }
        let rapport = complement
            .as_ref()
            .map_or_else(PathBuf::new, |c| c.rapports.join(format!("{i}.json")));
        match examiner(&git, complement.as_ref(), depot, &rapport) {
            Issue::Sain => sains += 1,
            Issue::Fuites(f) => avec.push((depot, f)),
            Issue::Illisible => illisibles.push(depot),
        }
    }
    if let Some(c) = &complement {
        let _ = std::fs::remove_dir_all(&c.rapports);
    }
    if terminal {
        print!("\r{}\r", " ".repeat(20));
    }
    for depot in &illisibles {
        println!(
            "  ⚠ {}",
            trf!(
                "{} : pas pu être relu, rien n'est conclu pour lui.",
                "{}: could not be read, nothing is concluded for it.",
                outil::chemin_affiche(depot, &maison)
            )
        );
    }
    if avec.is_empty() {
        if illisibles.is_empty() {
            println!(
                "  {VERT}✔{RESET} {}",
                trf!(
                    "Aucun secret dans l'historique de vos {sains} projet(s).",
                    "No secret in the history of your {sains} project(s)."
                )
            );
        }
        return;
    }
    let rouge = couleur(crate::risk::Niveau::Eleve);
    for (depot, fuites) in &avec {
        println!(
            "  {rouge}✖{RESET} {}",
            trf!(
                "{} : {} secret(s)",
                "{}: {} secret(s)",
                outil::chemin_affiche(depot, &maison),
                fuites.len()
            )
        );
        for f in fuites.iter().take(10) {
            println!(
                "      {GRIS}{}:{} — {} ({}){RESET}",
                f.fichier, f.ligne, f.regle, f.commit
            );
        }
        if fuites.len() > 10 {
            println!(
                "      {GRIS}{}{RESET}",
                trf!("… et {} autre(s)", "… and {} more", fuites.len() - 10)
            );
        }
    }
    println!();
    for ligne in envelopper(
        tr!(
            "Un secret écrit un jour reste dans l'historique, même effacé ensuite, et quiconque a une copie du dépôt peut le lire. D'abord le changer là où il sert (révoquer la clé, changer le mot de passe) ; puis, avant de publier, le retirer de l'historique (git filter-repo). Une règle peut se tromper : un exemple de documentation n'est pas un vrai secret. Les secrets ne sont ni affichés ni gardés par Vanguard.",
            "A secret written once stays in the history, even when deleted later, and anyone with a copy of the repository can read it. First change it where it is used (revoke the key, change the password); then, before publishing, remove it from the history (git filter-repo). A rule can be wrong: a documentation example is not a real secret. Secrets are neither shown nor kept by Vanguard."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
}

/// PRO-GIT-001 au corpus de détection : des lignes ajoutées dans l'historique d'un dépôt. Une fuite n'a pas de niveau
/// à l'écran : le corpus la compte comme une notification.
#[cfg(test)]
pub(crate) fn corpus(e: &crate::modele::corpus::Entree) -> Vec<crate::machine::Constat> {
    let mut constats: Vec<_> = e
        .lignes()
        .into_iter()
        .filter_map(|l| secret(l).map(|genre| crate::modele::corpus::notification(genre, &crate::ui::affichable(l))))
        .collect();
    if constats.is_empty() {
        constats.push(crate::machine::ok("Surveillance", "aucun secret dans ces lignes"));
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un rapport de gitleaks 8.16 tel qu'il l'écrit (secret masqué), sur un dépôt d'essai : valeurs inventées.
    const RAPPORT: &str = r#"[
 {
  "Description": "AWS",
  "StartLine": 1,
  "EndLine": 1,
  "Match": "REDACTED",
  "Secret": "REDACTED",
  "File": "config.env",
  "Commit": "70d57ee42c8a91d4b534c5879690a43bb8f89fe4",
  "Author": "alice",
  "Email": "alice@exemple.invalid",
  "RuleID": "aws-access-token"
 }
]"#;

    #[test]
    fn rapport_lu_sans_secret_ni_auteur() {
        let f = lire_rapport(RAPPORT).unwrap();
        assert_eq!(
            f,
            [Fuite {
                regle: "aws-access-token".into(),
                fichier: "config.env".into(),
                ligne: 1,
                commit: "70d57ee".into(),
            }]
        );
        assert_eq!(lire_rapport("[]").unwrap(), []);
        assert!(lire_rapport("").is_none() && lire_rapport("{\"a\":1}").is_none());
        // Un nom de fichier piégé ne pilote pas le terminal.
        let piege = RAPPORT.replace("config.env", "\\u001b[2Jx");
        assert!(!lire_rapport(&piege).unwrap()[0].fichier.contains('\x1b'));
    }

    #[test]
    fn commande_selon_la_version() {
        let depot = Path::new("/home/alice/projet");
        let rapport = Path::new("/tmp/r.json");
        let ancienne =
            "Available Commands:\n  completion  ...\n  detect      detect secrets in code\n  protect     ...\n";
        let a = arguments(ancienne, depot, rapport);
        assert_eq!(a[..3], ["detect", "--source", "/home/alice/projet"].map(OsString::from));
        assert!(a.contains(&"--redact".into()) && a.last() == Some(&OsString::from("/tmp/r.json")));
        let recente = "Available Commands:\n  dir         scan directories or files for secrets\n  git         scan git repositories for secrets\n";
        let a = arguments(recente, depot, rapport);
        assert_eq!(a[0], "git");
        assert_eq!(a.last(), Some(&OsString::from("/home/alice/projet")));
    }

    #[test]
    fn depots_du_dossier_personnel() {
        let maison = crate::protection::isoler::dossier_jetable().unwrap();
        for d in [
            "projets/site/.git",
            "projets/site/sous-module/.git",
            "projets/node_modules/paquet/.git",
            ".cache/outil/.git",
            "a/b/c/d/e/trop-profond/.git",
            "documents/notes/.git",
        ] {
            std::fs::create_dir_all(maison.join(d)).unwrap();
        }
        // Un arbre de travail lié : « .git » est un fichier.
        std::fs::create_dir_all(maison.join("projets/lie")).unwrap();
        std::fs::write(maison.join("projets/lie/.git"), "gitdir: ailleurs").unwrap();
        let trouves: Vec<String> = depots(&maison)
            .iter()
            .map(|d| d.strip_prefix(&maison).unwrap().to_string_lossy().replace('\\', "/"))
            .collect();
        assert_eq!(trouves, ["documents/notes", "projets/lie", "projets/site"]);
        // Le dossier personnel suivi par git (fichiers de configuration) ne cache pas les projets.
        std::fs::create_dir_all(maison.join(".git")).unwrap();
        assert_eq!(depots(&maison).len(), 4);
        let _ = std::fs::remove_dir_all(&maison);
    }

    // Toutes les clés ci-dessous sont inventées, à la forme des vraies, et coupées en deux dans le code : la recherche
    // lancée sur le dépôt de Vanguard (ou les détecteurs de GitHub) ne les prend pas pour de vraies clés.
    #[test]
    fn secrets_reconnus_a_leur_forme() {
        for (ligne, genre) in [
            (concat!("AWS_ACCESS_KEY_ID=AKIA", "Q3EGRK7LMZ5P2XJD"), "clé d'accès AWS"),
            (
                concat!("token: ghp", "_q8Zr2LmN4vB7xC1dF5gH9jK3pQ6sT0wY2eR4"),
                "jeton GitHub",
            ),
            (concat!("GITLAB=glpat", "-Ab3dE5gH7jK9mN1pQ3sT"), "jeton GitLab"),
            (
                concat!("\"key\": \"AIza", "SyB3x7Lm2Qp9Rt4Vw6Yz8Ab1Cd5Ef0Gh2Jk\""),
                "clé d'API Google",
            ),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "clé privée"),
            (
                "  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\\n",
                "clé privée",
            ),
            (
                concat!("url = https://alice:", "Q7v2mRz9@depot.exemple.org/x.git"),
                "mot de passe dans une adresse",
            ),
            ("db_password = \"Tr0ub4dor3x7\"", "mot de passe ou clé dans le code"),
            (
                concat!("API_KEY: 'k3Fz9L", "q2Wm8Rt4Pv'"),
                "mot de passe ou clé dans le code",
            ),
        ] {
            assert_eq!(secret(ligne), Some(genre), "{ligne}");
        }
    }

    #[test]
    fn exemples_et_code_ordinaire_laisses() {
        for ligne in [
            // L'exemple de la documentation d'AWS, et une suite trop longue pour être une clé.
            "AKIAIOSFODNN7EXAMPLE",
            concat!("AKIA", "Q3EGRK7LMZ5P2XJDZZZ"),
            // Préfixe au milieu d'un mot.
            concat!("xghp", "_q8Zr2LmN4vB7xC1dF5gH9jK3pQ6sT0wY2eR4"),
            "password = \"changeme123\"",
            "password = \"<ton-mot-de-passe>\"",
            "password = os.environ[\"PASSWORD\"]",
            "let password = demander(question);",
            "secret = \"abcdefghij\"",
            "https://alice@depot.exemple.org",
            // Du code qui cite le marqueur d'une clé, sans clé.
            "        \"-----BEGIN OPENSSH PRIVATE KEY-----\" => {",
            "assert_eq!(cle_protegee(\"-----BEGIN RSA PRIVATE KEY-----\\nMIIE\\n\"), Some(false));",
            "https://alice:${MOT}@serveur",
            "Voir https://exemple.org:8080/page",
        ] {
            assert_eq!(secret(ligne), None, "{ligne}");
        }
    }

    #[test]
    fn historique_lu_commit_par_commit() {
        // Deux commits : l'ajout d'une clé, puis son effacement (la ligne retirée ne compte pas) ; un « ++ » ajouté ne
        // passe pas pour un nom de fichier, et la même clé recopiée plus loin n'est comptée qu'une fois.
        let sortie = "\u{1e}2b1c3d4e5f60718293a4b5c6d7e8f9012345678\n\
                      diff --git a/config.env b/config.env\n\
                      index 1234567..89abcde 100644\n\
                      --- a/config.env\n\
                      +++ b/config.env\n\
                      @@ -1 +1 @@\n\
                      -AWS_ACCESS_KEY_ID=AKIA\
                      Q3EGRK7LMZ5P2XJD\n\
                      +AWS_ACCESS_KEY_ID=\n\
                      \u{1e}70d57ee42c8a91d4b534c5879690a43bb8f89fe4\n\
                      diff --git a/config.env b/config.env\n\
                      new file mode 100644\n\
                      --- /dev/null\n\
                      +++ b/config.env\n\
                      @@ -0,0 +1,3 @@\n\
                      +# réglages\n\
                      +++ pas un fichier\n\
                      +AWS_ACCESS_KEY_ID=AKIA\
                      Q3EGRK7LMZ5P2XJD\n\
                      diff --git a/vieux.txt b/vieux.txt\n\
                      deleted file mode 100644\n\
                      --- a/vieux.txt\n\
                      +++ /dev/null\n";
        assert_eq!(
            lire_historique(sortie),
            [Fuite {
                regle: "clé d'accès AWS".into(),
                fichier: "config.env".into(),
                ligne: 3,
                commit: "70d57ee".into(),
            }]
        );
    }

    /// Un vrai dépôt, relu par le vrai git : la clé effacée au second commit est retrouvée dans l'historique. Sans git
    /// (sous Wine), rien à essayer.
    #[test]
    fn vrai_depot_relu_par_git() {
        let Some(git) = outil::trouver("git") else {
            return crate::essais::saute("git absent");
        };
        let depot = crate::protection::isoler::dossier_jetable().unwrap();
        let git_ici = |args: &[&str]| {
            Command::new(&git)
                .args([
                    "-c",
                    "user.name=alice",
                    "-c",
                    "user.email=alice@exemple.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "-C",
                ])
                .arg(&depot)
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        };
        assert!(git_ici(&["init", "-q"]));
        assert_eq!(historique(&git, &depot), Some(Vec::new()), "dépôt sans commit : sain");
        std::fs::write(
            depot.join("config.env"),
            concat!("TOKEN=ghp", "_q8Zr2LmN4vB7xC1dF5gH9jK3pQ6sT0wY2eR4\n"),
        )
        .unwrap();
        assert!(git_ici(&["add", "."]) && git_ici(&["commit", "-qm", "ajout"]));
        std::fs::write(depot.join("config.env"), "TOKEN=\n").unwrap();
        assert!(git_ici(&["commit", "-qam", "effacé"]));
        let fuites = historique(&git, &depot).unwrap();
        assert_eq!(fuites.len(), 1);
        assert!(fuites[0].fichier == "config.env" && fuites[0].ligne == 1 && fuites[0].commit.len() == 7);
        let _ = std::fs::remove_dir_all(&depot);
    }
}
