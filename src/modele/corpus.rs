//! La régression de détection : un corpus de cas fabriqués et inoffensifs (tests/corpus-detection/<ID>/) prouve que
//! chaque règle de détection tire encore. Pourquoi : `toute_regle_muette_ou_plantee_dit_non_verifie` garde qu'une
//! règle parle, pas qu'elle voit ; une règle débranchée (qui ne rend plus que « sain ») ou un motif retiré passaient
//! la vérification complète. Ici, chaque cas appelle la fonction de jugement de sa règle avec des données fabriquées
//! (`fabrique.txt`) et exige un constat d'au moins la gravité attendue, qui nomme ce que le cas a fabriqué ; le même
//! cas propre (`propre.txt`) exige qu'elle se taise.
//!
//! Le cas juge, il ne lit pas le système : la lecture reste aux règles, et les tests ne touchent jamais les vraies
//! données. Une règle dont le jugement n'est pas encore à part attend son extraction (lot S3b), un outil son cas
//! (lot S3c) ; une règle qu'on ne peut pas exercer hors ligne, sans moteur externe ni contenu d'attaque, est
//! exemptée avec sa raison. La liste est fermée : chaque règle qui cite une technique d'ATT&CK (T…), et chaque outil
//! qui détecte, a son cas ou sa raison, et une raison qui ne sert plus fait échouer.
//!
//! Les règles de durcissement (une mesure M… : pare-feu allumé, chiffrement du disque, réglage du noyau) restent hors
//! du corpus : elles lisent un réglage, pas une attaque, et `toute_regle_muette_ou_plantee_dit_non_verifie` les garde.
//!
//! Un dossier de cas : `attendu.toml` (gravité minimale, mots attendus, ce que le cas propre peut dire au plus,
//! systèmes où il tourne), `fabrique.txt` et `propre.txt` (les données, au format que lit l'adaptateur de la règle).
//! Les adaptateurs sont près des règles (une table `CAS` par système, dans `machine::…::corpus`), là où le jugement
//! est visible. Rien qui ressemble à une signature (EICAR, motif YARA) n'y est écrit d'un bloc : assemblé à
//! l'exécution, comme dans analyse/tests.rs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::machine::Constat;
use crate::risk::Niveau;

/// Les données d'un cas, telles que l'adaptateur de la règle les lit.
pub(crate) struct Entree {
    /// Le dossier du cas (des fichiers fabriqués peuvent s'y trouver à côté des données).
    pub dossier: PathBuf,
    pub texte: String,
}

impl Entree {
    /// Les lignes utiles : sans blancs autour, ni vides, ni commentaires (« # »).
    pub(crate) fn lignes(&self) -> Vec<&str> {
        self.texte
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    }

    /// Les lignes coupées à « | ».
    pub(crate) fn champs(&self) -> Vec<Vec<&str>> {
        self.lignes().into_iter().map(|l| l.split('|').collect()).collect()
    }

    /// Les champs des lignes qui commencent par `genre|`, sans lui.
    pub(crate) fn de(&self, genre: &str) -> Vec<Vec<&str>> {
        self.champs()
            .into_iter()
            .filter(|c| c.first() == Some(&genre))
            .map(|c| c[1..].to_vec())
            .collect()
    }

    /// Un dossier jetable à ce cas, vide, hors du dépôt : pour les jugements qui lisent des fichiers posés exprès.
    #[cfg(unix)]
    pub(crate) fn jetable(&self, nom: &str) -> PathBuf {
        let cas = self
            .dossier
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let d = std::env::temp_dir().join(format!("vanguard-corpus-{}-{cas}-{nom}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}

/// L'adaptateur d'une règle : ses données fabriquées données à sa fonction de jugement.
pub(crate) type Juge = fn(&Entree) -> Vec<Constat>;

/// Ce système, comme `attendu.toml` le nomme.
fn ce_systeme() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Les cas qui tournent ici, de toutes les tables.
fn tous_les_cas() -> Vec<(&'static str, Juge)> {
    let mut cas: Vec<(&'static str, Juge)> = Vec::new();
    cas.extend_from_slice(crate::machine::corpus::CAS);
    #[cfg(target_os = "linux")]
    cas.extend_from_slice(crate::machine::linux::corpus::CAS);
    #[cfg(windows)]
    cas.extend_from_slice(crate::machine::windows::corpus::CAS);
    #[cfg(target_os = "macos")]
    cas.extend_from_slice(crate::machine::macos::corpus::CAS);
    cas.extend_from_slice(crate::journaux_windows::regles::corpus::CAS);
    cas
}

// ───────────────────────────── La liste fermée ─────────────────────────────

/// Les outils et surveillances qui détectent sans citer de technique (modele/registre.rs) : eux aussi doivent avoir
/// leur cas, ou leur raison.
const OUTILS_QUI_DETECTENT: &[&str] = &[
    "PRO-YAR-001",
    "PRO-MEM-001",
    "PRO-TEL-001",
    "SUR-TEL-001",
    "PRO-COU-001",
    "PRO-LIE-001",
    "PRO-ESP-001",
    "PRO-DIS-001",
    "SUR-BOT-001",
    "SUR-EMP-001",
    "SUR-FIC-001",
    "VEI-RAN-001",
    "VEI-RAN-002",
    "VEI-RAN-003",
    "VEI-EXF-001",
    "VEI-PRG-001",
    "VEI-CNX-001",
    "PRO-ANV-001",
    "PRO-CTN-001",
    "PRO-LNO-001",
    "PRO-PER-001",
];

/// Les règles de détection qu'aucun cas n'exerce, pour de bon, avec leur raison.
const EXEMPTEES: &[(&str, &str)] = &[
    (
        "PRO-ANV-001",
        "le moteur est ClamAV ou Defender, externes par décision : EICAR y est essayé dans la VM et par outils/test-linux/essai.sh",
    ),
    ("PRO-CTN-001", "le jugement est celui de trivy, un programme externe"),
    (
        "PRO-LNO-001",
        "la liste noire DNS s'interroge en direct : rien à juger hors ligne",
    ),
    (
        "PRO-PER-001",
        "les failles exploitées viennent du catalogue KEV, lu en ligne",
    ),
    (
        "EVT-PRC-001",
        "ses déclencheurs sont des noms d'outils d'attaque, masqués dans le source (src/masque.rs), et des lignes de commande d'attaque : les écrire en clair dans le corpus irait contre le masquage ; journaux_windows/regles/tests.rs (processus_suspects) l'exerce déjà",
    ),
];

/// Les règles qui attendent l'extraction de leur jugement (lot S3b) : la lecture et le jugement y sont encore mêlés.
/// S3b vide cette liste ; une entrée qui a reçu son cas fait échouer.
const EN_ATTENTE_S3B: &[(&str, &str)] = &[
    ("LNX-PRS-001", "persistance lue sous / seulement"),
    ("LNX-PRS-002", "persistance lue sous / seulement"),
    ("LNX-CPT-001", "jugement mêlé à la lecture"),
    ("LNX-SSH-002", "jugement mêlé à la lecture"),
    (
        "LNX-PRV-003",
        "le constat se forme après « sudo -n -l », dans la même fonction",
    ),
    ("COM-INT-001", "jugement mêlé à la lecture"),
    ("MAC-PRS-001", "jugement mêlé à la lecture"),
    ("MAC-PRV-002", "jugement mêlé à la lecture"),
    ("MAC-SYS-003", "jugement mêlé à la lecture"),
    ("WIN-PRS-001", "juger_persistance à vérifier"),
    ("WIN-JRN-003", "relie les règles EVT- au bilan"),
    ("COM-ARP-001", "fiche de l'audit du réseau, sans point d'entrée unique"),
    ("COM-ARP-002", "fiche de l'audit du réseau, sans point d'entrée unique"),
    ("COM-ARP-004", "fiche de l'audit du réseau, sans point d'entrée unique"),
    ("COM-DNS-004", "fiche de l'audit du réseau, sans point d'entrée unique"),
    ("COM-PST-003", "fiche de l'audit du réseau, sans point d'entrée unique"),
    ("COM-SEG-004", "fiche de l'audit du réseau, sans point d'entrée unique"),
    ("COM-SEG-005", "fiche de l'audit du réseau, sans point d'entrée unique"),
    ("COM-TLS-001", "fiche de l'audit du réseau, sans point d'entrée unique"),
    ("COM-TLS-003", "fiche de l'audit du réseau, sans point d'entrée unique"),
    ("COM-WIF-003", "fiche de l'audit du réseau, sans point d'entrée unique"),
];

/// Les outils et surveillances qui attendent leur cas (lot S3c). S3c vide cette liste.
const EN_ATTENTE_S3C: &[&str] = &[
    "PRO-YAR-001",
    "PRO-MEM-001",
    "PRO-TEL-001",
    "SUR-TEL-001",
    "PRO-COU-001",
    "PRO-LIE-001",
    "PRO-ESP-001",
    "PRO-DIS-001",
    "SUR-BOT-001",
    "SUR-EMP-001",
    "SUR-FIC-001",
    "VEI-RAN-001",
    "VEI-RAN-002",
    "VEI-RAN-003",
    "VEI-EXF-001",
    "VEI-PRG-001",
    "VEI-CNX-001",
];

/// Les règles qui citent une technique d'ATT&CK (T…), lues dans la carte que outils/couverture-attack.py tire des
/// sources (verifier.sh la garde à jour) : la liste vaut pour les trois systèmes, quel que soit celui qui compile.
fn regles_qui_detectent() -> BTreeSet<String> {
    include_str!("../../COUVERTURE-ATTACK.md")
        .lines()
        .filter(|l| l.starts_with("| T") || l.starts_with("| ↳ T"))
        .flat_map(|l| l.split('`').skip(1).step_by(2))
        .filter(|id| super::id::bien_forme(id))
        .map(str::to_string)
        .collect()
}

fn racine_du_corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus-detection")
}

/// Les dossiers de cas du corpus.
fn dossiers_de_cas() -> BTreeSet<String> {
    std::fs::read_dir(racine_du_corpus())
        .expect("tests/corpus-detection illisible")
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

// ───────────────────────────── Ce qu'un cas attend ─────────────────────────────

/// Pourquoi un `attendu.toml` ne se lit pas.
#[derive(Debug)]
struct Refus(String);

impl From<&str> for Refus {
    fn from(t: &str) -> Refus {
        Refus(t.to_string())
    }
}

impl From<String> for Refus {
    fn from(t: String) -> Refus {
        Refus(t)
    }
}

#[derive(Debug)]
struct Attendu {
    /// La gravité au moins du constat que le cas fabriqué doit faire tirer.
    gravite: Niveau,
    /// Des mots des données fabriquées, que ce constat doit nommer (sans la casse) : il tire pour ce cas, pas par
    /// hasard. Jamais un mot du message traduit, qui changerait avec la langue.
    mots: Vec<String>,
    /// Le plus que le cas propre peut dire : `None`, rien (« aucun ») ; sinon une information au plus.
    propre: Option<Niveau>,
    systemes: Vec<String>,
}

fn niveau(texte: &str) -> Option<Niveau> {
    Some(match texte {
        "info" => Niveau::Info,
        "moyen" => Niveau::Moyen,
        "eleve" => Niveau::Eleve,
        "critique" => Niveau::Critique,
        _ => return None,
    })
}

/// Une valeur `"texte"` ou `["a", "b"]` : le peu de TOML dont un cas a besoin, sans dépendance de plus.
fn valeurs(v: &str) -> Result<Vec<String>, Refus> {
    let texte = |t: &str| -> Result<String, Refus> {
        t.trim()
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .map(str::to_string)
            .ok_or_else(|| Refus(format!("« {t} » : un texte entre guillemets attendu")))
    };
    match v.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        Some(liste) => liste.split(',').filter(|t| !t.trim().is_empty()).map(texte).collect(),
        None => Ok(vec![texte(v)?]),
    }
}

fn lire_attendu(texte: &str) -> Result<Attendu, Refus> {
    let (mut gravite, mut mots, mut propre, mut systemes) = (None, Vec::new(), None, Vec::new());
    for ligne in texte
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (cle, v) = ligne
            .split_once('=')
            .ok_or_else(|| Refus(format!("« {ligne} » : « clé = valeur » attendu")))?;
        let v = valeurs(v.trim())?;
        let seul = || v.first().cloned().unwrap_or_default();
        match cle.trim() {
            "gravite" => gravite = Some(niveau(&seul()).ok_or("gravite : info, moyen, eleve ou critique")?),
            "mots" => mots = v,
            "propre" => {
                propre = Some(match seul().as_str() {
                    "aucun" => None,
                    "info" => Some(Niveau::Info),
                    _ => return Err("propre : aucun ou info".into()),
                });
            }
            "systemes" => systemes = v,
            autre => return Err(Refus(format!("clé inconnue : {autre}"))),
        }
    }
    let gravite = gravite.ok_or("gravite manque")?;
    if gravite == Niveau::Info {
        return Err("gravite : une information ne prouve pas qu'une règle de détection tire".into());
    }
    if mots.is_empty() {
        return Err("mots manque : le constat doit nommer ce que le cas a fabriqué".into());
    }
    let propre = propre.ok_or("propre manque")?;
    if systemes.is_empty()
        || systemes
            .iter()
            .any(|s| !["linux", "windows", "macos"].contains(&s.as_str()))
    {
        return Err("systemes : linux, windows ou macos".into());
    }
    Ok(Attendu {
        gravite,
        mots,
        propre,
        systemes,
    })
}

fn montrer(constats: &[Constat]) -> String {
    constats
        .iter()
        .map(|c| format!("  {:?} vérifié={} : {}", c.probleme, c.verifie, c.message))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Le cas `id` jugé : ce qui ne va pas, ou `None`.
fn faute_du_cas(id: &str, juge: Juge) -> Option<String> {
    let dossier = racine_du_corpus().join(id);
    let lire = |f: &str| std::fs::read_to_string(dossier.join(f)).map_err(|e| format!("{id}/{f} : {e}"));
    let attendu =
        match lire("attendu.toml").and_then(|t| lire_attendu(&t).map_err(|e| format!("{id}/attendu.toml : {}", e.0))) {
            Ok(a) => a,
            Err(e) => return Some(e),
        };
    let entree = |f: &str| {
        lire(f).map(|texte| Entree {
            dossier: dossier.clone(),
            texte,
        })
    };
    let (fabrique, propre) = match (entree("fabrique.txt"), entree("propre.txt")) {
        (Ok(f), Ok(p)) => (f, p),
        (Err(e), _) | (_, Err(e)) => return Some(e),
    };
    let tires = juge(&fabrique);
    let nomme = |c: &Constat| {
        let m = c.message.to_lowercase();
        attendu.mots.iter().all(|mot| m.contains(&mot.to_lowercase()))
    };
    if !tires
        .iter()
        .any(|c| c.verifie && c.probleme >= Some(attendu.gravite) && nomme(c))
    {
        return Some(format!(
            "{id} ne tire plus : aucun constat d'au moins {:?} qui nomme {:?}\n{}",
            attendu.gravite,
            attendu.mots,
            montrer(&tires)
        ));
    }
    let muets = juge(&propre);
    if muets.iter().any(|c| !c.verifie || c.probleme > attendu.propre) {
        return Some(format!(
            "{id} tire sur son cas propre (au plus {:?} attendu, tout vérifié)\n{}",
            attendu.propre,
            montrer(&muets)
        ));
    }
    None
}

#[test]
fn chaque_cas_du_corpus_tire() {
    let ici = ce_systeme();
    let cas = tous_les_cas();
    let mut fautes = Vec::new();
    let mut vus = BTreeSet::new();
    for (id, juge) in &cas {
        if !vus.insert(*id) {
            fautes.push(format!("{id} : deux adaptateurs"));
            continue;
        }
        if let Some(f) = faute_du_cas(id, *juge) {
            fautes.push(f);
        }
    }
    // Chaque cas qui dit tourner ici a son adaptateur ici, et aucun adaptateur ne tourne là où son cas ne le dit pas.
    for d in dossiers_de_cas() {
        let systemes = std::fs::read_to_string(racine_du_corpus().join(&d).join("attendu.toml"))
            .ok()
            .and_then(|t| lire_attendu(&t).ok())
            .map(|a| a.systemes)
            .unwrap_or_default();
        let ici_attendu = systemes.iter().any(|s| s == ici);
        match (ici_attendu, vus.contains(d.as_str())) {
            (true, false) => fautes.push(format!("{d} : son cas dit {ici}, aucun adaptateur ici")),
            (false, true) => fautes.push(format!("{d} : un adaptateur ici, son cas ne dit pas {ici}")),
            _ => {}
        }
    }
    for id in &vus {
        if !racine_du_corpus().join(id).is_dir() {
            fautes.push(format!("{id} : un adaptateur sans dossier de cas"));
        }
    }
    assert!(fautes.is_empty(), "corpus de détection :\n{}", fautes.join("\n"));
    // La ligne que verifier.sh montre au résumé (étape « régression de détection »).
    println!(
        "corpus de détection ({ici}) : {} règles tirent, {} exemptées, {} en attente de S3b, {} de S3c",
        vus.len(),
        EXEMPTEES.len(),
        EN_ATTENTE_S3B.len(),
        EN_ATTENTE_S3C.len()
    );
}

#[test]
fn chaque_regle_de_detection_a_son_cas() {
    let detectent: BTreeSet<String> = regles_qui_detectent()
        .into_iter()
        .chain(OUTILS_QUI_DETECTENT.iter().map(|s| (*s).to_string()))
        .collect();
    // La carte doit compter : un format changé qui ne rendrait plus rien viderait la liste sans bruit.
    assert!(regles_qui_detectent().len() >= 60, "carte ATT&CK mal lue");
    let cas = dossiers_de_cas();
    let mises_a_part: Vec<(&str, &str)> = EXEMPTEES
        .iter()
        .map(|(id, _)| (*id, "EXEMPTEES"))
        .chain(EN_ATTENTE_S3B.iter().map(|(id, _)| (*id, "EN_ATTENTE_S3B")))
        .chain(EN_ATTENTE_S3C.iter().map(|id| (*id, "EN_ATTENTE_S3C")))
        .collect();
    let connues: BTreeSet<&str> = include_str!("../../tests/regles-connues.txt")
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut mots = l.split_whitespace();
            let id = mots.next()?;
            (!mots.any(|m| m == "retire")).then_some(id)
        })
        .collect();
    let mut fautes = Vec::new();
    for id in &detectent {
        let ou: Vec<&str> = mises_a_part.iter().filter(|(i, _)| i == id).map(|(_, l)| *l).collect();
        match (cas.contains(id), ou.as_slice()) {
            (true, []) | (false, [_]) => {}
            (false, []) => fautes.push(format!(
                "{id} détecte sans cas : poser tests/corpus-detection/{id}/, ou le mettre dans EXEMPTEES avec sa raison"
            )),
            (true, l) => fautes.push(format!("{id} a son cas : le retirer de {}", l.join(", "))),
            (false, l) => fautes.push(format!("{id} deux fois : {}", l.join(", "))),
        }
    }
    for (id, liste) in &mises_a_part {
        if !detectent.contains(*id) {
            fautes.push(format!(
                "{id} ({liste}) ne détecte plus, ou n'existe plus : à retirer de la liste"
            ));
        }
    }
    for id in &cas {
        if !detectent.contains(id) {
            fautes.push(format!(
                "tests/corpus-detection/{id} : pas une règle de détection (sans technique T…, ni outil qui détecte)"
            ));
        }
    }
    for id in &detectent {
        if !connues.contains(id.as_str()) {
            fautes.push(format!("{id} absent de tests/regles-connues.txt, ou retiré"));
        }
    }
    for (id, raison) in EXEMPTEES.iter().chain(EN_ATTENTE_S3B) {
        if raison.trim().is_empty() {
            fautes.push(format!("{id} sans raison"));
        }
    }
    assert!(fautes.is_empty(), "liste fermée du corpus :\n{}", fautes.join("\n"));
}

#[test]
fn lecture_de_ce_qu_un_cas_attend() {
    let a = lire_attendu(
        "# un cas\ngravite = \"eleve\"\nmots = [\"outil-corpus\", \"/tmp\"]\npropre = \"info\"\nsystemes = [\"linux\"]\n",
    )
    .unwrap();
    assert_eq!(a.gravite, Niveau::Eleve);
    assert_eq!(a.mots, ["outil-corpus", "/tmp"]);
    assert_eq!(a.propre, Some(Niveau::Info));
    assert_eq!(a.systemes, ["linux"]);
    // Ce qui ne prouverait rien, ou se lirait de travers, est refusé.
    for faux in [
        "gravite = \"info\"\nmots = \"x\"\npropre = \"aucun\"\nsystemes = \"linux\"",
        "gravite = \"eleve\"\npropre = \"aucun\"\nsystemes = \"linux\"",
        "gravite = \"eleve\"\nmots = \"x\"\nsystemes = \"linux\"",
        "gravite = \"eleve\"\nmots = \"x\"\npropre = \"aucun\"\nsystemes = \"bsd\"",
        "gravite = \"eleve\"\nmots = \"x\"\npropre = \"aucun\"\nsystemes = \"linux\"\nautre = \"y\"",
        "gravite = eleve\nmots = \"x\"\npropre = \"aucun\"\nsystemes = \"linux\"",
    ] {
        assert!(lire_attendu(faux).is_err(), "{faux}");
    }
}
