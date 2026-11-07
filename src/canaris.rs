//! Canaris de format de la veille de nuit (`outils/veille/`) : chaque source réelle du programme est téléchargée à son
//! adresse fixe, par la même demande que le programme (même taille maximale, même délai, gzip, redirections), puis
//! relue par le même lecteur. Une réponse 200 que le lecteur refuse dit que le format a changé, avant qu'un utilisateur
//! ne voie « non vérifié » chez lui.
//!
//! Essais `#[ignore]` qui ne tournent que si `VANGUARD_CANARIS` donne un dossier : jamais dans `cargo test` ni dans
//! `outils/verifier.sh` (les tests ne vont pas sur Internet). abuse.ch (MalwareBazaar, URLhaus, ThreatFox) demande la
//! clé de l'auteur : sautée, la veille ne la lit jamais. Ce qui est reçu est une donnée venue d'Internet : écrit tel
//! quel dans le dossier, jamais interprété ici au-delà des lecteurs du programme.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha2::Digest;

use crate::http::{self, Demande};
use crate::protection::perimes::produits::FICHES;
use crate::protection::perimes::sources::{self, SOURCES};

/// LOLDrivers (`machine/windows/pilotes.rs`, compilé sous Windows seulement) : sa demande recopiée ici, l'égalité
/// vérifiée par un essai de pilotes.rs (tests Windows sous Wine).
pub(crate) const LOLDRIVERS: &str = "https://www.loldrivers.io/api/drivers.csv";
pub(crate) const LOLDRIVERS_MAX: u64 = 32 << 20;

/// Comme `liste_valide` de pilotes.rs : au moins une empreinte SHA-256 (64 chiffres hexadécimaux d'un seul tenant).
pub(crate) fn loldrivers_lisible(octets: &[u8]) -> bool {
    String::from_utf8_lossy(octets)
        .split(|c: char| !c.is_ascii_hexdigit())
        .any(|m| m.len() == 64)
}

/// Les noms que les essais existants sur de vraies copies attendent (`VANGUARD_ESSAI_PERIMES`), par identifiant.
const NOMS_D_ESSAI: &[(&str, &str)] = &[
    ("mozilla", "firefox_versions.json"),
    ("edge", "products"),
    ("office", "OfficeReleases"),
    ("chrome-win-stable", "chrome-win-stable.json"),
    ("mfsa", "foundation-security-advisories.tar.gz"),
    ("slack-windows", "slack-windows.json"),
    ("kev", "kev.json"),
    ("echap", "ioc.yaml"),
];

/// Une source surveillée : sa demande et son lecteur, qui rend le contenu lu (décompressé s'il le faut) ou `None` si le
/// programme refuserait la réponse.
struct Canari {
    id: &'static str,
    demande: fn() -> Demande<'static>,
    lecteur: fn(&[u8]) -> Option<Vec<u8>>,
}

fn tel_quel(ok: bool, brut: &[u8]) -> Option<Vec<u8>> {
    ok.then(|| brut.to_vec())
}

/// Les sources hors de la table des versions : catalogue de la CISA, liste d'Échap, LOLDrivers, Feodo Tracker.
const AUTRES: &[Canari] = &[
    Canari {
        id: "kev",
        demande: crate::protection::kev::demande,
        lecteur: |b| tel_quel(crate::protection::kev::analyser(b).is_some(), b),
    },
    Canari {
        id: "echap",
        demande: crate::protection::espions::echap_demande,
        lecteur: |b| tel_quel(crate::protection::espions::echap_comptes(b).is_some(), b),
    },
    Canari {
        id: "loldrivers",
        demande: || Demande {
            taille_max: LOLDRIVERS_MAX,
            ..Demande::get(LOLDRIVERS, std::time::Duration::from_secs(120))
        },
        lecteur: |b| tel_quel(loldrivers_lisible(b), b),
    },
    Canari {
        id: "feodo",
        demande: crate::protection::sortantes::demande_feodo,
        lecteur: |b| tel_quel(crate::protection::sortantes::feodo_lisible(b), b),
    },
];

fn sha256(octets: &[u8]) -> String {
    sha2::Sha256::digest(octets)
        .iter()
        .fold(String::with_capacity(64), |mut s, o| {
            let _ = write!(s, "{o:02x}");
            s
        })
}

/// Le dossier des canaris, ou `None` (essai lancé sans la veille : rien à faire).
fn dossier() -> Option<PathBuf> {
    std::env::var_os("VANGUARD_CANARIS").map(PathBuf::from)
}

/// Une demande envoyée, jugée : `ok`, `format` (200 que le lecteur refuse : le signal), `http-<code>` ou
/// `sans-reponse` (injoignable, délai dépassé, ou réponse plus grosse que la taille permise).
fn juger(id: &str, demande: Demande, lecteur: &dyn Fn(&[u8]) -> Option<Vec<u8>>, dossier: &Path) -> serde_json::Value {
    let Some(reponse) = http::envoyer(demande) else {
        return serde_json::json!({"id": id, "etat": "sans-reponse", "octets": 0});
    };
    let brut = dossier.join("brut");
    std::fs::write(brut.join(id), &reponse.corps).unwrap();
    let etat = if reponse.code != 200 {
        format!("http-{}", reponse.code)
    } else if let Some(contenu) = lecteur(&reponse.corps) {
        // Les essais existants lisent la réponse telle que reçue (l'archive MFSA reste en gzip), sauf formula.json,
        // qu'ils attendent décompressé.
        if id == "formules" {
            std::fs::write(dossier.join("formula.json"), contenu).unwrap();
        } else if let Some((_, nom)) = NOMS_D_ESSAI.iter().find(|(i, _)| *i == id) {
            std::fs::write(dossier.join(nom), &reponse.corps).unwrap();
        }
        "ok".to_string()
    } else {
        "format".to_string()
    };
    serde_json::json!({
        "id": id,
        "etat": etat,
        "octets": reponse.corps.len(),
        "sha256": sha256(&reponse.corps),
    })
}

/// Chaque source, téléchargée en parallèle comme le programme le fait ; `canaris.json` en sortie, une ligne par
/// source, et les copies sous les noms des essais existants.
#[test]
#[ignore = "réseau : seulement par la veille de nuit (VANGUARD_CANARIS)"]
fn canaris_telecharger() {
    let Some(dossier) = dossier() else {
        return;
    };
    std::fs::create_dir_all(dossier.join("brut")).unwrap();
    let mut lignes: Vec<serde_json::Value> = std::thread::scope(|portee| {
        let dossier = &dossier;
        let mut fils = Vec::new();
        for s in SOURCES {
            fils.push(portee.spawn(move || {
                juger(
                    s.id,
                    sources::demande(s, s.adresse),
                    &|b| sources::contenu(s, b),
                    dossier,
                )
            }));
        }
        for c in AUTRES {
            fils.push(portee.spawn(move || juger(c.id, (c.demande)(), &c.lecteur, dossier)));
        }
        fils.into_iter().map(|f| f.join().unwrap()).collect()
    });
    lignes.push(serde_json::json!({
        "id": "abuse-ch",
        "etat": "sautee",
        "raison": "clé abuse.ch : jamais lue par la veille",
    }));
    // Les comptes d'Échap, par le lecteur du programme : une liste qui maigrit d'un jour à l'autre se voit.
    if let Some([entrees, serveurs, ips, sites]) = std::fs::read(dossier.join("ioc.yaml"))
        .ok()
        .and_then(|o| crate::protection::espions::echap_comptes(&o))
    {
        let comptes = serde_json::json!({"entrees": entrees, "serveurs": serveurs, "ips": ips, "sites": sites});
        std::fs::write(dossier.join("echap.json"), comptes.to_string()).unwrap();
    }
    std::fs::write(
        dossier.join("canaris.json"),
        serde_json::to_string_pretty(&lignes).unwrap(),
    )
    .unwrap();
}

/// Le logiciel suivi dont la fiche reconnaît cette ligne du catalogue (nom interne fixe), sinon `None` : une faille
/// exploitée hors de la table des logiciels suivis sous Windows (écart de couverture).
fn couvert_par(e: &crate::protection::kev::Exploitee) -> Option<String> {
    FICHES
        .iter()
        .find(|f| (f.kev)(&e.editeur, &e.produit))
        .map(|f| format!("{:?}", f.produit))
}

/// Une valeur sur une ligne de TSV : ni tabulation ni retour à la ligne (le texte est déjà passé par
/// `ui::affichable` dans `kev::analyser`).
fn cellule(texte: &str) -> String {
    texte.replace(['\t', '\n', '\r'], " ")
}

/// Les failles ajoutées au catalogue depuis la copie d'hier (`VANGUARD_CANARIS_AVANT`) : `kev-nouvelles.json` ne
/// porte que des champs sûrs (identifiant, logiciel suivi, rançongiciel), le seul fichier qui peut aller à l'IA ;
/// le texte de la CISA (éditeur, produit, nom) ne va que dans `kev-nouvelles-humain.tsv`, pour le rapport de l'auteur.
#[test]
#[ignore = "copies réelles : seulement par la veille de nuit (VANGUARD_CANARIS)"]
fn canaris_kev() {
    let Some(dossier) = dossier() else {
        return;
    };
    let Ok(aujourd_hui) = std::fs::read(dossier.join("kev.json")) else {
        return;
    };
    let aujourd_hui = crate::protection::kev::analyser(&aujourd_hui).unwrap();
    let hier: std::collections::HashSet<String> = std::env::var_os("VANGUARD_CANARIS_AVANT")
        .and_then(|f| std::fs::read(f).ok())
        .and_then(|o| crate::protection::kev::analyser(&o))
        .map(|l| l.into_iter().map(|e| e.cve).collect())
        .unwrap_or_default();
    // Sans copie d'hier (première nuit), rien n'est « nouveau » : la copie du jour sert de point de départ.
    let nouvelles: Vec<_> = if hier.is_empty() {
        Vec::new()
    } else {
        aujourd_hui.iter().filter(|e| !hier.contains(&e.cve)).collect()
    };
    let surs: Vec<serde_json::Value> = nouvelles
        .iter()
        .map(|e| serde_json::json!({"cve": e.cve, "couvert_par": couvert_par(e), "rancongiciel": e.rancongiciel}))
        .collect();
    let humain = nouvelles.iter().fold(String::new(), |mut t, e| {
        let _ = writeln!(
            t,
            "{}\t{}\t{}\t{}",
            e.cve,
            cellule(&e.editeur),
            cellule(&e.produit),
            cellule(&e.nom)
        );
        t
    });
    std::fs::write(
        dossier.join("kev-nouvelles.json"),
        serde_json::to_string_pretty(&surs).unwrap(),
    )
    .unwrap();
    std::fs::write(dossier.join("kev-nouvelles-humain.tsv"), humain).unwrap();
    let couvertes = aujourd_hui.iter().filter(|e| couvert_par(e).is_some()).count();
    std::fs::write(
        dossier.join("kev-comptes.json"),
        serde_json::json!({"total": aujourd_hui.len(), "suivies": couvertes, "premiere": hier.is_empty()}).to_string(),
    )
    .unwrap();
}

/// Sans `VANGUARD_CANARIS`, les canaris ne font rien et ne vont jamais sur Internet ; les lecteurs qu'ils recopient
/// refusent une page qui n'est pas la leur.
#[test]
fn canaris_sans_dossier_et_lecteurs() {
    assert!(loldrivers_lisible(format!("x,{}\n", "0f".repeat(32)).as_bytes()));
    assert!(!loldrivers_lisible(b"<html>maintenance</html>"));
    for c in AUTRES {
        assert!((c.lecteur)(b"<html>portail Wi-Fi</html>").is_none(), "{}", c.id);
    }
    assert_eq!(cellule("a\tb\nc"), "a b c");
    assert_eq!(sha256(b"").len(), 64);
}
