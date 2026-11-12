//! « Mettre à jour Vanguard », relu pour sa feuille :
//!
//! - l'aperçu (`se-mettre-a-jour --voir --json`), lu strictement comme celui d'une correction : un champ inconnu,
//!   absent, nul ou d'un autre type, un autre jeton que celui de la mise à jour, une origine inconnue, une empreinte
//!   qui n'a pas ses 64 chiffres, une taille nulle ou trop grande, aucun programme à remplacer, un chemin pas absolu
//!   à la façon de ce système (`chemin_bien_forme`) rendent la réponse illisible ; chaque texte est nettoyé,
//!   `retouche` et `coupe` disent ce que le nettoyage a changé ;
//! - pourquoi rien n'est proposé, de son code (`etat`), jamais de son texte : « à jour » seulement quand Vanguard l'a
//!   vérifié ; « non vérifié » n'est jamais montré comme « à jour » ;
//! - l'issue de `se-mettre-a-jour --appliquer --accord <accord> --json` : seul « refuse » dit que rien n'a été fait ;
//!   une copie pas remplacée est un échec (l'ancienne reste en place, Vanguard le dit), jamais « fait ».
//!
//! La fenêtre ne télécharge, ne vérifie et n'écrit rien : elle montre, puis rend l'accord tel quel.

use serde::Deserialize;

use super::changements::{CHEMIN_MAX, IssueChange, RAISON_MAX, Relu, derniere_ligne, raison};
use super::correction::{SIGNES_ACCEPTABLES, montre, present};
use crate::commandes::{Accord, Empreinte, SorteGeste};

/// Programmes remplacés au plus dans un aperçu (la copie de Vanguard et le programme lancé : deux aujourd'hui).
pub const CIBLES_MAX: usize = 16;
/// La plus grande taille qu'un programme de mise à jour peut avoir, celle de Vanguard (`mise_a_jour::TAILLE_MAX`).
pub const TAILLE_MAX: u64 = 512 << 20;

/// D'où vient le programme qui s'installerait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origine {
    /// La clé VANGUARD d'où tourne Vanguard.
    Cle,
    /// La dernière version publiée sur GitHub, signée par l'auteur, vérifiée par Vanguard.
    Github,
}

/// Un programme d'ici que la mise à jour remplacerait : son chemin (« ~/… » sous le dossier personnel) et sa version
/// d'aujourd'hui.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cible {
    pub chemin: String,
    pub version: String,
}

/// L'aperçu de la mise à jour, prêt à montrer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiseAJour {
    pub origine: Origine,
    /// La version qui s'installerait.
    pub visee: String,
    /// L'empreinte SHA-256 du programme, 64 chiffres hexadécimaux minuscules.
    pub sha256: String,
    /// Sa taille, en octets.
    pub taille: u64,
    pub cibles: Vec<Cible>,
    pub accord: Accord,
    pub retouche: bool,
    pub coupe: bool,
}

impl MiseAJour {
    pub fn signes(&self) -> usize {
        let n = |t: &String| t.chars().count();
        self.cibles
            .iter()
            .map(|c| n(&c.chemin) + n(&c.version))
            .fold(n(&self.visee).saturating_add(n(&self.sha256)), usize::saturating_add)
    }

    /// Pourquoi elle ne s'installe pas depuis la fenêtre, si elle ne s'y installe pas : montrée exactement, assez
    /// courte.
    pub fn pas_d_ici(&self) -> Option<&'static str> {
        if self.retouche || self.coupe {
            return Some(crate::tr!(
                "Ce qui est montré n'est pas exactement le texte de Vanguard : elle ne s'installe pas d'ici (vanguard se-mettre-a-jour dans un terminal).",
                "What is shown is not exactly Vanguard's text: it is not installed from here (vanguard se-mettre-a-jour in a terminal)."
            ));
        }
        if self.signes() > SIGNES_ACCEPTABLES {
            return Some(crate::tr!(
                "Trop longue pour se lire ici d'un coup d'œil : vanguard se-mettre-a-jour dans un terminal.",
                "Too long to read here at a glance: vanguard se-mettre-a-jour in a terminal."
            ));
        }
        None
    }
}

/// Ce que l'aperçu a dit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Vue {
    /// Une mise à jour à montrer, avec son accord.
    Proposee(Box<MiseAJour>),
    /// Vérifié : rien de plus récent que ce qui est ici. La raison de Vanguard, nettoyée.
    AJour(String),
    /// Rien ici que la mise à jour remplacerait.
    Rien(String),
    /// Pas vérifié (pas de réponse de GitHub, manifeste plus vieux que celui déjà vu, copie illisible) : jamais
    /// « à jour ».
    NonVerifiee(String),
    /// Vanguard a refusé de montrer.
    Refusee(String),
    /// La réponse ne se lit pas comme un aperçu de la mise à jour : une raison courte.
    Illisible(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReponseBrute {
    geste: String,
    issue: String,
    raison: String,
    etat: String,
    #[serde(default, deserialize_with = "present")]
    apercu: Option<ApercuBrut>,
    #[serde(default, deserialize_with = "present")]
    accord: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApercuBrut {
    version: String,
    langue: String,
    jeton: String,
    origine: String,
    visee: String,
    sha256: String,
    taille: u64,
    cibles: Vec<CibleBrute>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CibleBrute {
    chemin: String,
    version: String,
}

fn illisible(r: &str) -> Vue {
    Vue::Illisible(r.to_string())
}

fn contradictoire() -> Vue {
    illisible(crate::tr!(
        "réponse de Vanguard contradictoire",
        "contradictory answer from Vanguard"
    ))
}

/// Lit la réponse de `se-mettre-a-jour --voir --json`, pour ce code de sortie. « fait » seulement avec le code 0,
/// l'état « propose », une raison vide, l'aperçu et l'accord ; « refuse » seulement avec un code non nul, sa raison,
/// ni aperçu ni accord, et l'état qui dit pourquoi (« a-jour », « rien », « non-verifie » : le code 1).
pub fn lire_apercu(code: Option<i32>, sortie: &[u8]) -> Vue {
    let Some(ligne) = derniere_ligne(sortie) else {
        return illisible(crate::tr!("Vanguard n'a rien répondu", "Vanguard gave no answer"));
    };
    let Ok(b) = super::lire::<ReponseBrute>(ligne) else {
        return illisible(crate::tr!(
            "réponse de Vanguard illisible",
            "unreadable answer from Vanguard"
        ));
    };
    if b.geste != SorteGeste::VoirMiseAJour.mot() {
        return illisible(crate::tr!("réponse d'un autre geste", "answer for another action"));
    }
    match (b.issue.as_str(), b.etat.as_str(), code, b.apercu, b.accord) {
        ("fait", "propose", Some(0), Some(a), Some(accord)) if b.raison.is_empty() => mise_a_jour(&a, &accord)
            .map_or_else(
                || {
                    illisible(crate::tr!(
                        "aperçu de Vanguard mal formé",
                        "malformed preview from Vanguard"
                    ))
                },
                |m| Vue::Proposee(Box::new(m)),
            ),
        ("refuse", etat, Some(c), None, None) if c != 0 => {
            let Some(r) = raison(&b.raison) else {
                return contradictoire();
            };
            match (etat, c) {
                ("a-jour", 1) => Vue::AJour(r),
                ("rien", 1) => Vue::Rien(r),
                ("non-verifie", 1) => Vue::NonVerifiee(r),
                ("refuse", _) => Vue::Refusee(r),
                _ => contradictoire(),
            }
        }
        _ => contradictoire(),
    }
}

/// 64 chiffres hexadécimaux minuscules.
fn sha256(t: &str) -> bool {
    t.len() == 64 && t.bytes().all(|o| matches!(o, b'0'..=b'9' | b'a'..=b'f'))
}

/// Le chemin d'un programme remplacé, tel que Vanguard le montre : « ~/… » sous le dossier personnel, sinon absolu à
/// la façon du système : « /… » ; sous Windows, une lettre de lecteur, « : » et « \ » (« C:\Outils\… »). Relatif,
/// « C:relatif », « C:/… », un partage « \\serveur », un chemin de l'autre système : mal formé.
fn chemin_bien_forme(chemin: &str, windows: bool) -> bool {
    if chemin.len() > 2 && chemin.starts_with("~/") {
        return true;
    }
    if !windows {
        return chemin.starts_with('/');
    }
    match chemin.as_bytes() {
        [lettre, b':', b'\\', reste @ ..] => lettre.is_ascii_alphabetic() && !reste.is_empty(),
        _ => false,
    }
}

fn mise_a_jour(a: &ApercuBrut, accord: &str) -> Option<MiseAJour> {
    let accord = Accord::lire(accord).filter(|a| !a.nul())?;
    if Empreinte::lire(&a.jeton)? != Empreinte::MISE_A_JOUR || !matches!(a.langue.as_str(), "fr" | "en") {
        return None;
    }
    let origine = match a.origine.as_str() {
        "cle" => Origine::Cle,
        "github" => Origine::Github,
        _ => return None,
    };
    if !sha256(&a.sha256) || a.taille == 0 || a.taille > TAILLE_MAX || a.version.chars().count() > 80 {
        return None;
    }
    if a.cibles.is_empty() || a.cibles.len() > CIBLES_MAX {
        return None;
    }
    let lisible = |t: &String| crate::nettoyage::lisible(t);
    let formes = a
        .cibles
        .iter()
        .all(|c| chemin_bien_forme(&c.chemin, cfg!(windows)) && lisible(&c.chemin) && lisible(&c.version));
    if !formes || !lisible(&a.visee) {
        return None;
    }
    let (mut retouche, mut coupe) = (false, false);
    let mut propre = |s: &str, max: usize| {
        let e = montre(s);
        retouche |= e != s || s.contains('\u{fffd}');
        coupe |= e.chars().count() > max;
        crate::nettoyage::couper(&e, max)
    };
    let visee = propre(&a.visee, 80);
    let cibles = a
        .cibles
        .iter()
        .map(|c| Cible {
            chemin: propre(&c.chemin, CHEMIN_MAX),
            version: propre(&c.version, 80),
        })
        .collect();
    Some(MiseAJour {
        origine,
        visee,
        sha256: a.sha256.clone(),
        taille: a.taille,
        cibles,
        accord,
        retouche,
        coupe,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueBrute {
    geste: String,
    issue: String,
    raison: String,
    cibles: Vec<CibleFaite>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CibleFaite {
    chemin: String,
    issue: String,
    raison: String,
}

/// Lit la dernière ligne de `se-mettre-a-jour --appliquer`. Les formes de Vanguard (`mise_a_jour::apercu`) : « fait »
/// avec le code 0, une raison vide et chaque programme « fait » ; « fait » avec le code 1, une raison, et au moins
/// un programme en « echec » avec la sienne (dit en échec : l'ancien reste en place là où c'est dit) ; « refuse »
/// avec le code 1 ou 2, sa raison et aucun programme ; « echec » avec le code 1, sa raison et aucun programme. Toute
/// autre forme est illisible.
pub fn lire_issue(code: Option<i32>, sortie: &[u8]) -> IssueChange {
    let illisible = |r: &str| IssueChange::Illisible(r.to_string());
    let contradictoire = || {
        illisible(crate::tr!(
            "réponse de Vanguard contradictoire",
            "contradictory answer from Vanguard"
        ))
    };
    let Some(ligne) = derniere_ligne(sortie) else {
        return illisible(crate::tr!("Vanguard n'a rien répondu", "Vanguard gave no answer"));
    };
    let Ok(b) = super::lire::<IssueBrute>(ligne) else {
        return illisible(crate::tr!(
            "réponse de Vanguard illisible",
            "unreadable answer from Vanguard"
        ));
    };
    if b.geste != SorteGeste::MettreAJour.mot() {
        return illisible(crate::tr!("réponse d'un autre geste", "answer for another action"));
    }
    if b.cibles.len() > CIBLES_MAX {
        return contradictoire();
    }
    let faite = |c: &CibleFaite| c.issue == "fait" && c.raison.is_empty();
    let ratee = |c: &CibleFaite| c.issue == "echec" && raison(&c.raison).is_some();
    match (b.issue.as_str(), code) {
        ("fait", Some(0)) if b.raison.is_empty() && !b.cibles.is_empty() && b.cibles.iter().all(faite) => {
            IssueChange::Fait {
                relu: Relu::MisAJour,
                annulation: None,
            }
        }
        ("fait", Some(1)) if b.cibles.iter().all(|c| faite(c) || ratee(c)) && b.cibles.iter().any(ratee) => {
            let Some(tete) = raison(&b.raison) else {
                return contradictoire();
            };
            // Chaque programme pas remplacé, avec la raison de Vanguard : le chemin seul ne dit pas pourquoi.
            let detail: Vec<String> = b
                .cibles
                .iter()
                .filter(|c| c.issue == "echec")
                .filter_map(|c| {
                    let chemin = crate::nettoyage::nom(&montre(&c.chemin), CHEMIN_MAX);
                    raison(&c.raison).map(|r| format!("{chemin} : {r}"))
                })
                .collect();
            IssueChange::Echec(crate::nettoyage::couper(
                &format!("{tete} ({})", detail.join(" ; ")),
                RAISON_MAX,
            ))
        }
        ("refuse", Some(1 | 2)) if b.cibles.is_empty() => {
            raison(&b.raison).map_or_else(contradictoire, IssueChange::Refuse)
        }
        ("echec", Some(1)) if b.cibles.is_empty() => raison(&b.raison).map_or_else(contradictoire, IssueChange::Echec),
        _ => contradictoire(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JETON: &str = "6d6973652d612d6a6f75722d76616e67";

    fn accord() -> String {
        "5e".repeat(32)
    }

    fn apercu(origine: &str, cibles: &str) -> String {
        format!(
            r#"{{"version":"0.95.0","langue":"fr","jeton":"{JETON}","origine":"{origine}","visee":"0.96.0","sha256":"{}","taille":12345678,"cibles":{cibles}}}"#,
            "ab".repeat(32)
        )
    }

    fn proposee(apercu: &str) -> String {
        format!(
            r#"{{"geste":"voir-mise-a-jour","issue":"fait","raison":"","etat":"propose","apercu":{apercu},"accord":"{}"}}"#,
            accord()
        )
    }

    const CIBLES: &str = r#"[{"chemin":"~/.local/share/vanguard/bin/vanguard","version":"0.95.0"}]"#;

    fn refus(etat: &str, raison: &str) -> String {
        format!(r#"{{"geste":"voir-mise-a-jour","issue":"refuse","raison":"{raison}","etat":"{etat}"}}"#)
    }

    /// L'aperçu proposé se lit tel quel : origine, version visée, empreinte, taille, chaque programme et l'accord.
    #[test]
    fn l_apercu_propose_se_lit_tel_quel() {
        for (mot, origine) in [("github", Origine::Github), ("cle", Origine::Cle)] {
            let sortie = format!("avertissement\n{}\n", proposee(&apercu(mot, CIBLES)));
            let Vue::Proposee(m) = lire_apercu(Some(0), sortie.as_bytes()) else {
                panic!("{mot}");
            };
            assert_eq!(m.origine, origine);
            assert_eq!(m.visee, "0.96.0");
            assert_eq!(m.sha256, "ab".repeat(32));
            assert_eq!(m.taille, 12_345_678);
            assert_eq!(
                m.cibles,
                [Cible {
                    chemin: "~/.local/share/vanguard/bin/vanguard".into(),
                    version: "0.95.0".into()
                }]
            );
            assert_eq!(m.accord, Accord::lire(&accord()).unwrap());
            assert_eq!(m.pas_d_ici(), None);
        }
    }

    /// Pourquoi rien n'est proposé vient du code de Vanguard : « à jour » seulement pour « a-jour » ; « non
    /// vérifié » ne se lit jamais « à jour », même quand son texte le dit.
    #[test]
    fn non_verifie_ne_se_lit_jamais_a_jour() {
        let lu = |etat: &str, r: &str, code| lire_apercu(Some(code), refus(etat, r).as_bytes());
        assert_eq!(
            lu("a-jour", "Vanguard est à jour ici", 1),
            Vue::AJour("Vanguard est à jour ici".into())
        );
        assert_eq!(
            lu("non-verifie", "Vanguard est à jour ici", 1),
            Vue::NonVerifiee("Vanguard est à jour ici".into())
        );
        assert_eq!(lu("rien", "rien ici", 1), Vue::Rien("rien ici".into()));
        assert_eq!(
            lu("refuse", "accord mal formé", 2),
            Vue::Refusee("accord mal formé".into())
        );
        // Un état inconnu, « a-jour » avec un autre code que 1, un code 0, une raison vide : contradictoires.
        for (etat, r, code) in [
            ("verifie", "x", 1),
            ("a-jour", "x", 2),
            ("a-jour", "x", 0),
            ("non-verifie", "", 1),
            ("propose", "x", 1),
        ] {
            assert!(matches!(lu(etat, r, code), Vue::Illisible(_)), "{etat} {code}");
        }
        assert!(matches!(
            lire_apercu(None, refus("a-jour", "x").as_bytes()),
            Vue::Illisible(_)
        ));
    }

    /// Un chemin absolu de ce système passe, sous Windows comme ailleurs ; toute autre forme, jamais.
    #[test]
    fn un_chemin_se_lit_selon_son_systeme() {
        for (c, linux, windows) in [
            ("/opt/vanguard", true, false),
            ("~/.local/share/vanguard/bin/vanguard", true, true),
            (r"~/AppData\Local\vanguard\bin\vanguard.exe", true, true),
            (r"C:\Outils\vanguard.exe", false, true),
            (r"z:\v.exe", false, true),
            ("C:", false, false),
            (r"C:\", false, false),
            (r"C:relatif\v.exe", false, false),
            ("C:/Outils/vanguard.exe", false, false),
            (r"\\serveur\v.exe", false, false),
            (r"\\?\C:\v.exe", false, false),
            (r"1:\v.exe", false, false),
            (r"é:\v.exe", false, false),
            (r"relatif\v.exe", false, false),
            ("relatif/v", false, false),
            ("~", false, false),
            ("~/", false, false),
            ("", false, false),
        ] {
            assert_eq!(chemin_bien_forme(c, false), linux, "{c}");
            assert_eq!(chemin_bien_forme(c, true), windows, "{c}");
        }
        // Dans l'aperçu entier (JSON : « \\ ») : lu sous Windows seulement.
        let a = apercu("github", CIBLES).replace("~/.local/share/vanguard/bin/vanguard", r"C:\\Outils\\vanguard.exe");
        let v = lire_apercu(Some(0), proposee(&a).as_bytes());
        assert_eq!(matches!(v, Vue::Illisible(_)), !cfg!(windows), "{a} : {v:?}");
    }

    /// Tout écart de forme rend l'aperçu illisible : jamais un aperçu à moitié lu, jamais un accord gardé.
    #[test]
    fn un_apercu_d_une_autre_forme_est_illisible() {
        let bon = apercu("github", CIBLES);
        let mal = [
            bon.replace(JETON, &"0".repeat(32)),
            bon.replace("\"github\"", "\"ailleurs\""),
            bon.replace(&"ab".repeat(32), &"AB".repeat(32)),
            bon.replace(&"ab".repeat(32), &"ab".repeat(31)),
            bon.replace("12345678", "0"),
            bon.replace("12345678", &(TAILLE_MAX + 1).to_string()),
            bon.replace(CIBLES, "[]"),
            bon.replace("~/.local", "relatif/.local"),
            bon.replace("\"langue\":\"fr\"", "\"langue\":\"de\""),
            bon.replace("\"taille\"", "\"autre\":1,\"taille\""),
            bon.replace(",\"visee\":\"0.96.0\"", ""),
        ];
        for a in mal {
            let v = lire_apercu(Some(0), proposee(&a).as_bytes());
            assert!(matches!(v, Vue::Illisible(_)), "{a} : {v:?}");
        }
        let p = proposee(&bon);
        for (sortie, code) in [
            (p.replace(&accord(), &"0".repeat(64)), Some(0)),
            (p.replace("\"propose\"", "\"a-jour\""), Some(0)),
            (p.replace("\"raison\":\"\"", "\"raison\":\"x\""), Some(0)),
            (p.replace("voir-mise-a-jour", "voir-correction"), Some(0)),
            (p.clone(), Some(1)),
            (p.clone(), None),
            (format!("{p}\n{{}}"), Some(0)),
            (String::new(), Some(0)),
        ] {
            let v = lire_apercu(code, sortie.as_bytes());
            assert!(matches!(v, Vue::Illisible(_)), "{sortie} {code:?} : {v:?}");
        }
    }

    /// Un texte retouché par le nettoyage (un caractère de contrôle dans la version) se montre retouché, et
    /// n'installe pas d'ici.
    #[test]
    fn un_texte_retouche_n_installe_pas_d_ici() {
        let a = apercu("cle", CIBLES).replace("\"0.96.0\"", "\"0.96.0\\u202e\"");
        let Vue::Proposee(m) = lire_apercu(Some(0), proposee(&a).as_bytes()) else {
            panic!("illisible");
        };
        assert!(m.retouche);
        assert!(m.pas_d_ici().is_some());
    }

    fn issue(issue: &str, raison: &str, cibles: &str) -> String {
        format!(r#"{{"geste":"mettre-a-jour","issue":"{issue}","raison":"{raison}","cibles":{cibles}}}"#)
    }

    /// L'issue : « fait » seulement quand chaque programme est remplacé (code 0) ; une copie pas remplacée est un
    /// échec qui la nomme ; seul « refuse » dit que rien n'a été fait ; toute autre forme est illisible.
    #[test]
    fn l_issue_ne_dit_fait_que_tout_remplace() {
        let fait = r#"[{"chemin":"~/a/vanguard","issue":"fait","raison":""}]"#;
        let rate = r#"[{"chemin":"~/a/vanguard","issue":"fait","raison":""},{"chemin":"/opt/b/vanguard","issue":"echec","raison":"essai refusé"}]"#;
        assert_eq!(
            lire_issue(Some(0), issue("fait", "", fait).as_bytes()),
            IssueChange::Fait {
                relu: Relu::MisAJour,
                annulation: None
            }
        );
        let IssueChange::Echec(e) = lire_issue(Some(1), issue("fait", "pas tout remplacé", rate).as_bytes()) else {
            panic!("pas un échec");
        };
        assert!(e.contains("/opt/b/vanguard") && e.contains("essai refusé"), "{e}");
        assert_eq!(
            lire_issue(Some(1), issue("refuse", "ça a changé", "[]").as_bytes()),
            IssueChange::Refuse("ça a changé".into())
        );
        assert_eq!(
            lire_issue(Some(1), issue("echec", "téléchargement", "[]").as_bytes()),
            IssueChange::Echec("téléchargement".into())
        );
        for (sortie, code) in [
            (issue("fait", "", fait), Some(1)),
            (issue("fait", "", rate), Some(0)),
            (issue("fait", "", "[]"), Some(0)),
            (issue("fait", "x", fait), Some(1)),
            (issue("refuse", "x", fait), Some(1)),
            (issue("refuse", "", "[]"), Some(1)),
            (issue("refuse", "x", "[]"), Some(0)),
            (issue("echec", "x", "[]"), Some(2)),
            (
                issue("fait", "", fait).replace("mettre-a-jour", "appliquer-correction"),
                Some(0),
            ),
            (
                issue("fait", "", fait).replace("\"raison\":\"\"}", "\"raison\":\"\",\"x\":1}"),
                Some(0),
            ),
            (issue("fait", "", fait), None),
        ] {
            let i = lire_issue(code, sortie.as_bytes());
            assert!(matches!(i, IssueChange::Illisible(_)), "{sortie} {code:?} : {i:?}");
        }
    }
}
