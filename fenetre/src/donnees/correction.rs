//! L'aperçu d'une correction (`correction --voir <jeton> --json`), relu strictement : la dernière ligne non vide,
//! `{"geste": "voir-correction", "issue": "fait", "apercu": {…}, "accord": "<64 chiffres>"}` avec le code 0, ou
//! `{"geste": "voir-correction", "issue": "refuse", "raison": "…"}` avec un autre code. Tout le reste (un autre
//! geste, un autre jeton que celui demandé, une issue qui contredit le code, un champ manquant ou d'un autre type,
//! des listes trop longues) est illisible : la feuille le dit, et rien n'est montré comme si c'était sûr.
//!
//! L'accord, Vanguard le calcule sur les textes tels qu'il les a écrits ; la fenêtre les montre nettoyés. Si le
//! nettoyage a changé un seul caractère d'un texte montré (un piège, une séquence, un texte coupé), `retouche` le dit :
//! ce qui est montré n'est alors plus exactement ce que l'accord engage (le prochain lot n'offrira pas d'accepter).

use serde::Deserialize;

use super::bilan::Gravite;
use crate::commandes::{Accord, Empreinte};

/// Lignes de commande montrées au plus (une correction de Vanguard en a quelques-unes).
pub const COMMANDES_MAX: usize = 64;
/// Valeurs d'avant montrées au plus.
pub const AVANT_MAX: usize = 64;
/// Longueur d'un nom court (règle, catégorie), en caractères.
const NOM_MAX: usize = 80;

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

/// Tous les champs sont exigés, avec leur type : un champ absent ou d'un autre type rend la réponse illisible.
#[derive(Deserialize)]
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
        ("fait", Some(0), Some(a)) => apercu(jeton, &a, &b.accord).map_or_else(
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
    let mut retouche = false;
    let mut nom = |s: &str| {
        let n = crate::nettoyage::nom(s, NOM_MAX);
        retouche |= n != s;
        n
    };
    let (version, regle, categorie) = (nom(&a.version), nom(&a.regle), nom(&a.categorie));
    let mut texte = |s: &str| {
        let t = crate::nettoyage::texte(s);
        retouche |= t != s;
        t
    };
    let message = texte(&a.message);
    let action = texte(&a.action);
    let pourquoi_pas = texte(&a.pourquoi_pas);
    let mut ligne = |s: &str| {
        let l = crate::nettoyage::ligne(s);
        retouche |= l != s;
        l
    };
    let commandes: Vec<String> = a.commandes.iter().map(|c| ligne(c)).collect();
    let avant: Vec<Avant> = a
        .avant
        .iter()
        .map(|v| Avant {
            geste: ligne(&v.geste),
            valeur: v.valeur.as_deref().map(&mut ligne),
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
        assert!(!a.retouche);
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
            ("regle", serde_json::json!("x".repeat(NOM_MAX + 1))),
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
