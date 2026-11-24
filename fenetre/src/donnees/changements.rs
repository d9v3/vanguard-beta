//! « Ce que Vanguard a changé » et ses gestes, relus pour l'affichage :
//!
//! - la liste (`changements --json`), lue comme les autres listes (un champ inconnu est ignoré, une ligne illisible
//!   comptée à part) ; seul son geste est lu strictement, avec la structure du relais (`commandes::GesteOffert`), pour
//!   que la fenêtre n'offre jamais « Remettre comme avant » quand le relais le refuserait. L'état d'une ligne vient de
//!   son code (`etat`), jamais de son texte : une ligne interrompue se dit « interrompue », même quand le texte de
//!   Vanguard ajoute « annulable » (campagne B, M-4) ;
//! - l'aperçu d'une annulation (`changements --voir <jeton> --json`), relu strictement comme celui d'une correction
//!   (`donnees::correction`) : un champ inconnu, absent, nul ou d'un autre type, un autre jeton, d'autres droits que
//!   ceux du compte, des droits de fichier qui ne sont pas des chiffres octaux rendent la réponse illisible ; chaque
//!   texte est nettoyé, `retouche` et `coupe` disent ce que le nettoyage a changé ;
//! - l'issue d'un geste qui change (`correction --appliquer`, `changements --annuler`) : la dernière ligne, lue
//!   strictement. Seul « refuse » dit que rien n'a été fait ; un échec ou une réponse illisible ne le dit jamais.
//!
//! Chaque texte de Vanguard passe par `nettoyage` dès la lecture (campagne B, M-5 : les champs JSON portent les
//! caractères tels quels, bidi et invisibles compris).

use serde::Deserialize;

use super::correction::{Lecture, montre, present};
use super::{Liste, Texte};
use crate::commandes::{Accord, Empreinte, Famille, GesteOffert, SorteGeste};

/// Valeurs remises au plus dans un aperçu (une note de droits en a quelques-unes).
pub const VALEURS_MAX: usize = 64;
/// Longueur d'une raison de refus ou d'échec montrée, en caractères : un refus de Vanguard peut citer le titre d'un
/// changement (« un changement plus récent touche la même chose (…) »), un échec dit ce que le système a répondu.
pub const RAISON_MAX: usize = 400;
/// Longueur d'un chemin ou d'un titre montré.
pub const CHEMIN_MAX: usize = 400;

// --- La liste -------------------------------------------------------------------------------------------------

/// L'état d'une ligne, lu de son code (`changements::ligne` dans Vanguard).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Etat {
    Annulable,
    /// Commencée (ou sa remise commencée), jamais finie : Vanguard a été arrêté en route.
    Interrompue,
    EnPlace,
    Fait,
    Defaite,
    Annule,
    Supprime,
    Echoue,
    /// Un code que cette fenêtre ne connaît pas.
    Inconnu,
}

impl Etat {
    fn lire(code: &str) -> Etat {
        match code {
            "annulable" => Etat::Annulable,
            "interrompue" => Etat::Interrompue,
            "en-place" => Etat::EnPlace,
            "fait" => Etat::Fait,
            "defaite" => Etat::Defaite,
            "annule" => Etat::Annule,
            "supprime" => Etat::Supprime,
            "echoue" => Etat::Echoue,
            _ => Etat::Inconnu,
        }
    }

    /// Le mot montré, écrit par la fenêtre.
    pub fn nom(self) -> &'static str {
        match self {
            Etat::Annulable => crate::tr!("annulable", "undoable"),
            Etat::Interrompue => crate::tr!("interrompue", "interrupted"),
            Etat::EnPlace => crate::tr!("en place", "in place"),
            Etat::Fait => crate::tr!("fait", "done"),
            Etat::Defaite => crate::tr!("remise comme avant", "restored"),
            Etat::Annule => crate::tr!("annulé", "undone"),
            Etat::Supprime => crate::tr!("fichier supprimé", "file deleted"),
            Etat::Echoue => crate::tr!("échoué", "failed"),
            Etat::Inconnu => crate::tr!("état inconnu", "unknown state"),
        }
    }
}

/// Une ligne de « Ce que Vanguard a changé ».
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ligne {
    pub date: String,
    pub texte: String,
    pub blocage: bool,
    pub etat: Etat,
    /// Changée hors de Vanguard, ou reprise d'avant le sceau : jamais lue comme une ligne de Vanguard.
    pub douteuse: bool,
    /// Le jeton de « Remettre comme avant », si Vanguard l'offre d'ici et qu'il n'est offert qu'une fois.
    pub annulation: Option<Empreinte>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vue {
    /// Comment le relevé s'est relu (« intact », « absent », « efface »…), nettoyé.
    pub releve: String,
    pub total: usize,
    pub plus_anciens: usize,
    pub lignes: Vec<Ligne>,
    pub illisibles: usize,
}

impl Vue {
    /// Le relevé s'est relu tel que Vanguard l'a scellé (ou il n'y en a pas encore).
    pub fn releve_sain(&self) -> bool {
        matches!(self.releve.as_str(), "intact" | "absent")
    }

    /// Cette liste offre-t-elle de remettre ce jeton ?
    pub fn offre(&self, jeton: Empreinte) -> bool {
        self.lignes.iter().any(|l| l.annulation == Some(jeton))
    }

    pub fn resume(&self) -> String {
        let n = self.lignes.len();
        let mut s = crate::trf!(
            "{} montrés sur {}",
            "{} shown of {}",
            crate::trn!(n, "changement", "changements", "change", "changes"),
            self.total
        );
        if !self.releve_sain() {
            s.push_str(&crate::trf!(
                " · relevé : {}",
                " · record: {}",
                if self.releve.is_empty() { "?" } else { &self.releve }
            ));
        }
        s
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Brut {
    releve: Texte,
    total: Texte,
    plus_anciens: Texte,
    changements: Liste<LigneBrute>,
}

/// Une ligne, lue en partie (la preuve et le nombre de commandes ne sont pas montrés). Son geste, s'il y en a un, est
/// lu strictement (`GesteOffert`) : mal formé, la ligne est illisible, comptée à part.
#[derive(Deserialize, Default)]
#[serde(default)]
struct LigneBrute {
    date: Texte,
    texte: Texte,
    genre: Texte,
    etat: Texte,
    origine: Texte,
    geste: Option<GesteOffert>,
}

pub fn lire(sortie: &[u8]) -> Result<Vue, String> {
    let b: Brut = super::lire(sortie)?;
    let nombre = |t: &Texte| t.as_str().parse::<usize>().unwrap_or(0);
    let jeton = |l: &LigneBrute| {
        l.geste
            .as_ref()
            .and_then(GesteOffert::lire)
            .filter(|(_, s)| *s == SorteGeste::VoirAnnulation)
            .map(|(j, _)| j)
    };
    // Un jeton offert deux fois n'est offert pour aucune ligne (le relais le refuserait aussi).
    let mut vus = std::collections::HashMap::<Empreinte, usize>::new();
    for j in b.changements.elements.iter().filter_map(jeton) {
        *vus.entry(j).or_default() += 1;
    }
    let lignes = b
        .changements
        .elements
        .iter()
        .map(|l| Ligne {
            date: crate::nettoyage::nom(l.date.as_str(), 40),
            texte: crate::nettoyage::nom(l.texte.as_str(), crate::nettoyage::LIGNE_MAX),
            blocage: l.genre.as_str() == "blocage",
            etat: Etat::lire(l.etat.as_str()),
            douteuse: !l.origine.is_empty(),
            annulation: jeton(l).filter(|j| vus.get(j) == Some(&1)),
        })
        .collect();
    Ok(Vue {
        releve: crate::nettoyage::nom(b.releve.as_str(), 40),
        total: nombre(&b.total),
        plus_anciens: nombre(&b.plus_anciens),
        lignes,
        illisibles: b.changements.illisibles,
    })
}

// --- L'aperçu d'une annulation -----------------------------------------------------------------------------------

/// Une valeur à remettre : les droits d'un fichier du compte, en chiffres octaux (« 0600 »).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Valeur {
    pub chemin: String,
    pub actuel: String,
    pub avant: String,
    /// Ce que Vanguard avait posé ; vide s'il ne le sait plus.
    pub pose: String,
    /// Aujourd'hui n'est pas ce que Vanguard a posé : changé depuis, par vous ou un programme.
    pub change_depuis: bool,
}

/// L'aperçu d'une annulation, prêt à montrer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Annulation {
    pub titre: String,
    pub date: String,
    pub valeurs: Vec<Valeur>,
    pub accord: Accord,
    pub retouche: bool,
    pub coupe: bool,
}

impl Annulation {
    pub fn signes(&self) -> usize {
        let n = |t: &String| t.chars().count();
        self.valeurs
            .iter()
            .map(|v| n(&v.chemin) + n(&v.actuel) + n(&v.avant) + n(&v.pose))
            .fold(n(&self.titre).saturating_add(n(&self.date)), usize::saturating_add)
    }

    /// Pourquoi elle ne se remet pas depuis la fenêtre, si elle ne s'y remet pas : montrée exactement, assez courte.
    pub fn pas_d_ici(&self) -> Option<&'static str> {
        if self.retouche || self.coupe {
            return Some(crate::tr!(
                "Ce qui est montré n'est pas exactement le texte de Vanguard : elle ne se remet pas d'ici (vanguard changements dans un terminal).",
                "What is shown is not exactly Vanguard's text: it is not restored from here (vanguard changes in a terminal)."
            ));
        }
        if self.signes() > super::correction::SIGNES_ACCEPTABLES {
            return Some(crate::tr!(
                "Trop longue pour se lire ici d'un coup d'œil : vanguard changements dans un terminal.",
                "Too long to read here at a glance: vanguard changes in a terminal."
            ));
        }
        None
    }
}

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApercuBrut {
    version: String,
    langue: String,
    jeton: String,
    titre: String,
    date: String,
    droits: String,
    valeurs: Vec<ValeurBrute>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValeurBrute {
    chemin: String,
    actuel: String,
    avant: String,
    pose: String,
    change_depuis: bool,
}

/// Des droits de fichier comme Vanguard les écrit : trois ou quatre chiffres octaux.
fn octal(t: &str) -> bool {
    matches!(t.len(), 3 | 4) && t.bytes().all(|o| matches!(o, b'0'..=b'7'))
}

/// La dernière ligne non vide d'une sortie.
pub(super) fn derniere_ligne(sortie: &[u8]) -> Option<&[u8]> {
    sortie
        .split(|o| *o == b'\n')
        .rev()
        .find(|l| !l.iter().all(u8::is_ascii_whitespace))
}

/// Une raison de Vanguard, montrée nettoyée et bornée ; vide ou sans signe dessiné, elle n'en est pas une.
pub(super) fn raison(r: &str) -> Option<String> {
    crate::nettoyage::lisible(r).then(|| crate::nettoyage::nom(&montre(r), RAISON_MAX))
}

fn illisible<A>(r: &str) -> Lecture<A> {
    Lecture::Illisible(r.to_string())
}

fn contradictoire<A>() -> Lecture<A> {
    illisible(crate::tr!(
        "réponse de Vanguard contradictoire",
        "contradictory answer from Vanguard"
    ))
}

/// Lit la réponse de `changements --voir <jeton> --json`, pour ce jeton-là et ce code de sortie.
pub fn lire_apercu(jeton: Empreinte, code: Option<i32>, sortie: &[u8]) -> Lecture<Annulation> {
    let Some(ligne) = derniere_ligne(sortie) else {
        return illisible(crate::tr!("Vanguard n'a rien répondu", "Vanguard gave no answer"));
    };
    let Ok(b) = super::lire::<ReponseBrute>(ligne) else {
        return illisible(crate::tr!(
            "réponse de Vanguard illisible",
            "unreadable answer from Vanguard"
        ));
    };
    if b.geste != SorteGeste::VoirAnnulation.mot() {
        return illisible(crate::tr!("réponse d'un autre geste", "answer for another action"));
    }
    match (b.issue.as_str(), code, b.raison, b.apercu, b.accord) {
        ("fait", Some(0), Some(r), Some(a), Some(accord)) if r.is_empty() => annulation(jeton, &a, &accord)
            .map_or_else(
                || {
                    illisible(crate::tr!(
                        "aperçu de Vanguard mal formé",
                        "malformed preview from Vanguard"
                    ))
                },
                |a| Lecture::Lue(Box::new(a)),
            ),
        ("refuse", Some(c), Some(r), None, None) if c != 0 => raison(&r).map_or_else(contradictoire, Lecture::Refusee),
        _ => contradictoire(),
    }
}

fn annulation(jeton: Empreinte, a: &ApercuBrut, accord: &str) -> Option<Annulation> {
    let accord = Accord::lire(accord).filter(|a| !a.nul())?;
    if Empreinte::lire(&a.jeton)? != jeton || !matches!(a.langue.as_str(), "fr" | "en") || a.droits != "compte" {
        return None;
    }
    if a.valeurs.is_empty() || a.valeurs.len() > VALEURS_MAX || a.version.chars().count() > 80 {
        return None;
    }
    let lisible = |t: &String| crate::nettoyage::lisible(t);
    let formes = a.valeurs.iter().all(|v| {
        octal(&v.actuel)
            && octal(&v.avant)
            && (v.pose.is_empty() || octal(&v.pose))
            && (v.chemin.starts_with('/') || v.chemin == "~" || v.chemin.starts_with("~/"))
            && lisible(&v.chemin)
    });
    if !formes || !lisible(&a.titre) {
        return None;
    }
    let (mut retouche, mut coupe) = (false, false);
    let mut propre = |s: &str, max: usize| {
        let e = montre(s);
        retouche |= e != s || s.contains('\u{fffd}');
        coupe |= e.chars().count() > max;
        crate::nettoyage::couper(&e, max)
    };
    let titre = propre(&a.titre, CHEMIN_MAX);
    let date = propre(&a.date, 40);
    let valeurs = a
        .valeurs
        .iter()
        .map(|v| Valeur {
            chemin: propre(&v.chemin, CHEMIN_MAX),
            actuel: v.actuel.clone(),
            avant: v.avant.clone(),
            pose: v.pose.clone(),
            change_depuis: v.change_depuis,
        })
        .collect();
    Some(Annulation {
        titre,
        date,
        valeurs,
        accord,
        retouche,
        coupe,
    })
}

// --- L'issue d'un geste qui change ---------------------------------------------------------------------------

/// Ce que Vanguard a relu après avoir fait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relu {
    /// La correction : le constat ne se voit plus.
    Corrige,
    /// La correction : faite, mais le constat se voit encore.
    EncoreSignale,
    /// L'annulation : chaque valeur est revenue comme avant.
    Revenu,
    /// L'annulation : remise, mais pas relue comme avant partout.
    PasRevenu,
    /// La mise à jour : chaque programme remplacé, relu, comparé et essayé par Vanguard.
    MisAJour,
}

impl Relu {
    /// Ce que la relecture dit est le but atteint.
    pub fn bon(self) -> bool {
        matches!(self, Relu::Corrige | Relu::Revenu | Relu::MisAJour)
    }
}

/// L'issue d'un geste qui change, lue strictement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueChange {
    /// Fait ; pour une correction, le jeton de son annulation (dans « Ce que Vanguard a changé »).
    Fait { relu: Relu, annulation: Option<Empreinte> },
    /// Refusé par Vanguard : rien n'a été fait.
    Refuse(String),
    /// Commencé, pas fini : Vanguard dit ce qui s'est passé.
    Echec(String),
    /// Pas de réponse lisible : on ne sait pas ce qui a été fait.
    Illisible(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueBrute {
    geste: String,
    issue: String,
    raison: String,
    relu: String,
    #[serde(default, deserialize_with = "present")]
    annulation: Option<String>,
}

/// Lit la dernière ligne d'un geste qui change de cette famille. Les formes de Vanguard
/// (`machine::appliquer`, `machine::annuler`) : « fait » avec le code 0 (ou 1 pour une annulation remise mais pas
/// relue), une raison vide et la relecture ; une correction faite donne le jeton de son annulation, jamais une
/// annulation ; « refuse » avec le code 1 ou 2 et sa raison ; « echec » avec le code 1 et sa raison. Toute autre forme
/// est illisible.
pub fn lire_issue(famille: Famille, code: Option<i32>, sortie: &[u8]) -> IssueChange {
    // La mise à jour a sa propre forme (`donnees::mise_a_jour`).
    if famille == Famille::MiseAJour {
        return super::mise_a_jour::lire_issue(code, sortie);
    }
    let illisible = |r: &str| IssueChange::Illisible(r.to_string());
    let Some(ligne) = derniere_ligne(sortie) else {
        return illisible(crate::tr!("Vanguard n'a rien répondu", "Vanguard gave no answer"));
    };
    let Ok(b) = super::lire::<IssueBrute>(ligne) else {
        return illisible(crate::tr!(
            "réponse de Vanguard illisible",
            "unreadable answer from Vanguard"
        ));
    };
    let contradictoire = || {
        illisible(crate::tr!(
            "réponse de Vanguard contradictoire",
            "contradictory answer from Vanguard"
        ))
    };
    if b.geste != famille.changer().mot() {
        return illisible(crate::tr!("réponse d'un autre geste", "answer for another action"));
    }
    let annulation = match b.annulation.as_deref().map(Empreinte::lire) {
        None => None,
        Some(Some(j)) => Some(j),
        Some(None) => return contradictoire(),
    };
    match (b.issue.as_str(), famille, code, b.relu.as_str()) {
        ("fait", Famille::Correction, Some(0), relu) if b.raison.is_empty() && annulation.is_some() => {
            let relu = match relu {
                "corrige" => Relu::Corrige,
                "encore-signale" => Relu::EncoreSignale,
                _ => return contradictoire(),
            };
            IssueChange::Fait { relu, annulation }
        }
        ("fait", Famille::Annulation, Some(0), "revenu") if b.raison.is_empty() && annulation.is_none() => {
            IssueChange::Fait {
                relu: Relu::Revenu,
                annulation: None,
            }
        }
        ("fait", Famille::Annulation, Some(1), "pas-revenu") if b.raison.is_empty() && annulation.is_none() => {
            IssueChange::Fait {
                relu: Relu::PasRevenu,
                annulation: None,
            }
        }
        ("refuse", _, Some(1 | 2), "") if annulation.is_none() => {
            raison(&b.raison).map_or_else(contradictoire, IssueChange::Refuse)
        }
        ("echec", _, Some(1), "") if annulation.is_none() => {
            raison(&b.raison).map_or_else(contradictoire, IssueChange::Echec)
        }
        _ => contradictoire(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JETON: &str = "00112233445566778899aabbccddeeff";
    const ACCORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn jeton() -> Empreinte {
        Empreinte::lire(JETON).unwrap()
    }

    fn apercu_json() -> serde_json::Value {
        serde_json::json!({
            "accord": ACCORD,
            "apercu": {
                "date": "2026-11-11 15:10", "droits": "compte", "jeton": JETON, "langue": "fr",
                "titre": "chmod 600 ~/.netrc", "version": "0.99.0",
                "valeurs": [{"actuel": "0600", "avant": "0644", "change_depuis": false, "chemin": "~/.netrc",
                             "pose": "0600"}]
            },
            "geste": "voir-annulation", "issue": "fait", "raison": ""
        })
    }

    fn lu(v: &serde_json::Value, code: i32) -> Lecture<Annulation> {
        lire_apercu(jeton(), Some(code), format!("avertissement\n{v}\n").as_bytes())
    }

    #[test]
    fn l_apercu_d_une_annulation_se_lit_strictement() {
        let Lecture::Lue(a) = lu(&apercu_json(), 0) else {
            panic!("{:?}", lu(&apercu_json(), 0));
        };
        assert_eq!(a.titre, "chmod 600 ~/.netrc");
        assert_eq!(a.valeurs.len(), 1);
        assert!(!a.retouche && !a.coupe && a.pas_d_ici().is_none());
        assert_eq!(a.accord, Accord::lire(ACCORD).unwrap());
        // Chaque écart rend la réponse illisible : rien n'est montré comme sûr.
        let ecarts: Vec<(&str, serde_json::Value)> = vec![
            ("/apercu/jeton", serde_json::json!("ffffffffffffffffffffffffffffffff")),
            ("/apercu/droits", serde_json::json!("admin")),
            ("/apercu/langue", serde_json::json!("de")),
            ("/apercu/valeurs", serde_json::json!([])),
            ("/apercu/valeurs/0/actuel", serde_json::json!("rw-------")),
            ("/apercu/valeurs/0/avant", serde_json::json!("0844")),
            ("/apercu/valeurs/0/pose", serde_json::json!("x")),
            ("/apercu/valeurs/0/chemin", serde_json::json!("relatif")),
            ("/apercu/valeurs/0/change_depuis", serde_json::json!(null)),
            ("/apercu/titre", serde_json::json!("\u{200b}")),
            ("/accord", serde_json::json!("0".repeat(64))),
            ("/accord", serde_json::json!("ABC")),
            ("/geste", serde_json::json!("voir-correction")),
            ("/raison", serde_json::json!("x")),
        ];
        for (chemin, valeur) in ecarts {
            let mut v = apercu_json();
            *v.pointer_mut(chemin).unwrap() = valeur;
            assert!(matches!(lu(&v, 0), Lecture::Illisible(_)), "{chemin}");
        }
        let mut v = apercu_json();
        v["apercu"]["nouveau"] = serde_json::json!(1);
        assert!(matches!(lu(&v, 0), Lecture::Illisible(_)));
        let mut v = apercu_json();
        v["apercu"]["valeurs"][0]["nouveau"] = serde_json::json!(1);
        assert!(matches!(lu(&v, 0), Lecture::Illisible(_)));
        // Le code contredit l'issue.
        assert!(matches!(lu(&apercu_json(), 1), Lecture::Illisible(_)));
    }

    #[test]
    fn un_piege_dans_un_chemin_est_retouche_et_ne_s_accepte_pas() {
        let mut v = apercu_json();
        v["apercu"]["valeurs"][0]["chemin"] = serde_json::json!("~/.net\u{202e}crn");
        let Lecture::Lue(a) = lu(&v, 0) else { panic!() };
        assert!(a.retouche);
        assert!(!a.valeurs[0].chemin.contains('\u{202e}'));
        assert!(a.pas_d_ici().is_some());
        let mut v = apercu_json();
        v["apercu"]["titre"] = serde_json::json!("x".repeat(700));
        let Lecture::Lue(a) = lu(&v, 0) else { panic!() };
        assert!(a.pas_d_ici().is_some(), "trop long : pas d'ici");
    }

    #[test]
    fn un_refus_d_annulation_est_montre_nettoye() {
        let v = serde_json::json!({"geste": "voir-annulation", "issue": "refuse",
            "raison": "un changement plus récent touche la même chose (chmod\u{202e} 600) : remettez-le d'abord"});
        let Lecture::Refusee(r) = lu(&v, 1) else { panic!() };
        assert!(!r.contains('\u{202e}') && r.starts_with("un changement plus récent"));
        // Un refus avec le code 0, sans raison ou avec un aperçu est contradictoire.
        assert!(matches!(lu(&v, 0), Lecture::Illisible(_)));
        let v = serde_json::json!({"geste": "voir-annulation", "issue": "refuse", "raison": ""});
        assert!(matches!(lu(&v, 1), Lecture::Illisible(_)));
    }

    fn issue(famille: Famille, code: i32, v: &serde_json::Value) -> IssueChange {
        lire_issue(famille, Some(code), format!("{v}\n").as_bytes())
    }

    #[test]
    fn l_issue_d_un_geste_qui_change_est_lue_strictement() {
        let c = Famille::Correction;
        let a = Famille::Annulation;
        let fait = serde_json::json!({"geste": "appliquer-correction", "issue": "fait", "raison": "",
            "relu": "corrige", "annulation": JETON});
        assert_eq!(
            issue(c, 0, &fait),
            IssueChange::Fait {
                relu: Relu::Corrige,
                annulation: Some(jeton())
            }
        );
        // Fait sans le jeton de l'annulation, avec un autre code, une autre relecture : contradictoire.
        for (pointeur, valeur) in [
            ("/annulation", serde_json::json!("court")),
            ("/relu", serde_json::json!("revenu")),
            ("/raison", serde_json::json!("x")),
            ("/geste", serde_json::json!("annuler-correction")),
        ] {
            let mut v = fait.clone();
            *v.pointer_mut(pointeur).unwrap() = valeur;
            assert!(matches!(issue(c, 0, &v), IssueChange::Illisible(_)), "{pointeur}");
        }
        assert!(matches!(issue(c, 1, &fait), IssueChange::Illisible(_)));
        let mut v = fait.clone();
        v.as_object_mut().unwrap().remove("annulation");
        assert!(matches!(issue(c, 0, &v), IssueChange::Illisible(_)));
        let refus = serde_json::json!({"geste": "appliquer-correction", "issue": "refuse",
            "raison": "ça a changé depuis l'aperçu : rien n'a été fait, refaites l'aperçu", "relu": ""});
        assert!(matches!(issue(c, 1, &refus), IssueChange::Refuse(_)));
        assert!(matches!(issue(c, 2, &refus), IssueChange::Refuse(_)));
        assert!(matches!(issue(c, 0, &refus), IssueChange::Illisible(_)));
        let echec = serde_json::json!({"geste": "appliquer-correction", "issue": "echec",
            "raison": "chmod : opération non permise", "relu": ""});
        assert!(matches!(issue(c, 1, &echec), IssueChange::Echec(_)));
        // L'annulation : revenu (code 0), pas revenu (code 1) ; jamais de jeton d'annulation.
        let remis = serde_json::json!({"geste": "annuler-correction", "issue": "fait", "raison": "", "relu": "revenu"});
        assert!(matches!(
            issue(a, 0, &remis),
            IssueChange::Fait {
                relu: Relu::Revenu,
                annulation: None
            }
        ));
        assert!(matches!(issue(a, 1, &remis), IssueChange::Illisible(_)));
        let pas =
            serde_json::json!({"geste": "annuler-correction", "issue": "fait", "raison": "", "relu": "pas-revenu"});
        assert!(matches!(
            issue(a, 1, &pas),
            IssueChange::Fait {
                relu: Relu::PasRevenu,
                ..
            }
        ));
        assert!(matches!(issue(a, 0, &pas), IssueChange::Illisible(_)));
        let mut v = remis.clone();
        v["annulation"] = serde_json::json!(JETON);
        assert!(matches!(issue(a, 0, &v), IssueChange::Illisible(_)));
        let mut v = remis;
        v["nouveau"] = serde_json::json!(1);
        assert!(matches!(issue(a, 0, &v), IssueChange::Illisible(_)));
        assert!(matches!(lire_issue(a, Some(0), b"  \n"), IssueChange::Illisible(_)));
    }

    #[test]
    fn la_liste_dit_l_etat_par_son_code_et_n_offre_qu_un_jeton_unique() {
        let sortie = serde_json::json!({
            "schema": 1, "releve": "intact", "total": 4, "montres": 4, "plus_anciens": 0,
            "changements": [
                {"date": "2026-11-11 15:10", "reussi": true, "genre": "correction",
                 "texte": "chmod 600 ~/.netrc (interrompue, annulable)", "commandes": 1, "etat": "interrompue",
                 "origine": null, "preuve": null, "geste": {"sorte": "voir-annulation", "jeton": JETON}},
                {"date": "2026-11-11 15:11", "reussi": true, "genre": "correction", "texte": "a\u{200b}b",
                 "commandes": 1, "etat": "annulable", "origine": null, "preuve": null,
                 "geste": {"sorte": "voir-annulation", "jeton": "ffffffffffffffffffffffffffffffff"}},
                {"date": "2026-11-11 15:12", "reussi": true, "genre": "correction", "texte": "b",
                 "commandes": 1, "etat": "annulable", "origine": null, "preuve": null,
                 "geste": {"sorte": "voir-annulation", "jeton": "ffffffffffffffffffffffffffffffff"}},
                {"date": "x", "etat": "annulable", "geste": {"sorte": "voir-correction", "jeton": JETON}},
                {"date": "y", "etat": "annulable", "geste": {"sorte": "voir-annulation", "jeton": JETON, "x": 1}}
            ]
        });
        let v = lire(serde_json::to_string_pretty(&sortie).unwrap().as_bytes()).unwrap();
        assert_eq!(v.lignes.len(), 4);
        assert_eq!(v.illisibles, 1);
        assert_eq!(v.lignes[0].etat, Etat::Interrompue);
        assert_eq!(v.lignes[0].etat.nom(), "interrompue");
        assert_eq!(v.lignes[0].annulation, Some(jeton()));
        assert!(!v.lignes[1].texte.contains('\u{200b}'));
        // Deux fois le même jeton : offert pour aucune ; un « voir » d'une autre famille : pas offert.
        assert_eq!(
            (v.lignes[1].annulation, v.lignes[2].annulation, v.lignes[3].annulation),
            (None, None, None)
        );
        assert!(v.offre(jeton()) && v.releve_sain());
    }
}
