//! Appliquer une correction montrée : `vanguard correction --appliquer <jeton> --accord <accord> [--json]`.
//!
//! La fenêtre ne renvoie que le jeton et l'accord reçus de `--voir`, jamais un texte qu'elle aurait relu. Tout est
//! rejugé ici, dans l'ordre de la conception (2.3), et un refus ne change rien (seul le journal des événements le
//! garde) :
//!
//! 1. la forme (jeton de 32 chiffres, accord de 64), avant toute lecture du système : code 2 ;
//! 2. le verrou des notes, pris tout de suite ou pas du tout, tenu jusqu'à la dernière écriture ;
//! 3. la seule règle du jeton relue (`apercu::relire_pour_agir`), le seul constat d'aujourd'hui retrouvé ;
//! 4. la politique, sur l'état relu : du compte, annulable, faite par Vanguard, chaque ligne `chmod <mode> ~/…`
//!    permise et couverte par la note d'annulation ; jamais sous Windows dans ce lot (une seule fenêtre
//!    administrateur, lot suivant) ;
//! 5. l'accord recalculé sur cette même lecture : différent, « changé depuis l'aperçu » ;
//! 6. le carnet des aperçus : l'entrée exacte, 2 s à 10 min, consommée avant de rien changer ;
//! 7. la note d'avant enregistrée et scellée (sinon rien), puis chaque ligne posée par `droits::poser_si` : ouvert
//!    sans suivre de lien, jugé sur son descripteur, posé seulement si ses droits sont encore ceux montrés ; aucun
//!    shell, aucun programme lancé, donc aucun élévateur atteignable ;
//! 8. la relecture après, puis le journal, et la dernière ligne JSON
//!    `{"geste","issue":"fait|refuse|echec","raison","annulation","relu"}`.
//!
//! Ce que l'accord ne prouve pas : qu'une personne a cliqué. Une fenêtre prise, ou un autre programme du compte, peut
//! enchaîner `--voir` puis `--appliquer` : il n'obtient qu'un durcissement des droits d'un fichier du compte, une
//! correction à la fois, 2 s au moins après son aperçu, notée et annulable (modèle de menace, 4.1 et 4.2).

use super::apercu::{self, Jeton};
use super::carnet;
use crate::ui::{RESET, VERT};
use crate::{tr, trf, trp};

/// La sorte du geste, dans le carnet, la dernière ligne et le journal.
pub(crate) const SORTE: &str = "appliquer-correction";

/// L'accord : 64 chiffres hexadécimaux minuscules.
pub(crate) fn accord_bien_forme(accord: &str) -> bool {
    accord.len() == 64 && accord.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Pourquoi rien n'est fait.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Jeton ou accord mal formés : code 2.
    MalForme,
    /// Un autre Vanguard tient les notes.
    Occupe,
    /// L'aperçu n'est plus donné (disparu, en double, règle hors liste…).
    Apercu(apercu::Refus),
    /// Elle ne s'applique pas d'ici : la raison.
    Politique(String),
    /// L'état relu ne donne plus le même accord.
    Change,
    /// Le carnet des aperçus refuse.
    Carnet(carnet::Refus),
    /// La note d'avant n'a pas pu être enregistrée : rien n'est appliqué.
    NonNote,
}

impl Refus {
    pub(crate) fn raison(&self) -> String {
        match self {
            Refus::MalForme => tr!(
                "jeton (32 chiffres) ou accord (64 chiffres) hexadécimaux minuscules mal formés",
                "malformed token (32 digits) or agreement (64 digits): lowercase hexadecimal expected"
            )
            .to_string(),
            Refus::Occupe => tr!(
                "un autre Vanguard change des réglages en ce moment : rien n'a changé, réessayez à sa fin",
                "another Vanguard is changing settings right now: nothing changed, try again when it ends"
            )
            .to_string(),
            Refus::Apercu(r) => r.raison(),
            Refus::Politique(r) => r.clone(),
            Refus::Change => tr!(
                "ça a changé depuis l'aperçu : rien n'a été fait, refaites l'aperçu",
                "it changed since the preview: nothing was done, show the preview again"
            )
            .to_string(),
            Refus::Carnet(r) => r.raison(),
            Refus::NonNote => tr!(
                "valeurs d'avant non enregistrées : rien n'a été appliqué",
                "previous values not saved: nothing was applied"
            )
            .to_string(),
        }
    }
}

/// Ce qu'est devenue la demande.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Issue {
    /// Faite : l'id de la note qui l'annule, et ce que la relecture d'après a trouvé (`true` : plus signalé).
    Fait {
        note: String,
        corrige: bool,
    },
    Refuse(Refus),
    /// Tentée sans succès (le détail) ; la note reste si quelque chose a changé.
    Echec(String),
}

/// Le jeton d'annulation d'une note : ce que `changements --voir|--annuler` reçoit (`changements::jeton_de_note`).
fn annulation(issue: &Issue) -> Option<String> {
    match issue {
        Issue::Fait { note, .. } => Some(crate::changements::jeton_de_note(note)),
        _ => None,
    }
}

/// `vanguard correction --appliquer <jeton> --accord <accord> [--json]`. Rend le code de sortie : 0 fait, 1 refusé
/// ou en échec, 2 forme refusée (avant toute lecture du système).
pub(crate) fn appliquer(jeton: &str, accord: &str, json: bool) -> i32 {
    let (regle, issue) = match Jeton::lire(jeton).filter(|_| accord_bien_forme(accord)) {
        None => (None, Issue::Refuse(Refus::MalForme)),
        Some(j) => match crate::optimiser::tenir_les_notes_sans_attendre(&crate::reseau::dossier_local()) {
            None => (None, Issue::Refuse(Refus::Occupe)),
            Some(_notes) => agir(&j, accord),
        },
    };
    let (code, mot, raison) = match &issue {
        Issue::Fait { .. } => (0, "fait", String::new()),
        Issue::Refuse(Refus::MalForme) => (2, "refuse", Refus::MalForme.raison()),
        Issue::Refuse(r) => (1, "refuse", r.raison()),
        Issue::Echec(e) => (1, "echec", e.clone()),
    };
    let relu = match &issue {
        Issue::Fait { corrige: true, .. } => "corrige",
        Issue::Fait { corrige: false, .. } => "encore-signale",
        _ => "",
    };
    noter_au_journal(jeton, regle.as_deref(), &issue, &raison);
    if json {
        let mut ligne = serde_json::json!({ "geste": SORTE, "issue": mot, "raison": raison, "relu": relu });
        if let Some(a) = annulation(&issue) {
            ligne["annulation"] = serde_json::Value::String(a);
        }
        println!("{ligne}");
    } else {
        match &issue {
            Issue::Fait { corrige: true, .. } => trp!(
                "  {VERT}✔{RESET} Fait. Vanguard a relu : corrigé. Elle s'annule depuis « Ce que Vanguard a changé ».",
                "  {VERT}✔{RESET} Done. Vanguard read it again: fixed. It can be undone from “What Vanguard changed”."
            ),
            Issue::Fait { corrige: false, .. } => trp!(
                "  ⚠ Fait, mais Vanguard la signale encore à la relecture. Elle s'annule depuis « Ce que Vanguard a changé ».",
                "  ⚠ Done, but Vanguard still reports it when reading again. It can be undone from “What Vanguard changed”."
            ),
            Issue::Refuse(_) => trp!("  ✖ Rien n'a changé : {raison}", "  ✖ Nothing changed: {raison}"),
            Issue::Echec(_) => trp!("  ✖ {raison}", "  ✖ {raison}"),
        }
    }
    code
}

/// Les étapes 3 à 8, le verrou des notes tenu : la règle visée (pour le journal) et l'issue.
fn agir(j: &Jeton, accord: &str) -> (Option<String>, Issue) {
    let constats = match apercu::relire_pour_agir(j) {
        Ok(c) => c,
        Err(r) => return (None, Issue::Refuse(Refus::Apercu(r))),
    };
    let c = match apercu::retrouver_ici(&constats, j) {
        Ok(c) => c,
        Err(r) => return (None, Issue::Refuse(Refus::Apercu(r))),
    };
    let regle = Some(c.regle.to_string());
    let id = crate::optimiser::annulables::id_bilan();
    let Some((a, releve)) = apercu::apercu_et_releve(c, j, id.clone()) else {
        return (regle, Issue::Refuse(Refus::Apercu(apercu::Refus::SansCorrection)));
    };
    // 4. La politique, sur ce qui vient d'être relu (jamais sur ce que la liste ou l'aperçu disaient).
    let lignes = match politique(&a, &releve) {
        Ok(l) => l,
        Err(r) => return (regle, Issue::Refuse(Refus::Politique(r))),
    };
    let Ok(releve) = releve else {
        return (regle, Issue::Refuse(Refus::Politique(non_annulable())));
    };
    // 5. L'accord recalculé sur cette même lecture.
    if a.accord() != accord {
        return (regle, Issue::Refuse(Refus::Change));
    }
    // 6. Le carnet : l'entrée exacte, consommée avant de rien changer.
    if let Err(r) = carnet::consommer(SORTE, &a.jeton, accord) {
        return (regle, Issue::Refuse(Refus::Carnet(r)));
    }
    // 7. La note d'avant, scellée, puis chaque ligne.
    if !crate::optimiser::annulables::noter(&[&releve]) {
        return (regle, Issue::Refuse(Refus::NonNote));
    }
    let erreurs = poser(&lignes);
    let ok = erreurs.is_empty();
    crate::optimiser::annulables::apres_application(&[(id.clone(), ok)]);
    crate::changements::noter_annulables(std::slice::from_ref(&a.commandes), &[ok], &[Some(id.clone())]);
    if !ok {
        return (
            regle,
            Issue::Echec(trf!("non fait : {}", "not done: {}", erreurs.join(" ; "))),
        );
    }
    // 8. La relecture d'après : le constat a-t-il disparu ? Une relecture refusée (autre programme lancé) ne compte
    // pas comme corrigé.
    let corrige = matches!(
        apercu::relire_pour_agir(j).map(|cs| apercu::retrouver_ici(&cs, j).err()),
        Ok(Some(apercu::Refus::Disparu | apercu::Refus::SansCorrection))
    );
    (regle, Issue::Fait { note: id, corrige })
}

fn non_annulable() -> String {
    tr!(
        "elle ne s'annulerait pas : elle se fait depuis le terminal (vanguard corriger)",
        "it could not be undone: it is done from the terminal (vanguard corriger)"
    )
    .to_string()
}

/// Ce qui sera posé, ligne par ligne, avec les droits d'avant montrés : seulement si l'aperçu relu est applicable
/// (`apercu::applicable`) et que chaque ligne est un `chmod` permis au compte dont la note d'annulation garde la
/// valeur d'avant. Sinon, la raison.
#[cfg(unix)]
fn politique(a: &apercu::Apercu, releve: &apercu::Releve) -> Result<Vec<(std::path::PathBuf, u32, u32)>, String> {
    if a.droits != super::Droits::Compte.mot() {
        return Err(admin_ou_terminal(&a.droits));
    }
    let Ok(r) = releve else {
        return Err(non_annulable());
    };
    if !apercu::applicable(a) {
        return Err(non_annulable());
    }
    let valeurs: Vec<(&str, Option<&str>)> = r.valeurs().collect();
    a.commandes
        .iter()
        .map(|l| {
            let (chemin, mode) = apercu::chmod_du_compte(l).ok_or_else(|| admin_ou_terminal("admin"))?;
            let geste = crate::optimiser::Geste::droits(&chemin).ok_or_else(non_annulable)?;
            // La valeur d'avant de ce chemin, notée par cette correction : sans elle, la ligne ne s'annulerait pas.
            let avant = valeurs
                .iter()
                .find(|(g, _)| *g == geste.0)
                .and_then(|(_, v)| *v)
                .filter(|v| crate::optimiser::annulables::droits_admis(v))
                .and_then(|v| u32::from_str_radix(v, 8).ok())
                .ok_or_else(non_annulable)?;
            Ok((chemin, avant, mode))
        })
        .collect()
}

/// Sous Windows, rien ne s'applique d'ici dans ce lot : toute correction y demande la fenêtre administrateur.
#[cfg(windows)]
fn politique(a: &apercu::Apercu, _releve: &apercu::Releve) -> Result<Vec<(std::path::PathBuf, u32, u32)>, String> {
    Err(admin_ou_terminal(&a.droits))
}

fn admin_ou_terminal(droits: &str) -> String {
    if droits == super::Droits::Terminal.mot() {
        tr!(
            "cette correction pose une question : elle se fait dans le terminal (vanguard corriger)",
            "this fix asks a question: it is done in the terminal (vanguard corriger)"
        )
    } else {
        tr!(
            "cette correction demande les droits d'administrateur : elle arrivera ici avec un prochain lot ; d'ici là, vanguard corriger dans un terminal",
            "this fix needs administrator rights: it will come here with a later batch; until then, vanguard corriger in a terminal"
        )
    }
    .to_string()
}

/// Pose chaque ligne, seulement sur les droits montrés ; rend les erreurs (vide : tout est posé). Une ligne refusée
/// arrête la suite : rien n'est posé après un état qui n'est plus celui montré.
#[cfg(unix)]
fn poser(lignes: &[(std::path::PathBuf, u32, u32)]) -> Vec<String> {
    for (chemin, avant, mode) in lignes {
        if let Err(e) = crate::optimiser::droits::poser_si(chemin, Some(*avant), *mode) {
            return vec![e];
        }
    }
    Vec::new()
}

#[cfg(windows)]
fn poser(_lignes: &[(std::path::PathBuf, u32, u32)]) -> Vec<String> {
    vec![admin_ou_terminal("admin")]
}

/// La demande au journal des événements, faite ou pas, comme le geste du démarrage : la règle et le jeton seulement
/// (jamais un nom de fichier, que le compte choisit), l'issue et sa raison. Un refus identique au dernier pour ce
/// jeton, il y a moins de 10 minutes, ne se réécrit pas.
fn noter_au_journal(jeton: &str, regle: Option<&str>, issue: &Issue, raison: &str) {
    use crate::modele::evenement::{Evenement, Source};
    let bien_forme = Jeton::lire(jeton).is_some();
    let qui = match regle {
        Some(r) => trf!("{} (jeton {})", "{} (token {})", r, jeton),
        None if bien_forme => trf!("jeton {}", "token {}", jeton),
        None => tr!("jeton mal formé", "malformed token").to_string(),
    };
    let texte = match issue {
        Issue::Fait { .. } => trf!(
            "Correction demandée par un geste : {} : faite",
            "Fix requested by a gesture: {}: done",
            qui
        ),
        Issue::Refuse(_) => trf!(
            "Correction demandée par un geste : {} : refusée ({})",
            "Fix requested by a gesture: {}: refused ({})",
            qui,
            raison
        ),
        Issue::Echec(_) => trf!(
            "Correction demandée par un geste : {} : {}",
            "Fix requested by a gesture: {}: {}",
            qui,
            raison
        ),
    };
    let cle = format!("{SORTE}|{}", if bien_forme { jeton } else { "mal-forme" });
    let ev = Evenement::action(Source::Correction, &texte, matches!(issue, Issue::Fait { .. }), &[]).cle(Some(&cle));
    if matches!(issue, Issue::Refuse(_))
        && crate::modele::journal::dernier_evenement(
            |e| e.cle.as_deref() == Some(cle.as_str()),
            chrono::Duration::minutes(10),
        )
        .is_some_and(|d| d.source == ev.source && d.quoi == ev.quoi)
    {
        return;
    }
    crate::modele::journal::noter(ev);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_accord_se_lit_strictement() {
        assert!(accord_bien_forme(&"0a".repeat(32)));
        for faux in [
            "",
            "0a",
            &"0A".repeat(32),
            &"0a".repeat(33),
            &format!("{}g", "0".repeat(63)),
        ] {
            assert!(!accord_bien_forme(faux), "{faux}");
        }
    }

    /// Sous Windows, rien ne s'applique d'ici dans ce lot, même une correction dite du compte : la fenêtre
    /// administrateur viendra au lot suivant.
    #[cfg(windows)]
    #[test]
    fn sous_windows_rien_ne_s_applique_d_ici() {
        let a = apercu::Apercu {
            version: "0.0.0".into(),
            langue: "fr".into(),
            jeton: "00112233445566778899aabbccddeeff".into(),
            cle: "WIN-ESS-001|x".into(),
            regle: "WIN-ESS-001".into(),
            categorie: "Essai".into(),
            niveau: "Moyen".into(),
            message: "inventé".into(),
            action: "inventé".into(),
            commandes: vec!["chmod 600 ~/.netrc".into()],
            automatique: true,
            droits: "compte".into(),
            annulable: true,
            pourquoi_pas: String::new(),
            avant: Vec::new(),
            point_de_restauration: false,
        };
        let releve: apercu::Releve = Err(crate::optimiser::annulables::PourquoiPas::NonReleve);
        assert!(politique(&a, &releve).is_err());
        let lignes = [(std::path::PathBuf::from(r"C:\essai\fichier"), 0o644, 0o600)];
        assert_eq!(poser(&lignes).len(), 1);
    }
}
