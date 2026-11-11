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
//! 7. la trace d'abord : la ligne « en cours » de « Ce que Vanguard a changé » et son événement (sinon rien), puis
//!    la note d'avant enregistrée et scellée (sinon rien), puis chaque ligne posée par `droits::poser_si` : ouvert
//!    sans suivre de lien, jugé sur son descripteur, posé seulement si c'est encore la cible montrée (même sorte,
//!    même inode) avec les droits montrés ; aucun shell, aucun programme lancé, donc aucun élévateur atteignable.
//!    Tout ou rien : une ligne refusée fait remettre celles déjà posées, et ce qui ne se remet pas est dit ligne par
//!    ligne. Un arrêt brutal en route laisse la ligne « interrompue », qui se remet depuis l'écran ;
//! 8. la relecture après, la ligne finie, puis le journal (règle, jeton et issue typée : jamais un nom de fichier ni
//!    une commande), et la dernière ligne JSON `{"geste","issue":"fait|refuse|echec","raison","annulation","relu"}`.
//!
//! En mode lecture seule (`autotest::lecture_seule`), rien de tout cela : refus net, code 2.
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
    /// La ligne « en cours » n'a pas pu s'écrire : rien n'est appliqué (un arrêt en route ne se verrait pas).
    NonTrace,
    /// Vanguard est en lecture seule : rien n'est lu ni changé, code 2.
    LectureSeule,
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
            Refus::NonTrace => tr!(
                "« Ce que Vanguard a changé » ne s'écrit pas : rien n'a été appliqué",
                "“What Vanguard changed” cannot be written: nothing was applied"
            )
            .to_string(),
            Refus::LectureSeule => lecture_seule(),
        }
    }

    /// Le mot du refus au journal des événements : fixe, sans rien de ce que le compte nomme.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Refus::MalForme => "mal-forme",
            Refus::Occupe => "occupe",
            Refus::Apercu(r) => r.code(),
            Refus::Politique(_) => "pas-d-ici",
            Refus::Change => "change-depuis",
            Refus::Carnet(r) => r.code(),
            Refus::NonNote => "note-non-ecrite",
            Refus::NonTrace => "trace-non-ecrite",
            Refus::LectureSeule => "lecture-seule",
        }
    }
}

/// Le refus d'un geste qui change quelque chose, en lecture seule (appliquer, remettre comme avant).
pub(crate) fn lecture_seule() -> String {
    tr!(
        "Vanguard est en lecture seule : rien n'est appliqué ni remis d'ici",
        "Vanguard is read-only: nothing is applied or restored from here"
    )
    .to_string()
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
    let lecture_seule = crate::autotest::lecture_seule::active();
    let (regle, issue) = match Jeton::lire(jeton).filter(|_| accord_bien_forme(accord)) {
        // Avant tout : en lecture seule, ni verrou, ni relecture, ni carnet.
        _ if lecture_seule => (None, Issue::Refuse(Refus::LectureSeule)),
        None => (None, Issue::Refuse(Refus::MalForme)),
        Some(j) => match crate::optimiser::tenir_les_notes_sans_attendre(&crate::reseau::dossier_local()) {
            None => (None, Issue::Refuse(Refus::Occupe)),
            Some(_notes) => agir(&j, accord),
        },
    };
    let (code, mot, raison) = match &issue {
        Issue::Fait { .. } => (0, "fait", String::new()),
        Issue::Refuse(r @ (Refus::MalForme | Refus::LectureSeule)) => (2, "refuse", r.raison()),
        Issue::Refuse(r) => (1, "refuse", r.raison()),
        Issue::Echec(e) => (1, "echec", e.clone()),
    };
    let relu = match &issue {
        Issue::Fait { corrige: true, .. } => "corrige",
        Issue::Fait { corrige: false, .. } => "encore-signale",
        _ => "",
    };
    noter_au_journal(jeton, regle.as_deref(), &issue);
    // Un carnet des aperçus trouvé altéré par l'aperçu se dit aussi au journal, ici où l'on peut écrire.
    super::carnet::noter_altere_au_journal();
    if json {
        let mut ligne = serde_json::json!({ "geste": SORTE, "issue": mot, "raison": raison, "relu": relu });
        if let (Some(a), Some(o)) = (annulation(&issue), ligne.as_object_mut()) {
            o.insert("annulation".into(), serde_json::Value::String(a));
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
        Err(r) => return (regle, Issue::Refuse(r)),
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
    // 7. La trace d'abord (la ligne « en cours » et son événement), puis la note d'avant, scellée, puis chaque ligne :
    // un arrêt brutal à n'importe quel moment laisse une ligne visible, qui dit « interrompue » et se remet.
    let en_cours = evenement(&a.jeton, regle.as_deref(), "en cours", "in progress", false);
    if !crate::changements::noter_en_cours(&a.commandes, &id, en_cours) {
        return (regle, Issue::Refuse(Refus::NonTrace));
    }
    arret_d_essai("avant-note");
    if !crate::optimiser::annulables::noter(&[&releve]) {
        crate::changements::finir(&id, false);
        return (regle, Issue::Refuse(Refus::NonNote));
    }
    arret_d_essai("avant-pose");
    let pose = poser(&lignes);
    arret_d_essai("apres-pose");
    let ok = pose.is_ok();
    crate::optimiser::annulables::apres_application(&[(id.clone(), ok)]);
    crate::changements::finir(&id, ok);
    if let Err(e) = pose {
        return (regle, Issue::Echec(trf!("non fait : {}", "not done: {}", e)));
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

/// Ce qu'était la cible montrée (sorte, périphérique, inode) ; sans objet sous Windows, où rien ne se pose d'ici.
#[cfg(unix)]
type Identite = crate::optimiser::droits::Identite;
#[cfg(windows)]
type Identite = ();

/// Une ligne à poser : le chemin, les droits montrés (ceux d'avant), ceux à poser, et la cible montrée.
#[derive(Debug, Clone)]
#[cfg_attr(windows, allow(dead_code))]
struct Ligne {
    chemin: std::path::PathBuf,
    avant: u32,
    mode: u32,
    identite: Identite,
}

/// Ce qui sera posé, ligne par ligne, avec les droits d'avant montrés et la cible relevée : seulement si l'aperçu relu
/// est applicable (`apercu::applicable`) et que chaque ligne est un `chmod` permis au compte dont la note d'annulation
/// garde la valeur d'avant et l'identité. Sinon, le refus et sa raison.
#[cfg(unix)]
fn politique(a: &apercu::Apercu, releve: &apercu::Releve) -> Result<Vec<Ligne>, Refus> {
    if a.droits != super::Droits::Compte.mot() {
        return Err(Refus::Politique(admin_ou_terminal(&a.droits)));
    }
    let Ok(r) = releve else {
        return Err(Refus::Politique(non_annulable()));
    };
    if !apercu::applicable(a) {
        return Err(Refus::Politique(non_annulable()));
    }
    let valeurs: Vec<(&str, Option<&str>)> = r.valeurs().collect();
    a.commandes
        .iter()
        .map(|l| {
            let (chemin, mode) =
                apercu::chmod_du_compte(l).ok_or_else(|| Refus::Politique(admin_ou_terminal("admin")))?;
            let geste = crate::optimiser::Geste::droits(&chemin).ok_or_else(|| Refus::Politique(non_annulable()))?;
            // La valeur d'avant de ce chemin, notée par cette correction : sans elle, la ligne ne s'annulerait pas.
            let avant = valeurs
                .iter()
                .find(|(g, _)| *g == geste.0)
                .and_then(|(_, v)| *v)
                .filter(|v| crate::optimiser::annulables::droits_admis(v))
                .and_then(|v| u32::from_str_radix(v, 8).ok())
                .ok_or_else(|| Refus::Politique(non_annulable()))?;
            // La cible relevée avec elle : un fichier lisible en a toujours une ; sans elle, rien ne garantirait que
            // le fichier posé est celui montré.
            let identite = r
                .identite(&geste.0)
                .and_then(Identite::lue)
                .ok_or_else(|| Refus::Politique(non_annulable()))?;
            Ok(Ligne {
                chemin,
                avant,
                mode,
                identite,
            })
        })
        .collect()
}

/// Sous Windows, rien ne s'applique d'ici dans ce lot : toute correction y demande la fenêtre administrateur.
#[cfg(windows)]
fn politique(a: &apercu::Apercu, _releve: &apercu::Releve) -> Result<Vec<Ligne>, Refus> {
    Err(Refus::Politique(admin_ou_terminal(&a.droits)))
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

/// Pose chaque ligne, seulement sur la cible et les droits montrés, tout ou rien : une ligne refusée arrête la suite
/// (rien n'est posé après un état qui n'est plus celui montré) et fait remettre, de la plus récente à la plus
/// ancienne, celles déjà posées, chacune seulement si elle a encore ce que Vanguard vient d'y poser. L'erreur dit,
/// ligne par ligne, ce qui a été refusé et ce qui a été remis ou non ; jamais une ligne que Vanguard n'a pas touchée.
#[cfg(unix)]
fn poser(lignes: &[Ligne]) -> Result<(), crate::modele::raison::Echec> {
    use crate::optimiser::droits;
    let n = lignes.len();
    let rang = |k: usize| k.saturating_add(1);
    for (k, l) in lignes.iter().enumerate() {
        let Err(e) = droits::poser_si(&l.chemin, Some(l.avant), Some(l.identite), l.mode) else {
            continue;
        };
        let mut dit = vec![trf!(
            "ligne {} sur {} refusée : {}",
            "line {} of {} refused: {}",
            rang(k),
            n,
            e
        )];
        // La ligne refusée elle-même n'est remise que si elle porte ce que Vanguard posait (refus après le geste).
        let touchee =
            l.mode != l.avant && droits::lire_identifie(&l.chemin).is_ok_and(|(m, i)| m == l.mode && i == l.identite);
        let a_remettre = if touchee { k.saturating_add(1) } else { k };
        for (j, p) in lignes.iter().enumerate().take(a_remettre).rev() {
            dit.push(
                match droits::poser_si(&p.chemin, Some(p.mode), Some(p.identite), p.avant) {
                    Ok(_) => trf!(
                        "ligne {} sur {} remise comme avant",
                        "line {} of {} restored as before",
                        rang(j),
                        n
                    ),
                    Err(e) => trf!(
                        "ligne {} sur {} NON remise ({}) : elle se remet depuis « Ce que Vanguard a changé »",
                        "line {} of {} NOT restored ({}): it can be restored from “What Vanguard changed”",
                        rang(j),
                        n,
                        e
                    ),
                },
            );
        }
        return Err(crate::modele::raison::Echec::echoue("appliquer/poser", dit.join(" ; ")));
    }
    Ok(())
}

#[cfg(windows)]
fn poser(_lignes: &[Ligne]) -> Result<(), crate::modele::raison::Echec> {
    Err(crate::modele::raison::Echec::refuse(
        "appliquer/poser",
        admin_ou_terminal("admin"),
    ))
}

/// Variante d'essai, absente du programme publié (compilé sans `debug_assertions`) : `VANGUARD_ESSAI_ARRET=<étape>`
/// fige le programme à cette étape, après l'avoir dit sur la sortie d'erreur, jusqu'à la fin de son entrée : un essai
/// le tue là, ou change un fichier puis ferme l'entrée pour qu'il reprenne (`tests/programme.rs`). Rien d'autre n'y
/// change.
fn arret_d_essai(etape: &str) {
    #[cfg(debug_assertions)]
    if std::env::var("VANGUARD_ESSAI_ARRET").is_ok_and(|e| e == etape) {
        use std::io::{Read as _, Write as _};
        let _ = writeln!(std::io::stderr(), "essai : arrêt {etape}");
        let _ = std::io::stdin().read_to_end(&mut Vec::new());
    }
    #[cfg(not(debug_assertions))]
    let _ = etape;
}

/// Un événement de la demande, pour le journal : la règle et le jeton, et ce qu'elle devient (`fr`/`en`), jamais un
/// nom de fichier (que le compte choisit) ni une commande (qui en porte un).
fn evenement(
    jeton: &str,
    regle: Option<&str>,
    fr: &str,
    en: &str,
    reussi: bool,
) -> crate::modele::evenement::Evenement {
    use crate::modele::evenement::{Evenement, Source};
    let bien_forme = Jeton::lire(jeton).is_some();
    let qui = match regle {
        Some(r) => trf!("{} (jeton {})", "{} (token {})", r, jeton),
        None if bien_forme => trf!("jeton {}", "token {}", jeton),
        None => tr!("jeton mal formé", "malformed token").to_string(),
    };
    let texte = trf!(
        "Correction demandée par un geste : {} : {}",
        "Fix requested by a gesture: {}: {}",
        qui,
        if crate::langue::anglais() { en } else { fr }
    );
    let cle = format!("{SORTE}|{}", if bien_forme { jeton } else { "mal-forme" });
    Evenement::action(Source::Correction, &texte, reussi, &[]).cle(Some(&cle))
}

/// La demande au journal des événements, faite ou pas, comme le geste du démarrage : la règle, le jeton et l'issue
/// typée (le mot du refus, `Refus::code`), jamais sa raison, qui peut nommer un fichier. Un refus identique au
/// dernier pour ce jeton, il y a moins de 10 minutes, ne se réécrit pas.
fn noter_au_journal(jeton: &str, regle: Option<&str>, issue: &Issue) {
    let (fr, en) = match issue {
        Issue::Fait { .. } => ("faite".to_string(), "done".to_string()),
        Issue::Refuse(r) => (format!("refusée ({})", r.code()), format!("refused ({})", r.code())),
        Issue::Echec(_) => ("en échec (echec)".to_string(), "failed (echec)".to_string()),
    };
    let ev = evenement(jeton, regle, &fr, &en, matches!(issue, Issue::Fait { .. }));
    if matches!(issue, Issue::Refuse(_))
        && crate::modele::journal::dernier_evenement(
            |e| e.cle.is_some() && e.cle == ev.cle,
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

    /// En lecture seule, le geste est refusé net, code 2, avant toute lecture (ni verrou, ni carnet, ni note).
    #[test]
    fn en_lecture_seule_rien_ne_s_applique() {
        crate::autotest::lecture_seule::poser();
        let code = appliquer(&"0a".repeat(16), &"0a".repeat(32), true);
        crate::autotest::lecture_seule::relever_pour_le_test();
        assert_eq!(code, 2);
    }

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
        let lignes = [Ligne {
            chemin: std::path::PathBuf::from(r"C:\essai\fichier"),
            avant: 0o644,
            mode: 0o600,
            identite: (),
        }];
        assert!(poser(&lignes).is_err());
    }

    #[cfg(unix)]
    fn dossier_d_essai(nom: &str) -> std::path::PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-appliquer-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    fn fichier(d: &std::path::Path, nom: &str, mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let f = d.join(nom);
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        f
    }

    #[cfg(unix)]
    fn mode(f: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(f).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    fn ligne(f: &std::path::Path, avant: u32, mode: u32) -> Ligne {
        Ligne {
            chemin: f.to_path_buf(),
            avant,
            mode,
            identite: crate::optimiser::droits::lire_identifie(f).unwrap().1,
        }
    }

    /// Un fichier changé entre la relecture et le geste n'est pas touché : chaque ligne n'est posée que si le fichier
    /// a encore les droits relus (mutation : `poser_si(.., None, ..)`), et s'il est encore le même fichier : un autre
    /// mis sous le même nom, aux mêmes droits, ne l'est pas (mutation : identité `None`).
    #[cfg(unix)]
    #[test]
    fn rien_n_est_pose_sur_un_fichier_change_depuis_la_relecture() {
        let d = dossier_d_essai("pose");
        let f = fichier(&d, "cle", 0o644);
        assert!(poser(&[ligne(&f, 0o664, 0o600)]).is_err());
        assert_eq!(mode(&f), 0o644);
        // Remplacé par un autre fichier, aux mêmes droits : la ligne relevée sur l'ancien n'y est pas posée.
        let montree = ligne(&f, 0o644, 0o600);
        let g = fichier(&d, "neuf", 0o644);
        std::fs::rename(&g, &f).unwrap();
        let e = poser(std::slice::from_ref(&montree)).unwrap_err().to_string();
        assert!(e.contains("autre inode"), "{e}");
        assert_eq!(mode(&f), 0o644);
        assert_eq!(poser(&[ligne(&f, 0o644, 0o600)]), Ok(()));
        assert_eq!(mode(&f), 0o600);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Tout ou rien : la deuxième ligne refusée, la première, déjà posée, est remise comme avant, et l'erreur le dit
    /// ligne par ligne ; la ligne refusée, jamais touchée, garde ce qu'elle avait (mutation : pas de remise).
    #[cfg(unix)]
    #[test]
    fn une_ligne_refusee_fait_remettre_les_lignes_deja_posees() {
        let dossier = dossier_d_essai("tout-ou-rien");
        let (f, g) = (fichier(&dossier, "un", 0o644), fichier(&dossier, "deux", 0o640));
        // La deuxième a été montrée à 0644 mais est à 0640 : refusée, rien n'y est posé.
        let erreur = poser(&[ligne(&f, 0o644, 0o600), ligne(&g, 0o644, 0o600)])
            .unwrap_err()
            .to_string();
        assert_eq!((mode(&f), mode(&g)), (0o644, 0o640));
        assert!(erreur.contains("ligne 2 sur 2 refusée"), "{erreur}");
        assert!(erreur.contains("ligne 1 sur 2 remise comme avant"), "{erreur}");
        assert!(!erreur.contains("ligne 2 sur 2 remise"), "{erreur}");
        // La remise elle-même refusée (la première changée entre-temps par un autre) se dit, ligne par ligne.
        let (f, g, h) = (
            fichier(&dossier, "a", 0o644),
            fichier(&dossier, "b", 0o644),
            fichier(&dossier, "c", 0o640),
        );
        let lignes = [
            ligne(&f, 0o644, 0o600),
            ligne(&g, 0o644, 0o600),
            ligne(&h, 0o644, 0o600),
        ];
        assert_eq!(poser(&lignes[..1]), Ok(()));
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o400)).unwrap();
        let erreur = poser(&[ligne(&f, 0o400, 0o600), lignes[1].clone(), lignes[2].clone()])
            .unwrap_err()
            .to_string();
        assert!(erreur.contains("ligne 3 sur 3 refusée"), "{erreur}");
        assert!(erreur.contains("ligne 2 sur 3 remise comme avant"), "{erreur}");
        assert!(erreur.contains("ligne 1 sur 3 remise comme avant"), "{erreur}");
        assert_eq!((mode(&f), mode(&g), mode(&h)), (0o400, 0o644, 0o640));
        let _ = std::fs::remove_dir_all(&dossier);
    }
}
