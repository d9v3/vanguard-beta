//! Remettre comme avant une correction du compte : `vanguard changements --voir <jeton> [--json]`, puis
//! `vanguard changements --annuler <jeton> --accord <accord> [--json]` (conception, 3.1).
//!
//! Le jeton est celui de la note d'annulation (`changements::jeton_de_note`), donné par `changements --json` ; jamais
//! son id ni ses chemins. Seule une note du bilan qui ne remet que des droits de fichiers du dossier personnel se
//! remet d'ici (`annulables::note_de_droits`) : un `fchmod` sur le fichier ouvert sans suivre de lien
//! (`droits::poser_si`), aucun shell, aucun programme lancé, donc aucun élévateur atteignable.
//!
//! `--voir` relit la note et chaque fichier, et montre valeur par valeur ce qui sera remis : la valeur d'aujourd'hui,
//! celle d'avant, celle que Vanguard avait posée, et « changé depuis » quand aujourd'hui n'est pas ce que Vanguard a
//! posé (par vous ou un programme). Il refuse si une note plus récente touche la même chose. L'aperçu donné est noté
//! au carnet des aperçus (`carnet`), comme celui d'une correction.
//!
//! `--annuler` rejuge tout, dans l'ordre de la conception (2.3) : la forme (code 2), le verrou des notes, la note et
//! les fichiers relus, l'accord recalculé sur cette lecture, le carnet (2 s à 10 min, consommé avant de rien changer),
//! puis chaque valeur remise seulement si le fichier a encore les droits montrés. Tout remis et relu : la note part et
//! la ligne de « Ce que Vanguard a changé » est dite défaite. Une valeur refusée en route arrête la suite ; la note
//! reste, si bien que le reste se remet plus tard (une valeur déjà remise se remet sans rien changer).

use super::appliquer::accord_bien_forme;
use super::carnet;
use crate::ui::{RESET, VERT};
use crate::{tr, trf, trp};

/// La sorte de l'aperçu, dans le geste de `changements --json` et la dernière ligne de `--voir`.
pub(crate) const SORTE_VOIR: &str = "voir-annulation";
/// La sorte du geste qui remet, dans le carnet, la dernière ligne et le journal.
pub(crate) const SORTE: &str = "annuler-correction";
/// Le contexte de l'accord : l'accord d'un aperçu de correction ne vaut jamais pour une annulation, ni l'inverse.
const CONTEXTE_ACCORD: &str = "vanguard accord v1 annulation";

/// Un jeton de note : 32 chiffres hexadécimaux minuscules.
fn jeton_bien_forme(jeton: &str) -> bool {
    jeton.len() == 32 && jeton.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Une valeur à remettre.
#[derive(serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Valeur {
    /// Le chemin, absolu, tel qu'il est remis.
    pub chemin: String,
    /// Les droits d'aujourd'hui (« 0600 »), lus sur le fichier ouvert sans suivre de lien.
    pub actuel: String,
    /// Les droits d'avant, notés par Vanguard avant sa correction : ceux qui seront remis.
    pub avant: String,
    /// Les droits que Vanguard a posés ; vide s'ils ne sont plus connus (ligne élaguée de l'historique).
    pub pose: String,
    /// Aujourd'hui n'est pas ce que Vanguard a posé (ou ce qu'il a posé n'est plus connu) : changé depuis, par vous ou
    /// un programme.
    pub change_depuis: bool,
}

/// Tout ce que l'aperçu donne à montrer ; chaque champ est dans l'accord (`champs`).
#[derive(serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Apercu {
    pub version: String,
    pub langue: String,
    pub jeton: String,
    /// Le titre de la note (la correction faite).
    pub titre: String,
    /// Quand elle a été faite.
    pub date: String,
    /// Toujours « compte » : rien d'autre ne se remet d'ici.
    pub droits: String,
    pub valeurs: Vec<Valeur>,
}

impl Apercu {
    fn champs(&self) -> Vec<(&'static str, Vec<u8>)> {
        use super::apercu::{bloc, liste};
        let valeurs: Vec<Vec<u8>> = self
            .valeurs
            .iter()
            .map(|v| {
                let mut o = Vec::new();
                for t in [&v.chemin, &v.actuel, &v.avant, &v.pose] {
                    bloc(&mut o, t.as_bytes());
                }
                o.push(u8::from(v.change_depuis));
                o
            })
            .collect();
        vec![
            ("version", self.version.clone().into_bytes()),
            ("langue", self.langue.clone().into_bytes()),
            ("jeton", self.jeton.clone().into_bytes()),
            ("titre", self.titre.clone().into_bytes()),
            ("date", self.date.clone().into_bytes()),
            ("droits", self.droits.clone().into_bytes()),
            ("valeurs", liste(valeurs.iter().map(Vec::as_slice))),
        ]
    }

    pub(crate) fn accord(&self) -> String {
        super::apercu::accord_de(CONTEXTE_ACCORD, self.champs())
    }
}

/// Pourquoi rien n'est fait.
// Sous Windows, rien ne se remet d'ici (lot suivant) : la plupart des refus et des issues n'y arrivent jamais.
#[cfg_attr(windows, allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Jeton (ou accord) mal formé : code 2.
    MalForme,
    /// Un autre Vanguard tient les notes.
    Occupe,
    /// Aucune note ne répond au jeton.
    Aucune,
    /// Elle ne se remet pas d'ici.
    Autre,
    /// Une note plus récente touche la même chose : son titre.
    PlusRecente(String),
    /// Un fichier ne se relit plus sans lien (supprimé, remplacé par un lien, autre propriétaire).
    Illisible,
    /// L'état relu ne donne plus le même accord.
    Change,
    Carnet(carnet::Refus),
    /// Sous Windows, rien ne se remet d'ici dans ce lot.
    Windows,
    /// L'aperçu sans la lecture seule posée par main avant tout : code 2.
    SansLectureSeule,
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
            Refus::Aucune => tr!(
                "plus rien à remettre : déjà remis comme avant, ou jamais noté",
                "nothing left to restore: already restored, or never noted"
            )
            .to_string(),
            Refus::Autre => tr!(
                "elle ne se remet pas d'ici : depuis le terminal (vanguard changements)",
                "it is not restored from here: from the terminal (vanguard changements)"
            )
            .to_string(),
            Refus::PlusRecente(titre) => trf!(
                "un changement plus récent touche la même chose ({}) : remettez-le d'abord",
                "a more recent change touches the same thing ({}): restore it first",
                crate::ui::affichable(titre)
            ),
            Refus::Illisible => tr!(
                "un fichier ne se relit plus sans lien (supprimé, remplacé, autre propriétaire) : rien n'a changé",
                "a file can no longer be read without a link (deleted, replaced, other owner): nothing changed"
            )
            .to_string(),
            Refus::Change => tr!(
                "ça a changé depuis l'aperçu : rien n'a été fait, refaites l'aperçu",
                "it changed since the preview: nothing was done, show the preview again"
            )
            .to_string(),
            Refus::Carnet(r) => r.raison(),
            Refus::SansLectureSeule => super::apercu::Refus::SansLectureSeule.raison(),
            Refus::Windows => tr!(
                "sous Windows, rien ne se remet d'ici pour l'instant : vanguard changements dans un terminal",
                "on Windows, nothing is restored from here for now: vanguard changements in a terminal"
            )
            .to_string(),
        }
    }
}

/// Ce qui sera remis : chaque chemin, ses droits d'aujourd'hui (montrés, exigés au moment de remettre) et d'avant.
type Remise = Vec<(std::path::PathBuf, u32, u32)>;

/// L'aperçu de la note au jeton `jeton`, relu maintenant, et les valeurs à remettre (chemin, droits d'aujourd'hui,
/// droits d'avant) ; ou pourquoi il n'est pas donné.
#[cfg(unix)]
fn relire(jeton: &str) -> Result<(Apercu, String, Remise), Refus> {
    use crate::optimiser::annulables::{PasDeNote, note_de_droits};
    let note = note_de_droits(jeton).map_err(|p| match p {
        PasDeNote::Aucune => Refus::Aucune,
        PasDeNote::Autre => Refus::Autre,
        PasDeNote::PlusRecente(t) => Refus::PlusRecente(t),
    })?;
    // Ce que Vanguard a posé, relu dans ses propres commandes (`chmod <mode> ~/…`), jamais dans un texte de la fenêtre.
    let poses: Vec<(std::path::PathBuf, u32)> = crate::changements::commandes_de_la_note(&note.id)
        .unwrap_or_default()
        .iter()
        .filter_map(|l| super::apercu::chmod_du_compte(l))
        .collect();
    let mut valeurs = Vec::new();
    let mut lignes = Vec::new();
    for (chemin, avant) in &note.droits {
        let actuel = crate::optimiser::droits::lire(chemin).map_err(|_| Refus::Illisible)?;
        let pose = poses.iter().rev().find(|(c, _)| c == chemin).map(|(_, m)| *m);
        valeurs.push(Valeur {
            chemin: chemin.to_string_lossy().into_owned(),
            actuel: format!("{actuel:04o}"),
            avant: format!("{avant:04o}"),
            pose: pose.map(|m| format!("{m:04o}")).unwrap_or_default(),
            change_depuis: pose != Some(actuel),
        });
        lignes.push((chemin.clone(), actuel, *avant));
    }
    let a = Apercu {
        version: env!("CARGO_PKG_VERSION").to_string(),
        langue: if crate::langue::anglais() { "en" } else { "fr" }.to_string(),
        jeton: jeton.to_string(),
        titre: note.titre,
        date: note.date,
        droits: super::Droits::Compte.mot().to_string(),
        valeurs,
    };
    Ok((a, note.id, lignes))
}

#[cfg(windows)]
fn relire(_jeton: &str) -> Result<(Apercu, String, Remise), Refus> {
    Err(Refus::Windows)
}

/// `vanguard changements --voir <jeton> [--json]` : ce qui serait remis, rien de changé (seul le carnet des aperçus
/// s'écrit). Avec `json`, la dernière ligne : `{"geste":"voir-annulation","issue":"fait"|"refuse","raison","apercu",
/// "accord"}`. Code : 0 donné, 1 refusé, 2 jeton mal formé.
pub(crate) fn voir(jeton: &str, json: bool) -> i32 {
    // Fermé par construction, comme l'aperçu d'une correction : sans la lecture seule posée par main avant tout le
    // reste, rien n'est relu.
    let issue = if !crate::autotest::lecture_seule::sans_attente() {
        Err(Refus::SansLectureSeule)
    } else if jeton_bien_forme(jeton) {
        relire(jeton).map(|(a, _, _)| a)
    } else {
        Err(Refus::MalForme)
    };
    if let Ok(a) = &issue {
        carnet::noter(SORTE, &a.jeton, &a.accord());
    }
    let code = match &issue {
        Ok(_) => 0,
        Err(Refus::MalForme | Refus::SansLectureSeule) => 2,
        Err(_) => 1,
    };
    if json {
        let ligne = match &issue {
            Ok(a) => serde_json::json!({
                "geste": SORTE_VOIR, "issue": "fait", "raison": "", "apercu": a, "accord": a.accord()
            }),
            Err(r) => serde_json::json!({ "geste": SORTE_VOIR, "issue": "refuse", "raison": r.raison() }),
        };
        println!("{ligne}");
    } else {
        match &issue {
            Ok(a) => {
                use super::apercu::montre_strict;
                use crate::ui::GRAS;
                trp!(
                    "{GRAS}Remettre comme avant{RESET} (rien n'a changé) : {} ({})",
                    "{GRAS}Restore as before{RESET} (nothing changed): {} ({})",
                    montre_strict(&a.titre),
                    montre_strict(&a.date)
                );
                for v in &a.valeurs {
                    trp!(
                        "  {} : {} → {}",
                        "  {}: {} → {}",
                        montre_strict(&v.chemin),
                        v.actuel,
                        v.avant
                    );
                    if v.change_depuis {
                        trp!(
                            "    ⚠ changé depuis, par vous ou un programme",
                            "    ⚠ changed since, by you or a program"
                        );
                    }
                }
                trp!("  Accord : {}", "  Consent: {}", a.accord());
            }
            Err(r) => trp!("  ✖ Pas d'aperçu : {}", "  ✖ No preview: {}", r.raison()),
        }
    }
    code
}

/// Ce qu'est devenue la demande.
#[cfg_attr(windows, allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
enum Issue {
    /// Tout remis ; `true` : relu à la valeur d'avant.
    Fait(bool),
    Refuse(Refus),
    /// Tenté sans aller au bout (le détail) ; la note reste.
    Echec(String),
}

/// `vanguard changements --annuler <jeton> --accord <accord> [--json]`. Code : 0 fait, 1 refusé ou en échec, 2 forme
/// refusée (avant toute lecture). Avec `json`, la dernière ligne : `{"geste":"annuler-correction","issue":
/// "fait|refuse|echec","raison","relu":"revenu|pas-revenu|"}`.
pub(crate) fn annuler(jeton: &str, accord: &str, json: bool) -> i32 {
    let issue = if !jeton_bien_forme(jeton) || !accord_bien_forme(accord) {
        Issue::Refuse(Refus::MalForme)
    } else if cfg!(windows) {
        Issue::Refuse(Refus::Windows)
    } else {
        match crate::optimiser::tenir_les_notes_sans_attendre(&crate::reseau::dossier_local()) {
            None => Issue::Refuse(Refus::Occupe),
            Some(_notes) => agir(jeton, accord),
        }
    };
    let (code, mot, raison) = match &issue {
        Issue::Fait(_) => (0, "fait", String::new()),
        Issue::Refuse(r @ Refus::MalForme) => (2, "refuse", r.raison()),
        Issue::Refuse(r) => (1, "refuse", r.raison()),
        Issue::Echec(e) => (1, "echec", e.clone()),
    };
    let relu = match &issue {
        Issue::Fait(true) => "revenu",
        Issue::Fait(false) => "pas-revenu",
        _ => "",
    };
    noter_au_journal(jeton, &issue, &raison);
    if json {
        println!(
            "{}",
            serde_json::json!({ "geste": SORTE, "issue": mot, "raison": raison, "relu": relu })
        );
    } else {
        match &issue {
            Issue::Fait(true) => trp!(
                "  {VERT}✔{RESET} Remis comme avant. Vanguard a relu : revenu.",
                "  {VERT}✔{RESET} Restored as before. Vanguard read it again: back."
            ),
            Issue::Fait(false) => trp!(
                "  ⚠ Remis, mais Vanguard ne relit pas la valeur d'avant partout.",
                "  ⚠ Restored, but Vanguard does not read the previous value back everywhere."
            ),
            Issue::Refuse(_) => trp!("  ✖ Rien n'a changé : {raison}", "  ✖ Nothing changed: {raison}"),
            Issue::Echec(_) => trp!("  ✖ {raison}", "  ✖ {raison}"),
        }
    }
    code
}

/// Le verrou des notes tenu : relire, comparer l'accord, consommer le carnet, remettre, relire.
#[cfg(unix)]
fn agir(jeton: &str, accord: &str) -> Issue {
    let (a, id, lignes) = match relire(jeton) {
        Ok(r) => r,
        Err(r) => return Issue::Refuse(r),
    };
    if a.accord() != accord {
        return Issue::Refuse(Refus::Change);
    }
    if let Err(r) = carnet::consommer(SORTE, jeton, accord) {
        return Issue::Refuse(Refus::Carnet(r));
    }
    // Une annulation change l'ordinateur : la cache des passages automatiques ne reprend rien d'avant.
    crate::autotest::cache::oublier();
    if let Err(e) = remettre_les(&lignes) {
        crate::autotest::cache::oublier();
        return Issue::Echec(trf!(
            "pas remis jusqu'au bout : {} ; le reste se remet plus tard",
            "not fully restored: {}; the rest can be restored later",
            e
        ));
    }
    let revenu = lignes
        .iter()
        .all(|(chemin, _, avant)| crate::optimiser::droits::lire(chemin).ok() == Some(*avant));
    if revenu {
        crate::optimiser::annulables::oublier(std::slice::from_ref(&id));
        crate::changements::marquer_defaite(&id);
    }
    crate::autotest::cache::oublier();
    Issue::Fait(revenu)
}

/// Chaque ligne (chemin, droits relus au moment d'agir, droits d'avant) remise dans l'ordre, seulement si le fichier a
/// encore les droits relus (`poser_si`) : un fichier changé entre la relecture et le geste n'est pas touché. Arrêté à
/// la première erreur.
#[cfg(unix)]
fn remettre_les(lignes: &[(std::path::PathBuf, u32, u32)]) -> Result<(), String> {
    for (chemin, actuel, avant) in lignes {
        crate::optimiser::droits::poser_si(chemin, Some(*actuel), *avant)?;
    }
    Ok(())
}

#[cfg(windows)]
fn agir(_jeton: &str, _accord: &str) -> Issue {
    Issue::Refuse(Refus::Windows)
}

/// La demande au journal des événements, faite ou pas : le jeton seulement (jamais un nom de fichier), l'issue et sa
/// raison. Un refus identique au dernier pour ce jeton, il y a moins de 10 minutes, ne se réécrit pas.
fn noter_au_journal(jeton: &str, issue: &Issue, raison: &str) {
    use crate::modele::evenement::{Evenement, Source};
    let bien_forme = jeton_bien_forme(jeton);
    let qui = if bien_forme {
        trf!("jeton {}", "token {}", jeton)
    } else {
        tr!("jeton mal formé", "malformed token").to_string()
    };
    let texte = match issue {
        Issue::Fait(_) => trf!(
            "Remise comme avant demandée par un geste : {} : faite",
            "Restore requested by a gesture: {}: done",
            qui
        ),
        Issue::Refuse(_) => trf!(
            "Remise comme avant demandée par un geste : {} : refusée ({})",
            "Restore requested by a gesture: {}: refused ({})",
            qui,
            raison
        ),
        Issue::Echec(_) => trf!(
            "Remise comme avant demandée par un geste : {} : {}",
            "Restore requested by a gesture: {}: {}",
            qui,
            raison
        ),
    };
    let cle = format!("{SORTE}|{}", if bien_forme { jeton } else { "mal-forme" });
    let ev = Evenement::action(Source::Correction, &texte, matches!(issue, Issue::Fait(_)), &[]).cle(Some(&cle));
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

    fn apercu() -> Apercu {
        Apercu {
            version: "0".into(),
            langue: "fr".into(),
            jeton: "0".repeat(32),
            titre: "t".into(),
            date: "d".into(),
            droits: "compte".into(),
            valeurs: vec![Valeur {
                chemin: "/home/alice/.netrc".into(),
                actuel: "0600".into(),
                avant: "0644".into(),
                pose: "0600".into(),
                change_depuis: false,
            }],
        }
    }

    /// Chaque champ montré change l'accord, et l'accord d'une annulation n'est jamais celui d'un aperçu de correction
    /// aux mêmes champs (contexte distinct).
    #[test]
    fn l_accord_de_l_annulation_tient_chaque_champ() {
        let base = apercu();
        let a = base.accord();
        let mut variantes = Vec::new();
        for i in 0..11 {
            let mut v = base.clone();
            match i {
                0 => v.version.push('1'),
                1 => v.langue = "en".into(),
                2 => v.jeton = "1".repeat(32),
                3 => v.titre.push('x'),
                4 => v.date.push('x'),
                5 => v.droits = "admin".into(),
                6 => v.valeurs[0].chemin.push('x'),
                7 => v.valeurs[0].actuel = "0700".into(),
                8 => v.valeurs[0].avant = "0640".into(),
                9 => v.valeurs[0].pose = String::new(),
                _ => v.valeurs[0].change_depuis = true,
            }
            variantes.push(v.accord());
        }
        assert!(variantes.iter().all(|v| *v != a), "chaque champ compte");
        assert_ne!(
            super::super::apercu::accord_de("vanguard accord v1 correction", base.champs()),
            a
        );
        // Les clés du JSON sont exactement les champs de l'accord.
        let json = serde_json::to_value(&base).unwrap();
        let mut cles: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
        let mut champs: Vec<&str> = base.champs().iter().map(|(n, _)| *n).collect();
        cles.sort_unstable();
        champs.sort_unstable();
        assert_eq!(cles, champs);
    }

    #[test]
    fn le_jeton_de_note_se_lit_strictement() {
        assert!(jeton_bien_forme(&"a".repeat(32)));
        for mauvais in [
            "",
            "A".repeat(32).as_str(),
            "a".repeat(31).as_str(),
            "a".repeat(33).as_str(),
            "g".repeat(32).as_str(),
        ] {
            assert!(!jeton_bien_forme(mauvais), "{mauvais}");
        }
    }

    /// La remise ne touche pas un fichier changé entre la relecture et le geste (mutation : `poser_si(.., None, ..)`),
    /// et s'arrête à la première ligne refusée.
    #[cfg(unix)]
    #[test]
    fn rien_n_est_remis_sur_un_fichier_change_depuis_la_relecture() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::essais::temporaire().join(format!("vanguard-annuler-remise-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let (f, g) = (d.join("cle"), d.join("autre"));
        for x in [&f, &g] {
            std::fs::write(x, b"x").unwrap();
            std::fs::set_permissions(x, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mode = |x: &std::path::Path| std::fs::symlink_metadata(x).unwrap().permissions().mode() & 0o7777;
        // Relu 0640, mais le fichier est à 0600 : rien n'est remis, ni lui ni la ligne d'après.
        assert!(remettre_les(&[(f.clone(), 0o640, 0o644), (g.clone(), 0o600, 0o644)]).is_err());
        assert_eq!((mode(&f), mode(&g)), (0o600, 0o600));
        assert!(remettre_les(&[(f.clone(), 0o600, 0o644), (g.clone(), 0o600, 0o644)]).is_ok());
        assert_eq!((mode(&f), mode(&g)), (0o644, 0o644));
        let _ = std::fs::remove_dir_all(&d);
    }
}
