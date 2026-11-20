//! Le carnet des aperçus : ce que `--voir` a montré, pour que le geste qui change ne passe qu'après lui.
//!
//! Chaque aperçu d'un geste qui pourra changer quelque chose (une correction du compte, annulable) y note une entrée :
//! la sorte du geste qui suivra, le jeton, l'accord et l'heure. Le geste qui change (`--appliquer`, `--annuler`) exige
//! son entrée exacte, âgée de 2 s au moins (le temps de lire, contre le clic piégé) et de 10 min au plus (contre le
//! rejeu d'une vieille demande), et la **consomme** avant de rien changer : un double clic, ou la même demande
//! rejouée, ne trouve plus rien. C'est ce qui tient « montré puis accepté » sous Windows aussi, où aucun relais ne
//! s'interpose entre la fenêtre et `vanguard`.
//!
//! Le carnet n'est pas une preuve qu'une personne a vu l'aperçu : un programme du compte peut lancer `--voir` puis
//! `--appliquer` lui-même (il n'y gagne qu'un durcissement qu'il pouvait faire à la main, noté et annulable ; modèle
//! de menace, 4.2). Il est scellé (`sceau::APERCUS`) : changé hors de Vanguard, aucun geste ne passe, et le prochain
//! aperçu repart d'un carnet neuf, et le dit : « carnet des aperçus altéré : remplacé » au `--voir` même, puis au
//! journal des événements (alerte « carnet-altere ») au premier geste qui l'écrit (`--appliquer` ou `--annuler` :
//! sous la lecture seule de l'aperçu, le journal ne s'écrit pas). Huit entrées au plus : les plus vieilles partent.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::tr;

/// Les entrées gardées au plus : une fenêtre n'en a qu'une ou deux en cours.
const PLACES: usize = 8;
/// L'âge minimal d'une entrée consommée : « Accepter » n'est actif qu'après 2 s dans la fenêtre, et le relais refuse
/// avant ; ici, la même borne vaut pour tout lanceur.
pub(crate) const AGE_MIN_MS: i64 = 2_000;
/// L'âge maximal : au-delà, l'aperçu est trop vieux pour dire l'état d'aujourd'hui, il faut le refaire.
pub(crate) const AGE_MAX_MS: i64 = 600_000;
/// Le verrou du carnet, tenu de sa lecture à son écriture.
const VERROU: &str = "apercus.lock";
/// Les essais du verrou, 20 ms d'écart : l'aperçu ne l'attend jamais longtemps (un autre `--voir` l'écrit).
const ESSAIS_VERROU: u32 = 25;

/// Une entrée : ce qui a été montré, et quand.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entree {
    sorte: String,
    jeton: String,
    accord: String,
    /// Millisecondes depuis 1970, heure du système (que seul l'administrateur peut changer).
    heure_ms: i64,
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
struct Carnet {
    entrees: Vec<Entree>,
    /// Le carnet d'avant était altéré (changé hors de Vanguard, illisible) et celui-ci l'a remplacé à cette heure :
    /// pas encore dit au journal (`altere_a_dire`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    altere_ms: Option<i64>,
}

/// Ce qu'a donné la note d'un aperçu.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Notee {
    /// L'entrée est notée.
    Oui,
    /// Notée dans un carnet neuf : celui d'avant était altéré, et il est remplacé. À dire.
    Remplace,
    /// Pas notée : le geste qui suivrait sera refusé (« aucun aperçu »), rien d'autre.
    Non,
}

/// Ce qui se dit quand un carnet altéré est remplacé.
pub(crate) fn dit_remplace() -> &'static str {
    tr!(
        "carnet des aperçus altéré : remplacé (changé hors de Vanguard, ou illisible ; les aperçus d'avant ne valent plus)",
        "preview log tampered with: replaced (changed outside Vanguard, or unreadable; earlier previews no longer count)"
    )
}

/// Pourquoi le carnet refuse le geste.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Refus {
    /// Aucun aperçu de cet état exact : jamais montré, déjà consommé, ou montré autrement.
    Absent,
    /// Montré il y a moins de 2 s : rien n'est consommé, la demande peut revenir.
    TropJeune,
    /// Montré il y a plus de 10 min.
    TropVieux,
    /// Le carnet a été changé hors de Vanguard, ne se lit pas, ou une heure y est dans le futur.
    Douteux,
    /// Le carnet n'a pas pu être pris ou réécrit : l'entrée n'est pas consommée, donc rien ne change.
    NonEcrit,
}

impl Refus {
    /// Le mot du refus au journal des événements : fixe, sans rien de ce que le compte nomme.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Refus::Absent => "apercu-absent",
            Refus::TropJeune => "apercu-trop-jeune",
            Refus::TropVieux => "apercu-trop-vieux",
            Refus::Douteux => "carnet-douteux",
            Refus::NonEcrit => "carnet-non-ecrit",
        }
    }

    pub(crate) fn raison(self) -> String {
        match self {
            Refus::Absent => tr!(
                "aucun aperçu de cet état n'a été montré (ou il a déjà servi) : refaites l'aperçu",
                "no preview of this state was shown (or it was already used): show the preview again"
            ),
            Refus::TropJeune => tr!(
                "accepté moins de 2 secondes après l'aperçu : prenez le temps de le lire",
                "accepted less than 2 seconds after the preview: take the time to read it"
            ),
            Refus::TropVieux => tr!(
                "l'aperçu a plus de 10 minutes : refaites-le",
                "the preview is more than 10 minutes old: show it again"
            ),
            Refus::Douteux => tr!(
                "le carnet des aperçus a été changé hors de Vanguard : refaites l'aperçu",
                "the preview log was changed outside Vanguard: show the preview again"
            ),
            Refus::NonEcrit => tr!(
                "le carnet des aperçus n'a pas pu être mis à jour : rien n'a été fait",
                "the preview log could not be updated: nothing was done"
            ),
        }
        .to_string()
    }
}

/// L'heure, en millisecondes depuis 1970.
pub(crate) fn maintenant_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Le verrou du carnet, pris en quelques essais sans jamais attendre longtemps.
fn prendre(dossier: &Path) -> Option<crate::socle::Verrou> {
    for _ in 0..ESSAIS_VERROU {
        match crate::socle::Verrou::prendre(dossier, VERROU, false, std::time::Duration::ZERO) {
            Ok(v) => return Some(v),
            Err(crate::socle::SansVerrou::Occupe) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
    None
}

/// Le carnet de `dossier`, d'après son sceau. `None` : il ne vaut rien (falsifié, adopté, illisible, mal formé).
fn lire(dossier: &Path) -> Option<Carnet> {
    use crate::sceau::Lecture;
    match crate::sceau::lire_dans(dossier, crate::sceau::APERCUS) {
        Lecture::Absent | Lecture::Inconnu => Some(Carnet::default()),
        Lecture::Intact(o) => serde_json::from_slice(&o).ok(),
        Lecture::Adopte(_) | Lecture::Falsifie(_) | Lecture::Illisible(_) => None,
    }
}

fn ecrire(dossier: &Path, c: &Carnet) -> bool {
    serde_json::to_vec(c).is_ok_and(|o| crate::sceau::ecrire_dans(dossier, crate::sceau::APERCUS, &o).is_ok())
}

/// Note ce que l'aperçu vient de montrer. Sous la lecture seule de l'aperçu, seul ce fil écrit, et seulement le
/// carnet et ses sceaux (`lecture_seule::ecrire_carnet`).
pub(crate) fn noter(sorte: &str, jeton: &str, accord: &str) -> Notee {
    let dossier = crate::reseau::dossier_local();
    crate::autotest::lecture_seule::ecrire_carnet(|| {
        // Le dossier de données naît réservé au compte (0700), comme au chemin ordinaire.
        #[cfg(unix)]
        crate::socle::proteger_dossier_local();
        noter_dans(&dossier, sorte, jeton, accord, maintenant_ms())
    })
}

fn noter_dans(dossier: &Path, sorte: &str, jeton: &str, accord: &str, maintenant: i64) -> Notee {
    let Some(_verrou) = prendre(dossier) else {
        return Notee::Non;
    };
    // Un carnet changé hors de Vanguard ne refuse que les gestes qu'il porte : l'aperçu suivant repart d'un neuf
    // (le garder tel quel bloquerait tout geste jusqu'à ce qu'on l'efface à la main), jamais en silence.
    let (mut c, remplace) = match lire(dossier) {
        Some(c) => (c, false),
        None => (
            Carnet {
                altere_ms: Some(maintenant),
                ..Carnet::default()
            },
            true,
        ),
    };
    c.entrees.retain(|e| {
        let age = maintenant.saturating_sub(e.heure_ms);
        (0..=AGE_MAX_MS).contains(&age) && !(e.sorte == sorte && e.jeton == jeton)
    });
    c.entrees.push(Entree {
        sorte: sorte.to_string(),
        jeton: jeton.to_string(),
        accord: accord.to_string(),
        heure_ms: maintenant,
    });
    let trop = c.entrees.len().saturating_sub(PLACES);
    c.entrees.drain(..trop);
    match (ecrire(dossier, &c), remplace) {
        (false, _) => Notee::Non,
        (true, false) => Notee::Oui,
        (true, true) => Notee::Remplace,
    }
}

/// Au `--voir` : un carnet altéré remplacé se dit, jamais en silence (sur la sortie d'erreur en JSON, dont la
/// dernière ligne reste celle du geste).
pub(crate) fn dire_si_remplace(n: Notee, json: bool) {
    use std::io::Write;
    // Une sortie fermée ou pleine n'est pas un plantage (`apercu::ecrire_sortie`).
    if n == Notee::Remplace {
        let _ = if json {
            writeln!(std::io::stderr(), "{}", dit_remplace())
        } else {
            writeln!(std::io::stdout(), "  ⚠ {}", dit_remplace())
        };
    }
}

/// Le carnet altéré remplacé, au journal des événements : l'alerte typée « carnet-altere », écrite par le premier
/// geste qui écrit le journal après le `--voir` qui l'a remplacé.
pub(crate) fn noter_altere_au_journal() {
    if crate::autotest::lecture_seule::active() {
        return;
    }
    if let Some(heure) = altere_a_dire() {
        let quand = chrono::DateTime::from_timestamp_millis(heure)
            .map_or_default(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string());
        crate::modele::journal::noter(crate::modele::evenement::Evenement::alerte(
            crate::modele::evenement::Source::Vanguard,
            "carnet-altere",
            tr!("Carnet des aperçus altéré", "Preview log tampered with"),
            &format!("{} ({quand})", dit_remplace()),
        ));
    }
}

/// Un carnet altéré remplacé et pas encore dit au journal : son heure, retirée du carnet (rescellé) avant d'être
/// rendue, pour que le journal le dise une seule fois. `None` : rien à dire, ou le carnet ne s'est pas réécrit (il le
/// sera au geste suivant).
pub(crate) fn altere_a_dire() -> Option<i64> {
    altere_a_dire_dans(&crate::reseau::dossier_local())
}

fn altere_a_dire_dans(dossier: &Path) -> Option<i64> {
    let _verrou = prendre(dossier)?;
    let mut c = lire(dossier)?;
    let heure = c.altere_ms.take()?;
    ecrire(dossier, &c).then_some(heure)
}

/// Consomme l'entrée exacte (sorte, jeton, accord), âgée de 2 s à 10 min : retirée et le carnet rescellé AVANT que
/// l'appelant ne change quoi que ce soit. Une entrée trop jeune reste (la demande peut revenir) ; trop vieille ou
/// dans le futur, elle part, rien n'est fait.
pub(crate) fn consommer(sorte: &str, jeton: &str, accord: &str) -> Result<(), Refus> {
    consommer_dans(&crate::reseau::dossier_local(), sorte, jeton, accord, maintenant_ms())
}

fn consommer_dans(dossier: &Path, sorte: &str, jeton: &str, accord: &str, maintenant: i64) -> Result<(), Refus> {
    let _verrou = prendre(dossier).ok_or(Refus::NonEcrit)?;
    let mut c = lire(dossier).ok_or(Refus::Douteux)?;
    let (i, heure_ms) = c
        .entrees
        .iter()
        .enumerate()
        .find(|(_, e)| e.sorte == sorte && e.jeton == jeton && e.accord == accord)
        .map(|(i, e)| (i, e.heure_ms))
        .ok_or(Refus::Absent)?;
    let age = maintenant.saturating_sub(heure_ms);
    if (0..AGE_MIN_MS).contains(&age) {
        return Err(Refus::TropJeune);
    }
    let refus = if age < 0 {
        Some(Refus::Douteux)
    } else if age > AGE_MAX_MS {
        Some(Refus::TropVieux)
    } else {
        None
    };
    c.entrees.remove(i);
    match (ecrire(dossier, &c), refus) {
        (true, None) => Ok(()),
        (false, None) => Err(Refus::NonEcrit),
        (_, Some(r)) => Err(r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier(nom: &str) -> std::path::PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-carnet-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const J: &str = "0123456789abcdef0123456789abcdef";
    const A: &str = "aa";
    const T: i64 = 1_800_000_000_000;

    #[test]
    fn une_entree_se_consomme_une_fois_entre_2_s_et_10_min() {
        let d = dossier("une-fois");
        assert_eq!(consommer_dans(&d, "s", J, A, T), Err(Refus::Absent));
        assert_eq!(noter_dans(&d, "s", J, A, T), Notee::Oui);
        // Trop jeune : refusée, gardée.
        assert_eq!(consommer_dans(&d, "s", J, A, T + 1_999), Err(Refus::TropJeune));
        // Un autre accord, une autre sorte : absents.
        assert_eq!(consommer_dans(&d, "s", J, "bb", T + 2_000), Err(Refus::Absent));
        assert_eq!(consommer_dans(&d, "t", J, A, T + 2_000), Err(Refus::Absent));
        assert_eq!(consommer_dans(&d, "s", J, A, T + 2_000), Ok(()));
        // Rejouée : plus rien.
        assert_eq!(consommer_dans(&d, "s", J, A, T + 3_000), Err(Refus::Absent));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn trop_vieille_ou_dans_le_futur_elle_part_sans_rien_permettre() {
        let d = dossier("vieille");
        assert_eq!(noter_dans(&d, "s", J, A, T), Notee::Oui);
        assert_eq!(consommer_dans(&d, "s", J, A, T + AGE_MAX_MS + 1), Err(Refus::TropVieux));
        assert_eq!(consommer_dans(&d, "s", J, A, T + 3_000), Err(Refus::Absent));
        assert_eq!(noter_dans(&d, "s", J, A, T + 10_000), Notee::Oui);
        assert_eq!(consommer_dans(&d, "s", J, A, T), Err(Refus::Douteux));
        assert_eq!(consommer_dans(&d, "s", J, A, T + 20_000), Err(Refus::Absent));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn un_nouvel_apercu_remplace_l_ancien_et_le_carnet_reste_petit() {
        let d = dossier("remplace");
        assert_eq!(noter_dans(&d, "s", J, A, T), Notee::Oui);
        assert_eq!(noter_dans(&d, "s", J, "bb", T + 1), Notee::Oui);
        // L'état montré en dernier seul compte.
        assert_eq!(consommer_dans(&d, "s", J, A, T + 5_000), Err(Refus::Absent));
        for i in 0..20u8 {
            let j = format!("{i:032x}");
            assert_eq!(noter_dans(&d, "s", &j, A, T + i64::from(i)), Notee::Oui);
        }
        assert_eq!(lire(&d).unwrap().entrees.len(), PLACES);
        // Les plus vieilles sont parties, la plus récente reste.
        assert_eq!(
            consommer_dans(&d, "s", &format!("{:032x}", 0), A, T + 5_000),
            Err(Refus::Absent)
        );
        assert_eq!(consommer_dans(&d, "s", &format!("{:032x}", 19), A, T + 5_000), Ok(()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn un_carnet_falsifie_ne_permet_rien() {
        let d = dossier("falsifie");
        assert_eq!(noter_dans(&d, "s", J, A, T), Notee::Oui);
        // Réécrit hors de Vanguard, avec une entrée « montrée » qu'il n'a jamais vue.
        let forge = serde_json::json!({"entrees":[{"sorte":"s","jeton":J,"accord":"cc","heure_ms":T}]});
        std::fs::write(d.join(crate::sceau::APERCUS), forge.to_string()).unwrap();
        assert_eq!(consommer_dans(&d, "s", J, "cc", T + 5_000), Err(Refus::Douteux));
        assert_eq!(consommer_dans(&d, "s", J, A, T + 5_000), Err(Refus::Douteux));
        // Le prochain aperçu repart d'un carnet neuf, et le dit : seule son entrée vaut.
        assert_eq!(noter_dans(&d, "s", J, A, T + 6_000), Notee::Remplace);
        assert_eq!(noter_dans(&d, "s", J, A, T + 7_000), Notee::Oui);
        assert_eq!(consommer_dans(&d, "s", J, A, T + 9_000), Ok(()));
        // Le remplacement reste à dire au journal, une seule fois, même après un geste qui a consommé une entrée.
        assert_eq!(altere_a_dire_dans(&d), Some(T + 6_000));
        assert_eq!(altere_a_dire_dans(&d), None);
        assert_eq!(noter_dans(&d, "s", J, A, T + 10_000), Notee::Oui);
        assert_eq!(altere_a_dire_dans(&d), None);
        let _ = std::fs::remove_dir_all(&d);
    }
}
