//! « Surveiller de plus près » : un programme douteux qu'on ne veut ni bloquer ni taire est inscrit, avec son
//! empreinte, pour 7 jours dans une liste scellée (`sceau::SURVEILLES`). Le veilleur Linux la relit chaque minute et
//! alerte à chaque nouveau lancement de ce programme (le même chemin, ou le même fichier ailleurs : la même empreinte).
//! Une alerte seulement : rien n'est arrêté ni gelé. Windows : après le veilleur de Windows (W1), dit dans le menu.
//!
//! Les connexions et les fichiers écrits ne sont pas suivis ici : une connexion fermée ne dit pas son programme au
//! veilleur (le noyau ne le donne pas), et les dossiers piégés ne disent pas qui écrit.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

use crate::modele::Echec;
use crate::ui::*;

const OU: &str = "blocage/surveiller";
/// Combien de jours un programme reste surveillé de plus près.
pub(crate) const JOURS: i64 = 7;
/// Au plus tant de programmes surveillés : le plus ancien part d'abord.
const SURVEILLES_MAX: usize = 64;
const FORMAT: &str = "%Y-%m-%d %H:%M";

/// Un programme surveillé de plus près.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Surveille {
    pub(crate) chemin: String,
    /// SHA-256 en hexadécimal, minuscules.
    pub(crate) empreinte: String,
    /// AAAA-MM-JJ HH:MM, heure locale : la surveillance s'arrête là.
    pub(crate) jusqu_a: String,
    /// Ce que la menace disait, pour l'alerte.
    pub(crate) quoi: String,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
struct Liste {
    #[serde(default)]
    surveilles: Vec<Surveille>,
}

/// L'empreinte en hexadécimal, minuscules.
pub(crate) fn hex(empreinte: &[u8; 32]) -> String {
    use std::fmt::Write;
    empreinte.iter().fold(String::with_capacity(64), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    })
}

/// La liste ; changée hors de Vanguard : la raison (et le veilleur n'alerte sur rien de cette liste-là).
fn charger() -> Result<Liste, &'static str> {
    use crate::sceau::Lecture;
    match crate::sceau::lire(crate::sceau::SURVEILLES) {
        Lecture::Absent | Lecture::Inconnu => Ok(Liste::default()),
        Lecture::Intact(o) => serde_json::from_slice(&o).map_err(|_| illisible()),
        Lecture::Adopte(_) | Lecture::Falsifie(_) => Err(tr!(
            "la liste des programmes surveillés de près a été changée hors de Vanguard",
            "the list of closely watched programs was changed outside Vanguard"
        )),
        Lecture::Illisible(_) => Err(illisible()),
    }
}

fn illisible() -> &'static str {
    tr!(
        "la liste des programmes surveillés de près ne se lit plus",
        "the list of closely watched programs can no longer be read"
    )
}

fn maintenant() -> NaiveDateTime {
    chrono::Local::now().naive_local()
}

/// Ce qui vaut encore à `quand` : une date illisible ne vaut pas.
fn en_vigueur(s: &Surveille, quand: NaiveDateTime) -> bool {
    NaiveDateTime::parse_from_str(&s.jusqu_a, FORMAT).is_ok_and(|fin| quand < fin)
}

/// La liste à jour : ce qui a expiré part, le même programme (même chemin et même empreinte) est remplacé, et au-delà
/// du maximum le plus ancien part.
fn inscrire(mut l: Vec<Surveille>, s: Surveille, quand: NaiveDateTime) -> Vec<Surveille> {
    l.retain(|x| en_vigueur(x, quand) && !(x.chemin == s.chemin && x.empreinte == s.empreinte));
    l.push(s);
    let trop = l.len().saturating_sub(SURVEILLES_MAX);
    l.drain(..trop);
    l
}

/// Le programme surveillé que ce lancement désigne : le même chemin, ou la même empreinte (le fichier copié ou
/// renommé). Une alerte de trop vaut mieux qu'une de moins : rien n'est arrêté sur ce critère.
#[cfg(any(target_os = "linux", test))]
fn designe<'a>(
    l: &'a [Surveille],
    chemin: Option<&str>,
    empreinte: Option<&str>,
    quand: NaiveDateTime,
) -> Option<&'a Surveille> {
    l.iter().filter(|s| en_vigueur(s, quand)).find(|s| {
        chemin.is_some_and(|c| c == s.chemin) || empreinte.is_some_and(|e| e.eq_ignore_ascii_case(&s.empreinte))
    })
}

/// Inscrit le programme pour 7 jours ; rend la date de fin (à dire). `Err` : rien n'est inscrit, et pourquoi.
pub(crate) fn ajouter(chemin: &str, empreinte: &[u8; 32], quoi: &str) -> Result<String, Echec> {
    let l = charger().map_err(|r| Echec::refuse(OU, r))?;
    let quand = maintenant();
    let fin = quand
        .checked_add_signed(chrono::Duration::days(JOURS))
        .ok_or_else(|| Echec::refuse(OU, tr!("date hors limites", "date out of range")))?
        .format(FORMAT)
        .to_string();
    let s = Surveille {
        chemin: chemin.to_string(),
        empreinte: hex(empreinte),
        jusqu_a: fin.clone(),
        quoi: quoi.to_string(),
    };
    let surveilles = inscrire(l.surveilles, s, quand);
    let texte = serde_json::to_string_pretty(&Liste { surveilles })
        .map_err(|e| Echec::ecriture(OU, &std::io::Error::other(e)))?;
    crate::sceau::ecrire(crate::sceau::SURVEILLES, texte).map_err(|e| Echec::ecriture(OU, &e))?;
    let ev = crate::modele::evenement::Evenement::action(
        crate::modele::evenement::Source::Utilisateur,
        &trf!(
            "Surveillance rapprochée de « {} » jusqu'au {fin}",
            "Close watch on “{}” until {fin}",
            affichable(chemin)
        ),
        true,
        &[],
    );
    crate::modele::journal::noter(ev);
    Ok(fin)
}

/// Les programmes surveillés en ce moment (rien si la liste a été changée hors de Vanguard ou ne se lit plus).
pub(crate) fn en_cours() -> Vec<Surveille> {
    let quand = maintenant();
    charger()
        .map(|l| l.surveilles.into_iter().filter(|s| en_vigueur(s, quand)).collect())
        .unwrap_or_default()
}

/// Pour le veilleur : la liste relue au plus une fois par minute.
#[cfg(target_os = "linux")]
pub(crate) fn designe_par(chemin: Option<&str>, empreinte: Option<&[u8; 32]>) -> Option<Surveille> {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static RELUE: Mutex<Option<(Instant, Vec<Surveille>)>> = Mutex::new(None);
    let mut garde = RELUE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let fraiche = garde
        .as_ref()
        .is_some_and(|(t, _)| t.elapsed() < Duration::from_mins(1));
    if !fraiche {
        *garde = Some((Instant::now(), en_cours()));
    }
    let l = garde.as_ref().map(|(_, l)| l.as_slice()).unwrap_or_default();
    let empreinte = empreinte.map(hex);
    designe(l, chemin, empreinte.as_deref(), maintenant()).cloned()
}

/// La clé, le titre et le texte de l'alerte d'un lancement surveillé.
#[cfg(target_os = "linux")]
pub(crate) fn alerte(s: &Surveille, pid: u32, chemin: &str) -> (String, &'static str, String) {
    (
        format!("rapprochee|{}|{pid}", s.empreinte),
        tr!(
            "Vanguard : programme surveillé de près lancé",
            "Vanguard: closely watched program started"
        ),
        trf!(
            "« {} » (PID {pid}) vient de se lancer. Vous avez demandé à le surveiller de près jusqu'au {} ({}). Rien n'est arrêté : ouvrez Vanguard (Bloquer) pour le suspendre ou le bloquer.",
            "“{}” (PID {pid}) has just started. You asked to watch it closely until {} ({}). Nothing is stopped: open Vanguard (Block) to suspend or block it.",
            affichable(chemin),
            s.jusqu_a,
            affichable(&s.quoi)
        ),
    )
}

/// Au bilan : ce qui est surveillé de près, et jusqu'à quand.
pub(crate) fn rappeler() {
    let l = en_cours();
    if l.is_empty() {
        return;
    }
    crate::ui::section(tr!("SURVEILLÉS DE PRÈS", "CLOSELY WATCHED"));
    for s in &l {
        afficher_aligne(
            &format!("  {GRIS}◉{RESET} "),
            &trf!(
                "{} : alerte à chaque lancement, jusqu'au {}.",
                "{}: an alert at each start, until {}.",
                affichable(&s.chemin),
                s.jusqu_a
            ),
            4,
            "",
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
mod tests {
    use super::*;

    fn le(t: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(t, FORMAT).unwrap()
    }

    fn s(chemin: &str, empreinte: &str, fin: &str) -> Surveille {
        Surveille {
            chemin: chemin.into(),
            empreinte: empreinte.into(),
            jusqu_a: fin.into(),
            quoi: "q".into(),
        }
    }

    #[test]
    fn empreinte_en_hexadecimal() {
        let mut e = [0u8; 32];
        e[0] = 0xab;
        e[31] = 0x01;
        let h = hex(&e);
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("ab00"));
        assert!(h.ends_with("01"));
    }

    /// Le même chemin ou la même empreinte désigne ; rien d'expiré, ni de date illisible, ne désigne.
    #[test]
    fn un_lancement_designe_le_programme_surveille() {
        let quand = le("2026-11-07 12:00");
        let l = vec![
            s("/home/a/x", "aa", "2026-11-10 12:00"),
            s("/home/a/vieux", "bb", "2026-11-07 11:59"),
            s("/home/a/forge", "cc", "demain"),
        ];
        assert!(designe(&l, Some("/home/a/x"), None, quand).is_some());
        assert!(designe(&l, Some("/tmp/copie"), Some("AA"), quand).is_some());
        assert!(designe(&l, Some("/home/a/vieux"), Some("bb"), quand).is_none());
        assert!(designe(&l, Some("/home/a/forge"), Some("cc"), quand).is_none());
        assert!(designe(&l, Some("/home/a/autre"), Some("dd"), quand).is_none());
        assert!(designe(&l, None, None, quand).is_none());
    }

    /// Inscrire : l'expiré part, le même programme est remplacé (sa date repart), le maximum tient.
    #[test]
    fn inscrire_remplace_et_borne() {
        let quand = le("2026-11-07 12:00");
        let l = vec![
            s("/home/a/x", "aa", "2026-11-08 12:00"),
            s("/home/a/vieux", "bb", "2026-11-01 12:00"),
        ];
        let l = inscrire(l, s("/home/a/x", "aa", "2026-11-14 12:00"), quand);
        assert_eq!(l, vec![s("/home/a/x", "aa", "2026-11-14 12:00")]);
        let mut l = Vec::new();
        for i in 0..SURVEILLES_MAX + 5 {
            l = inscrire(l, s(&format!("/p/{i}"), "e", "2026-11-14 12:00"), quand);
        }
        assert_eq!(l.len(), SURVEILLES_MAX);
        assert_eq!(l[0].chemin, "/p/5");
    }
}
