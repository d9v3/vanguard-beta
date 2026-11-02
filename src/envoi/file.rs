//! La file des lots et l'état de l'envoi, dans le dossier local. Ni l'une ni l'autre n'est scellée : chaque lot est
//! relu par la lecture stricte du schéma 2 avant de partir (un lot forgé ne peut porter que ce que le schéma permet,
//! ce qu'un programme du compte pourrait envoyer lui-même), et l'état ne fait que borner les essais (une valeur
//! forgée est ramenée dans ses bornes, au pire un jour d'attente de plus ou de moins).

use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::compte_rendu::champs::{Jour, Version};
use crate::compte_rendu::envoi::{self, IdInstallation, LOT_MAX, Lot};

/// Les lots en file, un fichier par jour (« envoi/file/2026-11-01.json »).
pub(crate) const FILE: &str = "envoi/file";
/// Les dates de l'envoi, ses essais du jour et l'identifiant d'installation (2 Kio au plus).
pub(crate) const ETAT: &str = "envoi/etat.json";

/// L'état tient en moins de 2 Kio : au-delà, il n'est pas de nous, et il repart de zéro.
pub(crate) const ETAT_MAX: u64 = 2048;

/// Pourquoi le dernier envoi n'a pas abouti : une liste fermée, jamais le texte d'une erreur (il porterait l'adresse).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Raison {
    /// Le relais a refusé le lot (400, 413, 415, 422…) : le lot est jeté.
    Refuse,
    /// 429 : le relais limite ; rien avant 24 h.
    Limite,
    /// 503 : le relais ne peut pas garder le lot ; rien avant 24 h.
    Indisponible,
    /// Un autre code (redirection, erreur du relais) : le lot attend.
    Autre,
    /// Pas de réponse dans les délais (hors ligne, serveur muet, coupure) : le lot attend.
    SansReponse,
    /// Un lot de la file qui ne se relit pas (abîmé, forgé, d'un autre jour) : jeté sans partir.
    Illisible,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Echec {
    pub(crate) jour: Jour,
    pub(crate) raison: Raison,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<u16>,
}

/// Les essais d'un jour (UTC).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Essais {
    pub(crate) jour: Jour,
    pub(crate) n: u32,
}

/// L'identifiant d'installation (P1) et le jour où il a été tiré.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Installation {
    pub(crate) id: IdInstallation,
    pub(crate) depuis: Jour,
}

/// La version qui a envoyé en dernier, et celle d'avant quand elle a changé (`version_avant` des 7 jours suivants).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuiviVersion {
    pub(crate) version: Version,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) avant: Option<Version>,
    pub(crate) depuis: Jour,
}

/// `envoi/etat.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Etat {
    /// Le premier jour vu : l'ancienneté du lot, en quatre classes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) premier_jour: Option<Jour>,
    /// Le dernier jour mis en file (ou passé faute de relevé) : un jour envoyé ne se refait pas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dernier_mis: Option<Jour>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dernier_succes: Option<Jour>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dernier_echec: Option<Echec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) essais: Option<Essais>,
    /// Rien avant cet instant (secondes depuis 1970) : après un 429 ou un 503.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) attendre_jusqu_a: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) installation: Option<Installation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<SuiviVersion>,
}

/// Le jour d'un `Jour`, toujours lisible (le motif l'assure).
pub(crate) fn date(j: &Jour) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(j.as_str(), "%Y-%m-%d").ok()
}

pub(crate) fn jour(d: NaiveDate) -> Jour {
    Jour::new(&d.format("%Y-%m-%d").to_string()).unwrap_or_else(Jour::aujourdhui)
}

/// `envoi/` et `envoi/file/` sont-ils de vrais dossiers (ou absents) ? Un lien posé à leur place enverrait les
/// écritures et les effacements ailleurs que dans le dossier de Vanguard.
pub(crate) fn dossiers_surs(dossier: &Path) -> bool {
    let envoi = dossier.join("envoi");
    [envoi.clone(), dossier.join(FILE)]
        .iter()
        .all(|d| match std::fs::symlink_metadata(d) {
            Ok(m) => m.file_type().is_dir(),
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        })
}

/// L'état, ou un état vide s'il manque, déborde ou ne se lit pas exactement.
pub(crate) fn lire_etat(dossier: &Path) -> Etat {
    crate::socle::lire_ordinaire(&dossier.join(ETAT), ETAT_MAX)
        .ok()
        .and_then(|o| serde_json::from_slice(&o).ok())
        .unwrap_or_default()
}

pub(crate) fn ecrire_etat(dossier: &Path, etat: &Etat) -> std::io::Result<()> {
    if !dossiers_surs(dossier) {
        return Err(std::io::Error::other("envoi/ n'est pas un dossier"));
    }
    let octets = serde_json::to_vec(etat).map_err(std::io::Error::other)?;
    if octets.len() as u64 > ETAT_MAX {
        return Err(std::io::Error::other("état de plus de 2 Kio"));
    }
    crate::socle::ecrire_atomique(&dossier.join(ETAT), octets)
}

/// Le fichier du lot du jour `d`.
pub(crate) fn chemin(dossier: &Path, d: NaiveDate) -> PathBuf {
    dossier.join(FILE).join(format!("{}.json", d.format("%Y-%m-%d")))
}

/// Le jour d'un nom de la file (« 2026-11-01.json »), s'il en est un.
pub(crate) fn jour_du_nom(nom: &str) -> Option<NaiveDate> {
    let j = Jour::new(nom.strip_suffix(".json")?)?;
    date(&j)
}

/// Met le lot du jour `d` en file, relu d'abord comme il le sera avant de partir : un lot que la lecture stricte
/// refuserait ne s'écrit pas.
pub(crate) fn mettre(dossier: &Path, d: NaiveDate, mut lot: Lot) -> std::io::Result<()> {
    if !dossiers_surs(dossier) {
        return Err(std::io::Error::other("envoi/ n'est pas un dossier"));
    }
    lot.tronquer();
    let octets = lot.ecrire();
    if envoi::lire(&octets).ok().as_ref() != Some(&lot) {
        return Err(std::io::Error::other("lot hors du schéma"));
    }
    crate::socle::ecrire_atomique(&chemin(dossier, d), octets)
}

/// Les jours en file, du plus vieux au plus récent.
pub(crate) fn jours_en_file(dossier: &Path) -> Vec<NaiveDate> {
    let Ok(lus) = std::fs::read_dir(dossier.join(FILE)) else {
        return Vec::new();
    };
    let mut v: Vec<NaiveDate> = lus
        .filter_map(Result::ok)
        .filter_map(|e| jour_du_nom(&e.file_name().to_string_lossy()))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Retire de la file tout ce qui n'est pas le lot d'un jour de `garde` (les jours trop vieux, ceux d'un futur que
/// l'horloge ne connaît pas encore, les restes d'une écriture coupée, ce qu'un autre y a posé) : la file ne garde
/// jamais plus de jours que la fenêtre. Les sous-dossiers restent, ils ne sont pas lus.
pub(crate) fn purger(dossier: &Path, garde: impl Fn(NaiveDate) -> bool) {
    if !dossiers_surs(dossier) {
        return;
    }
    let Ok(lus) = std::fs::read_dir(dossier.join(FILE)) else {
        return;
    };
    for e in lus.filter_map(Result::ok) {
        let dossier = e.file_type().is_ok_and(|t| t.is_dir());
        let gardee = jour_du_nom(&e.file_name().to_string_lossy()).is_some_and(&garde);
        if !dossier && !gardee {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Le lot en file du jour `d`, relu strictement. `Err(())` : il est là mais ne vaut rien (trop gros, pas un simple
/// fichier, hors du schéma, d'un autre jour) et doit être jeté ; `Ok(None)` : il n'est pas là.
pub(crate) fn relire(dossier: &Path, d: NaiveDate) -> Result<Option<Lot>, ()> {
    let octets = match crate::socle::lire_ordinaire(&chemin(dossier, d), LOT_MAX as u64) {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let lot = envoi::lire(&octets).map_err(|_| ())?;
    if date(&lot.jour) == Some(d) {
        Ok(Some(lot))
    } else {
        Err(())
    }
}

/// Retire le lot du jour `d` (un lien posé à sa place est retiré lui-même, jamais suivi).
pub(crate) fn retirer(dossier: &Path, d: NaiveDate) {
    if dossiers_surs(dossier) {
        let _ = std::fs::remove_file(chemin(dossier, d));
    }
}

/// Vide la file et l'état (« Ne pas partager ») : l'identifiant d'installation part avec l'état. Les dossiers ne
/// sont retirés que vides.
pub(crate) fn vider(dossier: &Path) -> std::io::Result<()> {
    if !dossiers_surs(dossier) {
        return Err(std::io::Error::other("envoi/ n'est pas un dossier"));
    }
    purger(dossier, |_| false);
    let etat = std::fs::remove_file(dossier.join(ETAT));
    let _ = std::fs::remove_dir(dossier.join(FILE));
    let _ = std::fs::remove_dir(dossier.join("envoi"));
    match etat {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}
