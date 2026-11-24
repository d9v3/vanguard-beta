//! Les images de secours de la clé, jugées à la taille : ce que leurs relectures octet par octet ont trouvé, dit avec
//! ce qui n'a pas été vu. Une image illisible est « à vérifier », jamais saine ni « changée » ; une recopie pas finie
//! (clé débranchée en route) est notée avant que l'image ne soit retirée, et reprend seule ; deux images aux octets
//! changés, ou deux recopies ratées, disent la clé « à remplacer » : plus rien n'y est recopié de soi-même, pour ne pas
//! achever une clé qui meurt ni faire d'une alerte de piège un bruit de chaque jour. Le compte est dans la référence
//! scellée, sur l'ordinateur de l'auteur, et ne repart que par son geste (outils/deployer.sh --accepter-cle).

use std::path::Path;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use super::{Entree, Manifeste, enregistrer, lire, maintenant};
use crate::machine::{Constat, alerte, impossible, ok};
use crate::modele::Echec;
use crate::risk::Niveau;
use crate::{tr, trf};

/// Images aux octets changés, ou recopies ratées, à partir desquelles la clé est dite à remplacer.
const USEE: usize = 2;
/// Les incidents gardés : le compte n'a besoin que des derniers.
const INCIDENTS_MAX: usize = 50;

/// Ce qui est arrivé à une image de la clé.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Sorte {
    /// Relue, elle avait d'autres octets que l'image vérifiée.
    Differente,
    /// Recopiée, sa relecture n'a pas retrouvé l'image vérifiée (clé toujours branchée).
    Recopie,
}

/// Un incident d'une image.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Incident {
    date: String,
    chemin: String,
    sorte: Sorte,
}

/// Ce qui est su des images de la clé jugées à la taille.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Etat {
    /// Les images jugées à la taille seule.
    total: usize,
    /// Celles qu'aucune relecture n'a encore retrouvées octet pour octet.
    jamais: usize,
    /// Parmi elles, celles qui n'ont pas d'empreinte à retrouver : rien ne peut les relire.
    sans_empreinte: usize,
    /// L'âge, en jours, de la plus ancienne des dernières relectures.
    plus_ancienne: Option<i64>,
    /// Les images qui ne se sont pas lues à leur dernière relecture.
    illisibles: Vec<String>,
    /// Les fichiers retirés pour être recopiés, dont la recopie n'est pas finie.
    pub(super) recopies: Vec<String>,
    differentes: usize,
    ratees: usize,
}

impl Etat {
    /// La clé est à remplacer.
    fn usee(&self) -> bool {
        self.differentes >= USEE || self.ratees >= USEE
    }

    /// Une phrase par chose à dire ; aucune quand la clé n'a pas d'image jugée à la taille.
    pub(crate) fn lignes(&self) -> Vec<String> {
        let mut lignes = Vec::new();
        if self.total > 0 {
            let sans = if self.sans_empreinte > 0 {
                trf!(
                    " (dont {} sans empreinte connue, que rien ne peut relire)",
                    " ({} of them without a known checksum, which nothing can re-read)",
                    self.sans_empreinte
                )
            } else {
                String::new()
            };
            lignes.push(match self.plus_ancienne {
                Some(jours) => trf!(
                    "{} image(s) jugée(s) à la taille ; relues octet par octet : la plus ancienne il y a {jours} jour(s), {} jamais{sans}.",
                    "{} image(s) judged by size; re-read byte by byte: the oldest {jours} day(s) ago, {} never{sans}.",
                    self.total,
                    self.jamais
                ),
                None => trf!(
                    "{} image(s) jugée(s) à la taille ; aucune encore relue octet par octet{sans}.",
                    "{} image(s) judged by size; none re-read byte by byte yet{sans}.",
                    self.total
                ),
            });
        }
        if !self.illisibles.is_empty() {
            lignes.push(trf!(
                "À vérifier, image illisible à sa dernière relecture : {}.",
                "To check, image unreadable when last re-read: {}.",
                noms(&self.illisibles)
            ));
        }
        if !self.recopies.is_empty() {
            lignes.push(trf!(
                "Recopie pas finie, l'image manque sur la clé : {} (elle reprend seule, clé branchée chez vous).",
                "Copy not finished, the image is missing from the key: {} (it resumes by itself, key plugged in at home).",
                noms(&self.recopies)
            ));
        }
        if self.usee() {
            lignes.push(trf!(
                "Clé à remplacer : {} image(s) aux octets changés, {} recopie(s) ratée(s) ; plus rien n'y est recopié de soi-même.",
                "Key to replace: {} image(s) with changed bytes, {} failed copy(ies); nothing is copied to it by itself any more.",
                self.differentes,
                self.ratees
            ));
        }
        lignes
    }

    /// Le constat d'une clé que rien ne dit changée (`debut`) : ce qui n'a pas été vu des images ne passe pas pour sain.
    pub(super) fn constat(&self, cat: &'static str, debut: String) -> Constat {
        let suite = self.lignes().join(" ");
        let message = if suite.is_empty() {
            debut
        } else {
            format!("{debut} {suite}")
        };
        if self.usee() {
            alerte(cat, Niveau::Moyen, message).manuel(
                tr!(
                    "Refaites la clé de secours sur une autre clé USB ; si celle-ci a voyagé, des octets changés peuvent aussi être un piège. Pour continuer avec elle, une fois regardée : outils/deployer.sh --accepter-cle",
                    "Rebuild the rescue key on another USB key; if this one has traveled, changed bytes may also be a trap. To go on with it once looked at: outils/deployer.sh --accepter-cle"
                ),
                &[],
            )
        } else if self.illisibles.is_empty() && self.recopies.is_empty() {
            ok(cat, message)
        } else {
            impossible(cat, &message)
        }
    }
}

/// Les noms, sans « ISO/ », en une liste courte.
fn noms(chemins: &[String]) -> String {
    let noms: Vec<String> = chemins
        .iter()
        .map(|c| crate::ui::affichable(c.strip_prefix("ISO/").unwrap_or(c)))
        .collect();
    crate::ui::resume(&noms, 5, ", ")
}

/// Une image jugée à la taille : dans ISO/, sans empreinte BLAKE3 (trop grosse pour le bilan).
fn a_la_taille(e: &Entree) -> bool {
    e.chemin.starts_with("ISO/") && e.blake3.is_none()
}

/// La dernière relecture tentée, réussie ou non : la rotation prend la plus ancienne (`None` d'abord).
pub(super) fn tentee(e: &Entree) -> Option<&str> {
    e.relue.as_deref().max(e.illisible.as_deref())
}

/// Le jour d'une date « AAAA-MM-JJ HH:MM ».
fn jour(date: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(date.get(..10)?, "%Y-%m-%d").ok()
}

/// Ce que la référence dit des images, au jour `aujourdhui`. Une date illisible ou à venir (horloge reculée) ne compte
/// pas comme une relecture.
pub(super) fn etat(m: &Manifeste, aujourdhui: NaiveDate) -> Etat {
    let mut etat = Etat::default();
    // Une référence d'avant les images ne les compare pas : rien à en dire.
    for e in m.fichiers.iter().filter(|e| m.images && a_la_taille(e)) {
        etat.total = etat.total.saturating_add(1);
        let age = e
            .relue
            .as_deref()
            .filter(|_| e.sha256.is_some() && !e.differente)
            .and_then(jour)
            .map(|j| aujourdhui.signed_duration_since(j).num_days())
            .filter(|j| *j >= 0);
        if let Some(j) = age {
            etat.plus_ancienne = etat.plus_ancienne.max(Some(j));
        } else {
            etat.jamais = etat.jamais.saturating_add(1);
            etat.sans_empreinte = etat.sans_empreinte.saturating_add(usize::from(e.sha256.is_none()));
        }
        if e.illisible.is_some() {
            etat.illisibles.push(e.chemin.clone());
        }
    }
    for i in &m.incidents {
        let compte = match i.sorte {
            Sorte::Differente => &mut etat.differentes,
            Sorte::Recopie => &mut etat.ratees,
        };
        *compte = compte.saturating_add(1);
    }
    etat
}

/// La clé de cette référence est à remplacer.
pub(super) fn usee(m: &Manifeste) -> bool {
    etat(m, chrono::Local::now().date_naive()).usee()
}

/// Note un incident de l'image `chemin`.
pub(super) fn noter_incident(m: &mut Manifeste, sorte: Sorte, chemin: &str) {
    m.incidents.push(Incident {
        date: maintenant(),
        chemin: chemin.to_string(),
        sorte,
    });
    let trop = m.incidents.len().saturating_sub(INCIDENTS_MAX);
    m.incidents.drain(..trop);
}

/// Ce qu'outils/images-cle.sh dit d'une recopie (`vanguard deploiement recopie-image`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Geste<'a> {
    /// Rien à noter : dire les recopies pas finies.
    Voir,
    /// `par` va être copiée, `noms` (elle comprise) peuvent être retirés avant.
    Debut { par: &'a str, noms: &'a [String] },
    /// La copie de `par` n'a pas été retrouvée sur la clé, toujours branchée.
    Ratee { par: &'a str },
}

/// Les fichiers d'ISO/ dont la recopie n'est pas finie (le fichier manque), chacun avec l'image qui le remplace, et si
/// la clé est à remplacer.
pub(crate) type Recopies = (Vec<(String, String)>, bool);

const CONTEXTE: &str = "manifeste/recopie";

/// Un nom de fichier d'ISO/, rien d'autre : un chemin ferait noter (donc admettre absent) un fichier d'ailleurs.
fn nom_permis(nom: &str) -> Result<(), Echec> {
    if nom.is_empty() || nom == "." || nom == ".." || nom.contains(['/', '\\']) {
        return Err(Echec::refuse(
            CONTEXTE,
            trf!("nom d'image refusé : {nom}", "image name refused: {nom}"),
        ));
    }
    Ok(())
}

pub(super) fn recopie_dans(racine: &Path, reference: &Path, geste: &Geste) -> Result<Recopies, Echec> {
    let mut m = lire(reference).map_err(|e| Echec::echoue(CONTEXTE, e))?;
    let change = match geste {
        Geste::Voir => false,
        Geste::Debut { par, noms } => {
            nom_permis(par)?;
            noms.iter().try_for_each(|n| nom_permis(n))?;
            for e in &mut m.fichiers {
                let voulu = e
                    .chemin
                    .strip_prefix("ISO/")
                    .is_some_and(|c| noms.iter().any(|n| n == c));
                if voulu {
                    e.recopie = Some((*par).to_string());
                }
            }
            true
        }
        Geste::Ratee { par } => {
            nom_permis(par)?;
            noter_incident(&mut m, Sorte::Recopie, &format!("ISO/{par}"));
            true
        }
    };
    if change {
        enregistrer(reference, &m).map_err(|e| Echec::ecriture(CONTEXTE, &e))?;
    }
    let en_attente = m
        .fichiers
        .iter()
        .filter(|e| !racine.join(&e.chemin).is_file())
        .filter_map(|e| Some((e.chemin.strip_prefix("ISO/")?.to_string(), e.recopie.clone()?)))
        .collect();
    Ok((en_attente, usee(&m)))
}

/// `recopie_dans` pour la clé `racine` et sa référence sur cet ordinateur.
pub(crate) fn recopie(racine: &Path, geste: &Geste) -> Result<Recopies, Echec> {
    let reference = super::reference(racine).ok_or_else(|| {
        Echec::refuse(
            CONTEXTE,
            tr!("aucune référence pour cette clé", "no reference for this key"),
        )
    })?;
    recopie_dans(racine, &reference, geste)
}

#[cfg(test)]
#[path = "images_essais.rs"]
mod essais;
