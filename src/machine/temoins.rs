//! Les témoins d'une alerte : ce qu'un choix « c'est normal chez moi » déclare normal, relevé au bilan qui l'a
//! montrée. Pour une ligne de lancement : le fichier qui la porte (son contenu entier, et s'il est un lien, vers où) et
//! les fichiers qu'elle lance ou précharge (leur contenu). Le choix retient l'empreinte de l'ensemble (`empreinte`) :
//! un fichier changé ou remplacé, devenu un lien, un programme lancé changé, une ligne ajoutée ou une autre source
//! dans la même alerte, et l'empreinte n'est plus la même — l'alerte revient.
//!
//! Ce qui ne se relève pas (fichier illisible, trop gros, tube nommé, commande ambiguë, trop de lignes) donne
//! `Temoins::Refuse` : l'alerte ne peut pas être déclarée normale, et la raison est dite.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Sous Windows, aucune règle ne relève encore de témoins (les tâches et les clés Run restent reconnues à leur clé) :
// seul `Aucun` y sert, le reste attend.
#![cfg_attr(windows, allow(dead_code))]

use crate::{tr, trf};

/// Pourquoi une ligne ne se relève pas pour un choix « normal » : une phrase prête à montrer. Ce n'est pas une panne
/// de Vanguard : rien n'est noté au journal des erreurs, l'alerte reste seulement à corriger soi-même.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refus(pub String);

impl std::fmt::Display for Refus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Au plus autant de lignes dans une alerte qu'on peut déclarer normale : chacune est montrée avant le choix.
pub(crate) const TEMOINS_MAX: usize = 12;
/// Une ligne montrée plus longue est coupée (« … ») : son empreinte, elle, porte la ligne entière.
const LIGNE_MONTREE: usize = 300;
/// Au-delà, un fichier lancé n'est pas lu en entier à chaque bilan : l'alerte ne peut pas être déclarée normale.
#[cfg(unix)]
const TAILLE_MAX: u64 = 256 * 1024 * 1024;

/// Ce qu'un choix « normal » déclarerait normal.
#[derive(Clone, Debug, Default)]
pub enum Temoins {
    /// La règle ne relève rien : un choix la reconnaît à sa clé (ou son texte), comme avant ces témoins.
    #[default]
    Aucun,
    /// Chaque ligne signalée, avec ce qu'elle désigne.
    Releves(Vec<Temoin>),
    /// Ne peut pas être déclarée normale : pourquoi (déjà traduit, prêt à montrer).
    Refuse(String),
}

/// Une ligne signalée, telle qu'elle sera montrée avant le choix, et son empreinte.
#[derive(Clone, Debug)]
pub struct Temoin {
    /// « ~/.config/systemd/user/x.service:6 », « crontab:3 », « LD_PRELOAD de cette session » (affichable).
    pub ou: String,
    /// La ligne (affichable, coupée).
    pub ligne: String,
    /// Le fichier qui la porte : « empreinte 1a2b… », « lien vers … ; empreinte … » ; `None` : pas un fichier.
    pub contenant: Option<String>,
    /// Les fichiers qu'elle lance ou précharge : (chemin affichable, état affichable).
    pub cibles: Vec<(String, String)>,
    empreinte: [u8; 32],
    /// La ligne ne se montre pas en entier (plus de `LIGNE_MONTREE` colonnes) : ce qui passe la coupure ne serait
    /// pas vu avant le choix.
    coupee: bool,
}

impl Temoins {
    /// L'empreinte de l'ensemble (64 chiffres hexadécimaux), indépendante de l'ordre de lecture ; `None` sans relevé.
    pub fn empreinte(&self) -> Option<String> {
        let Temoins::Releves(liste) = self else {
            return None;
        };
        let mut e: Vec<[u8; 32]> = liste.iter().map(|t| t.empreinte).collect();
        e.sort_unstable();
        e.dedup();
        let mut h = blake3::Hasher::new_derive_key("vanguard 2026-11 temoins d'une alerte v1");
        h.update(&u64::try_from(e.len()).unwrap_or(u64::MAX).to_le_bytes());
        for x in &e {
            h.update(x);
        }
        Some(h.finalize().to_hex().to_string())
    }

    /// Les lignes relevées, sans double (une ligne lue deux fois compte une fois).
    pub fn lignes(&self) -> Vec<&Temoin> {
        let Temoins::Releves(liste) = self else {
            return Vec::new();
        };
        let mut vus: Vec<[u8; 32]> = Vec::new();
        liste
            .iter()
            .filter(|t| {
                let neuf = !vus.contains(&t.empreinte);
                vus.push(t.empreinte);
                neuf
            })
            .collect()
    }

    /// Les témoins d'une alerte à partir de chaque ligne relevée : le premier refus l'emporte, et au-delà de
    /// `TEMOINS_MAX` lignes distinctes, l'alerte est trop chargée pour être montrée en entier avant le choix.
    pub(crate) fn de(releves: Vec<Result<Temoin, Refus>>) -> Temoins {
        let mut liste = Vec::with_capacity(releves.len());
        for r in releves {
            match r {
                Ok(t) if t.coupee => {
                    return Temoins::Refuse(trf!(
                        "la ligne {} est trop longue pour être montrée en entier avant un tel choix",
                        "line {} is too long to be shown in full before such a choice",
                        t.ou
                    ));
                }
                Ok(t) => liste.push(t),
                Err(raison) => return Temoins::Refuse(raison.to_string()),
            }
        }
        let t = Temoins::Releves(liste);
        let n = t.lignes().len();
        if n > TEMOINS_MAX {
            return Temoins::Refuse(trf!(
                "{n} lignes signalées, plus que les {TEMOINS_MAX} qui se montrent avant un tel choix",
                "{n} reported lines, more than the {TEMOINS_MAX} that can be shown before such a choice"
            ));
        }
        if n == 0 {
            return Temoins::Refuse(tr!("aucune ligne relevée", "no line recorded").to_string());
        }
        t
    }
}

/// L'état d'un fichier, tel qu'il entre dans une empreinte et se montre.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Etat {
    Absent,
    Fichier { empreinte: [u8; 32] },
    Lien { vers: String, puis: Box<Etat> },
}

impl Etat {
    fn ecrire(&self, h: &mut blake3::Hasher) {
        match self {
            Etat::Absent => {
                h.update(b"A");
            }
            Etat::Fichier { empreinte } => {
                h.update(b"F");
                h.update(empreinte);
            }
            Etat::Lien { vers, puis } => {
                h.update(b"L");
                champ(h, vers);
                puis.ecrire(h);
            }
        }
    }

    fn montre(&self) -> String {
        match self {
            Etat::Absent => tr!("absent", "missing").to_string(),
            Etat::Fichier { empreinte } => {
                let hex = blake3::Hash::from_bytes(*empreinte).to_hex();
                trf!("empreinte {}", "fingerprint {}", hex.get(..16).unwrap_or_default())
            }
            Etat::Lien { vers, puis } => trf!(
                "lien vers {} ; {}",
                "link to {}; {}",
                crate::ui::affichable(vers),
                puis.montre()
            ),
        }
    }
}

/// Un champ d'une empreinte, précédé de sa longueur : « ab » puis « c » ne s'écrit pas comme « a » puis « bc ».
fn champ(h: &mut blake3::Hasher, texte: &str) {
    h.update(&u64::try_from(texte.len()).unwrap_or(u64::MAX).to_le_bytes());
    h.update(texte.as_bytes());
}

/// L'empreinte d'un contenu de fichier (le texte tel que lu pour juger la ligne : rien ne change entre les deux).
pub(crate) fn empreinte_du_texte(texte: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("vanguard 2026-11 contenu d'un fichier v1");
    h.update(texte);
    *h.finalize().as_bytes()
}

/// Un témoin : `ou_brut` et `ligne_brute` tels que lus (l'empreinte les porte entiers), `ou` déjà affichable,
/// `contenant` l'état du fichier qui porte la ligne, `cibles` (chemin tel que lu, état) ce qu'elle désigne.
pub(crate) fn temoin(
    ou_brut: &str,
    ou: String,
    ligne_brute: &str,
    contenant: Option<&Etat>,
    cibles: &[(String, Etat)],
) -> Temoin {
    let mut h = blake3::Hasher::new_derive_key("vanguard 2026-11 temoin d'une ligne v1");
    champ(&mut h, ou_brut);
    champ(&mut h, ligne_brute.trim());
    match contenant {
        Some(e) => {
            h.update(b"C");
            e.ecrire(&mut h);
        }
        None => {
            h.update(b"-");
        }
    }
    h.update(&u64::try_from(cibles.len()).unwrap_or(u64::MAX).to_le_bytes());
    for (chemin, etat) in cibles {
        champ(&mut h, chemin);
        etat.ecrire(&mut h);
    }
    let entiere = crate::ui::affichable(ligne_brute.trim());
    Temoin {
        ou,
        coupee: crate::ui::largeur_affichee(&entiere) > LIGNE_MONTREE,
        ligne: crate::ui::couper(&entiere, LIGNE_MONTREE),
        contenant: contenant.map(Etat::montre),
        cibles: cibles
            .iter()
            .map(|(c, e)| (crate::ui::affichable(c), e.montre()))
            .collect(),
        empreinte: *h.finalize().as_bytes(),
    }
}

/// L'état du fichier `f` qui porte une ligne, dont `texte` est le contenu déjà lu : ce contenu, et s'il est un lien,
/// vers où il pointe (un fichier remplacé par un lien vers un autre au même contenu se voit aussi).
#[cfg(unix)]
pub(crate) fn etat_du_contenant(f: &std::path::Path, texte: &str) -> Etat {
    let contenu = Etat::Fichier {
        empreinte: empreinte_du_texte(texte.as_bytes()),
    };
    match std::fs::read_link(f) {
        Ok(vers) => Etat::Lien {
            vers: vers.to_string_lossy().into_owned(),
            puis: Box::new(contenu),
        },
        Err(_) => contenu,
    }
}

/// L'état d'un fichier lancé ou préchargé : absent, son contenu, ou un lien (vers où, puis ce qu'il désigne).
/// `Err` : il ne se relève pas (illisible, dossier, tube, trop gros), et la raison, prête à montrer.
#[cfg(unix)]
pub(crate) fn etat_de_la_cible(chemin: &std::path::Path) -> Result<Etat, Refus> {
    use std::io::ErrorKind;
    let montre = || crate::ui::chemin_affichable(chemin);
    match std::fs::symlink_metadata(chemin) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Etat::Absent),
        Err(e) => {
            return Err(Refus(trf!(
                "{} ne se lit pas ({e})",
                "{} cannot be read ({e})",
                montre()
            )));
        }
        Ok(m) if m.file_type().is_symlink() => {
            let vers = std::fs::read_link(chemin)
                .map_err(|e| Refus(trf!("{} ne se lit pas ({e})", "{} cannot be read ({e})", montre())))?;
            let puis = match std::fs::metadata(chemin) {
                Err(e) if e.kind() == ErrorKind::NotFound => Etat::Absent,
                _ => contenu(chemin)?,
            };
            return Ok(Etat::Lien {
                vers: vers.to_string_lossy().into_owned(),
                puis: Box::new(puis),
            });
        }
        Ok(_) => {}
    }
    contenu(chemin)
}

/// Le contenu d'un fichier ordinaire, ouvert sans attendre (un tube nommé bloquerait la lecture) et lu en entier.
#[cfg(unix)]
fn contenu(chemin: &std::path::Path) -> Result<Etat, Refus> {
    use std::io::Read as _;
    let montre = || crate::ui::chemin_affichable(chemin);
    let illisible = |e: std::io::Error| Refus(trf!("{} ne se lit pas ({e})", "{} cannot be read ({e})", montre()));
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let fichier = options.open(chemin).map_err(illisible)?;
    let meta = fichier.metadata().map_err(illisible)?;
    if !meta.is_file() {
        return Err(Refus(trf!(
            "{} n'est pas un fichier ordinaire : son contenu ne se suit pas",
            "{} is not a regular file: its content cannot be tracked",
            montre()
        )));
    }
    if meta.len() > TAILLE_MAX {
        return Err(Refus(trf!(
            "{} est trop gros pour être relu à chaque bilan",
            "{} is too large to be re-read at each check",
            montre()
        )));
    }
    let mut h = blake3::Hasher::new_derive_key("vanguard 2026-11 contenu d'un fichier v1");
    let lus = std::io::copy(&mut fichier.take(TAILLE_MAX.saturating_add(1)), &mut h).map_err(illisible)?;
    // Grossi pendant la lecture : on ne lie pas un choix à un contenu qu'on n'a pas lu en entier.
    if lus > TAILLE_MAX {
        return Err(Refus(trf!(
            "{} est trop gros pour être relu à chaque bilan",
            "{} is too large to be re-read at each check",
            montre()
        )));
    }
    Ok(Etat::Fichier {
        empreinte: *h.finalize().as_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fichier(octets: &[u8]) -> Etat {
        Etat::Fichier {
            empreinte: empreinte_du_texte(octets),
        }
    }

    fn un(ligne: &str, contenant: &Etat, cibles: &[(String, Etat)]) -> Temoin {
        temoin(
            "~/.config/systemd/user/a.service",
            "a:1".into(),
            ligne,
            Some(contenant),
            cibles,
        )
    }

    /// Chaque changement d'un témoin change l'empreinte de l'ensemble ; l'ordre et une ligne relue deux fois, non.
    #[test]
    fn empreinte_de_l_ensemble() {
        let ligne = "ExecStart=%h/.cache-x/rappel.sh";
        let c = fichier(b"[Service]\nExecStart=%h/.cache-x/rappel.sh\n");
        let cible = (
            "/home/alice/.cache-x/rappel.sh".to_string(),
            fichier(b"#!/bin/sh\necho ok\n"),
        );
        let base = Temoins::Releves(vec![un(ligne, &c, std::slice::from_ref(&cible))]).empreinte();
        let autre_contenant = fichier(b"[Service]\nExecStart=%h/.cache-x/rappel.sh\nNice=5\n");
        let autre_cible = (cible.0.clone(), fichier(b"#!/bin/sh\ncurl x | sh\n"));
        let lien = Etat::Lien {
            vers: "/tmp/x.service".into(),
            puis: Box::new(c.clone()),
        };
        let seconde = un("ExecStartPre=/opt/b", &c, &[]);
        for e in [
            Temoins::Releves(vec![un(ligne, &autre_contenant, std::slice::from_ref(&cible))]),
            Temoins::Releves(vec![un(ligne, &c, std::slice::from_ref(&autre_cible))]),
            Temoins::Releves(vec![un(ligne, &lien, std::slice::from_ref(&cible))]),
            Temoins::Releves(vec![un(ligne, &c, &[(cible.0.clone(), Etat::Absent)])]),
            Temoins::Releves(vec![un(ligne, &c, std::slice::from_ref(&cible)), seconde.clone()]),
        ] {
            assert_ne!(e.empreinte(), base);
        }
        let deux = Temoins::Releves(vec![un(ligne, &c, std::slice::from_ref(&cible)), seconde.clone()]);
        let deux_inverses = Temoins::Releves(vec![
            seconde.clone(),
            un(ligne, &c, std::slice::from_ref(&cible)),
            seconde,
        ]);
        assert_eq!(deux.empreinte(), deux_inverses.empreinte());
        assert_eq!(deux_inverses.lignes().len(), 2);
        assert_eq!(Temoins::Aucun.empreinte(), None);
        assert_eq!(Temoins::Refuse("x".into()).empreinte(), None);
    }

    #[test]
    fn trop_de_lignes_ou_un_refus() {
        let c = fichier(b"x");
        let n = |i: usize| Ok(un(&format!("ExecStart=/opt/{i}"), &c, &[]));
        assert!(matches!(
            Temoins::de((0..TEMOINS_MAX).map(n).collect()),
            Temoins::Releves(_)
        ));
        assert!(matches!(
            Temoins::de((0..=TEMOINS_MAX).map(n).collect()),
            Temoins::Refuse(_)
        ));
        assert!(matches!(
            Temoins::de(vec![n(0), Err(Refus("illisible".into()))]),
            Temoins::Refuse(r) if r == "illisible"
        ));
        assert!(matches!(Temoins::de(Vec::new()), Temoins::Refuse(_)));
        // Ce qui passerait la coupure ne serait pas vu avant le choix : la ligne longue ne se déclare pas.
        let pleine = format!("ExecStart=/opt/a{}", " ".repeat(LIGNE_MONTREE));
        assert!(matches!(
            Temoins::de(vec![Ok(un(&format!("{pleine}/tmp/x"), &c, &[]))]),
            Temoins::Refuse(_)
        ));
        assert!(matches!(
            Temoins::de(vec![Ok(un(&format!("{pleine}   "), &c, &[]))]),
            Temoins::Releves(_)
        ));
    }

    /// Sur de vrais fichiers : absent, contenu, lien, dossier et tube nommé (refusés sans bloquer).
    #[cfg(unix)]
    #[test]
    fn etats_des_cibles() {
        let d = crate::essais::temporaire().join(format!("vanguard-temoins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("rappel.sh");
        assert_eq!(etat_de_la_cible(&p), Ok(Etat::Absent));
        std::fs::write(&p, b"#!/bin/sh\necho ok\n").unwrap();
        let avant = etat_de_la_cible(&p).unwrap();
        assert_eq!(avant, fichier(b"#!/bin/sh\necho ok\n"));
        std::fs::write(&p, b"#!/bin/sh\necho ko\n").unwrap();
        assert_ne!(etat_de_la_cible(&p).unwrap(), avant);
        let l = d.join("lien");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(matches!(etat_de_la_cible(&l), Ok(Etat::Lien { .. })));
        assert!(etat_de_la_cible(&d).is_err());
        let tube = d.join("tube");
        if std::process::Command::new("mkfifo")
            .arg(&tube)
            .status()
            .is_ok_and(|s| s.success())
        {
            assert!(etat_de_la_cible(&tube).is_err());
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
