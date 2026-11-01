//! Vider un dossier de Windows (Temp, téléchargements de Windows Update, file d'impression) et mettre un cache de
//! côté, pour le processus élevé (`windows::eleve`, actes de `gestes`). Le dossier de Windows est donné par
//! l'appelant (lu à GetSystemDirectoryW, jamais dans l'environnement) ; les dossiers sous lui sont ceux de la table.
//!
//! Le processus élevé efface dans des dossiers où un compte ordinaire peut écrire (Windows\Temp) : une jonction ou un
//! lien posé là le ferait effacer ailleurs, avec ses droits. Chaque dossier fixe, du dossier de Windows au dernier,
//! est donc refusé s'il est un point d'analyse ; chaque entrée du premier niveau est jugée sur ses propres attributs,
//! sans suivre de lien, et un lien est sauté, compté et nommé. Le tri et le compte sont à part des E/S (`trier`),
//! testés sous Linux, et le vrai vidage aussi, avec un lien symbolique dont la cible doit rester intacte.

// Sous Linux, seuls les tests s'en servent : le processus élevé n'existe que sous Windows.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::{Path, PathBuf};

use crate::machine::gestes::{ACoter, Vidable};
use crate::modele::Echec;
use crate::ui::{tr, trf};

/// Le contexte des échecs, au journal.
const CONTEXTE: &str = "vidage";

/// Ce qu'une entrée du dossier est, jugée sur ses propres attributs, sans suivre de lien.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sorte {
    /// Un point d'analyse (lien symbolique, jonction, point de montage) : il mène ailleurs, on n'y touche pas.
    Lien,
    Fichier,
    Dossier,
}

/// La sorte d'une entrée d'après ses métadonnées NON suivies (`DirEntry::metadata`, `symlink_metadata`).
pub(crate) fn sorte(meta: &std::fs::Metadata) -> Sorte {
    if est_lien(meta) {
        Sorte::Lien
    } else if meta.is_dir() {
        Sorte::Dossier
    } else {
        Sorte::Fichier
    }
}

/// FILE_ATTRIBUTE_REPARSE_POINT, et pas seulement les liens que `is_symlink` reconnaît : tout point d'analyse peut
/// mener ailleurs (jonction, point de montage, fichier de nuage), aucun n'est suivi.
#[cfg(windows)]
fn est_lien(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const POINT_D_ANALYSE: u32 = 0x400;
    meta.file_attributes() & POINT_D_ANALYSE != 0
}

#[cfg(not(windows))]
fn est_lien(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Ce qu'un vidage a fait.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Bilan {
    pub retires: usize,
    /// Encore en usage (fichier ouvert), refusé, ou illisible : laissé, sans que ce soit un échec.
    pub laisses: usize,
    /// Les liens sautés, par leur nom.
    pub liens: Vec<String>,
}

/// Le tri, sans E/S : chaque entrée (`None` : illisible, laissée) est retirée par `retirer`, sauf un lien, sauté et
/// nommé, et un dossier quand seuls les fichiers sont visés (la file d'impression : le spouleur n'y met que des
/// fichiers ; un dossier n'est pas à lui, il n'est ni retiré ni compté).
pub(crate) fn trier(
    entrees: impl IntoIterator<Item = (PathBuf, Option<Sorte>)>,
    fichiers_seulement: bool,
    mut retirer: impl FnMut(&Path, Sorte) -> bool,
) -> Bilan {
    let mut b = Bilan::default();
    for (chemin, sorte) in entrees {
        match sorte {
            None => b.laisses = b.laisses.saturating_add(1),
            Some(Sorte::Lien) => b.liens.push(
                chemin
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
            ),
            Some(Sorte::Dossier) if fichiers_seulement => {}
            Some(s) => {
                if retirer(&chemin, s) {
                    b.retires = b.retires.saturating_add(1);
                } else {
                    b.laisses = b.laisses.saturating_add(1);
                }
            }
        }
    }
    b
}

/// Vide `dossier` (son contenu, pas lui). Un fichier par `remove_file`, un dossier par `remove_dir_all`, qui depuis
/// Rust 1.58.1 (CVE-2022-21658) ne suit aucun lien ni jonction, même remplacé entre le jugement et le retrait : au
/// pire il efface un lien imbriqué lui-même, jamais ce vers quoi il mène. `remove_file` sur un lien glissé à la place
/// d'un fichier retire le lien, pas sa cible. Seule la lecture du dossier peut échouer.
pub(crate) fn vider(dossier: &Path, fichiers_seulement: bool) -> std::io::Result<Bilan> {
    let entrees = std::fs::read_dir(dossier)?.map(|e| match e {
        Ok(e) => {
            let s = e.metadata().ok().map(|m| sorte(&m));
            (e.path(), s)
        }
        Err(_) => (PathBuf::new(), None),
    });
    Ok(trier(entrees, fichiers_seulement, |chemin, s| match s {
        Sorte::Fichier => std::fs::remove_file(chemin).is_ok(),
        Sorte::Dossier => std::fs::remove_dir_all(chemin).is_ok(),
        Sorte::Lien => false,
    }))
}

/// Au plus ces noms de liens sont cités : venus d'un dossier où tout compte écrit, ils ne font pas une ligne sans fin.
const LIENS_CITES: usize = 5;
/// Un nom de lien cité est coupé à cette longueur.
const NOM_CITE_MAX: usize = 60;

/// « 12 retirés, 3 laissés (en usage), 1 lien(s) sauté(s) : x ».
pub(crate) fn texte_bilan(b: &Bilan) -> String {
    let mut t = trf!(
        "{} retirés, {} laissés (en usage)",
        "{} removed, {} left (in use)",
        b.retires,
        b.laisses
    );
    if !b.liens.is_empty() {
        let mut noms: Vec<String> = b
            .liens
            .iter()
            .take(LIENS_CITES)
            .map(|n| crate::ui::affichable(&n.chars().take(NOM_CITE_MAX).collect::<String>()))
            .collect();
        if b.liens.len() > LIENS_CITES {
            noms.push("…".to_string());
        }
        t.push_str(&trf!(
            ", {} lien(s) sauté(s) : {}",
            ", {} link(s) skipped: {}",
            b.liens.len(),
            noms.join(", ")
        ));
    }
    t
}

/// Où mène un dossier fixe sous celui de Windows.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lieu {
    /// Un vrai dossier, et chacun de ses parents jusqu'à celui de Windows compris.
    Ici(PathBuf),
    /// Lui ou un parent manque.
    Absent,
    /// Lui ou un parent est un point d'analyse, ou n'est pas un dossier : refusé.
    Refuse(PathBuf),
    /// Illisible (droits) : on ne conclut pas.
    Illisible(PathBuf),
}

/// Le dossier `windows`, puis chaque dossier de `sous` l'un dans l'autre : chacun jugé sans suivre de lien.
pub(crate) fn suivre(windows: &Path, sous: &[impl AsRef<Path>]) -> Lieu {
    let mut p = windows.to_path_buf();
    for etape in std::iter::once(None).chain(sous.iter().map(Some)) {
        if let Some(s) = etape {
            p.push(s);
        }
        match std::fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Lieu::Absent,
            Err(_) => return Lieu::Illisible(p),
            Ok(m) if sorte(&m) != Sorte::Dossier => return Lieu::Refuse(p),
            Ok(_) => {}
        }
    }
    Lieu::Ici(p)
}

/// Les dossiers de `chemin` sous `windows`, s'il y est vraiment : composants entiers, comparés sans tenir compte de
/// la casse (comme Windows), sans « . » ni « .. » ni composant vide, ni « : » (flux de données) ni variable (« % »),
/// et au moins un dossier sous celui de Windows. Du texte seulement : les liens se jugent ensuite (`suivre`).
pub(crate) fn sous_windows(windows: &str, chemin: &str) -> Option<Vec<String>> {
    let morceaux = |t: &str| -> Vec<String> {
        t.trim_end_matches(['\\', '/'])
            .split(['\\', '/'])
            .map(str::to_string)
            .collect()
    };
    let w = morceaux(windows);
    let c = morceaux(chemin);
    if w.iter().any(String::is_empty) || c.len() <= w.len() || chemin.contains('%') {
        return None;
    }
    let (tete, reste) = c.split_at(w.len());
    let meme = tete.iter().zip(&w).all(|(a, b)| a.eq_ignore_ascii_case(b));
    let sain = reste
        .iter()
        .all(|m| !m.is_empty() && m != "." && m != ".." && !m.contains(':'));
    (meme && sain).then(|| reste.to_vec())
}

/// Vide un dossier de la table sous `windows`. `Ok` : ce qui est à dire (absent : rien à vider) ; `Err` : l'échec.
pub(crate) fn vider_sous(windows: &Path, dossier: Vidable) -> Result<String, Echec> {
    vider_lieu(suivre(windows, dossier.sous_windows()), false)
}

/// Vide la file d'impression : les fichiers seulement, dans `relatif` (sous `windows`, voir `sous_windows`).
pub(crate) fn vider_file(windows: &Path, relatif: &[String]) -> Result<String, Echec> {
    vider_lieu(suivre(windows, relatif), true)
}

/// Un dossier fixe refusé (lien, pas un dossier) ou illisible : l'échec à dire, `faire` disant ce qui n'est pas fait.
fn refus(lieu: &Lieu, faire: &str) -> Option<Echec> {
    match lieu {
        Lieu::Refuse(p) => Some(Echec::refuse(
            CONTEXTE,
            trf!(
                "{} est un lien ou une jonction (ou pas un dossier) : refusé, rien n'est {faire}",
                "{} is a link or a junction (or not a folder): refused, nothing is {faire}",
                crate::ui::chemin_affichable(p)
            ),
        )),
        Lieu::Illisible(p) => Some(Echec::echoue(
            CONTEXTE,
            trf!(
                "{} ne se lit pas : rien n'est {faire}",
                "{} cannot be read: nothing is {faire}",
                crate::ui::chemin_affichable(p)
            ),
        )),
        Lieu::Ici(_) | Lieu::Absent => None,
    }
}

fn vider_lieu(lieu: Lieu, fichiers_seulement: bool) -> Result<String, Echec> {
    let efface = tr!("effacé", "deleted");
    if let Some(r) = refus(&lieu, efface) {
        return Err(r);
    }
    let Lieu::Ici(p) = lieu else {
        return Ok(tr!("dossier absent : rien à vider", "folder missing: nothing to empty").to_string());
    };
    vider(&p, fichiers_seulement).map(|b| texte_bilan(&b)).map_err(|e| {
        Echec::echoue(
            CONTEXTE,
            trf!(
                "{} ne se lit pas ({e}) : rien n'est {efface}",
                "{} cannot be read ({e}): nothing is {efface}",
                crate::ui::chemin_affichable(&p)
            ),
        )
    })
}

/// Met un cache de côté sous `windows` : renommé `<nom>.<date>` dans son dossier (`date` : AAAAMMJJHHmm, heure
/// locale), Windows en refait un neuf. Refusé si lui ou un parent est un lien ; absent : rien à faire. Le service
/// qui s'en sert doit être arrêté avant (la réparation l'arrête) : sinon le renommage échoue, rien n'est perdu.
pub(crate) fn mettre_de_cote(windows: &Path, cache: ACoter, date: &str) -> Result<String, Echec> {
    let lieu = suivre(windows, cache.sous_windows());
    if let Some(r) = refus(&lieu, tr!("renommé", "renamed")) {
        return Err(r);
    }
    let Lieu::Ici(source) = lieu else {
        return Ok(tr!("absent : rien à mettre de côté", "missing: nothing to set aside").to_string());
    };
    let nom = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let cible = source.with_file_name(format!("{nom}.{date}"));
    // Deux fois dans la même minute : l'ancien mis de côté n'est jamais remplacé.
    if std::fs::symlink_metadata(&cible).is_ok() {
        return Err(Echec::refuse(
            CONTEXTE,
            trf!(
                "{} existe déjà : rien n'est renommé, réessayez dans une minute",
                "{} already exists: nothing is renamed, try again in a minute",
                crate::ui::chemin_affichable(&cible)
            ),
        ));
    }
    std::fs::rename(&source, &cible)
        .map(|()| {
            trf!(
                "l'ancien est dans {}",
                "the old one is in {}",
                crate::ui::chemin_affichable(&cible)
            )
        })
        .map_err(|e| {
            Echec::echoue(
                CONTEXTE,
                trf!(
                    "{} n'a pas pu être renommé ({e}) ; un service s'en sert encore ?",
                    "{} could not be renamed ({e}); is a service still using it?",
                    crate::ui::chemin_affichable(&source)
                ),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: &str) -> PathBuf {
        PathBuf::from(n)
    }

    #[test]
    fn le_tri_saute_les_liens_et_compte_le_reste() {
        let mut vus = Vec::new();
        let b = trier(
            [
                (p("a.tmp"), Some(Sorte::Fichier)),
                (p("piege"), Some(Sorte::Lien)),
                (p("ouvert.log"), Some(Sorte::Fichier)),
                (p("sous"), Some(Sorte::Dossier)),
                (p("?"), None),
            ],
            false,
            |c, s| {
                vus.push((c.to_path_buf(), s));
                c != Path::new("ouvert.log")
            },
        );
        assert_eq!(
            b,
            Bilan {
                retires: 2,
                laisses: 2,
                liens: vec!["piege".into()],
            }
        );
        // Le lien n'est jamais confié à `retirer`.
        assert!(vus.iter().all(|(_, s)| *s != Sorte::Lien));
        // La file d'impression : les dossiers ne sont ni retirés ni comptés.
        let b = trier(
            [(p("j.spl"), Some(Sorte::Fichier)), (p("d"), Some(Sorte::Dossier))],
            true,
            |_, s| {
                assert_eq!(s, Sorte::Fichier);
                true
            },
        );
        assert_eq!((b.retires, b.laisses), (1, 0));
    }

    #[test]
    fn le_bilan_se_lit() {
        let b = Bilan {
            retires: 12,
            laisses: 3,
            liens: vec!["x".into()],
        };
        assert_eq!(
            texte_bilan(&b),
            "12 retirés, 3 laissés (en usage), 1 lien(s) sauté(s) : x"
        );
        let b = Bilan {
            retires: 0,
            laisses: 0,
            liens: (0..9).map(|i| format!("l{i}\u{1b}[2J")).collect(),
        };
        let t = texte_bilan(&b);
        assert!(
            t.contains("9 lien(s) sauté(s)") && t.ends_with(", …") && !t.contains('\u{1b}'),
            "{t}"
        );
    }

    #[test]
    fn la_file_doit_etre_sous_windows() {
        let w = r"C:\Windows";
        let bon = Some(vec!["System32".to_string(), "spool".into(), "PRINTERS".into()]);
        assert_eq!(sous_windows(w, r"C:\Windows\System32\spool\PRINTERS"), bon);
        assert_eq!(
            sous_windows(w, r"c:\windows\system32\spool\PRINTERS\").map(|v| v.len()),
            Some(3)
        );
        for mauvais in [
            r"C:\Windows",
            r"C:\Windows\",
            r"C:\WindowsX\spool",
            r"D:\Windows\System32\spool\PRINTERS",
            r"C:\Windows\System32\..\..\Users\alice",
            r"C:\Windows\.\spool",
            r"C:\Windows\\spool",
            r"C:\Windows\spool:flux",
            r"%SystemRoot%\System32\spool\PRINTERS",
            r"\\?\C:\Windows\System32\spool\PRINTERS",
            r"\\203.0.113.7\partage\spool",
            "",
        ] {
            assert_eq!(sous_windows(w, mauvais), None, "{mauvais}");
        }
    }

    /// Le vrai vidage, avec un lien vers un dossier hors de celui qu'on vide et un autre caché dans un sous-dossier :
    /// ce vers quoi ils mènent reste intact ; le lien du premier niveau est sauté et nommé.
    #[cfg(unix)]
    #[test]
    fn un_lien_ne_fait_jamais_effacer_ailleurs() {
        let racine = crate::essais::Jetable::nouveau("vidage-lien");
        let windows = racine.join("Windows");
        let temp = windows.join("Temp");
        let ailleurs = racine.join("ailleurs");
        std::fs::create_dir_all(temp.join("sous")).unwrap();
        std::fs::create_dir_all(&ailleurs).unwrap();
        std::fs::write(ailleurs.join("temoin"), b"reste").unwrap();
        std::fs::write(temp.join("a.tmp"), b"x").unwrap();
        std::fs::write(temp.join("sous").join("b.tmp"), b"x").unwrap();
        std::os::unix::fs::symlink(&ailleurs, temp.join("piege")).unwrap();
        std::os::unix::fs::symlink(&ailleurs, temp.join("sous").join("cache")).unwrap();
        std::os::unix::fs::symlink(ailleurs.join("temoin"), temp.join("fichier-lien")).unwrap();
        let note = vider_sous(&windows, Vidable::TempWindows).unwrap();
        assert!(note.starts_with("2 retirés, 0 laissés"), "{note}");
        assert!(note.contains("2 lien(s) sauté(s)"), "{note}");
        assert_eq!(std::fs::read(ailleurs.join("temoin")).unwrap(), b"reste");
        assert!(!temp.join("a.tmp").exists() && !temp.join("sous").exists());
        // Les liens du premier niveau restent, eux.
        assert!(std::fs::symlink_metadata(temp.join("piege")).is_ok());
        // Absent : rien à vider, ce n'est pas un échec.
        assert!(vider_sous(&windows, Vidable::WuTelechargements).is_ok());
    }

    /// Un dossier fixe (ou un de ses parents) remplacé par un lien : refusé, rien n'est effacé ni renommé.
    #[cfg(unix)]
    #[test]
    fn un_dossier_fixe_qui_est_un_lien_est_refuse() {
        let racine = crate::essais::Jetable::nouveau("vidage-fixe");
        let windows = racine.join("Windows");
        let ailleurs = racine.join("ailleurs");
        std::fs::create_dir_all(windows.join("System32")).unwrap();
        std::fs::create_dir_all(&ailleurs).unwrap();
        std::fs::write(ailleurs.join("temoin"), b"reste").unwrap();
        std::os::unix::fs::symlink(&ailleurs, windows.join("Temp")).unwrap();
        std::os::unix::fs::symlink(&ailleurs, windows.join("SoftwareDistribution")).unwrap();
        std::os::unix::fs::symlink(&ailleurs, windows.join("System32").join("spool")).unwrap();
        assert!(vider_sous(&windows, Vidable::TempWindows).is_err());
        assert!(vider_sous(&windows, Vidable::WuTelechargements).is_err());
        let file = ["System32".to_string(), "spool".into(), "PRINTERS".into()];
        assert!(vider_file(&windows, &file).is_err());
        assert!(mettre_de_cote(&windows, ACoter::SoftwareDistribution, "202611011200").is_err());
        assert_eq!(std::fs::read(ailleurs.join("temoin")).unwrap(), b"reste");
        assert!(std::fs::symlink_metadata(windows.join("SoftwareDistribution")).is_ok());
    }

    #[test]
    fn mettre_de_cote_renomme_et_dit_ou() {
        let racine = crate::essais::Jetable::nouveau("vidage-cote");
        let windows = racine.join("Windows");
        std::fs::create_dir_all(windows.join("SoftwareDistribution").join("Download")).unwrap();
        let note = mettre_de_cote(&windows, ACoter::SoftwareDistribution, "202611011200").unwrap();
        assert!(note.contains("SoftwareDistribution.202611011200"), "{note}");
        assert!(
            windows
                .join("SoftwareDistribution.202611011200")
                .join("Download")
                .is_dir()
        );
        assert!(!windows.join("SoftwareDistribution").exists());
        // Absent : rien à mettre de côté.
        let note = mettre_de_cote(&windows, ACoter::Catroot2, "202611011200").unwrap();
        assert!(note.contains("rien à mettre de côté"), "{note}");
        // Deux fois dans la même minute : la cible existe, rien n'est écrasé.
        std::fs::create_dir_all(windows.join("SoftwareDistribution")).unwrap();
        assert!(mettre_de_cote(&windows, ACoter::SoftwareDistribution, "202611011200").is_err());
    }

    #[test]
    fn la_file_ne_retire_que_des_fichiers() {
        let racine = crate::essais::Jetable::nouveau("vidage-file");
        let windows = racine.join("Windows");
        let file = windows.join("System32").join("spool").join("PRINTERS");
        std::fs::create_dir_all(file.join("dossier")).unwrap();
        std::fs::write(file.join("00001.SPL"), b"x").unwrap();
        let relatif = vec!["System32".to_string(), "spool".into(), "PRINTERS".into()];
        let note = vider_file(&windows, &relatif).unwrap();
        assert!(note.starts_with("1 retirés, 0 laissés"), "{note}");
        assert!(file.join("dossier").is_dir() && !file.join("00001.SPL").exists());
    }
}
