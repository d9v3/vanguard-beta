//! Les archives de tldr-pages sur la clé, mises à jour par le déploiement (`vanguard deploiement tldr <clé>/tldr`) :
//! lancé depuis la clé, le guide a ses exemples dès le premier lancement, même sur un ordinateur sans Internet. Le
//! programme n'écrit sur la clé que si outils/deployer.sh le lui demande.
//!
//! Plus strict que le guide, qui prend une archive dès qu'elle se lit (`lire_zip`) : une archive part sur la clé
//! seulement si elle est intacte, comme le vérifiait `zipfile.testzip()` dans le script d'avant : chaque entrée
//! relue, son CRC-32 recalculé, et assez de pages. Le guide lui-même ne change pas : ce contrôle-là ne vaut que pour
//! la copie de la clé, qui part chez d'autres.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::{ADRESSE, LANGUES, TAILLE_ARCHIVE, archive, nom_d_archive};
use crate::archives::zip::{self, Defaut};
use crate::ui::*;

/// Une archive intacte de la clé plus jeune est gardée : le projet refait les siennes chaque jour.
const UN_JOUR: Duration = Duration::from_hours(24);

/// L'avance tolérée sur l'horloge : FAT arrondit les dates à 2 s, et deux horloges ne s'accordent jamais tout à fait.
/// Au-delà, une date dans le futur est suspecte.
const MARGE_FUTUR: Duration = Duration::from_mins(5);

/// Les bornes du contrôle, jugées sur les tailles annoncées avant toute décompression : une entrée plus grosse n'est
/// pas une page, et quelques Mo de deflate pourraient sinon en annoncer des Go à recalculer. Autant d'entrées que le
/// format en permet sans zip64.
const BORNES: crate::archives::Bornes = crate::archives::Bornes {
    entrees: u16::MAX as usize,
    fichier: 64 << 20,
    total: 512 << 20,
};

/// Le nombre minimal de pages d'une archive intacte : l'anglais en a environ 7 600, le français 1 100. Une archive
/// qui en a bien moins n'est pas celle du projet (page d'erreur, archive vidée).
fn minimum(langue: &str) -> usize {
    if langue == "en" { 5000 } else { 500 }
}

/// Pourquoi une archive ne part pas sur la clé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refus {
    /// Pas intacte (`archives::zip::controler`).
    Abimee(Defaut),
    /// Intacte, mais avec trop peu de pages : (pages, minimum).
    TropPeu(usize, usize),
}

impl Refus {
    fn texte(self) -> String {
        match self {
            Refus::Abimee(Defaut::PasUnZip) => tr!("pas un zip", "not a zip").to_string(),
            Refus::Abimee(Defaut::NonPrise) => tr!("zip64 ou sur plusieurs disques", "zip64 or multi-disk").to_string(),
            Refus::Abimee(Defaut::Demesuree) => tr!("entrée démesurée", "oversized entry").to_string(),
            Refus::Abimee(Defaut::Illisible(n)) => trf!("entrée {n} illisible", "entry {n} unreadable"),
            Refus::Abimee(Defaut::Methode(n)) => trf!(
                "entrée {n} chiffrée ou d'une méthode inconnue",
                "entry {n} encrypted or of an unknown method"
            ),
            Refus::Abimee(Defaut::Crc(n)) => trf!("CRC faux à l'entrée {n}", "wrong CRC at entry {n}"),
            Refus::Abimee(Defaut::Delai) => tr!(
                "trop longue à décompresser (blocs vides)",
                "too slow to decompress (empty blocks)"
            )
            .to_string(),
            Refus::TropPeu(pages, minimum) => trf!(
                "{pages} pages, moins de {minimum}",
                "{pages} pages, fewer than {minimum}"
            ),
        }
    }
}

/// L'archive est-elle intacte (`archives::zip::controler`), avec au moins `minimum` pages ? Le nombre de pages, ou
/// pourquoi elle est refusée. Une page : un nom en « .md » rangé dans un dossier (« pages/linux/ls.md »), comme le
/// comptait le script d'avant.
pub(super) fn intacte(octets: &[u8], minimum: usize) -> Result<usize, Refus> {
    let noms = zip::controler(octets, &BORNES).map_err(Refus::Abimee)?;
    // Sensible à la casse, comme endswith(".md") de Python.
    let pages = noms
        .iter()
        .filter(|n| n.as_bytes().ends_with(b".md") && n.contains('/'))
        .count();
    if pages < minimum {
        return Err(Refus::TropPeu(pages, minimum));
    }
    Ok(pages)
}

/// La date d'un fichier ordinaire ; `None` s'il n'y en a pas.
fn date_de(chemin: &Path) -> Option<SystemTime> {
    std::fs::metadata(chemin)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .and_then(|m| m.modified().ok())
}

/// Le contenu d'une archive de cet ordinateur : un simple fichier (ni lien, ni tube), jamais plus de
/// `TAILLE_ARCHIVE` lus.
fn lire_archive(chemin: &Path) -> Option<Vec<u8>> {
    crate::socle::lire_ordinaire(chemin, TAILLE_ARCHIVE).ok()
}

/// Les restes d'une copie interrompue (clé pleine, déploiement arrêté) : le temporaire de l'écriture atomique
/// (`tldr-pages.en.tmp-…`), ou le `.zip.nouveau` du script d'avant. Tronqués, ils occuperaient la clé, et son
/// manifeste les enregistrerait.
fn retirer_les_restes(dossier: &Path) {
    let Ok(fichiers) = std::fs::read_dir(dossier) else {
        return;
    };
    for f in fichiers.flatten() {
        let nom = f.file_name().to_string_lossy().into_owned();
        let reste = LANGUES.iter().any(|l| {
            let base = format!("tldr-pages.{l}.");
            nom.strip_prefix(&base)
                .is_some_and(|fin| fin.starts_with("tmp-") || fin == "zip.nouveau")
        });
        if reste && f.file_type().is_ok_and(|t| t.is_file()) {
            let _ = std::fs::remove_file(f.path());
        }
    }
}

/// Met à jour les archives de `dossier` (celui de la clé) : pour chaque langue, une archive intacte de moins d'un jour
/// est gardée ; sinon, celle téléchargée si elle est intacte ; sinon, sans Internet, la copie de cet ordinateur
/// (`locale`) si elle est intacte et plus récente que celle de la clé (ou si celle de la clé est refusée : abîmée,
/// datée dans le futur). Une archive abîmée que rien ne remplace est retirée. Une page d'erreur ou une archive
/// tronquée ne remplace jamais la bonne. Une copie qui échoue laisse la clé avec son archive, et l'autre langue est
/// quand même essayée. `false` : une copie a échoué.
fn mettre_a_jour(
    dossier: &Path,
    locale: impl Fn(&str) -> PathBuf,
    telecharger: impl Fn(&str) -> Option<Vec<u8>>,
    poser: impl Fn(&Path, &[u8], Option<SystemTime>) -> std::io::Result<()>,
) -> bool {
    if let Err(e) = std::fs::create_dir_all(dossier) {
        eprintln!(
            "{}",
            trf!(
                "tldr-pages : dossier {} impossible à créer ({e}).",
                "tldr-pages: folder {} cannot be created ({e}).",
                dossier.display()
            )
        );
        return false;
    }
    retirer_les_restes(dossier);
    let mut reussi = true;
    for langue in LANGUES {
        let fin = dossier.join(nom_d_archive(langue));
        let minimum = minimum(langue);
        // L'archive de la clé est contrôlée comme une autre : un ordinateur piégé où la clé a été branchée a pu y
        // poser une archive « fraîche » qui fige le guide ; le déploiement la gardait sans la relire, puis
        // l'inscrivait au manifeste. Une date dans le futur n'est pas fraîche : elle est suspecte, et ne sert pas de
        // référence (elle ferait refuser toute copie plus ancienne qu'elle).
        let sur_la_cle = date_de(&fin).map(|date| {
            let futur = date
                .duration_since(SystemTime::now())
                .is_ok_and(|ecart| ecart > MARGE_FUTUR);
            let jugee = lire_archive(&fin).map_or(Err(None), |o| intacte(&o, minimum).map(|_| ()).map_err(Some));
            (date, futur, jugee)
        });
        let reference = match &sur_la_cle {
            Some((date, false, Ok(()))) => {
                if date.elapsed().is_ok_and(|age| age < UN_JOUR) {
                    continue;
                }
                Some(*date)
            }
            Some((_, futur, jugee)) => {
                let raison = match (futur, jugee) {
                    (true, _) => tr!("datée dans le futur", "dated in the future").to_string(),
                    (false, Err(Some(r))) => r.texte(),
                    (false, _) => tr!("illisible", "unreadable").to_string(),
                };
                eprintln!(
                    "{}",
                    trf!(
                        "tldr-pages ({langue}) : archive de la clé refusée ({raison}).",
                        "tldr-pages ({langue}): key archive refused ({raison})."
                    )
                );
                None
            }
            None => None,
        };
        // Seule une archive qui n'est pas intacte est retirée faute de remplaçante : une archive intacte datée dans le
        // futur (l'horloge de cet ordinateur en retard) n'est que privée de son rôle de référence.
        let refusee = matches!(sur_la_cle, Some((_, _, Err(_))));
        // Une archive reçue mais refusée le dit : le script d'avant la taisait.
        let recue = telecharger(langue).filter(|o| match intacte(o, minimum) {
            Ok(_) => true,
            Err(r) => {
                eprintln!(
                    "{}",
                    trf!(
                        "tldr-pages ({langue}) : archive téléchargée refusée ({}).",
                        "tldr-pages ({langue}): downloaded archive refused ({}).",
                        r.texte()
                    )
                );
                false
            }
        });
        let source = recue.map(|o| (o, None)).or_else(|| {
            let chemin = locale(langue);
            let date = date_de(&chemin).filter(|d| reference.is_none_or(|c| d > &c))?;
            let octets = lire_archive(&chemin).filter(|o| intacte(o, minimum).is_ok())?;
            Some((octets, Some(date)))
        });
        let Some((octets, date)) = source else {
            // Rien pour la remplacer : une archive refusée ne reste pas sur la clé, où le guide la lirait et où le
            // manifeste l'inscrirait.
            if refusee {
                if std::fs::remove_file(&fin).is_ok() {
                    eprintln!(
                        "{}",
                        trf!(
                            "tldr-pages ({langue}) : rien à copier, l'archive refusée est retirée de la clé.",
                            "tldr-pages ({langue}): nothing to copy, the refused archive is removed from the key."
                        )
                    );
                } else {
                    eprintln!(
                        "{}",
                        trf!(
                            "tldr-pages ({langue}) : l'archive refusée n'a pas pu être retirée de la clé.",
                            "tldr-pages ({langue}): the refused archive could not be removed from the key."
                        )
                    );
                    reussi = false;
                }
                continue;
            }
            eprintln!(
                "{}",
                trf!(
                    "tldr-pages ({langue}) : rien de neuf à copier, la clé garde son archive.",
                    "tldr-pages ({langue}): nothing new to copy, the key keeps its archive."
                )
            );
            continue;
        };
        // Écrite à côté, sur le disque, avec sa date, puis mise à sa place : une clé retirée pendant la copie ne
        // laisse pas une archive à moitié écrite.
        if poser(&fin, &octets, date).is_err() {
            eprintln!(
                "{}",
                trf!(
                    "tldr-pages ({langue}) : la copie a échoué, la clé garde son archive.",
                    "tldr-pages ({langue}): the copy failed, the key keeps its archive."
                )
            );
            reussi = false;
            continue;
        }
        println!(
            "{}",
            trf!(
                "tldr-pages ({langue}) : archive de la clé à jour.",
                "tldr-pages ({langue}): key archive up to date."
            )
        );
    }
    reussi
}

/// Les archives de la clé dans `dossier`, depuis tldr-pages (40 Mo et 2 minutes au plus, sauf en travail sans
/// Internet : le client HTTPS ne le vérifie pas lui-même) ou la copie de cet ordinateur. `false` : une copie a échoué.
pub(crate) fn sur_la_cle(dossier: &Path) -> bool {
    let hors_ligne = crate::parametres::hors_ligne();
    mettre_a_jour(
        dossier,
        archive,
        |langue| {
            if hors_ligne {
                return None;
            }
            let adresse = format!("{ADRESSE}{}", nom_d_archive(langue));
            let demande = crate::http::Demande {
                taille_max: TAILLE_ARCHIVE,
                ..crate::http::Demande::get(&adresse, Duration::from_secs(120))
            };
            crate::http::envoyer(demande).filter(|r| r.code == 200).map(|r| r.corps)
        },
        crate::socle::ecrire_atomique_date,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archives::zip::essais::archive_controlee as zip_d_essai;
    use std::cell::Cell;

    /// Un zip fait par `zipfile` de Python (date fixe : 22 oct. 2026, midi) : le dossier « pages/ », une page
    /// compressée (deflate) et une stockée telle quelle. Un oracle indépendant de ce module : son CRC et sa forme
    /// viennent d'un autre code.
    const ZIP_DE_PYTHON: &[u8] =
        b"\x50\x4b\x03\x04\x14\x00\x00\x00\x00\x00\x00\x60\x56\x5d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x06\x00\x00\x00\x70\x61\x67\x65\x73\x2f\x50\x4b\x03\x04\x14\x00\x00\x00\x08\x00\x00\x60\
        \x56\x5d\x89\x9a\x30\xbc\x4a\x00\x00\x00\xea\x00\x00\x00\x13\x00\x00\x00\x70\x61\x67\x65\x73\x2f\
        \x63\x6f\x6d\x6d\x6f\x6e\x2f\x74\x61\x72\x2e\x6d\x64\x53\x56\x28\x49\x2c\xe2\xe2\xb2\x53\x70\x2c\
        \x4a\xce\xc8\x2c\x4b\x2d\xd2\xe3\xe2\xd2\x55\x70\x2e\x4a\x4d\x2d\x52\x28\xcd\x4b\x55\x48\x84\x08\
        \x2b\x58\x71\x71\x25\x00\x55\x2a\x24\xa7\x29\x54\x57\x27\x67\x26\xe5\xa4\xea\x01\xb9\xb5\xb5\x40\
        \x5e\x5a\x26\x50\x49\x2a\x90\x9d\xc0\xa5\x3c\x88\x4d\x03\x00\x50\x4b\x03\x04\x14\x00\x00\x00\x00\
        \x00\x00\x60\x56\x5d\x29\xb2\xfb\x57\x23\x00\x00\x00\x23\x00\x00\x00\x11\x00\x00\x00\x70\x61\x67\
        \x65\x73\x2f\x6c\x69\x6e\x75\x78\x2f\x6c\x73\x2e\x6d\x64\x23\x20\x6c\x73\x0a\x0a\x3e\x20\x4c\x69\
        \x73\x74\x65\x72\x2e\x0a\x0a\x2d\x20\x54\x6f\x75\x74\x20\x3a\x0a\x0a\x60\x6c\x73\x20\x2d\x61\x60\
        \x0a\x50\x4b\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x60\x56\x5d\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00\x70\
        \x61\x67\x65\x73\x2f\x50\x4b\x01\x02\x14\x03\x14\x00\x00\x00\x08\x00\x00\x60\x56\x5d\x89\x9a\x30\
        \xbc\x4a\x00\x00\x00\xea\x00\x00\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x24\
        \x00\x00\x00\x70\x61\x67\x65\x73\x2f\x63\x6f\x6d\x6d\x6f\x6e\x2f\x74\x61\x72\x2e\x6d\x64\x50\x4b\
        \x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x60\x56\x5d\x29\xb2\xfb\x57\x23\x00\x00\x00\x23\x00\
        \x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x9f\x00\x00\x00\x70\x61\x67\x65\
        \x73\x2f\x6c\x69\x6e\x75\x78\x2f\x6c\x73\x2e\x6d\x64\x50\x4b\x05\x06\x00\x00\x00\x00\x03\x00\x03\
        \x00\xb4\x00\x00\x00\xf1\x00\x00\x00\x00\x00";

    #[test]
    fn le_zip_de_python_est_intact() {
        // Deux pages ; le dossier « pages/ » n'en est pas une.
        assert_eq!(intacte(ZIP_DE_PYTHON, 2), Ok(2));
        assert!(intacte(ZIP_DE_PYTHON, 3).is_err());
        // Tronqué : refusé.
        assert!(intacte(&ZIP_DE_PYTHON[..ZIP_DE_PYTHON.len() - 30], 0).is_err());
        assert!(intacte(&ZIP_DE_PYTHON[40..], 0).is_err());
    }

    /// Une archive de `pages` pages stockées, d'une marque reconnaissable.
    fn archive_de(pages: usize, marque: &str) -> Vec<u8> {
        let noms: Vec<String> = (0..pages).map(|n| format!("pages/common/p{n}.md")).collect();
        let contenu = format!("# {marque}\n");
        let entrees: Vec<(&str, u16, &[u8])> = noms.iter().map(|n| (n.as_str(), 0, contenu.as_bytes())).collect();
        zip_d_essai(&entrees)
    }

    /// Le compte des pages : un dossier, même en « .md/ », n'en est pas une, ni une page hors d'un dossier ; une
    /// archive abîmée est refusée quel que soit son compte (le détail : `archives::zip`).
    #[test]
    fn pages_comptees_comme_le_script() {
        let dossiers = zip_d_essai(&[("pages/a.md/", 0, b""), ("pages/linux/ls.md", 0, b"# ls\n")]);
        assert_eq!(intacte(&dossiers, 1), Ok(1));
        assert!(intacte(&dossiers, 2).is_err());
        assert!(intacte(&zip_d_essai(&[("ls.md", 0, b"# ls\n")]), 1).is_err());
        let bonne = zip_d_essai(&[("pages/common/tar.md", 8, b"# tar\n\n> Archiver.\n")]);
        let mut crc = bonne.clone();
        let central = crc.windows(4).position(|f| f == 0x0201_4b50u32.to_le_bytes()).unwrap();
        crc[central + 16] ^= 1;
        assert_eq!(intacte(&bonne, 1), Ok(1));
        assert!(intacte(&crc, 0).is_err());
        assert!(intacte(b"pas un zip", 0).is_err());
    }

    /// L'écriture du programme, celle de la clé.
    const POSER: fn(&Path, &[u8], Option<SystemTime>) -> std::io::Result<()> = crate::socle::ecrire_atomique_date;

    fn dossier_d_essai() -> PathBuf {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::create_dir_all(d.join("cle")).unwrap();
        std::fs::create_dir_all(d.join("local")).unwrap();
        d
    }

    fn il_y_a(heures: u64) -> SystemTime {
        SystemTime::now() - Duration::from_hours(heures)
    }

    fn ecrire_date(chemin: &Path, octets: &[u8], date: SystemTime) {
        std::fs::write(chemin, octets).unwrap();
        std::fs::File::options()
            .write(true)
            .open(chemin)
            .unwrap()
            .set_modified(date)
            .unwrap();
    }

    #[test]
    fn archive_fraiche_et_intacte_de_la_cle_pas_touchee() {
        let d = dossier_d_essai();
        let cle = d.join("cle");
        for l in LANGUES {
            ecrire_date(
                &cle.join(nom_d_archive(l)),
                &archive_de(minimum(l), "fraiche"),
                il_y_a(2),
            );
        }
        let appels = Cell::new(0);
        let local = d.join("local");
        assert!(mettre_a_jour(
            &cle,
            |l| local.join(nom_d_archive(l)),
            |_| {
                appels.set(appels.get() + 1);
                None
            },
            POSER
        ));
        assert_eq!(appels.get(), 0);
        assert_eq!(
            std::fs::read(cle.join("tldr-pages.en.zip")).unwrap(),
            archive_de(5000, "fraiche")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une archive « fraîche » posée sur la clé par un ordinateur piégé : abîmée (ou pas un zip), ou datée dans le
    /// futur. Elle était gardée sans être relue ; elle est contrôlée, refusée, remplacée par une archive intacte
    /// (même plus ancienne qu'elle), ou retirée si rien ne la remplace.
    #[test]
    fn archive_fraiche_abimee_ou_du_futur_refusee() {
        let d = dossier_d_essai();
        let (cle, local) = (d.join("cle"), d.join("local"));
        // Anglais : pas un zip, d'il y a deux heures ; une copie locale intacte de 30 h la remplace.
        ecrire_date(&cle.join("tldr-pages.en.zip"), b"pas un zip", il_y_a(2));
        let anglais = archive_de(5000, "locale");
        ecrire_date(&local.join("tldr-pages.en.zip"), &anglais, il_y_a(30));
        // Français : intact mais daté d'une semaine dans le futur, rien pour le remplacer : refusé comme référence,
        // gardé (une horloge en retard ne fait pas perdre une bonne archive) ; abîmé et sans remplaçante : retiré.
        let futur = SystemTime::now() + Duration::from_hours(7 * 24);
        ecrire_date(&cle.join("tldr-pages.fr.zip"), &archive_de(500, "futur"), futur);
        let appels = Cell::new(0);
        assert!(mettre_a_jour(
            &cle,
            |l| local.join(nom_d_archive(l)),
            |_| {
                appels.set(appels.get() + 1);
                None
            },
            POSER
        ));
        assert_eq!(
            appels.get(),
            2,
            "les deux refusées : un téléchargement essayé pour chacune"
        );
        assert_eq!(std::fs::read(cle.join("tldr-pages.en.zip")).unwrap(), anglais);
        assert_eq!(
            std::fs::read(cle.join("tldr-pages.fr.zip")).unwrap(),
            archive_de(500, "futur")
        );
        // Abîmée, fraîche, sans remplaçante : retirée.
        ecrire_date(&cle.join("tldr-pages.fr.zip"), b"pas un zip", il_y_a(1));
        assert!(mettre_a_jour(&cle, |l| local.join(nom_d_archive(l)), |_| None, POSER));
        assert!(!cle.join("tldr-pages.fr.zip").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn copie_locale_plus_recente_copiee_avec_sa_date() {
        let d = dossier_d_essai();
        let (cle, local) = (d.join("cle"), d.join("local"));
        let anglais = archive_de(5000, "locale");
        let francais = archive_de(500, "locale");
        let date = il_y_a(30);
        ecrire_date(&local.join("tldr-pages.en.zip"), &anglais, date);
        ecrire_date(&local.join("tldr-pages.fr.zip"), &francais, date);
        // Sur la clé : une anglaise plus ancienne que la copie locale, pas de française.
        ecrire_date(&cle.join("tldr-pages.en.zip"), b"vieille", il_y_a(100));
        assert!(mettre_a_jour(&cle, |l| local.join(nom_d_archive(l)), |_| None, POSER));
        assert_eq!(std::fs::read(cle.join("tldr-pages.en.zip")).unwrap(), anglais);
        assert_eq!(std::fs::read(cle.join("tldr-pages.fr.zip")).unwrap(), francais);
        let copiee = date_de(&cle.join("tldr-pages.en.zip")).unwrap();
        let ecart = copiee.duration_since(date).unwrap_or_else(|e| e.duration());
        assert!(ecart < Duration::from_secs(2), "{ecart:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn copie_locale_plus_ancienne_rien_ne_change() {
        let d = dossier_d_essai();
        let (cle, local) = (d.join("cle"), d.join("local"));
        for l in LANGUES {
            ecrire_date(
                &local.join(nom_d_archive(l)),
                &archive_de(minimum(l), "locale"),
                il_y_a(200),
            );
            ecrire_date(&cle.join(nom_d_archive(l)), &archive_de(minimum(l), "cle"), il_y_a(100));
        }
        assert!(mettre_a_jour(&cle, |l| local.join(nom_d_archive(l)), |_| None, POSER));
        assert_eq!(
            std::fs::read(cle.join("tldr-pages.en.zip")).unwrap(),
            archive_de(5000, "cle")
        );
        assert_eq!(
            std::fs::read(cle.join("tldr-pages.fr.zip")).unwrap(),
            archive_de(500, "cle")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn telechargement_abime_la_bonne_archive_reste_et_le_reste_part() {
        let d = dossier_d_essai();
        let (cle, local) = (d.join("cle"), d.join("local"));
        let bonne = archive_de(5000, "bonne");
        ecrire_date(&cle.join("tldr-pages.en.zip"), &bonne, il_y_a(48));
        // Les restes d'une copie interrompue : du script d'avant, de l'écriture atomique ; un autre fichier reste.
        std::fs::write(cle.join("tldr-pages.en.zip.nouveau"), b"reste").unwrap();
        std::fs::write(cle.join("tldr-pages.fr.tmp-12-0-0123456789abcdef"), b"reste").unwrap();
        std::fs::write(cle.join("LISEZMOI.tmp-1"), b"autre").unwrap();
        // Le téléchargement anglais est tronqué ; le français arrive intact.
        let francais = archive_de(500, "telechargee");
        assert!(mettre_a_jour(
            &cle,
            |l| local.join(nom_d_archive(l)),
            |l| {
                Some(if l == "en" {
                    bonne[..bonne.len() - 10].to_vec()
                } else {
                    francais.clone()
                })
            },
            POSER
        ));
        assert_eq!(std::fs::read(cle.join("tldr-pages.en.zip")).unwrap(), bonne);
        assert_eq!(std::fs::read(cle.join("tldr-pages.fr.zip")).unwrap(), francais);
        assert!(!cle.join("tldr-pages.en.zip.nouveau").exists());
        assert!(!cle.join("tldr-pages.fr.tmp-12-0-0123456789abcdef").exists());
        assert!(cle.join("LISEZMOI.tmp-1").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn copie_qui_echoue_la_cle_garde_son_archive_et_l_autre_langue_passe() {
        let d = dossier_d_essai();
        let (cle, local) = (d.join("cle"), d.join("local"));
        ecrire_date(&cle.join("tldr-pages.en.zip"), b"de la cle", il_y_a(48));
        let (anglais, francais) = (archive_de(5000, "en"), archive_de(500, "fr"));
        // La clé pleine, pour l'anglais seulement.
        assert!(!mettre_a_jour(
            &cle,
            |l| local.join(nom_d_archive(l)),
            |l| Some(if l == "en" { anglais.clone() } else { francais.clone() }),
            |fin, octets, date| {
                if fin.ends_with("tldr-pages.en.zip") {
                    return Err(std::io::Error::other("clé pleine"));
                }
                POSER(fin, octets, date)
            }
        ));
        assert_eq!(std::fs::read(cle.join("tldr-pages.en.zip")).unwrap(), b"de la cle");
        assert_eq!(std::fs::read(cle.join("tldr-pages.fr.zip")).unwrap(), francais);
        let _ = std::fs::remove_dir_all(&d);
    }
}
