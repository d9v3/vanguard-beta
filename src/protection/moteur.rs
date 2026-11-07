//! Le moteur d'analyse d'un fichier, commun aux analyses à la demande : le fichier est lu une seule fois par le socle
//! d'analyse (`analyse::analyser_fichier`), qui le découpe en parties (lui-même, les entrées de ses archives, les flux
//! d'un document OLE, la source de ses macros, les octets ajoutés après un exécutable…), et chaque partie passe aux
//! règles YARA : un programme caché dans un zip, ou une macro compressée dans un document Office, est vu comme s'il
//! était seul. Ce que le socle n'a pas pu lire (ses `manques` : format reconnu mais non ouvert, chiffré, coupé, borne
//! atteinte) est rendu « non vérifié », jamais compté sain.
//!
//! Les signatures ClamAV (`clamav`) et les heuristiques viendront s'y ajouter, partie par partie, avec le verdict
//! commun (lot AV4).

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::path::Path;
use std::time::{Duration, Instant};

use crate::analyse::{self, Bornes, Partie, Raison, Type};
use crate::protection::moteur_yara::Regles;
use crate::{tr, trf};

/// Ce que le moteur a vu dans un fichier lu.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Constat {
    /// Les rangs des règles YARA qui correspondent à une partie au moins, chacun une fois, dans l'ordre.
    pub(crate) regles: Vec<usize>,
    /// L'empreinte SHA-256 de chaque partie contenue dans le fichier (pas du fichier lui-même, qu'on cherche
    /// déjà parmi les empreintes connues), pour y trouver un logiciel malveillant connu caché dans une archive.
    pub(crate) contenues: Vec<[u8; 32]>,
    /// Ce qui n'a pas été lu, une phrase par manque (« archive.zip › doc.pdf : contenu PDF non ouvert »), prête à
    /// montrer. Vide : tout le fichier a été vérifié.
    pub(crate) non_verifie: Vec<String>,
}

/// Un manque du socle qui laisse une partie non vérifiée. Ni un format inconnu (ses octets sont passés tels quels aux
/// règles, comme avant le socle), ni une « quine » (le contenu, égal à l'un de ses ancêtres, a déjà été vérifié).
pub(crate) fn laisse_non_verifie(raison: &Raison) -> bool {
    !matches!(raison, Raison::FormatInconnu | Raison::Quine)
}

/// Le nom d'un format reconnu que Vanguard n'ouvre pas.
fn nom_du_format(t: Type) -> &'static str {
    match t {
        Type::ExecutableDos => tr!("programme DOS ou 16 bits", "DOS or 16-bit program"),
        Type::ClasseJava => tr!("classe Java", "Java class"),
        Type::PresentationPowerPoint => "PowerPoint",
        Type::SeptZip => "7z",
        Type::Rar => "RAR",
        Type::Cab => "CAB",
        Type::Iso => "ISO",
        Type::Bzip2 => "bzip2",
        Type::Xz => "xz",
        Type::Zstd => "zstd",
        Type::Lzip => "lzip",
        Type::Pdf => "PDF",
        Type::Rtf => "RTF",
        Type::OneNote => "OneNote",
        Type::Chm => "CHM",
        Type::Wim => "WIM",
        Type::DisqueVirtuel => tr!("disque virtuel", "virtual disk"),
        Type::Dmg => "DMG",
        Type::Xar => "XAR",
        Type::Ar => "ar",
        Type::Rpm => "RPM",
        Type::Cpio => "cpio",
        Type::SquashFs => "SquashFS",
        _ => tr!("ce format", "this format"),
    }
}

/// Un manque, en quelques mots.
pub(crate) fn raison(r: &Raison) -> String {
    match r {
        Raison::FormatInconnu => tr!("format inconnu", "unknown format").into(),
        Raison::FormatNonLu(t) => trf!("contenu {} non ouvert", "{} content not opened", nom_du_format(*t)),
        Raison::Chiffre => tr!("chiffré", "encrypted").into(),
        Raison::Tronque => tr!("coupé", "truncated").into(),
        Raison::Illisible(quoi) => trf!("structure illisible ({quoi})", "unreadable structure ({quoi})"),
        Raison::Methode(m) => trf!("méthode de compression {m} non lue", "compression method {m} not read"),
        Raison::TropGros => tr!("trop gros", "too large").into(),
        Raison::Profondeur => tr!("trop d'archives imbriquées", "too many nested archives").into(),
        Raison::TropDeParties => tr!("trop de parties", "too many parts").into(),
        Raison::Production => tr!("trop d'octets décompressés", "too many decompressed bytes").into(),
        Raison::TauxDeCompression => tr!("taux de compression d'une bombe", "compression ratio of a bomb").into(),
        Raison::Quine => tr!("se contient lui-même", "contains itself").into(),
        Raison::Delai => tr!("trop long à lire", "too slow to read").into(),
        Raison::EntreesLimitees => tr!("trop d'entrées", "too many entries").into(),
        Raison::CibleNonDecodee => tr!("cible du raccourci non décodée", "shortcut target not decoded").into(),
        Raison::SourceVbaIllisible => tr!("source de macro illisible", "unreadable macro source").into(),
        Raison::Travail => tr!("trop d'octets à examiner", "too many bytes to examine").into(),
        Raison::MacrosXlmNonDecodees => tr!("macros Excel 4.0 non décodées", "Excel 4.0 macros not decoded").into(),
        Raison::Paquete(p) => trf!("compressé par {p}, code non lu", "packed with {p}, code not read"),
        Raison::FinIntrouvable => tr!("fin du format introuvable", "end of format not found").into(),
        Raison::PcodeNonLu => tr!("code compilé de macro non lu", "compiled macro code not read").into(),
    }
}

/// Le fichier à `chemin`, lu par le socle d'analyse et chaque partie passée aux `regles`, le tout en moins de `delai`.
/// `Err` : le fichier n'a pas pu être lu (absent, illisible, lien, tube, pas un fichier ordinaire), ou les règles
/// n'ont pas fini à temps : rien n'est conclu. Une partie qui manque est dite dans `non_verifie`.
pub(crate) fn examiner(chemin: &Path, regles: &Regles, delai: Duration) -> Result<Constat, ()> {
    let echeance = Instant::now().checked_add(delai);
    let bornes = Bornes {
        delai,
        ..Bornes::default()
    };
    let mut vues = vec![false; regles.nombre()];
    let mut echec = false;
    let mut visiteur = |_: &Partie, octets: &[u8]| {
        if echec {
            return;
        }
        match regles.analyser_tampon(octets, echeance) {
            Ok(trouvees) => {
                for k in trouvees {
                    if let Some(v) = vues.get_mut(k) {
                        *v = true;
                    }
                }
            }
            Err(_) => echec = true,
        }
    };
    let analyse = analyse::analyser_fichier(chemin, &bornes, &mut visiteur).map_err(|_| ())?;
    if echec {
        return Err(());
    }
    let mut non_verifie: Vec<String> = Vec::new();
    for (i, r) in analyse.manques() {
        if laisse_non_verifie(r) {
            let phrase = format!("{} : {}", analyse.chemin_complet(i), raison(r));
            if !non_verifie.contains(&phrase) {
                non_verifie.push(phrase);
            }
        }
    }
    Ok(Constat {
        regles: vues.iter().enumerate().filter(|(_, v)| **v).map(|(k, _)| k).collect(),
        contenues: analyse.parties.iter().skip(1).filter_map(|p| p.sha256).collect(),
        non_verifie,
    })
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
mod tests {
    use super::*;

    fn essai() -> Regles {
        let r = Regles::compiler(
            r##"rule Programme { strings: $a = "#!/bin/sh" $b = "vanguard-essai-moteur" condition: $a at 0 and $b }
               rule Texte { strings: $a = "vanguard-essai-texte" condition: $a }"##,
        );
        assert_eq!(r.refus(), []);
        r
    }

    /// Un script caché dans un zip, compressé : la règle qui exige « #! » au début le trouve dans sa partie, pas dans
    /// les octets compressés du zip. Son empreinte est rendue avec celle des autres parties.
    #[test]
    fn une_partie_cachee_dans_un_zip_est_vue() {
        let regles = essai();
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let programme = b"#!/bin/sh\necho vanguard-essai-moteur vanguard-essai-moteur vanguard-essai-moteur\n".to_vec();
        let zip = crate::archives::zip::essais::archive_controlee(&[
            ("facture.sh", 8, &programme),
            ("lisez-moi.txt", 0, b"rien"),
        ]);
        assert!(!zip.windows(21).any(|w| w == b"vanguard-essai-moteur"));
        let chemin = d.join("colis.zip");
        std::fs::write(&chemin, &zip).unwrap();
        let constat = examiner(&chemin, &regles, Duration::from_secs(30)).unwrap();
        assert_eq!(constat.regles, [0]);
        assert_eq!(constat.non_verifie, Vec::<String>::new());
        let empreinte: [u8; 32] = {
            use sha2::Digest;
            sha2::Sha256::digest(&programme).into()
        };
        assert!(constat.contenues.contains(&empreinte));
        // Le même programme seul : vu aussi, sans partie contenue.
        let seul = d.join("facture.sh");
        std::fs::write(&seul, &programme).unwrap();
        let constat = examiner(&seul, &regles, Duration::from_secs(30)).unwrap();
        assert_eq!(constat.regles, [0]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ce qui n'est pas ouvert (un 7z dans un zip) est dit non vérifié, avec son chemin ; un format inconnu, lu tel
    /// quel, ne l'est pas.
    #[test]
    fn un_contenu_non_ouvert_est_non_verifie() {
        let regles = essai();
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let sept = b"7z\xBC\xAF\x27\x1C\x00\x04 vanguard-essai-texte".to_vec();
        let zip = crate::archives::zip::essais::archive_controlee(&[("archive.7z", 0, &sept)]);
        let chemin = d.join("colis.zip");
        std::fs::write(&chemin, &zip).unwrap();
        let constat = examiner(&chemin, &regles, Duration::from_secs(30)).unwrap();
        assert_eq!(constat.regles, [1]);
        assert_eq!(constat.non_verifie.len(), 1, "{:?}", constat.non_verifie);
        assert!(
            constat.non_verifie[0].contains("colis.zip › archive.7z") && constat.non_verifie[0].contains("7z"),
            "{:?}",
            constat.non_verifie
        );
        let inconnu = d.join("donnees.bin");
        std::fs::write(&inconnu, [0x17_u8, 0x42, 0x99, 0x03, 0xEE, 0x10]).unwrap();
        assert_eq!(
            examiner(&inconnu, &regles, Duration::from_secs(30)).unwrap(),
            Constat::default()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un lien, un tube, un fichier absent : rien n'est lu, et c'est une erreur, jamais un constat vide.
    #[cfg(unix)]
    #[test]
    fn rien_de_lu_n_est_pas_un_constat() {
        let regles = essai();
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let vrai = d.join("vrai.txt");
        std::fs::write(&vrai, b"vanguard-essai-texte").unwrap();
        let lien = d.join("lien.txt");
        std::os::unix::fs::symlink(&vrai, &lien).unwrap();
        let tube = d.join("tube");
        crate::essais::tube_nomme(&tube).unwrap();
        assert_eq!(examiner(&vrai, &regles, Duration::from_secs(30)).unwrap().regles, [1]);
        for cible in [lien, tube, d.join("absent")] {
            assert!(
                examiner(&cible, &regles, Duration::from_secs(30)).is_err(),
                "{}",
                cible.display()
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Chaque manque se dit, dans les deux langues, et seuls le format inconnu et la quine ne laissent rien de non
    /// vérifié.
    #[test]
    fn chaque_manque_se_dit() {
        for r in [
            Raison::FormatInconnu,
            Raison::FormatNonLu(Type::Pdf),
            Raison::Chiffre,
            Raison::Tronque,
            Raison::Illisible("en-tête"),
            Raison::Methode(14),
            Raison::TropGros,
            Raison::Profondeur,
            Raison::TropDeParties,
            Raison::Production,
            Raison::TauxDeCompression,
            Raison::Quine,
            Raison::Delai,
            Raison::EntreesLimitees,
            Raison::CibleNonDecodee,
            Raison::SourceVbaIllisible,
            Raison::Travail,
            Raison::MacrosXlmNonDecodees,
            Raison::Paquete("UPX"),
            Raison::FinIntrouvable,
            Raison::PcodeNonLu,
        ] {
            assert_ne!(raison(&r), "");
            assert_eq!(
                laisse_non_verifie(&r),
                !matches!(r, Raison::FormatInconnu | Raison::Quine)
            );
        }
        assert!(raison(&Raison::FormatNonLu(Type::SeptZip)).contains("7z"));
    }
}
