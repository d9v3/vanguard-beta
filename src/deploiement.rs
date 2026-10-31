//! Les étapes de `outils/deployer.sh` confiées au programme (`vanguard deploiement …`, commande cachée) : elles
//! étaient en bash et en Python, à côté d'un code Rust qui faisait la même chose et pouvait en diverger. Le programme
//! n'écrit rien de lui-même : chaque étape n'est lancée que par le déploiement, sur l'ordinateur de l'auteur.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::ui::*;

mod binaire;

/// Une étape du déploiement.
#[derive(clap::Subcommand)]
pub(crate) enum Etape {
    /// Mettre à jour les archives de tldr-pages de la clé (anglais, français), vérifiées comme zipfile.testzip.
    Tldr {
        /// Le dossier tldr de la clé.
        dossier: PathBuf,
    },
    /// Vérifier les protections d'un programme livré, lu sans être lancé (`binaire`) : Linux (ELF x86-64 : PIE,
    /// statique, marque RELRO, pile non exécutable, rien d'écrivable et exécutable), Windows (PE32+ AMD64 : DLL
    /// importées depuis System32, manifeste UTF-8 et asInvoker, ASLR, DEP, relocalisations) et Mac (Mach-O universel
    /// arm64 et x86_64, chaque tranche). Une architecture qu'on ne livre pas est refusée. Réussit seulement si tous
    /// les fichiers passent.
    #[command(name = "verifier-binaire")]
    VerifierBinaire {
        /// Le système de chaque fichier : un autre format est refusé (un programme Linux posé à la place du .exe
        /// porterait toutes ses protections, et ne démarrerait pas sous Windows).
        #[arg(long, value_enum)]
        attendu: Option<Systeme>,
        /// Les programmes compilés.
        #[arg(required = true)]
        fichiers: Vec<PathBuf>,
    },
    /// L'ancien nom (un deployer.sh d'avant l'appelle encore), qui ne vérifiait que des .exe : le format Windows y est
    /// imposé, comme `verifier-binaire --attendu windows`.
    #[command(name = "verifier-pe", hide = true)]
    VerifierPe {
        /// Les programmes Windows compilés.
        #[arg(required = true)]
        fichiers: Vec<PathBuf>,
    },
    /// Écrire les témoins de la clé : son jeton d'identité (tiré une fois) et l'empreinte de cet ordinateur.
    Temoins {
        /// La racine de la clé.
        racine: PathBuf,
    },
    /// La racine de la clé VANGUARD de cet ordinateur : le volume monté au témoin vanguard.cle dont le jeton est connu
    /// ici, comme le programme la reconnaît. Rien (code 0) sans volume au témoin ; code 3 quand des volumes portent le
    /// témoin sans jeton connu, 4 quand plusieurs portent le même jeton connu (une copie de la clé) ; dits sur la sortie
    /// d'erreur : rien ne doit y être écrit.
    Cle,
    /// Avant d'écrire sur la clé : elle doit être exactement sa référence (manifeste). Code 2 : elle a changé (l'écart
    /// est dit) ; 3 : pas de référence pour elle ici.
    #[command(name = "comparer-cle")]
    ComparerCle {
        /// La racine de la clé.
        racine: PathBuf,
        /// Le déploiement d'avant s'est arrêté en route (son repère est resté) : ses propres fichiers à moitié
        /// écrits ne comptent pas, tout le reste si.
        #[arg(long)]
        reprise: bool,
    },
    /// Relire en entier une image de ISO/ (la moins récemment relue) et comparer son SHA-256 à la référence. Code 2 :
    /// l'image a été remplacée (notée dans la référence : le bilan la dit modifiée).
    #[command(name = "relire-image")]
    RelireImage {
        /// La racine de la clé.
        racine: PathBuf,
        /// « NOM=SHA256 » d'une image vérifiée du cache, pour une image que la référence a sans empreinte.
        #[arg(long)]
        empreinte: Vec<String>,
    },
}

/// Le système d'un programme livré, que le script qui le vérifie annonce (`--attendu`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Systeme {
    Linux,
    Windows,
    Macos,
}

/// 0 : l'étape a réussi ; 1 : elle a échoué, et l'a dit.
pub(crate) fn executer(etape: Etape) -> i32 {
    let reussi = match etape {
        Etape::Tldr { dossier } => crate::guide::tldr_sur_la_cle(&dossier),
        Etape::VerifierBinaire { attendu, fichiers } => binaire::verifier(&fichiers, attendu),
        Etape::VerifierPe { fichiers } => binaire::verifier(&fichiers, Some(Systeme::Windows)),
        Etape::Temoins { racine } => match temoins(&racine, crate::machine::empreinte_machine()) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("{e}");
                false
            }
        },
        Etape::Cle => return cle(),
        Etape::ComparerCle { racine, reprise } => return comparer_cle(&racine, reprise),
        Etape::RelireImage { racine, empreinte } => return relire_image(&racine, &empreinte),
    };
    i32::from(!reussi)
}

/// Pourquoi aucun volume n'est la clé où écrire.
#[derive(Debug, PartialEq)]
enum PasLaCle {
    /// Des volumes au témoin, aucun au jeton connu.
    Inconnus(Vec<PathBuf>),
    /// Plusieurs volumes au même jeton connu : une copie de la clé, dont rien ne dit laquelle est la vraie.
    MemeJeton(Vec<PathBuf>),
}

/// La clé connue parmi `volumes` (`Ok(Some)`), aucune (`Ok(None)` : aucun volume ne porte le témoin), ou pourquoi
/// aucun n'est retenu (`Err`). La règle du programme (`reseau::cle_usb`) : le témoin dit qu'un volume est fait comme
/// une clé, pas que c'est la sienne. Le jeton ne suffit pas non plus quand deux volumes le portent : une copie de la
/// clé (identifiant de volume compris, un numéro de série exFAT se réécrit) passerait pour elle selon l'ordre des
/// chemins (campagne d'attaque n° 4, C-B2) ; aucun des deux ne l'est alors.
fn cle_parmi(volumes: Vec<PathBuf>, jetons: &std::collections::BTreeSet<String>) -> Result<Option<PathBuf>, PasLaCle> {
    // La même clé vue par deux chemins n'est pas une copie d'elle-même (`reseau::sans_doublons`).
    let mut volumes = crate::reseau::sans_doublons(volumes);
    volumes.retain(|d| d.join(crate::reseau::TEMOIN_CLE).is_file());
    volumes.sort();
    let connues: Vec<(PathBuf, String)> = volumes
        .iter()
        .filter_map(|d| crate::protection::cles_connues::jeton_de(d).map(|j| (d.clone(), j)))
        .filter(|(_, j)| jetons.contains(j))
        .collect();
    if let Some((c, jeton)) = connues.first() {
        let memes: Vec<PathBuf> = connues
            .iter()
            .filter(|(_, j)| j == jeton)
            .map(|(d, _)| d.clone())
            .collect();
        return if memes.len() > 1 {
            Err(PasLaCle::MemeJeton(memes))
        } else {
            Ok(Some(c.clone()))
        };
    }
    if volumes.is_empty() {
        Ok(None)
    } else {
        Err(PasLaCle::Inconnus(volumes))
    }
}

fn cle() -> i32 {
    match cle_parmi(
        crate::reseau::volumes_montes(),
        &crate::protection::cles_connues::jetons(),
    ) {
        Ok(Some(c)) => {
            println!("{}", c.display());
            0
        }
        Ok(None) => 0,
        Err(PasLaCle::MemeJeton(copies)) => {
            for v in copies {
                eprintln!(
                    "{}",
                    trf!(
                        "Volume au même jeton qu'une autre clé branchée : {} (copie de la clé ? rien n'est écrit sur aucune ; n'en branchez qu'une)",
                        "Volume with the same token as another plugged-in key: {} (copy of the key? nothing is written to either; plug in only one)",
                        v.display()
                    )
                );
            }
            4
        }
        Err(PasLaCle::Inconnus(inconnus)) => {
            for v in inconnus {
                eprintln!(
                    "{}",
                    trf!(
                        "Volume au témoin de la clé, sans jeton connu de cet ordinateur : {} (rien n'y est écrit)",
                        "Volume with the key marker, without a token known to this computer: {} (nothing is written to it)",
                        v.display()
                    )
                );
            }
            3
        }
    }
}

fn comparer_cle(racine: &Path, reprise: bool) -> i32 {
    match crate::protection::manifeste::avant_deploiement(racine, reprise) {
        Ok(n) => {
            println!(
                "{}",
                trf!(
                    "✔ Clé identique à sa référence ({n} fichiers vérifiés).",
                    "✔ Key identical to its reference ({n} files checked)."
                )
            );
            0
        }
        Err((code, pourquoi)) => {
            eprintln!(
                "{}",
                trf!(
                    "✖ Clé différente de sa référence : {pourquoi}",
                    "✖ Key different from its reference: {pourquoi}"
                )
            );
            code
        }
    }
}

fn relire_image(racine: &Path, empreintes: &[String]) -> i32 {
    use crate::protection::manifeste::{Relecture, image_et_empreinte, relire_image};
    let empreintes: Result<Vec<_>, crate::modele::Echec> = empreintes.iter().map(|e| image_et_empreinte(e)).collect();
    let resultat = empreintes.and_then(|e| relire_image(racine, &e));
    match resultat {
        Ok(Relecture::Rien) => {
            println!(
                "{}",
                tr!(
                    "· Aucune image de la clé n'a d'empreinte à relire.",
                    "· No image on the key has a checksum to re-read."
                )
            );
            0
        }
        Ok(Relecture::Pareille(c)) => {
            println!(
                "{}",
                trf!(
                    "✔ {} relue en entier : l'image vérifiée, octet pour octet.",
                    "✔ {} re-read in full: the verified image, byte for byte.",
                    affichable(&c)
                )
            );
            0
        }
        Ok(Relecture::Differente(c)) => {
            // Le chemin sur la sortie : outils/images-cle.sh recopie l'image vérifiée.
            println!("{c}");
            eprintln!(
                "{}",
                trf!(
                    "✖ {} : autres octets que l'image vérifiée (même taille) ; remplacée sur la clé. Le bilan la dit modifiée.",
                    "✖ {}: different bytes from the verified image (same size); replaced on the key. The check-up reports it modified.",
                    affichable(&c)
                )
            );
            2
        }
        Ok(Relecture::Illisible(c)) => {
            eprintln!(
                "{}",
                trf!(
                    "· {} pas relue (illisible, clé retirée ?) : rien de conclu.",
                    "· {} not re-read (unreadable, key removed?): nothing concluded.",
                    affichable(&c)
                )
            );
            1
        }
        Err(e) => {
            eprintln!("{}", trf!("✖ Relecture impossible : {e}", "✖ Re-read impossible: {e}"));
            1
        }
    }
}

/// Ce que demande le manifeste du programme (ressource RT_MANIFEST n° 1, celle que Windows lit en le lançant), lu
/// comme du XML (quick-xml) et non cherché comme du texte : un « asInvoker » dans un commentaire, à côté d'un
/// requestedExecutionLevel à requireAdministrator, ne passe plus (campagne d'attaque n° 3). Les niveaux demandés
/// (attribut level de chaque requestedExecutionLevel) et les pages de code (texte de chaque activeCodePage), quel
/// que soit le préfixe d'espace de noms ; `None` si le XML est malformé ou démesuré.
fn lire_manifeste(octets: &[u8]) -> Option<(Vec<String>, Vec<String>)> {
    use quick_xml::events::Event;
    let texte = std::str::from_utf8(octets.strip_prefix(b"\xef\xbb\xbf").unwrap_or(octets)).ok()?;
    let mut lecteur = quick_xml::Reader::from_str(texte);
    let (mut niveaux, mut pages) = (Vec::new(), Vec::new());
    let mut page: Option<String> = None;
    // Les éléments ouverts : un manifeste tronqué (racine jamais fermée) est malformé.
    let mut ouverts = 0usize;
    for _ in 0..100_000 {
        let evenement = lecteur.read_event().ok()?;
        match &evenement {
            Event::Start(_) => ouverts += 1,
            Event::End(_) => ouverts = ouverts.checked_sub(1)?,
            _ => {}
        }
        match evenement {
            Event::Eof => return (page.is_none() && ouverts == 0).then_some((niveaux, pages)),
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == "requestedExecutionLevel" => {
                let mut level = String::new();
                for a in e.attributes() {
                    let a = a.ok()?;
                    if a.key.local_name().as_ref() == "level" {
                        level = a.value.to_string();
                    }
                }
                niveaux.push(level);
            }
            Event::Start(e) if e.local_name().as_ref() == "activeCodePage" => page = Some(String::new()),
            Event::Empty(e) if e.local_name().as_ref() == "activeCodePage" => pages.push(String::new()),
            Event::Text(t) => {
                if let Some(p) = page.as_mut() {
                    p.push_str(&t.xml10_content());
                }
            }
            Event::End(e) if e.local_name().as_ref() == "activeCodePage" => pages.push(page.take()?.trim().to_string()),
            _ => {}
        }
    }
    None
}

/// Les deux témoins de la clé, que le bash du déploiement écrivait à côté du code qui les relit :
/// - `vanguard.jeton` (`protection::cles_connues`), tiré une seule fois : 16 octets du hasard du système en 32
///   caractères hexadécimaux minuscules et un saut de ligne, comme `head -c 16 /dev/urandom | od`. Un jeton que le
///   programme lit déjà (`cles_connues::jeton_de`) est gardé tel quel, même en majuscules : cet ordinateur et la
///   partition des journaux le connaissent ainsi ;
/// - `vanguard.cle`, l'empreinte de cet ordinateur (`machine::empreinte_d_identifiant`, celle que la clé compare),
///   réécrit seulement s'il change (une écriture de moins sur la clé à chaque déploiement).
///
/// Chacun s'écrit à côté, sur le disque, puis prend sa place (`socle::ecrire_atomique`) : une clé retirée pendant
/// l'écriture ne garde pas un témoin à moitié écrit, qui la ferait prendre pour une autre. Sans empreinte lisible,
/// rien n'est écrit : un témoin faux remonterait la clé en lecture seule chez son propriétaire. `Ok(true)` : un jeton
/// a été tiré.
fn temoins(racine: &Path, empreinte: Option<String>) -> Result<bool, PasEcrit> {
    let empreinte = empreinte.ok_or(PasEcrit::SansEmpreinte)?;
    retirer_les_restes(racine);
    let jeton = crate::protection::cles_connues::JETON;
    let tire = crate::protection::cles_connues::jeton_de(racine).is_none();
    if tire {
        let mut octets = [0u8; 16];
        getrandom::fill(&mut octets).map_err(|e| PasEcrit::Fichier(jeton, std::io::Error::other(e.to_string())))?;
        let mut texte = String::with_capacity(33);
        for o in octets {
            let _ = write!(texte, "{o:02x}");
        }
        texte.push('\n');
        crate::socle::ecrire_atomique(&racine.join(jeton), texte.as_bytes())
            .map_err(|e| PasEcrit::Fichier(jeton, e))?;
        // Le jeton lui-même n'est pas affiché : il identifie la clé, et la sortie du déploiement se garde.
        println!(
            "{}",
            trf!(
                "Jeton de la clé tiré : {}",
                "Key token drawn: {}",
                racine.join(jeton).display()
            )
        );
    }
    let temoin = racine.join(crate::reseau::TEMOIN_CLE);
    let attendu = format!("{empreinte}\n");
    if crate::socle::lire_ordinaire(&temoin, 256).ok().as_deref() != Some(attendu.as_bytes()) {
        crate::socle::ecrire_atomique(&temoin, attendu.as_bytes())
            .map_err(|e| PasEcrit::Fichier(crate::reseau::TEMOIN_CLE, e))?;
    }
    Ok(tire)
}

/// Les temporaires d'une écriture de témoin interrompue (clé retirée, déploiement arrêté) : `vanguard.tmp-…`, que le
/// manifeste de la clé compterait sinon. Seulement des fichiers ordinaires de cette forme, à la racine.
fn retirer_les_restes(racine: &Path) {
    let Ok(fichiers) = std::fs::read_dir(racine) else {
        return;
    };
    for f in fichiers.flatten() {
        let nom = f.file_name().to_string_lossy().into_owned();
        if nom.starts_with("vanguard.tmp-") && f.file_type().is_ok_and(|t| t.is_file()) {
            let _ = std::fs::remove_file(f.path());
        }
    }
}

/// Pourquoi les témoins ne sont pas écrits.
#[derive(Debug)]
enum PasEcrit {
    /// L'empreinte de cet ordinateur ne se lit pas : rien n'est écrit.
    SansEmpreinte,
    /// Ce témoin n'a pas pu s'écrire sur la clé.
    Fichier(&'static str, std::io::Error),
}

impl std::fmt::Display for PasEcrit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasEcrit::SansEmpreinte => f.write_str(tr!(
                "✖ Empreinte de cet ordinateur illisible : témoins de la clé non écrits",
                "✖ This computer's fingerprint is unreadable: key markers not written"
            )),
            PasEcrit::Fichier(nom, e) => f.write_str(&trf!(
                "✖ {nom} non écrit sur la clé : {e}",
                "✖ {nom} not written to the key: {e}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::essais::gardes_d_essai;

    fn dossier() -> PathBuf {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const MANIFESTE_D_ESSAI: &[u8] = br#"<assembly><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security><windowsSettings><activeCodePage>UTF-8</activeCodePage></windowsSettings></assembly>"#;

    /// `--attendu` lu pour tous les fichiers de l'appel ; l'ancien nom reste accepté (un deployer.sh d'avant l'appelle
    /// encore) et n'admet que des programmes Windows ; sans fichier, refusé avant toute lecture.
    #[test]
    fn verifier_binaire_et_son_ancien_nom() {
        #[derive(clap::Parser)]
        struct Essai {
            #[command(subcommand)]
            etape: Etape,
        }
        use clap::Parser as _;
        let deux = [PathBuf::from("a"), PathBuf::from("b.exe")];
        let e = Essai::try_parse_from(["vanguard", "verifier-binaire", "a", "b.exe"]).unwrap();
        assert!(matches!(&e.etape, Etape::VerifierBinaire { attendu: None, fichiers } if fichiers == &deux));
        for (valeur, systeme) in [
            ("linux", Systeme::Linux),
            ("windows", Systeme::Windows),
            ("macos", Systeme::Macos),
        ] {
            let e = Essai::try_parse_from(["vanguard", "verifier-binaire", "--attendu", valeur, "a", "b.exe"]).unwrap();
            assert!(
                matches!(&e.etape, Etape::VerifierBinaire { attendu: Some(s), fichiers } if *s == systeme && fichiers == &deux),
                "{valeur}"
            );
        }
        assert!(Essai::try_parse_from(["vanguard", "verifier-binaire", "--attendu", "android", "a"]).is_err());
        let e = Essai::try_parse_from(["vanguard", "verifier-pe", "a", "b.exe"]).unwrap();
        assert!(matches!(&e.etape, Etape::VerifierPe { fichiers } if fichiers == &deux));
        for nom in ["verifier-binaire", "verifier-pe"] {
            assert!(Essai::try_parse_from(["vanguard", nom]).is_err(), "{nom} sans fichier");
        }
    }

    /// verifier-pe impose le format Windows : un programme Linux, protégé, y est refusé ; vanguard.exe passe.
    #[test]
    fn verifier_pe_n_admet_que_windows() {
        let d = dossier();
        let linux = d.join("vanguard");
        std::fs::write(
            &linux,
            crate::analyse::elf::essais::elf64_durci(crate::analyse::elf::essais::Durci::COMPLET),
        )
        .unwrap();
        let exe = d.join("vanguard.exe");
        std::fs::write(
            &exe,
            gardes_d_essai(Some((148, 148, 0x800)), Some(MANIFESTE_D_ESSAI), 1),
        )
        .unwrap();
        assert_eq!(
            executer(Etape::VerifierBinaire {
                attendu: None,
                fichiers: vec![linux.clone(), exe.clone()]
            }),
            0
        );
        assert_eq!(
            executer(Etape::VerifierPe {
                fichiers: vec![exe.clone()]
            }),
            0
        );
        assert_eq!(
            executer(Etape::VerifierPe {
                fichiers: vec![linux.clone()]
            }),
            1
        );
        assert_eq!(
            executer(Etape::VerifierBinaire {
                attendu: Some(Systeme::Windows),
                fichiers: vec![exe, linux]
            }),
            1
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn verifier_binaire_garde_les_controles_de_verifier_pe() {
        let d = dossier();
        let essai = |nom: &str, octets: Vec<u8>| {
            let chemin = d.join(nom);
            std::fs::write(&chemin, octets).unwrap();
            binaire::verifier(&[chemin], None)
        };
        let bon = d.join("bon.exe");
        std::fs::write(
            &bon,
            gardes_d_essai(Some((148, 148, 0x800)), Some(MANIFESTE_D_ESSAI), 1),
        )
        .unwrap();
        assert!(binaire::verifier(std::slice::from_ref(&bon), None));
        assert_eq!(
            executer(Etape::VerifierBinaire {
                attendu: None,
                fichiers: vec![bon]
            }),
            0
        );
        // DependentLoadFlags absent, autre, ou pas couvert par l'une des deux tailles.
        assert!(!essai("sans.exe", gardes_d_essai(None, Some(MANIFESTE_D_ESSAI), 1)));
        assert!(!essai(
            "zero.exe",
            gardes_d_essai(Some((148, 148, 0)), Some(MANIFESTE_D_ESSAI), 1)
        ));
        assert!(!essai(
            "court.exe",
            gardes_d_essai(Some((64, 148, 0x800)), Some(MANIFESTE_D_ESSAI), 1)
        ));
        assert!(!essai(
            "repertoire.exe",
            gardes_d_essai(Some((148, 64, 0x800)), Some(MANIFESTE_D_ESSAI), 1)
        ));
        // Manifeste absent, incomplet, ou sous un autre numéro que celui que Windows lit.
        assert!(!essai(
            "sans-manifeste.exe",
            gardes_d_essai(Some((148, 148, 0x800)), None, 1)
        ));
        let sans_utf8 = String::from_utf8_lossy(MANIFESTE_D_ESSAI).replace("UTF-8", "Latin1");
        assert!(!essai(
            "latin1.exe",
            gardes_d_essai(Some((148, 148, 0x800)), Some(sans_utf8.as_bytes()), 1)
        ));
        let administrateur = String::from_utf8_lossy(MANIFESTE_D_ESSAI).replace("asInvoker", "requireAdministrator");
        assert!(!essai(
            "admin.exe",
            gardes_d_essai(Some((148, 148, 0x800)), Some(administrateur.as_bytes()), 1)
        ));
        assert!(!essai(
            "autre-numero.exe",
            gardes_d_essai(Some((148, 148, 0x800)), Some(MANIFESTE_D_ESSAI), 2)
        ));
        // Campagne 3 : un asInvoker en commentaire à côté d'un requireAdministrator, deux niveaux, UTF-8 en
        // commentaire seulement, du XML malformé : refusés (la recherche de texte les laissait passer).
        let piege = String::from_utf8_lossy(MANIFESTE_D_ESSAI).replace(
            r#"<requestedExecutionLevel level="asInvoker" uiAccess="false"/>"#,
            r#"<!-- <requestedExecutionLevel level="asInvoker" --><requestedExecutionLevel level="requireAdministrator"/>"#,
        );
        assert!(!essai(
            "commentaire.exe",
            gardes_d_essai(Some((148, 148, 0x800)), Some(piege.as_bytes()), 1)
        ));
        let deux = String::from_utf8_lossy(MANIFESTE_D_ESSAI).replace(
            "</requestedPrivileges>",
            r#"<requestedExecutionLevel level="requireAdministrator"/></requestedPrivileges>"#,
        );
        assert!(!essai(
            "deux-niveaux.exe",
            gardes_d_essai(Some((148, 148, 0x800)), Some(deux.as_bytes()), 1)
        ));
        let page_en_commentaire = String::from_utf8_lossy(MANIFESTE_D_ESSAI).replace(
            "<activeCodePage>UTF-8</activeCodePage>",
            "<!-- >UTF-8</activeCodePage> -->",
        );
        assert!(!essai(
            "page-commentee.exe",
            gardes_d_essai(Some((148, 148, 0x800)), Some(page_en_commentaire.as_bytes()), 1)
        ));
        let malforme = String::from_utf8_lossy(MANIFESTE_D_ESSAI).replace("</assembly>", "");
        assert!(!essai(
            "malforme.exe",
            gardes_d_essai(Some((148, 148, 0x800)), Some(malforme.as_bytes()), 1)
        ));
        // Avec espaces de noms (préfixes), comme le vrai : accepté.
        let prefixe = br#"<v1:assembly xmlns:v1="urn:a"><v1:security><v1:requestedExecutionLevel level="asInvoker"/></v1:security><v3:windowsSettings xmlns:v3="urn:b"><activeCodePage xmlns="urn:c">UTF-8</activeCodePage></v3:windowsSettings></v1:assembly>"#;
        assert!(essai(
            "prefixes.exe",
            gardes_d_essai(Some((148, 148, 0x800)), Some(prefixe), 1)
        ));
        // Les deux textes ailleurs que dans le manifeste (une chaîne du programme) : pas un manifeste.
        let mut ailleurs = gardes_d_essai(Some((148, 148, 0x800)), None, 1);
        ailleurs.extend_from_slice(MANIFESTE_D_ESSAI);
        assert!(!essai("ailleurs.exe", ailleurs));
        // Pas un PE, absent, ou un dossier : refusé, jamais compté comme vérifié.
        assert!(!essai("texte.exe", b"MZ pas un programme".to_vec()));
        assert!(!binaire::verifier(&[d.join("absent.exe")], None));
        assert!(!binaire::verifier(std::slice::from_ref(&d), None));
        assert_eq!(
            executer(Etape::VerifierBinaire {
                attendu: None,
                fichiers: vec![d.join("absent.exe")]
            }),
            1
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La valeur de `printf '%s' 0123456789abcdef0123456789abcdef | sha1sum`, calculée à côté : le témoin est le même
    /// octet pour octet que celui de l'ancien bash, avec ou sans saut de ligne final dans /etc/machine-id.
    const SHA1_DE_L_ESSAI: &str = "b1775a785f09a6ebaf2dc33d6eaeb98974d9cdb8";

    #[test]
    fn empreinte_comme_sha1sum() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            crate::machine::empreinte_d_identifiant(id).as_deref(),
            Some(SHA1_DE_L_ESSAI)
        );
        assert_eq!(
            crate::machine::empreinte_d_identifiant(&format!("{id}\n")).as_deref(),
            Some(SHA1_DE_L_ESSAI)
        );
        assert_eq!(crate::machine::empreinte_d_identifiant(" \n"), None);
    }

    #[test]
    fn temoins_jeton_tire_ou_garde() {
        let d = dossier();
        let empreinte = || crate::machine::empreinte_d_identifiant("0123456789abcdef0123456789abcdef");
        // Absent : tiré, 32 caractères hexadécimaux minuscules et un saut de ligne, relisible par le programme.
        assert!(matches!(temoins(&d, empreinte()), Ok(true)));
        let texte = std::fs::read_to_string(d.join("vanguard.jeton")).unwrap();
        assert_eq!(texte.len(), 33);
        assert!(texte.ends_with('\n'));
        assert!(texte[..32].chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_eq!(
            crate::protection::cles_connues::jeton_de(&d).as_deref(),
            Some(&texte[..32])
        );
        assert_eq!(
            std::fs::read_to_string(d.join("vanguard.cle")).unwrap(),
            format!("{SHA1_DE_L_ESSAI}\n")
        );
        // Déjà là : gardé.
        assert!(matches!(temoins(&d, empreinte()), Ok(false)));
        assert_eq!(std::fs::read_to_string(d.join("vanguard.jeton")).unwrap(), texte);
        // Valide en majuscules : gardé tel quel.
        std::fs::write(d.join("vanguard.jeton"), "0123456789ABCDEF0123456789ABCDEF\n").unwrap();
        assert!(matches!(temoins(&d, empreinte()), Ok(false)));
        assert_eq!(
            std::fs::read_to_string(d.join("vanguard.jeton")).unwrap(),
            "0123456789ABCDEF0123456789ABCDEF\n"
        );
        // Invalide : retiré au profit d'un nouveau.
        std::fs::write(d.join("vanguard.jeton"), "pas un jeton\n").unwrap();
        assert!(matches!(temoins(&d, empreinte()), Ok(true)));
        assert!(crate::protection::cles_connues::jeton_de(&d).is_some());
        // Le reste d'une écriture interrompue est retiré ; aucun temporaire ne reste sur la clé.
        std::fs::write(d.join("vanguard.tmp-1-0-0123456789abcdef"), "tronq").unwrap();
        assert!(matches!(temoins(&d, empreinte()), Ok(false)));
        let restes: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .map(|f| f.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(restes.is_empty(), "{restes:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Campagne 3 : les scripts prenaient le premier volume au témoin vanguard.cle. Seul un volume au jeton connu est
    /// la clé ; un volume étranger, même au témoin, est dit, et rien n'y est écrit.
    #[test]
    fn cle_au_jeton_connu_seulement() {
        let d = dossier();
        let jeton = "0123456789abcdef0123456789abcdef";
        let volume = |nom: &str, jeton: Option<&str>| {
            let v = d.join(nom);
            std::fs::create_dir_all(&v).unwrap();
            std::fs::write(v.join("vanguard.cle"), "x\n").unwrap();
            if let Some(j) = jeton {
                std::fs::write(v.join("vanguard.jeton"), format!("{j}\n")).unwrap();
            }
            v
        };
        let etrangere = volume("VANGUARD", None);
        let autre_jeton = volume("VANGUARD1", Some("ffffffffffffffffffffffffffffffff"));
        let sans_temoin = d.join("PHOTOS");
        std::fs::create_dir_all(&sans_temoin).unwrap();
        let connus: std::collections::BTreeSet<String> = [jeton.to_string()].into();
        assert_eq!(cle_parmi(vec![sans_temoin.clone()], &connus), Ok(None));
        assert_eq!(
            cle_parmi(
                vec![etrangere.clone(), autre_jeton.clone(), sans_temoin.clone()],
                &connus
            ),
            Err(PasLaCle::Inconnus(vec![etrangere.clone(), autre_jeton.clone()]))
        );
        let la_mienne = volume("VANGUARD2", Some(&jeton.to_uppercase()));
        assert_eq!(
            cle_parmi(
                vec![
                    etrangere.clone(),
                    autre_jeton.clone(),
                    la_mienne.clone(),
                    sans_temoin.clone()
                ],
                &connus
            ),
            Ok(Some(la_mienne.clone()))
        );
        // Campagne 4, C-B2 : une copie au même jeton, triée avant ou après, ne fait choisir aucune des deux.
        let copie = volume("VANGUARD0", Some(jeton));
        assert_eq!(
            cle_parmi(vec![la_mienne.clone(), etrangere, copie.clone(), sans_temoin], &connus),
            Err(PasLaCle::MemeJeton(vec![copie, la_mienne.clone()]))
        );
        // La même clé vue par deux chemins (ici un lien, rangé avant elle) n'est pas une copie d'elle-même : elle
        // reste choisie, par son chemin.
        #[cfg(unix)]
        {
            let lien = d.join("VANGUARD1-lien");
            std::os::unix::fs::symlink(&la_mienne, &lien).unwrap();
            assert_eq!(
                cle_parmi(vec![lien.clone(), la_mienne.clone()], &connus),
                Ok(Some(la_mienne.clone()))
            );
            std::fs::remove_file(lien).unwrap();
        }
        // Une autre clé connue, à son propre jeton, n'est pas une copie : la première reste choisie.
        let deuxieme = "fedcba9876543210fedcba9876543210";
        let autre_cle = volume("VANGUARD3", Some(deuxieme));
        let deux: std::collections::BTreeSet<String> = [jeton.to_string(), deuxieme.to_string()].into();
        assert_eq!(
            cle_parmi(vec![autre_cle, la_mienne.clone()], &deux),
            Ok(Some(la_mienne))
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn temoins_sans_empreinte_rien_n_est_touche() {
        let d = dossier();
        std::fs::write(d.join("vanguard.cle"), "ancien\n").unwrap();
        assert!(temoins(&d, None).is_err());
        assert_eq!(std::fs::read_to_string(d.join("vanguard.cle")).unwrap(), "ancien\n");
        assert!(!d.join("vanguard.jeton").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
