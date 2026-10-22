//! Analyse YARA : 308 règles de ReversingLabs (rançongiciels, voleurs de mots de passe, chevaux de Troie, portes
//! dérobées…), intégrées au programme (assets/yara, outils/maj-yara.sh ; allégées par build.rs, de 2,7 Mo à 1,2 Mo,
//! sans en changer le sens) et appliquées par YARA-X, le moteur YARA écrit en Rust par VirusTotal (licence
//! BSD-3-Clause), compilé dans Vanguard : rien à installer, depuis la clé et sans Internet comme ailleurs. En
//! complément de l'antivirus : une règle décrit une famille entière, variantes comprises. Lecture seule : rien n'est
//! déplacé ni supprimé. Chaque fichier lu est aussi comparé aux empreintes de MalwareBazaar (`empreintes`) : là, c'est
//! un logiciel malveillant précis, reconnu sans doute possible.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use crate::protection::antivirus::{Examen, Portee};
use crate::protection::empreintes::{self, Empreintes};
use crate::ui::*;

const REGLES: &str = include_str!(concat!(env!("OUT_DIR"), "/reversinglabs.yara"));

/// Les fichiers plus gros ne sont pas lus (images disque, vidéos), mais dits : aucun des programmes que visent les
/// règles n'en approche, et les lire prendrait de longues minutes.
const TAILLE_MAX: u64 = 256 << 20;

/// Le temps laissé à chaque fichier, et le nombre de fichiers analysés ensemble.
const DELAI_PAR_FICHIER: Duration = Duration::from_secs(30);
const FILS: usize = 4;

/// Les règles, compilées une fois par lancement (une seconde et demie) ; les analyses suivantes les reprennent.
/// `Err` : elles ne se compilent pas, ce qu'un test empêche d'arriver jusqu'à une version livrée.
pub(crate) fn regles() -> Result<&'static yara_x::Rules, &'static str> {
    static COMPILEES: OnceLock<Result<yara_x::Rules, String>> = OnceLock::new();
    COMPILEES
        .get_or_init(|| {
            let mut compilateur = yara_x::Compiler::new();
            compilateur.add_source(REGLES).map_err(|e| e.to_string())?;
            Ok(compilateur.build())
        })
        .as_ref()
        .map_err(String::as_str)
}

/// Les endroits à risque : téléchargements, bureau, programmes lancés au démarrage (et le dossier temporaire sous
/// Windows, où atterrissent les programmes téléchargés).
pub(crate) fn endroits_a_risque() -> Vec<PathBuf> {
    let maison = crate::socle::maison();
    #[cfg(windows)]
    let mut liste: Vec<PathBuf> = ["Downloads", "Desktop"].iter().map(|d| maison.join(d)).collect();
    #[cfg(windows)]
    liste.extend(
        [
            std::env::var_os("APPDATA")
                .map(|a| PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
            std::env::var_os("TEMP").map(PathBuf::from),
        ]
        .into_iter()
        .flatten(),
    );
    #[cfg(unix)]
    let liste: Vec<PathBuf> = crate::protection::antivirus::ENDROITS_A_RISQUE
        .iter()
        .map(|d| maison.join(d))
        .collect();
    liste.into_iter().filter(|p| p.is_dir()).collect()
}

/// Une correspondance : la règle (« Win32_Ransomware_WannaCry ») et le fichier.
#[derive(Debug, PartialEq)]
struct Trouve {
    regle: String,
    /// Prêt à montrer.
    fichier: String,
    /// Tel quel, pour l'isoler.
    chemin: PathBuf,
}

impl Trouve {
    /// Le chemin, seulement montré, est rendu inoffensif : son nom est celui qu'a choisi l'auteur du fichier.
    fn nouveau(regle: &str, chemin: &Path) -> Trouve {
        Trouve {
            regle: regle.to_string(),
            fichier: affichable(&chemin.display().to_string()),
            chemin: chemin.to_path_buf(),
        }
    }
}

/// Les fichiers d'une cible, sans suivre les liens (pas de boucle, rien hors des dossiers choisis) ; les dossiers
/// illisibles s'ajoutent à `illisibles`, et les fichiers de plus de `TAILLE_MAX`, qui ne sont pas lus : ce qui n'a pas
/// été vérifié est dit.
fn fichiers(cible: &Path, illisibles: &mut Vec<PathBuf>) -> Vec<PathBuf> {
    let mut trouves = Vec::new();
    let mut a_voir = vec![cible.to_path_buf()];
    while let Some(chemin) = a_voir.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&chemin) else {
            illisibles.push(chemin);
            continue;
        };
        if meta.is_file() {
            if meta.len() <= TAILLE_MAX {
                trouves.push(chemin);
            } else {
                illisibles.push(chemin);
            }
        } else if meta.is_dir() {
            match std::fs::read_dir(&chemin) {
                Ok(entrees) => a_voir.extend(entrees.flatten().map(|e| e.path())),
                Err(_) => illisibles.push(chemin),
            }
        }
    }
    trouves
}

/// Les règles appliquées à des fichiers, par `FILS` fils, chacun avec son propre analyseur, et l'empreinte de chaque
/// fichier cherchée dans celles de MalwareBazaar : (correspondances, fichiers illisibles ou trop longs à lire).
fn analyser_fichiers(
    regles: &yara_x::Rules,
    empreintes: Option<&Empreintes>,
    liste: &[PathBuf],
) -> (Vec<Trouve>, Vec<PathBuf>) {
    par_lots(
        liste,
        || {
            let mut analyseur = yara_x::Scanner::new(regles);
            analyseur.set_timeout(DELAI_PAR_FICHIER);
            analyseur
        },
        |analyseur, f| match analyseur.scan_file(f) {
            Ok(r) => (
                r.matching_rules().map(|m| Trouve::nouveau(m.identifier(), f)).collect(),
                true,
            ),
            Err(_) => (Vec::new(), false),
        },
        // Le fichier vient d'être lu : il est encore en mémoire, l'empreinte coûte peu.
        |f| {
            empreintes
                .map(|e| empreintes::connus(e, std::slice::from_ref(f)))
                .unwrap_or_default()
                .into_iter()
                .map(|(chemin, e)| Trouve::nouveau(&format!("{MALWAREBAZAAR}{e}"), &chemin))
                .collect()
        },
    )
}

/// `liste` répartie en `FILS` lots, un fil par lot avec son propre analyseur (`nouveau`) ; `un` passe un fichier aux
/// règles : (correspondances, lu jusqu'au bout) ; `empreinte` le cherche ensuite parmi les empreintes connues. Un
/// fichier piégé peut faire paniquer YARA-X : il est alors rendu illisible, jamais sain, sans emporter les autres
/// fichiers de son lot, et l'analyseur, peut-être resté au milieu de l'analyse interrompue, n'est plus réutilisé.
/// L'empreinte, qui ne dépend pas de YARA-X, a sa propre garde : cherchée même après une panique des règles, elle
/// garde « logiciel malveillant connu » à un fichier de MalwareBazaar qui ferait aussi paniquer YARA-X, au lieu de
/// « impossible à vérifier ». Un fil qui tombe malgré tout (analyseur impossible à créer) rend tout son lot
/// illisible : jeté en silence, ce lot faisait conclure « sain » sans avoir été lu.
fn par_lots<A>(
    liste: &[PathBuf],
    nouveau: impl Fn() -> A + Sync,
    un: impl Fn(&mut A, &PathBuf) -> (Vec<Trouve>, bool) + Sync,
    empreinte: impl Fn(&PathBuf) -> Vec<Trouve> + Sync,
) -> (Vec<Trouve>, Vec<PathBuf>) {
    let (nouveau, un, empreinte) = (&nouveau, &un, &empreinte);
    let lots: Vec<&[PathBuf]> = liste.chunks(liste.len().div_ceil(FILS).max(1)).collect();
    std::thread::scope(|s| {
        let fils: Vec<_> = lots
            .into_iter()
            .map(|lot| {
                let fil = s.spawn(move || {
                    let mut analyseur = nouveau();
                    let (mut trouves, mut echecs) = (Vec::new(), Vec::new());
                    for f in lot {
                        let regles = crate::journal::rattraper(std::panic::AssertUnwindSafe(|| un(&mut analyseur, f)));
                        let connu = crate::journal::rattraper(std::panic::AssertUnwindSafe(|| empreinte(f)));
                        if !(matches!(regles, Ok((_, true))) && connu.is_ok()) {
                            echecs.push(f.clone());
                        }
                        match regles {
                            Ok((t, _)) => trouves.extend(t),
                            Err(_) => analyseur = nouveau(),
                        }
                        trouves.extend(connu.unwrap_or_default());
                    }
                    (trouves, echecs)
                });
                (lot, fil)
            })
            .collect();
        let (mut trouves, mut echecs) = (Vec::new(), Vec::new());
        for (lot, fil) in fils {
            match fil.join() {
                Ok((t, e)) => {
                    trouves.extend(t);
                    echecs.extend(e);
                }
                Err(_) => echecs.extend(lot.iter().cloned()),
            }
        }
        (trouves, echecs)
    })
}

/// Ce qui n'a pas pu être lu dans une cible, en une phrase : le nombre, et le premier pour exemple.
fn illisible(cible: &Path, echecs: &[PathBuf]) -> Option<String> {
    let premier = echecs.first()?;
    Some(trf!(
        "{} : {} élément(s) illisible(s), trop gros ou trop long(s) à lire, dont {}",
        "{}: {} item(s) unreadable, too large or too slow to read, including {}",
        chemin_affichable(cible),
        echecs.len(),
        chemin_affichable(premier)
    ))
}

/// Le début du nom d'une correspondance par empreinte : « MalwareBazaar sha256:<empreinte> ».
const MALWAREBAZAAR: &str = "MalwareBazaar sha256:";

/// La famille d'une règle de ReversingLabs, lue dans son nom (« ByteCode_MSIL_Ransomware_Apis »).
pub(crate) fn famille(regle: &str) -> &'static str {
    if regle.starts_with(MALWAREBAZAAR) {
        return tr!(
            "logiciel malveillant connu, empreinte exacte",
            "known malware, exact fingerprint"
        );
    }
    for morceau in regle.split('_') {
        let nom = match morceau {
            "Ransomware" => tr!("rançongiciel", "ransomware"),
            "Infostealer" => tr!("voleur de mots de passe", "password stealer"),
            "Trojan" => tr!("cheval de Troie", "trojan"),
            "Backdoor" => tr!("porte dérobée", "backdoor"),
            "Downloader" => tr!("téléchargeur de logiciels malveillants", "malware downloader"),
            "Exploit" => tr!("exploit d'une faille", "exploit"),
            "Rootkit" => tr!("rootkit", "rootkit"),
            "Virus" => tr!("virus", "virus"),
            _ => continue,
        };
        return nom;
    }
    tr!("logiciel malveillant", "malware")
}

/// Applique les 308 règles et les empreintes de MalwareBazaar aux cibles : (correspondances, ce qui n'a pas pu être
/// lu, les empreintes s'il y en avait). `None` : règles qui ne se compilent pas, ce qui est dit. Tout ce qui n'a pas
/// pu être lu est rendu : jamais compté comme sain.
fn appliquer(cibles: &[PathBuf]) -> Option<(Vec<Trouve>, Vec<String>, empreintes::Chargees)> {
    let regles = match regles() {
        Ok(r) => r,
        Err(e) => {
            println!(
                "  ✖ {}",
                trf!(
                    "Règles YARA impossibles à compiler : {e}",
                    "YARA rules could not be compiled: {e}"
                )
            );
            return None;
        }
    };
    let empreintes = empreintes::connues();
    let mut trouves = Vec::new();
    let mut erreurs = Vec::new();
    for cible in cibles {
        trp!("  Analyse de {}…", "  Scanning {}…", chemin_affichable(cible));
        let mut echecs = Vec::new();
        let liste = fichiers(cible, &mut echecs);
        let (t, e) = analyser_fichiers(regles, empreintes.ok(), &liste);
        trouves.extend(t);
        echecs.extend(e);
        erreurs.extend(illisible(cible, &echecs));
    }
    Some((trouves, erreurs, empreintes))
}

pub fn analyser(portee: &Portee) {
    titre(tr!("Analyse YARA", "YARA scan"));
    let cibles = match portee {
        Portee::Dossier(d) => vec![d.clone()],
        Portee::Complete => vec![crate::socle::maison()],
        Portee::Rapide => endroits_a_risque(),
    };
    if cibles.is_empty() {
        trp!("  Rien à analyser ici.", "  Nothing to scan here.");
        return;
    }
    let Some((trouves, erreurs, empreintes)) = appliquer(&cibles) else {
        return;
    };
    println!();
    match empreintes {
        Err(raison) => afficher_aligne(
            "  ⚠ ",
            &trf!(
                "Empreintes de MalwareBazaar {raison} : seules les 308 règles ont servi.",
                "MalwareBazaar fingerprints {raison}: only the 308 rules were used."
            ),
            4,
            "",
        ),
        Ok(Empreintes {
            avertissement: Some(a), ..
        }) => afficher_aligne("  ⚠ ", a, 4, ""),
        Ok(_) => {}
    }
    for e in &erreurs {
        for (i, ligne) in envelopper(
            &trf!(
                "Analyse incomplète, rien n'est conclu pour ce qui n'a pas été lu. {e}",
                "Incomplete scan, nothing is concluded for what was not read. {e}"
            ),
            LARGEUR - 4,
        )
        .iter()
        .enumerate()
        {
            println!("  {} {ligne}", if i == 0 { "⚠" } else { " " });
        }
    }
    if trouves.is_empty() {
        match (erreurs.is_empty(), empreintes.ok()) {
            (true, Some(e)) => trp!(
                "  {VERT}✔{RESET} Aucun fichier ne correspond aux 308 règles ni aux {} empreintes de MalwareBazaar.",
                "  {VERT}✔{RESET} No file matches the 308 rules or the {} MalwareBazaar fingerprints.",
                e.nombre()
            ),
            (true, None) => trp!(
                "  {VERT}✔{RESET} Aucun fichier ne correspond aux 308 règles.",
                "  {VERT}✔{RESET} No file matches the 308 rules."
            ),
            _ => {}
        }
        return;
    }
    for t in &trouves {
        let niveau = if t.regle.starts_with(MALWAREBAZAAR) {
            crate::risk::Niveau::Critique
        } else {
            crate::risk::Niveau::Eleve
        };
        println!("  {}✖{RESET} {}", couleur(niveau), t.fichier);
        println!("      {GRIS}{} ({}){RESET}", famille(&t.regle), t.regle);
    }
    println!();
    for ligne in envelopper(
        tr!(
            "Ne les ouvrez pas. Faites-les aussi analyser par l'antivirus (même menu). Une règle peut se tromper sur un fichier légitime : la quarantaine se défait, et en cas de doute, envoyez-le à VirusTotal.",
            "Do not open them. Have the antivirus scan them too (same menu). A rule can be wrong about a legitimate file: the quarantine can be undone, and when in doubt, upload it to VirusTotal."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    let mut a_isoler: Vec<(PathBuf, String)> = Vec::new();
    for t in &trouves {
        if t.chemin.is_file() && !a_isoler.iter().any(|(c, _)| *c == t.chemin) {
            let raison = if t.regle.starts_with(MALWAREBAZAAR) {
                t.regle.clone()
            } else {
                format!("YARA {}", t.regle)
            };
            a_isoler.push((t.chemin.clone(), raison));
        }
    }
    crate::protection::quarantaine::proposer(&a_isoler);
}

/// Un seul fichier, pour « Vérifier un fichier téléchargé » : le résultat, que l'appelant affiche.
pub(crate) fn examiner(fichier: &Path) -> Examen {
    match appliquer(&[fichier.to_path_buf()]) {
        None => Examen::Impossible(tr!("règles YARA inutilisables", "YARA rules unusable").into()),
        Some((trouves, _, _)) if !trouves.is_empty() => Examen::Trouve(
            trouves
                .iter()
                .map(|t| format!("{} ({})", famille(&t.regle), t.regle))
                .collect(),
        ),
        Some((_, erreurs, _)) if !erreurs.is_empty() => Examen::Impossible(erreurs.join(" ; ")),
        Some(_) => Examen::Sain,
    }
}

/// Menu Antivirus et protection › Analyse YARA : les endroits à risque, ou le dossier tapé.
pub fn menu() {
    let reponse = demander(tr!(
        "  Dossier à analyser (Entrée : téléchargements, bureau, démarrage) : ",
        "  Folder to scan (Enter: downloads, desktop, startup): "
    ));
    let reponse = reponse.trim().trim_matches(['"', '\'']);
    if reponse.is_empty() {
        analyser(&Portee::Rapide);
    } else {
        analyser(&Portee::Dossier(PathBuf::from(reponse)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regles_integrees() {
        assert!(REGLES.starts_with("// Règles YARA de ReversingLabs"));
        let regles = REGLES
            .lines()
            .filter(|l| l.trim_start().starts_with("rule ") || l.trim_start().starts_with("private rule "))
            .count();
        assert_eq!(regles, 308, "le message « 308 règles » doit suivre outils/maj-yara.sh");
    }

    const ORIGINE: &str = include_str!("../../assets/yara/reversinglabs.yara");

    /// Les noms des règles, dans l'ordre : chaque déclaration commence une ligne (« rule » paraît aussi dans les
    /// descriptions d'origine, « Yara rule that detects… »).
    fn noms(texte: &str) -> Vec<&str> {
        texte
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("rule "))
            .filter_map(|r| r.split([' ', ':']).next())
            .collect()
    }

    /// Chaque chaîne hexadécimale (« = { … } »), sans espaces, chaque saut fixe « [n] » redéveloppé en n « ?? » : la
    /// forme à laquelle l'origine et les règles allégées doivent se ramener.
    fn hexadecimales(texte: &str) -> Vec<String> {
        let mut liste = Vec::new();
        let mut reste = texte;
        while let Some(p) = reste.find('=') {
            reste = &reste[p + 1..];
            let Some(dedans) = reste.trim_start().strip_prefix('{') else {
                continue;
            };
            let fin = dedans.find('}').unwrap();
            let compact: String = dedans[..fin].chars().filter(|c| !c.is_whitespace()).collect();
            let mut forme = String::new();
            let mut morceaux = compact.split('[');
            forme.push_str(morceaux.next().unwrap_or_default());
            for m in morceaux {
                let (saut, apres) = m.split_once(']').unwrap();
                if let Ok(n) = saut.parse::<usize>() {
                    forme.push_str(&"??".repeat(n));
                } else {
                    forme.push('[');
                    forme.push_str(saut);
                    forme.push(']');
                }
                forme.push_str(apres);
            }
            liste.push(forme);
            reste = &dedans[fin..];
        }
        liste
    }

    /// Ce qui suit chaque « condition: », sans espaces, jusqu'à l'accolade qui ferme la règle (avant la règle suivante
    /// et ses imports).
    fn conditions(texte: &str) -> Vec<String> {
        texte
            .split("condition:")
            .skip(1)
            .map(|c| {
                let suite = c.find("\nrule ").unwrap_or(c.len());
                let fin = c[..suite].rfind('}').unwrap_or(suite);
                c[..fin].chars().filter(|x| !x.is_whitespace()).collect()
            })
            .collect()
    }

    #[test]
    fn regles_allegees_sans_changer_de_sens() {
        // Au moins deux fois plus légères : c'est la raison d'être de l'allègement.
        assert!(
            REGLES.len() * 2 < ORIGINE.len(),
            "{} contre {}",
            REGLES.len(),
            ORIGINE.len()
        );
        assert!(!REGLES.contains("meta:"));
        // L'en-tête (source et licence MIT) reste.
        assert!(REGLES.lines().nth(1).is_some_and(|l| l.contains("Licence MIT")));
        assert_eq!(noms(REGLES), noms(ORIGINE));
        let (allegees, origine) = (hexadecimales(REGLES), hexadecimales(ORIGINE));
        assert_eq!(allegees.len(), origine.len());
        for (a, o) in allegees.iter().zip(&origine) {
            assert_eq!(a, o);
        }
        assert_eq!(conditions(REGLES), conditions(ORIGINE));
        // Un module importé une seule fois.
        assert_eq!(REGLES.matches("import \"pe\"").count(), 1);
    }

    #[test]
    fn familles_des_regles() {
        assert_eq!(famille("Win32_Ransomware_WannaCry"), "rançongiciel");
        assert_eq!(famille("ByteCode_MSIL_Infostealer_RedLine"), "voleur de mots de passe");
        assert_eq!(famille("Linux_Inconnu_X"), "logiciel malveillant");
        // Le nom du fichier est celui que son auteur a choisi : piégé, il arrive inoffensif.
        let piege = Trouve::nouveau(
            "X",
            Path::new("/home/alice/fa\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}cture.exe"),
        );
        assert!(!piege.fichier.contains('\x1b') && !piege.fichier.contains('\u{202e}'));
    }

    /// Les 308 règles se compilent avec YARA-X : une règle refusée ne passe pas jusqu'à une version livrée.
    #[test]
    fn les_308_regles_se_compilent() {
        assert!(regles().is_ok(), "{:?}", regles().err());
    }

    /// Le fichier d'origine de ReversingLabs, tel qu'outils/maj-yara.sh le pose, sans l'allègement de build.rs, se
    /// compile aussi avec YARA-X, le moteur du programme, et donne autant de règles que la version allégée. Il remplace
    /// l'étape de la CI qui le passait à libyara (yara-python, installé par pip sans version épinglée) : un autre moteur
    /// pouvait accepter une règle que YARA-X refuse, ou l'inverse.
    #[test]
    fn les_regles_d_origine_se_compilent_avec_yara_x() {
        let mut compilateur = yara_x::Compiler::new();
        if let Err(e) = compilateur.add_source(ORIGINE) {
            panic!("règles d'origine refusées par YARA-X : {e}");
        }
        let origine = compilateur.build();
        assert_eq!(origine.iter().count(), regles().unwrap().iter().count());
    }

    /// Un dossier d'essai : un faux programme qui remplit une règle d'essai de même forme que celles de ReversingLabs
    /// (en-tête « MZ » et textes), un fichier ordinaire, un lien et un fichier creux trop gros, sautés.
    #[test]
    fn analyse_d_un_dossier() {
        let mut compilateur = yara_x::Compiler::new();
        compilateur
            .add_source(
                r#"rule Win32_Trojan_Essai { strings: $a = "vanguard-essai-yara" $b = { 4D 5A 90 } condition: uint16(0) == 0x5A4D and all of them }"#,
            )
            .unwrap();
        let essai = compilateur.build();
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::create_dir_all(dossier.join("sous")).unwrap();
        std::fs::write(dossier.join("sous/facture.exe"), b"MZ\x90\x00 vanguard-essai-yara").unwrap();
        std::fs::write(dossier.join("note.txt"), b"PK vanguard-essai-yara").unwrap();
        std::fs::File::create(dossier.join("image.iso"))
            .unwrap()
            .set_len(TAILLE_MAX + 1)
            .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dossier.join("sous/facture.exe"), dossier.join("lien.exe")).unwrap();
        let mut illisibles = Vec::new();
        let liste = fichiers(&dossier, &mut illisibles);
        assert_eq!(liste.len(), 2, "{liste:?}");
        let (trouves, echecs) = analyser_fichiers(&essai, None, &liste);
        // Le trop gros n'est pas lu, mais il est dit.
        assert!(
            illisibles.len() == 1 && illisibles[0].ends_with("image.iso"),
            "{illisibles:?}"
        );
        assert_eq!(echecs, Vec::<PathBuf>::new());
        assert_eq!(trouves.len(), 1);
        assert_eq!(trouves[0].regle, "Win32_Trojan_Essai");
        assert!(trouves[0].chemin.ends_with("sous/facture.exe"));
        assert_eq!(famille(&trouves[0].regle), "cheval de Troie");
        // Les vraies règles, sur le même dossier : rien.
        assert_eq!(analyser_fichiers(regles().unwrap(), None, &liste).0, []);
        // Avec l'empreinte de note.txt parmi celles de MalwareBazaar : trouvé par elle, sans règle.
        let note = dossier.join("note.txt");
        let connues = Empreintes::depuis(vec![empreintes::sha256(&note).unwrap()]);
        let par_empreinte = analyser_fichiers(regles().unwrap(), Some(&connues), &liste).0;
        assert_eq!(par_empreinte.len(), 1);
        assert_eq!(par_empreinte[0].chemin, note);
        assert!(
            par_empreinte[0].regle.starts_with(MALWAREBAZAAR)
                && par_empreinte[0].regle.len() == MALWAREBAZAAR.len() + 64
        );
        assert_eq!(
            famille(&par_empreinte[0].regle),
            "logiciel malveillant connu, empreinte exacte"
        );
        // Une cible qui n'existe pas : dite, pas comptée comme saine.
        let mut absents = Vec::new();
        assert_eq!(fichiers(&dossier.join("absent"), &mut absents), Vec::<PathBuf>::new());
        assert!(illisible(&dossier, &absents).is_some());
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Un PE réduit à l'essentiel, dont l'unique section commence à 0xFFFFFF00 pour 0x200 octets : sa fin dépasse un
    /// u32. YARA-X (1.21 comme 1.22) l'additionne sans contrôle dans pe.section_index, et les tests compilent avec le
    /// contrôle des débordements : l'analyse panique, comme sur un vrai fichier piégé.
    fn pe_dont_la_section_deborde() -> Vec<u8> {
        let mut pe = vec![0_u8; 0x200];
        pe[..2].copy_from_slice(b"MZ");
        // e_lfanew : l'en-tête PE suit l'en-tête DOS.
        pe[0x3C..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        pe[0x44..0x46].copy_from_slice(&0x014C_u16.to_le_bytes());
        pe[0x46..0x48].copy_from_slice(&1_u16.to_le_bytes());
        // Sans en-tête optionnel, la table des sections suit les 24 octets de l'en-tête PE : taille, puis position.
        pe[0x58..0x60].copy_from_slice(b".text\0\0\0");
        pe[0x68..0x6C].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[0x6C..0x70].copy_from_slice(&0xFFFF_FF00_u32.to_le_bytes());
        pe
    }

    /// Un fichier qui fait paniquer le vrai YARA-X n'est ni perdu ni dit sain. Avant, le fil emportait tout son lot (le
    /// piège et son voisin), et le piège examiné seul ne donnait ni correspondance ni échec : « sain ». Une version de
    /// YARA-X qui ne paniquerait plus lirait le piège, et l'essai tiendrait encore : chaque fichier est lu (la règle Tout
    /// correspond à tout fichier lu) ou dit illisible, jamais ni l'un ni l'autre.
    #[test]
    fn un_fichier_qui_fait_paniquer_yara_x_n_est_ni_perdu_ni_sain() {
        let mut compilateur = yara_x::Compiler::new();
        compilateur
            .add_source(
                r#"import "pe" rule Section { condition: pe.section_index(0) == 0 } rule Tout { condition: true }"#,
            )
            .unwrap();
        let essai = compilateur.build();
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let piege = dossier.join("piege.exe");
        std::fs::write(&piege, pe_dont_la_section_deborde()).unwrap();
        // Huit fichiers, quatre lots de deux : le piège ouvre le troisième, son voisin passe après lui.
        let mut liste: Vec<PathBuf> = (0..7)
            .map(|i| {
                let f = dossier.join(format!("note{i}.txt"));
                std::fs::write(&f, b"rien").unwrap();
                f
            })
            .collect();
        liste.insert(4, piege.clone());
        let (trouves, echecs) = analyser_fichiers(&essai, None, &liste);
        for f in &liste {
            let lu = trouves.iter().any(|t| t.chemin == *f && t.regle == "Tout");
            assert!(lu != echecs.contains(f), "{f:?} : {trouves:?} {echecs:?}");
        }
        assert!(echecs.iter().all(|f| *f == piege), "{echecs:?}");
        // Seul, comme examiner() le passe : lu, ou illisible, donc « impossible à vérifier ».
        let (trouves, echecs) = analyser_fichiers(&essai, None, std::slice::from_ref(&piege));
        assert!(
            !trouves.is_empty() || (echecs == std::slice::from_ref(&piege) && illisible(&piege, &echecs).is_some()),
            "{trouves:?} {echecs:?}"
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Un fichier connu de MalwareBazaar qui fait aussi paniquer YARA-X reste un « logiciel malveillant connu » :
    /// l'empreinte ne dépend pas de YARA-X. Avant, elle était cherchée après l'analyse, sous la même garde, et la
    /// panique la sautait : le fichier n'était plus qu'« impossible à vérifier », et une extension qui le portait
    /// demandait quand même l'accord.
    #[test]
    fn une_empreinte_connue_est_trouvee_meme_si_yara_x_panique() {
        let mut compilateur = yara_x::Compiler::new();
        compilateur
            .add_source(r#"import "pe" rule Section { condition: pe.section_index(0) == 0 }"#)
            .unwrap();
        let essai = compilateur.build();
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let piege = dossier.join("piege.exe");
        std::fs::write(&piege, pe_dont_la_section_deborde()).unwrap();
        let connues = Empreintes::depuis(vec![empreintes::sha256(&piege).unwrap()]);
        let (trouves, _) = analyser_fichiers(&essai, Some(&connues), std::slice::from_ref(&piege));
        assert!(
            trouves
                .iter()
                .any(|t| t.chemin == piege && t.regle.starts_with(MALWAREBAZAAR)),
            "{trouves:?}"
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// La garde elle-même, sans YARA-X : une panique ne coûte que son fichier, l'analyseur qui l'a vue est remplacé,
    /// et un fil qui tombe hors de toute analyse (analyseur impossible à créer) rend son lot illisible, sans toucher aux
    /// autres.
    #[test]
    fn une_panique_ne_fait_disparaitre_aucun_fichier() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let liste: Vec<PathBuf> = (0..8).map(|i| PathBuf::from(format!("/home/alice/f{i}"))).collect();
        let piege = liste[4].clone();
        // L'analyseur compte les fichiers qu'il a vus : le voisin du piège doit être le premier d'un analyseur neuf.
        let (trouves, echecs) = par_lots(
            &liste,
            || 0_usize,
            |vus, f| {
                *vus += 1;
                assert!(*f != piege, "fichier piégé");
                (vec![Trouve::nouveau(&vus.to_string(), f)], true)
            },
            |_| Vec::new(),
        );
        assert_eq!(echecs, std::slice::from_ref(&piege));
        assert_eq!(trouves.len(), 7, "{trouves:?}");
        assert!(
            trouves.iter().any(|t| t.chemin == liste[5] && t.regle == "1"),
            "{trouves:?}"
        );
        // Seul, comme examiner() le passe : illisible, donc « impossible à vérifier », et plus « sain ».
        let (trouves, echecs) = par_lots(
            std::slice::from_ref(&piege),
            || (),
            |(), _| panic!("fichier piégé"),
            |_| Vec::new(),
        );
        assert_eq!(trouves, []);
        assert_eq!(echecs, std::slice::from_ref(&piege));
        assert!(illisible(Path::new("/home/alice"), &echecs).is_some());
        // Le premier analyseur créé panique : son fil tombe, ses deux fichiers sont illisibles, les six autres lus.
        let premier = AtomicBool::new(true);
        let (trouves, mut echecs) = par_lots(
            &liste,
            || assert!(!premier.swap(false, Ordering::SeqCst), "analyseur impossible à créer"),
            |(), f| (vec![Trouve::nouveau("lu", f)], true),
            |_| Vec::new(),
        );
        assert_eq!((trouves.len(), echecs.len()), (6, 2));
        echecs.extend(trouves.into_iter().map(|t| t.chemin));
        echecs.sort();
        assert_eq!(echecs, liste);
    }

    /// Les règles et l'empreinte, chacune sous sa garde : une panique des règles ne saute pas l'empreinte (le fichier
    /// connu reste trouvé, et dit illisible pour les règles), et une panique de l'empreinte ne jette pas ce que les
    /// règles ont trouvé, mais rend le fichier illisible : comparé à rien, il n'est pas sain.
    #[test]
    fn l_empreinte_ne_depend_pas_des_regles() {
        let liste: Vec<PathBuf> = (0..8).map(|i| PathBuf::from(format!("/home/alice/f{i}"))).collect();
        let (connu, piege) = (liste[2].clone(), liste[5].clone());
        let (trouves, mut echecs) = par_lots(
            &liste,
            || (),
            |(), f| {
                assert!(*f != connu, "fichier piégé");
                (vec![Trouve::nouveau("regle", f)], true)
            },
            |f| {
                assert!(*f != piege, "empreinte impossible");
                if *f == connu {
                    vec![Trouve::nouveau(&format!("{MALWAREBAZAAR}essai"), f)]
                } else {
                    Vec::new()
                }
            },
        );
        echecs.sort();
        assert_eq!(echecs, [connu.clone(), piege.clone()]);
        let regles: Vec<&PathBuf> = trouves
            .iter()
            .filter(|t| t.regle == "regle")
            .map(|t| &t.chemin)
            .collect();
        assert_eq!(regles.len(), 7, "{trouves:?}");
        assert!(regles.contains(&&piege) && !regles.contains(&&connu));
        let connus: Vec<&Trouve> = trouves.iter().filter(|t| t.regle.starts_with(MALWAREBAZAAR)).collect();
        assert!(connus.len() == 1 && connus[0].chemin == connu, "{trouves:?}");
    }
}
