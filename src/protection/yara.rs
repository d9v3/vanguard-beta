//! Analyse YARA : 308 règles de ReversingLabs (rançongiciels, voleurs de mots de passe, chevaux de Troie, portes
//! dérobées…), intégrées au programme (assets/yara, outils/maj-yara.sh ; allégées par build.rs, de 2,7 Mo à 1,2 Mo,
//! sans en changer le sens) et appliquées par le moteur YARA de Vanguard (`moteur_yara`, écrit pour lui : rien à
//! installer, depuis la clé et sans Internet comme ailleurs), que les tests comparent à YARA-X, le moteur de VirusTotal,
//! gardé en oracle de développement seulement. Une règle que le moteur ne comprend pas entière est refusée, comptée et
//! nommée : tant qu'il en reste une, aucune analyse ne se dit saine. En complément de l'antivirus : une règle décrit une
//! famille entière, variantes comprises. Lecture seule : rien n'est déplacé ni supprimé. Chaque fichier lu est aussi comparé aux empreintes de MalwareBazaar (`empreintes`) : là, c'est
//! un logiciel malveillant précis, reconnu sans doute possible. Depuis le verdict commun (`moteur`), chaque fichier passe
//! par toutes les sources du moteur de Vanguard : empreintes, règles, base ClamAV installée et heuristiques.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use crate::protection::antivirus::{Examen, Portee};
use crate::protection::empreintes;
use crate::protection::moteur::{self, Source, Sources, Usage};
use crate::protection::moteur_yara::Regles;
use crate::protection::regles_yara::Raison;
use crate::ui::*;

const REGLES: &str = include_str!(concat!(env!("OUT_DIR"), "/reversinglabs.yara"));

/// Les fichiers plus gros ne sont pas lus (images disque, vidéos), mais dits : aucun des programmes que visent les
/// règles n'en approche, et les lire prendrait de longues minutes.
const TAILLE_MAX: u64 = 256 << 20;

/// Le temps laissé à chaque fichier, et le nombre de fichiers analysés ensemble.
const DELAI_PAR_FICHIER: Duration = Duration::from_secs(30);
const FILS: usize = 4;

/// Les règles, compilées une fois par lancement (quelques millisecondes) ; les analyses suivantes les reprennent.
/// `Err` : aucune ne s'applique, ce qu'un test empêche d'arriver jusqu'à une version livrée.
pub(crate) fn regles() -> Result<&'static Regles, &'static str> {
    static COMPILEES: OnceLock<Regles> = OnceLock::new();
    let regles = COMPILEES.get_or_init(|| Regles::compiler(REGLES));
    if regles.nombre() == 0 {
        return Err(tr!("aucune règle lisible", "no readable rule"));
    }
    Ok(regles)
}

/// La raison d'un refus, prête à montrer.
fn raison(r: &Raison) -> String {
    match r {
        Raison::Inconnue(c) => trf!(
            "construction inconnue du moteur ({c})",
            "construct unknown to the engine ({c})"
        ),
        Raison::Syntaxe(a) => trf!("texte mal formé (attendu : {a})", "malformed text (expected: {a})"),
        Raison::Nom(n) => trf!("nom en double ou introuvable ({n})", "duplicate or missing name ({n})"),
        Raison::Import(m) => trf!("module {m} sans import", "module {m} without import"),
        Raison::Borne(b) => trf!("trop grande ({b})", "too large ({b})"),
        Raison::Motif(m) => trf!("chaîne refusée ({m})", "string refused ({m})"),
    }
}

/// Les règles refusées par le moteur, en une phrase : leur nombre, les premières nommées avec leur raison. `None` :
/// toutes s'appliquent.
pub(crate) fn non_verifiees(regles: &Regles) -> Option<String> {
    let refus = regles.refus();
    if refus.is_empty() {
        return None;
    }
    let premieres: Vec<String> = refus
        .iter()
        .take(3)
        .map(|r| {
            let nom = r
                .regle
                .as_deref()
                .map_or_else(|| trf!("ligne {}", "line {}", r.ligne), affichable);
            format!("{nom} : {}", raison(&r.raison))
        })
        .collect();
    Some(trf!(
        "{} règle(s) YARA non vérifiée(s), refusée(s) par le moteur : {}{}",
        "{} YARA rule(s) not checked, refused by the engine: {}{}",
        refus.len(),
        premieres.join(" ; "),
        if refus.len() > 3 { " ; …" } else { "" }
    ))
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

/// Une correspondance : la source, la règle (« Win32_Ransomware_WannaCry », ou le texte de l'heuristique) et le
/// fichier.
#[derive(Debug, PartialEq)]
struct Trouve {
    source: Source,
    regle: String,
    /// Prêt à montrer.
    fichier: String,
    /// Tel quel, pour l'isoler.
    chemin: PathBuf,
}

impl Trouve {
    /// Une correspondance d'une règle (essais).
    #[cfg(test)]
    fn nouveau(regle: &str, chemin: &Path) -> Trouve {
        Trouve::de(Source::Yara, regle, chemin)
    }

    /// Le chemin, seulement montré, est rendu inoffensif : son nom est celui qu'a choisi l'auteur du fichier.
    fn de(source: Source, regle: &str, chemin: &Path) -> Trouve {
        Trouve {
            source,
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
        // La cible elle-même, ni fichier ni dossier (un lien, un tube nommé) : rien n'en est lu, et ce n'est pas
        // « rien trouvé ». Plus bas dans un dossier, un lien n'est pas suivi, comme dit.
        if chemin.as_path() == cible && !meta.is_file() && !meta.is_dir() {
            illisibles.push(chemin);
            continue;
        }
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

/// Ce qu'un fichier a laissé lire.
#[derive(Debug, Clone, PartialEq)]
enum Lu {
    /// En entier, chaque partie passée aux règles.
    Tout,
    /// Lu, mais une partie au moins n'a pas pu être vérifiée (la première, avec sa raison, prête à montrer).
    EnPartie(String),
    /// Illisible, changé pendant la lecture, ou trop long à lire : rien n'est conclu.
    Non,
}

/// Un fichier passé au moteur d'analyse (`moteur::examiner`) : ouvert sans suivre de lien et sans attendre (un tube
/// nommé glissé à sa place bloquerait la lecture), découpé en parties (entrées d'archive, flux OLE, source des macros,
/// octets ajoutés…), chacune passée à toutes les sources. `Err` : rien n'a pu être conclu.
fn analyser_fichier(sources: &Sources<'_>, chemin: &Path) -> Result<moteur::Resultat, ()> {
    moteur::examiner(chemin, sources, DELAI_PAR_FICHIER)
}

/// Les sources du moteur appliquées à des fichiers, par `FILS` fils, et l'empreinte de chaque fichier cherchée à part
/// dans celles de MalwareBazaar (sa propre garde, voir `par_lots`) : (correspondances, fichiers illisibles ou trop
/// longs à lire, fichiers vérifiés en partie seulement avec la raison). Une partie connue cachée dans une archive :
/// l'archive entière est désignée. Les heuristiques arrivent en correspondances de source `Heuristique`.
fn analyser_fichiers(sources: &Sources<'_>, liste: &[PathBuf]) -> (Vec<Trouve>, Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let (mut trouves, echecs, partiels) = par_lots(
        liste,
        || (),
        |(), f| match analyser_fichier(sources, f) {
            Ok(r) => {
                let mut trouves: Vec<Trouve> = r.trouvailles.iter().map(|t| Trouve::de(t.source, &t.nom, f)).collect();
                trouves.extend(r.indices.iter().map(|i| Trouve::de(Source::Heuristique, &i.texte(), f)));
                let lu = match r.non_verifie.into_iter().next() {
                    None => Lu::Tout,
                    Some(raison) => Lu::EnPartie(raison),
                };
                (trouves, lu)
            }
            Err(()) => (Vec::new(), Lu::Non),
        },
        // Le fichier vient d'être lu : il est encore en mémoire, l'empreinte coûte peu.
        |f| {
            sources
                .malwarebazaar
                .map(|e| empreintes::connus(e, std::slice::from_ref(f)))
                .unwrap_or_default()
                .into_iter()
                .map(|(chemin, e)| {
                    Trouve::de(
                        Source::EmpreinteMalwareBazaar,
                        &format!("{}{e}", moteur::MALWAREBAZAAR),
                        &chemin,
                    )
                })
                .collect()
        },
    );
    // Un fichier connu de MalwareBazaar l'est par le moteur et par la garde de l'empreinte : dit une fois.
    let mut vus = std::collections::HashSet::new();
    trouves.retain(|t| vus.insert((t.chemin.clone(), t.regle.clone())));
    (trouves, echecs, partiels)
}

/// `liste` répartie en `FILS` lots, un fil par lot avec son propre analyseur (`nouveau`) ; `un` passe un fichier aux
/// règles : (correspondances, ce qui a été lu) ; `empreinte` le cherche ensuite parmi les empreintes connues. Un
/// fichier piégé qui ferait paniquer le moteur (un dépassement de capacité oublié, que la version publiée vérifie aussi)
/// est alors rendu illisible, jamais sain, sans emporter les autres fichiers de son lot, et l'analyseur, peut-être
/// resté au milieu de l'analyse interrompue, n'est plus réutilisé. L'empreinte, qui ne dépend pas des règles, a sa
/// propre garde : cherchée même après une panique des règles, elle garde « logiciel malveillant connu » à un fichier de
/// MalwareBazaar qui ferait aussi paniquer le moteur, au lieu de « impossible à vérifier ». Un fil qui tombe malgré tout (analyseur impossible à créer) rend tout son lot
/// illisible : jeté en silence, ce lot faisait conclure « sain » sans avoir été lu.
fn par_lots<A>(
    liste: &[PathBuf],
    nouveau: impl Fn() -> A + Sync,
    un: impl Fn(&mut A, &PathBuf) -> (Vec<Trouve>, Lu) + Sync,
    empreinte: impl Fn(&PathBuf) -> Vec<Trouve> + Sync,
) -> (Vec<Trouve>, Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let (nouveau, un, empreinte) = (&nouveau, &un, &empreinte);
    let lots: Vec<&[PathBuf]> = liste.chunks(liste.len().div_ceil(FILS).max(1)).collect();
    std::thread::scope(|s| {
        let fils: Vec<_> = lots
            .into_iter()
            .map(|lot| {
                let fil = s.spawn(move || {
                    let mut analyseur = nouveau();
                    let (mut trouves, mut echecs, mut partiels) = (Vec::new(), Vec::new(), Vec::new());
                    for f in lot {
                        let regles = crate::journal::rattraper(std::panic::AssertUnwindSafe(|| un(&mut analyseur, f)));
                        let connu = crate::journal::rattraper(std::panic::AssertUnwindSafe(|| empreinte(f)));
                        match (&regles, connu.is_ok()) {
                            (Ok((_, Lu::Tout)), true) => {}
                            (Ok((_, Lu::EnPartie(raison))), true) => partiels.push((f.clone(), raison.clone())),
                            _ => echecs.push(f.clone()),
                        }
                        match regles {
                            Ok((t, _)) => trouves.extend(t),
                            Err(_) => analyseur = nouveau(),
                        }
                        trouves.extend(connu.unwrap_or_default());
                    }
                    (trouves, echecs, partiels)
                });
                (lot, fil)
            })
            .collect();
        let (mut trouves, mut echecs, mut partiels) = (Vec::new(), Vec::new(), Vec::new());
        for (lot, fil) in fils {
            match fil.join() {
                Ok((t, e, p)) => {
                    trouves.extend(t);
                    echecs.extend(e);
                    partiels.extend(p);
                }
                Err(_) => echecs.extend(lot.iter().cloned()),
            }
        }
        (trouves, echecs, partiels)
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

/// Ce qui n'a été vérifié qu'en partie dans une cible, en une phrase : le nombre, et le premier pour exemple avec sa
/// raison. Rien n'est conclu pour ces parties-là.
fn en_partie(cible: &Path, partiels: &[(PathBuf, String)]) -> Option<String> {
    let (premier, raison) = partiels.first()?;
    Some(trf!(
        "{} : {} fichier(s) vérifié(s) en partie seulement, dont {} ({})",
        "{}: {} file(s) only partly checked, including {} ({})",
        chemin_affichable(cible),
        partiels.len(),
        chemin_affichable(premier),
        affichable(raison)
    ))
}

/// Le début du nom d'une correspondance par empreinte : « MalwareBazaar `sha256:<empreinte>` ».
const MALWAREBAZAAR: &str = moteur::MALWAREBAZAAR;

/// La famille d'une règle de ReversingLabs ou d'une signature ClamAV, lue dans son nom
/// (« ByteCode_MSIL_Ransomware_Apis », « Win.Trojan.Agent-1 »).
pub(crate) fn famille(regle: &str) -> &'static str {
    if regle.starts_with(MALWAREBAZAAR) {
        return tr!(
            "logiciel malveillant connu, empreinte exacte",
            "known malware, exact fingerprint"
        );
    }
    if regle.to_ascii_lowercase().contains("eicar") {
        return tr!("fichier d'essai EICAR, inoffensif", "EICAR test file, harmless");
    }
    for morceau in regle.split(['_', '.', '-']) {
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

/// Applique les sources du moteur aux cibles : (correspondances, ce qui n'a pas pu être lu, nombre de fichiers listés).
/// Une source attendue qui manque (règles YARA refusées ou inutilisables) est rendue avec ce qui n'a pas été lu :
/// jamais compté comme sain.
fn appliquer(sources: &Sources<'_>, cibles: &[PathBuf], bavard: bool) -> (Vec<Trouve>, Vec<String>, usize) {
    let mut trouves = Vec::new();
    let mut erreurs: Vec<String> = sources.manquantes.clone();
    let mut listes = 0usize;
    for cible in cibles {
        if bavard {
            trp!("  Analyse de {}…", "  Scanning {}…", chemin_affichable(cible));
        }
        let mut echecs = Vec::new();
        let liste = fichiers(cible, &mut echecs);
        listes = listes.saturating_add(liste.len());
        let (t, e, p) = analyser_fichiers(sources, &liste);
        trouves.extend(t);
        echecs.extend(e);
        erreurs.extend(illisible(cible, &echecs));
        erreurs.extend(en_partie(cible, &p));
    }
    (trouves, erreurs, listes)
}

/// Le niveau d'une correspondance : certaine (empreinte exacte, essai) critique, famille élevée, suspect moyen.
fn niveau(t: &Trouve) -> crate::risk::Niveau {
    match t.source {
        Source::Heuristique => crate::risk::Niveau::Moyen,
        s if s.certaine() => crate::risk::Niveau::Critique,
        _ => crate::risk::Niveau::Eleve,
    }
}

pub fn analyser(portee: &Portee) {
    titre(tr!("Analyse YARA", "YARA scan"));
    analyser_sans_titre(portee, true);
}

/// Le moteur de Vanguard sur les endroits de la portée, sous le titre de l'appelant. `seule` : l'analyse est lancée
/// pour elle-même (menu Analyse YARA), et le conseil renvoie à l'antivirus ; dans l'analyse antivirus, qui la suit
/// d'un second avis, il ne le fait pas.
pub(crate) fn analyser_sans_titre(portee: &Portee, seule: bool) {
    let cibles = match portee {
        Portee::Dossier(d) => vec![d.clone()],
        Portee::Complete => vec![crate::socle::maison()],
        Portee::Rapide => endroits_a_risque(),
    };
    if cibles.is_empty() {
        trp!("  Rien à analyser ici.", "  Nothing to scan here.");
        return;
    }
    let sources = moteur::sources(Usage::ALaDemande);
    let (trouves, erreurs, _) = appliquer(&sources, &cibles, true);
    println!();
    // Ce qui manquait sans empêcher de conclure (base ClamAV absente, empreintes non chargées) : dit d'abord.
    for r in &sources.reserves {
        afficher_aligne("  ⚠ ", r, 4, "");
    }
    // Les flux de données alternatifs de NTFS (« fichier.txt:cache ») ne sont pas listés par le système de fichiers
    // comme des fichiers : un contenu qui s'y cache n'est pas lu, et c'est dit.
    if cfg!(windows) {
        for ligne in envelopper(
            tr!(
                "Les flux de données alternatifs de NTFS (« fichier:flux ») ne sont pas lus : un contenu qui s'y cache n'est pas vérifié.",
                "NTFS alternate data streams (“file:stream”) are not read: content hidden in them is not checked."
            ),
            LARGEUR - 2,
        ) {
            println!("  {GRIS}{ligne}{RESET}");
        }
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
        if erreurs.is_empty() {
            match sources.malwarebazaar {
                Some(e) => trp!(
                    "  {VERT}✔{RESET} Rien de connu ni de suspect (308 règles, {} empreintes de MalwareBazaar, heuristiques).",
                    "  {VERT}✔{RESET} Nothing known or suspicious (308 rules, {} MalwareBazaar fingerprints, heuristics).",
                    e.nombre()
                ),
                None => trp!(
                    "  {VERT}✔{RESET} Rien de connu ni de suspect (308 règles, heuristiques).",
                    "  {VERT}✔{RESET} Nothing known or suspicious (308 rules, heuristics)."
                ),
            }
        }
        return;
    }
    for t in &trouves {
        println!("  {}✖{RESET} {}", couleur(niveau(t)), t.fichier);
        if t.source == Source::Heuristique {
            println!("      {GRIS}{}{RESET}", trf!("suspect : {}", "suspicious: {}", t.regle));
        } else {
            println!("      {GRIS}{} ({}){RESET}", famille(&t.regle), affichable(&t.regle));
        }
    }
    println!();
    let mut a_isoler: Vec<(PathBuf, String)> = Vec::new();
    // Une heuristique seule ne propose jamais la quarantaine : elle dit, la personne juge.
    for t in trouves.iter().filter(|t| t.source != Source::Heuristique) {
        if t.chemin.is_file() && !a_isoler.iter().any(|(c, _)| *c == t.chemin) {
            let raison = match t.source {
                Source::EmpreinteMalwareBazaar => t.regle.clone(),
                Source::Yara => format!("YARA {}", t.regle),
                s => format!("{} {}", s.nom(), t.regle),
            };
            a_isoler.push((t.chemin.clone(), raison));
        }
    }
    let conseil = if !seule {
        if a_isoler.is_empty() {
            tr!(
                "Seulement suspect : rien de connu n'y est reconnu, et rien n'est mis en quarantaine ; en cas de doute, ne les ouvrez pas. Un faux positif connu se fait taire dans Alertes déclarées normales.",
                "Suspicious only: nothing known is recognized, and nothing is quarantined; when in doubt, do not open them. A known false positive can be silenced in Alerts marked as normal."
            )
        } else {
            tr!(
                "Ne les ouvrez pas. Une règle peut se tromper sur un fichier légitime : la quarantaine se défait, et en cas de doute, envoyez-le à VirusTotal.",
                "Do not open them. A rule can be wrong about a legitimate file: the quarantine can be undone, and when in doubt, upload it to VirusTotal."
            )
        }
    } else if a_isoler.is_empty() {
        tr!(
            "Seulement suspect : rien de connu n'y est reconnu, et rien n'est mis en quarantaine. Faites-les analyser par l'antivirus (même menu) ; en cas de doute, ne les ouvrez pas. Un faux positif connu se fait taire dans Alertes déclarées normales.",
            "Suspicious only: nothing known is recognized, and nothing is quarantined. Have the antivirus scan them (same menu); when in doubt, do not open them. A known false positive can be silenced in Alerts marked as normal."
        )
    } else {
        tr!(
            "Ne les ouvrez pas. Faites-les aussi analyser par l'antivirus (même menu). Une règle peut se tromper sur un fichier légitime : la quarantaine se défait, et en cas de doute, envoyez-le à VirusTotal.",
            "Do not open them. Have the antivirus scan them too (same menu). A rule can be wrong about a legitimate file: the quarantine can be undone, and when in doubt, upload it to VirusTotal."
        )
    };
    for ligne in envelopper(conseil, LARGEUR - 2) {
        println!("  {ligne}");
    }
    if !a_isoler.is_empty() {
        crate::protection::quarantaine::proposer(&a_isoler);
    }
}

/// Un seul fichier, pour « Vérifier un fichier téléchargé », le courriel suspect et les plugins : le résultat du
/// moteur de Vanguard, que l'appelant affiche. Une reconnaissance par une source de signatures l'emporte, puis le
/// suspect, puis l'impossible ; un « rien trouvé » auquel une source manquait le dit.
pub(crate) fn examiner(fichier: &Path) -> Examen {
    let sources = moteur::sources(Usage::ALaDemande);
    examiner_avec(&sources, fichier)
}

/// Comme `examiner`, avec le résultat du moteur quand le fichier a pu lui être passé en entier (fichier ordinaire, pas
/// trop gros, sans panique) : « Vérifier un fichier téléchargé » le verse au journal et le rend en `--json`. Sinon
/// (`None`), l'examen ordinaire, qui dit ce qui n'a pas pu être lu ; le fichier n'est lu qu'une fois dans les deux cas.
pub(crate) fn examiner_en_detail(fichier: &Path) -> (Examen, Option<moteur::Resultat>) {
    let sources = moteur::sources(Usage::ALaDemande);
    let ordinaire = std::fs::symlink_metadata(fichier).is_ok_and(|m| m.is_file() && m.len() <= TAILLE_MAX);
    if ordinaire
        && let Ok(Ok(r)) =
            crate::journal::rattraper(std::panic::AssertUnwindSafe(|| analyser_fichier(&sources, fichier)))
    {
        return (examen_de(&r), Some(r));
    }
    (examiner_avec(&sources, fichier), None)
}

/// L'examen tiré d'un résultat du moteur, dans l'ordre de `examiner_avec` : reconnu, suspect, impossible (source
/// attendue absente ou partie non lue), puis sain, sous réserve si une source facultative manquait.
fn examen_de(r: &moteur::Resultat) -> Examen {
    if !r.trouvailles.is_empty() {
        return Examen::Trouve(
            r.trouvailles
                .iter()
                .map(|t| format!("{} ({})", famille(&t.nom), t.nom))
                .collect(),
        );
    }
    if !r.indices.is_empty() {
        return Examen::Suspect(r.indices.iter().map(moteur::Indice::texte).collect());
    }
    if !r.manquantes.is_empty() || !r.non_verifie.is_empty() {
        return Examen::Impossible(
            r.manquantes
                .iter()
                .chain(&r.non_verifie)
                .cloned()
                .collect::<Vec<_>>()
                .join(" ; "),
        );
    }
    if r.reserves.is_empty() {
        Examen::Sain
    } else {
        Examen::SainSousReserve(r.reserves.clone())
    }
}

fn examiner_avec(sources: &Sources<'_>, fichier: &Path) -> Examen {
    let (trouves, erreurs, listes) = appliquer(sources, &[fichier.to_path_buf()], false);
    let (signes, connus): (Vec<&Trouve>, Vec<&Trouve>) = trouves.iter().partition(|t| t.source == Source::Heuristique);
    if !connus.is_empty() {
        return Examen::Trouve(
            connus
                .iter()
                .map(|t| format!("{} ({})", famille(&t.regle), t.regle))
                .collect(),
        );
    }
    if !signes.is_empty() {
        return Examen::Suspect(signes.iter().map(|t| t.regle.clone()).collect());
    }
    if !erreurs.is_empty() {
        return Examen::Impossible(erreurs.join(" ; "));
    }
    // Aucun fichier listé : rien n'a été lu, ce n'est pas « sain ».
    if listes == 0 {
        return Examen::Impossible(tr!("aucun fichier lu", "no file read").into());
    }
    if sources.reserves.is_empty() {
        Examen::Sain
    } else {
        Examen::SainSousReserve(sources.reserves.clone())
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

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::empreintes::Empreintes;

    /// Les règles données et, s'il y en a, des empreintes : ni base ClamAV, ni heuristiques, rien qui manque.
    fn yara_seul<'a>(regles: &'a Regles, malwarebazaar: Option<&'a Empreintes>) -> Sources<'a> {
        Sources {
            yara: Some(regles),
            malwarebazaar,
            clamav: None,
            heuristiques: false,
            lieu: Some(crate::protection::heuristiques::Lieu::Ordinaire),
            normale: |_| false,
            manquantes: Vec::new(),
            reserves: Vec::new(),
        }
    }

    /// Le résultat d'un fichier : une détection l'emporte sur un signe, un signe seul est suspect (jamais une
    /// détection), et un « rien trouvé » sans une source attendue le dit.
    #[test]
    fn examen_d_un_fichier_par_le_moteur() {
        let essai =
            Regles::compiler(r#"rule Win32_Trojan_Essai { strings: $a = "vanguard-essai-yara" condition: $a }"#);
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let outil = d.join("outil");
        std::fs::write(&outil, crate::protection::heuristiques::corpus::elf_wx()).unwrap();
        let mut sources = yara_seul(&essai, None);
        sources.heuristiques = true;
        assert!(
            matches!(examiner_avec(&sources, &outil), Examen::Suspect(s) if s.len() == 1),
            "{:?}",
            examiner_avec(&sources, &outil)
        );
        let mut piege = crate::protection::heuristiques::corpus::elf_wx();
        piege.extend(b"vanguard-essai-yara");
        std::fs::write(&outil, piege).unwrap();
        assert_eq!(
            examiner_avec(&sources, &outil),
            Examen::Trouve(vec!["cheval de Troie (Win32_Trojan_Essai)".into()])
        );
        std::fs::write(&outil, b"rien").unwrap();
        assert_eq!(examiner_avec(&sources, &outil), Examen::Sain);
        sources.reserves.push("base ClamAV absente".into());
        assert_eq!(
            examiner_avec(&sources, &outil),
            Examen::SainSousReserve(vec!["base ClamAV absente".into()])
        );
        sources.manquantes.push("règles refusées".into());
        assert!(matches!(examiner_avec(&sources, &outil), Examen::Impossible(r) if r.contains("règles refusées")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le résultat du moteur gardé pour `--json` (`examiner_en_detail`) donne le même examen que le chemin ordinaire,
    /// cas par cas : détection, suspect, sain, sain sous réserve, source attendue absente, partie non lue.
    #[test]
    fn examen_du_resultat_comme_l_ordinaire() {
        let essai =
            Regles::compiler(r#"rule Win32_Trojan_Essai { strings: $a = "vanguard-essai-yara" condition: $a }"#);
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let outil = d.join("outil");
        let mut sources = yara_seul(&essai, None);
        sources.heuristiques = true;
        let mut piege = crate::protection::heuristiques::corpus::elf_wx();
        piege.extend(b"vanguard-essai-yara");
        let pareil = |sources: &Sources<'_>| {
            let r = analyser_fichier(sources, &outil).expect("fichier lu");
            assert_eq!(examen_de(&r), examiner_avec(sources, &outil), "{r:?}");
        };
        for contenu in [
            piege,
            crate::protection::heuristiques::corpus::elf_wx(),
            b"rien".to_vec(),
        ] {
            std::fs::write(&outil, contenu).unwrap();
            pareil(&sources);
        }
        sources.reserves.push("base ClamAV absente".into());
        pareil(&sources);
        sources.manquantes.push("règles refusées".into());
        pareil(&sources);
        let vide = moteur::Resultat {
            non_verifie: vec!["archive.zip › doc.pdf : contenu PDF non ouvert".into()],
            ..moteur::Resultat::default()
        };
        assert!(matches!(examen_de(&vide), Examen::Impossible(r) if r.contains("PDF non ouvert")));
        let _ = std::fs::remove_dir_all(&d);
    }

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
        assert_eq!(famille("Win.Trojan.Agent-1"), "cheval de Troie");
        assert_eq!(
            famille("Doc.Downloader.Emotet-2"),
            "téléchargeur de logiciels malveillants"
        );
        assert_eq!(famille(moteur::NOM_EICAR), "fichier d'essai EICAR, inoffensif");
        // Le nom du fichier est celui que son auteur a choisi : piégé, il arrive inoffensif.
        let piege = Trouve::nouveau(
            "X",
            Path::new("/home/alice/fa\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}cture.exe"),
        );
        assert!(!piege.fichier.contains('\x1b') && !piege.fichier.contains('\u{202e}'));
    }

    /// Les 308 règles s'appliquent toutes : une règle que le moteur refuserait (non vérifiée) ne passe pas jusqu'à une
    /// version livrée.
    #[test]
    fn les_308_regles_se_compilent() {
        let r = regles().unwrap();
        assert_eq!(r.refus(), [], "règles refusées par le moteur");
        assert_eq!(r.nombre(), 308);
        assert_eq!(non_verifiees(r), None);
    }

    /// Le fichier d'origine de ReversingLabs, tel qu'outils/maj-yara.sh le pose, sans l'allègement de build.rs, se
    /// compile aussi avec YARA-X, l'oracle du moteur, et donne autant de règles que la version allégée. Il remplace
    /// l'étape de la CI qui le passait à libyara (yara-python, installé par pip sans version épinglée) : un autre moteur
    /// pouvait accepter une règle que YARA-X refuse, ou l'inverse.
    #[test]
    #[cfg(not(miri))]
    fn les_regles_d_origine_se_compilent_avec_yara_x() {
        let mut compilateur = yara_x::Compiler::new();
        if let Err(e) = compilateur.add_source(ORIGINE) {
            panic!("règles d'origine refusées par YARA-X : {e}");
        }
        let origine = compilateur.build();
        assert_eq!(origine.iter().count(), regles().unwrap().nombre());
    }

    /// Le moteur de Vanguard accepte toutes les règles d'origine, sans l'allègement, et les mêmes que dans leur forme
    /// allégée. outils/maj-yara.sh lance ce test après chaque mise à jour : une construction nouvelle de ReversingLabs
    /// que le moteur ne connaît pas y est nommée, règle par règle.
    #[test]
    fn les_regles_d_origine_acceptees_par_le_moteur_maison() {
        let origine = Regles::compiler(ORIGINE);
        for r in origine.refus() {
            eprintln!(
                "RÈGLE NON VÉRIFIÉE : {} (ligne {}) : {}",
                r.regle.as_deref().unwrap_or("?"),
                r.ligne,
                raison(&r.raison)
            );
        }
        assert_eq!(origine.refus().len(), 0, "règles refusées, voir plus haut");
        let allegees: Vec<&str> = regles().unwrap().noms().collect();
        assert_eq!(origine.noms().collect::<Vec<_>>(), allegees);
        assert_eq!(allegees.len(), 308);
    }

    /// Une règle refusée est dite, nommée, et empêche de conclure « sain » : examiner() rend « impossible ».
    #[test]
    fn une_regle_refusee_est_dite() {
        let r = Regles::compiler(
            r#"rule Bonne { strings: $a = "x" condition: $a } rule Mauvaise { strings: $a = "x" xor condition: $a }"#,
        );
        assert_eq!(r.nombre(), 1);
        let texte = non_verifiees(&r).unwrap();
        assert!(texte.contains("Mauvaise") && texte.contains("xor"), "{texte}");
    }

    /// Un dossier d'essai : un faux programme qui remplit une règle d'essai de même forme que celles de ReversingLabs
    /// (en-tête « MZ » et textes), un fichier ordinaire, un lien et un fichier creux trop gros, sautés.
    #[test]
    fn analyse_d_un_dossier() {
        let essai = Regles::compiler(
            r#"rule Win32_Trojan_Essai { strings: $a = "vanguard-essai-yara" $b = { 4D 5A 90 } condition: uint16(0) == 0x5A4D and all of them }"#,
        );
        assert_eq!(essai.refus(), []);
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
        let (trouves, echecs, partiels) = analyser_fichiers(&yara_seul(&essai, None), &liste);
        // Le trop gros n'est pas lu, mais il est dit.
        assert!(
            illisibles.len() == 1 && illisibles[0].ends_with("image.iso"),
            "{illisibles:?}"
        );
        assert_eq!(echecs, Vec::<PathBuf>::new());
        // « MZ » sans en-tête PE : un programme DOS, que Vanguard n'ouvre pas ; lu par les règles, mais pas vérifié
        // en entier, et dit.
        assert!(
            partiels.len() == 1 && partiels[0].0.ends_with("sous/facture.exe") && partiels[0].1.contains("DOS"),
            "{partiels:?}"
        );
        assert!(en_partie(&dossier, &partiels).is_some_and(|p| p.contains("facture.exe")));
        assert_eq!(trouves.len(), 1);
        assert_eq!(trouves[0].regle, "Win32_Trojan_Essai");
        assert!(trouves[0].chemin.ends_with("sous/facture.exe"));
        assert_eq!(famille(&trouves[0].regle), "cheval de Troie");
        // Les vraies règles, sur le même dossier : rien.
        assert_eq!(analyser_fichiers(&yara_seul(regles().unwrap(), None), &liste).0, []);
        // Avec l'empreinte de note.txt parmi celles de MalwareBazaar : trouvé par elle, sans règle.
        let note = dossier.join("note.txt");
        let connues = Empreintes::depuis(vec![empreintes::sha256(&note).unwrap()]);
        let par_empreinte = analyser_fichiers(&yara_seul(regles().unwrap(), Some(&connues)), &liste).0;
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
        // Un fichier qui disparaît entre la liste et la lecture : illisible, pas sain.
        let parti = dossier.join("parti.exe");
        let (trouves, echecs, partiels) = analyser_fichiers(&yara_seul(&essai, None), std::slice::from_ref(&parti));
        assert!(trouves.is_empty() && echecs == [parti] && partiels.is_empty());
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Un fichier de MalwareBazaar caché dans une archive (zip, compressé) : son empreinte n'est pas celle de
    /// l'archive, mais celle d'une partie lue par le socle ; l'archive est désignée.
    #[test]
    fn un_fichier_connu_cache_dans_un_zip_est_trouve() {
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let cache = b"contenu invente pour l'essai, vanguard-essai-empreinte".repeat(8);
        let zip =
            crate::archives::zip::essais::archive_controlee(&[("outil.bin", 8, &cache), ("note.txt", 0, b"rien")]);
        let archive = dossier.join("colis.zip");
        std::fs::write(&archive, zip).unwrap();
        let connue: [u8; 32] = {
            use sha2::Digest;
            sha2::Sha256::digest(&cache).into()
        };
        let connues = Empreintes::depuis(vec![connue]);
        let (trouves, echecs, _) = analyser_fichiers(
            &yara_seul(regles().unwrap(), Some(&connues)),
            std::slice::from_ref(&archive),
        );
        assert_eq!(echecs, Vec::<PathBuf>::new());
        assert_eq!(trouves.len(), 1, "{trouves:?}");
        assert_eq!(trouves[0].chemin, archive);
        assert_eq!(trouves[0].regle, format!("{MALWAREBAZAAR}{}", empreintes::hex(&connue)));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Un PE réduit à l'essentiel, dont l'unique section commence à 0xFFFFFF00 pour 0x200 octets : sa fin dépasse un
    /// u32. YARA-X (1.21 comme 1.22) l'additionnait sans contrôle dans pe.section_index, et les tests compilent avec le
    /// contrôle des débordements : l'analyse paniquait, comme sur un vrai fichier piégé.
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

    /// Le piège qui faisait paniquer YARA-X est lu par le moteur de Vanguard, ses voisins aussi, et son empreinte
    /// reste trouvée : chaque fichier est lu (la règle Tout correspond à tout fichier lu) ou dit illisible, jamais ni
    /// l'un ni l'autre.
    #[test]
    fn le_pe_qui_faisait_paniquer_yara_x_est_lu() {
        let essai = Regles::compiler(
            r#"import "pe" rule Entree { strings: $a = { 4D 5A } condition: $a at pe.entry_point } rule Tout { condition: true }"#,
        );
        assert_eq!(essai.refus(), []);
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let piege = dossier.join("piege.exe");
        std::fs::write(&piege, pe_dont_la_section_deborde()).unwrap();
        let mut liste: Vec<PathBuf> = (0..7)
            .map(|i| {
                let f = dossier.join(format!("note{i}.txt"));
                std::fs::write(&f, b"rien").unwrap();
                f
            })
            .collect();
        liste.insert(4, piege.clone());
        let connues = Empreintes::depuis(vec![empreintes::sha256(&piege).unwrap()]);
        let (trouves, echecs, _) = analyser_fichiers(&yara_seul(&essai, Some(&connues)), &liste);
        assert_eq!(echecs, Vec::<PathBuf>::new());
        for f in &liste {
            assert!(
                trouves.iter().any(|t| t.chemin == *f && t.regle == "Tout"),
                "{f:?} : {trouves:?}"
            );
        }
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
        let (trouves, echecs, _) = par_lots(
            &liste,
            || 0_usize,
            |vus, f| {
                *vus += 1;
                assert!(*f != piege, "fichier piégé");
                (vec![Trouve::nouveau(&vus.to_string(), f)], Lu::Tout)
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
        let (trouves, echecs, _) = par_lots(
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
        let (trouves, mut echecs, _) = par_lots(
            &liste,
            || assert!(!premier.swap(false, Ordering::SeqCst), "analyseur impossible à créer"),
            |(), f| (vec![Trouve::nouveau("lu", f)], Lu::Tout),
            |_| Vec::new(),
        );
        assert_eq!((trouves.len(), echecs.len()), (6, 2));
        echecs.extend(trouves.into_iter().map(|t| t.chemin));
        echecs.sort();
        assert_eq!(echecs, liste);
    }

    /// La preuve de la campagne d'attaque n° 3 : examiner() répondait « Sain » sans lire un octet quand la cible était
    /// un lien ou un tube nommé. Désormais : impossible à vérifier ; et un fichier remplacé par un lien après avoir été
    /// listé n'est pas suivi.
    #[cfg(unix)]
    #[test]
    fn un_lien_ou_un_tube_n_est_jamais_sain() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let vrai = d.join("vrai.bin");
        std::fs::write(&vrai, b"rien de particulier").unwrap();
        let lien = d.join("lien.bin");
        std::os::unix::fs::symlink(&vrai, &lien).unwrap();
        let tube = d.join("tube");
        crate::essais::tube_nomme(&tube).unwrap();
        assert!(matches!(examiner(&vrai), Examen::Sain | Examen::SainSousReserve(_)));
        for cible in [&lien, &tube] {
            assert!(matches!(examiner(cible), Examen::Impossible(_)), "{}", cible.display());
        }
        let mut illisibles = Vec::new();
        assert_eq!(fichiers(&lien, &mut illisibles), Vec::<PathBuf>::new());
        assert_eq!(illisibles, std::slice::from_ref(&lien));
        // Listé comme fichier, ouvert comme lien : illisible.
        let regles = regles().unwrap();
        assert!(analyser_fichier(&yara_seul(regles, None), &lien).is_err());
        assert!(analyser_fichier(&yara_seul(regles, None), &vrai).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les règles et l'empreinte, chacune sous sa garde : une panique des règles ne saute pas l'empreinte (le fichier
    /// connu reste trouvé, et dit illisible pour les règles), et une panique de l'empreinte ne jette pas ce que les
    /// règles ont trouvé, mais rend le fichier illisible : comparé à rien, il n'est pas sain.
    #[test]
    fn l_empreinte_ne_depend_pas_des_regles() {
        let liste: Vec<PathBuf> = (0..8).map(|i| PathBuf::from(format!("/home/alice/f{i}"))).collect();
        let (connu, piege) = (liste[2].clone(), liste[5].clone());
        let (trouves, mut echecs, _) = par_lots(
            &liste,
            || (),
            |(), f| {
                assert!(*f != connu, "fichier piégé");
                (vec![Trouve::nouveau("regle", f)], Lu::Tout)
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
