//! Le laboratoire : un script posé tel quel dans `<dossier des plugins>/labo/`, sans manifeste, pour essayer vite une
//! idée qui n'entrera jamais dans le programme de Vanguard. L'interpréteur vient de l'extension (`interprete`).
//!
//! Mêmes garde-fous que les plugins, parce que c'est le même risque : un programme qui n'est pas de Vanguard. Au
//! premier lancement, le script est montré (chemin, empreinte, 20 premières lignes) et approuvé ; s'il change, il est
//! remontré et redemandé. Le script est copié en étant haché, et c'est cette copie qui est montrée, approuvée puis
//! lancée : le fichier ne peut pas changer entre ce qu'on a lu et ce qui tourne. Jamais en administrateur, jamais
//! dans le bilan, la surveillance, l'entretien ni `complet`, et ses constats ne touchent jamais la note.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::*;

/// Le sous-dossier du laboratoire, dans celui des plugins.
pub const DOSSIER: &str = "labo";
/// Un script du laboratoire ne tourne pas plus longtemps : c'est un essai.
const DELAI: u64 = 300;
const SCRIPTS_MAX: usize = 200;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Approbation {
    pub empreinte: String,
    pub le: String,
}

/// Où en est un script du laboratoire.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Etat {
    Approuve,
    NonApprouve,
    Change,
    /// Un lien, un fichier d'un autre compte, ou rien que Vanguard sache lancer : montré, jamais lancé.
    Refuse(String),
}

pub struct Script {
    pub fichier: String,
    /// Son empreinte tel qu'il est maintenant (aucune s'il est refusé).
    pub empreinte: Option<String>,
    pub etat: Etat,
}

/// Le dossier du laboratoire, créé à soi seul s'il manque, et jugé comme celui des plugins.
pub fn dossier_labo(racine: &Path) -> Result<PathBuf, String> {
    let d = racine.join(DOSSIER);
    creer_prive(&d).map_err(|e| e.to_string())?;
    dossier_sur(&d)?;
    Ok(d)
}

/// Un nom de fichier du laboratoire : lettres, chiffres, « . », « _ », « - », sans « . » en tête ; il sert d'argument
/// et de clé d'approbation, et ne peut désigner rien hors du dossier.
pub fn nom_valide(fichier: &str) -> bool {
    (1..=64).contains(&fichier.len())
        && !fichier.starts_with('.')
        && fichier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Vanguard sait-il lancer ce fichier ? Une extension connue, ou un programme : sous Unix, un fichier exécutable ;
/// sous Windows, .exe, .bat, .cmd ou .com. Un LISEZMOI posé là n'est pas « lancé ».
fn lancable(chemin: &Path, m: &std::fs::Metadata) -> bool {
    let extension = chemin
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if matches!(extension.as_str(), "ps1" | "py") || (cfg!(unix) && matches!(extension.as_str(), "sh" | "bash")) {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o111 != 0
    }
    #[cfg(windows)]
    {
        let _ = m;
        matches!(extension.as_str(), "exe" | "bat" | "cmd" | "com")
    }
}

/// Les scripts du laboratoire, dans l'ordre des noms, et leur état.
pub fn scripts(racine: &Path) -> Vec<Script> {
    let Ok(d) = dossier_labo(racine) else {
        return Vec::new();
    };
    let approuves = approbations(racine).labo;
    let mut liste: Vec<Script> = std::fs::read_dir(&d)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .take(SCRIPTS_MAX)
        .filter_map(|fichier| {
            let chemin = d.join(&fichier);
            let m = std::fs::symlink_metadata(&chemin).ok()?;
            if m.is_dir() {
                return None;
            }
            let mut empreinte = None;
            let etat = if !nom_valide(&fichier) {
                Etat::Refuse(tr!("nom refusé", "name refused").to_string())
            } else if m.file_type().is_symlink() {
                Etat::Refuse(tr!("un lien : jamais suivi", "a link: never followed").to_string())
            } else if !lancable(&chemin, &m) {
                Etat::Refuse(tr!("rien à lancer", "nothing to run").to_string())
            } else {
                match hacher_et_copier(&chemin, None) {
                    Err(e) => Etat::Refuse(e),
                    Ok(e) => {
                        let etat = match approuves.get(&fichier) {
                            None => Etat::NonApprouve,
                            Some(a) if a.empreinte != e => Etat::Change,
                            Some(_) => Etat::Approuve,
                        };
                        empreinte = Some(e);
                        etat
                    }
                }
            };
            Some(Script {
                fichier,
                empreinte,
                etat,
            })
        })
        .collect();
    liste.sort_by(|a, b| a.fichier.cmp(&b.fichier));
    liste
}

/// Les premières lignes d'un script, prêtes à montrer ; un programme binaire est dit tel quel.
fn apercu(copie: &Path) -> Vec<String> {
    let octets = crate::socle::lire_ordinaire(copie, 16 << 20).unwrap_or_default();
    if octets.iter().take(4096).any(|o| *o == 0) {
        return vec![trf!(
            "(programme binaire, {} octets)",
            "(binary program, {} bytes)",
            octets.len()
        )];
    }
    String::from_utf8_lossy(&octets)
        .lines()
        .take(20)
        .map(|l| couper(&affichable(&l.replace('\t', "    ")), LARGEUR - 6))
        .collect()
}

/// Montre le script copié avant de demander l'accord : chemin, empreinte, ce qui le lancera, ses premières lignes.
fn presenter(chemin: &Path, copie: &Path, empreinte: &str, avant: Option<&Approbation>, analyse: &str) {
    println!();
    afficher_aligne(
        &trf!("  {GRAS}Script du labo{RESET} : ", "  {GRAS}Lab script{RESET}: "),
        &chemin_affichable(chemin),
        4,
        "",
    );
    let fichier = chemin
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    afficher_aligne(
        &trf!("  Lancé par : ", "  Run by   : "),
        &decrire(&fichier, &[]),
        14,
        "",
    );
    trp!(
        "  Au plus {DELAI} s, sans droits d'administrateur, dans le dossier du labo.",
        "  At most {DELAI} s, without administrator rights, in the lab folder."
    );
    trp!("  SHA-256 :", "  SHA-256:");
    println!("    {GRIS}{empreinte}{RESET}");
    if let Some(a) = avant {
        trp!(
            "  {}⚠{RESET} Modifié depuis l'approbation du {}.",
            "  {}⚠{RESET} Changed since the approval of {}.",
            couleur(crate::risk::Niveau::Moyen),
            a.le
        );
    }
    afficher_aligne(&trf!("  Analyse : ", "  Scan   : "), analyse, 12, "");
    trp!("  Début du script :", "  Start of the script:");
    for l in apercu(copie) {
        println!("  {GRIS}│{RESET} {l}");
    }
    println!();
    rappel(tr!(
        "Ce script n'est pas du code de Vanguard : il pourra lire et modifier vos fichiers, comme vous. N'approuvez que ce que vous avez écrit ou relu.",
        "This script is not Vanguard's code: it will be able to read and change your files, like you. Only approve what you wrote or reviewed."
    ));
}

/// Le script `fichier` copié en étant haché, dans un dossier temporaire. Rend la copie à lancer (qui vit autant que le
/// dossier) et si elle tourne sans restrictions (marquée « à moi » telle quelle). Sinon il doit être approuvé tel
/// quel, ou il est montré puis approuvé sur accord (la première fois, et après chaque changement). En administrateur,
/// rien du dossier ne vaut : chaque lancement est demandé, avec l'empreinte.
fn copie_approuvee(
    racine: &Path,
    fichier: &str,
    et_lancer: bool,
    accord: impl FnOnce(&str) -> bool,
) -> Result<(Temporaire, PathBuf, bool), String> {
    let administrateur = eleve();
    if administrateur && !et_lancer {
        return Err(refus_eleve());
    }
    let chemin = chemin_du_script(racine, fichier)?;
    menage(racine);
    let essai = Temporaire::creer(racine, "lancement")?;
    let copie = essai.0.join(fichier);
    let empreinte = hacher_et_copier(&chemin, Some(&copie))?;
    if administrateur {
        if !accord_administrateur(fichier, &empreinte) {
            return Err(tr!("Non lancé.", "Not run.").to_string());
        }
        return Ok((essai, copie, false));
    }
    if et_lancer && reglages::charger(racine).labo_a_moi(fichier, &empreinte) {
        return Ok((essai, copie, true));
    }
    let mut a = approbations(racine);
    let avant = a.labo.get(fichier).cloned();
    if avant.as_ref().is_none_or(|x| x.empreinte != empreinte) {
        let analyse = analyser_avant_accord(&copie)?;
        presenter(&chemin, &copie, &empreinte, avant.as_ref(), &analyse);
        let question = match (avant.is_some(), et_lancer) {
            (true, true) => tr!(
                "\n  Approuver la nouvelle version et la lancer ? [o/N] : ",
                "\n  Approve the new version and run it? [y/N]: "
            ),
            (false, true) => tr!(
                "\n  Approuver ce script et le lancer ? [o/N] : ",
                "\n  Approve this script and run it? [y/N]: "
            ),
            (true, false) => tr!(
                "\n  Approuver la nouvelle version ? [o/N] : ",
                "\n  Approve the new version? [y/N]: "
            ),
            (false, false) => tr!("\n  Approuver ce script ? [o/N] : ", "\n  Approve this script? [y/N]: "),
        };
        if !accord(question) {
            return Err(tr!("Rien n'a été approuvé.", "Nothing was approved.").to_string());
        }
        a.labo.insert(
            fichier.to_string(),
            Approbation {
                empreinte,
                le: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
            },
        );
        enregistrer(racine, &a)?;
    }
    Ok((essai, copie, false))
}

/// Le chemin d'un script du labo : un nom valide, présent, que Vanguard sait lancer (un lien est refusé plus loin,
/// à l'ouverture sans suivi).
fn chemin_du_script(racine: &Path, fichier: &str) -> Result<PathBuf, String> {
    if !nom_valide(fichier) {
        return Err(trf!(
            "« {} » n'est pas un nom de script du labo.",
            "“{}” is not a lab script name.",
            affichable(fichier)
        ));
    }
    let chemin = dossier_labo(racine)?.join(fichier);
    let m = std::fs::symlink_metadata(&chemin).map_err(|_| {
        trf!(
            "Aucun script « {fichier} » dans le labo : « vanguard labo ».",
            "No script “{fichier}” in the lab: “vanguard lab”."
        )
    })?;
    if !m.file_type().is_symlink() && !lancable(&chemin, &m) {
        return Err(trf!(
            "« {fichier} » : Vanguard ne sait pas le lancer (.sh, .bash, .ps1, .py ou un programme).",
            "“{fichier}”: Vanguard cannot run it (.sh, .bash, .ps1, .py or a program)."
        ));
    }
    Ok(chemin)
}

/// Lance un script du laboratoire : la copie hachée (approuvée, approuvée sur accord, ou « à moi » telle quelle),
/// le dossier du labo comme dossier courant, environnement minimal sauf « à moi », délai et sortie bornés.
/// Interrupteur général coupé (jamais en administrateur) : le script lui-même, sans copie ni accord.
pub fn lancer(
    racine: &Path,
    fichier: &str,
    arguments: &[String],
    facon: Facon,
    accord: impl FnOnce(&str) -> bool,
) -> Result<crate::commande::Borne, String> {
    if arguments.len() > ARGUMENTS_MAX || arguments.iter().any(|a| a.len() > ARGUMENT_MAX || a.contains('\0')) {
        return Err(trf!(
            "Trop d'arguments, ou trop longs ({ARGUMENTS_MAX} de {ARGUMENT_MAX} caractères au plus).",
            "Too many arguments, or too long ({ARGUMENTS_MAX} of {ARGUMENT_MAX} characters at most)."
        ));
    }
    let d = dossier_labo(racine)?;
    let general = !eleve() && reglages::charger(racine).sans_restrictions;
    let (essai, programme, libre) = if general {
        let chemin = chemin_du_script(racine, fichier)?;
        // L'original : un vrai fichier à soi, jamais un lien qui mènerait ailleurs.
        ouvrir_sur(&chemin)?;
        menage(racine);
        (Temporaire::creer(racine, "lancement")?, chemin, true)
    } else {
        copie_approuvee(racine, fichier, true, accord)?
    };
    let (delai, sortie) = if libre {
        (reglages::DELAI_LIBRE, reglages::SORTIE_LIBRE)
    } else {
        (DELAI, SORTIE_MAX)
    };
    let mut commande = commande_de(
        &programme,
        arguments,
        &d,
        libre,
        facon.isole.then_some(essai.0.as_path()),
    )?;
    let borne = crate::commande::lancer_borne(&mut commande, delai, sortie)
        .ok_or_else(|| trf!("« {fichier} » n'a pas pu démarrer.", "“{fichier}” could not start."))?;
    drop(essai);
    Ok(borne)
}

/// Le bandeau de chaque lancement du laboratoire.
fn bandeau(fichier: &str) {
    titre(&trf!(
        "EXPÉRIMENTAL — hors du programme de Vanguard",
        "EXPERIMENTAL — outside Vanguard's program"
    ));
    trp!(
        "  {GRIS}labo › {}{RESET}",
        "  {GRIS}lab › {}{RESET}",
        affichable(fichier)
    );
}

/// Lance et montre : bandeau, sortie, constats marqués « labo `<fichier>` ». Rend le code de sortie.
pub fn executer(racine: &Path, fichier: &str, arguments: &[String], facon: Facon) -> i32 {
    bandeau(fichier);
    match lancer(racine, fichier, arguments, facon, |q| demander(q).oui()) {
        Err(e) => echec(&e),
        Ok(b) => {
            let lu = sortie::analyser(&b.sortie);
            sortie::afficher(&format!("labo {fichier}"), fichier, DELAI, &b, &lu);
            b.code.unwrap_or(1)
        }
    }
}

/// Approuve un script tel qu'il est maintenant, sans le lancer.
pub fn approuver(racine: &Path, fichier: &str, accord: impl FnOnce(&str) -> bool) -> Result<(), String> {
    let mut demande = false;
    copie_approuvee(racine, fichier, false, |q| {
        demande = true;
        accord(q)
    })?;
    if !demande {
        trp!("  Déjà approuvé tel quel.", "  Already approved as it is.");
    }
    Ok(())
}

/// Retire un script du laboratoire (le fichier et son approbation), sur accord.
pub fn retirer(racine: &Path, fichier: &str, accord: impl FnOnce(&str) -> bool) -> Result<bool, String> {
    if !nom_valide(fichier) {
        return Err(trf!(
            "« {} » n'est pas un nom de script du labo.",
            "“{}” is not a lab script name.",
            affichable(fichier)
        ));
    }
    let chemin = dossier_labo(racine)?.join(fichier);
    let mut a = approbations(racine);
    if std::fs::symlink_metadata(&chemin).is_err() && !a.labo.contains_key(fichier) {
        return Err(trf!("Aucun script « {fichier} ».", "No script “{fichier}”."));
    }
    if !accord(&trf!(
        "  Effacer « {fichier} » du labo et son approbation ? [o/N] : ",
        "  Delete “{fichier}” from the lab and its approval? [y/N]: "
    )) {
        return Ok(false);
    }
    // Un lien est effacé lui-même, sans suivre ce qu'il désigne.
    if std::fs::symlink_metadata(&chemin).is_ok() {
        std::fs::remove_file(&chemin).map_err(|e| e.to_string())?;
    }
    reglages::oublier(racine, true, fichier)?;
    if a.labo.remove(fichier).is_some() {
        enregistrer(racine, &a)?;
    }
    Ok(true)
}

/// Le libellé d'un état, pour les listes et le menu.
pub fn libelle(e: &Etat) -> String {
    match e {
        Etat::Approuve => tr!("approuvé", "approved").to_string(),
        Etat::NonApprouve => tr!("non approuvé", "not approved").to_string(),
        Etat::Change => tr!("modifié depuis l'approbation", "changed since approval").to_string(),
        Etat::Refuse(pourquoi) => trf!("refusé : {}", "refused: {}", affichable(pourquoi)),
    }
}

/// `vanguard labo …` : rend le code de sortie.
pub fn commande(quoi: &[String]) -> i32 {
    let racine = match dossier() {
        Ok(r) => r,
        Err(e) => return echec(&e),
    };
    match quoi.first().map(String::as_str) {
        None => {
            menu::labo(&racine);
            0
        }
        Some("liste" | "list") => {
            liste(&racine);
            0
        }
        Some("ouvrir" | "open") => {
            if eleve() {
                return echec(&refus_eleve());
            }
            match dossier_labo(&racine) {
                Ok(d) => {
                    montrer_dossier(&d);
                    0
                }
                Err(e) => echec(&e),
            }
        }
        Some(fichier) => {
            let (_, facon, arguments) = options_de_lancement(&quoi[1..]);
            executer(&racine, fichier, &arguments, facon)
        }
    }
}

pub fn montrer_dossier(d: &Path) {
    trp!(
        "  Dossier du labo (posez vos scripts ici : .sh, .bash, .ps1, .py ou un programme) :",
        "  Lab folder (put your scripts here: .sh, .bash, .ps1, .py or a program):"
    );
    println!("  {}", chemin_affichable(d));
}

fn liste(racine: &Path) {
    titre(tr!("Laboratoire (expérimental)", "Lab (experimental)"));
    let scripts = scripts(racine);
    if scripts.is_empty() {
        trp!("  Aucun script dans le labo.", "  No script in the lab.");
        if let Ok(d) = dossier_labo(racine) {
            montrer_dossier(&d);
        }
        return;
    }
    for s in &scripts {
        let marque = match s.etat {
            Etat::Approuve => format!("{VERT}✔{RESET}"),
            Etat::NonApprouve => format!("{}•{RESET}", couleur(crate::risk::Niveau::Moyen)),
            _ => format!("{}✖{RESET}", couleur(crate::risk::Niveau::Eleve)),
        };
        afficher_aligne(
            &format!("  {marque} {GRAS}{}{RESET} ", affichable(&s.fichier)),
            &libelle(&s.etat),
            4,
            GRIS,
        );
    }
    trp!(
        "  {GRIS}Lancer : vanguard labo <fichier> [arguments]{RESET}",
        "  {GRIS}Run: vanguard lab <file> [arguments]{RESET}"
    );
}
