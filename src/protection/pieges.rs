//! Fichiers-pièges contre les rançongiciels : deux fichiers leurres (un texte et un PDF) dans Documents, Images et
//! Bureau. Personne n'a de raison d'y toucher ; un rançongiciel, lui, chiffre tout ce qu'il trouve, souvent dans
//! l'ordre alphabétique : leur nom commence par « ! » pour passer parmi les premiers, et finit par un code tiré au
//! hasard pour ne jamais être le même d'un ordinateur à l'autre. Chaque bilan, et la surveillance toutes les heures,
//! compare leur empreinte à celle de leur pose : modifié, ou renommé avec une extension en plus (« .locked »), c'est
//! l'alerte. Vanguard n'arrête aucun programme lui-même : il prévient et dit quoi faire.
//!
//! Posés et retirés seulement après accord ; la liste exacte est gardée dans pieges.json, le retrait n'enlève qu'elle.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::machine::{Constat, Correctif};
use crate::risk::Niveau;
use crate::ui::*;

const CAT: &str = "Rançongiciels";

/// Un fichier-piège posé : son chemin et l'empreinte BLAKE3 de son contenu au moment de la pose.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Piege {
    chemin: PathBuf,
    empreinte: String,
}

/// Ce qu'est devenu un fichier-piège.
#[derive(Debug, PartialEq)]
enum Etat {
    Intact,
    Modifie,
    /// Renommé avec une extension en plus, comme le font la plupart des rançongiciels.
    Renomme(PathBuf),
    Supprime,
    /// Présent mais pas lisible (verrouillé par un antivirus, fichier OneDrive en ligne seulement, droits) : rien n'est
    /// conclu.
    Illisible,
}

/// La liste exacte des fichiers-pièges posés, dans le dossier de données : sans elle, ils ne se retirent plus
/// exactement.
pub(crate) const LISTE: &str = "pieges.json";

fn fichier() -> PathBuf {
    crate::socle::dossier_local().join(LISTE)
}

/// Les fichiers-pièges posés ; `Err` si la liste existe mais ne se lit plus.
fn charger() -> Result<Vec<Piege>, ()> {
    charger_de(&fichier())
}

/// Les chemins des fichiers-pièges posés, pour que le veilleur anti-rançongiciel les surveille en direct et juge R6
/// avec la même liste que le bilan. Vide si la liste est absente ou illisible (« non vérifié = dit » : sans pièges,
/// R6 ne se déclenche jamais, au lieu d'un faux).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn chemins_poses() -> Vec<PathBuf> {
    charger().unwrap_or_default().into_iter().map(|p| p.chemin).collect()
}

/// Les dossiers que le veilleur anti-rançongiciel surveille en direct : ceux des pièges (Documents, Images, Bureau),
/// plus Musique, Vidéos et Téléchargements. L'accord promet « tes dossiers personnels » : les trois premiers seuls
/// laissaient chiffrer le reste sans un mot. Les pièges, eux, restent dans les trois premiers. Un disque monté ou un
/// dossier de projets s'ajoute à la main (réglages), pas d'office.
#[cfg(target_os = "linux")]
pub(crate) fn dossiers_a_veiller() -> Vec<PathBuf> {
    let maison = crate::socle::maison();
    let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
    let declares = std::fs::read_to_string(config.join("user-dirs.dirs")).unwrap_or_default();
    let mut liste = dossiers();
    liste.extend(dossiers_en_plus(&declares, &maison).into_iter().filter(|d| d.is_dir()));
    liste.sort();
    liste.dedup();
    liste
}

/// Musique, Vidéos et Téléchargements d'après user-dirs.dirs (dans la langue du bureau), sinon leurs noms courants
/// en français et en anglais. Sans regarder le disque : l'appelant garde ceux qui existent.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn dossiers_en_plus(declares: &str, maison: &Path) -> Vec<PathBuf> {
    let mut liste = Vec::new();
    for (cle, noms) in [
        ("XDG_MUSIC_DIR", ["Musique", "Music"]),
        ("XDG_VIDEOS_DIR", ["Vidéos", "Videos"]),
        ("XDG_DOWNLOAD_DIR", ["Téléchargements", "Downloads"]),
    ] {
        match dossier_declare(declares, cle, maison) {
            Some(d) => liste.push(d),
            None => liste.extend(noms.iter().map(|n| maison.join(n))),
        }
    }
    liste
}

fn charger_de(liste: &Path) -> Result<Vec<Piege>, ()> {
    match std::fs::read_to_string(liste) {
        Ok(texte) => serde_json::from_str(&texte).map_err(|_| ()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(()),
    }
}

fn etat(piege: &Piege) -> Etat {
    match std::fs::read(&piege.chemin) {
        Ok(octets) if blake3::hash(&octets).to_hex().as_str() == piege.empreinte => Etat::Intact,
        Ok(_) => Etat::Modifie,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            renomme(&piege.chemin).map_or(Etat::Supprime, Etat::Renomme)
        }
        Err(_) => Etat::Illisible,
    }
}

/// Le fichier-piège renommé avec une extension en plus : « !Vanguard … 3f9a.txt.locked ».
fn renomme(chemin: &Path) -> Option<PathBuf> {
    let nom = chemin.file_name()?.to_str()?;
    std::fs::read_dir(chemin.parent()?)
        .ok()?
        .flatten()
        .map(|f| f.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.len() > nom.len() && n.starts_with(nom) && n[nom.len()..].starts_with('.'))
        })
}

/// Dossiers personnels où frappent d'abord les rançongiciels : Documents, Images, Bureau (ceux qui existent).
fn dossiers() -> Vec<PathBuf> {
    let mut liste = dossiers_du_systeme();
    liste.retain(|d| d.is_dir());
    liste.sort();
    liste.dedup();
    liste
}

#[cfg(target_os = "linux")]
fn dossiers_du_systeme() -> Vec<PathBuf> {
    let maison = crate::socle::maison();
    // Noms des dossiers dans la langue du bureau : ~/.config/user-dirs.dirs (« XDG_DOCUMENTS_DIR="$HOME/Documents" »).
    let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
    let declares = std::fs::read_to_string(config.join("user-dirs.dirs")).unwrap_or_default();
    let mut liste: Vec<PathBuf> = ["XDG_DOCUMENTS_DIR", "XDG_PICTURES_DIR", "XDG_DESKTOP_DIR"]
        .iter()
        .filter_map(|cle| dossier_declare(&declares, cle, &maison))
        .collect();
    if liste.is_empty() {
        liste = ["Documents", "Images", "Pictures", "Bureau", "Desktop"]
            .iter()
            .map(|d| maison.join(d))
            .collect();
    }
    liste
}

/// Un dossier de user-dirs.dirs. « $HOME » seul (dossier non configuré) n'est pas un dossier personnel.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn dossier_declare(declares: &str, cle: &str, maison: &Path) -> Option<PathBuf> {
    let valeur = declares
        .lines()
        .find_map(|l| l.trim().strip_prefix(cle)?.strip_prefix('='))?
        .trim()
        .trim_matches('"');
    let chemin = match valeur.strip_prefix("$HOME") {
        Some(reste) => maison.join(reste.trim_start_matches('/')),
        None => PathBuf::from(valeur),
    };
    (chemin != maison && chemin.is_absolute()).then_some(chemin)
}

/// Windows : les dossiers déclarés pour le compte (déplacés dans OneDrive le cas échéant), sinon ceux du profil.
/// « User Shell Folders » fait foi (chemins à développer, « %USERPROFILE%\Documents ») ; « Shell Folders » n'en est
/// qu'une copie de compatibilité, parfois périmée : en secours seulement.
#[cfg(windows)]
fn dossiers_du_systeme() -> Vec<PathBuf> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;
    let profil = PathBuf::from(std::env::var_os("USERPROFILE").unwrap_or_default());
    let cle = |nom: &str| {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(format!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\{nom}"))
            .ok()
    };
    let (declares, copie) = (cle("User Shell Folders"), cle("Shell Folders"));
    [
        ("Personal", "Documents"),
        ("My Pictures", "Pictures"),
        ("Desktop", "Desktop"),
    ]
    .iter()
    .map(|(valeur, defaut)| {
        declares
            .as_ref()
            .and_then(|d| d.get_value::<String, _>(valeur).ok())
            .map(|c| developper(&c))
            .or_else(|| copie.as_ref().and_then(|d| d.get_value::<String, _>(valeur).ok()))
            .map_or_else(|| profil.join(defaut), PathBuf::from)
    })
    .collect()
}

/// « %USERPROFILE%\Documents » → le vrai chemin, d'après les variables d'environnement ; une variable inconnue reste
/// telle quelle.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn developper(chemin: &str) -> String {
    let mut sortie = String::new();
    let mut reste = chemin;
    while let Some(debut) = reste.find('%') {
        sortie.push_str(&reste[..debut]);
        let apres = &reste[debut + 1..];
        let Some(fin) = apres.find('%') else {
            sortie.push_str(&reste[debut..]);
            reste = "";
            break;
        };
        let nom = &apres[..fin];
        match std::env::var(nom) {
            Ok(valeur) if !nom.is_empty() => sortie.push_str(&valeur),
            _ => {
                sortie.push('%');
                sortie.push_str(nom);
                sortie.push('%');
            }
        }
        reste = &apres[fin + 1..];
    }
    sortie.push_str(reste);
    sortie
}

#[cfg(target_os = "macos")]
fn dossiers_du_systeme() -> Vec<PathBuf> {
    let maison = crate::socle::maison();
    ["Documents", "Pictures", "Desktop"]
        .iter()
        .map(|d| maison.join(d))
        .collect()
}

/// Code tiré au hasard (4 chiffres hexadécimaux), pour que le nom change d'un ordinateur et d'une pose à l'autre.
fn code(graine: usize) -> String {
    let instant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let melange = format!("{instant}-{}-{graine}", std::process::id());
    blake3::hash(melange.as_bytes()).to_hex()[..4].to_string()
}

fn nom(code: &str, extension: &str) -> String {
    trf!(
        "!Vanguard - fichier-piège {code}.{extension}",
        "!Vanguard - decoy file {code}.{extension}"
    )
}

/// Le texte d'un fichier-piège : ce qu'il est, dans les deux langues (la personne qui l'ouvre comprend), puis assez
/// de lignes pour qu'il ne passe pas pour un fichier vide, que certains rançongiciels sautent.
fn texte() -> String {
    let mut t = String::from(
        "Fichier-piège de Vanguard : ne le modifiez pas, ne le déplacez pas, ne le supprimez pas.\n\
         Il sert à repérer un rançongiciel : s'il change, Vanguard vous alerte.\n\
         Pour le retirer : Vanguard, menu Antivirus et protection › Fichiers-pièges, ou « vanguard pieges --retirer ».\n\n\
         Vanguard decoy file: do not modify, move or delete it.\n\
         It is there to catch ransomware: if it changes, Vanguard warns you.\n\
         To remove it: Vanguard, Antivirus and protection menu › Decoy files, or “vanguard decoys --remove”.\n\n",
    );
    for i in 1..=250 {
        let _ = writeln!(t, "{i:03}  rien d'important ici / nothing important here");
    }
    t
}

/// Un PDF d'une page qui dit ce qu'il est, lisible par tout lecteur de PDF (les rançongiciels visent les PDF).
fn pdf() -> Vec<u8> {
    let page = "BT /F1 14 Tf 50 780 Td (Fichier-piege de Vanguard : ne pas modifier, deplacer ni supprimer.) Tj \
                0 -24 Td (Vanguard decoy file: do not modify, move or delete it.) Tj ET";
    let objets = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> >>"
            .to_string(),
        format!("<< /Length {} >>\nstream\n{page}\nendstream", page.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    // Commentaire de remplissage (permis après l'en-tête) : un PDF de quelques centaines d'octets serait sauté.
    let mut sortie = format!("%PDF-1.4\n%{}\n", "Vanguard ".repeat(2000));
    let mut positions = Vec::new();
    for (i, objet) in objets.iter().enumerate() {
        positions.push(sortie.len());
        let _ = write!(sortie, "{} 0 obj\n{objet}\nendobj\n", i + 1);
    }
    let table = sortie.len();
    let _ = write!(sortie, "xref\n0 {}\n0000000000 65535 f \n", objets.len() + 1);
    for p in positions {
        let _ = writeln!(sortie, "{p:010} 00000 n ");
    }
    let _ = write!(
        sortie,
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{table}\n%%EOF\n",
        objets.len() + 1
    );
    sortie.into_bytes()
}

/// Windows : les dossiers où l'accès contrôlé aux dossiers de Defender bloque déjà les programmes inconnus. Il
/// protège d'office Documents et Images, même déplacés (OneDrive compris), et ceux qu'on lui a ajoutés ; pas le Bureau.
/// Un piège y serait inutile, et Windows bloquerait Vanguard en affichant une alerte.
#[cfg(windows)]
fn proteges_par_windows() -> Vec<PathBuf> {
    let Some(ajoutes) = crate::optimiser::dossiers_controles() else {
        return Vec::new();
    };
    // `dossiers_du_systeme` : Documents, Images, puis Bureau.
    let mut l: Vec<PathBuf> = dossiers_du_systeme().into_iter().take(2).collect();
    l.extend(
        dossiers()
            .into_iter()
            .filter(|d| ajoutes.iter().any(|a| sous_dossier(d, a))),
    );
    l
}

#[cfg(not(windows))]
fn proteges_par_windows() -> Vec<PathBuf> {
    Vec::new()
}

/// `dossier` est-il `parent` ou dedans ? À la façon de Windows : sans tenir compte de la casse.
#[cfg_attr(not(windows), allow(dead_code))]
fn sous_dossier(dossier: &Path, parent: &str) -> bool {
    let d = dossier.to_string_lossy().to_lowercase();
    let p = parent.trim_end_matches(['\\', '/']).to_lowercase();
    !p.is_empty() && (d == p || d.strip_prefix(&p).is_some_and(|reste| reste.starts_with(['\\', '/'])))
}

/// Pose un texte et un PDF dans chaque dossier. Création exclusive : jamais un fichier existant écrasé. Rend aussi
/// les dossiers refusés, avec la première erreur : sans eux, la personne croirait protégé un dossier qui ne l'est pas
/// (l'accès contrôlé aux dossiers de Defender, par exemple, bloque l'écriture dans Documents).
fn poser_dans(dossiers: &[PathBuf]) -> (Vec<Piege>, Vec<(PathBuf, std::io::Error)>) {
    let mut poses = Vec::new();
    let mut refus = Vec::new();
    for (i, dossier) in dossiers.iter().enumerate() {
        let code = code(i);
        let mut erreur = None;
        for (extension, contenu) in [("txt", texte().into_bytes()), ("pdf", pdf())] {
            let chemin = dossier.join(nom(&code, extension));
            let ecrit = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&chemin)
                .and_then(|mut f| std::io::Write::write_all(&mut f, &contenu));
            match ecrit {
                Ok(()) => poses.push(Piege {
                    chemin,
                    empreinte: blake3::hash(&contenu).to_hex().to_string(),
                }),
                Err(e) => {
                    erreur.get_or_insert(e);
                }
            }
        }
        if let Some(e) = erreur {
            refus.push((dossier.clone(), e));
        }
    }
    (poses, refus)
}

fn enregistrer(pieges: &[Piege], liste: &Path) -> std::io::Result<()> {
    if let Some(dossier) = liste.parent() {
        std::fs::create_dir_all(dossier)?;
    }
    crate::socle::ecrire_atomique(liste, serde_json::to_string_pretty(pieges).unwrap_or_default())
}

/// Retire exactement les fichiers posés et intacts, puis la liste. Un piège modifié ou renommé reste : c'est la preuve
/// d'un rançongiciel ; un piège illisible reste aussi (on ne sait pas ce qu'il est devenu). La liste ne garde alors que
/// les pièges restés en place : ceux déjà retirés passeraient pour supprimés par un programme. Rend (fichiers qui
/// n'ont pas pu être retirés, fichiers gardés comme preuve).
fn retirer_tous(pieges: &[Piege], liste: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let (mut restes, mut preuves) = (Vec::new(), Vec::new());
    let mut gardes = Vec::new();
    for p in pieges {
        match etat(p) {
            Etat::Intact => {
                if std::fs::remove_file(&p.chemin).is_err() {
                    gardes.push(p.clone());
                }
            }
            Etat::Modifie => preuves.push(p.chemin.clone()),
            Etat::Renomme(nouveau) => preuves.push(nouveau),
            Etat::Illisible => gardes.push(p.clone()),
            Etat::Supprime => {}
        }
    }
    if gardes.is_empty() {
        let _ = std::fs::remove_file(liste);
    } else {
        let _ = enregistrer(&gardes, liste);
        restes.extend(gardes.into_iter().map(|p| p.chemin));
    }
    (restes, preuves)
}

/// Le nombre de fichiers-pièges posés, d'après la liste du dossier de données `donnees` ; `Err` si elle ne se lit plus.
pub(crate) fn nombre_dans(donnees: &Path) -> Result<usize, ()> {
    charger_de(&donnees.join(LISTE)).map(|p| p.len())
}

/// Retire les fichiers-pièges sans question (la désinstallation l'a montré et fait accepter) : rend ceux qui n'ont
/// pas pu partir, et ceux gardés comme preuves (modifiés ou renommés : la trace d'un passage). `Err` si la liste ne
/// se lit plus.
pub(crate) fn retirer_sans_question() -> Result<(Vec<PathBuf>, Vec<PathBuf>), ()> {
    let pieges = charger()?;
    Ok(retirer_tous(&pieges, &fichier()))
}

/// Un constat de la catégorie, avec une marche à suivre à faire soi-même.
fn constat_de(probleme: Option<Niveau>, message: String, conseil: Option<&str>) -> Constat {
    Constat {
        categorie: CAT,
        probleme,
        message,
        correctif: conseil.map(|c| Correctif {
            action: c.to_string(),
            commandes: Vec::new(),
            automatique: false,
            bloque: None,
            defaire: crate::machine::Defaire::Inconnu,
        }),
        verifie: true,
        regle: "",
        objet: crate::modele::Objet::NonMigre,
        precision: crate::modele::Precision::Aucune,
    }
}

/// Constat du bilan : rien tant qu'aucun fichier-piège n'est posé.
pub fn constat() -> Option<Constat> {
    let Ok(pieges) = charger() else {
        return Some(Constat {
            verifie: false,
            ..constat_de(
                Some(Niveau::Info),
                trf!(
                    "Impossible de vérifier ({}).",
                    "Could not check ({}).",
                    tr!("liste des fichiers-pièges illisible", "decoy file list unreadable")
                ),
                None,
            )
        });
    };
    if pieges.is_empty() {
        return None;
    }
    let etats: Vec<(&Piege, Etat)> = pieges.iter().map(|p| (p, etat(p))).collect();
    Some(juger(&etats))
}

/// Le constat d'après ce que sont devenus les fichiers-pièges. Les chemins sont montrés rendus inoffensifs : un
/// rançongiciel choisit le nouveau nom du fichier qu'il renomme, et pourrait sinon effacer l'alerte.
fn juger(etats: &[(&Piege, Etat)]) -> Constat {
    let touches: Vec<String> = etats
        .iter()
        .filter_map(|(p, e)| match e {
            Etat::Modifie => Some(trf!("{} (modifié)", "{} (modified)", chemin_affichable(&p.chemin))),
            Etat::Renomme(n) => Some(trf!(
                "{} (renommé en {})",
                "{} (renamed to {})",
                chemin_affichable(&p.chemin),
                chemin_affichable(n)
            )),
            _ => None,
        })
        .collect();
    let supprimes: Vec<String> = etats
        .iter()
        .filter(|(_, e)| *e == Etat::Supprime)
        .map(|(p, _)| chemin_affichable(&p.chemin))
        .collect();
    let illisibles: Vec<String> = etats
        .iter()
        .filter(|(_, e)| *e == Etat::Illisible)
        .map(|(p, _)| chemin_affichable(&p.chemin))
        .collect();
    if !touches.is_empty() {
        constat_de(
            Some(Niveau::Critique),
            trf!(
                "Fichier-piège touché : {}. Un rançongiciel chiffre peut-être vos fichiers en ce moment.",
                "Decoy file touched: {}. Ransomware may be encrypting your files right now.",
                touches.join(", ")
            ),
            Some(tr!(
                "Débranchez tout de suite Internet (câble, Wi-Fi) et vos disques de sauvegarde, puis éteignez l'ordinateur pour arrêter le chiffrement. Ensuite, analysez-le avec l'antivirus de Vanguard depuis la clé, avant de le rebrancher. Si c'est vous qui avez ouvert et modifié ce fichier, reposez les fichiers-pièges",
                "Unplug the Internet (cable, Wi-Fi) and your backup drives right now, then shut the computer down to stop the encryption. Then scan it with Vanguard's antivirus from the key before plugging it back in. If you opened and changed that file yourself, set the decoy files again"
            )),
        )
    } else if !supprimes.is_empty() {
        constat_de(
            Some(Niveau::Moyen),
            trf!(
                "Fichier-piège supprimé : {}. Si ce n'est pas vous, un programme touche à vos documents.",
                "Decoy file deleted: {}. If it was not you, a program is touching your documents.",
                supprimes.join(", ")
            ),
            Some(tr!(
                "Si c'est vous, reposez les fichiers-pièges (menu Antivirus et protection) ; sinon, lancez une analyse antivirus",
                "If it was you, set the decoy files again (Antivirus and protection menu); otherwise, run an antivirus scan"
            )),
        )
    } else if !illisibles.is_empty() {
        // Verrouillé ou en ligne seulement : ce qu'il contient n'est pas connu, donc jamais compté comme intact.
        Constat {
            verifie: false,
            ..constat_de(
                Some(Niveau::Info),
                trf!(
                    "Impossible de vérifier ({}).",
                    "Could not check ({}).",
                    trf!(
                        "fichier-piège illisible, verrouillé ou en ligne seulement : {}",
                        "decoy file unreadable, locked or online-only: {}",
                        illisibles.join(", ")
                    )
                ),
                None,
            )
        }
    } else {
        constat_de(
            None,
            trf!(
                "{} fichiers-pièges intacts : aucun rançongiciel n'y a touché.",
                "{} decoy files intact: no ransomware touched them.",
                etats.len()
            ),
            None,
        )
    }
}

/// Un paragraphe coupé pour tenir dans la largeur de l'écran, en retrait de deux espaces.
fn dire(texte: &str) {
    for ligne in envelopper(texte, LARGEUR - 2) {
        println!("  {ligne}");
    }
}

/// Menu Antivirus et protection › Fichiers-pièges : poser, voir où ils en sont, ou les retirer.
pub fn menu() {
    titre(tr!(
        "Fichiers-pièges contre les rançongiciels",
        "Decoy files against ransomware"
    ));
    let Ok(pieges) = charger() else {
        trp!(
            "  ✖ La liste des fichiers-pièges ne se lit plus : {}",
            "  ✖ The decoy file list can no longer be read: {}",
            fichier().display()
        );
        return;
    };
    if pieges.is_empty() {
        poser();
    } else {
        for p in &pieges {
            let (marque, texte) = match etat(p) {
                Etat::Intact => (format!("{VERT}✔{RESET}"), tr!("intact", "intact").to_string()),
                Etat::Modifie => (
                    format!("{}✖{RESET}", couleur(Niveau::Critique)),
                    tr!("MODIFIÉ", "MODIFIED").to_string(),
                ),
                Etat::Renomme(n) => (
                    format!("{}✖{RESET}", couleur(Niveau::Critique)),
                    trf!("RENOMMÉ en {}", "RENAMED to {}", chemin_affichable(&n)),
                ),
                Etat::Supprime => (
                    format!("{}⚠{RESET}", couleur(Niveau::Moyen)),
                    tr!("supprimé", "deleted").to_string(),
                ),
                Etat::Illisible => (format!("{GRIS}?{RESET}"), tr!("illisible", "unreadable").to_string()),
            };
            println!("  {marque} {}  {GRIS}{texte}{RESET}", chemin_affichable(&p.chemin));
        }
        if let Some(c) = constat()
            && c.probleme.is_some()
        {
            println!();
            dire(&c.message);
            if let Some(k) = &c.correctif {
                dire(&k.action);
            }
        }
        retirer(&pieges, false);
    }
}

/// Montre où iront les fichiers-pièges, puis les pose après accord.
fn poser() {
    let proteges = proteges_par_windows();
    let (cibles, deja): (Vec<PathBuf>, Vec<PathBuf>) = dossiers().into_iter().partition(|d| !proteges.contains(d));
    for d in &deja {
        afficher_aligne(
            &format!("  {VERT}✔{RESET} "),
            &trf!(
                "{} : déjà protégé par l'accès contrôlé aux dossiers de Windows, qui bloque les programmes inconnus ; un piège y serait inutile.",
                "{}: already protected by Windows controlled folder access, which blocks unknown programs; a decoy would be useless there.",
                chemin_affichable(d)
            ),
            4,
            "",
        );
    }
    if cibles.is_empty() && !deja.is_empty() {
        return;
    }
    if cibles.is_empty() {
        trp!(
            "  Aucun dossier Documents, Images ou Bureau trouvé.",
            "  No Documents, Pictures or Desktop folder found."
        );
        return;
    }
    dire(tr!(
        "Vanguard peut poser un texte et un PDF leurres dans vos dossiers. Personne n'a de raison d'y toucher ; un rançongiciel, lui, les chiffre avec le reste : chaque bilan, et la surveillance toutes les heures, le voient et vous alertent. Leur nom commence par « !Vanguard » ; ils s'enlèvent d'ici, en une fois.",
        "Vanguard can place a decoy text file and PDF in your folders. Nobody has a reason to touch them; ransomware encrypts them along with everything else: each check, and hourly monitoring, see it and warn you. Their name starts with “!Vanguard”; they are removed from here, in one go."
    ));
    println!();
    for d in &cibles {
        println!("    {GRIS}{}{RESET}", chemin_affichable(d));
    }
    if !demander(tr!(
        "\n  Poser les fichiers-pièges dans ces dossiers ? [o/N] : ",
        "\n  Place the decoy files in these folders? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a été posé.", "  Nothing was placed.");
        return;
    }
    let (poses, refus) = poser_dans(&cibles);
    for (dossier, e) in &refus {
        println!(
            "  {}✖{RESET} {}",
            couleur(Niveau::Critique),
            trf!(
                "Pas de fichier-piège dans {} ({e}).",
                "No decoy file in {} ({e}).",
                chemin_affichable(dossier)
            )
        );
    }
    if poses.is_empty() {
        trp!("  Rien n'a été posé.", "  Nothing was placed.");
        return;
    }
    match enregistrer(&poses, &fichier()) {
        Ok(()) => {
            println!(
                "  {VERT}✔{RESET} {}",
                trf!("{} fichiers-pièges posés.", "{} decoy files placed.", poses.len())
            );
            if !crate::reseau::surveillance::active() {
                dire(tr!(
                    "Activez la surveillance (menu Réseau et Internet) pour qu'ils soient vérifiés toutes les heures, et pas seulement à chaque bilan.",
                    "Turn monitoring on (Network and Internet menu) so they are checked every hour, not only at each check."
                ));
            }
        }
        Err(e) => {
            // Sans la liste, on ne saurait ni les vérifier ni les retirer exactement : on les retire tout de suite.
            retirer_tous(&poses, &fichier());
            dire(&trf!(
                "✖ Liste des fichiers-pièges impossible à écrire ({e}) : rien n'est posé.",
                "✖ Could not write the decoy file list ({e}): nothing is placed."
            ));
        }
    }
}

/// Propose de retirer les fichiers-pièges ; `force` : sans question (ligne de commande « --retirer »).
fn retirer(pieges: &[Piege], force: bool) {
    if !force
        && !demander(tr!(
            "\n  Retirer les fichiers-pièges ? [o/N] : ",
            "\n  Remove the decoy files? [y/N]: "
        ))
        .oui()
    {
        return;
    }
    let (restes, preuves) = retirer_tous(pieges, &fichier());
    if restes.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Fichiers-pièges retirés.",
            "  {VERT}✔{RESET} Decoy files removed."
        );
    } else {
        for r in &restes {
            trp!(
                "  ✖ Impossible de retirer {}",
                "  ✖ Could not remove {}",
                chemin_affichable(r)
            );
        }
    }
    for p in &preuves {
        trp!(
            "  ⚠ Gardé, c'est la preuve d'un passage : {}",
            "  ⚠ Kept, it is the evidence of an attack: {}",
            chemin_affichable(p)
        );
    }
}

/// « vanguard pieges » : comme le menu ; « --retirer » : retire sans question.
pub fn commande(retirer_seulement: bool) {
    if !retirer_seulement {
        menu();
        return;
    }
    match charger() {
        Ok(p) if p.is_empty() => trp!("  Aucun fichier-piège posé.", "  No decoy file placed."),
        Ok(p) => retirer(&p, true),
        Err(()) => trp!(
            "  ✖ La liste des fichiers-pièges ne se lit plus : {}",
            "  ✖ The decoy file list can no longer be read: {}",
            fichier().display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veille_aussi_musique_videos_telechargements() {
        let maison = Path::new("/home/alice");
        let declares = "XDG_MUSIC_DIR=\"$HOME/Musique\"\nXDG_VIDEOS_DIR=\"$HOME/Vidéos\"\nXDG_DOWNLOAD_DIR=\"$HOME/Téléchargements\"\n";
        let liste = dossiers_en_plus(declares, maison);
        for d in ["Musique", "Vidéos", "Téléchargements"] {
            assert!(liste.contains(&maison.join(d)), "{d} : {liste:?}");
        }
        // Sans user-dirs.dirs : les noms courants.
        let repli = dossiers_en_plus("", maison);
        assert!(repli.contains(&maison.join("Downloads")));
        assert!(repli.contains(&maison.join("Musique")));
    }

    fn dossier_jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-pieges-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn pose_verification_retrait() {
        let d = dossier_jetable("pose");
        let (pieges, _) = poser_dans(std::slice::from_ref(&d));
        assert_eq!(pieges.len(), 2);
        for p in &pieges {
            let nom = p.chemin.file_name().unwrap().to_str().unwrap();
            assert!(nom.starts_with("!Vanguard - "), "{nom}");
            assert_eq!(etat(p), Etat::Intact);
        }
        // Un rançongiciel chiffre le texte, et renomme le PDF avec son extension.
        std::fs::write(&pieges[0].chemin, b"\x8f\x02chiffre").unwrap();
        assert_eq!(etat(&pieges[0]), Etat::Modifie);
        let verrouille = PathBuf::from(format!("{}.locked", pieges[1].chemin.display()));
        std::fs::rename(&pieges[1].chemin, &verrouille).unwrap();
        assert_eq!(etat(&pieges[1]), Etat::Renomme(verrouille.clone()));
        std::fs::remove_file(&verrouille).unwrap();
        assert_eq!(etat(&pieges[1]), Etat::Supprime);
        // Retrait exact : les pièges intacts partent ; le modifié reste, c'est la preuve ; un fichier de la personne
        // n'est pas touché.
        std::fs::write(d.join("mes notes.txt"), "à garder").unwrap();
        let (restes, preuves) = retirer_tous(&pieges, &d.join("pieges.json"));
        assert_eq!(restes, Vec::<PathBuf>::new());
        assert_eq!(preuves, [pieges[0].chemin.clone()]);
        assert!(pieges[0].chemin.exists());
        assert!(d.join("mes notes.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un rançongiciel choisit le nouveau nom du fichier qu'il chiffre : un nom piégé (effacement de ligne, retour
    /// chariot, montée du curseur, bidi) ne doit ni effacer l'alerte ni la réécrire.
    #[test]
    fn nom_choisi_par_un_rancongiciel() {
        let p = Piege {
            chemin: PathBuf::from("/home/alice/Documents/piege 3f9a.txt"),
            empreinte: String::new(),
        };
        let renomme = PathBuf::from("/home/alice/Documents/piege 3f9a.txt.\x1b[2K\r\x1b[1A\u{202e}locked");
        let c = juger(&[(&p, Etat::Renomme(renomme))]);
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(!crate::ui::contient_un_piege(&c.message), "{}", c.message);
        assert!(c.message.contains("piege 3f9a.txt.�[2K��[1A�locked"), "{}", c.message);
        let c = juger(&[(&p, Etat::Intact), (&p, Etat::Intact)]);
        assert_eq!((c.probleme, c.message.starts_with('2')), (None, true));
    }

    // Retrait en partie refusé : la liste ne garde que les pièges restés en place. Avec les pièges déjà retirés, le
    // bilan suivant les aurait dits « supprimés » et aurait soupçonné un programme.
    #[cfg(unix)]
    #[test]
    fn retrait_partiel_liste_a_jour() {
        use std::os::unix::fs::PermissionsExt;
        let d = dossier_jetable("partiel");
        let liste = d.join("pieges.json");
        let (pieges, _) = poser_dans(std::slice::from_ref(&d));
        enregistrer(&pieges, &liste).unwrap();
        std::fs::set_permissions(&pieges[0].chemin, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&pieges[0].chemin).is_ok() {
            let _ = std::fs::remove_dir_all(&d);
            return crate::essais::saute("en root : un fichier en 000 se lit encore");
        }
        let (restes, _) = retirer_tous(&pieges, &liste);
        assert_eq!(restes, [pieges[0].chemin.clone()]);
        assert!(!pieges[1].chemin.exists());
        let gardes: Vec<Piege> = serde_json::from_str(&std::fs::read_to_string(&liste).unwrap()).unwrap();
        assert_eq!(gardes, [pieges[0].clone()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    // Un fichier sans droit de lecture : « illisible », jamais « supprimé » (root lit tout : rien à essayer alors).
    #[cfg(unix)]
    #[test]
    fn piege_illisible() {
        use std::os::unix::fs::PermissionsExt;
        let d = dossier_jetable("illisible");
        let (pieges, _) = poser_dans(std::slice::from_ref(&d));
        std::fs::set_permissions(&pieges[0].chemin, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&pieges[0].chemin).is_err() {
            assert_eq!(etat(&pieges[0]), Etat::Illisible);
        }
        std::fs::set_permissions(&pieges[0].chemin, std::fs::Permissions::from_mode(0o600)).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    // Un dossier refusé est rendu avec son erreur, une seule fois ; les autres dossiers reçoivent quand même leurs pièges.
    #[test]
    fn dossier_refuse_signale() {
        let d = dossier_jetable("refus");
        let absent = d.join("absent");
        let (pieges, refus) = poser_dans(&[d.clone(), absent.clone()]);
        assert_eq!(pieges.len(), 2);
        assert_eq!(refus.len(), 1);
        assert_eq!(refus[0].0, absent);
        assert_eq!(refus[0].1.kind(), std::io::ErrorKind::NotFound);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dossiers_ajoutes_a_l_acces_controle() {
        let d = Path::new("C:\\Users\\alice\\Desktop");
        assert!(sous_dossier(d, "c:\\users\\alice\\desktop"));
        assert!(sous_dossier(d, "C:\\Users\\alice\\"));
        // Un nom qui commence pareil n'est pas un dossier parent.
        assert!(!sous_dossier(d, "C:\\Users\\alice\\Desk"));
        assert!(!sous_dossier(d, ""));
    }

    #[test]
    fn variables_developpees() {
        let path = std::env::var("PATH").unwrap_or_default();
        assert_eq!(developper("%PATH%\\x"), format!("{path}\\x"));
        assert_eq!(developper("%VANGUARD_INCONNUE%\\y"), "%VANGUARD_INCONNUE%\\y");
        assert_eq!(developper("50% de 10"), "50% de 10");
        assert_eq!(developper("sans"), "sans");
    }

    #[test]
    fn jamais_un_fichier_ecrase() {
        let d = dossier_jetable("existant");
        let (premier, _) = poser_dans(std::slice::from_ref(&d));
        // Même nom imposé : la création exclusive refuse, le fichier d'avant est intact.
        std::fs::write(&premier[0].chemin, "contenu de la personne").unwrap();
        let ecrit = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&premier[0].chemin);
        assert!(ecrit.is_err());
        assert_eq!(
            std::fs::read_to_string(&premier[0].chemin).unwrap(),
            "contenu de la personne"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn pdf_valide() {
        let pdf = pdf();
        let texte = String::from_utf8(pdf.clone()).unwrap();
        assert!(texte.starts_with("%PDF-1.4\n"));
        assert!(pdf.len() > 15_000);
        // La table des objets est là où « startxref » le dit, et chaque entrée pointe sur son objet.
        let table: usize = texte
            .rsplit("startxref\n")
            .next()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(texte[table..].starts_with("xref\n0 6\n"));
        for (i, entree) in texte[table..].lines().skip(3).take(5).enumerate() {
            let position: usize = entree[..10].parse().unwrap();
            assert_eq!(entree.len(), 19, "entrée de 20 octets avec son saut de ligne");
            assert!(texte[position..].starts_with(&format!("{} 0 obj\n", i + 1)));
        }
    }

    // user-dirs.dirs n'existe que sous Linux ; « /home/alice » n'est pas un chemin absolu pour Windows.
    #[cfg(unix)]
    #[test]
    fn dossiers_de_user_dirs() {
        let maison = Path::new("/home/alice");
        let declares = "# commentaire\nXDG_DOCUMENTS_DIR=\"$HOME/Documents\"\nXDG_DESKTOP_DIR=\"$HOME\"\nXDG_PICTURES_DIR=\"/data/Images\"\n";
        assert_eq!(
            dossier_declare(declares, "XDG_DOCUMENTS_DIR", maison),
            Some(PathBuf::from("/home/alice/Documents"))
        );
        assert_eq!(
            dossier_declare(declares, "XDG_PICTURES_DIR", maison),
            Some(PathBuf::from("/data/Images"))
        );
        // « $HOME » seul : dossier non configuré.
        assert_eq!(dossier_declare(declares, "XDG_DESKTOP_DIR", maison), None);
        assert_eq!(dossier_declare(declares, "XDG_MUSIC_DIR", maison), None);
    }

    #[test]
    fn codes_differents() {
        assert_ne!(code(1), code(2));
        assert_eq!(code(1).len(), 4);
    }
}
