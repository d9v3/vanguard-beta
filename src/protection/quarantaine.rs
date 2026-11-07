//! Quarantaine réversible : un fichier jugé dangereux (antivirus, YARA) est déplacé dans le dossier de Vanguard sur cet
//! ordinateur (jamais sur la clé : on ne transporte pas de logiciel malveillant), rendu inutilisable (aucune
//! permission sous Linux ; sous Windows, une extension qui empêche de le lancer d'un double-clic, et lecture
//! seule), et noté : d'où il vient, ses permissions, la détection, la date. Une détection peut se tromper : « Remettre »
//! le replace exactement où il était, avec ses permissions d'avant, sans jamais écraser un fichier qui aurait pris sa
//! place. Les fichiers isolés avant la 0.61 (journal.txt seulement) se remettent aussi.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

use std::path::{Path, PathBuf};

use crate::modele::{Echec, Raison};

use serde::{Deserialize, Serialize};

use crate::ui::*;

/// Ajouté au nom sous Windows : un fichier en « .exe.vanguard-quarantaine » ne se lance plus d'un double-clic.
const SUFFIXE_WINDOWS: &str = ".vanguard-quarantaine";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Entree {
    /// Nom du fichier dans le dossier de la quarantaine.
    nom: String,
    /// Chemin d'origine, tel quel (pour le remettre) ; montré, il passe par `affichable`.
    origine: String,
    detection: String,
    /// « AAAA-MM-JJ HH:MM:SS ».
    date: String,
    /// Permissions d'origine (Linux), pour les remettre ; absentes pour un fichier isolé avant la 0.61.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<u32>,
    /// Empreinte SHA-256 relevée avant l'isolement : pour le chercher (VirusTotal) et prouver que c'est le même
    /// fichier ; absente pour un fichier isolé avant la 0.86, ou trop gros pour être haché.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Registre {
    fichiers: Vec<Entree>,
}

pub fn dossier() -> PathBuf {
    crate::socle::dossier_local().join("quarantaine")
}

fn registre_dans(dossier: &Path) -> PathBuf {
    dossier.join("quarantaine.json")
}

fn charger(dossier: &Path) -> Registre {
    crate::socle::lire_texte_ordinaire(&registre_dans(dossier), 16 << 20)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn enregistrer(dossier: &Path, r: &Registre) -> std::io::Result<()> {
    let texte = serde_json::to_string_pretty(r).map_err(std::io::Error::other)?;
    crate::socle::ecrire_atomique(&registre_dans(dossier), texte)
}

/// Qui demande la quarantaine, pour la noter dans « Ce que Vanguard a changé » (`changements`), avec de quoi
/// l'annuler (`vanguard blocage annuler`) : le blocage d'une menace, ou une analyse (antivirus, YARA) après accord.
pub(crate) struct Demande {
    /// La menace (« fichier:/chemin ») : relie l'alerte, le blocage et la quarantaine dans les traces d'incident.
    pub cle: String,
    /// Ce qui est fait, et pourquoi, prêt à montrer.
    pub quoi: String,
    pub automatique: bool,
    /// Ce qui a été fait juste avant (l'arrêt du processus), noté avec la quarantaine.
    pub lancees: Vec<String>,
    /// Le relevé d'avant le geste (`preuve::relever`) : sans lui, pas de quarantaine.
    pub preuve: crate::protection::preuve::PreuveFaite,
}

/// La demande d'une analyse (antivirus, YARA) qui a trouvé `chemin` : son relevé est fait maintenant, avant
/// l'isolement.
pub(crate) fn demande_d_analyse(chemin: &Path, detection: &str) -> Demande {
    Demande {
        cle: format!("fichier:{}", chemin.display()),
        quoi: trf!(
            "Quarantaine de « {} » : {}",
            "Quarantine of “{}”: {}",
            chemin_affichable(chemin),
            affichable(detection)
        ),
        automatique: false,
        lancees: Vec::new(),
        preuve: crate::protection::preuve::relever(
            crate::protection::preuve::Releve::Fichier(chemin),
            &format!("fichier:{}", chemin.display()),
            crate::modele::evenement::Source::Analyse,
        ),
    }
}

/// Le seul chemin vers la quarantaine, pour le blocage comme pour les analyses : isole `chemin` dans la quarantaine
/// de cet ordinateur, puis note le geste (réussi ou non) avec sa preuve et de quoi l'annuler. Rend son chemin en
/// quarantaine.
pub(crate) fn isoler(chemin: &Path, detection: &str, d: Demande) -> std::io::Result<PathBuf> {
    let mut lancees = d.lancees;
    lancees.push(format!("quarantaine : {}", chemin.display()));
    let sha256 = d
        .preuve
        .preuve()
        .and_then(|p| p.fichier.as_ref())
        .filter(|f| Path::new(&f.chemin) == chemin)
        .and_then(|f| f.sha256.clone());
    // Le seul chemin vers la quarantaine : un fichier signé par Microsoft n'y va jamais, d'où que vienne la demande
    // (défense D6a) ; une signature illisible s'y montre puis se confirme, seulement à la demande de la personne.
    let r = garde_de_signature(chemin, d.automatique, &mut lancees)
        .and_then(|()| isoler_dans(chemin, detection, &dossier(), sha256));
    let annulation =
        r.as_ref()
            .ok()
            .and_then(|dest| dest.file_name())
            .map(|n| crate::changements::Annulation::Quarantaine {
                nom: n.to_string_lossy().into_owned(),
            });
    crate::changements::noter_blocage(
        lancees,
        r.is_ok(),
        crate::changements::Blocage {
            id: crate::changements::nouvel_id(),
            cle: d.cle,
            quoi: d.quoi,
            automatique: d.automatique,
            annulation,
            annule: None,
            supprime: false,
            preuve: None,
            evenement: None,
            origine: None,
        },
        d.preuve,
    );
    r
}

/// Supprime pour de bon un fichier trouvé par une analyse, après accord : relevé d'abord (son empreinte disparaît
/// avec lui), puis noté dans « Ce que Vanguard a changé », sans rien à annuler. Les traces d'incident le reprennent,
/// comme une quarantaine. ClamAV, seul à le proposer, n'est lancé d'ici que sous Linux.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn supprimer_apres_analyse(chemin: &Path, detection: &str) -> std::io::Result<()> {
    let cle = format!("fichier:{}", chemin.display());
    let preuve = crate::protection::preuve::relever(
        crate::protection::preuve::Releve::Fichier(chemin),
        &cle,
        crate::modele::evenement::Source::Analyse,
    );
    let r = std::fs::remove_file(chemin);
    crate::changements::noter_blocage(
        vec![format!("suppression : {}", chemin.display())],
        r.is_ok(),
        crate::changements::Blocage {
            id: crate::changements::nouvel_id(),
            cle,
            quoi: trf!(
                "Suppression de « {} » : {}",
                "Deletion of “{}”: {}",
                chemin_affichable(chemin),
                affichable(detection)
            ),
            automatique: false,
            annulation: None,
            annule: None,
            supprime: false,
            preuve: None,
            evenement: None,
            origine: None,
        },
        preuve,
    );
    r
}

/// La garde de signature de la quarantaine (défense D6a, choix 3.1) : Microsoft lisible refuse ; illisible refuse un
/// geste automatique ou sans vraie console, sinon montre pourquoi et ce qu'on sait du fichier, puis demande « Mettre
/// de côté quand même ? [o/N] ». Un fichier qu'une autre garde refuse (système, Vanguard) n'en reçoit jamais la
/// question. La signature est relue après la réponse : devenue Microsoft lisible, la réponse ne vaut plus.
fn garde_de_signature(chemin: &Path, automatique: bool, lancees: &mut Vec<String>) -> std::io::Result<()> {
    use crate::protection::blocage::gardes::{self, Decision};
    let texte = chemin.to_string_lossy();
    let sig = gardes::signature_lue(&texte);
    if matches!(sig, gardes::Signature::Autre) {
        // Lisible et pas Microsoft : rien de plus qu'avant (les autres gardes sont celles de l'appelant).
        return Ok(());
    }
    let mon_programme = std::env::current_exe().ok().map(|c| c.to_string_lossy().into_owned());
    let autre = gardes::fichier_intouchable(&texte, crate::machine::regles::Os::actuel(), mon_programme.as_deref());
    let raison = match gardes::decider_signature(sig, autre, !automatique, gardes::console_reelle()) {
        Decision::Permis => return Ok(()),
        Decision::Refuse(r) => return Err(std::io::Error::other(r)),
        Decision::Demander(r) => r,
    };
    if let Some(pourquoi) = gardes::mise_de_cote_bloquee(essai_de_deplacement(chemin)) {
        return Err(std::io::Error::other(pourquoi));
    }
    let portrait = gardes::portrait_de_fichier(chemin);
    let question = tr!(
        "\n  Mettre de côté quand même ? [o/N] : ",
        "\n  Set it aside anyway? [y/N]: "
    );
    if !gardes::montrer_et_confirmer(raison, &portrait, question) {
        return Err(std::io::Error::other(tr!(
            "vous avez répondu non : rien n'est mis de côté",
            "you answered no: nothing is set aside"
        )));
    }
    let relue = gardes::signature_lue(&texte);
    if matches!(relue, gardes::Signature::Microsoft) {
        return Err(std::io::Error::other(
            gardes::signature_intouchable(relue).unwrap_or_default(),
        ));
    }
    lancees.push(gardes::note_confirmee(true, raison, portrait.sha256.as_deref()));
    Ok(())
}

/// Le fichier s'ouvrirait-il pour être déplacé ? Ouvert avec le seul droit que demande un déplacement (DELETE), en
/// permettant tout partage pour ne gêner personne, et refermé aussitôt : l'erreur système, ou `None`.
#[cfg(windows)]
fn essai_de_deplacement(chemin: &Path) -> Option<u32> {
    use std::os::windows::fs::OpenOptionsExt as _;
    // DELETE ; FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE.
    let essai = std::fs::OpenOptions::new()
        .access_mode(0x0001_0000)
        .share_mode(7)
        .open(chemin);
    essai.err()?.raw_os_error().map(i32::cast_unsigned)
}

/// Hors de Windows, un fichier ouvert ne bloque pas son déplacement.
#[cfg(not(windows))]
fn essai_de_deplacement(_chemin: &Path) -> Option<u32> {
    None
}

fn isoler_dans(chemin: &Path, detection: &str, dossier: &Path, sha256: Option<String>) -> std::io::Result<PathBuf> {
    // Lancé par sudo -E, root écrirait dans le dossier d'un compte, où un programme de ce compte a pu changer
    // journal.txt en lien vers /etc/ld.so.preload : la ligne ajoutée (une origine choisie par lui) y serait lue. Le
    // fichier reste en place, et `isoler` note l'échec.
    if !crate::socle::ecriture_sure(dossier) {
        return Err(std::io::Error::other(tr!(
            "root n'écrit pas dans le dossier d'un compte (sudo -E) : relancez sans sudo",
            "root does not write into an account's folder (sudo -E): start again without sudo"
        )));
    }
    #[cfg(windows)]
    destination_sure(dossier, true)?;
    std::fs::create_dir_all(dossier)?;
    // Tenus jusqu'au retour : le déplacement, la note et le journal vont là où ils ont été relus.
    #[cfg(windows)]
    let _tenus = destination_tenue(dossier)?;
    let meta = std::fs::symlink_metadata(chemin)?;
    if !meta.is_file() {
        return Err(std::io::Error::other(tr!(
            "ce n'est pas un fichier",
            "this is not a file"
        )));
    }
    #[cfg(unix)]
    let mode = Some(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777);
    #[cfg(windows)]
    let mode = None;
    let nom_origine = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let horodatage = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let suffixe = if cfg!(windows) { SUFFIXE_WINDOWS } else { "" };
    let nom = format!("{horodatage}.{nom_origine}{suffixe}");
    let dest = dossier.join(&nom);
    // rename échoue d'un disque à l'autre (clé USB → disque) : copie, puis suppression de l'original.
    std::fs::rename(chemin, &dest).or_else(|_| {
        std::fs::copy(chemin, &dest)?;
        // Original impossible à supprimer : pas de seconde copie, encore utilisable, en quarantaine.
        std::fs::remove_file(chemin).inspect_err(|_| {
            let _ = std::fs::remove_file(&dest);
        })
    })?;
    #[cfg(unix)]
    std::fs::set_permissions(&dest, std::os::unix::fs::PermissionsExt::from_mode(0o000))?;
    #[cfg(windows)]
    {
        let mut p = std::fs::metadata(&dest)?.permissions();
        p.set_readonly(true);
        std::fs::set_permissions(&dest, p)?;
    }
    let mut r = charger(dossier);
    let entree = Entree {
        nom,
        origine: chemin.to_string_lossy().into_owned(),
        detection: detection.to_string(),
        date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        mode,
        sha256,
    };
    noter_journal(dossier, &entree);
    r.fichiers.push(entree);
    enregistrer(dossier, &r)?;
    Ok(dest)
}

/// Vanguard administrateur (Windows) écrit la quarantaine dans le profil du compte qui l'a ouvert ainsi, où un
/// programme de ce compte a pu poser une jonction vers un dossier de Windows : chaque dossier jusqu'à la racine du
/// profil est relu avant la création (défense D6a), puis tenu ouvert pendant le geste (`destination_tenue`). Les
/// essais écrivent dans leurs dossiers jetables, hors de tout profil : la règle s'y essaie par
/// `gardes::destination_de_quarantaine` et `tenir`.
#[cfg(windows)]
fn destination_sure(dossier: &Path, absents_permis: bool) -> std::io::Result<()> {
    if eleve_hors_essai() {
        let raison = match crate::machine::windows::environnement::profil() {
            Some(profil) => crate::protection::blocage::gardes::destination_de_quarantaine(
                dossier,
                &profil,
                |d| std::fs::symlink_metadata(d).map(|m| crate::machine::vidage::est_lien(&m)),
                absents_permis,
            ),
            None => Some(tr!(
                "le profil du compte ne se lit pas : Vanguard administrateur ne met rien en quarantaine",
                "the account profile cannot be read: Vanguard as administrator quarantines nothing"
            )),
        };
        if let Some(raison) = raison {
            return Err(std::io::Error::other(raison));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn eleve_hors_essai() -> bool {
    !cfg!(test) && crate::machine::windows::processus::eleve_ou_inconnu()
}

/// En administrateur : chaque dossier, du profil à la quarantaine, tenu ouvert (`tenir`). Ailleurs, rien à tenir.
#[cfg(windows)]
fn destination_tenue(dossier: &Path) -> std::io::Result<Vec<std::fs::File>> {
    if !eleve_hors_essai() {
        return Ok(Vec::new());
    }
    let Some(profil) = crate::machine::windows::environnement::profil() else {
        return Err(std::io::Error::other(tr!(
            "le profil du compte ne se lit pas : Vanguard administrateur ne met rien en quarantaine",
            "the account profile cannot be read: Vanguard as administrator quarantines nothing"
        )));
    };
    tenir(dossier, &profil)
}

/// Ouvre chaque dossier de `profil` jusqu'à `dossier`, de la racine vers le bas, sans suivre un lien
/// (FILE_FLAG_OPEN_REPARSE_POINT) et sans permettre à personne de le renommer ni de l'effacer (pas de
/// FILE_SHARE_DELETE) ; chacun est jugé par sa poignée (`gardes::destination_de_quarantaine`). Tant que les poignées
/// vivent, le chemin désigne ces dossiers-là : aucune jonction ne s'y glisse entre la relecture et l'écriture
/// (relecture de D6a, qui fermait la course par une seconde relecture seulement). Ouvert de haut en bas : chaque
/// dossier s'ouvre au travers de parents déjà tenus.
#[cfg(windows)]
fn tenir(dossier: &Path, profil: &Path) -> std::io::Result<Vec<std::fs::File>> {
    use std::collections::HashMap;
    use std::io::ErrorKind;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    // FILE_LIST_DIRECTORY : sans droit sur les données, Windows ne retiendrait pas le partage refusé de la poignée.
    const LISTER: u32 = 0x0001;
    const LIRE_ATTRIBUTS: u32 = 0x0080;
    const SYNCHRONISER: u32 = 0x0010_0000;
    const PARTAGE_LIRE_ECRIRE: u32 = 0x1 | 0x2;
    const SANS_SUIVRE_DOSSIER: u32 = 0x0020_0000 | 0x0200_0000;
    const POINT_DE_REANALYSE: u32 = 0x400;
    let n = dossier.components().count().saturating_sub(profil.components().count()) + 1;
    let mut chemins: Vec<&Path> = dossier.ancestors().take(n).collect();
    chemins.reverse();
    let mut tenus = Vec::new();
    // Ce que chaque poignée dit : un lien, ou ce qui l'a empêchée ; tout ce qui est en dessous d'un refus en hérite.
    let mut lus: HashMap<&Path, Result<bool, ErrorKind>> = HashMap::new();
    let mut refus = None;
    for c in chemins {
        if let Some(r) = refus {
            lus.insert(c, r);
            continue;
        }
        let lu = std::fs::OpenOptions::new()
            .access_mode(LISTER | LIRE_ATTRIBUTS | SYNCHRONISER)
            .share_mode(PARTAGE_LIRE_ECRIRE)
            .custom_flags(SANS_SUIVRE_DOSSIER)
            .open(c)
            .and_then(|f| f.metadata().map(|m| (f, m)));
        let verdict = match lu {
            Ok((f, m)) => {
                let lien = m.file_attributes() & POINT_DE_REANALYSE != 0 || !m.is_dir();
                tenus.push(f);
                Ok(lien)
            }
            Err(e) => Err(e.kind()),
        };
        if verdict != Ok(false) {
            refus = Some(verdict);
        }
        lus.insert(c, verdict);
    }
    let raison = crate::protection::blocage::gardes::destination_de_quarantaine(
        dossier,
        profil,
        |a| match lus.get(a) {
            Some(Ok(lien)) => Ok(*lien),
            Some(Err(k)) => Err((*k).into()),
            None => Err(ErrorKind::NotFound.into()),
        },
        false,
    );
    match raison {
        Some(raison) => Err(std::io::Error::other(raison)),
        None => Ok(tenus),
    }
}

/// Le journal lisible par une personne (cat, éditeur), comme avant la 0.61 : noms rendus inoffensifs.
fn noter_journal(dossier: &Path, e: &Entree) {
    use std::io::Write;
    let ligne = format!(
        "{}\t{}\t{}\t{}\n",
        e.date,
        affichable(&e.detection),
        affichable(&e.origine),
        affichable(&e.nom)
    );
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    // Jamais au travers d'un lien : un journal.txt changé en lien ferait ajouter la ligne au fichier visé.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut o, libc::O_NOFOLLOW);
    let _ = o
        .open(dossier.join("journal.txt"))
        .and_then(|mut j| j.write_all(ligne.as_bytes()));
}

/// Tout ce qui est en quarantaine : le registre, puis les fichiers isolés avant la 0.61 (journal.txt seulement),
/// quand leur ligne est fidèle (un nom réécrit pour l'affichage ne se remettrait pas au bon endroit) et le fichier
/// toujours là.
fn liste_dans(dossier: &Path) -> Vec<Entree> {
    let mut fichiers: Vec<Entree> = charger(dossier)
        .fichiers
        .into_iter()
        .filter(|e| dossier.join(&e.nom).exists())
        .collect();
    let journal = crate::socle::lire_texte_ordinaire(&dossier.join("journal.txt"), 16 << 20).unwrap_or_default();
    for l in journal.lines() {
        let c: Vec<&str> = l.split('\t').collect();
        let [date, detection, origine, nom] = c[..] else {
            continue;
        };
        let deja = fichiers.iter().any(|e| e.nom == nom);
        if deja || origine.contains('\u{fffd}') || nom.contains('\u{fffd}') || !dossier.join(nom).exists() {
            continue;
        }
        fichiers.push(Entree {
            nom: nom.to_string(),
            origine: origine.to_string(),
            detection: detection.to_string(),
            date: date.to_string(),
            mode: None,
            sha256: None,
        });
    }
    fichiers
}

/// Un fichier en quarantaine, pour les traces : (date, origine, détection, empreinte SHA-256).
pub(crate) type PourTraces = (String, String, String, Option<String>);

/// Ce qui est en quarantaine dans `dossier`, pour les traces d'incident : (date, origine, détection, empreinte
/// SHA-256). `Err` : un registre qui n'est pas un fichier ordinaire. La collecte peut tourner en administrateur dans
/// le dossier du compte : un tube nommé à sa place la bloquerait sans fin, un lien ferait lire un autre fichier.
pub(crate) fn pour_traces_dans(dossier: &Path) -> Result<Vec<PourTraces>, Echec> {
    for f in [registre_dans(dossier), dossier.join("journal.txt")] {
        if let Ok(m) = std::fs::symlink_metadata(&f)
            && !m.is_file()
        {
            return Err(Echec::refuse(
                "quarantaine/traces",
                format!("{} : pas un fichier ordinaire / not a regular file", f.display()),
            ));
        }
    }
    Ok(liste_dans(dossier)
        .into_iter()
        .map(|e| (e.date, e.origine, e.detection, e.sha256))
        .collect())
}

/// Remet un fichier à sa place d'origine, avec ses permissions d'avant. Refuse d'écraser ce qui l'aurait remplacé.
fn remettre_dans(e: &Entree, dossier: &Path) -> Result<(), Echec> {
    const OU: &str = "quarantaine/remettre";
    let source = dossier.join(&e.nom);
    let origine = PathBuf::from(&e.origine);
    if origine.exists() {
        return Err(Echec::refuse(
            OU,
            tr!(
                "un autre fichier est à sa place : rien n'est écrasé",
                "another file is in its place: nothing is overwritten"
            ),
        ));
    }
    if let Some(parent) = origine.parent() {
        std::fs::create_dir_all(parent).map_err(|x| Echec::ecriture(OU, &x))?;
    }
    // Il faut pouvoir le lire pour le copier d'un disque à l'autre.
    #[cfg(unix)]
    let _ = std::fs::set_permissions(&source, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    #[cfg(windows)]
    if let Ok(m) = std::fs::metadata(&source) {
        let mut p = m.permissions();
        #[allow(clippy::permissions_set_readonly_false)] // le fichier redevient celui d'avant
        p.set_readonly(false);
        let _ = std::fs::set_permissions(&source, p);
    }
    std::fs::rename(&source, &origine)
        .or_else(|_| std::fs::copy(&source, &origine).and_then(|_| std::fs::remove_file(&source)))
        .map_err(|x| Echec::ecriture(OU, &x))?;
    #[cfg(unix)]
    {
        // Sans mode noté (isolé avant la 0.61) : lecture et écriture pour soi, rien d'exécutable.
        let mode = e.mode.unwrap_or(0o600);
        let _ = std::fs::set_permissions(&origine, std::os::unix::fs::PermissionsExt::from_mode(mode));
    }
    retirer_du_registre(dossier, &e.nom);
    // Le fichier est revenu : un résultat gardé d'avant (la cache du passage horaire) ne doit pas le cacher.
    crate::autotest::cache::oublier();
    Ok(())
}

/// Remet à sa place le fichier isolé sous ce nom (l'annulation d'un blocage) ; même garde que le menu : rien n'est
/// écrasé.
pub(crate) fn remettre(nom: &str) -> Result<(), Echec> {
    let dossier = dossier();
    let e = liste_dans(&dossier).into_iter().find(|e| e.nom == nom).ok_or_else(|| {
        Echec::new("quarantaine/remettre", Raison::Introuvable)
            .detail(tr!("plus dans la quarantaine", "no longer in the quarantine"))
    })?;
    remettre_dans(&e, &dossier)
}

/// Le nombre de fichiers en quarantaine sur cet ordinateur.
pub(crate) fn nombre() -> usize {
    nombre_dans(&dossier())
}

/// Le nombre de fichiers isolés dans le dossier de quarantaine `dossier`.
pub(crate) fn nombre_dans(dossier: &Path) -> usize {
    liste_dans(dossier).len()
}

/// Supprime pour de bon un fichier de la quarantaine.
fn supprimer_dans(e: &Entree, dossier: &Path) -> Result<(), Echec> {
    let chemin = dossier.join(&e.nom);
    #[cfg(windows)]
    if let Ok(m) = std::fs::metadata(&chemin) {
        let mut p = m.permissions();
        #[allow(clippy::permissions_set_readonly_false)] // il va être supprimé
        p.set_readonly(false);
        let _ = std::fs::set_permissions(&chemin, p);
    }
    std::fs::remove_file(&chemin).map_err(|x| Echec::ecriture("quarantaine/supprimer", &x))?;
    retirer_du_registre(dossier, &e.nom);
    Ok(())
}

fn retirer_du_registre(dossier: &Path, nom: &str) {
    let mut r = charger(dossier);
    let avant = r.fichiers.len();
    r.fichiers.retain(|x| x.nom != nom);
    if r.fichiers.len() != avant {
        let _ = enregistrer(dossier, &r);
    }
}

/// Après une analyse : propose d'isoler les fichiers trouvés, (chemin, détection). Rien sans accord.
pub fn proposer(trouves: &[(PathBuf, String)]) {
    if trouves.is_empty() {
        return;
    }
    let rep = demander(tr!(
        "\n  Les mettre en quarantaine (réversible : menu Virus et logiciels espions › Quarantaine) ? [o/N] : ",
        "\n  Quarantine them (reversible: menu Viruses and spyware › Quarantine)? [y/N]: "
    ));
    if !rep.oui() {
        trp!(
            "  Rien n'a été fait : les fichiers restent à leur place.",
            "  Nothing was done: the files stay where they are."
        );
        return;
    }
    for (chemin, detection) in trouves {
        let montre = chemin_affichable(chemin);
        match isoler(chemin, detection, demande_d_analyse(chemin, detection)) {
            Ok(_) => println!("  {VERT}✔{RESET} {montre}"),
            Err(e) => trp!(
                "  ✖ {montre} : {e} (fichier du système ? relancer avec les droits administrateur)",
                "  ✖ {montre}: {e} (system file? run again with administrator rights)"
            ),
        }
    }
}

/// Menu Antivirus et protection › Quarantaine (`vanguard quarantaine`) : ce qui est isolé, à remettre ou à supprimer.
pub fn menu() {
    titre(tr!("Quarantaine", "Quarantine"));
    let dossier = dossier();
    loop {
        let fichiers = liste_dans(&dossier);
        if fichiers.is_empty() {
            trp!("  La quarantaine est vide.", "  The quarantine is empty.");
            return;
        }
        for (i, e) in fichiers.iter().enumerate() {
            println!(
                "  {TOUCHE}{:>2}{RESET}  {}",
                i.saturating_add(1),
                affichable(&e.origine)
            );
            println!(
                "      {GRIS}{} · {}{RESET}",
                affichable(&e.detection),
                e.date.get(..16).unwrap_or(&e.date)
            );
            if let Some(h) = &e.sha256 {
                println!("      {GRIS}SHA-256 {h}{RESET}");
            }
        }
        let choix = crate::selection::demander_ou_revenir(tr!(
            "\n  Numéro du fichier (Entrée pour revenir) : ",
            "\n  File number (Enter to go back): "
        ));
        let Some(e) = choix
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| fichiers.get(i))
        else {
            return;
        };
        let montre = affichable(&e.origine);
        println!("\n  « {montre} »");
        let supprimer = tr!("s", "d");
        let Some(action) = crate::selection::choisir_en_ligne(
            &[
                (
                    "r",
                    tr!(
                        "Remettre à sa place (faux positif)",
                        "Restore to its place (false positive)"
                    ),
                ),
                (supprimer, tr!("Supprimer pour de bon", "Delete for good")),
            ],
            &trf!(
                "  r : remettre à sa place · {supprimer} : supprimer pour de bon · Entrée : rien : ",
                "  r: restore to its place · {supprimer}: delete for good · Enter: nothing: "
            ),
        ) else {
            continue;
        };
        let resultat = if action == "r" {
            remettre_dans(e, &dossier)
        } else {
            supprimer_dans(e, &dossier)
        };
        match resultat {
            Ok(()) => {
                // Sorti de la quarantaine : le blocage qui l'y avait mis n'est plus à annuler.
                crate::changements::marquer_annule_quarantaine(&e.nom, action.trim() != "r");
                trp!("  {VERT}✔{RESET} Fait.", "  {VERT}✔{RESET} Done.");
            }
            Err(x) => trp!("  ✖ {x}", "  ✖ {x}"),
        }
        println!();
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

    /// Retiré à la fin de l'essai, même fermé ou après une panique (M-1 de la relecture des restes c6).
    fn jetable(nom: &str) -> crate::essais::Jetable {
        crate::essais::Jetable::nouveau(&format!("quarantaine-{nom}"))
    }

    /// Relecture de D6a : chaque dossier du profil à la quarantaine est tenu pendant le geste ; ni lui ni un parent ne
    /// se renomme ni ne s'efface (une jonction ne peut donc pas prendre sa place), puis tout se libère. Hors du
    /// profil, ou un fichier à la place d'un dossier : refusé.
    #[cfg(windows)]
    #[test]
    fn quarantaine_tenue_pendant_le_geste() {
        let profil = jetable("tenue");
        let q = profil
            .join("AppData")
            .join("Local")
            .join("vanguard")
            .join("quarantaine");
        std::fs::create_dir_all(&q).unwrap();
        let tenus = tenir(&q, &profil).unwrap();
        assert_eq!(tenus.len(), 5);
        let local = profil.join("AppData").join("Local");
        assert!(std::fs::rename(local.join("vanguard"), local.join("ailleurs")).is_err());
        assert!(std::fs::rename(&q, local.join("vanguard").join("autre")).is_err());
        assert!(std::fs::remove_dir(&q).is_err());
        drop(tenus);
        std::fs::rename(&q, local.join("vanguard").join("autre")).unwrap();
        std::fs::write(&q, b"pas un dossier").unwrap();
        assert!(tenir(&q, &profil).is_err());
        assert!(tenir(&q, &profil.join("autre-compte")).is_err());
    }

    #[test]
    fn isole_puis_remet_a_l_identique() {
        let maison = jetable("maison");
        let q = maison.join("quarantaine");
        let fichier = maison.join("Téléchargements").join("facture.pdf.exe");
        std::fs::create_dir_all(fichier.parent().unwrap()).unwrap();
        std::fs::write(&fichier, b"MZ contenu").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&fichier, std::os::unix::fs::PermissionsExt::from_mode(0o751)).unwrap();
        let dest = isoler_dans(&fichier, "Win32.Trojan.Exemple", &q, Some("ab".repeat(32))).unwrap();
        assert!(!fichier.exists() && dest.exists());
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&dest).unwrap().permissions()) & 0o777,
            0
        );
        let liste = liste_dans(&q);
        assert_eq!(liste.len(), 1);
        assert_eq!(liste[0].origine, fichier.to_string_lossy());
        assert_eq!(liste[0].sha256.as_deref(), Some("ab".repeat(32).as_str()));
        // Un autre fichier a pris sa place : rien n'est écrasé.
        std::fs::write(&fichier, b"nouveau").unwrap();
        let oublis = crate::autotest::cache::OUBLIS.with(std::cell::Cell::get);
        assert!(remettre_dans(&liste[0], &q).is_err());
        assert_eq!(std::fs::read(&fichier).unwrap(), b"nouveau");
        assert_eq!(crate::autotest::cache::OUBLIS.with(std::cell::Cell::get), oublis);
        std::fs::remove_file(&fichier).unwrap();
        // Remis : même contenu, mêmes permissions, sorti du registre, et la cache vidée (reste du lot L6c).
        remettre_dans(&liste[0], &q).unwrap();
        assert_eq!(crate::autotest::cache::OUBLIS.with(std::cell::Cell::get), oublis + 1);
        assert_eq!(std::fs::read(&fichier).unwrap(), b"MZ contenu");
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&fichier).unwrap().permissions()) & 0o777,
            0o751
        );
        assert_eq!(liste_dans(&q), Vec::<Entree>::new());
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Le journal de la quarantaine se lit avec cat : un nom piégé n'y pilote pas le terminal, et ses tabulations ou
    /// sauts de ligne ne cassent pas les quatre colonnes.
    /// journal.txt changé en lien par un autre programme : la ligne n'est pas ajoutée au fichier visé. Et en root, le
    /// dossier de quarantaine d'un compte (le nôtre ici) est refusé par la règle que `isoler_dans` applique.
    #[cfg(unix)]
    #[test]
    fn journal_en_lien_jamais_suivi() {
        let d = jetable("lien");
        let q = d.join("quarantaine");
        std::fs::create_dir_all(&q).unwrap();
        let cible = d.join("ld.so.preload");
        std::fs::write(&cible, b"").unwrap();
        std::os::unix::fs::symlink(&cible, q.join("journal.txt")).unwrap();
        let f = d.join("x.so");
        std::fs::write(&f, b"x").unwrap();
        isoler_dans(&f, "Test.Fichier", &q, None).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), b"");
        if crate::socle::uid() == 0 {
            return crate::essais::saute("lancé en root : un dossier à soi est à root");
        }
        assert!(!crate::socle::ecriture_sure_pour(0, &q));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn journal_de_quarantaine_sans_piege() {
        let d = jetable("journal");
        noter_journal(
            &d,
            &Entree {
                nom: "x.q".into(),
                origine: "/home/alice/a\tb\x1b[2K\nc".into(),
                detection: "Eicar\x07".into(),
                date: "2026-10-18 23:00:00".into(),
                mode: None,
                sha256: None,
            },
        );
        let journal = std::fs::read_to_string(d.join("journal.txt")).unwrap();
        assert_eq!(journal.lines().count(), 1, "{journal:?}");
        let champs: Vec<&str> = journal.trim_end().split('\t').collect();
        assert_eq!(champs.len(), 4, "{journal:?}");
        assert_eq!(champs[1], "Eicar\u{fffd}");
        assert_eq!(champs[2], "/home/alice/a\u{fffd}b\u{fffd}[2K\u{fffd}c");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn anciennes_lignes_du_journal_et_suppression() {
        let q = jetable("ancien");
        // Isolé avant la 0.61 : journal.txt seulement.
        std::fs::write(q.join("123.outil.sh"), b"#!/bin/sh").unwrap();
        std::fs::write(
            q.join("journal.txt"),
            "2026-10-01 10:00:00\tEicar\t/home/alice/outil.sh\t123.outil.sh\n\
             2026-10-01 10:00:01\tEicar\t/home/alice/pi\u{fffd}ge.sh\t124.pi\u{fffd}ge.sh\n\
             2026-10-01 10:00:02\tEicar\t/home/alice/parti.sh\t125.parti.sh\n",
        )
        .unwrap();
        let liste = liste_dans(&q);
        // Le nom réécrit pour l'affichage et le fichier disparu ne sont pas proposés.
        assert_eq!(liste.len(), 1);
        assert_eq!(liste[0].origine, "/home/alice/outil.sh");
        assert_eq!(liste[0].mode, None);
        supprimer_dans(&liste[0], &q).unwrap();
        assert_eq!(liste_dans(&q), Vec::<Entree>::new());
        let _ = std::fs::remove_dir_all(&q);
    }
    /// Supprimé après une analyse : le fichier n'est plus là, mais son empreinte est relevée et le geste noté pour
    /// les traces d'incident.
    #[test]
    fn suppression_apres_analyse_relevee_et_notee() {
        let d = jetable("suppression");
        let f = d.join("facture.pdf.exe");
        std::fs::write(&f, b"charge inventee").unwrap();
        supprimer_apres_analyse(&f, "Win.Test.EICAR").unwrap();
        assert!(!f.exists());
        let cle = format!("fichier:{}", f.display());
        let (_, reussi, b) = crate::changements::blocages()
            .into_iter()
            .find(|(_, _, b)| b.cle == cle)
            .expect("suppression notée");
        assert!(reussi && b.annulation.is_none());
        assert!(
            b.preuve
                .and_then(|p| p.fichier)
                .and_then(|x| x.sha256)
                .is_some_and(|h| h.len() == 64)
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
