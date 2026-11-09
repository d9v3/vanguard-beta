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

/// L'identité d'un fichier (périphérique, inode, nombre de noms) prise à son examen, sur le descripteur même qui a été
/// lu. La quarantaine déplace ensuite un nom : sans cette identité, un programme du compte qui glisse sous ce nom un
/// lien dur vers ~/.bashrc entre l'examen et le déplacement ferait rendre ~/.bashrc illisible (permissions à zéro sur
/// l'inode partagé), au nom de la quarantaine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identite {
    pub dev: u64,
    pub ino: u64,
    pub liens: u64,
}

#[cfg(unix)]
impl Identite {
    pub(crate) fn de(m: &std::fs::Metadata) -> Identite {
        use std::os::unix::fs::MetadataExt;
        Identite {
            dev: m.dev(),
            ino: m.ino(),
            liens: m.nlink(),
        }
    }

    /// Le même inode (le nombre de noms à part).
    pub(crate) fn meme_fichier(&self, autre: &Identite) -> bool {
        (self.dev, self.ino) == (autre.dev, autre.ino)
    }
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
    /// L'identité du fichier à son examen (temps réel) : un autre fichier sous ce nom n'est pas isolé.
    pub identite: Option<Identite>,
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
        identite: None,
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
        .and_then(|()| isoler_dans(chemin, detection, &dossier(), sha256, d.identite));
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

fn isoler_dans(
    chemin: &Path,
    detection: &str,
    dossier: &Path,
    sha256: Option<String>,
    attendue: Option<Identite>,
) -> std::io::Result<PathBuf> {
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
    let avant = {
        let avant = Identite::de(&meta);
        identite_permise(&avant, attendue.as_ref())?;
        avant
    };
    #[cfg(not(unix))]
    let _ = attendue;
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
    let renomme = std::fs::rename(chemin, &dest).map(|()| true).or_else(|_| {
        #[cfg(unix)]
        copier_le_meme(chemin, &dest, &avant)?;
        #[cfg(not(unix))]
        std::fs::copy(chemin, &dest)?;
        // Original impossible à supprimer : pas de seconde copie, encore utilisable, en quarantaine.
        std::fs::remove_file(chemin)
            .inspect_err(|_| {
                let _ = std::fs::remove_file(&dest);
            })
            .map(|()| false)
    })?;
    // Le nom déplacé est relu avant de toucher aux permissions : un autre inode glissé sous ce nom entre la relecture
    // et le déplacement retourne à sa place, intact.
    #[cfg(unix)]
    if renomme {
        let apres = std::fs::symlink_metadata(&dest).map(|m| Identite::de(&m));
        if !apres.as_ref().is_ok_and(|a| a.meme_fichier(&avant) && a.liens == 1) {
            return Err(remettre_le_nom(&dest, chemin));
        }
    }
    #[cfg(not(unix))]
    let _ = renomme;
    // Décidé : le même contenu déjà en quarantaine n'y entre pas deux fois ; le fichier trouvé quitte quand même son
    // dossier.
    let lu = crate::protection::empreintes::sha256(&dest).map(|e| crate::protection::empreintes::hex(&e));
    // Sous Windows, chaque fichier garde sa copie : remis depuis celle d'un autre, il perdrait sa marque du web
    // (Zone.Identifier), qui fait avertir Windows à son ouverture.
    #[cfg(unix)]
    let joint = lu.as_deref().is_some_and(|h| rejoindre_un_jumeau(dossier, &dest, h));
    #[cfg(not(unix))]
    let joint = false;
    // Joint : l'empreinte relue des deux côtés, la même que celle du jumeau au registre ; sinon celle de la preuve.
    let sha256 = if joint { lu } else { sha256.or(lu) };
    fermer(&dest)?;
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

/// Fermé : illisible pour tous (Unix), en lecture seule (Windows).
fn fermer(chemin: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    std::fs::set_permissions(chemin, std::os::unix::fs::PermissionsExt::from_mode(0o000))?;
    #[cfg(windows)]
    {
        let mut p = std::fs::metadata(chemin)?.permissions();
        p.set_readonly(true);
        std::fs::set_permissions(chemin, p)?;
    }
    Ok(())
}

/// Un contenu déjà isolé n'y entre pas deux fois : `dest` (le fichier trouvé, déjà déplacé et relu) devient un second
/// nom du fichier isolé qui a la même empreinte, relue des deux côtés (jamais celle du seul registre). Pas de seconde
/// copie ; chaque nom garde son origine et se remet ou se supprime à part. `lu` : l'empreinte de `dest`. `false` :
/// pas de jumeau, ou le lien impossible (le fichier reste une quarantaine ordinaire).
#[cfg(unix)]
fn rejoindre_un_jumeau(dossier: &Path, dest: &Path, lu: &str) -> bool {
    let Some(jumeau) = liste_dans(dossier)
        .into_iter()
        .filter(|x| x.sha256.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(lu)))
        .map(|x| dossier.join(&x.nom))
        .find(|c| c != dest && contenu_isole(c).is_some_and(|h| h.eq_ignore_ascii_case(lu)))
    else {
        return false;
    };
    let Some(mut nom) = dest.file_name().map(std::ffi::OsStr::to_os_string) else {
        return false;
    };
    nom.push(".lien");
    let lien = dest.with_file_name(nom);
    if std::fs::hard_link(&jumeau, &lien).is_err() {
        return false;
    }
    // Remplacé d'un coup : le nom n'est jamais vide, et seul l'inode du fichier trouvé s'en va.
    if std::fs::rename(&lien, dest).is_err() {
        let _ = std::fs::remove_file(&lien);
        return false;
    }
    true
}

/// L'empreinte d'un fichier isolé, ouvert le temps de la lire puis refermé (illisible sinon).
#[cfg(unix)]
fn contenu_isole(chemin: &Path) -> Option<String> {
    if !std::fs::symlink_metadata(chemin).ok()?.is_file() {
        return None;
    }
    std::fs::set_permissions(chemin, std::os::unix::fs::PermissionsExt::from_mode(0o400)).ok()?;
    let lu = crate::protection::empreintes::sha256(chemin);
    let _ = fermer(chemin);
    lu.map(|e| crate::protection::empreintes::hex(&e))
}

/// Les autres noms en quarantaine du même contenu que `e` (`rejoindre_un_jumeau`).
fn jumeaux(e: &Entree, dossier: &Path) -> Vec<PathBuf> {
    let Some(h) = e.sha256.as_deref() else {
        return Vec::new();
    };
    liste_dans(dossier)
        .into_iter()
        .filter(|x| x.nom != e.nom && x.sha256.as_deref().is_some_and(|y| y.eq_ignore_ascii_case(h)))
        .map(|x| dossier.join(&x.nom))
        .filter(|c| c.exists())
        .collect()
}

/// Le fichier relu juste avant le déplacement est-il celui qui a été examiné, et seul à porter son contenu ? Un fichier
/// à plusieurs noms (liens durs) n'est jamais isolé : ses permissions à zéro toucheraient aussi les autres noms, que
/// la personne n'a pas vus (un ~/.bashrc, une sauvegarde par liens durs).
#[cfg(unix)]
fn identite_permise(avant: &Identite, attendue: Option<&Identite>) -> std::io::Result<()> {
    if attendue.is_some_and(|a| !a.meme_fichier(avant)) {
        return Err(std::io::Error::other(tr!(
            "le fichier a changé depuis son examen : rien n'est isolé, il sera examiné de nouveau",
            "the file changed since it was scanned: nothing is isolated, it will be scanned again"
        )));
    }
    if avant.liens > 1 {
        return Err(std::io::Error::other(trf!(
            "ce fichier a {} noms (liens durs) : le rendre inutilisable toucherait aussi les autres ; rien n'est fait",
            "this file has {} names (hard links): making it unusable would also affect the others; nothing is done",
            avant.liens
        )));
    }
    Ok(())
}

/// D'un disque à l'autre : la copie part du descripteur ouvert sans suivre de lien, dont l'identité est relue, puis
/// l'original n'est supprimé que s'il porte encore cette identité.
#[cfg(unix)]
fn copier_le_meme(chemin: &Path, dest: &Path, avant: &Identite) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let change = || {
        std::io::Error::other(tr!(
            "le fichier a changé pendant la quarantaine : rien n'est isolé",
            "the file changed during quarantine: nothing is isolated"
        ))
    };
    let mut source = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(chemin)?;
    if !Identite::de(&source.metadata()?).meme_fichier(avant) {
        return Err(change());
    }
    let mut copie = std::fs::OpenOptions::new().write(true).create_new(true).open(dest)?;
    let copiee = std::io::copy(&mut source, &mut copie).and_then(|_| copie.sync_all());
    let toujours = std::fs::symlink_metadata(chemin).is_ok_and(|m| Identite::de(&m).meme_fichier(avant));
    if copiee.is_err() || !toujours {
        let _ = std::fs::remove_file(dest);
        return Err(copiee.err().unwrap_or_else(change));
    }
    Ok(())
}

/// Un autre inode est arrivé dans la quarantaine sous le nom examiné : il retourne à son nom, sans rien écraser
/// (un lien vers le nom d'origine, puis le retrait de la quarantaine). Un nom repris entre-temps le laisse où il est,
/// et l'erreur le dit.
#[cfg(unix)]
fn remettre_le_nom(dest: &Path, chemin: &Path) -> std::io::Error {
    let remis = std::fs::hard_link(dest, chemin).and_then(|()| std::fs::remove_file(dest));
    match remis {
        Ok(()) => std::io::Error::other(tr!(
            "un autre fichier a pris ce nom pendant la quarantaine : remis à sa place, rien n'est isolé",
            "another file took this name during quarantine: put back in place, nothing is isolated"
        )),
        Err(e) => std::io::Error::other(trf!(
            "un autre fichier a pris ce nom pendant la quarantaine, et ne se remet pas ({e}) : il est intact dans {}",
            "another file took this name during quarantine and cannot be put back ({e}): it is intact in {}",
            chemin_affichable(dest)
        )),
    }
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
    // L'empreinte de ce qui sort vraiment, lue avant : c'est ce contenu-là que la personne reprend.
    let empreinte = crate::protection::empreintes::sha256(&source);
    // Un contenu isolé sous plusieurs noms (`rejoindre_un_jumeau`) : ce nom-ci sort en copie, les autres restent
    // fermés en quarantaine.
    let autres = jumeaux(e, dossier);
    #[cfg(unix)]
    let partage = !autres.is_empty()
        || std::fs::symlink_metadata(&source).is_ok_and(|m| std::os::unix::fs::MetadataExt::nlink(&m) > 1);
    #[cfg(not(unix))]
    let partage = !autres.is_empty();
    let sorti = if partage {
        std::fs::copy(&source, &origine).and_then(|_| std::fs::remove_file(&source))
    } else {
        std::fs::rename(&source, &origine)
            .or_else(|_| std::fs::copy(&source, &origine).and_then(|_| std::fs::remove_file(&source)))
    };
    for autre in &autres {
        let _ = fermer(autre);
    }
    // Resté en quarantaine après un échec : fermé de nouveau, comme avant la tentative.
    if sorti.is_err() && source.exists() {
        let _ = fermer(&source);
    }
    sorti.map_err(|x| Echec::ecriture(OU, &x))?;
    #[cfg(unix)]
    {
        // Sans mode noté (isolé avant la 0.61) : lecture et écriture pour soi, rien d'exécutable.
        let mode = e.mode.unwrap_or(0o600);
        let _ = std::fs::set_permissions(&origine, std::os::unix::fs::PermissionsExt::from_mode(mode));
    }
    retirer_du_registre(dossier, &e.nom);
    declarer_remise(empreinte.as_ref(), &origine);
    // Le fichier est revenu : un résultat gardé d'avant (la cache du passage horaire) ne doit pas le cacher.
    crate::autotest::cache::oublier();
    Ok(())
}

/// Retient que la personne a sorti ce contenu exact de la quarantaine (`normales::cle_remise`, 90 jours) : ni la
/// passe horaire ni le temps réel ne l'y remettent tout seuls, sans quoi l'annulation serait défaite à leur passage ;
/// un autre contenu au même nom est examiné de nouveau. Sans empreinte lue ou sans liste écrite, c'est dit.
fn declarer_remise(empreinte: Option<&[u8; 32]>, origine: &Path) {
    let retenu = empreinte
        .ok_or_else(|| tr!("contenu illisible", "unreadable content").to_string())
        .and_then(|e| {
            crate::protection::normales::declarer(
                &crate::protection::normales::cle_remise(e, origine),
                crate::reseau::tableau::nom_genre(crate::reseau::tableau::Genre::Blocage),
                tr!("Sorti de la quarantaine", "Taken out of quarantine"),
                &affichable(&origine.to_string_lossy()),
            )
            .map_err(|x| x.to_string())
        });
    if let Err(x) = retenu {
        trp!(
            "  ⚠ Non retenu ({x}) : une prochaine analyse peut le remettre en quarantaine.",
            "  ⚠ Not remembered ({x}): a later scan may put it back in quarantine."
        );
    }
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
    let r = std::fs::remove_file(&chemin);
    // Le même contenu sous un autre nom (`rejoindre_un_jumeau`) reste fermé.
    for autre in jumeaux(e, dossier) {
        let _ = fermer(&autre);
    }
    r.map_err(|x| Echec::ecriture("quarantaine/supprimer", &x))?;
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
        let dest = isoler_dans(&fichier, "Win32.Trojan.Exemple", &q, Some("ab".repeat(32)), None).unwrap();
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
        // Sorti par la personne : ce contenu exact à ce chemin est retenu (décidé : il n'y retourne pas tout seul) ;
        // un autre contenu au même nom, non.
        let normale = |contenu: &[u8]| {
            let e = crate::protection::empreintes::sha256_de(contenu).unwrap();
            crate::protection::normales::est_normale(&crate::protection::normales::cle_remise(&e, &fichier))
        };
        assert!(normale(b"MZ contenu"));
        assert!(!normale(b"MZ autre contenu"));
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Décidé : un contenu déjà en quarantaine n'y entre pas deux fois (un second nom du même fichier isolé, pas de
    /// seconde copie), mais le fichier trouvé quitte quand même son dossier ; chaque nom se remet à part, avec son
    /// origine et son mode, et l'autre reste fermé ; un autre contenu reste une copie à part. Sous Windows, chaque
    /// fichier garde sa copie (sa marque du web), et se remet de même.
    #[test]
    fn meme_contenu_isole_une_fois() {
        let maison = jetable("jumeaux");
        let q = maison.join("quarantaine");
        let telecharges = maison.join("Téléchargements");
        std::fs::create_dir_all(&telecharges).unwrap();
        let (a, b, autre) = (
            telecharges.join("a.exe"),
            telecharges.join("b.exe"),
            telecharges.join("c.exe"),
        );
        std::fs::write(&a, b"MZ jumeau").unwrap();
        std::fs::write(&b, b"MZ jumeau").unwrap();
        std::fs::write(&autre, b"MZ autre").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&b, std::os::unix::fs::PermissionsExt::from_mode(0o640)).unwrap();
        // La preuve de « a » n'avait pas d'empreinte : celle relue est notée, et sert au suivant.
        let da = isoler_dans(&a, "X", &q, None, None).unwrap();
        let db = isoler_dans(&b, "X", &q, Some("cd".repeat(32)), None).unwrap();
        let d_autre = isoler_dans(&autre, "X", &q, None, None).unwrap();
        assert!(
            !a.exists() && !b.exists() && !autre.exists(),
            "chaque fichier trouvé quitte son dossier"
        );
        assert!(da != db && d_autre.exists());
        let liste = liste_dans(&q);
        assert_eq!(liste.len(), 3);
        assert_ne!(liste[0].sha256, liste[2].sha256);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            assert_eq!(liste[0].sha256, liste[1].sha256, "l'empreinte relue des deux côtés");
            let ma = std::fs::metadata(&da).unwrap();
            assert_eq!(ma.ino(), std::fs::metadata(&db).unwrap().ino(), "pas de seconde copie");
            assert_ne!(ma.ino(), std::fs::metadata(&d_autre).unwrap().ino());
            assert_eq!(ma.nlink(), 2);
            assert_eq!(ma.permissions().mode() & 0o777, 0);
        }
        // « b » sort : son origine, son contenu, son mode ; « a » reste en quarantaine, fermé et intact.
        remettre_dans(&liste[1], &q).unwrap();
        assert_eq!(std::fs::read(&b).unwrap(), b"MZ jumeau");
        assert!(da.exists() && !db.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            assert_eq!(std::fs::metadata(&b).unwrap().permissions().mode() & 0o777, 0o640);
            let ma = std::fs::metadata(&da).unwrap();
            assert_eq!(ma.permissions().mode() & 0o777, 0, "l'autre nom reste fermé");
            assert_eq!(ma.nlink(), 1);
        }
        #[cfg(unix)]
        assert_eq!(contenu_isole(&da), liste[0].sha256);
        // Isolé de nouveau, puis supprimé pour de bon sous ce nom : l'autre ne bouge pas.
        let db = isoler_dans(&b, "X", &q, None, None).unwrap();
        let liste = liste_dans(&q);
        let eb = liste.iter().find(|x| q.join(&x.nom) == db).unwrap();
        supprimer_dans(eb, &q).unwrap();
        assert!(da.exists() && !db.exists());
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&da).unwrap().permissions()) & 0o777,
            0
        );
        remettre_dans(&liste[0], &q).unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), b"MZ jumeau");
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Un lien dur glissé sous le nom examiné (vers un fichier de la personne) n'est jamais isolé ni rendu illisible ;
    /// un fichier à plusieurs noms non plus ; le fichier examiné, lui, l'est.
    #[cfg(unix)]
    #[test]
    fn lien_dur_jamais_isole() {
        use std::os::unix::fs::PermissionsExt;
        let d = jetable("lien-dur");
        let q = d.join("quarantaine");
        let colis = d.join("colis.exe");
        let precieux = d.join("bashrc");
        std::fs::write(&colis, b"MZ examine").unwrap();
        std::fs::write(&precieux, b"export PS1=alice").unwrap();
        std::fs::set_permissions(&precieux, PermissionsExt::from_mode(0o644)).unwrap();
        let examine = Identite::de(&std::fs::symlink_metadata(&colis).unwrap());
        assert_eq!(examine.liens, 1);
        // Après l'examen, le nom devient un lien dur vers le fichier de la personne.
        std::fs::remove_file(&colis).unwrap();
        std::fs::hard_link(&precieux, &colis).unwrap();
        assert!(isoler_dans(&colis, "Test.Fichier", &q, None, Some(examine)).is_err());
        // Même sans identité attendue : deux noms, rien n'est fait.
        assert!(isoler_dans(&colis, "Test.Fichier", &q, None, None).is_err());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&precieux), 0o644);
        assert_eq!(mode(&colis), 0o644);
        assert_eq!(std::fs::read(&precieux).unwrap(), b"export PS1=alice");
        assert_eq!(liste_dans(&q), Vec::<Entree>::new());
        // La copie d'un disque à l'autre relit aussi l'identité : rien n'est copié.
        let ailleurs = d.join("copie");
        assert!(copier_le_meme(&colis, &ailleurs, &examine).is_err());
        assert!(!ailleurs.exists());
        // Le fichier examiné, à son nom, part en quarantaine.
        std::fs::remove_file(&colis).unwrap();
        std::fs::write(&colis, b"MZ examine").unwrap();
        let examine = Identite::de(&std::fs::symlink_metadata(&colis).unwrap());
        let dest = isoler_dans(&colis, "Test.Fichier", &q, None, Some(examine)).unwrap();
        assert!(!colis.exists());
        assert_eq!(mode(&dest), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un autre inode arrivé dans la quarantaine retourne à son nom sans rien écraser ; un nom repris le laisse où il
    /// est, intact.
    #[cfg(unix)]
    #[test]
    fn autre_inode_remis_a_son_nom() {
        let d = jetable("remis");
        let dest = d.join("123.colis.exe");
        let chemin = d.join("colis.exe");
        std::fs::write(&dest, b"fichier de la personne").unwrap();
        let _ = remettre_le_nom(&dest, &chemin);
        assert!(!dest.exists());
        assert_eq!(std::fs::read(&chemin).unwrap(), b"fichier de la personne");
        std::fs::write(&dest, b"second").unwrap();
        let e = remettre_le_nom(&dest, &chemin);
        assert!(e.to_string().contains("123.colis.exe"), "{e}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"second");
        assert_eq!(std::fs::read(&chemin).unwrap(), b"fichier de la personne");
        let _ = std::fs::remove_dir_all(&d);
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
        isoler_dans(&f, "Test.Fichier", &q, None, None).unwrap();
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
