//! La clé USB du programme : Vanguard ne doit jamais dépendre d'elle pendant qu'il tourne, et sous Linux il la
//! protège des écritures sur les ordinateurs des autres.
//!
//! Lancé depuis la clé, le programme s'y relirait (pages du programme relues à la demande) : clé retirée ou port USB
//! coupé, Linux le tuerait (SIGBUS) et Windows l'arrêterait sur une fenêtre d'erreur (STATUS_IN_PAGE_ERROR). Il se
//! recopie donc d'abord sur cet ordinateur, vérifie que la copie a ses octets, et la lance avec les mêmes arguments ;
//! `VANGUARD_ORIGINE` dit à la copie où est le programme de la clé (`exe_d_origine`). Linux : dossier temporaire
//! réservé à la personne, `exec` (même processus), la copie s'efface dès son départ. Windows : `copies/` du dossier
//! local, le premier processus attend la fin de la copie, rend son code de sortie et l'efface.
//!
//! Sous Linux, la partition VANGUARD n'est pas en lecture seule (Windows, lui, respecte l'attribut GPT) : sur tout
//! ordinateur autre que celui du propriétaire, Vanguard la remonte donc lui-même en lecture seule (udisks, sans mot de
//! passe) avant de commencer. Le propriétaire est reconnu par l'empreinte SHA-1 de son /etc/machine-id, que
//! outils/deployer.sh écrit dans le fichier témoin `vanguard.cle`. Témoin vide (clé jamais déployée) : pas de
//! protection. C'est une barrière contre les écritures par erreur ou par un programme quelconque, pas un coffre-fort :
//! un programme malveillant lancé avec le compte de la personne peut remonter la clé en écriture de la même façon.

use std::path::{Path, PathBuf};

use crate::ui::*;

/// Variable posée par la copie temporaire : chemin du programme d'origine, sur la clé.
const ORIGINE: &str = "VANGUARD_ORIGINE";
/// Dossier du programme sur la clé.
#[cfg(target_os = "linux")]
const DOSSIER_PROGRAMME: &str = "Linux";
/// Nom du programme dans sa copie (`<base>/vanguard-<pid>-<nanos>/<NOM_COPIE>`).
#[cfg(unix)]
const NOM_COPIE: &str = "vanguard";
#[cfg(windows)]
const NOM_COPIE: &str = "vanguard.exe";

/// Le programme tel que lancé par la personne (sur la clé), même quand c'est sa copie temporaire qui tourne. Décidé
/// une fois par lancement (la copie temporaire s'efface au démarrage, `proteger_cle` le demande avant).
///
/// `VANGUARD_ORIGINE` n'est qu'une variable d'environnement, que tout programme du compte peut poser : elle faisait
/// installer, poser en tâche ou dire vérifié un autre programme que Vanguard. Elle n'est donc crue que si le fichier
/// qu'elle désigne a exactement les octets du programme qui tourne ; sinon elle est ignorée, l'écart est dit (et noté
/// au journal des erreurs), et c'est le programme qui tourne qui compte : rien n'est installé depuis elle.
pub fn exe_d_origine() -> Option<PathBuf> {
    static DECIDE: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    DECIDE
        .get_or_init(|| {
            let courant = exe_courant;
            let Some(designee) = std::env::var_os(ORIGINE) else {
                return courant();
            };
            match origine_crue(Path::new(&designee), image_qui_tourne()) {
                Ok(chemin) => Some(lisible(&chemin)),
                // Hors de la copie temporaire, la variable n'est qu'héritée (un Vanguard lancé par celui de la clé) ou
                // posée par un autre programme : ignorée sans bruit, elle ne sert à rien. Dans la copie, l'écart se dit.
                Err(_) if !std::env::current_exe().is_ok_and(|e| est_une_copie(&e)) => courant(),
                Err(raison) => {
                    tre!(
                        "Attention : VANGUARD_ORIGINE désigne {}, qui n'est pas le programme qui tourne ({raison}) : ignorée.",
                        "Warning: VANGUARD_ORIGINE points to {}, which is not the running program ({raison}): ignored.",
                        chemin_affichable(Path::new(&designee))
                    );
                    crate::journal::erreur(crate::compte_rendu::Contexte::OrigineProgramme, &format!("VANGUARD_ORIGINE ignorée : {raison}"));
                    courant()
                }
            }
        })
        .clone()
}

/// Le fichier du programme qui tourne, chemin complet (sous Windows, sans le préfixe `\\?\` de canonicalize, qui
/// se montrerait tel quel et ne se comparerait plus aux chemins ordinaires).
fn exe_courant() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.canonicalize().ok())
        .map(|e| lisible(&e))
}

fn lisible(chemin: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        crate::reseau::surveillance::sans_verbatim(chemin)
    }
    #[cfg(not(windows))]
    {
        chemin.to_path_buf()
    }
}

/// L'empreinte du programme qui tourne : son image (/proc/self/exe sous Linux, lisible même effacée), sinon son
/// fichier.
fn image_qui_tourne() -> Option<String> {
    // Déjà lue par les programmes posés : pas une seconde lecture du programme.
    if let Some(soi) = crate::programmes_poses::soi() {
        return Some(soi.to_string());
    }
    #[cfg(target_os = "linux")]
    let image = PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let image = std::env::current_exe().ok()?;
    crate::programmes_poses::empreinte_de(&image).ok()
}

/// Le fichier `designee`, s'il a exactement les octets du programme qui tourne (`soi` : leur empreinte) ; sinon
/// pourquoi il n'est pas cru.
fn origine_crue(designee: &Path, soi: Option<String>) -> Result<PathBuf, crate::modele::Echec> {
    const OU: &str = "cle/origine";
    let chemin = designee.canonicalize().map_err(|e| crate::modele::Echec::io(OU, &e))?;
    let lu = crate::programmes_poses::empreinte_de(&chemin).map_err(|e| crate::modele::Echec::refuse(OU, e))?;
    let soi = soi.ok_or_else(|| {
        crate::modele::Echec::refuse(OU, tr!("programme qui tourne illisible", "running program unreadable"))
    })?;
    if lu == soi {
        Ok(chemin)
    } else {
        Err(crate::modele::Echec::refuse(
            OU,
            tr!(
                "ses octets ne sont pas ceux du programme qui tourne",
                "its bytes are not those of the running program"
            ),
        ))
    }
}

/// Périphérique et état (lecture seule ou non) du point de montage `dossier`, d'après /proc/self/mountinfo.
#[cfg(target_os = "linux")]
pub(crate) fn montage(dossier: &Path) -> Option<(String, bool)> {
    let infos = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    // Les espaces des chemins y sont écrits \040.
    let cible = dossier.to_string_lossy().replace(' ', "\\040");
    infos.lines().rev().find_map(|l| {
        let champs: Vec<&str> = l.split(' ').collect();
        let (point, options) = (*champs.get(4)?, *champs.get(5)?);
        if point != cible {
            return None;
        }
        let apres = l.split(" - ").nth(1)?;
        let source = apres.split(' ').nth(1)?.to_string();
        Some((source, options.split(',').any(|o| o == "ro")))
    })
}

/// Lance l'outil de montage (udisksctl) ; en cas d'échec, son message d'erreur.
#[cfg(target_os = "linux")]
fn outil(cmd: &str, args: &[&str]) -> Result<(), String> {
    match crate::commande::lancer(std::process::Command::new(cmd).args(args), 30) {
        Some(r) if r.code == Some(0) => Ok(()),
        Some(r) => Err(format!("{} {}", r.erreurs.trim(), r.sortie.trim()).trim().to_string()),
        None => Err(format!("{cmd} absent ou sans réponse")),
    }
}

#[cfg(target_os = "linux")]
fn demonter(peripherique: &str) -> Result<(), String> {
    outil("udisksctl", &["unmount", "-b", peripherique])
}

#[cfg(target_os = "linux")]
fn monter(peripherique: &str, lecture_seule: bool) -> Result<(), String> {
    if lecture_seule {
        outil("udisksctl", &["mount", "-b", peripherique, "-o", "ro"])
    } else {
        outil("udisksctl", &["mount", "-b", peripherique])
    }
}

/// Cet ordinateur est-il celui du propriétaire de la clé (empreinte écrite par deployer.sh dans le témoin) ?
#[cfg(unix)]
pub fn chez_le_proprietaire(cle: &Path) -> bool {
    let attendue = empreinte_attendue(cle);
    let attendue = attendue.trim();
    !attendue.is_empty() && Some(attendue) == crate::machine::empreinte_machine().as_deref()
}

#[cfg(unix)]
fn empreinte_attendue(cle: &Path) -> String {
    crate::socle::lire_texte_ordinaire(&cle.join(crate::reseau::TEMOIN_CLE), 4 << 10).unwrap_or_default()
}

/// Au démarrage, sous Linux : lancé depuis la clé, se relancer depuis une copie (`relancer_depuis_une_copie`) ; puis, sur un
/// ordinateur qui n'est pas celui du propriétaire, remonter la clé en lecture seule.
#[cfg(target_os = "linux")]
pub fn proteger_cle() {
    // L'origine se décide avant que la copie temporaire ne s'efface : sans elle, rien ne se compare plus.
    let _ = exe_d_origine();
    // Copie temporaire relancée : elle supprime son fichier (Linux le garde lisible jusqu'à la fin du programme).
    if std::env::var_os(ORIGINE).is_some()
        && let Ok(copie) = std::env::current_exe()
        && est_une_copie(&copie)
    {
        effacer_copie(&copie);
    }
    // Lancé depuis la clé, chez le propriétaire comme ailleurs : relancé depuis une copie, la clé peut partir.
    if let Some(exe) = exe_courant()
        && doit_se_recopier(&exe, crate::reseau::cle_du_programme().as_deref())
    {
        let erreurs = relancer_depuis_une_copie(&exe);
        // Revenu : aucune copie n'a pu être lancée. Ailleurs que chez le propriétaire, la clé ne pourrait pas non
        // plus être démontée (le programme s'y lit) : rien de plus à essayer.
        sans_copie(&erreurs);
        return;
    }
    let Some(cle) = crate::reseau::cle_usb() else {
        return;
    };
    let attendue = empreinte_attendue(&cle);
    let attendue = attendue.trim();
    if attendue.is_empty() || Some(attendue) == crate::machine::empreinte_machine().as_deref() {
        return;
    }
    let Some((peripherique, lecture_seule)) = montage(&cle) else {
        return;
    };
    if lecture_seule {
        return;
    }
    // Le dossier courant est peut-être sur la clé (terminal ouvert dans Linux/) : on en sort.
    if let Some(maison) = crate::socle::personnel::dossier_personnel() {
        let _ = std::env::set_current_dir(maison);
    }
    // Un programme du bureau (indexation, miniatures) peut lire la clé un court instant : on réessaie un peu.
    let mut demontage = demonter(&peripherique);
    for _ in 0..4 {
        if demontage.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        demontage = demonter(&peripherique);
    }
    if let Err(e) = demontage {
        trp!(
            "  ⚠ Clé VANGUARD non protégée : elle est utilisée (terminal ou fenêtre ouverts dans la clé ?).\n    {GRIS}Fermez-les, puis relancez Vanguard depuis un autre dossier : {}/{DOSSIER_PROGRAMME}/vanguard{RESET}",
            "  ⚠ VANGUARD key not protected: it is in use (terminal or window open inside the key?).\n    {GRIS}Close them, then run Vanguard from another folder: {}/{DOSSIER_PROGRAMME}/vanguard{RESET}",
            cle.display()
        );
        crate::journal::erreur(
            crate::compte_rendu::Contexte::ProtectionCle,
            &format!("démontage impossible : {e}"),
        );
        return;
    }
    if let Err(e) = monter(&peripherique, true) {
        // Remontée impossible : on la remonte comme avant plutôt que de la laisser invisible.
        let _ = monter(&peripherique, false);
        crate::journal::erreur(
            crate::compte_rendu::Contexte::ProtectionCle,
            &format!("remontage en lecture seule refusé : {e}"),
        );
    } else {
        trp!(
            "  {GRIS}Clé VANGUARD remontée en lecture seule : cet ordinateur ne peut rien y écrire jusqu'au débranchement.{RESET}",
            "  {GRIS}VANGUARD key remounted read-only: this computer cannot write to it until it is unplugged.{RESET}"
        );
    }
}

/// Au démarrage, sous Windows : lancé depuis la clé, se relancer depuis une copie de `copies/` du dossier local et
/// attendre sa fin (`lancer_une_copie`) ; ce processus ne revient alors jamais. Dans une copie : effacer celles
/// d'avant dont le programme ne tourne plus.
#[cfg(windows)]
pub fn se_detacher_de_la_cle() {
    let _ = exe_d_origine();
    let Some(exe) = exe_courant() else {
        return;
    };
    let base = crate::socle::dossier_local().join("copies");
    if est_une_copie(&exe) {
        // Jamais en administrateur : effacer dans un dossier que le compte peut changer sous ses pieds (jonction posée
        // entre la vérification et l'effacement) ferait effacer ailleurs avec des droits qu'il n'a pas.
        if !crate::machine::windows::processus::eleve_ou_inconnu() {
            effacer_les_copies_orphelines(&base);
        }
        return;
    }
    if !doit_se_recopier(&exe, crate::reseau::cle_du_programme().as_deref()) {
        return;
    }
    if !crate::machine::windows::processus::eleve_ou_inconnu() {
        effacer_les_copies_orphelines(&base);
    }
    let Some(soi) = image_qui_tourne() else {
        sans_copie(&[tr!("programme qui tourne illisible", "running program unreadable").to_string()]);
        return;
    };
    match lancer_une_copie(
        &exe,
        &soi,
        &base,
        std::env::args_os().skip(1).collect(),
        &exe,
        attendre_sans_bruit,
    ) {
        Ok(code) => {
            // Après une désinstallation, il ne reste que ces dossiers vides : ils partent aussi. Jamais rien de plein.
            let _ = std::fs::remove_dir(&base);
            let _ = std::fs::remove_dir(crate::socle::dossier_local());
            std::process::exit(code)
        }
        Err(e) => sans_copie(&[e]),
    }
}

/// Le programme continue depuis la clé : dit en une ligne et noté au journal.
fn sans_copie(erreurs: &[String]) {
    trp!(
        "  ⚠ Vanguard tourne depuis la clé (copie sur cet ordinateur impossible) : ne la retirez pas avant de le quitter.",
        "  ⚠ Vanguard is running from the key (copy to this computer impossible): do not remove it before quitting."
    );
    crate::journal::erreur(
        crate::compte_rendu::Contexte::ProtectionCle,
        &format!("relance depuis une copie impossible : {}", erreurs.join(" ; ")),
    );
}

/// Se relancer depuis une copie ? Oui pour le programme `exe` posé sur la clé `cle` (chez le propriétaire comme
/// ailleurs), jamais hors de la clé ni pour une copie déjà faite. Une copie est reconnue à sa place, pas à
/// `VANGUARD_ORIGINE` : une variable que tout programme du compte peut poser ne doit pas laisser Vanguard sur la clé.
fn doit_se_recopier(exe: &Path, cle: Option<&Path>) -> bool {
    cle.is_some_and(|c| exe.starts_with(c)) && !est_une_copie(exe)
}

/// Où faire la copie, dans l'ordre essayé. Linux : d'abord `/run/user/<uid>`, réservé à la personne (/tmp est partagé
/// par tous les comptes de l'ordinateur). Windows : `copies/` du dossier local, celui du compte.
fn bases_des_copies() -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|d| d.is_dir())
            .into_iter()
            .chain([std::env::temp_dir()])
            .collect()
    }
    #[cfg(windows)]
    {
        vec![crate::socle::dossier_local().join("copies")]
    }
}

/// `exe` est-il une copie faite ici (`<base>/vanguard-<…>/vanguard`, `vanguard.exe` sous Windows) ?
/// La variable VANGUARD_ORIGINE ne suffit pas : tout programme lancé depuis la copie en hérite, et un Vanguard
/// relancé de là effacerait sinon son propre programme.
pub(crate) fn est_une_copie(exe: &Path) -> bool {
    let Some(dossier) = exe.parent() else {
        return false;
    };
    let base = dossier.parent().and_then(|b| b.canonicalize().ok());
    exe.file_name() == Some(std::ffi::OsStr::new(NOM_COPIE))
        && dossier
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("vanguard-"))
        && base.is_some_and(|b| {
            bases_des_copies()
                .iter()
                .any(|t| t.canonicalize().is_ok_and(|t| t == b))
        })
}

/// Un nom de dossier imprévisible (numéro du processus, nanosecondes) : `vanguard-<pid>-<nanos>`.
fn nom_de_copie() -> String {
    format!(
        "vanguard-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    )
}

/// Copie `exe` dans un dossier neuf `<base>/<nom>` : dossier et fichier refusés s'ils existent déjà (sinon un autre
/// compte de l'ordinateur pourrait les préparer d'avance et remplacer le programme entre la copie et son lancement),
/// réservés à la personne sous Linux. Un échec n'en laisse rien.
fn preparer_copie(exe: &Path, base: &Path, nom: &str) -> std::io::Result<PathBuf> {
    let dossier = base.join(nom);
    let copie = dossier.join(NOM_COPIE);
    // Le mode 0700 ne se pose que sous Linux : ailleurs, rien ne modifie le constructeur.
    #[cfg_attr(windows, allow(unused_mut))]
    let mut constructeur = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut constructeur, 0o700);
    constructeur.create(&dossier)?;
    let ecrite = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o700);
        let mut f = options.open(&copie)?;
        std::io::copy(&mut std::fs::File::open(exe)?, &mut f)?;
        f.sync_all()
    })();
    match ecrite {
        Ok(()) => Ok(copie),
        Err(e) => {
            effacer_copie(&copie);
            Err(e)
        }
    }
}

/// La copie a-t-elle exactement les octets du programme qui tourne (`soi` : leur empreinte) ? Sinon pourquoi.
fn verifier_copie(copie: &Path, soi: &str) -> Result<(), String> {
    let lu = crate::programmes_poses::empreinte_de(copie)?;
    if lu == soi {
        Ok(())
    } else {
        Err(tr!(
            "la copie n'a pas les octets du programme qui tourne",
            "the copy does not have the running program's bytes"
        )
        .to_string())
    }
}

/// Efface la copie et son dossier, rien d'autre : le dossier ne part que s'il est vide.
fn effacer_copie(copie: &Path) {
    let _ = std::fs::remove_file(copie);
    if let Some(dossier) = copie.parent() {
        let _ = std::fs::remove_dir(dossier);
    }
}

/// Copie le programme hors de la clé, vérifie la copie et la relance avec les mêmes arguments (exec : le même
/// processus). Ne revient qu'en cas d'échec, avec la raison de chaque base essayée.
#[cfg(unix)]
fn relancer_depuis_une_copie(exe: &Path) -> Vec<String> {
    use std::os::unix::process::CommandExt;
    let nom = nom_de_copie();
    let Some(soi) = image_qui_tourne() else {
        return vec![tr!("programme qui tourne illisible", "running program unreadable").to_string()];
    };
    let mut erreurs = Vec::new();
    for base in bases_des_copies() {
        // exec ne revient qu'en cas d'échec (dossier monté sans droit d'exécution…) : on essaie le suivant.
        let erreur = match copie_verifiee(exe, &base, &nom, &soi) {
            Ok(copie) => {
                let e = std::process::Command::new(&copie)
                    .args(std::env::args_os().skip(1))
                    .env(ORIGINE, exe)
                    .exec()
                    .to_string();
                effacer_copie(&copie);
                e
            }
            Err(e) => e,
        };
        erreurs.push(format!("{} : {erreur}", base.display()));
    }
    erreurs
}

/// `preparer_copie` puis `verifier_copie` ; une copie refusée est effacée.
#[cfg(unix)]
fn copie_verifiee(exe: &Path, base: &Path, nom: &str, soi: &str) -> Result<PathBuf, String> {
    let copie = preparer_copie(exe, base, nom).map_err(|e| e.to_string())?;
    if let Err(e) = verifier_copie(&copie, soi) {
        effacer_copie(&copie);
        return Err(e);
    }
    Ok(copie)
}

/// Copie `source` dans `base`, la tient ouverte en lecture seule partagée (ni écriture, ni renommage, ni effacement
/// jusqu'à la fin du fils), vérifie qu'elle a les octets `soi` du programme qui tourne, la lance avec `args` et
/// `VANGUARD_ORIGINE=origine` dans la même console, appelle `avant_d_attendre`, attend sa fin, l'efface et rend son
/// code de sortie. Un échec avant le lancement efface la copie et dit pourquoi.
#[cfg(windows)]
fn lancer_une_copie(
    source: &Path,
    soi: &str,
    base: &Path,
    args: Vec<std::ffi::OsString>,
    origine: &Path,
    avant_d_attendre: impl FnOnce(),
) -> Result<i32, String> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_SHARE_READ seul : Windows refuse alors toute ouverture en écriture ou en effacement, pas l'exécution.
    const PARTAGE_LECTURE: u32 = 1;
    std::fs::create_dir_all(base).map_err(|e| e.to_string())?;
    let copie = preparer_copie(source, base, &nom_de_copie()).map_err(|e| e.to_string())?;
    let refus = |e: String| {
        effacer_copie(&copie);
        Err(e)
    };
    let verrou = match std::fs::OpenOptions::new()
        .read(true)
        .share_mode(PARTAGE_LECTURE)
        .open(&copie)
    {
        Ok(v) => v,
        Err(e) => return refus(e.to_string()),
    };
    if let Err(e) = verifier_copie(&copie, soi) {
        drop(verrou);
        return refus(e);
    }
    let mut fils = match std::process::Command::new(&copie)
        .args(args)
        .env(ORIGINE, origine)
        .spawn()
    {
        Ok(f) => f,
        Err(e) => {
            drop(verrou);
            return refus(e.to_string());
        }
    };
    // Après le lancement : ce que pose `avant_d_attendre` (mode d'erreur) ne doit pas passer au fils.
    avant_d_attendre();
    let statut = fils.wait();
    drop(verrou);
    // L'image du fils peut rester projetée un court instant après sa fin.
    for _ in 0..20 {
        if std::fs::remove_file(&copie).is_ok() || std::fs::symlink_metadata(&copie).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    effacer_copie(&copie);
    let statut = statut.map_err(|e| e.to_string())?;
    Ok(statut.code().unwrap_or(1))
}

/// Pendant l'attente, le processus lancé depuis la clé ne doit ni montrer de fenêtre d'erreur (clé retirée : sa
/// prochaine page lue échoue, il s'arrête en silence et la copie continue) ni mourir d'un Ctrl+C avant la copie, qui
/// le reçoit aussi et décide elle-même.
#[cfg(windows)]
// FFI de kernel32 : SetErrorMode, SetConsoleCtrlHandler.
#[allow(unsafe_code)]
fn attendre_sans_bruit() {
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetErrorMode(mode: u32) -> u32;
        fn SetConsoleCtrlHandler(routine: Option<unsafe extern "system" fn(u32) -> i32>, ajouter: i32) -> i32;
    }
    /// Ctrl+C (0) et Ctrl+Pause (1) : gardés ; fermeture de la console, fin de session : le traitement de Windows.
    unsafe extern "system" fn ignorer(evenement: u32) -> i32 {
        i32::from(evenement <= 1)
    }
    // SAFETY: SetErrorMode ne prend qu'un entier et ne touche à aucune mémoire de Vanguard.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX) };
    // SAFETY: `ignorer` est une fonction `extern "system"` qui vit tout le programme et ne lit que son argument.
    unsafe { SetConsoleCtrlHandler(Some(ignorer), 1) };
}

/// Efface les copies d'avant (`<base>/vanguard-*/vanguard.exe` et leur dossier) dont le programme ne tourne plus :
/// celui qui les a lancées a disparu (clé retirée, fenêtre fermée). Jamais un lien ni une jonction, jamais hors de
/// `base`, jamais le dossier d'un processus encore là (il a pu créer son dossier sans encore tenir sa copie) ; un
/// programme en marche ne s'efface pas : sauté.
#[cfg(windows)]
fn effacer_les_copies_orphelines(base: &Path) {
    let Ok(entrees) = std::fs::read_dir(base) else {
        return;
    };
    for entree in entrees.flatten() {
        let nom = entree.file_name().to_string_lossy().into_owned();
        let Some(reste) = nom.strip_prefix("vanguard-") else {
            continue;
        };
        let dossier = base.join(&nom);
        if !std::fs::symlink_metadata(&dossier).is_ok_and(|m| m.is_dir() && !m.is_symlink()) {
            continue;
        }
        let pid = reste.split('-').next().and_then(|p| p.parse::<u32>().ok());
        if pid.is_some_and(|p| p == std::process::id() || crate::machine::windows::processus::creation(p).is_some()) {
            continue;
        }
        let copie = dossier.join(NOM_COPIE);
        if std::fs::symlink_metadata(&copie).is_ok_and(|m| m.is_symlink()) {
            continue;
        }
        effacer_copie(&copie);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S2c : VANGUARD_ORIGINE n'est crue que si le fichier désigné a les octets du programme qui tourne ; un autre
    /// programme, un fichier absent ou un programme illisible : ignorée, avec la raison.
    #[test]
    fn origine_crue_seulement_aux_memes_octets() {
        let d = crate::essais::temporaire().join(format!("vanguard-origine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let vrai = d.join("vanguard");
        let autre = d.join("autre");
        std::fs::write(&vrai, b"programme de vanguard").unwrap();
        std::fs::write(&autre, b"programme d'un autre").unwrap();
        let soi = crate::programmes_poses::empreinte_de(&vrai).ok();
        assert_eq!(
            origine_crue(&vrai, soi.clone()).ok(),
            Some(vrai.canonicalize().unwrap())
        );
        assert!(origine_crue(&autre, soi.clone()).is_err());
        assert!(origine_crue(&d.join("absent"), soi).is_err());
        assert!(origine_crue(&vrai, None).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn montage_de_la_racine() {
        let donnees = Path::new("/");
        let (_, lecture_seule) = montage(donnees).expect("volume de données monté");
        assert!(!lecture_seule);
        assert!(montage(Path::new("/pas/un/montage")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn empreinte_lue_dans_le_temoin() {
        let cle = crate::essais::temporaire().join(format!("vanguard-temoin-{}", std::process::id()));
        std::fs::create_dir_all(&cle).unwrap();
        assert_eq!(empreinte_attendue(&cle), "");
        std::fs::write(cle.join("vanguard.cle"), "abc").unwrap();
        assert_eq!(empreinte_attendue(&cle), "abc");
        let _ = std::fs::remove_dir_all(&cle);
    }

    #[test]
    fn seule_la_copie_temporaire_s_efface() {
        let base = bases_des_copies().remove(0);
        let dossier = base.join(format!("vanguard-test-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let copie = dossier.join(NOM_COPIE);
        std::fs::write(&copie, "").unwrap();
        assert!(est_une_copie(&copie));
        // Le programme installé, ou un « Vanguard » posé ailleurs : jamais effacés.
        assert!(!est_une_copie(Path::new("/usr/bin/vanguard")));
        assert!(!est_une_copie(&base.join(NOM_COPIE)));
        effacer_copie(&copie);
        assert!(!dossier.exists());
    }

    /// Une fausse clé (témoin `vanguard.cle`, programme dans Linux/ ou Windows/), au témoin `temoin`.
    fn fausse_cle(nom: &str, temoin: &str) -> PathBuf {
        let cle = crate::essais::temporaire().join(format!("vanguard-cle-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cle);
        std::fs::create_dir_all(cle.join("Linux")).unwrap();
        std::fs::write(cle.join(crate::reseau::TEMOIN_CLE), temoin).unwrap();
        std::fs::write(cle.join("Linux").join(NOM_COPIE), "programme").unwrap();
        cle
    }

    /// Lancé depuis la clé, Vanguard se recopie toujours : chez le propriétaire (témoin à l'empreinte de cet
    /// ordinateur) comme chez un proche ; jamais hors de la clé, ni depuis une copie déjà faite, même si la clé la
    /// contenait.
    #[test]
    fn se_recopier_seulement_depuis_la_cle() {
        let ici = crate::machine::empreinte_machine().unwrap_or_else(|| "empreinte-d-essai".into());
        for (nom, temoin) in [
            ("proprietaire", ici.as_str()),
            ("proche", "0123456789abcdef"),
            ("vide", ""),
        ] {
            let cle = fausse_cle(nom, temoin);
            let exe = cle.join("Linux").join(NOM_COPIE);
            assert!(doit_se_recopier(&exe, Some(&cle)), "{nom}");
            assert!(!doit_se_recopier(&exe, None), "{nom}");
            assert!(!doit_se_recopier(Path::new("/usr/bin/vanguard"), Some(&cle)), "{nom}");
            let _ = std::fs::remove_dir_all(&cle);
        }
        let base = bases_des_copies().remove(0);
        std::fs::create_dir_all(&base).unwrap();
        let dossier = base.join(format!("vanguard-decision-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let copie = dossier.join(NOM_COPIE);
        std::fs::write(&copie, "").unwrap();
        assert!(!doit_se_recopier(&copie, Some(&base)));
        effacer_copie(&copie);
    }

    /// La copie se fait dans un dossier neuf, refusé s'il existe déjà ; une copie aux octets différents de ceux du
    /// programme qui tourne est refusée et effacée, la bonne est gardée (réservée à la personne sous Linux).
    #[cfg(unix)]
    #[test]
    fn copie_aux_octets_differents_refusee() {
        use std::os::unix::fs::PermissionsExt;
        let cle = fausse_cle("octets", "");
        let exe = cle.join("Linux").join(NOM_COPIE);
        let base = crate::essais::temporaire().join(format!("vanguard-bases-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let soi = crate::programmes_poses::empreinte_de(&exe).unwrap();
        let autre = crate::programmes_poses::empreinte_de(&cle.join(crate::reseau::TEMOIN_CLE)).unwrap();
        assert!(copie_verifiee(&exe, &base, "vanguard-1-2", &autre).is_err());
        assert!(!base.join("vanguard-1-2").exists(), "copie refusée laissée");
        let copie = copie_verifiee(&exe, &base, "vanguard-1-3", &soi).unwrap();
        assert_eq!(std::fs::read(&copie).unwrap(), b"programme");
        let droits = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((droits(&copie), droits(copie.parent().unwrap())), (0o700, 0o700));
        // Un dossier déjà là (préparé d'avance par un autre) : refusé, et rien de ce qu'il contient n'est touché.
        std::fs::create_dir_all(base.join("vanguard-1-4")).unwrap();
        std::fs::write(base.join("vanguard-1-4").join("autre"), "x").unwrap();
        assert!(copie_verifiee(&exe, &base, "vanguard-1-4", &soi).is_err());
        assert!(base.join("vanguard-1-4").join("autre").exists());
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&cle);
    }

    /// Le programme de Windows de cmd.exe : petit, et qui rend le code qu'on lui demande.
    #[cfg(windows)]
    fn cmd() -> Option<PathBuf> {
        Some(crate::commande::dossier_systeme().join("cmd.exe")).filter(|c| c.is_file())
    }

    /// Windows : la copie est créée dans copies/, vérifiée, lancée avec les arguments et VANGUARD_ORIGINE ; son code
    /// de sortie est rendu et son dossier effacé. Aux octets différents : refusée, effacée, jamais lancée.
    #[cfg(windows)]
    #[test]
    fn copie_lancee_attendue_puis_effacee() {
        let Some(source) = cmd() else {
            return crate::essais::saute("cmd.exe absent");
        };
        let base = crate::essais::temporaire().join(format!("vanguard-copies-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let soi = crate::programmes_poses::empreinte_de(&source).unwrap();
        let mut appele = false;
        let code = lancer_une_copie(
            &source,
            &soi,
            &base,
            vec!["/c".into(), "if defined VANGUARD_ORIGINE (exit 7) else (exit 3)".into()],
            Path::new(r"C:\origine"),
            || appele = true,
        );
        assert_eq!(code, Ok(7));
        assert!(appele);
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0, "copie laissée");
        let refus = lancer_une_copie(
            &source,
            "0000",
            &base,
            vec!["/c".into(), "exit 7".into()],
            &source,
            || panic!("attente d'une copie refusée"),
        );
        assert!(refus.is_err());
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0, "copie refusée laissée");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Windows : les copies d'avant s'effacent, sauf celle d'un processus qui tourne encore (ici le nôtre, et un
    /// programme tenu ouvert) ; rien hors de `vanguard-*/vanguard.exe` : ni un autre fichier, ni un autre dossier, ni
    /// ce qui est à côté de `copies/`.
    #[cfg(windows)]
    #[test]
    fn seules_les_copies_orphelines_s_effacent() {
        use std::os::windows::fs::OpenOptionsExt;
        let racine = crate::essais::temporaire().join(format!("vanguard-orphelines-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&racine);
        let base = racine.join("copies");
        let poser = |chemin: &Path| {
            std::fs::create_dir_all(chemin.parent().unwrap()).unwrap();
            std::fs::write(chemin, "programme").unwrap();
        };
        // Numéros de processus qui ne tournent pas : pas un nombre, ou au-delà de ce que Windows donne.
        let orpheline = base.join("vanguard-x-1").join(NOM_COPIE);
        let orpheline_2 = base.join("vanguard-4294967295-2").join(NOM_COPIE);
        let la_mienne = base.join(format!("vanguard-{}-3", std::process::id())).join(NOM_COPIE);
        let tenue = base.join("vanguard-y-4").join(NOM_COPIE);
        let avec_autre = base.join("vanguard-z-5");
        let autre_nom = base.join("autre-6").join(NOM_COPIE);
        let a_cote = racine.join("vanguard-7").join(NOM_COPIE);
        for f in [&orpheline, &orpheline_2, &la_mienne, &tenue, &autre_nom, &a_cote] {
            poser(f);
        }
        poser(&avec_autre.join(NOM_COPIE));
        poser(&avec_autre.join("autre.txt"));
        // Tenu comme le premier processus tient la copie de son fils : ni effacement ni renommage.
        let verrou = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&tenue)
            .unwrap();
        effacer_les_copies_orphelines(&base);
        assert!(!orpheline.parent().unwrap().exists());
        assert!(!orpheline_2.parent().unwrap().exists());
        assert!(la_mienne.exists() && tenue.exists() && autre_nom.exists() && a_cote.exists());
        assert!(
            avec_autre.join("autre.txt").exists(),
            "un autre fichier du dossier effacé"
        );
        drop(verrou);
        let _ = std::fs::remove_dir_all(&racine);
    }
}
