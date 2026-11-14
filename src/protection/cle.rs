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

use crate::modele::Echec;
use crate::ui::*;

/// Le contexte des échecs de la copie du programme hors de la clé.
const OU_COPIE: &str = "cle/copie";

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
/// installer, poser en tâche ou dire vérifié un autre programme que Vanguard, et prendre un dossier du compte pour la
/// clé. Elle n'est donc crue que dans une copie temporaire (`est_une_copie`, reconnue à sa place), et seulement si le
/// fichier qu'elle désigne a exactement les octets du programme qui tourne ; hors d'une copie elle est ignorée sans
/// bruit, dans une copie l'écart est dit (et noté au journal des erreurs). Sinon c'est le programme qui tourne qui
/// compte : rien n'est installé depuis elle.
pub fn exe_d_origine() -> Option<PathBuf> {
    /// L'origine décidée, et l'écart à dire : (chemin désigné montrable, raison).
    type Decision = (Option<PathBuf>, Option<(String, String)>);
    static DECIDE: std::sync::OnceLock<Decision> = std::sync::OnceLock::new();
    // L'alerte se dit après l'initialisation, jamais pendant : le journal se demande où il est (clé ou non) et
    // rappellerait cette fonction sur le même fil, dans une initialisation pas finie (blocage ou panique).
    static ALERTE_DITE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let (origine, alerte) = DECIDE.get_or_init(|| {
        let designee = std::env::var_os(ORIGINE);
        let dans_une_copie = || std::env::current_exe().is_ok_and(|e| est_une_copie(&e));
        let (crue, alerte) = decider_origine(designee.as_deref().map(Path::new), dans_une_copie, image_qui_tourne);
        let alerte = alerte.map(|raison| {
            let designee = designee.as_deref().map_or_else(PathBuf::new, PathBuf::from);
            (chemin_affichable(&designee), raison.to_string())
        });
        (crue.map(|c| lisible(&c)).or_else(exe_courant), alerte)
    });
    if let Some((designee, raison)) = alerte
        && !ALERTE_DITE.swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        tre!(
            "Attention : VANGUARD_ORIGINE désigne {designee}, qui n'est pas le programme qui tourne ({raison}) : ignorée.",
            "Warning: VANGUARD_ORIGINE points to {designee}, which is not the running program ({raison}): ignored."
        );
        crate::journal::erreur(
            crate::compte_rendu::Contexte::OrigineProgramme,
            &format!("VANGUARD_ORIGINE ignorée : {raison}"),
        );
    }
    origine.clone()
}

/// Ce que vaut `VANGUARD_ORIGINE` (`designee`) : le chemin cru, ou `None` (le programme qui tourne compte), et l'écart
/// à dire. Hors d'une copie temporaire (`dans_une_copie`), la variable n'est qu'héritée (un Vanguard lancé par celui
/// de la clé) ou posée par un autre programme du compte : ignorée sans bruit, ses octets ne sont même pas lus (une
/// copie exacte de Vanguard posée dans un dossier du compte les aurait). Le fichier désigné absent (clé retirée avant
/// ce lancement : un Vanguard relancé par la copie, l'autotest) : rien à dire, il n'est pas cru non plus.
fn decider_origine(
    designee: Option<&Path>,
    dans_une_copie: impl FnOnce() -> bool,
    soi: impl FnOnce() -> Option<String>,
) -> (Option<PathBuf>, Option<Echec>) {
    let Some(designee) = designee else {
        return (None, None);
    };
    if !dans_une_copie() {
        return (None, None);
    }
    match origine_crue(designee, soi()) {
        Ok(chemin) => (Some(chemin), None),
        Err(Refus::Absente) => (None, None),
        Err(Refus::Autre(raison)) => (None, Some(raison)),
    }
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
/// fichier (sous Windows, celui tenu par `soi_au_depart` dans une copie). La copie de cet ordinateur ne se pose
/// qu'à partir d'octets qui l'ont (`mise_a_jour::poser_copie`).
pub(crate) fn image_qui_tourne() -> Option<String> {
    // Déjà lue par les programmes posés : pas une seconde lecture du programme.
    if let Some(soi) = crate::programmes_poses::soi() {
        return Some(soi.to_string());
    }
    #[cfg(windows)]
    {
        soi_au_depart().map(str::to_string)
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "linux")]
        let image = PathBuf::from("/proc/self/exe");
        #[cfg(not(target_os = "linux"))]
        let image = std::env::current_exe().ok()?;
        crate::programmes_poses::empreinte_de(&image).ok()
    }
}

/// Pourquoi `VANGUARD_ORIGINE` n'est pas crue.
#[derive(Debug)]
enum Refus {
    /// Le fichier désigné n'existe plus (clé retirée, lecteur disparu).
    Absente,
    /// Présent mais pas le programme qui tourne, ou illisible : un écart à dire.
    Autre(crate::modele::Echec),
}

/// Le fichier `designee`, s'il a exactement les octets du programme qui tourne (`soi` : leur empreinte) ; sinon
/// pourquoi il n'est pas cru.
fn origine_crue(designee: &Path, soi: Option<String>) -> Result<PathBuf, Refus> {
    const OU: &str = "cle/origine";
    let chemin = designee.canonicalize().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Refus::Absente
        } else {
            Refus::Autre(crate::modele::Echec::io(OU, &e))
        }
    })?;
    let lu = crate::programmes_poses::empreinte_de(&chemin)
        .map_err(|e| Refus::Autre(crate::modele::Echec::refuse(OU, e)))?;
    let soi = soi.ok_or_else(|| {
        Refus::Autre(crate::modele::Echec::refuse(
            OU,
            tr!("programme qui tourne illisible", "running program unreadable"),
        ))
    })?;
    if lu == soi {
        Ok(chemin)
    } else {
        Err(Refus::Autre(crate::modele::Echec::refuse(
            OU,
            tr!(
                "ses octets ne sont pas ceux du programme qui tourne",
                "its bytes are not those of the running program"
            ),
        )))
    }
}

/// La clé d'où ce lancement est parti, fixée au démarrage, pendant que son témoin se lit encore. Une fois la clé
/// retirée, `reseau::cle_usb` ne la voit plus, mais le programme d'origine reste un chemin de la clé : il ne doit
/// jamais être posé en tâche, en raccourci ni remplacé par une mise à jour (`programme_ephemere`).
pub(crate) fn cle_de_lancement() -> Option<&'static Path> {
    static CLE: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    CLE.get_or_init(|| exe_d_origine().as_deref().and_then(crate::reseau::cle_de))
        .as_deref()
}

/// `exe` ne restera pas sur cet ordinateur : sur la clé (branchée, ou celle du lancement, même retirée) ou copie
/// temporaire. Ce qui le lancerait plus tard doit lancer une copie locale à la place.
pub(crate) fn programme_ephemere(exe: &Path) -> bool {
    ephemere_parmi(exe, crate::reseau::cle_usb().as_deref(), cle_de_lancement())
}

/// `programme_ephemere`, la clé branchée (`branchee`) et celle du lancement (`de_lancement`) données.
pub(crate) fn ephemere_parmi(exe: &Path, branchee: Option<&Path>, de_lancement: Option<&Path>) -> bool {
    [branchee, de_lancement]
        .into_iter()
        .flatten()
        .any(|cle| crate::reseau::surveillance::sous(exe, cle))
        || est_une_copie(exe)
}

/// Le programme à relancer pour un Vanguard à part (l'autotest du menu). Sous Linux, l'image qui tourne : la copie
/// temporaire s'est déjà effacée, et `current_exe` rendrait « …/vanguard (deleted) », qui ne se lance pas.
#[cfg_attr(target_os = "linux", allow(clippy::unnecessary_wraps))] // même signature que sous Windows, où le chemin peut manquer
pub(crate) fn programme_a_relancer() -> std::io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Ok(PathBuf::from("/proc/self/exe"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe()
    }
}

/// Windows : l'empreinte du programme qui tourne, prise une fois au démarrage (`se_detacher_de_la_cle`). Dans une
/// copie temporaire, son fichier reste ouvert en lecture seule partagée toute la vie du processus : ni renommé, ni
/// remplacé, ni effacé, même si le premier processus (qui le tenait aussi) meurt avec la clé ; l'empreinte est lue par
/// cette poignée-là, c'est bien celle de l'image lancée. Hors d'une copie, c'est seulement le fichier qui se trouve à
/// ce chemin à ce moment, lu par son nom : Windows laisse renommer un programme en marche, et un fichier mis à sa place
/// entre le lancement et cette lecture serait pris pour soi. Celui qui le peut aurait pu remplacer le programme avant
/// son lancement : ce n'est pas une preuve que l'image qui tourne a ces octets, seulement que ce fichier les a.
#[cfg(windows)]
pub(crate) fn soi_au_depart() -> Option<&'static str> {
    use std::os::windows::fs::OpenOptionsExt;
    static SOI: std::sync::OnceLock<Option<(Option<std::fs::File>, String)>> = std::sync::OnceLock::new();
    SOI.get_or_init(|| {
        let exe = std::env::current_exe().ok()?;
        if est_une_copie(&exe) {
            let tenu = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(PARTAGE_LECTURE)
                .open(&exe)
                .ok()?;
            let empreinte = crate::programmes_poses::empreinte_du_fichier(&tenu).ok()?;
            return Some((Some(tenu), empreinte));
        }
        Some((None, crate::programmes_poses::empreinte_de(&exe).ok()?))
    })
    .as_ref()
    .map(|(_, empreinte)| empreinte.as_str())
}

/// Windows : le fichier ouvert `f` a-t-il les octets du programme qui tourne (`soi_au_depart`) ? La relance en
/// administrateur le demande au fichier qu'elle a verrouillé, juste avant de le lancer.
#[cfg(windows)]
pub(crate) fn meme_que_soi(f: &std::fs::File) -> bool {
    memes_octets(f, soi_au_depart())
}

#[cfg(windows)]
fn memes_octets(f: &std::fs::File, soi: Option<&str>) -> bool {
    soi.is_some_and(|soi| crate::programmes_poses::empreinte_du_fichier(f).is_ok_and(|lu| lu == soi))
}

/// FILE_SHARE_READ seul : Windows refuse alors toute ouverture en écriture ou en effacement (renommage compris), pas
/// la lecture ni l'exécution.
#[cfg(windows)]
const PARTAGE_LECTURE: u32 = 1;

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
    // L'origine et sa clé se décident avant que la copie temporaire ne s'efface et tant que la clé se lit : sans
    // elles, rien ne se compare plus.
    let _ = exe_d_origine();
    let _ = cle_de_lancement();
    // Copie temporaire relancée : elle supprime son fichier (Linux le garde lisible jusqu'à la fin du programme).
    if std::env::var_os(ORIGINE).is_some()
        && let Ok(copie) = std::env::current_exe()
        && est_ma_copie(&copie)
    {
        effacer_copie(&copie);
        sortir_de_la_cle();
    }
    // Les copies d'un lancement tué avant de s'effacer (Ctrl+C au démarrage, arrêt).
    for base in bases_des_copies() {
        effacer_les_copies_orphelines(&base);
    }
    // Lancé depuis la clé, chez le propriétaire comme ailleurs : relancé depuis une copie, la clé peut partir. La clé
    // se lit au programme qui tourne, pas à VANGUARD_ORIGINE, que tout programme du compte peut poser.
    if let Some(exe) = exe_courant()
        && doit_se_recopier(&exe, crate::reseau::cle_de(&exe).as_deref())
    {
        let erreurs = relancer_depuis_une_copie(&exe);
        // Revenu : aucune copie n'a pu être lancée. Ailleurs que chez le propriétaire, la clé ne pourrait pas non
        // plus être démontée (le programme s'y lit) : rien de plus à essayer.
        sans_copie(
            tr!(
                "copie sur cet ordinateur impossible",
                "copy to this computer impossible"
            ),
            &erreurs,
        );
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
/// attendre sa fin (`lancer_une_copie`) ; ce processus ne revient alors jamais. À chaque lancement hors
/// administrateur : effacer les copies d'avant dont le lanceur ne tourne plus (clé retirée, fenêtre fermée de force).
#[cfg(windows)]
pub fn se_detacher_de_la_cle() {
    let _ = exe_d_origine();
    let _ = cle_de_lancement();
    // Pris tôt, une fois ; dans une copie, le fichier reste tenu jusqu'à la fin. Hors d'une copie, lu par son chemin
    // (voir `soi_au_depart` : ce n'est pas une preuve sur l'image qui tourne).
    let _ = soi_au_depart();
    let eleve = crate::machine::windows::processus::eleve_ou_inconnu();
    let base = bases_des_copies().into_iter().next();
    // Jamais en administrateur : effacer dans un dossier que le compte peut changer sous ses pieds (jonction posée
    // entre la vérification et l'effacement) ferait effacer ailleurs avec des droits qu'il n'a pas.
    if !eleve && let Some(base) = &base {
        effacer_les_copies_orphelines(base);
    }
    let Some(exe) = exe_courant() else {
        return;
    };
    if est_une_copie(&exe) {
        sortir_de_la_cle();
        return;
    }
    let base = match depart(&exe, crate::reseau::cle_de(&exe).as_deref(), eleve, base) {
        Depart::Rester => return,
        Depart::SansCopie(pourquoi) => {
            sans_copie(pourquoi, &[]);
            return;
        }
        Depart::Copier(base) => base,
    };
    let Some(soi) = image_qui_tourne() else {
        sans_copie(
            tr!(
                "copie sur cet ordinateur impossible",
                "copy to this computer impossible"
            ),
            &[tr!("programme qui tourne illisible", "running program unreadable").to_string()],
        );
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
        Err(e) => sans_copie(
            tr!(
                "copie sur cet ordinateur impossible",
                "copy to this computer impossible"
            ),
            &[e.to_string()],
        ),
    }
}

/// Ce que fait au démarrage un Vanguard lancé sous Windows.
#[cfg(windows)]
#[derive(Debug, PartialEq)]
enum Depart {
    /// Pas sur la clé, ou déjà une copie : rien à faire.
    Rester,
    /// Sur la clé, mais rester sur elle, pour la raison donnée.
    SansCopie(&'static str),
    /// Se recopier dans ce dossier.
    Copier(PathBuf),
}

/// `exe` lancé depuis la clé `cle` (élevé ou non, `base` : où copier) : se recopier ? Jamais en administrateur : la
/// copie se ferait dans le dossier du compte, que tout programme non élevé de ce compte peut changer (une jonction
/// posée sur `copies/` entre la vérification et le lancement), et Windows lancerait alors un autre programme avec les
/// droits d'administrateur. Vanguard reste alors sur la clé, comme avant, et le dit.
#[cfg(windows)]
fn depart(exe: &Path, cle: Option<&Path>, eleve: bool, base: Option<PathBuf>) -> Depart {
    if !doit_se_recopier(exe, cle) {
        return Depart::Rester;
    }
    if eleve {
        return Depart::SansCopie(tr!("lancé en administrateur", "started as administrator"));
    }
    match base {
        Some(base) => Depart::Copier(base),
        None => Depart::SansCopie(tr!(
            "dossier de Vanguard de cet ordinateur inconnu",
            "Vanguard's folder on this computer unknown"
        )),
    }
}

/// Le programme continue depuis la clé, pour la raison `pourquoi` : dit en une ligne ; une erreur est notée au
/// journal.
fn sans_copie(pourquoi: &str, erreurs: &[String]) {
    trp!(
        "  ⚠ Vanguard tourne depuis la clé ({pourquoi}) : ne la retirez pas avant de le quitter.",
        "  ⚠ Vanguard is running from the key ({pourquoi}): do not remove it before quitting."
    );
    if !erreurs.is_empty() {
        crate::journal::erreur(
            crate::compte_rendu::Contexte::ProtectionCle,
            &format!("relance depuis une copie impossible : {}", erreurs.join(" ; ")),
        );
    }
}

/// La copie a démarré avec le dossier courant de celui qui l'a lancée, souvent dans la clé (terminal ouvert dans
/// Linux/ ou Windows\, gestionnaire de fichiers) : elle en sort pour ne pas tenir la clé occupée (éjection refusée).
/// Seulement dans ce cas, pour ne pas changer le sens d'un chemin relatif donné depuis un autre dossier.
fn sortir_de_la_cle() {
    if let Some(cle) = cle_de_lancement()
        && std::env::current_dir().is_ok_and(|d| crate::reseau::surveillance::sous(&d, cle))
        && let Some(maison) = crate::socle::personnel::dossier_personnel()
    {
        let _ = std::env::set_current_dir(maison);
    }
}

/// Se relancer depuis une copie ? Oui pour le programme `exe` posé sur la clé `cle` (chez le propriétaire comme
/// ailleurs), jamais hors de la clé ni pour une copie déjà faite. Une copie est reconnue à sa place, pas à
/// `VANGUARD_ORIGINE` : une variable que tout programme du compte peut poser ne doit pas laisser Vanguard sur la clé.
fn doit_se_recopier(exe: &Path, cle: Option<&Path>) -> bool {
    cle.is_some_and(|c| exe.starts_with(c)) && !est_une_copie(exe)
}

/// Où faire la copie, dans l'ordre essayé. Linux : d'abord `/run/user/<uid>`, réservé à la personne (/tmp est partagé
/// par tous les comptes de l'ordinateur). Windows : `copies/` du dossier local, celui du compte. Jamais un chemin
/// relatif (variable absente ou vide) : il se lirait depuis le dossier courant, peut-être la clé elle-même.
fn bases_des_copies() -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .into_iter()
            .chain([std::env::temp_dir()])
            .filter(|d| base_sure(d))
            .collect()
    }
    #[cfg(windows)]
    {
        Some(crate::socle::dossier_local().join("copies"))
            .filter(|d| d.is_absolute())
            .into_iter()
            .collect()
    }
}

/// Unix : un vrai dossier (pas un lien), absolu, à ce compte et que ni son groupe ni les autres ne peuvent changer ;
/// ou à root avec le bit collant (/tmp), où personne ne renomme ce qu'un autre y a créé. Sinon (root qui a gardé
/// l'environnement du compte : `/run/user/<uid>` du compte), un autre pourrait remplacer la copie entre sa
/// vérification et son lancement.
#[cfg(unix)]
fn base_sure(d: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    d.is_absolute()
        && std::fs::symlink_metadata(d).is_ok_and(|m| {
            m.is_dir()
                && ((m.uid() == crate::socle::euid() && m.mode() & 0o022 == 0)
                    || (m.uid() == 0 && m.mode() & 0o1000 != 0))
        })
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

/// `copie` est-elle la copie de ce processus-ci, à effacer à son départ ? Une copie (`est_une_copie`), dans le dossier
/// que ce processus a créé avant son exec (même numéro), à ce compte et réservé à lui. Pas seulement la place et
/// VANGUARD_ORIGINE héritée : un autre Vanguard posé là effacerait sinon son propre programme.
#[cfg(unix)]
fn est_ma_copie(copie: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(dossier) = copie.parent() else {
        return false;
    };
    est_une_copie(copie)
        && dossier.file_name().is_some_and(|n| {
            n.to_string_lossy()
                .starts_with(&format!("vanguard-{}-", std::process::id()))
        })
        && std::fs::symlink_metadata(dossier)
            .is_ok_and(|m| m.is_dir() && m.uid() == crate::socle::euid() && m.mode() & 0o777 == 0o700)
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
        // Windows : personne d'autre ne l'ouvre pendant qu'elle s'écrit.
        #[cfg(windows)]
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, 0);
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
#[cfg(unix)]
fn verifier_copie(copie: &Path, soi: &str) -> Result<(), Echec> {
    let lu = crate::programmes_poses::empreinte_de(copie)?;
    if lu == soi {
        Ok(())
    } else {
        Err(Echec::refuse(
            OU_COPIE,
            tr!(
                "la copie n'a pas les octets du programme qui tourne",
                "the copy does not have the running program's bytes"
            ),
        ))
    }
}

/// Windows : la copie tenue ouverte (`verrou`) a-t-elle les octets `soi`, lus par sa poignée ?
#[cfg(windows)]
fn verifier_tenue(verrou: &std::fs::File, soi: &str) -> Result<(), Echec> {
    if memes_octets(verrou, Some(soi)) {
        Ok(())
    } else {
        Err(Echec::refuse(
            OU_COPIE,
            tr!(
                "la copie n'a pas les octets du programme qui tourne",
                "the copy does not have the running program's bytes"
            ),
        ))
    }
}

/// Windows : `base` (`copies\`) et son dossier (`vanguard\`, le dossier local), quand ils existent, ne sont pas des
/// points d'analyse (jonction, lien) : le compte les possède et pourrait y retourner une jonction entre la vérification
/// de la copie et son lancement.
#[cfg(windows)]
fn base_sans_point_d_analyse(base: &Path) -> Result<(), Echec> {
    use std::os::windows::fs::MetadataExt;
    const POINT_D_ANALYSE: u32 = 0x400;
    for d in [base.parent(), Some(base)].into_iter().flatten() {
        match std::fs::symlink_metadata(d) {
            Ok(m) if m.file_attributes() & POINT_D_ANALYSE != 0 || m.file_type().is_symlink() => {
                return Err(Echec::refuse(
                    OU_COPIE,
                    tr!(
                        "le dossier des copies est un lien ou une jonction : refusé",
                        "the copies folder is a link or a junction: refused"
                    ),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Echec::io(OU_COPIE, &e)),
        }
    }
    Ok(())
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
    let bases = bases_des_copies();
    if bases.is_empty() {
        erreurs.push(
            tr!(
                "aucun dossier temporaire sûr pour la copie",
                "no safe temporary folder for the copy"
            )
            .to_string(),
        );
    }
    for base in bases {
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
            Err(e) => e.to_string(),
        };
        erreurs.push(format!("{} : {erreur}", base.display()));
    }
    erreurs
}

/// `preparer_copie` puis `verifier_copie` ; une copie refusée est effacée.
#[cfg(unix)]
fn copie_verifiee(exe: &Path, base: &Path, nom: &str, soi: &str) -> Result<PathBuf, Echec> {
    let copie = preparer_copie(exe, base, nom).map_err(|e| Echec::ecriture(OU_COPIE, &e))?;
    if let Err(e) = verifier_copie(&copie, soi) {
        effacer_copie(&copie);
        return Err(e);
    }
    Ok(copie)
}

/// Copie `source` dans `base`, tient le fichier de la copie ouvert en lecture seule partagée (ni écriture, ni
/// renommage, ni effacement du fichier jusqu'à la fin du fils ; les dossiers du chemin, eux, ne sont pas tenus : c'est
/// pourquoi elle n'est jamais faite en administrateur, voir `depart`), vérifie qu'elle a les octets `soi` du programme
/// qui tourne, la lance avec `args` et `VANGUARD_ORIGINE=origine` dans la même console, appelle `avant_d_attendre`,
/// attend sa fin, l'efface et rend son code de sortie. Un échec avant le lancement efface la copie et dit pourquoi.
#[cfg(windows)]
fn lancer_une_copie(
    source: &Path,
    soi: &str,
    base: &Path,
    args: Vec<std::ffi::OsString>,
    origine: &Path,
    avant_d_attendre: impl FnOnce(),
) -> Result<i32, Echec> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    // Avant et après la création : une jonction posée d'avance sur `vanguard\` ou `copies\` (le compte les possède)
    // se retournerait entre la vérification et le lancement.
    base_sans_point_d_analyse(base)?;
    std::fs::create_dir_all(base).map_err(|e| Echec::ecriture(OU_COPIE, &e))?;
    base_sans_point_d_analyse(base)?;
    let copie = preparer_copie(source, base, &nom_de_copie()).map_err(|e| Echec::ecriture(OU_COPIE, &e))?;
    let refus = |e: Echec| {
        effacer_copie(&copie);
        Err(e)
    };
    let verrou = match std::fs::OpenOptions::new()
        .read(true)
        .share_mode(PARTAGE_LECTURE)
        .open(&copie)
    {
        Ok(v) => v,
        Err(e) => return refus(Echec::io(OU_COPIE, &e)),
    };
    // Par la poignée du verrou, pas par le chemin : c'est ce fichier-là que plus rien ne change.
    if let Err(e) = verifier_tenue(&verrou, soi) {
        drop(verrou);
        return refus(e);
    }
    // Suivi par les coulisses jusqu'à sa fin : la copie lancée s'y voit, avec son code.
    let (lance, mut suivi) =
        crate::coulisses::Suivie::spawn_et_suivre(std::process::Command::new(&copie).args(args).env(ORIGINE, origine));
    let mut fils = match lance {
        Ok(f) => f,
        Err(e) => {
            drop(verrou);
            return refus(Echec::echoue(OU_COPIE, e.to_string()));
        }
    };
    // Lancée par son chemin : son image doit être le fichier tenu et vérifié. Sinon (un dossier du chemin retourné
    // entre-temps), elle est arrêtée et Vanguard reste sur la clé, en le disant.
    if !crate::machine::windows::eleve::image_du_fils_est(fils.as_raw_handle(), &verrou) {
        let _ = fils.kill();
        let _ = fils.wait();
        drop(suivi);
        drop(verrou);
        return refus(Echec::refuse(
            OU_COPIE,
            tr!(
                "la copie lancée n'est pas le fichier vérifié : arrêtée",
                "the started copy is not the verified file: stopped"
            ),
        ));
    }
    // La console fermée par le X, la fin de session : Windows ne laisse que le gestionnaire (`effacer_a_la_fermeture`)
    // agir avant d'arrêter ce processus ; il retrouve ici la copie et son verrou.
    if let Ok(mut en_cours) = COPIE_EN_COURS.lock() {
        *en_cours = Some((copie.clone(), Some(verrou)));
    }
    // Après le lancement : ce que pose `avant_d_attendre` (mode d'erreur) ne doit pas passer au fils.
    avant_d_attendre();
    let statut = fils.wait();
    if let Ok(s) = &statut {
        suivi.fin(crate::coulisses::Issue::Code(s.code()));
    }
    drop(suivi);
    if let Ok(mut en_cours) = COPIE_EN_COURS.lock() {
        en_cours.take();
    }
    // L'image du fils peut rester projetée un court instant après sa fin.
    for _ in 0..20 {
        if std::fs::remove_file(&copie).is_ok() || std::fs::symlink_metadata(&copie).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    effacer_copie(&copie);
    let statut = statut.map_err(|e| Echec::echoue(OU_COPIE, e.to_string()))?;
    Ok(statut.code().unwrap_or(1))
}

/// La copie lancée par ce processus et le verrou de son fichier, le temps de l'attendre.
#[cfg(windows)]
static COPIE_EN_COURS: std::sync::Mutex<Option<(PathBuf, Option<std::fs::File>)>> = std::sync::Mutex::new(None);

/// Console fermée par le X, fin de session ou arrêt : la copie reçoit le même événement et s'arrête ; Windows laisse
/// environ 5 s avant d'arrêter ce processus-ci. On lâche le verrou et on efface la copie dès qu'elle est finie (une
/// image en marche ne s'efface pas). Coupé avant (clé retirée, arrêt forcé) : `effacer_les_copies_orphelines` la
/// retrouve au prochain lancement de Vanguard sur cet ordinateur.
#[cfg(windows)]
fn effacer_a_la_fermeture() {
    let Some((copie, verrou)) = COPIE_EN_COURS.lock().ok().and_then(|mut e| e.take()) else {
        return;
    };
    drop(verrou);
    for _ in 0..40 {
        if std::fs::remove_file(&copie).is_ok() || std::fs::symlink_metadata(&copie).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    effacer_copie(&copie);
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
    /// Ctrl+C (0) et Ctrl+Pause (1) : gardés ; fermeture de la console, fin de session, arrêt : la copie effacée
    /// une fois finie, puis le traitement de Windows (fin du processus).
    unsafe extern "system" fn ignorer(evenement: u32) -> i32 {
        if evenement <= 1 {
            return 1;
        }
        effacer_a_la_fermeture();
        0
    }
    // SAFETY: SetErrorMode ne prend qu'un entier et ne touche à aucune mémoire de Vanguard.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX) };
    // SAFETY: `ignorer` est une fonction `extern "system"` qui vit tout le programme et ne lit que son argument.
    unsafe { SetConsoleCtrlHandler(Some(ignorer), 1) };
}

/// Efface les copies d'avant (`<base>/vanguard-*/<NOM_COPIE>` et leur dossier) dont le lanceur ne tourne plus : clé
/// retirée, fenêtre fermée de force, programme tué avant de s'effacer. Jamais un lien ni une jonction, jamais hors de
/// `base`, jamais le dossier d'un autre compte (Unix), jamais celui d'un processus encore là (il a pu créer son dossier
/// sans encore tenir sa copie) ; un programme en marche ne s'efface pas : sauté.
fn effacer_les_copies_orphelines(base: &Path) {
    let Ok(entrees) = std::fs::read_dir(base) else {
        return;
    };
    for entree in entrees.flatten() {
        let nom = entree.file_name().to_string_lossy().into_owned();
        if !nom.starts_with("vanguard-") {
            continue;
        }
        let dossier = base.join(&nom);
        let Ok(meta) = std::fs::symlink_metadata(&dossier) else {
            continue;
        };
        if !meta.is_dir() || meta.is_symlink() {
            continue;
        }
        #[cfg(unix)]
        if std::os::unix::fs::MetadataExt::uid(&meta) != crate::socle::euid() {
            continue;
        }
        if lanceur_vivant(&nom) {
            continue;
        }
        let copie = dossier.join(NOM_COPIE);
        if std::fs::symlink_metadata(&copie).is_ok_and(|m| m.is_symlink()) {
            continue;
        }
        effacer_copie(&copie);
    }
}

/// Le numéro du processus qui a créé la copie `vanguard-<pid>-<nanos>` et l'heure de création (ns depuis 1970).
fn lanceur_de(nom: &str) -> (Option<u32>, Option<u128>) {
    let mut parts = nom.strip_prefix("vanguard-").unwrap_or_default().split('-');
    (
        parts.next().and_then(|p| p.parse().ok()),
        parts.next().and_then(|n| n.parse().ok()),
    )
}

/// Le lanceur du dossier de copie `nom` tourne-t-il encore ? Ce processus-ci, oui. Un nom sans numéro n'est pas de
/// Vanguard : non.
fn lanceur_vivant(nom: &str) -> bool {
    let (pid, nanos) = lanceur_de(nom);
    let Some(pid) = pid else {
        return false;
    };
    if pid == std::process::id() {
        return true;
    }
    #[cfg(unix)]
    {
        // Un numéro repris par un autre programme garde la copie jusqu'à la fin de la session (/run/user est vidé) :
        // jamais celle d'un lancement en cours.
        let _ = nanos;
        Path::new("/proc").join(pid.to_string()).exists()
    }
    #[cfg(windows)]
    {
        crate::machine::windows::processus::creation(pid).is_some_and(|c| cree_avant(c, nanos))
    }
}

/// Windows : un processus créé à `creation` (FILETIME, centaines de ns depuis 1601) peut-il avoir créé une copie à
/// `nanos` (ns depuis 1970) ? Non s'il est né après (le numéro a été repris : la copie est orpheline). Deux secondes
/// de marge pour les horloges ; sans heure lisible dans le nom, on le croit vivant.
#[cfg(windows)]
fn cree_avant(creation: u64, nanos: Option<u128>) -> bool {
    /// 1601 → 1970, en centaines de nanosecondes.
    const DECALAGE: u64 = 116_444_736_000_000_000;
    let Some(nanos) = nanos else {
        return true;
    };
    let creation_ns = u128::from(creation.saturating_sub(DECALAGE)) * 100;
    creation_ns <= nanos + 2_000_000_000
}

/// Windows : le lanceur de la copie `copie` (le premier processus, qui l'efface à sa fin) tourne-t-il encore ?
#[cfg(windows)]
pub(crate) fn lanceur_de_la_copie_vivant(copie: &Path) -> bool {
    copie
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|n| lanceur_vivant(&n.to_string_lossy()))
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
        // Un autre programme, un programme qui tourne illisible : un écart, dit. Un fichier qui n'est plus là (clé
        // retirée) : ignoré sans fausse alerte, et jamais cru.
        assert!(matches!(origine_crue(&autre, soi.clone()), Err(Refus::Autre(_))));
        assert!(matches!(origine_crue(&d.join("absent"), soi), Err(Refus::Absente)));
        assert!(matches!(origine_crue(&vrai, None), Err(Refus::Autre(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// MOYENNE (campagne d'attaque, DONNEES-1, COPIE-2) : hors d'une copie temporaire, VANGUARD_ORIGINE n'est jamais
    /// crue, même vers une copie exacte du programme posée dans un dossier du compte avec un témoin de clé : sinon ce
    /// dossier devenait « la clé » (données, clés connues, désinstallation, mise à jour). Ses octets ne sont même pas
    /// lus, et rien n'est dit. Dans une copie, la règle des mêmes octets reste.
    #[test]
    fn origine_jamais_crue_hors_d_une_copie() {
        let d = crate::essais::temporaire().join(format!("vanguard-hors-copie-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("x")).unwrap();
        std::fs::write(d.join("vanguard.cle"), "").unwrap();
        let exacte = d.join("x").join("v");
        std::fs::write(&exacte, b"programme de vanguard").unwrap();
        let soi = crate::programmes_poses::empreinte_de(&exacte).ok();
        let (crue, alerte) = decider_origine(Some(&exacte), || false, || panic!("octets lus hors d'une copie"));
        assert!(crue.is_none() && alerte.is_none(), "crue hors d'une copie : {crue:?}");
        let (crue, alerte) = decider_origine(Some(&exacte), || true, || soi.clone());
        assert_eq!(crue, Some(exacte.canonicalize().unwrap()));
        assert!(alerte.is_none());
        let (crue, alerte) = decider_origine(Some(&d.join("vanguard.cle")), || true, || soi.clone());
        assert!(crue.is_none() && alerte.is_some());
        assert_eq!(decider_origine(None, || true, || soi.clone()).0, None);
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
        let dossier = base.join(format!("vanguard-{}-essai", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let copie = dossier.join(NOM_COPIE);
        std::fs::write(&copie, "").unwrap();
        assert!(est_une_copie(&copie));
        // Le programme installé, ou un « Vanguard » posé ailleurs : jamais effacés.
        assert!(!est_une_copie(Path::new("/usr/bin/vanguard")));
        assert!(!est_une_copie(&base.join(NOM_COPIE)));
        // Unix : seule la copie de ce processus (son numéro, dossier à lui en 0700) s'efface d'elle-même ; celle d'un
        // autre numéro, ou un dossier ouvert aux autres, non.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(!est_ma_copie(&copie), "dossier 0755 pris pour le sien");
            std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(est_ma_copie(&copie));
            let autre = base.join("vanguard-1-essai");
            std::fs::create_dir_all(&autre).unwrap();
            std::fs::set_permissions(&autre, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(autre.join(NOM_COPIE), "").unwrap();
            assert!(est_une_copie(&autre.join(NOM_COPIE)) && !est_ma_copie(&autre.join(NOM_COPIE)));
            effacer_copie(&autre.join(NOM_COPIE));
        }
        effacer_copie(&copie);
        assert!(!dossier.exists());
    }

    /// Unix : une base de copies n'est acceptée que réservée à ce compte (ou /tmp, collant à root) ; relative, liée,
    /// ouverte aux autres sans bit collant, ou à un autre compte : refusée.
    #[cfg(unix)]
    #[test]
    fn base_des_copies_sure_seulement() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::essais::temporaire().join(format!("vanguard-base-sure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(base_sure(&d));
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!base_sure(&d), "ouverte à tous sans bit collant");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lien = d.with_extension("lien");
        let _ = std::fs::remove_file(&lien);
        std::os::unix::fs::symlink(&d, &lien).unwrap();
        assert!(!base_sure(&lien), "lien");
        assert!(!base_sure(Path::new("relatif")), "relatif");
        if crate::socle::euid() != 0 {
            assert!(!base_sure(Path::new("/usr")), "à un autre compte");
        }
        let _ = std::fs::remove_file(&lien);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Unix : les copies d'un lancement tué avant de s'effacer partent au lancement suivant ; pas celle d'un
    /// processus vivant (ici le nôtre), ni un lien, ni ce qui n'est pas `vanguard-*`, ni un autre fichier du dossier.
    #[cfg(unix)]
    #[test]
    fn copies_orphelines_effacees_sous_unix() {
        let base = crate::essais::temporaire().join(format!("vanguard-orph-unix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let poser = |chemin: &Path| {
            std::fs::create_dir_all(chemin.parent().unwrap()).unwrap();
            std::fs::write(chemin, "programme").unwrap();
        };
        let morte = base.join("vanguard-4294967295-1").join(NOM_COPIE);
        let la_mienne = base.join(format!("vanguard-{}-2", std::process::id())).join(NOM_COPIE);
        let autre_nom = base.join("autre-3").join(NOM_COPIE);
        let avec_autre = base.join("vanguard-4294967294-4");
        for f in [&morte, &la_mienne, &autre_nom] {
            poser(f);
        }
        poser(&avec_autre.join(NOM_COPIE));
        poser(&avec_autre.join("autre.txt"));
        let cible = base.join("ailleurs");
        poser(&cible.join(NOM_COPIE));
        std::os::unix::fs::symlink(&cible, base.join("vanguard-4294967293-5")).unwrap();
        effacer_les_copies_orphelines(&base);
        assert!(!morte.parent().unwrap().exists());
        assert!(la_mienne.exists() && autre_nom.exists() && cible.join(NOM_COPIE).exists());
        assert!(avec_autre.join("autre.txt").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Le dossier d'une copie dit qui l'a lancée et quand.
    #[test]
    fn lanceur_lu_dans_le_nom() {
        assert_eq!(
            lanceur_de("vanguard-42-1700000000000000000"),
            (Some(42), Some(1_700_000_000_000_000_000))
        );
        assert_eq!(lanceur_de("vanguard-x-1"), (None, Some(1)));
        assert!(lanceur_vivant(&format!("vanguard-{}-1", std::process::id())));
        assert!(!lanceur_vivant("vanguard-x-1"));
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

    /// HAUTE (relecture) : en administrateur, jamais de copie. Elle se ferait dans le dossier du compte, qu'un programme
    /// non élevé peut détourner (jonction sur copies/) pour faire lancer le sien avec le jeton administrateur. Vanguard
    /// reste sur la clé et le dit ; hors administrateur, il se recopie ; sans dossier local sûr, il reste aussi.
    #[cfg(windows)]
    #[test]
    fn jamais_de_copie_en_administrateur() {
        let cle = fausse_cle("eleve", "");
        let exe = cle.join("Linux").join(NOM_COPIE);
        let base = crate::essais::temporaire().join("copies");
        assert!(matches!(
            depart(&exe, Some(&cle), true, Some(base.clone())),
            Depart::SansCopie(_)
        ));
        assert_eq!(
            depart(&exe, Some(&cle), false, Some(base.clone())),
            Depart::Copier(base.clone())
        );
        assert!(matches!(depart(&exe, Some(&cle), false, None), Depart::SansCopie(_)));
        assert_eq!(
            depart(
                Path::new(r"C:\Program Files\vanguard.exe"),
                Some(&cle),
                true,
                Some(base)
            ),
            Depart::Rester
        );
        let _ = std::fs::remove_dir_all(&cle);
    }

    /// Windows : la relance en administrateur ne lance que le fichier aux octets du programme qui tourne (empreinte
    /// prise au démarrage) ; un autre, ou sans empreinte, non.
    #[cfg(windows)]
    #[test]
    fn relance_seulement_aux_octets_de_soi() {
        let d = crate::essais::temporaire().join(format!("vanguard-soi-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let (vrai, autre) = (d.join("vrai.exe"), d.join("autre.exe"));
        std::fs::write(&vrai, b"programme de vanguard").unwrap();
        std::fs::write(&autre, b"programme d'un autre").unwrap();
        let soi = crate::programmes_poses::empreinte_de(&vrai).unwrap();
        assert!(memes_octets(&std::fs::File::open(&vrai).unwrap(), Some(&soi)));
        assert!(!memes_octets(&std::fs::File::open(&autre).unwrap(), Some(&soi)));
        assert!(!memes_octets(&std::fs::File::open(&vrai).unwrap(), None));
        // Le programme des essais se reconnaît lui-même : la vraie relance ne refuserait pas Vanguard.
        let exe = std::env::current_exe().unwrap();
        assert!(meme_que_soi(&std::fs::File::open(&exe).unwrap()));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Windows : un numéro de processus repris par un programme né après la copie ne la garde pas.
    #[cfg(windows)]
    #[test]
    fn numero_repris_ne_garde_pas_la_copie() {
        // 2023-11-14 22:13:20 UTC en FILETIME, et la même heure en ns depuis 1970.
        let creation = 116_444_736_000_000_000 + 17_000_000_000_000_000;
        let nanos = 1_700_000_000_000_000_000u128;
        assert!(cree_avant(creation, Some(nanos)));
        assert!(cree_avant(creation, Some(nanos - 1_000_000_000)), "marge des horloges");
        assert!(
            !cree_avant(creation, Some(nanos - 60_000_000_000)),
            "né une minute après la copie"
        );
        assert!(cree_avant(creation, None));
    }

    /// Windows : la copie est créée dans copies/, vérifiée, lancée avec les arguments et VANGUARD_ORIGINE ; son code
    /// de sortie est rendu et son dossier effacé. Aux octets différents : refusée, effacée, jamais lancée.
    #[cfg(windows)]
    #[test]
    fn copie_lancee_attendue_puis_effacee() {
        let Some(source) = cmd() else {
            return crate::essais::saute("cmd.exe absent");
        };
        // Dans le dossier temporaire du système (C: sous Wine) : sur Z:, Wine ne donne pas le chemin NT du fichier
        // tenu, et la copie lancée y serait refusée comme une image inconnue.
        let jetable = crate::essais::Jetable::garder(std::env::temp_dir().join(crate::essais::nom_unique("copies")));
        let base = jetable.to_path_buf();
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

    /// BASSE (campagne d'attaque, COPIE-3) : un dossier des copies (`copies\`, ou le dossier local au-dessus) qui est
    /// un lien ou une jonction est refusé avant toute copie : le compte pourrait le retourner entre la vérification et
    /// le lancement. Rien n'est lancé, rien n'est laissé dans la cible.
    #[cfg(windows)]
    #[test]
    fn base_des_copies_en_lien_refusee() {
        use std::os::windows::fs::MetadataExt;
        let Some(source) = cmd() else {
            return crate::essais::saute("cmd.exe absent");
        };
        // Sur C: sous Wine (comme copie_lancee_attendue_puis_effacee) : sur Z:, l'image de la copie lancée serait
        // refusée de toute façon, et l'essai ne verrait pas une base en lien acceptée.
        let jetable = crate::essais::Jetable::garder(std::env::temp_dir().join(crate::essais::nom_unique("base-lien")));
        let d = jetable.to_path_buf();
        let (cible, local) = (d.join("ailleurs"), d.join("local"));
        std::fs::create_dir_all(&cible).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        let base = local.join("copies");
        if std::os::windows::fs::symlink_dir(&cible, &base).is_err()
            || !std::fs::symlink_metadata(&base).is_ok_and(|m| m.file_attributes() & 0x400 != 0)
        {
            let _ = std::fs::remove_dir_all(&d);
            return crate::essais::saute("lien symbolique de dossier impossible ou invisible ici");
        }
        let soi = crate::programmes_poses::empreinte_de(&source).unwrap();
        let r = lancer_une_copie(
            &source,
            &soi,
            &base,
            vec!["/c".into(), "exit 7".into()],
            &source,
            || panic!("copie lancée par une base en lien"),
        );
        let vu = format!("{r:?}");
        assert!(
            vu.contains("jonction") || vu.contains("junction"),
            "base en lien acceptée, ou refusée pour une autre raison : {r:?}"
        );
        assert_eq!(
            std::fs::read_dir(&cible).unwrap().count(),
            0,
            "copie posée dans la cible du lien"
        );
        let _ = std::fs::remove_dir(&base);
        let _ = std::fs::remove_dir_all(&d);
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
