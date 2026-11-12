//! `vanguard` sans argument : la fenêtre de Vanguard (`vanguard-fenetre`, posée à côté du programme) quand la
//! personne est devant un écran graphique, sinon le menu du terminal, comme avant. Tant que la fenêtre n'est pas
//! livrée (`FENETRE_LIVREE`, faux en 0.94 et 0.95), toujours le menu : aucun `vanguard-fenetre` n'est lancé. La fenêtre ne fait rien d'elle-même :
//! elle relance ce programme-ci avec des commandes en lecture, et un seul changement, un programme retiré du démarrage
//! ou remis, après sa confirmation (voir `fenetre/` et MODELE-DE-MENACE.md, « La fenêtre »).
//!
//! Le menu reste le choix sûr : sans terminal des deux côtés (un script qui écrit les choix, une sortie redirigée),
//! en SSH ou au Bureau à distance, en administrateur, sans écran graphique, sans fenêtre posée à côté, avec une fenêtre que d'autres
//! comptes pourraient remplacer, ou si elle ne dit pas « ouverte » à temps. `vanguard --menu` le force.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::coulisses::Suivie;
use crate::{tr, trf};

/// La ligne que la fenêtre écrit sur sa sortie quand elle s'est ouverte (fenetre/src/dessin/mod.rs).
const OUVERTE: &str = "vanguard-fenetre:ouverte";

/// La fenêtre n'est pas livrée avec cette version : `vanguard` ne lance alors aucun `vanguard-fenetre`, même posé à
/// côté. Avant, la confiance allait au nom et à l'emplacement du fichier, pas à son contenu : n'importe quel
/// programme de ce nom, exécutable, était lancé et pouvait dire « ouverte » à sa place (LIV-1). La fenêtre revient
/// quand son lancement vérifie une empreinte signée (0.96, MODELE-DE-MENACE.md, « La fenêtre »).
pub(crate) const FENETRE_LIVREE: bool = false;

/// Le temps laissé à la fenêtre pour s'ouvrir (premier lancement sur un vieil ordinateur, pilote graphique lent).
const ATTENTE: Duration = Duration::from_secs(20);

/// Ce qui décide entre la fenêtre et le menu, lu une fois.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)] // des constats, chacun pour lui-même
pub(crate) struct Contexte {
    /// L'entrée et la sortie sont un terminal : quelqu'un est là, pas un script.
    pub(crate) terminal: bool,
    /// Un écran graphique est là (Linux : WAYLAND_DISPLAY ou DISPLAY).
    pub(crate) graphique: bool,
    /// Session à distance : SSH (Linux), Bureau à distance (Windows).
    pub(crate) a_distance: bool,
    /// Vanguard tourne en administrateur (root, sudo, console administrateur) : pas de fenêtre avec tous les droits.
    pub(crate) eleve: bool,
}

/// La fenêtre ou le menu ? La fenêtre seulement quand tout le dit ; dans le doute, le menu.
pub(crate) fn choisir(c: Contexte) -> bool {
    c.terminal && c.graphique && !c.a_distance && !c.eleve
}

fn contexte() -> Contexte {
    use std::io::IsTerminal;
    let present = |v: &str| std::env::var_os(v).is_some_and(|x| !x.is_empty());
    Contexte {
        terminal: std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        graphique: cfg!(windows) || present("WAYLAND_DISPLAY") || present("DISPLAY"),
        a_distance: a_distance(&present),
        eleve: super::droits::processus_eleve(),
    }
}

#[cfg(windows)]
fn a_distance(_present: &dyn Fn(&str) -> bool) -> bool {
    crate::machine::windows::session_a_distance()
}

#[cfg(not(windows))]
fn a_distance(present: &dyn Fn(&str) -> bool) -> bool {
    present("SSH_CONNECTION") || present("SSH_TTY") || present("SSH_CLIENT")
}

/// Le nom de la fenêtre sur la page de la version, téléchargée à côté de `vanguard-linux-x86_64`.
#[cfg(windows)]
const NOM_PAGE: &str = "vanguard-fenetre-windows-x86_64.exe";
#[cfg(not(windows))]
const NOM_PAGE: &str = "vanguard-fenetre-linux-x86_64";

/// Le chemin de la fenêtre à côté de ce programme (jamais cherchée dans le PATH) : `vanguard-fenetre`, sinon le nom
/// de la page de la version. Deux noms n'ouvrent rien de plus : la confiance va à l'empreinte, pas au nom. Aucune des
/// deux : la première, que `ouvrir_depuis` dira absente.
fn voisine(programme: &Path) -> Option<PathBuf> {
    let dossier = programme.parent()?;
    let premiere = dossier.join(format!("vanguard-fenetre{}", std::env::consts::EXE_SUFFIX));
    let page = dossier.join(NOM_PAGE);
    if std::fs::symlink_metadata(&premiere).is_err() && std::fs::symlink_metadata(&page).is_ok() {
        return Some(page);
    }
    Some(premiere)
}

/// Ce que reçoit la fenêtre : dire « ouverte » à ce programme, sa langue, et le programme qu'elle lancera, celui
/// d'origine (`programme`) : lancée d'une copie en mémoire, elle n'a plus de dossier où le trouver.
fn arguments(programme: &Path) -> Vec<std::ffi::OsString> {
    let langue = if crate::langue::anglais() { "en" } else { "fr" };
    let mut a: Vec<std::ffi::OsString> = ["--depuis-vanguard", "--langue", langue, "--vanguard"]
        .map(Into::into)
        .into();
    a.push(programme.into());
    a
}

/// Pourquoi la fenêtre posée à côté n'est pas lancée, s'il y a une raison. Sous Linux, elle doit être un vrai
/// fichier (pas un lien), à ce compte ou à root, et que ni le groupe ni les autres ne peuvent modifier : sinon un
/// autre compte pourrait y mettre une fausse fenêtre qui dirait « tout va bien ».
#[cfg(unix)]
fn refus(m: &std::fs::Metadata, moi: u32) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    if !m.file_type().is_file() {
        return Some(tr!("pas un fichier ordinaire", "not a regular file"));
    }
    if m.uid() != moi && m.uid() != 0 {
        return Some(tr!("à un autre compte", "owned by another account"));
    }
    if m.mode() & 0o022 != 0 {
        return Some(tr!("modifiable par d'autres comptes", "writable by other accounts"));
    }
    None
}

/// Un dossier du chemin de la fenêtre : un vrai dossier, à ce compte ou à root, que ni le groupe ni les autres ne
/// peuvent modifier, sauf s'il est « collant » (sticky, comme /tmp : les autres comptes n'y renomment ni n'y
/// effacent ce qui n'est pas à eux). Sinon un autre compte pourrait renommer la fenêtre ou son dossier et en poser
/// une fausse entre la vérification et le lancement.
#[cfg(unix)]
fn refus_dossier(m: &std::fs::Metadata, moi: u32) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    if !m.file_type().is_dir() {
        return Some(tr!(
            "un dossier du chemin est un lien",
            "a folder on the path is a link"
        ));
    }
    if m.uid() != moi && m.uid() != 0 {
        return Some(tr!(
            "un dossier du chemin est à un autre compte",
            "a folder on the path is owned by another account"
        ));
    }
    if m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
        return Some(tr!(
            "un dossier du chemin est modifiable par d'autres comptes",
            "a folder on the path is writable by other accounts"
        ));
    }
    None
}

/// La fenêtre (`refus`), puis chacun des dossiers qui la contiennent jusqu'à la racine (`refus_dossier`), sans
/// suivre aucun lien. Le chemin vient de `current_exe`, déjà résolu sous Linux.
#[cfg(unix)]
fn refus_chemin(chemin: &Path, m: &std::fs::Metadata, moi: u32) -> Option<&'static str> {
    if let Some(r) = refus(m, moi) {
        return Some(r);
    }
    chemin
        .ancestors()
        .skip(1)
        .filter(|d| !d.as_os_str().is_empty())
        .find_map(|d| match std::fs::symlink_metadata(d) {
            Ok(m) => refus_dossier(&m, moi),
            Err(_) => Some(tr!("un dossier illisible", "an unreadable folder")),
        })
}

#[cfg(windows)]
fn refus(m: &std::fs::Metadata) -> Option<&'static str> {
    (!m.file_type().is_file()).then(|| tr!("pas un fichier ordinaire", "not a regular file"))
}

/// Ouvre la fenêtre si c'est le bon choix et qu'elle dit s'être ouverte ; `false` : le menu du terminal.
/// La fenêtre est cherchée à côté du programme d'origine : sous Linux, avec la protection de la clé, ce programme
/// tourne d'une copie temporaire (`protection::cle::exe_d_origine`).
pub(crate) fn ouvrir() -> bool {
    #[cfg(unix)]
    let programme = crate::protection::cle::exe_d_origine();
    // Sous Windows, pas de protection de la clé : le programme qui tourne est celui d'origine.
    #[cfg(windows)]
    let programme = std::env::current_exe().ok();
    let Some(programme) = programme else {
        return false;
    };
    let Some(chemin) = voisine(&programme) else {
        return false;
    };
    ouvrir_depuis(contexte(), &chemin, &programme)
}

/// `ouvrir`, pour un contexte, un chemin de fenêtre et un programme d'origine donnés (les essais).
fn ouvrir_depuis(c: Contexte, chemin: &Path, programme: &Path) -> bool {
    if !choisir(c) {
        return false;
    }
    if !FENETRE_LIVREE {
        // Quelqu'un attendait la fenêtre (un fichier à son nom est posé à côté) : le dire, sans rien lancer.
        if std::fs::symlink_metadata(chemin).is_ok() {
            eprintln!(
                "{}",
                tr!(
                    "La fenêtre de Vanguard n'est pas livrée avec cette version : le fichier « vanguard-fenetre » posé à côté n'est pas lancé. Le menu du terminal.",
                    "The Vanguard window is not shipped with this version: the \"vanguard-fenetre\" file next to it is not started. The terminal menu."
                )
            );
        }
        return false;
    }
    let chemin = chemin.to_path_buf();
    // symlink_metadata : un lien n'est pas suivi, il est refusé (pas un fichier ordinaire).
    let Ok(m) = std::fs::symlink_metadata(&chemin) else {
        // Pas de fenêtre posée à côté (un Vanguard sans elle) : le menu, sans un mot.
        return false;
    };
    #[cfg(unix)]
    let raison = refus_chemin(&chemin, &m, crate::socle::uid());
    #[cfg(windows)]
    let raison = refus(&m);
    if let Some(r) = raison {
        eprintln!(
            "{}",
            trf!(
                "Fenêtre de Vanguard laissée de côté ({}) : le menu du terminal.",
                "Vanguard window left aside ({}): the terminal menu.",
                r
            )
        );
        return false;
    }
    match lancer(&chemin, programme) {
        Lancement::Ouverte => return true,
        Lancement::Refusee(r) => eprintln!(
            "{}",
            trf!(
                "Fenêtre de Vanguard laissée de côté ({}) : le menu du terminal.",
                "Vanguard window left aside ({}): the terminal menu.",
                r
            )
        ),
        Lancement::PasOuverte => eprintln!(
            "{}",
            tr!(
                "La fenêtre de Vanguard ne s'est pas ouverte : le menu du terminal.",
                "The Vanguard window did not open: the terminal menu."
            )
        ),
    }
    false
}

/// Ce qu'est devenu le lancement de la fenêtre.
#[derive(Debug)]
enum Lancement {
    /// Elle a dit « ouverte ».
    Ouverte,
    /// Pas lancée : la raison.
    Refusee(String),
    /// Lancée, mais elle n'a pas dit « ouverte » à temps (arrêtée).
    PasOuverte,
}

/// Le plus gros fichier de fenêtre lu (la fenêtre compilée fait une dizaine de Mio).
const TAILLE_MAX: u64 = 128 * 1024 * 1024;

/// Les octets de la fenêtre ouverte, `TAILLE_MAX` au plus (`m` : ce que dit la poignée).
fn lire_borne(f: &std::fs::File, m: &std::fs::Metadata) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let trop = || tr!("fichier trop gros", "file too large").to_string();
    if m.len() > TAILLE_MAX {
        return Err(trop());
    }
    let mut octets = Vec::new();
    f.take(TAILLE_MAX.saturating_add(1))
        .read_to_end(&mut octets)
        .map_err(|e| trf!("illisible : {}", "unreadable: {}", e))?;
    if u64::try_from(octets.len()).map_or(true, |n| n > TAILLE_MAX) {
        return Err(trop());
    }
    Ok(octets)
}

/// L'empreinte lue est-elle celle attendue ? Sinon la raison.
fn comparer(lue: &[u8; 32], attendue: &[u8; 32]) -> Result<(), String> {
    if lue == attendue {
        return Ok(());
    }
    Err(tr!(
        "son empreinte n'est pas celle de la fenêtre de cette version",
        "its fingerprint is not that of this version's window"
    )
    .into())
}

/// La fenêtre vérifiée, prête à lancer : une copie de ses octets en mémoire (memfd), scellée, dont l'empreinte est
/// celle gravée dans ce programme. Lancée d'elle, plus rien ne peut changer ce qui tourne entre la vérification et le
/// lancement : ni un autre compte, ni ce compte-ci, ni ce programme.
#[cfg(target_os = "linux")]
struct Verifiee(std::fs::File);

/// La fenêtre de `chemin`, si elle passe : ouverte sans suivre de lien ni attendre (un tube nommé), jugée sur ce qui
/// est ouvert (`refus` : fichier ordinaire, à ce compte ou à root, non modifiable par d'autres), lue entière, copiée
/// dans un memfd scellé, et l'empreinte calculée **sur cette copie scellée**, celle qui sera lancée. Sinon la raison.
#[cfg(target_os = "linux")]
fn verifier(chemin: &Path, attendue: &[u8; 32], moi: u32) -> Result<Verifiee, String> {
    use sha2::Digest;
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(chemin)
        .map_err(|e| trf!("illisible : {}", "unreadable: {}", e))?;
    let m = f.metadata().map_err(|e| trf!("illisible : {}", "unreadable: {}", e))?;
    if let Some(r) = refus(&m, moi) {
        return Err(r.into());
    }
    let octets = lire_borne(&f, &m)?;
    let copie = super::memfd::scelle("vanguard-fenetre", &octets)
        .map_err(|e| trf!("copie scellée impossible : {}", "sealed copy impossible: {}", e))?;
    drop(octets);
    // L'empreinte de la copie scellée, relue du début : exactement ce que le noyau lancera.
    let mut h = sha2::Sha256::new();
    let mut tampon = vec![0u8; 1 << 16];
    let mut position = 0u64;
    loop {
        let n = copie
            .read_at(&mut tampon, position)
            .map_err(|e| trf!("copie illisible : {}", "copy unreadable: {}", e))?;
        let Some(lus) = tampon.get(..n).filter(|l| !l.is_empty()) else {
            break;
        };
        h.update(lus);
        position = position.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    comparer(&h.finalize().into(), attendue)?;
    Ok(Verifiee(copie))
}

/// La commande qui lance la copie scellée : `/proc/self/fd/<n>`, ce que fait `fexecve` (glibc, musl). Le descripteur
/// est fermé au lancement (`MFD_CLOEXEC`) : la fenêtre ne l'hérite pas. Son nom affiché reste `vanguard-fenetre`.
#[cfg(target_os = "linux")]
fn commande(v: &Verifiee) -> Command {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let mut c = Command::new(format!("/proc/self/fd/{}", v.0.as_raw_fd()));
    c.arg0("vanguard-fenetre");
    c
}

/// Windows : la fenêtre vérifiée, **tenue** ouverte avec le partage en lecture seule (ni écriture, ni effacement, ni
/// renommage par personne tant que la poignée vit ; une écriture déjà ouverte fait échouer l'ouverture), et son
/// chemin. Windows lance un fichier par son chemin : tenu jusqu'à la fin du lancement, c'est le fichier vérifié qui
/// est lancé ; une fois lancé, Windows refuse d'écrire l'image d'un programme qui tourne.
#[cfg(windows)]
struct Verifiee {
    _tenue: std::fs::File,
    chemin: PathBuf,
}

/// La fenêtre de `chemin`, si elle passe : ouverte tenue, sans suivre de lien (`FILE_FLAG_OPEN_REPARSE_POINT` : un
/// lien ou une jonction est ouvert lui-même, puis refusé), fichier ordinaire, lue entière sur cette poignée, son
/// empreinte comparée. Sinon la raison. Les droits (ACL) du fichier et de ses dossiers ne sont pas lus (limite dite
/// au modèle de menace).
#[cfg(windows)]
fn verifier(chemin: &Path, attendue: &[u8; 32]) -> Result<Verifiee, String> {
    use sha2::Digest;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(chemin)
        .map_err(|e| trf!("illisible : {}", "unreadable: {}", e))?;
    let m = f.metadata().map_err(|e| trf!("illisible : {}", "unreadable: {}", e))?;
    if let Some(r) = refus(&m) {
        return Err(r.into());
    }
    if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(tr!("un lien", "a link").into());
    }
    let octets = lire_borne(&f, &m)?;
    comparer(&sha2::Sha256::digest(&octets).into(), attendue)?;
    Ok(Verifiee {
        _tenue: f,
        chemin: chemin.to_path_buf(),
    })
}

/// La commande qui lance la fenêtre tenue, par son chemin.
#[cfg(windows)]
fn commande(v: &Verifiee) -> Command {
    Command::new(&v.chemin)
}

/// Lance la fenêtre et attend qu'elle dise « ouverte ». Elle n'est pas attendue au-delà : ce programme s'arrête et
/// la fenêtre continue seule. Sa sortie d'erreur est jetée (un pilote graphique bavard ne salit pas le terminal).
/// Pas par `commande::lancer`, qui attend la fin du programme : la fenêtre vit après nous ; lancée par les coulisses
/// quand même (`spawn_suivi`), elle s'y voit.
fn lancer(chemin: &Path, programme: &Path) -> Lancement {
    // Seconde garde, au seul endroit qui construit la commande : rien ne lance la fenêtre tant qu'elle n'est pas livrée.
    if !FENETRE_LIVREE {
        return Lancement::Refusee(tr!("pas livrée", "not shipped").into());
    }
    // Une compilation sans empreinte de fenêtre (`cargo build`, les essais) n'en lance jamais aucune.
    let Some(super::empreinte_fenetre::Gravee::Empreinte(attendue)) = super::empreinte_fenetre::de_ce_programme()
    else {
        return Lancement::Refusee(
            tr!(
                "ce programme a été compilé sans empreinte de fenêtre",
                "this program was built without a window fingerprint"
            )
            .into(),
        );
    };
    #[cfg(target_os = "linux")]
    let verifiee = verifier(chemin, &attendue, crate::socle::uid());
    #[cfg(windows)]
    let verifiee = verifier(chemin, &attendue);
    // `verifiee` vit jusqu'à la fin : ce qu'elle tient reste ouvert jusqu'à « ouverte » ou l'échec (Linux : fermé
    // avant, le numéro de son descripteur pourrait désigner un autre fichier ; Windows : le fichier tenu).
    let verifiee = match verifiee {
        Ok(v) => v,
        Err(r) => return Lancement::Refusee(r),
    };
    let mut c = commande(&verifiee);
    c.args(arguments(programme))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Son propre groupe de processus : la fermeture du terminal (SIGHUP au groupe de premier plan) ne la ferme pas,
    // ni un Ctrl+C tapé ensuite dans ce terminal.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut c, 0);
    let Ok(mut enfant) = c.spawn_suivi() else {
        return Lancement::PasOuverte;
    };
    let Some(sortie) = enfant.stdout.take() else {
        crate::commande::arreter(&mut enfant);
        return Lancement::PasOuverte;
    };
    let (envoi, reception) = mpsc::channel();
    let lecture = crate::socle::fil::lancer("fenetre-ouverte", move || {
        // Une seule ligne, bornée : rien d'autre n'est attendu sur cette sortie.
        let mut ligne = String::new();
        let lu = BufReader::new(std::io::Read::take(sortie, 256))
            .read_line(&mut ligne)
            .is_ok();
        let _ = envoi.send(lu && ligne.trim_end() == OUVERTE);
    });
    // Sans fil pour lire sa réponse, la fenêtre n'est pas attendue : arrêtée, comme si elle n'avait pas répondu.
    if lecture.is_err() {
        crate::commande::arreter(&mut enfant);
        return Lancement::PasOuverte;
    }
    if reception.recv_timeout(ATTENTE) == Ok(true) {
        return Lancement::Ouverte;
    }
    crate::commande::arreter(&mut enfant);
    Lancement::PasOuverte
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_fenetre_seulement_quand_tout_le_dit() {
        let devant = Contexte {
            terminal: true,
            graphique: true,
            a_distance: false,
            eleve: false,
        };
        assert!(choisir(devant));
        // Un script qui écrit les choix ou lit la sortie garde le menu.
        assert!(!choisir(Contexte {
            terminal: false,
            ..devant
        }));
        assert!(!choisir(Contexte {
            graphique: false,
            ..devant
        }));
        // SSH ou Bureau à distance : le menu, dans la session où l'on est.
        assert!(!choisir(Contexte {
            a_distance: true,
            ..devant
        }));
        // En administrateur : le menu, jamais une fenêtre avec tous les droits.
        assert!(!choisir(Contexte { eleve: true, ..devant }));
        assert!(!choisir(Contexte::default()));
    }

    /// LIV-1 : un faux `vanguard-fenetre` posé à côté, exécutable (755), qui dirait « ouverte », n'est jamais lancé
    /// tant que la fenêtre n'est pas livrée : ni par `ouvrir`, ni par `lancer` lui-même.
    #[cfg(unix)]
    #[test]
    fn une_fausse_fenetre_posee_a_cote_n_est_jamais_lancee() {
        use std::os::unix::fs::PermissionsExt;
        let dossier = crate::socle::dossier_local().join("essai-fausse-fenetre");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let temoin = dossier.join("lancee");
        let f = dossier.join("vanguard-fenetre");
        std::fs::write(&f, format!("#!/bin/sh\n: > '{}'\necho {OUVERTE}\n", temoin.display())).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        let devant = Contexte {
            terminal: true,
            graphique: true,
            a_distance: false,
            eleve: false,
        };
        assert!(
            !ouvrir_depuis(devant, &f, &dossier.join("vanguard")),
            "la fenêtre n'est pas livrée : le menu"
        );
        assert!(
            !matches!(lancer(&f, &dossier.join("vanguard")), Lancement::Ouverte),
            "jamais lancée, même appelée directement"
        );
        assert!(!temoin.exists(), "le faux voisin a tourné");
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// LIV-1 : seuls les octets dont l'empreinte est attendue sont lancés, depuis une copie scellée en mémoire ; la
    /// fenêtre remplacée sur le disque après la vérification ne tourne pas ; un lien, une fenêtre modifiable par
    /// d'autres ou d'une autre empreinte ne sont pas lancés. `echo` y joue la fenêtre (un vrai programme ELF : il dit
    /// ce qu'on lui donne).
    #[cfg(target_os = "linux")]
    #[test]
    fn seuls_les_octets_verifies_sont_lances() {
        use sha2::Digest;
        use std::io::Write;
        use std::os::unix::fs::{FileExt, PermissionsExt};
        let Ok(echo) = std::fs::read("/usr/bin/echo") else {
            return crate::essais::saute("pas de /usr/bin/echo");
        };
        let dossier = crate::socle::dossier_local().join("essai-fenetre-verifiee");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let poser = |nom: &str, octets: &[u8], mode: u32| {
            let f = dossier.join(nom);
            let _ = std::fs::remove_file(&f);
            std::fs::write(&f, octets).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
            f
        };
        let f = poser("vanguard-fenetre", &echo, 0o755);
        let bonne: [u8; 32] = sha2::Sha256::digest(&echo).into();
        let moi = crate::socle::uid();
        let mut autre = bonne;
        autre[0] ^= 1;
        assert!(verifier(&f, &autre, moi).is_err(), "une autre empreinte : refusée");
        let v = verifier(&f, &bonne, moi).unwrap();
        // Remplacée sur le disque après la vérification : c'est quand même la fenêtre vérifiée qui tourne.
        let temoin = dossier.join("lancee");
        let faux = format!("#!/bin/sh\n: > '{}'\necho {OUVERTE}\n", temoin.display());
        poser("vanguard-fenetre", faux.as_bytes(), 0o755);
        let sortie = commande(&v).arg("vérifiée").stderr(Stdio::null()).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&sortie.stdout).trim_end(), "vérifiée");
        assert!(!temoin.exists(), "le fichier posé après la vérification a tourné");
        // Scellée : ni réécrite en place (au début : écrire à la fin l'allongerait, refusé pour une autre raison), ni
        // raccourcie, ni allongée, et les sceaux ne se retirent plus.
        assert!(v.0.write_at(b"x", 0).is_err(), "réécrite en place");
        assert!((&v.0).write_all(b"x").is_err());
        assert!(v.0.set_len(0).is_err());
        assert!(v.0.set_len(1 << 20).is_err());
        let tous = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        assert_eq!(super::super::memfd::sceaux(&v.0).unwrap() & tous, tous);
        // Un lien vers la vraie fenêtre : pas suivi. Modifiable par d'autres : refusée.
        let vraie = poser("vraie", &echo, 0o755);
        let lien = dossier.join("lien");
        std::os::unix::fs::symlink(&vraie, &lien).unwrap();
        assert!(verifier(&lien, &bonne, moi).is_err(), "un lien est suivi");
        assert!(verifier(&vraie, &bonne, moi).is_ok());
        std::fs::set_permissions(&vraie, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert!(verifier(&vraie, &bonne, moi).is_err(), "modifiable par d'autres");
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Windows : la fenêtre d'une autre empreinte n'est pas lancée ; vérifiée, elle est tenue (ni réécrite, ni
    /// effacée, ni renommée) jusqu'à la fin du lancement, et c'est elle que la commande lance.
    #[cfg(windows)]
    #[test]
    fn windows_la_fenetre_verifiee_est_tenue_jusqu_au_lancement() {
        use sha2::Digest;
        let dossier = crate::socle::dossier_local().join("essai-fenetre-verifiee");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let f = dossier.join("vanguard-fenetre.exe");
        let octets = b"MZ une fausse fenetre ".repeat(100);
        std::fs::write(&f, &octets).unwrap();
        let bonne: [u8; 32] = sha2::Sha256::digest(&octets).into();
        let mut autre = bonne;
        autre[0] ^= 1;
        assert!(verifier(&f, &autre).is_err(), "une autre empreinte : refusée");
        let v = verifier(&f, &bonne).unwrap();
        assert!(std::fs::OpenOptions::new().write(true).open(&f).is_err(), "réécrite");
        assert!(std::fs::remove_file(&f).is_err(), "effacée");
        assert!(std::fs::rename(&f, dossier.join("autre.exe")).is_err(), "renommée");
        assert_eq!(commande(&v).get_program(), f.as_os_str());
        drop(v);
        // Relâchée après le lancement : le fichier redevient libre.
        assert!(std::fs::rename(&f, dossier.join("autre.exe")).is_ok());
        assert!(verifier(&dossier, &bonne).is_err(), "un dossier");
        // Tenue, elle se lance quand même (Windows ouvre l'image en lecture, permise par ce partage) : un vrai
        // programme, `cmd.exe` copié, joue la fenêtre.
        let systeme = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_default();
        let Ok(cmd) = std::fs::read(systeme.join("System32").join("cmd.exe")) else {
            let _ = std::fs::remove_dir_all(&dossier);
            return crate::essais::saute("pas de cmd.exe");
        };
        let copie = dossier.join("fenetre-cmd.exe");
        std::fs::write(&copie, &cmd).unwrap();
        let v = verifier(&copie, &sha2::Sha256::digest(&cmd).into()).unwrap();
        let sortie = commande(&v).args(["/c", "echo", "verifiee"]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&sortie.stdout).trim_end(), "verifiee");
        drop(v);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    #[test]
    fn la_fenetre_est_cherchee_a_cote_du_programme() {
        let p = Path::new("/opt/vanguard/vanguard");
        let v = voisine(p).unwrap();
        assert_eq!(v.parent(), Some(Path::new("/opt/vanguard")));
        assert!(
            v.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("vanguard-fenetre"))
        );
        // Le nom de la page de la version, s'il est seul ; `vanguard-fenetre` d'abord.
        let dossier = crate::socle::dossier_local().join("essai-voisine");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let programme = dossier.join("vanguard");
        let premiere = dossier.join(format!("vanguard-fenetre{}", std::env::consts::EXE_SUFFIX));
        assert_eq!(voisine(&programme), Some(premiere.clone()), "aucune : la première");
        std::fs::write(dossier.join(NOM_PAGE), b"").unwrap();
        assert_eq!(voisine(&programme), Some(dossier.join(NOM_PAGE)));
        std::fs::write(&premiere, b"").unwrap();
        assert_eq!(voisine(&programme), Some(premiere));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// La fenêtre reçoit le programme d'origine à lancer, tel quel (même téléchargé sous le nom de la page).
    #[test]
    fn la_fenetre_recoit_le_programme_a_lancer() {
        let a = arguments(Path::new("/opt/v/vanguard-linux-x86_64"));
        let i = a.iter().position(|x| x == "--vanguard").expect("--vanguard");
        assert_eq!(
            a.get(i + 1).map(PathBuf::from),
            Some(PathBuf::from("/opt/v/vanguard-linux-x86_64"))
        );
        assert!(a.iter().any(|x| x == "--depuis-vanguard"));
        assert!(a.iter().any(|x| x == "--langue"));
    }

    /// Une fenêtre que d'autres comptes pourraient remplacer n'est pas lancée ; un lien non plus.
    #[cfg(unix)]
    #[test]
    fn une_fenetre_modifiable_par_d_autres_est_refusee() {
        use std::os::unix::fs::PermissionsExt;
        let dossier = crate::socle::dossier_local().join("essai-lancer-fenetre");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let f = dossier.join("vanguard-fenetre");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        let moi = crate::socle::uid();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(refus(&std::fs::symlink_metadata(&f).unwrap(), moi), None);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(refus(&std::fs::symlink_metadata(&f).unwrap(), moi).is_some());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert!(refus(&std::fs::symlink_metadata(&f).unwrap(), moi).is_some());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Un autre propriétaire (ni ce compte ni root).
        if moi != 0 {
            assert!(refus(&std::fs::symlink_metadata(&f).unwrap(), moi.wrapping_add(1)).is_some());
        }
        let lien = dossier.join("lien");
        std::os::unix::fs::symlink(&f, &lien).unwrap();
        assert!(refus(&std::fs::symlink_metadata(&lien).unwrap(), moi).is_some());
        std::fs::remove_file(&lien).unwrap();
        // Sous `unshare -r` (les tests sans Internet), les dossiers de root y paraissent à « nobody » : la chaîne y est
        // refusée, à raison, et l'essai des dossiers ne peut pas y tourner.
        if dossier
            .ancestors()
            .skip(1)
            .filter(|d| !d.as_os_str().is_empty())
            .any(|d| {
                std::fs::symlink_metadata(d)
                    .ok()
                    .is_none_or(|m| refus_dossier(&m, moi).is_some())
            })
        {
            let _ = std::fs::remove_dir_all(&dossier);
            return crate::essais::saute("un dossier au-dessus du dossier jetable n'est ni à ce compte ni à root");
        }
        // Le dossier : modifiable par d'autres, refusé ; collant (sticky, comme /tmp), permis.
        let meta = std::fs::symlink_metadata(&f).unwrap();
        assert_eq!(refus_chemin(&f, &meta, moi), None);
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(refus_chemin(&f, &meta, moi).is_some());
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(refus_chemin(&f, &meta, moi), None);
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&dossier);
    }
}
