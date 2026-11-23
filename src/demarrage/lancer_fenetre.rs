//! `vanguard` sans argument : la fenêtre de Vanguard (`vanguard-fenetre`, posée à côté du programme) quand la
//! personne est devant un écran graphique, sinon le menu du terminal, comme avant. Seulement la fenêtre dont ce
//! programme porte l'empreinte gravée (`fenetre_livree`, `empreinte_fenetre`) ; sous Linux, ce sont les octets vérifiés
//! qui sont lancés, pas le chemin ; sous Windows, le chemin, le fichier et ses dossiers tenus ; un programme compilé sans empreinte (`cargo build`, les essais) n'en lance aucune, comme la
//! 0.95 (LIV-1). La fenêtre ne fait rien d'elle-même :
//! elle relance ce programme-ci avec des commandes en lecture, et quatre gestes qui changent, chacun montré puis
//! accepté : un programme retiré du démarrage ou remis, une correction du compte appliquée, remise comme avant, et la
//! mise à jour de Vanguard (voir `fenetre/` et MODELE-DE-MENACE.md, « La fenêtre »).
//!
//! Le menu reste le choix sûr : sans terminal des deux côtés (un script qui écrit les choix, une sortie redirigée),
//! en SSH ou au Bureau à distance, en administrateur, sans écran graphique, sans fenêtre posée à côté, avec une fenêtre que d'autres
//! comptes pourraient remplacer, ou si elle ne dit pas « ouverte » à temps. `vanguard --menu` le force. Sans fenêtre
//! posée à côté, quand rien d'autre ne garde le menu, il le dit et propose de l'ajouter (`absente`, C-6, 0.97).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::coulisses::Suivie;
use crate::modele::{Echec, Raison};
use crate::{tr, trf};

/// La ligne que la fenêtre écrit sur sa sortie quand elle s'est ouverte (fenetre/src/dessin/mod.rs).
const OUVERTE: &str = "vanguard-fenetre:ouverte";

/// La fenêtre est livrée avec ce programme : il porte gravée l'empreinte de sa fenêtre (`outils/compiler-version.sh`).
/// Sinon `vanguard` ne lance aucun `vanguard-fenetre`, même posé à côté, et l'aide ne la promet pas. En 0.94, la
/// confiance allait au nom et à l'emplacement du fichier, pas à son contenu : n'importe quel programme de ce nom,
/// exécutable, était lancé et pouvait dire « ouverte » à sa place (LIV-1) ; la 0.95 ne la lançait plus du tout.
pub(crate) fn fenetre_livree() -> bool {
    livree_selon(super::empreinte_fenetre::de_ce_programme())
}

/// `fenetre_livree`, pour une marque donnée : seule une empreinte livre la fenêtre ; « aucune » ou pas de marque lisible,
/// non.
fn livree_selon(g: Option<super::empreinte_fenetre::Gravee>) -> bool {
    matches!(g, Some(super::empreinte_fenetre::Gravee::Empreinte(_)))
}

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
    /// L'alerte « bibliothèque injectée » est levée (`protection::environnement`) : elle irait aussi dans la fenêtre.
    pub(crate) injection: bool,
}

/// La fenêtre ou le menu ? La fenêtre seulement quand tout le dit ; dans le doute, le menu.
pub(crate) fn choisir(c: Contexte) -> bool {
    c.terminal && c.graphique && !c.a_distance && !c.eleve
}

/// Ce qui, dans le contexte, garde le menu et se dit (contrairement à `choisir`, qui se tait) : une bibliothèque
/// injectée dans les programmes de la session (/etc/ld.so.preload, LD_PRELOAD inconnu, AppInit_DLLs) que
/// `protection::environnement` signale en alerte. `vanguard` est statique sous Linux ; la fenêtre, elle, charge les
/// bibliothèques du système (OpenGL, Wayland, X11) : /etc/ld.so.preload y entrerait, liste fermée de variables ou
/// pas, et AppInit_DLLs entre dans tout programme Windows à fenêtres. Une bibliothèque que l'alerte juge du système
/// (une simple information) ne l'empêche pas.
fn refus_du_contexte(c: Contexte) -> Option<&'static str> {
    c.injection.then(|| {
        tr!(
            "une bibliothèque injectée dans les programmes de la session y entrerait aussi, voir l'alerte plus haut",
            "a library injected into the session's programs would get into it too, see the alert above"
        )
    })
}

fn contexte() -> Contexte {
    use std::io::IsTerminal;
    let present = |v: &str| std::env::var_os(v).is_some_and(|x| !x.is_empty());
    Contexte {
        terminal: std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        graphique: cfg!(windows) || present("WAYLAND_DISPLAY") || present("DISPLAY"),
        a_distance: a_distance(&present),
        eleve: super::droits::processus_eleve(),
        injection: crate::protection::environnement::injection_alertee(),
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
pub(crate) const NOM_PAGE: &str = "vanguard-fenetre-windows-x86_64.exe";
#[cfg(not(windows))]
pub(crate) const NOM_PAGE: &str = "vanguard-fenetre-linux-x86_64";

/// Le chemin de la fenêtre à côté de ce programme (jamais cherchée dans le PATH) : `vanguard-fenetre`, sinon le nom
/// de la page de la version. Deux noms n'ouvrent rien de plus : la confiance va à l'empreinte, pas au nom. Aucune des
/// deux : la première, que `ouvrir_depuis` dira absente.
pub(crate) fn voisine(programme: &Path) -> Option<PathBuf> {
    let dossier = programme.parent()?;
    let premiere = dossier.join(format!("vanguard-fenetre{}", std::env::consts::EXE_SUFFIX));
    let page = dossier.join(NOM_PAGE);
    if std::fs::symlink_metadata(&premiere).is_err() && std::fs::symlink_metadata(&page).is_ok() {
        return Some(page);
    }
    Some(premiere)
}

/// Ce que reçoit la fenêtre : dire « ouverte » à ce programme, sa langue, le programme qu'elle lancera, celui
/// d'origine (`programme`) : lancée d'une copie en mémoire, elle n'a plus de dossier où le trouver ; et l'empreinte
/// SHA-256 de ce programme-ci (`soi`, en hexadécimal) : elle ne lancera ce chemin que si ses octets l'ont encore (L2 de
/// la relecture 0.96 : la fenêtre vit des heures, et le fichier au bout du chemin peut avoir changé).
fn arguments(programme: &Path, soi: &[u8; 32]) -> Vec<std::ffi::OsString> {
    use std::fmt::Write;
    let langue = if crate::langue::anglais() { "en" } else { "fr" };
    let mut a: Vec<std::ffi::OsString> = ["--depuis-vanguard", "--langue", langue, "--vanguard"]
        .map(Into::into)
        .into();
    a.push(programme.into());
    let hex = soi.iter().fold(String::with_capacity(64), |mut h, o| {
        let _ = write!(h, "{o:02x}");
        h
    });
    a.extend(["--empreinte-vanguard".into(), hex.into()]);
    a
}

/// L'empreinte SHA-256 de ce programme, lue par son image : sous Linux `/proc/self/exe`, l'image qui tourne, même
/// effacée ou remplacée depuis le lancement ; sous Windows, son fichier, ouvert sans partage d'écriture (dans une copie
/// temporaire, tenu depuis le départ par `cle::soi_au_depart` ; hors d'une copie, le fichier qui se trouve à ce chemin
/// maintenant, la limite dite là). Celle que la fenêtre exigera de chaque `vanguard` qu'elle relance.
fn empreinte_de_soi() -> std::io::Result<[u8; 32]> {
    use sha2::Digest;
    use std::io::Read;
    #[cfg(target_os = "linux")]
    let mut f = std::fs::File::open("/proc/self/exe")?;
    #[cfg(windows)]
    let mut f = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x1;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(std::env::current_exe()?)?
    };
    let mut h = sha2::Sha256::new();
    let mut tampon = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut tampon)?;
        let Some(lus) = tampon.get(..n).filter(|l| !l.is_empty()) else {
            break;
        };
        h.update(lus);
    }
    Ok(h.finalize().into())
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
    refus(m, moi).or_else(|| refus_des_dossiers(chemin, moi))
}

/// Les dossiers qui contiennent `chemin`, jusqu'à la racine (`refus_dossier`), sans suivre aucun lien.
#[cfg(unix)]
fn refus_des_dossiers(chemin: &Path, moi: u32) -> Option<&'static str> {
    chemin
        .ancestors()
        .skip(1)
        .filter(|d| !d.as_os_str().is_empty())
        .take_while(|d| dans_les_essais(d))
        .find_map(|d| match std::fs::symlink_metadata(d) {
            Ok(m) => refus_dossier(&m, moi),
            Err(_) => Some(tr!("un dossier illisible", "an unreadable folder")),
        })
}

/// Hors essais, tous les dossiers comptent. Dans les essais de la mise à jour, seulement ceux du dossier
/// temporaire des essais (lui compris) : sous `unshare -r` (la suite hors ligne), /home et la racine paraissent à
/// « nobody » et tout serait refusé ; l'essai du lancement, lui, se saute dans ce cas.
#[cfg(all(unix, not(test)))]
fn dans_les_essais(_: &Path) -> bool {
    true
}

#[cfg(all(unix, test))]
fn dans_les_essais(d: &Path) -> bool {
    // Le chemin tel quel et résolu : les essais du lancement passent l'un, `dossiers_refuses` l'autre.
    static RACINES: std::sync::OnceLock<[PathBuf; 2]> = std::sync::OnceLock::new();
    RACINES
        .get_or_init(|| {
            let t = crate::essais::temporaire();
            [std::fs::canonicalize(&t).unwrap_or_else(|_| t.clone()), t]
        })
        .iter()
        .any(|r| d.starts_with(r))
}

/// Le refus que le lancement opposerait aux dossiers de la fenêtre `chemin` (A-ACCORD-2, relecture C-6/C-7) : le
/// lancement juge le chemin résolu (`current_exe`), donc le dossier est résolu ici aussi. Un refus d'un dossier ne
/// se répare pas en reposant la fenêtre : la mise à jour le dit, sans le proposer. Sous Windows, aucun.
pub(crate) fn dossiers_refuses(chemin: &Path) -> Option<&'static str> {
    #[cfg(unix)]
    {
        let (Some(dossier), Some(nom)) = (chemin.parent(), chemin.file_name()) else {
            return Some(tr!("un dossier illisible", "an unreadable folder"));
        };
        let Ok(dossier) = std::fs::canonicalize(if dossier.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dossier
        }) else {
            return Some(tr!("un dossier illisible", "an unreadable folder"));
        };
        refus_des_dossiers(&dossier.join(nom), crate::socle::uid())
    }
    #[cfg(windows)]
    {
        let _ = chemin;
        None
    }
}

#[cfg(windows)]
fn refus(m: &std::fs::Metadata) -> Option<&'static str> {
    (!m.file_type().is_file()).then(|| tr!("pas un fichier ordinaire", "not a regular file"))
}

/// Le refus que le lancement opposerait à la fenêtre décrite par `m` (sans suivre de lien), pour ce compte : la
/// mise à jour juge « juste » comme lui (relecture C-6/C-7), jamais une fenêtre qu'il refuserait.
pub(crate) fn refusee(m: &std::fs::Metadata) -> Option<&'static str> {
    #[cfg(unix)]
    return refus(m, crate::socle::uid());
    #[cfg(windows)]
    return refus(m);
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

/// La fenêtre que le lancement a cherchée et pas trouvée, alors que tout le reste la voulait (C-6, 0.97) : le
/// programme d'origine et le chemin cherché. Le menu le dit et propose de l'ajouter par la mise à jour
/// (`mise_a_jour::fenetre_absente`), qui seule la télécharge, la vérifie et la pose.
static ABSENTE: std::sync::OnceLock<(PathBuf, PathBuf)> = std::sync::OnceLock::new();

/// La fenêtre trouvée absente au lancement (programme, chemin de la fenêtre), si elle l'est encore : posée depuis (la
/// mise à jour vient de l'ajouter), le menu n'en dit plus rien.
pub(crate) fn absente() -> Option<(&'static Path, &'static Path)> {
    ABSENTE
        .get()
        .filter(|(_, f)| std::fs::symlink_metadata(f).is_err())
        .map(|(p, f)| (p.as_path(), f.as_path()))
}

/// Ce que décide le lancement avant de lancer quoi que ce soit.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Le menu, sans rien proposer : une garde tient (pas de terminal, pas d'écran, à distance, administrateur,
    /// bibliothèque injectée, fenêtre non livrée), ou ce qui la refuse est déjà dit.
    Menu,
    /// Tout voulait la fenêtre, mais aucun fichier n'est posé à côté : le menu, qui le dit et propose de l'ajouter.
    Absente,
    /// Un fichier est là : à juger puis lancer.
    Lancer,
}

/// La décision pour un contexte, une fenêtre livrée ou non (`livree`, son empreinte gravée) et un chemin donnés.
/// Une garde du contexte passe toujours avant l'absence : en SSH, en administrateur ou sans écran, rien n'est proposé.
fn decider(c: Contexte, livree: bool, chemin: &Path) -> Decision {
    if !choisir(c) {
        return Decision::Menu;
    }
    if !livree {
        // Quelqu'un attendait la fenêtre (un fichier à son nom est posé à côté) : le dire, sans rien lancer.
        if std::fs::symlink_metadata(chemin).is_ok() {
            eprintln!(
                "{}",
                tr!(
                    "Ce programme a été compilé sans empreinte de fenêtre : le fichier « vanguard-fenetre » posé à côté n'est pas lancé. Le menu du terminal.",
                    "This program was built without a window fingerprint: the \"vanguard-fenetre\" file next to it is not started. The terminal menu."
                )
            );
        }
        return Decision::Menu;
    }
    // symlink_metadata : un lien n'est pas suivi, il est refusé plus loin (pas un fichier ordinaire).
    if std::fs::symlink_metadata(chemin).is_err() {
        // Une bibliothèque injectée refuserait aussi la fenêtre une fois posée : rien à proposer, l'alerte le dit.
        return if refus_du_contexte(c).is_some() {
            Decision::Menu
        } else {
            Decision::Absente
        };
    }
    Decision::Lancer
}

/// `ouvrir`, pour un contexte, un chemin de fenêtre et un programme d'origine donnés (les essais).
fn ouvrir_depuis(c: Contexte, chemin: &Path, programme: &Path) -> bool {
    match decider(c, fenetre_livree(), chemin) {
        Decision::Menu => return false,
        Decision::Absente => {
            let _ = ABSENTE.set((programme.to_path_buf(), chemin.to_path_buf()));
            return false;
        }
        Decision::Lancer => {}
    }
    let chemin = chemin.to_path_buf();
    // Disparue depuis la décision : le menu, comme si elle n'avait jamais été là.
    let Ok(m) = std::fs::symlink_metadata(&chemin) else {
        return false;
    };
    #[cfg(unix)]
    let raison = refus_chemin(&chemin, &m, crate::socle::uid());
    #[cfg(windows)]
    let raison = refus(&m);
    if let Some(r) = raison.or_else(|| refus_du_contexte(c)) {
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
        Lancement::Ramenee(confirmee) => {
            let texte = if confirmee {
                tr!(
                    "La fenêtre de Vanguard est déjà ouverte : elle revient devant.",
                    "The Vanguard window is already open: it comes back to the front."
                )
            } else {
                tr!(
                    "La fenêtre de Vanguard est déjà ouverte : il lui a été demandé de revenir devant.",
                    "The Vanguard window is already open: it was asked to come back to the front."
                )
            };
            eprintln!("{texte}");
            return true;
        }
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
    /// Déjà ouverte (vérifiée : la fenêtre de Vanguard de ce compte et de cette session) : rien de lancé. Vrai : le
    /// bureau a confirmé la ramener ; faux : elle a été priée de revenir devant.
    Ramenee(bool),
    /// Pas lancée : la raison.
    Refusee(String),
    /// Lancée, mais elle n'a pas dit « ouverte » à temps (arrêtée).
    PasOuverte,
}

/// Le plus gros fichier de fenêtre lu (la fenêtre compilée fait une dizaine de Mio). Dans les essais seulement, 1 Gio :
/// ils lancent comme fenêtre leur propre programme d'essai, qui dépasse 128 Mio ; le programme publié garde 128 Mio.
pub(crate) const TAILLE_MAX: u64 = if cfg!(test) { 1 << 30 } else { 128 * 1024 * 1024 };

/// Les octets de la fenêtre ouverte, `TAILLE_MAX` au plus (`m` : ce que dit la poignée).
fn lire_borne(f: &std::fs::File, m: &std::fs::Metadata) -> Result<Vec<u8>, Echec> {
    use std::io::Read;
    let trop = || Echec::refuse("fenetre/verifier", tr!("fichier trop gros", "file too large"));
    if m.len() > TAILLE_MAX {
        return Err(trop());
    }
    let mut octets = Vec::new();
    f.take(TAILLE_MAX.saturating_add(1))
        .read_to_end(&mut octets)
        .map_err(|e| illisible(&e))?;
    if u64::try_from(octets.len()).map_or(true, |n| n > TAILLE_MAX) {
        return Err(trop());
    }
    Ok(octets)
}

/// « illisible : … » (« unreadable: … ») : la lecture de la fenêtre a échoué, avec ce qu'en dit le système.
fn illisible(e: &std::io::Error) -> Echec {
    Echec::new("fenetre/verifier", Raison::Illisible(e.to_string()))
}

/// L'empreinte lue est-elle celle attendue ? Sinon la raison : une fenêtre qui n'est pas la gravée, jamais crue
/// (la phrase seule est rendue, `Raison::Falsifie` avec son détail).
fn comparer(lue: &[u8; 32], attendue: &[u8; 32]) -> Result<(), Echec> {
    if lue == attendue {
        return Ok(());
    }
    Err(Echec::new("fenetre/verifier", Raison::Falsifie).detail(tr!(
        "son empreinte n'est pas celle de la fenêtre de cette version",
        "its fingerprint is not that of this version's window"
    )))
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
fn verifier(chemin: &Path, attendue: &[u8; 32], moi: u32) -> Result<Verifiee, Echec> {
    use sha2::Digest;
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(chemin)
        .map_err(|e| illisible(&e))?;
    let m = f.metadata().map_err(|e| illisible(&e))?;
    if let Some(r) = refus(&m, moi) {
        return Err(Echec::refuse("fenetre/verifier", r));
    }
    let octets = lire_borne(&f, &m)?;
    let copie = super::memfd::scelle("vanguard-fenetre", &octets).map_err(|e| {
        Echec::echoue(
            "fenetre/verifier",
            trf!("copie scellée impossible : {}", "sealed copy impossible: {}", e),
        )
    })?;
    drop(octets);
    // L'empreinte de la copie scellée, relue du début : exactement ce que le noyau lancera.
    let mut h = sha2::Sha256::new();
    let mut tampon = vec![0u8; 1 << 16];
    let mut position = 0u64;
    loop {
        let n = copie.read_at(&mut tampon, position).map_err(|e| {
            Echec::echoue(
                "fenetre/verifier",
                trf!("copie illisible : {}", "copy unreadable: {}", e),
            )
        })?;
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
fn commande(v: &Verifiee, de: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>) -> Command {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let mut c = Command::new(format!("/proc/self/fd/{}", v.0.as_raw_fd()));
    c.arg0("vanguard-fenetre");
    environnement_fenetre(&mut c, de);
    c
}

/// Les variables que la fenêtre reçoit (L1, relecture 0.96) : ce qu'il lui faut pour s'afficher (l'écran Wayland ou
/// X11, XDG_RUNTIME_DIR, le curseur, la composition des touches), sa langue (LANG, LANGUAGE, LC_*), ses dossiers
/// (HOME, XDG_*), et ce que le `vanguard` qu'elle relance lit pour reconnaître le bureau et la session (bus D-Bus,
/// XDG_CURRENT_DESKTOP, HYPRLAND_INSTANCE_SIGNATURE…) et pour télécharger derrière un proxy. Plus les réglages de
/// Vanguard lui-même (`VANGUARD_*`, et leur ancien nom `GARDIEN_*` : VANGUARD_HORS_LIGNE, VANGUARD_ENVOI=0, la clé
/// HIBP…), sauf VANGUARD_ORIGINE (L2 : le `vanguard` à lancer vient de --vanguard, jamais de l'environnement).
///
/// Rien d'autre : ni LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH (une bibliothèque du compte dans la fenêtre vérifiée, qui
/// est dynamique), ni GTK_MODULES, GTK_IM_MODULE, LIBGL_*, __EGL_*, __GLX_* (des modules chargés par les
/// bibliothèques d'affichage), ni WAYLAND_SOCKET (un descripteur à usage unique, celui du terminal), ni BASH_ENV, ni
/// le PATH du compte : `PATH_PROPRE`, que le `vanguard` relancé reçoit à son tour (sudo et pkexec, il les prend de
/// toute façon dans les dossiers du système, `commande::outil_systeme`).
#[cfg(target_os = "linux")]
const GARDEES_FENETRE: [&str; 33] = [
    "LANG",
    "LANGUAGE",
    "HOME",
    "USER",
    "LOGNAME",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_SESSION_DESKTOP",
    "XDG_CURRENT_DESKTOP",
    "DESKTOP_SESSION",
    "HYPRLAND_INSTANCE_SIGNATURE",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_DIRS",
    "XCURSOR_THEME",
    "XCURSOR_SIZE",
    "XCURSOR_PATH",
    "XCOMPOSEFILE",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "ftp_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "FTP_PROXY",
];

/// Une variable passe-t-elle à la fenêtre (`GARDEES_FENETRE`, les LC_* de la langue, les réglages de Vanguard) ?
#[cfg(target_os = "linux")]
fn gardee_fenetre(nom: &std::ffi::OsStr) -> bool {
    let Some(n) = nom.to_str() else {
        return false;
    };
    let reglage = ["VANGUARD_", "GARDIEN_"]
        .iter()
        .any(|p| n.strip_prefix(p).is_some_and(|r| !r.is_empty() && r != "ORIGINE"));
    GARDEES_FENETRE.contains(&n) || n.strip_prefix("LC_").is_some_and(|r| !r.is_empty()) || reglage
}

/// L'environnement de la fenêtre : `de` (celui de Vanguard, en pratique) vidé, sauf `GARDEES_FENETRE`, et
/// `PATH_PROPRE`. C'était le trou L1 : la fenêtre vérifiée héritait de tout, et une bibliothèque nommée par
/// LD_PRELOAD tournait dans ses octets vérifiés dès le démarrage, avant la première ligne de Vanguard.
#[cfg(target_os = "linux")]
fn environnement_fenetre(c: &mut Command, de: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>) {
    c.env_clear();
    for (nom, valeur) in de {
        if gardee_fenetre(&nom) {
            c.env(nom, valeur);
        }
    }
    c.env("PATH", crate::commande::PATH_PROPRE);
}

/// Windows : la fenêtre vérifiée, **tenue** ouverte avec le partage en lecture seule (ni écriture, ni effacement, ni
/// renommage par personne tant que la poignée vit ; une écriture déjà ouverte fait échouer l'ouverture), chacun des
/// dossiers de son chemin tenu aussi, sans partage d'effacement (ni renommés ni effacés : W2), et son chemin. La
/// poignée garantit les octets du fichier, pas le chemin jusqu'à lui : Windows lance par le chemin, qu'il relit. Les
/// dossiers tenus et refusés s'ils sont des liens ou des jonctions ferment ce qui se fait par les dossiers ; ce qui
/// change le sens d'un nom sans toucher aux dossiers (une lettre de lecteur redéfinie pour la session, `subst`,
/// DefineDosDevice) reste ouvert (W1 : le lancement suspendu, puis l'image vérifiée, au lot suivant, essayé dans la
/// machine virtuelle). Une fois lancé, Windows refuse d'écrire l'image d'un programme qui tourne.
#[cfg(windows)]
struct Verifiee {
    _tenue: std::fs::File,
    _dossiers: Vec<std::fs::File>,
    chemin: PathBuf,
}

/// La fenêtre de `chemin`, si elle passe : ouverte tenue, sans suivre de lien (`FILE_FLAG_OPEN_REPARSE_POINT` : un
/// lien ou une jonction est ouvert lui-même, puis refusé), fichier ordinaire, lue entière sur cette poignée, son
/// empreinte comparée. Sinon la raison. Les droits (ACL) du fichier et de ses dossiers ne sont pas lus (limite dite
/// au modèle de menace).
#[cfg(windows)]
fn verifier(chemin: &Path, attendue: &[u8; 32]) -> Result<Verifiee, Echec> {
    use sha2::Digest;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    // Les dossiers d'abord : le nom vérifié et le nom lancé mènent alors au même fichier.
    let dossiers = dossiers_tenus(chemin)?;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(chemin)
        .map_err(|e| illisible(&e))?;
    let m = f.metadata().map_err(|e| illisible(&e))?;
    if let Some(r) = refus(&m) {
        return Err(Echec::refuse("fenetre/verifier", r));
    }
    if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Echec::refuse("fenetre/verifier", tr!("un lien", "a link")));
    }
    let octets = lire_borne(&f, &m)?;
    comparer(&sha2::Sha256::digest(&octets).into(), attendue)?;
    Ok(Verifiee {
        _tenue: f,
        _dossiers: dossiers,
        chemin: chemin.to_path_buf(),
    })
}

/// Chacun des dossiers de `chemin`, de la racine jusqu'au sien, ouvert tenu (W1, W2) : sans partage d'effacement,
/// personne ne le renomme ni ne l'efface tant que la poignée vit, et le nom suivant, dans un dossier tenu, mène
/// toujours au même dossier. Un lien, une jonction ou un dossier monté (`FILE_FLAG_OPEN_REPARSE_POINT` : ouvert
/// lui-même) est tenu en plus sans partage d'écriture : il ne peut plus être re-pointé ni défait. Un dossier ordinaire
/// ne devient pas une jonction tant qu'il n'est pas vide, et chacun contient le suivant, tenu. Ce qui n'est pas tenu :
/// les dossiers de l'autre côté d'une jonction (sa cible), et le sens d'une lettre de lecteur. Un dossier qui ne
/// s'ouvre pas : refusé (dans le doute, le menu).
#[cfg(windows)]
fn dossiers_tenus(chemin: &Path) -> Result<Vec<std::fs::File>, Echec> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    // Lister le dossier, pas seulement lire ses attributs : une poignée sans accès aux données ne compte pas dans le
    // partage (Windows ne le vérifie ni ne l'enregistre), elle n'empêcherait rien.
    const FILE_LIST_DIRECTORY: u32 = 0x1;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let illisible = |e: std::io::Error| {
        Echec::echoue(
            "fenetre/verifier",
            trf!(
                "un dossier du chemin illisible : {}",
                "an unreadable folder in the path: {}",
                e
            ),
        )
    };
    let ouvrir = |d: &Path, partage: u32| {
        std::fs::OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES)
            .share_mode(partage)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(d)
            .map_err(illisible)
    };
    let dossiers: Vec<&Path> = chemin
        .ancestors()
        .skip(1)
        .filter(|d| !d.as_os_str().is_empty())
        .collect();
    let mut tenus = Vec::new();
    for d in dossiers.into_iter().rev() {
        let f = ouvrir(d, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
        let attributs = f.metadata().map_err(illisible)?.file_attributes();
        if attributs & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(Echec::refuse(
                "fenetre/verifier",
                tr!(
                    "un élément du chemin n'est pas un dossier",
                    "a path element is not a folder"
                ),
            ));
        }
        if attributs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            // Tenu par la première poignée pendant que la seconde s'ouvre : c'est le même lien.
            tenus.push(ouvrir(d, FILE_SHARE_READ)?);
        }
        tenus.push(f);
    }
    Ok(tenus)
}

/// La commande qui lance la fenêtre tenue, par son chemin (que Windows relit : voir `Verifiee`).
#[cfg(windows)]
fn commande(v: &Verifiee) -> Command {
    Command::new(&v.chemin)
}

/// Lance la fenêtre et attend qu'elle dise « ouverte ». Elle n'est pas attendue au-delà : ce programme s'arrête et
/// la fenêtre continue seule. Sa sortie d'erreur est jetée (un pilote graphique bavard ne salit pas le terminal).
/// Pas par `commande::lancer`, qui attend la fin du programme : la fenêtre vit après nous ; lancée par les coulisses
/// quand même (`spawn_suivi`), elle s'y voit.
fn lancer(chemin: &Path, programme: &Path) -> Lancement {
    // Seconde garde, au seul endroit qui construit la commande : une compilation sans empreinte de fenêtre
    // (`cargo build`, les essais) n'en lance jamais aucune.
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
    // Une seule fenêtre : celle qui est déjà ouverte, si c'est bien elle, revient devant ; sinon la fenêtre est
    // lancée sous le verrou du tour (voir `une_seule`).
    une_seule(
        || super::une_fenetre::ramener(&attendue, chemin),
        |remplacer| lancer_la_fenetre(chemin, programme, &attendue, remplacer),
    )
}

/// Une seule fenêtre autour d'un lancement : `ramener` d'abord. La fenêtre ramenée, rien n'est ouvert. Sinon
/// `ouvrir` est appelé, le verrou du tour tenu jusqu'à son retour (un second lancement simultané attend que celle-ci
/// ait dit « ouverte », puis la ramène), avec `remplacer` vrai quand ce qui écoute n'est pas une fenêtre de Vanguard
/// qui répond (la nouvelle prend sa prise). Un canal refusé ou impossible, un verrou qui ne se prend pas : dits.
fn une_seule(ramener: impl FnOnce() -> super::une_fenetre::Tour, ouvrir: impl FnOnce(bool) -> Lancement) -> Lancement {
    use super::une_fenetre::Issue;
    let tour = ramener();
    let remplacer = match &tour.issue {
        Issue::Ramenee(confirmee) => return Lancement::Ramenee(*confirmee),
        Issue::Personne => false,
        Issue::Refusee(r) => {
            eprintln!(
                "{}",
                trf!(
                    "Fenêtre déjà ouverte non ramenée ({}) : rien ne lui est demandé, une nouvelle s'ouvre.",
                    "Already open window not brought back ({}): nothing is asked of it, a new one opens.",
                    r
                )
            );
            true
        }
        Issue::Indisponible(r) => {
            eprintln!(
                "{}",
                trf!(
                    "Une seule fenêtre impossible ici ({}) : une nouvelle s'ouvre.",
                    "Single window impossible here ({}): a new one opens.",
                    r
                )
            );
            true
        }
    };
    if let (Err(r), Issue::Personne | Issue::Refusee(_)) = (&tour.verrou, &tour.issue) {
        eprintln!(
            "{}",
            trf!(
                "Ordre des lancements non garanti ({}) : un lancement simultané pourrait ouvrir une seconde fenêtre.",
                "Launch order not guaranteed ({}): a simultaneous launch could open a second window.",
                r
            )
        );
    }
    let lancement = ouvrir(remplacer);
    drop(tour);
    lancement
}

/// Ouvre la fenêtre `chemin` (vérifiée de nouveau juste avant : l'empreinte `attendue`) et attend qu'elle dise
/// « ouverte ». `remplacer` : elle prend la prise « une seule fenêtre » même si quelque chose y écoute.
fn lancer_la_fenetre(chemin: &Path, programme: &Path, attendue: &[u8; 32], remplacer: bool) -> Lancement {
    // Ce programme-ci d'abord : sans son empreinte, la fenêtre refuserait chaque commande (`--empreinte-vanguard`).
    let soi = match empreinte_de_soi() {
        Ok(e) => e,
        Err(e) => {
            return Lancement::Refusee(trf!(
                "l'empreinte de ce programme est illisible : {}",
                "this program's fingerprint is unreadable: {}",
                e
            ));
        }
    };
    #[cfg(target_os = "linux")]
    let verifiee = verifier(chemin, attendue, crate::socle::uid());
    #[cfg(windows)]
    let verifiee = verifier(chemin, attendue);
    // `verifiee` vit jusqu'à la fin : ce qu'elle tient reste ouvert jusqu'à « ouverte » ou l'échec (Linux : fermé
    // avant, le numéro de son descripteur pourrait désigner un autre fichier ; Windows : le fichier tenu).
    let verifiee = match verifiee {
        Ok(v) => v,
        Err(r) => return Lancement::Refusee(r.to_string()),
    };
    #[cfg(target_os = "linux")]
    let mut c = commande(&verifiee, std::env::vars_os());
    #[cfg(windows)]
    let mut c = commande(&verifiee);
    c.args(arguments(programme, &soi))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if remplacer {
        c.arg("--remplacer-prise");
    }
    // Son propre groupe de processus : la fermeture du terminal (SIGHUP au groupe de premier plan) ne la ferme pas,
    // ni un Ctrl+C tapé ensuite dans ce terminal.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut c, 0);
    attendre_ouverte(c)
}

/// Démarre la commande de la fenêtre et attend qu'elle dise « ouverte » (`ATTENTE` au plus), sinon l'arrête.
fn attendre_ouverte(mut c: Command) -> Lancement {
    // Refusé par le système (exécution interdite par une politique, /proc absent…) : la raison est dite.
    let mut enfant = match c.spawn_suivi() {
        Ok(enfant) => enfant,
        Err(e) => {
            return Lancement::Refusee(trf!("lancement impossible : {}", "launch impossible: {}", e));
        }
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
            injection: false,
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

    /// C-6 (0.97) : une fenêtre livrée mais absente, quand tout la voulait, est dite au menu (`Absente`) ; un fichier
    /// posé, lui, est à juger puis lancer.
    #[test]
    fn une_fenetre_absente_est_dite_quand_tout_la_voulait() {
        let dossier = crate::essais::temporaire().join(crate::essais::nom_unique("fenetre-absente-dite"));
        std::fs::create_dir_all(&dossier).unwrap();
        let absente = dossier.join("vanguard-fenetre");
        let devant = Contexte {
            terminal: true,
            graphique: true,
            a_distance: false,
            eleve: false,
            injection: false,
        };
        assert_eq!(decider(devant, true, &absente), Decision::Absente);
        std::fs::write(&absente, b"une fenetre inventee").unwrap();
        assert_eq!(
            decider(devant, true, &absente),
            Decision::Lancer,
            "posée : jugée puis lancée"
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// C-6 (0.97) : quand une garde tient (pas de terminal, pas d'écran, SSH ou Bureau à distance, administrateur,
    /// bibliothèque injectée, fenêtre non livrée), une fenêtre absente n'est jamais proposée : le menu, comme avant.
    #[test]
    fn une_garde_ne_propose_jamais_la_fenetre_absente() {
        let absente = crate::essais::temporaire().join(crate::essais::nom_unique("fenetre-absente-gardee"));
        let devant = Contexte {
            terminal: true,
            graphique: true,
            a_distance: false,
            eleve: false,
            injection: false,
        };
        for (garde, c) in [
            (
                "pas de terminal",
                Contexte {
                    terminal: false,
                    ..devant
                },
            ),
            (
                "pas d'écran",
                Contexte {
                    graphique: false,
                    ..devant
                },
            ),
            (
                "à distance",
                Contexte {
                    a_distance: true,
                    ..devant
                },
            ),
            ("administrateur", Contexte { eleve: true, ..devant }),
            (
                "bibliothèque injectée",
                Contexte {
                    injection: true,
                    ..devant
                },
            ),
        ] {
            assert_eq!(decider(c, true, &absente), Decision::Menu, "{garde}");
        }
        assert_eq!(decider(devant, false, &absente), Decision::Menu, "non livrée");
    }

    /// La fenêtre n'est livrée que par une empreinte gravée : « aucune » (`cargo build`, les essais) ou une marque
    /// illisible ou contredite (`None`) ne la livrent pas.
    #[test]
    fn seule_une_empreinte_gravee_livre_la_fenetre() {
        use crate::demarrage::empreinte_fenetre::Gravee;
        assert!(livree_selon(Some(Gravee::Empreinte([7; 32]))));
        assert!(!livree_selon(Some(Gravee::Aucune)));
        assert!(!livree_selon(None));
        // Les essais compilent sans empreinte : pas de fenêtre, et l'aide ne la promet pas (menu/tests.rs).
        assert!(!fenetre_livree());
    }

    /// LIV-1 : un faux `vanguard-fenetre` posé à côté, exécutable (755), qui dirait « ouverte », n'est jamais lancé
    /// par un programme compilé sans empreinte de fenêtre : ni par `ouvrir`, ni par `lancer` lui-même.
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
            injection: false,
        };
        assert!(
            !ouvrir_depuis(devant, &f, &dossier.join("vanguard")),
            "compilé sans empreinte : le menu"
        );
        assert!(
            !matches!(lancer(&f, &dossier.join("vanguard")), Lancement::Ouverte),
            "jamais lancée, même appelée directement"
        );
        assert!(!temoin.exists(), "le faux voisin a tourné");
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// La variable qui dit à `joue_la_fenetre` quoi faire : « env » pour écrire ses variables, sinon la dire.
    #[cfg(target_os = "linux")]
    const JOUER: &str = "VANGUARD_ESSAI_JOUER";

    /// Le programme qui joue la fenêtre dans les essais suivants : ce programme d'essai lui-même (un vrai ELF, lancé
    /// depuis la copie scellée comme la fenêtre), et les arguments qui n'y lancent que `joue_la_fenetre`. Pas
    /// /usr/bin/echo ni /usr/bin/env : uutils (Ubuntu 26.04, la CI de la 0.96.0) est un seul programme qui choisit
    /// l'outil d'après son nom, et nommé « vanguard-fenetre », il ne disait rien.
    #[cfg(target_os = "linux")]
    fn joueur() -> (Vec<u8>, [&'static str; 6]) {
        let octets = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let essai = "demarrage::lancer_fenetre::tests::joue_la_fenetre";
        (
            octets,
            [
                "--exact",
                essai,
                "--ignored",
                "--nocapture",
                "--quiet",
                "--test-threads=1",
            ],
        )
    }

    /// Joue la fenêtre (`joueur`) ; ne fait rien sans `JOUER`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "lancé seulement par les essais de la fenêtre, depuis une copie scellée"]
    fn joue_la_fenetre() {
        match std::env::var(JOUER).as_deref() {
            Ok("env") => {
                for (nom, valeur) in std::env::vars_os() {
                    println!("{}={}", nom.to_string_lossy(), valeur.to_string_lossy());
                }
            }
            Ok(texte) => println!("dit:{texte}"),
            Err(_) => {}
        }
    }

    /// LIV-1 : seuls les octets dont l'empreinte est attendue sont lancés, depuis une copie scellée en mémoire ; la
    /// fenêtre remplacée sur le disque après la vérification ne tourne pas ; un lien, une fenêtre modifiable par
    /// d'autres ou d'une autre empreinte ne sont pas lancés. Le programme d'essai y joue la fenêtre (`joueur`).
    #[cfg(target_os = "linux")]
    #[test]
    fn seuls_les_octets_verifies_sont_lances() {
        use sha2::Digest;
        use std::io::Write;
        use std::os::unix::fs::{FileExt, PermissionsExt};
        let (echo, arguments) = joueur();
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
        let de = std::env::vars_os().chain([(JOUER.into(), "vérifiée".into())]);
        let sortie = commande(&v, de).args(arguments).stderr(Stdio::null()).output().unwrap();
        let texte = String::from_utf8_lossy(&sortie.stdout).into_owned();
        assert!(texte.lines().any(|l| l == "dit:vérifiée"), "{texte}");
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
    /// effacée, ni renommée), son dossier aussi (W2), jusqu'à la fin du lancement, et la commande lance son chemin.
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
        // W2 (relecture 0.96) : son dossier non plus ne se renomme pas pendant la tenue (un autre dossier aurait pris
        // son nom, avec une fausse fenêtre, et Windows lance par le chemin).
        let ailleurs = crate::socle::dossier_local().join("essai-fenetre-ailleurs");
        let _ = std::fs::remove_dir_all(&ailleurs);
        assert!(std::fs::rename(&dossier, &ailleurs).is_err(), "son dossier renommé");
        assert_eq!(commande(&v).get_program(), f.as_os_str());
        drop(v);
        // Relâchée après le lancement : le fichier redevient libre.
        assert!(std::fs::rename(&f, dossier.join("autre.exe")).is_ok());
        assert!(verifier(&dossier, &bonne).is_err(), "un dossier");
        // Tenue, elle se lance quand même (Windows ouvre l'image en lecture, permise par ce partage) : un vrai
        // programme, `cmd.exe` copié, joue la fenêtre.
        let systeme = std::env::var_os("SystemRoot").map_or_default(PathBuf::from);
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

    /// L3 (relecture 0.96) : un lancement refusé par le système (exécution interdite, /proc absent, fichier
    /// disparu) disait seulement « ne s'est pas ouverte » ; la raison doit être dite.
    #[test]
    fn un_lancement_refuse_par_le_systeme_dit_pourquoi() {
        let absente = crate::essais::temporaire().join(crate::essais::nom_unique("fenetre-absente"));
        let c = Command::new(absente);
        match attendre_ouverte(c) {
            Lancement::Refusee(r) => assert!(
                r.contains("lancement impossible") || r.contains("launch impossible"),
                "{r}"
            ),
            autre => panic!("la raison n'est pas dite : {autre:?}"),
        }
    }

    /// L1 (relecture 0.96) : une bibliothèque injectée dans la session (l'alerte de `protection::environnement`)
    /// irait aussi dans la fenêtre vérifiée : le menu, et la raison dite.
    #[test]
    fn une_bibliotheque_injectee_garde_le_menu() {
        let devant = Contexte {
            terminal: true,
            graphique: true,
            ..Contexte::default()
        };
        assert_eq!(refus_du_contexte(devant), None);
        let r = refus_du_contexte(Contexte {
            injection: true,
            ..devant
        });
        assert!(
            r.is_some_and(|r| r.contains("injectée") || r.contains("injected")),
            "{r:?}"
        );
    }

    /// L1 (relecture 0.96) : la fenêtre vérifiée héritait de tout l'environnement du compte, et LD_PRELOAD y faisait
    /// tourner une bibliothèque étrangère dès son démarrage (la fenêtre est dynamique, `vanguard` non). Elle ne reçoit
    /// plus qu'une liste fermée, et un PATH fixe. Le programme d'essai (`joueur`), lancé comme la fenêtre, dit ce
    /// qu'il a reçu.
    #[cfg(target_os = "linux")]
    #[test]
    fn la_fenetre_ne_recoit_qu_une_liste_fermee_de_variables() {
        use sha2::Digest;
        use std::os::unix::fs::PermissionsExt;
        let (env, arguments) = joueur();
        let dossier = crate::socle::dossier_local().join("essai-environnement-fenetre");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let f = dossier.join("vanguard-fenetre");
        std::fs::write(&f, &env).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        let v = verifier(&f, &sha2::Sha256::digest(&env).into(), crate::socle::uid()).unwrap();
        let interdites = [
            ("LD_PRELOAD", "/home/alice/.cache/libtemoin.so"),
            ("LD_AUDIT", "/home/alice/.cache/libtemoin.so"),
            ("LD_LIBRARY_PATH", "/home/alice/lib"),
            ("GTK_MODULES", "temoin"),
            ("GTK_IM_MODULE", "temoin"),
            ("LIBGL_DRIVERS_PATH", "/home/alice/dri"),
            ("__EGL_VENDOR_LIBRARY_FILENAMES", "/home/alice/egl.json"),
            ("VANGUARD_ORIGINE", "/home/alice/faux/vanguard"),
            ("BASH_ENV", "/home/alice/.piege"),
            ("WAYLAND_SOCKET", "3"),
        ];
        let gardees = [
            ("WAYLAND_DISPLAY", "wayland-essai"),
            ("DISPLAY", ":7"),
            ("XAUTHORITY", "/run/user/1000/xauth-essai"),
            ("LANG", "fr_CA.UTF-8"),
            ("LC_TIME", "C"),
            ("HOME", "/home/alice"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
            ("VANGUARD_HORS_LIGNE", "1"),
        ];
        let de: Vec<(std::ffi::OsString, std::ffi::OsString)> = interdites
            .iter()
            .chain(gardees.iter())
            .chain([("PATH", "/home/alice/bin:/usr/bin"), (JOUER, "env")].iter())
            .map(|(n, v)| ((*n).into(), (*v).into()))
            .collect();
        let sortie = commande(&v, de).args(arguments).stderr(Stdio::null()).output().unwrap();
        let texte = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let recues: std::collections::BTreeMap<&str, &str> = texte.lines().filter_map(|l| l.split_once('=')).collect();
        for (nom, _) in interdites {
            assert!(!recues.contains_key(nom), "{nom} passe à la fenêtre : {texte}");
        }
        for (nom, valeur) in gardees {
            assert_eq!(recues.get(nom), Some(&valeur), "{nom} : {texte}");
        }
        // Un PATH fixe, celui des outils du système : le `vanguard` relancé par le relais y trouve sudo et pkexec.
        assert_eq!(recues.get("PATH"), Some(&crate::commande::PATH_PROPRE), "{texte}");
        // Rien d'autre, même ce que le test hérite de cargo (CARGO_*, RUST_*).
        for nom in recues.keys() {
            assert!(
                *nom == "PATH" || gardee_fenetre(std::ffi::OsStr::new(nom)),
                "{nom} hors de la liste : {texte}"
            );
        }
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

    /// La fenêtre reçoit le programme d'origine à lancer, tel quel (même téléchargé sous le nom de la page), et
    /// l'empreinte qu'il doit avoir, en 64 chiffres hexadécimaux minuscules (fenetre/src/main.rs les exige ainsi).
    #[test]
    fn la_fenetre_recoit_le_programme_a_lancer() {
        let mut soi = [0u8; 32];
        soi[0] = 0xab;
        soi[31] = 0x0c;
        let a = arguments(Path::new("/opt/v/vanguard-linux-x86_64"), &soi);
        let i = a.iter().position(|x| x == "--vanguard").expect("--vanguard");
        assert_eq!(
            a.get(i + 1).map(PathBuf::from),
            Some(PathBuf::from("/opt/v/vanguard-linux-x86_64"))
        );
        let i = a
            .iter()
            .position(|x| x == "--empreinte-vanguard")
            .expect("--empreinte-vanguard");
        let attendue = format!("ab{}0c", "00".repeat(30));
        assert_eq!(a.get(i + 1).and_then(|x| x.to_str()), Some(attendue.as_str()));
        assert!(a.iter().any(|x| x == "--depuis-vanguard"));
        assert!(a.iter().any(|x| x == "--langue"));
    }

    /// L'empreinte de soi est celle des octets du programme qui tourne (ici, le programme d'essai).
    #[test]
    fn l_empreinte_de_soi_est_celle_du_programme() {
        use sha2::Digest;
        let octets = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let attendue: [u8; 32] = sha2::Sha256::digest(&octets).into();
        assert_eq!(empreinte_de_soi().unwrap(), attendue);
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

    /// Constat 24 : le câblage de `lancer`. Une fenêtre ramenée : rien n'est lancé.
    #[test]
    fn une_fenetre_ramenee_n_en_ouvre_pas_d_autre() {
        use super::super::une_fenetre::{Issue, Tour};
        for confirmee in [false, true] {
            let tour = || Tour {
                issue: Issue::Ramenee(confirmee),
                verrou: Err("essai".into()),
            };
            let lancement = une_seule(tour, |_| panic!("une seconde fenêtre lancée"));
            assert!(
                matches!(lancement, Lancement::Ramenee(c) if c == confirmee),
                "{lancement:?}"
            );
        }
    }

    /// Personne n'écoute : la fenêtre est lancée sans prendre la prise d'une autre, et le verrou des lancements est
    /// tenu jusqu'à ce qu'elle dise « ouverte » (un second lancement attend, puis la ramène) ; rendu ensuite.
    #[test]
    fn le_verrou_est_tenu_jusqu_a_ouverte() {
        use super::super::une_fenetre::{Issue, Tour};
        use crate::socle::{SansVerrou, Verrou};
        let d = crate::essais::Jetable::nouveau("une-seule");
        let essayer = || Verrou::prendre(&d, "fenetre.verrou", false, std::time::Duration::ZERO);
        let verrou = essayer().map_err(|_| "verrou d'essai").unwrap();
        let tour = || Tour {
            issue: Issue::Personne,
            verrou: Ok(verrou),
        };
        let lancement = une_seule(tour, |remplacer| {
            assert!(!remplacer, "la prise d'une fenêtre vivante serait prise");
            assert!(
                matches!(essayer(), Err(SansVerrou::Occupe)),
                "verrou rendu avant « ouverte »"
            );
            Lancement::Ouverte
        });
        assert!(matches!(lancement, Lancement::Ouverte), "{lancement:?}");
        assert!(essayer().is_ok(), "verrou gardé après le lancement");
    }

    /// Ce qui écoute n'est pas une fenêtre de Vanguard qui répond (refusé, muet, ancienne version) : la nouvelle
    /// fenêtre prend la prise.
    #[test]
    fn un_canal_refuse_fait_prendre_la_prise() {
        use super::super::une_fenetre::{Issue, Tour};
        for issue in [Issue::Refusee("essai".into()), Issue::Indisponible("essai".into())] {
            let tour = || Tour {
                issue,
                verrou: Err("essai".into()),
            };
            let mut demande = None;
            let lancement = une_seule(tour, |remplacer| {
                demande = Some(remplacer);
                Lancement::Ouverte
            });
            assert!(matches!(lancement, Lancement::Ouverte), "{lancement:?}");
            assert_eq!(demande, Some(true));
        }
    }
}
