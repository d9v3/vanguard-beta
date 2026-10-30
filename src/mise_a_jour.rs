//! Mettre Vanguard à jour sur cet ordinateur. La copie que la surveillance, l'entretien et le raccourci y lancent
//! (`reseau::surveillance::executable`) ne suit pas la clé, qui, elle, se met à jour chez son propriétaire. Lancé
//! depuis une clé plus récente, Vanguard le dit au menu et remplace la copie sur accord par le programme qui tourne :
//! copié à côté, sa version revérifiée, relu et comparé, puis mis en place d'un coup. Jamais vers une version plus
//! ancienne. La source est toujours le programme lancé depuis la clé, la confiance que la surveillance lui faisait
//! déjà en le copiant ; jamais un volume seulement branché, qui n'aurait qu'à porter le fichier témoin. La version
//! d'une copie se lit dans son fichier, sans la lancer : une vieille copie ne refait pas ses étapes de démarrage
//! (protection de la clé, passage à un nouveau nom). Sans clé, la dernière version publiée vient de GitHub, signée par
//! l'auteur et vérifiée (`github`) ; elle remplace la copie de cet ordinateur et le programme lancé, s'il n'est pas
//! sur la clé (la clé, elle, se met à jour chez son propriétaire).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::ui::*;

mod github;

/// La version de ce programme et la date de son commit, gravées dans son fichier pour qu'une autre copie les lise sans
/// le lancer (« VANGUARD-VERSION:0.78.0+1760900000; »). `courante` la lit là : sans lecture, l'éditeur de liens
/// retirerait ce texte du programme publié.
static VERSION_GRAVEE: &str = concat!(
    "VANGUARD-VERSION:",
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("VANGUARD_COMMIT_SECONDES"),
    ";"
);

/// Ce qui précède la version gravée, écrit décalé d'un cran (« W » pour « V ») : en clair, ce texte paraîtrait une
/// seconde fois dans le programme, suivi de ce que l'éditeur de liens met après lui (« 0.78.0 » d'un autre texte,
/// par exemple), et la recherche pourrait y lire une fausse version. Ainsi, seule la version gravée le porte.
const ENTETE_DECALE: [u8; 17] = *b"WBOHVBSE.WFSTJPO;";

/// L'en-tête en clair, refait au lancement (`black_box` : le compilateur ne le calcule pas d'avance, ce qui l'écrirait
/// en clair dans le programme).
fn entete() -> [u8; 17] {
    std::hint::black_box(ENTETE_DECALE).map(|o| o - 1)
}

/// Au-delà, un fichier n'est pas un programme de Vanguard (en 0.85, un release fait 31 Mo sous Windows et 33 sous
/// Linux, avec YARA-X ; le programme de mise au point environ 230 Mo, celui des tests unitaires, qui se lit lui-même
/// dans `ce_programme_porte_sa_version`, 290 Mo sous Linux, voir [profile.test] de Cargo.toml) : il n'est pas lu, la
/// mémoire ne se remplit pas.
const TAILLE_MAX: u64 = 512 << 20;

/// Le nom du programme copié dans bin/ (la désinstallation le retrouve aussi, avec ses restes `.ancien`, `.nouveau`).
pub(crate) const NOM: &str = if cfg!(windows) { "vanguard.exe" } else { "vanguard" };

/// Une version : majeure, mineure, correctif, puis la date de son commit en secondes (0 : inconnue). Entre deux
/// publications, les compilations intermédiaires gardent le même numéro : la date les départage, et l'ordre des
/// tuples fait le reste.
type Version = (u32, u32, u32, u64);

/// « 0.78.0 » ou « 0.78.0+1760900000 ».
fn lire_version(texte: &str) -> Option<Version> {
    let (numero, date) = match texte.split_once('+') {
        Some((n, d)) => (n, d.parse::<u64>().ok()?),
        None => (texte, 0),
    };
    let mut morceaux = numero.split('.').map(|m| m.parse::<u32>().ok());
    let version = (morceaux.next()??, morceaux.next()??, morceaux.next()??, date);
    morceaux.next().is_none().then_some(version)
}

fn ecrire(v: Version) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// Deux versions à montrer côte à côte : le numéro seul, et la date du commit quand le numéro ne suffit pas à les
/// distinguer (deux compilations entre deux publications).
fn cote_a_cote(a: Version, b: Version) -> (String, String) {
    if (a.0, a.1, a.2) != (b.0, b.1, b.2) || a.3 == b.3 {
        return (ecrire(a), ecrire(b));
    }
    let date = |v: Version| {
        i64::try_from(v.3)
            .ok()
            .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
            .filter(|_| v.3 > 0)
            .map_or_else(
                || tr!("sans date", "undated").to_string(),
                |d| {
                    d.with_timezone(&chrono::Local)
                        .format(tr!("%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M"))
                        .to_string()
                },
            )
    };
    (
        format!("{} ({})", ecrire(a), date(a)),
        format!("{} ({})", ecrire(b), date(b)),
    )
}

/// La version de ce programme, lue dans sa version gravée (`black_box` : le compilateur ne la remplace pas par sa
/// valeur, le texte reste dans le fichier). `None` ne devrait jamais arriver (un test le garde) : rien n'est alors
/// proposé, plutôt que de comparer à une version inventée.
fn courante() -> Option<Version> {
    version_gravee(std::hint::black_box(VERSION_GRAVEE).as_bytes())
}

/// La version gravée dans le contenu d'un programme : `None` quand il n'en a pas (une copie d'avant la 0.78, donc
/// plus ancienne que toute copie qui en a une). Seule une occurrence suivie d'une version et d'un « ; » compte.
fn version_gravee(octets: &[u8]) -> Option<Version> {
    let entete = entete();
    let mut reste = octets;
    while let Some(i) = reste.windows(entete.len()).position(|f| f == entete) {
        // Ce qui suit l'occurrence ; les 32 premiers octets suffisent à une version et son « ; ».
        let Some(apres) = reste.get(i + entete.len()..) else {
            break;
        };
        let suite = apres.get(..32).unwrap_or(apres);
        if let Some(fin) = suite.iter().position(|&o| o == b';')
            && let Some(v) = suite
                .get(..fin)
                .and_then(|t| std::str::from_utf8(t).ok())
                .and_then(lire_version)
        {
            return Some(v);
        }
        reste = apres;
    }
    None
}

/// Ce qu'on lit d'un programme sur le disque.
#[derive(Debug, PartialEq, Eq)]
enum Lu {
    Absent,
    /// Là, mais pas lisible comme un programme (droits, dossier, fichier spécial, démesuré) : le pourquoi.
    Illisible(String),
    /// Sans version gravée : d'avant la 0.78.
    Ancien,
    Version(Version),
}

/// Le contenu d'un programme : seulement un fichier ordinaire, jamais plus de `max` octets lus (un fichier spécial
/// bloquerait, un fichier démesuré remplirait la mémoire).
fn lire_octets(chemin: &Path, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    // Un lien est suivi (une copie posée par un lien vers le programme reste un programme), mais ce qui est ouvert
    // est jugé sur la poignée, sans attendre : entre un regard au chemin et l'ouverture, un tube pouvait prendre sa
    // place, et open() restait bloqué.
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let f = options.open(chemin).map_err(|e| e.to_string())?;
    if !f.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(tr!("pas un fichier ordinaire", "not a regular file").into());
    }
    let mut octets = Vec::new();
    f.take(max + 1).read_to_end(&mut octets).map_err(|e| e.to_string())?;
    if u64::try_from(octets.len()).unwrap_or(u64::MAX) > max {
        return Err(tr!("fichier démesuré", "oversized file").into());
    }
    Ok(octets)
}

fn lire_programme(chemin: &Path, max: u64) -> Lu {
    if std::fs::symlink_metadata(chemin).is_err() {
        return Lu::Absent;
    }
    match lire_octets(chemin, max) {
        Err(e) => Lu::Illisible(e),
        Ok(octets) => version_gravee(&octets).map_or(Lu::Ancien, Lu::Version),
    }
}

/// Où en est la copie de cet ordinateur.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Etat {
    /// Rien à dire : pas de copie sur cet ordinateur.
    Rien,
    /// Une copie est là, mais Vanguard ne tourne pas depuis la clé : la mise à jour se fait depuis la clé.
    PasDepuisLaCle,
    /// La copie est là mais ne se lit pas : sa version n'a pas pu être vérifiée (le pourquoi).
    Illisible(String),
    AJour(Version),
    /// La copie est plus récente que la clé : la clé est à remettre à jour chez son propriétaire.
    ClePlusAncienne {
        copie: Version,
        cle: Version,
    },
    /// La clé est plus récente : la copie peut être remplacée par `source`, le programme qui tourne.
    AMettreAJour {
        source: PathBuf,
        copie: Option<Version>,
        cle: Version,
    },
}

/// Compare la copie de cet ordinateur et ce programme. `copie` : sa version (`None` : d'avant la 0.78).
fn comparer(copie: Option<Version>, cle: Version, source: PathBuf) -> Etat {
    match copie {
        Some(c) if c == cle => Etat::AJour(c),
        Some(c) if c > cle => Etat::ClePlusAncienne { copie: c, cle },
        _ => Etat::AMettreAJour { source, copie, cle },
    }
}

/// L'état, d'après le programme lancé (`exe`), la clé d'où il tourne (`cle_du_programme`), la copie de cet ordinateur
/// et la version de ce programme.
fn etat_de(exe: &Path, cle_du_programme: Option<&Path>, copie: &Path, courante: Option<Version>, max: u64) -> Etat {
    let lu = lire_programme(copie, max);
    if lu == Lu::Absent {
        return Etat::Rien;
    }
    if !cle_du_programme.is_some_and(|c| exe.starts_with(c)) {
        return Etat::PasDepuisLaCle;
    }
    let Some(courante) = courante else {
        return Etat::Rien;
    };
    match lu {
        Lu::Absent => Etat::Rien,
        Lu::Illisible(e) => Etat::Illisible(e),
        Lu::Ancien => comparer(None, courante, exe.to_path_buf()),
        Lu::Version(v) => comparer(Some(v), courante, exe.to_path_buf()),
    }
}

/// La copie de cet ordinateur (celle de `reseau::surveillance::executable`).
pub(crate) fn copie_de_cet_ordinateur() -> PathBuf {
    crate::socle::dossier_local().join("bin").join(NOM)
}

fn programme() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        crate::protection::cle::exe_d_origine()
    }
    #[cfg(windows)]
    {
        std::env::current_exe().ok().and_then(|e| e.canonicalize().ok())
    }
}

/// Ce qui dit qu'une copie a changé : sa taille et sa date (`None` : absente).
type Empreinte = Option<(u64, SystemTime)>;

fn empreinte(chemin: &Path) -> Empreinte {
    let meta = std::fs::metadata(chemin).ok()?;
    Some((meta.len(), meta.modified().ok()?))
}

/// L'état gardé tant que la copie ne change pas : le menu le demande à chaque affichage, et lire la copie prend un
/// moment. Une copie posée ou remplacée pendant la session (surveillance activée, mise à jour) le fait relire.
struct Memoire(Mutex<Option<(Empreinte, Etat)>>);

impl Memoire {
    const fn new() -> Self {
        Self(Mutex::new(None))
    }

    fn lire(&self, empreinte: Empreinte, calcul: impl FnOnce() -> Etat) -> Etat {
        let mut garde = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((e, etat)) = garde.as_ref()
            && *e == empreinte
        {
            return etat.clone();
        }
        let etat = calcul();
        *garde = Some((empreinte, etat.clone()));
        etat
    }
}

static ETAT: Memoire = Memoire::new();

fn etat() -> Etat {
    // Jamais pendant les tests : la vraie copie peut être là.
    if cfg!(test) {
        return Etat::Rien;
    }
    let copie = copie_de_cet_ordinateur();
    ETAT.lire(empreinte(&copie), || {
        // Le reste d'une mise à jour faite pendant que la copie tournait (Windows), s'il ne tourne plus.
        let _ = std::fs::remove_file(copie.with_file_name(format!("{NOM}.ancien")));
        programme().map_or(Etat::Rien, |exe| {
            etat_de(
                &exe,
                crate::reseau::cle_du_programme().as_deref(),
                &copie,
                courante(),
                TAILLE_MAX,
            )
        })
    })
}

/// La copie, avant la 0.78, n'avait pas de version lisible.
fn version_affichee(v: Option<Version>) -> String {
    v.map_or_else(|| tr!("d'avant la 0.78", "older than 0.78").to_string(), ecrire)
}

/// La ligne du menu quand la clé d'où tourne Vanguard est plus récente que la copie de cet ordinateur, sinon rien.
/// `touche` : l'entrée du menu qui la met à jour (« 9.9 »).
pub fn avertissement(touche: &str) -> Option<String> {
    if let Etat::AMettreAJour { cle, .. } = etat() {
        return Some(trf!(
            "Nouvelle version sur la clé ({}) : {touche} met à jour cet ordinateur.",
            "New version on the key ({}): {touche} updates this computer.",
            ecrire(cle)
        ));
    }
    // Sinon, une version plus récente publiée sur GitHub, s'il y a ici quelque chose qu'elle remplacerait.
    let publiee = github::annonce()?;
    cibles_github().iter().any(|c| plus_ancien(c, publiee)).then(|| {
        trf!(
            "Vanguard {} est sorti : {touche} met à jour cet ordinateur.",
            "Vanguard {} is out: {touche} updates this computer.",
            ecrire(publiee)
        )
    })
}

/// Ce que la mise à jour depuis GitHub remplace : la copie de cet ordinateur, et le programme lancé s'il n'est ni
/// sur la clé (elle se met à jour chez son propriétaire) ni cette copie.
fn cibles_github() -> Vec<PathBuf> {
    if cfg!(test) {
        return Vec::new();
    }
    let copie = copie_de_cet_ordinateur();
    let mut cibles = Vec::new();
    if std::fs::symlink_metadata(&copie).is_ok() {
        cibles.push(copie.clone());
    }
    if let Some(exe) = programme() {
        let sur_la_cle = crate::reseau::cle_du_programme().is_some_and(|c| exe.starts_with(c));
        if !sur_la_cle && !meme_fichier(&exe, &copie) && remplacable_ici(&exe) {
            cibles.push(exe);
        }
    }
    cibles
}

/// En root, un programme ne se remplace que dans un dossier à root que ni son groupe ni les autres ne peuvent
/// changer : le nouveau est écrit à côté, relu, essayé puis renommé par son chemin, et le compte à qui appartient le
/// dossier (un « sudo ~/Téléchargements/vanguard ») l'aurait échangé entre la relecture et l'essai, que root lance.
/// Chaque dossier au-dessus aussi, jusqu'à « / » : un dossier à root posé dans celui d'un compte (~/bin) se renomme
/// par ce compte, qui en met un autre à sa place sous le même chemin. Hors de root : toujours (le compte ne risque que
/// lui-même).
fn remplacable_ici(programme: &Path) -> bool {
    #[cfg(unix)]
    {
        // SAFETY : geteuid n'a ni pointeur ni effet de bord.
        remplacable_pour(unsafe { libc::geteuid() }, programme)
    }
    #[cfg(not(unix))]
    {
        let _ = programme;
        true
    }
}

#[cfg(unix)]
fn remplacable_pour(euid: libc::uid_t, programme: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    if euid != 0 {
        return true;
    }
    // Le chemin tel qu'il sera écrit, puis le même résolu : un lien en route (« /bin » vers « usr/bin ») est sûr s'il
    // est à root dans un dossier sûr, et ce qu'il désigne doit l'être aussi.
    let a_root = |chemin: &Path, lien_permis: bool| {
        chemin.ancestors().all(|d| {
            std::fs::symlink_metadata(d).is_ok_and(|m| {
                let genre = m.file_type();
                m.uid() == 0 && ((genre.is_dir() && m.mode() & 0o022 == 0) || (lien_permis && genre.is_symlink()))
            })
        })
    };
    let Some(dossier) = programme.parent().filter(|d| d.is_absolute()) else {
        return false;
    };
    a_root(dossier, true) && dossier.canonicalize().is_ok_and(|vrai| a_root(&vrai, false))
}

/// Le programme lancé est-il laissé de côté par la mise à jour, lancé en root depuis un dossier qui n'est pas sûr ?
/// Pour le dire, plutôt que de le taire.
fn programme_ecarte_en_root() -> Option<PathBuf> {
    programme().filter(|exe| !remplacable_ici(exe))
}

/// Deux chemins vers le même fichier ? Comparés une fois résolus : sous Windows, le programme lancé se lit en
/// « \\?\C:\… » et la copie en « C:\… ».
fn meme_fichier(a: &Path, b: &Path) -> bool {
    a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
}

/// Ce programme est-il plus ancien que `publiee` ? Sans version gravée (d'avant la 0.78), oui ; illisible, non :
/// on ne remplace pas ce qu'on n'a pas pu lire.
fn plus_ancien(chemin: &Path, publiee: Version) -> bool {
    match lire_programme(chemin, TAILLE_MAX) {
        Lu::Ancien => true,
        Lu::Version(v) => v < publiee,
        Lu::Absent | Lu::Illisible(_) => false,
    }
}

/// Le programme d'empreinte `sha256` est-il une version publiée et signée par l'auteur ? D'après l'historique signé
/// des versions sur GitHub (`github::dans_l_historique`) : (version, système), `None` s'il n'y est pas, `Err` quand on
/// ne sait pas.
pub(crate) fn version_signee(sha256: &[u8; 32]) -> Result<Option<(String, String)>, String> {
    github::dans_l_historique(sha256).map(|t| t.map(|(v, systeme)| (format!("{}.{}.{}", v.0, v.1, v.2), systeme)))
}

/// Copie `source` à la place de `cible` : à côté d'abord, sa version revérifiée (ce qui a été montré est ce qui
/// s'installe : la clé a pu changer depuis l'affichage), relue et comparée, puis renommée d'un coup ; une copie
/// interrompue ou abîmée ne remplace jamais celle qui marche, et ne reste pas sur le disque.
fn remplacer(source: &Path, cible: &Path, attendue: Version, max: u64, essai: Essai) -> Result<(), String> {
    installer(&lire_octets(source, max)?, cible, attendue, essai)
}

/// L'essai d'un programme posé à côté, avant qu'il remplace l'ancien (`essayer`, ou celui d'un test).
type Essai = fn(&Path, Version) -> Result<(), String>;

/// Les octets d'un programme à la place de `cible`, s'ils portent la version `attendue` et que l'essai les a vus
/// démarrer.
fn installer(octets: &[u8], cible: &Path, attendue: Version, essai: Essai) -> Result<(), String> {
    if version_gravee(octets) != Some(attendue) {
        return Err(tr!(
            "le programme de la clé a changé depuis l'affichage, rien n'est remplacé",
            "the key's program changed since it was shown, nothing is replaced"
        )
        .into());
    }
    let provisoire = cible.with_file_name(format!("{NOM}.nouveau"));
    let ecrite = (|| -> Result<(), String> {
        use std::io::Write;
        // Créé neuf (O_EXCL) : un lien posé à ce nom n'est jamais suivi, l'écriture échoue plutôt. Les droits sont
        // donnés par le descripteur, pas par le chemin.
        let _ = std::fs::remove_file(&provisoire);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&provisoire)
            .map_err(|e| e.to_string())?;
        f.write_all(octets)
            .and_then(|()| f.sync_all())
            .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
        }
        drop(f);
        if lire_octets(&provisoire, TAILLE_MAX).ok().as_deref() != Some(octets) {
            return Err(tr!("la copie relue ne correspond pas", "the copy read back does not match").into());
        }
        essai(&provisoire, attendue)?;
        mettre_en_place(&provisoire, cible).map_err(|e| e.to_string())
    })();
    if ecrite.is_err() {
        let _ = std::fs::remove_file(&provisoire);
    } else {
        // Posée par Vanguard : chaque tâche qui la lance garde un sceau juste (`programmes_poses`), sans quoi le bilan
        // la dirait remplacée hors de Vanguard.
        let touchees = crate::programmes_poses::copie_posee(cible, octets);
        // Le veilleur tourne sans s'arrêter : relancé, il prend la copie posée au lieu de garder l'ancienne en mémoire,
        // que plus rien sur le disque ne reconnaît.
        // Son unité suffit à le dire : posé par une version d'avant, rien n'est encore noté pour lui.
        #[cfg(target_os = "linux")]
        if touchees.contains(&crate::programmes_poses::Tache::Veilleur)
            || crate::machine::linux::veilleur::lance_la_copie(cible)
        {
            crate::machine::linux::veilleur::relancer_si_actif();
        }
        #[cfg(not(target_os = "linux"))]
        let _ = touchees;
    }
    ecrite
}

/// Lance la nouvelle copie, encore à côté, avec « --version » : la surveillance, l'entretien et le veilleur la
/// relanceront sans personne devant l'écran, et une copie qui ne démarre pas sur ce système (programme abîmé, mauvaise
/// architecture) arrêterait la défense sans bruit. Elle doit finir, sans erreur, en disant la version attendue ;
/// sinon l'ancienne reste en place. Sous Windows, pas d'essai : le fichier provisoire n'a pas l'extension .exe, et
/// son lancement par ce nom n'a pas été vérifié sur un vrai Windows.
fn essayer(programme: &Path, attendue: Version) -> Result<(), String> {
    if cfg!(windows) {
        return Ok(());
    }
    let r = crate::commande::lancer_borne(
        std::process::Command::new(programme)
            .arg("--version")
            .env("VANGUARD_HORS_LIGNE", "1"),
        30,
        64 << 10,
    );
    match r {
        Some(r) if r.code == Some(0) && r.sortie.split_whitespace().any(|m| m == ecrire(attendue)) => Ok(()),
        _ => Err(tr!(
            "la nouvelle copie ne démarre pas sur cet ordinateur : l'ancienne reste en place",
            "the new copy does not start on this computer: the old one stays in place"
        )
        .into()),
    }
}

/// La copie de cet ordinateur posée depuis `source`, le programme lancé sur la clé (surveillance, entretien,
/// raccourci, veilleur), par le même chemin que la mise à jour : à côté, version revérifiée, essayée, relue, puis
/// mise en place d'un coup. Jamais par-dessus une copie plus récente : elle est gardée, et c'est elle que la
/// surveillance lancera (« jamais vers une version plus ancienne »). Rend le chemin de la copie, ou pourquoi elle
/// n'a pas pu se faire : jamais celui de la clé, qu'une minuterie ne retrouverait plus une fois débranchée.
pub(crate) fn poser_copie(source: &Path) -> Result<PathBuf, String> {
    let cible = copie_de_cet_ordinateur();
    poser_copie_dans(source, &cible, essayer)?;
    Ok(cible)
}

fn poser_copie_dans(source: &Path, cible: &Path, essai: Essai) -> Result<(), String> {
    let octets = lire_octets(source, TAILLE_MAX)?;
    let Some(version) = version_gravee(&octets) else {
        return Err(tr!(
            "pas de version gravée dans le programme",
            "no engraved version in the program"
        )
        .into());
    };
    match lire_programme(cible, TAILLE_MAX) {
        Lu::Version(v) if v > version => return Ok(()),
        Lu::Version(v) if v == version && lire_octets(cible, TAILLE_MAX).ok().as_deref() == Some(&octets[..]) => {
            return Ok(());
        }
        _ => {}
    }
    if let Some(d) = cible.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    installer(&octets, cible, version, essai)
}

/// La copie de cet ordinateur est-elle plus ancienne que ce programme ? Elle écrit alors encore l'état de Vanguard
/// sans sceau (`sceau`), et le bilan le dit comme cause probable.
pub(crate) fn copie_plus_ancienne() -> bool {
    let Some(ici) = courante() else {
        return false;
    };
    match lire_programme(&copie_de_cet_ordinateur(), TAILLE_MAX) {
        Lu::Ancien => true,
        Lu::Version(v) => v < ici,
        Lu::Absent | Lu::Illisible(_) => false,
    }
}

/// Le renommage final. Sous Windows, un programme qui tourne (la surveillance, lancée à l'heure pile) ne se remplace
/// pas, mais il se renomme : l'ancien part de côté et s'efface à la prochaine mise à jour.
fn mettre_en_place(provisoire: &Path, cible: &Path) -> std::io::Result<()> {
    let erreur = match std::fs::rename(provisoire, cible) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    if !cfg!(windows) {
        return Err(erreur);
    }
    let ancien = cible.with_file_name(format!("{NOM}.ancien"));
    // Celui d'une mise à jour précédente tourne peut-être encore : rien ne se remplace, et c'est dit clairement.
    if std::fs::symlink_metadata(&ancien).is_ok() && std::fs::remove_file(&ancien).is_err() {
        return Err(std::io::Error::other(tr!(
            "l'ancienne copie tourne encore (surveillance) : réessayez dans une minute",
            "the old copy is still running (monitoring): try again in a minute"
        )));
    }
    std::fs::rename(cible, &ancien)?;
    std::fs::rename(provisoire, cible).inspect_err(|_| {
        let _ = std::fs::rename(&ancien, cible);
    })
}

/// « vanguard se-mettre-a-jour » et l'entrée du menu : l'état, puis la mise à jour sur accord.
pub fn commande() {
    titre(tr!("Mettre Vanguard à jour", "Update Vanguard"));
    trp!(
        "  {GRIS}La copie de Vanguard posée sur cet ordinateur (surveillance, entretien,\n  raccourci) ne suit pas la clé : elle se met à jour d'ici, sur accord.{RESET}\n",
        "  {GRIS}The copy of Vanguard placed on this computer (monitoring, maintenance,\n  shortcut) does not follow the key: it is updated from here, on your OK.{RESET}\n"
    );
    let cible = copie_de_cet_ordinateur();
    // Le reste d'une mise à jour faite pendant que la copie tournait (Windows).
    let _ = std::fs::remove_file(cible.with_file_name(format!("{NOM}.ancien")));
    match etat() {
        Etat::Rien => trp!(
            "  Pas de copie de Vanguard posée sur cet ordinateur (la surveillance,\n  l'entretien et le raccourci en posent une).",
            "  No copy of Vanguard placed on this computer (monitoring, maintenance\n  and the shortcut place one)."
        ),
        Etat::PasDepuisLaCle => trp!(
            "  {GRIS}Vanguard ne tourne pas depuis la clé VANGUARD : la mise à jour vient de GitHub.{RESET}",
            "  {GRIS}Vanguard is not running from the VANGUARD key: the update comes from GitHub.{RESET}"
        ),
        Etat::Illisible(e) => trp!(
            "  ✖ La copie de cet ordinateur ne se lit pas : sa version reste inconnue.\n    {GRIS}{} : {}{RESET}",
            "  ✖ The copy on this computer cannot be read: its version is unknown.\n    {GRIS}{}: {}{RESET}",
            affichable(&cible.display().to_string()),
            affichable(&e)
        ),
        Etat::AJour(v) => trp!(
            "  {VERT}✔{RESET} La copie de cet ordinateur est à jour ({}).",
            "  {VERT}✔{RESET} The copy on this computer is up to date ({}).",
            ecrire(v)
        ),
        Etat::ClePlusAncienne { copie, cle } => {
            let (copie, cle) = cote_a_cote(copie, cle);
            trp!(
                "  La copie d'ici ({copie}) est plus récente que la clé ({cle}).\n  Remettez la clé à jour chez vous : Vanguard ne revient jamais en arrière.",
                "  The copy on this computer ({copie}) is newer than the key ({cle}).\n  Update the key at home: Vanguard never goes back to an older version."
            );
        }
        Etat::AMettreAJour { source, copie, cle } => proposer(&source, &cible, copie, cle),
    }
    depuis_github();
}

/// La dernière version publiée sur GitHub : montrée, puis téléchargée, vérifiée et installée après un « o », à la
/// place de chaque programme d'ici qui est plus ancien.
fn depuis_github() {
    if let Some(exe) = programme_ecarte_en_root() {
        trp!(
            "\n  {GRIS}Lancé en root depuis un dossier que d'autres comptes peuvent changer :\n  {}\n  Ce programme n'est pas remplacé d'ici : posez-le dans un dossier à root,\n  ou mettez-le à jour sans sudo.{RESET}",
            "\n  {GRIS}Started as root from a folder other accounts can change:\n  {}\n  This program is not replaced from here: put it in a root-owned folder,\n  or update it without sudo.{RESET}",
            chemin_affichable(&exe)
        );
    }
    let cibles = cibles_github();
    if cibles.is_empty() {
        return;
    }
    if !github::dossier_sur() {
        trp!(
            "\n  {GRIS}Lancé en root avec le dossier d'un autre compte : pas de mise à jour depuis GitHub.\n  Relancez Vanguard depuis ce compte.{RESET}",
            "\n  {GRIS}Started as root with another account's folder: no update from GitHub.\n  Start Vanguard again from that account.{RESET}"
        );
        return;
    }
    if github::versions_vues_douteuses() {
        trp!(
            "\n  ✖ Les versions déjà vues ici ont été changées hors de Vanguard :\n    elles ne protègent plus d'un vieux manifeste remis sur GitHub.\n    Rien n'est vérifié tant qu'elles ne repartent pas de zéro.",
            "\n  ✖ The versions already seen here were changed outside Vanguard:\n    they no longer protect against an old manifest put back on GitHub.\n    Nothing is checked until they start over."
        );
        if !demander(tr!(
            "  Repartir de la version signée reçue maintenant ? [o/N] : ",
            "  Start over from the signed version received now? [y/N]: "
        ))
        .oui()
        {
            return;
        }
        if let Err(e) = github::oublier_versions_vues() {
            trp!("  ✖ {}", "  ✖ {}", affichable(&e.to_string()));
            return;
        }
    }
    trp!(
        "\n  {GRIS}Dernière version publiée sur GitHub…{RESET}",
        "\n  {GRIS}Latest version published on GitHub…{RESET}"
    );
    let publiee = match github::derniere() {
        Ok(p) => p,
        Err(e) => {
            trp!(
                "  GitHub : {}. Rien n'a été vérifié.",
                "  GitHub: {}. Nothing was checked.",
                affichable(&e)
            );
            return;
        }
    };
    // Le programme lancé et les copies d'ici servent de plancher : une version plus récente que la dernière signée
    // sur GitHub (passée par la clé VANGUARD, sans jamais voir GitHub) trahit un ancien manifeste remis en place.
    let ici: Vec<Version> = cibles
        .iter()
        .filter_map(|c| match lire_programme(c, TAILLE_MAX) {
            Lu::Version(v) => Some(v),
            _ => None,
        })
        .chain(courante())
        .collect();
    let a_remplacer: Vec<PathBuf> = cibles.into_iter().filter(|c| plus_ancien(c, publiee.version)).collect();
    if a_remplacer.is_empty() {
        dire_a_jour(publiee.version, &ici, maintenant());
        return;
    }
    trp!(
        "  Vanguard {} est publié, signé par son auteur (signature vérifiée).\n  Il remplacerait :",
        "  Vanguard {} is published, signed by its author (signature checked).\n  It would replace:",
        ecrire(publiee.version)
    );
    for c in &a_remplacer {
        let v = match lire_programme(c, TAILLE_MAX) {
            Lu::Version(v) => ecrire(v),
            _ => version_affichee(None),
        };
        println!("    {} {GRIS}({v}){RESET}", affichable(&c.display().to_string()));
    }
    if !demander(tr!(
        "  Le télécharger et l'installer ? [o/N] : ",
        "  Download and install it? [y/N]: "
    ))
    .oui()
    {
        return;
    }
    let octets = match github::programme_verifie(&publiee) {
        Ok(o) => o,
        Err(e) => {
            trp!("  ✖ {}", "  ✖ {}", affichable(&e));
            return;
        }
    };
    for c in &a_remplacer {
        match installer(&octets, c, publiee.version, essayer) {
            Ok(()) => trp!(
                "  {VERT}✔{RESET} {} : Vanguard {}.",
                "  {VERT}✔{RESET} {}: Vanguard {}.",
                affichable(&c.display().to_string()),
                ecrire(publiee.version)
            ),
            Err(e) => trp!(
                "  ✖ {} n'est pas remplacé, l'ancien reste en place :\n    {}",
                "  ✖ {} is not replaced, the old one stays in place:\n    {}",
                affichable(&c.display().to_string()),
                affichable(&e)
            ),
        }
    }
}

/// Les secondes depuis 1970 (0 si l'horloge est avant 1970). Une horloge en retard sur la date de la dernière
/// version signée rend son âge inconnu (`github::age_jours`, donc « non vérifié ») : jamais « frais ».
fn maintenant() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Ce que le contrôle depuis GitHub peut dire quand rien d'ici n'est plus ancien que la dernière version signée.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    AJour,
    /// Trop vieille pour être crue la dernière : pourquoi (« date de 50 jours »).
    Perimee(String),
    /// Un programme d'ici porte un numéro plus récent (celui-ci) : un ancien manifeste a pu être remis en place.
    PlusRecenteIci(Version),
}

/// Le verdict d'après la dernière version signée, les versions des programmes d'ici et l'heure. Seul le numéro
/// compte pour le plancher, pas la date : une compilation de développement porte le numéro publié et une date
/// plus récente, sans rien trahir.
fn verdict(publiee: Version, ici: &[Version], maintenant: u64) -> Verdict {
    let numero = |v: Version| (v.0, v.1, v.2);
    if let Some(&v) = ici.iter().filter(|v| numero(**v) > numero(publiee)).max() {
        return Verdict::PlusRecenteIci(v);
    }
    match github::age_jours(publiee, maintenant) {
        Some(jours) if jours <= github::FRAICHEUR_JOURS => Verdict::AJour,
        Some(jours) => Verdict::Perimee(trf!("date de {jours} jours", "is {jours} days old")),
        None => Verdict::Perimee(tr!("n'a pas de date fiable", "has no reliable date").to_string()),
    }
}

/// « Rien de plus récent », seulement si la dernière version signée est assez récente pour être crue la dernière
/// et que rien d'ici n'est plus récent qu'elle : un vieux manifeste remis en place sur GitHub gèlerait sinon les
/// mises à jour derrière une coche verte.
fn dire_a_jour(publiee: Version, ici: &[Version], maintenant: u64) {
    match verdict(publiee, ici, maintenant) {
        Verdict::AJour => trp!(
            "  {VERT}✔{RESET} Rien de plus récent sur GitHub (dernière version : {}).",
            "  {VERT}✔{RESET} Nothing newer on GitHub (latest version: {}).",
            ecrire(publiee)
        ),
        Verdict::Perimee(age) => {
            trp!(
                "  Non vérifié : la dernière version signée {age} ({}).\n  Rien de plus récent sur GitHub, mais rien ne prouve que ce soit\n  encore la dernière.",
                "  Not verified: the latest signed version {age} ({}).\n  Nothing newer on GitHub, but nothing proves it is still the latest.",
                ecrire(publiee)
            );
        }
        Verdict::PlusRecenteIci(v) => {
            trp!(
                "  Non vérifié : Vanguard {} tourne ici, plus récent que la dernière\n  version signée sur GitHub ({}) : un ancien manifeste a pu être\n  remis en place.",
                "  Not verified: Vanguard {} runs here, newer than the latest signed\n  version on GitHub ({}): an old manifest may have been put back.",
                ecrire(v),
                ecrire(publiee)
            );
        }
    }
}

/// Montre les deux versions et d'où vient la nouvelle, puis remplace la copie après un « o ».
fn proposer(source: &Path, cible: &Path, copie: Option<Version>, cle: Version) {
    let (ici, sur_la_cle) = match copie {
        Some(c) => cote_a_cote(c, cle),
        None => (version_affichee(None), ecrire(cle)),
    };
    trp!(
        "  Copie de cet ordinateur : {ici}\n  Clé VANGUARD           : {sur_la_cle}\n  {GRIS}Depuis {}{RESET}\n",
        "  Copy on this computer: {ici}\n  VANGUARD key         : {sur_la_cle}\n  {GRIS}From {}{RESET}\n",
        affichable(&source.display().to_string())
    );
    if !demander(tr!(
        "  La remplacer par celle de la clé ? [o/N] : ",
        "  Replace it with the key's? [y/N]: "
    ))
    .oui()
    {
        return;
    }
    match remplacer(source, cible, cle, TAILLE_MAX, essayer) {
        Ok(()) => trp!(
            "  {VERT}✔{RESET} Copie de cet ordinateur mise à jour : Vanguard {}.\n    La surveillance, l'entretien et le raccourci lancent cette version.",
            "  {VERT}✔{RESET} Copy on this computer updated: Vanguard {}.\n    Monitoring, maintenance and the shortcut start this version.",
            ecrire(cle)
        ),
        Err(e) => trp!(
            "  ✖ Copie non mise à jour, l'ancienne reste en place :\n    {}",
            "  ✖ Copy not updated, the old one stays in place:\n    {}",
            affichable(&e)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une copie posée par Vanguard (`installer`) renote l'empreinte de la tâche qui la lance : la mise à jour
    /// légitime ne se dit pas « remplacée hors de Vanguard ».
    #[test]
    fn copie_posee_renote_la_tache() {
        use crate::programmes_poses::{Tache, empreinte_notee};
        let racine = crate::socle::dossier_local().join("essai-renote");
        let _ = std::fs::remove_dir_all(&racine);
        std::fs::create_dir_all(&racine).unwrap();
        let (source, cible) = (racine.join("source"), racine.join(NOM));
        faux_programme(&cible, None);
        crate::programmes_poses::noter(Tache::Entretien, &cible, &Ok(b"[Service]".to_vec()));
        let avant = empreinte_notee(Tache::Entretien).expect("notée");
        faux_programme(&source, Some("0.81.0"));
        poser_copie_dans(&source, &cible, SANS_ESSAI).unwrap();
        let apres = empreinte_notee(Tache::Entretien).expect("notée");
        assert_ne!(avant, apres);
        assert_eq!(apres, crate::programmes_poses::empreinte_de(&cible).unwrap());
        crate::programmes_poses::oublier(Tache::Entretien);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// En root, un programme posé dans un dossier que son compte (ou n'importe qui) peut changer n'est pas remplacé :
    /// ce compte échangerait le nouveau entre sa relecture et l'essai que root lance.
    #[cfg(unix)]
    #[test]
    fn en_root_pas_de_remplacement_dans_un_dossier_d_un_compte() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = std::env::temp_dir().join(format!("vanguard-cible-root-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let exe = d.join("vanguard-linux-x86_64");
        // Hors de root : le compte ne risque que lui-même.
        assert!(remplacable_pour(1000, &exe));
        // Ouvert à tous (comme /tmp) : jamais en root.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!remplacable_pour(0, &exe));
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Le dossier d'un compte (le nôtre, qui n'est pas root ; sous `unshare -r`, il paraît à root).
        // SAFETY : getuid lit le compte du processus, sans argument.
        if unsafe { libc::getuid() } != 0 {
            assert!(!remplacable_pour(0, &exe));
        }
        // Un dossier sûr dans un dossier ouvert à tous : refusé quand même, celui du dessus se renomme. Sous
        // `unshare -r`, les deux paraissent à root, et seul le dossier du dessus le refuse.
        let sous = d.join("sous");
        std::fs::create_dir_all(&sous).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!remplacable_pour(0, &sous.join("vanguard-linux-x86_64")));
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Un chemin relatif ne dit rien des dossiers au-dessus : refusé.
        assert!(!remplacable_pour(0, Path::new("vanguard-linux-x86_64")));
        // Un vrai dossier de root (/usr/bin, peut-être par le lien /bin) : accepté, si root le possède ici (sous
        // `unshare -r`, il paraît au compte « nobody »).
        let systeme = Path::new("/usr/bin");
        if std::fs::metadata(systeme).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
            && std::fs::symlink_metadata("/usr").is_ok_and(|m| m.uid() == 0)
            && std::fs::symlink_metadata("/").is_ok_and(|m| m.uid() == 0)
        {
            assert!(remplacable_pour(0, &systeme.join("vanguard-linux-x86_64")));
            if std::fs::symlink_metadata("/bin").is_ok_and(|m| m.file_type().is_symlink() && m.uid() == 0) {
                assert!(remplacable_pour(0, Path::new("/bin/vanguard-linux-x86_64")));
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn versions_lues_et_comparees() {
        assert_eq!(lire_version("0.78.0"), Some((0, 78, 0, 0)));
        assert_eq!(lire_version("0.78.0+1760900000"), Some((0, 78, 0, 1_760_900_000)));
        assert_eq!(lire_version("0.78.0+x"), None);
        assert_eq!(lire_version("1.2"), None);
        assert_eq!(lire_version("1.2.3.4"), None);
        assert_eq!(lire_version("1.x.3"), None);
        // Comparées comme des nombres : 0.100 vient après 0.99 ; à numéro égal, le commit le plus récent l'emporte, et
        // le numéro passe toujours avant la date.
        assert!((0, 100, 0, 0) > (0, 99, 9, 0));
        assert!((0, 78, 0, 2) > (0, 78, 0, 1));
        assert!((0, 79, 0, 1) > (0, 78, 0, 9));
        // La version gravée est bien celle du paquet, avec la date de son commit : sans quoi rien ne serait proposé.
        let numero = |v: Option<Version>| v.map(|v| (v.0, v.1, v.2));
        assert_eq!(numero(courante()), numero(lire_version(env!("CARGO_PKG_VERSION"))));
        assert_eq!(
            courante().map(|v| v.3.to_string()).as_deref(),
            Some(env!("VANGUARD_COMMIT_SECONDES"))
        );
    }

    /// Une dernière version signée de plus de 45 jours n'est plus « à jour » : le nombre de jours est dit.
    #[test]
    fn a_jour_seulement_si_la_signee_est_recente() {
        let jour = 86_400;
        let v = (0, 85, 0, 1_792_540_000);
        assert_eq!(verdict(v, &[], v.3 + 45 * jour), Verdict::AJour);
        let Verdict::Perimee(dit) = verdict(v, &[], v.3 + 46 * jour) else {
            panic!("46 jours : périmée");
        };
        assert!(dit.contains("46"), "{dit}");
        assert!(matches!(verdict((0, 85, 0, 0), &[], v.3), Verdict::Perimee(_)));
        // Horloge revenue en 2020 : l'âge est inconnu, jamais « à jour ».
        assert!(matches!(verdict(v, &[], 1_577_836_800), Verdict::Perimee(_)));
        // Une heure de décalage juste après la publication : à jour.
        assert_eq!(verdict(v, &[], v.3 - 3_600), Verdict::AJour);
    }

    /// Une copie passée à la 0.86 par la clé, et GitHub qui rend le manifeste de la 0.85 : jamais la coche verte.
    #[test]
    fn une_copie_plus_recente_que_github_n_est_pas_a_jour() {
        let v = (0, 85, 0, 1_792_540_000);
        let ici = (0, 86, 0, 1_792_600_000);
        assert_eq!(verdict(v, &[ici, v], v.3), Verdict::PlusRecenteIci(ici));
        // Même numéro : à jour, même si la compilation d'ici est plus récente (développement).
        assert_eq!(verdict(v, &[(0, 85, 0, 1_792_700_000)], v.3), Verdict::AJour);
        assert_eq!(verdict(v, &[(0, 84, 2, 1)], v.3), Verdict::AJour);
    }

    #[test]
    fn deux_compilations_d_un_meme_numero_se_distinguent_par_la_date() {
        let (a, b) = cote_a_cote((0, 78, 0, 0), (0, 79, 0, 5));
        assert_eq!((a.as_str(), b.as_str()), ("0.78.0", "0.79.0"));
        let (a, b) = cote_a_cote((0, 78, 0, 5), (0, 78, 0, 5));
        assert_eq!((a.as_str(), b.as_str()), ("0.78.0", "0.78.0"));
        let (a, b) = cote_a_cote((0, 78, 0, 1_760_000_000), (0, 78, 0, 1_760_900_000));
        assert!(
            a.starts_with("0.78.0 (") && b.starts_with("0.78.0 (") && a != b,
            "{a} / {b}"
        );
    }

    /// Un contenu de programme avec l'en-tête de la version gravée : construit au lancement, jamais écrit tel quel
    /// dans le code, sans quoi le programme des tests porterait ces fausses versions et la recherche les prendrait.
    fn avec_entete(avant: &str, apres: &str) -> Vec<u8> {
        [avant.as_bytes(), &entete(), apres.as_bytes()].concat()
    }

    #[test]
    fn version_gravee_dans_un_programme() {
        // L'en-tête seul, suivi d'autre chose, ne compte pas ; la vraie version, oui.
        let mut octets = avec_entete("\x00\x7fELF...", "\x00abc...");
        octets.extend(avec_entete("", ""));
        octets.extend(avec_entete("", "0.81.2+x;..."));
        octets.extend(avec_entete("", "0.81.2+1760900000;..."));
        assert_eq!(version_gravee(&octets), Some((0, 81, 2, 1_760_900_000)));
        assert_eq!(version_gravee(&avec_entete("", "0.81.2;")), Some((0, 81, 2, 0)));
        // Une copie d'avant la 0.78 : pas de version.
        assert_eq!(version_gravee(b"\x7fELF un vieux programme"), None);
        // Tronquée, ou sans « ; » : rien.
        assert_eq!(version_gravee(&avec_entete("", "0.81")), None);
        assert_eq!(version_gravee(&avec_entete("", "0.81.2")), None);
        assert_eq!(version_gravee(b""), None);
    }

    /// Le programme des tests porte sa version, lisible sans le lancer, et aucune autre (le programme publié non plus :
    /// l'en-tête n'est écrit en clair qu'une fois, dans la version gravée).
    #[test]
    fn ce_programme_porte_sa_version() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(lire_programme(&exe, TAILLE_MAX), Lu::Version(courante().unwrap()));
    }

    /// Un faux programme : son contenu, avec sa version gravée (ou sans, pour une copie d'avant la 0.78).
    fn faux_programme(chemin: &Path, version: Option<&str>) {
        std::fs::create_dir_all(chemin.parent().unwrap()).unwrap();
        let contenu = version.map_or_else(
            || b"ancien programme".to_vec(),
            |v| avec_entete("prog ", &format!("{v}; fin")),
        );
        std::fs::write(chemin, contenu).unwrap();
    }

    #[test]
    fn ce_que_dit_le_menu_selon_la_copie() {
        let racine = crate::socle::dossier_local().join("essai-mise-a-jour");
        let _ = std::fs::remove_dir_all(&racine);
        let cle = racine.join("cle");
        let sur_la_cle = cle.join("Linux").join(NOM);
        let copie = racine.join("ordinateur").join("bin").join(NOM);
        let v = (0, 78, 0, 0);
        let etat =
            |exe: &Path, cle_du_programme: Option<&Path>| etat_de(exe, cle_du_programme, &copie, Some(v), TAILLE_MAX);
        faux_programme(&sur_la_cle, Some("0.78.0"));

        // Pas de copie sur l'ordinateur : rien à dire.
        assert_eq!(etat(&sur_la_cle, Some(&cle)), Etat::Rien);
        // Lancé depuis la clé, copie d'avant la 0.78 : à mettre à jour depuis le programme qui tourne.
        faux_programme(&copie, None);
        assert_eq!(
            etat(&sur_la_cle, Some(&cle)),
            Etat::AMettreAJour {
                source: sur_la_cle.clone(),
                copie: None,
                cle: v
            }
        );
        // Copie à la même version : à jour ; plus récente : la clé est à remettre à jour, jamais de retour en arrière.
        faux_programme(&copie, Some("0.78.0"));
        assert_eq!(etat(&sur_la_cle, Some(&cle)), Etat::AJour(v));
        faux_programme(&copie, Some("0.79.0"));
        assert_eq!(
            etat(&sur_la_cle, Some(&cle)),
            Etat::ClePlusAncienne {
                copie: (0, 79, 0, 0),
                cle: v
            }
        );
        // Même numéro : le commit le plus récent l'emporte (compilations entre deux publications).
        faux_programme(&copie, Some("0.78.0+5"));
        let plus_tard = (0, 78, 0, 9);
        assert!(matches!(
            etat_de(&sur_la_cle, Some(&cle), &copie, Some(plus_tard), TAILLE_MAX),
            Etat::AMettreAJour {
                copie: Some((0, 78, 0, 5)),
                ..
            }
        ));
        assert!(matches!(
            etat_de(&sur_la_cle, Some(&cle), &copie, Some((0, 78, 0, 1)), TAILLE_MAX),
            Etat::ClePlusAncienne { .. }
        ));
        // Lancé depuis la copie, ou d'ailleurs : la mise à jour se fait depuis la clé, jamais depuis un volume
        // seulement branché.
        assert_eq!(etat(&copie, None), Etat::PasDepuisLaCle);
        assert_eq!(etat(&racine.join("ailleurs").join(NOM), None), Etat::PasDepuisLaCle);
        // Sans version lisible pour ce programme : rien n'est proposé.
        assert_eq!(etat_de(&sur_la_cle, Some(&cle), &copie, None, TAILLE_MAX), Etat::Rien);
        // Une copie qui ne se lit pas (ici un dossier, ou démesurée) est dite, jamais comptée comme à jour. Chaque cas
        // a son chemin : sous Windows, un nom tout juste supprimé reste pris tant qu'un autre programme (Defender,
        // Wine) tient le fichier ouvert, et le recréer aussitôt échouait parfois.
        let en_dossier = racine.join("ordinateur-dossier").join(NOM);
        std::fs::create_dir_all(&en_dossier).unwrap();
        assert!(matches!(
            etat_de(&sur_la_cle, Some(&cle), &en_dossier, Some(v), TAILLE_MAX),
            Etat::Illisible(_)
        ));
        let demesuree = racine.join("ordinateur-demesure").join(NOM);
        faux_programme(&demesuree, Some("0.70.0"));
        assert!(matches!(
            etat_de(&sur_la_cle, Some(&cle), &demesuree, Some(v), 4),
            Etat::Illisible(_)
        ));
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Une copie posée ou remplacée pendant la session (surveillance activée) fait relire l'état ; sinon il est gardé.
    #[test]
    fn l_etat_suit_la_copie() {
        let memoire = Memoire::new();
        let premiere = Some((10, SystemTime::UNIX_EPOCH));
        assert_eq!(
            memoire.lire(premiere, || Etat::AJour((0, 1, 0, 0))),
            Etat::AJour((0, 1, 0, 0))
        );
        assert_eq!(
            memoire.lire(premiere, || unreachable!("gardé")),
            Etat::AJour((0, 1, 0, 0))
        );
        assert_eq!(
            memoire.lire(Some((11, SystemTime::UNIX_EPOCH)), || Etat::Rien),
            Etat::Rien
        );
        assert_eq!(memoire.lire(None, || Etat::PasDepuisLaCle), Etat::PasDepuisLaCle);
    }

    #[test]
    fn la_copie_remplacee_d_un_coup() {
        let racine = crate::socle::dossier_local().join("essai-remplacement");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0"));
        faux_programme(&cible, None);
        remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX, SANS_ESSAI).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&cible).unwrap().permissions().mode() & 0o777, 0o755);
        }
        // La clé a changé depuis l'affichage (une autre version) : rien n'est remplacé.
        faux_programme(&cible, Some("0.70.0"));
        faux_programme(&source, Some("0.69.0"));
        assert!(remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX, SANS_ESSAI).is_err());
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 70, 0, 0)));
        // Une source absente ou démesurée : l'ancienne copie reste, rien ne traîne à côté.
        assert!(remplacer(&racine.join("absente"), &cible, (0, 80, 0, 0), TAILLE_MAX, SANS_ESSAI).is_err());
        faux_programme(&source, Some("0.80.0"));
        assert!(remplacer(&source, &cible, (0, 80, 0, 0), 4, SANS_ESSAI).is_err());
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 70, 0, 0)));
        assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Les faux programmes des tests ne se lancent pas : l'essai réel a son propre test.
    const SANS_ESSAI: Essai = |_, _| Ok(());

    fn essai_rate(_: &Path, _: Version) -> Result<(), String> {
        Err("ne démarre pas".into())
    }

    /// La copie posée pour la surveillance passe par les mêmes garde-fous que la mise à jour : jamais par-dessus une
    /// plus récente, jamais si l'essai échoue, rien qui traîne à côté.
    #[test]
    fn copie_locale_par_le_chemin_sur() {
        let racine = crate::socle::dossier_local().join("essai-copie-locale");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0+5"));
        // Pas encore de copie : posée.
        poser_copie_dans(&source, &cible, SANS_ESSAI).unwrap();
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 80, 0, 5)));
        // Une copie plus récente que la clé : gardée telle quelle (une vieille clé ne fait pas revenir en arrière).
        faux_programme(&cible, Some("0.81.0+1"));
        poser_copie_dans(&source, &cible, SANS_ESSAI).unwrap();
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 81, 0, 1)));
        // Une copie plus ancienne : remplacée, sauf si la nouvelle ne démarre pas.
        faux_programme(&cible, Some("0.79.0+1"));
        assert!(poser_copie_dans(&source, &cible, essai_rate).is_err());
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 79, 0, 1)));
        assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
        poser_copie_dans(&source, &cible, SANS_ESSAI).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        // Une source sans version gravée : rien n'est posé.
        faux_programme(&source, None);
        assert!(poser_copie_dans(&source, &cible, SANS_ESSAI).is_err());
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// L'essai lance vraiment le programme : il doit finir sans erreur en disant la version attendue.
    #[cfg(unix)]
    #[test]
    fn essai_de_la_nouvelle_copie() {
        use std::os::unix::fs::PermissionsExt;
        let racine = crate::socle::dossier_local().join("essai-demarrage");
        std::fs::create_dir_all(&racine).unwrap();
        let script = |nom: &str, corps: &str| {
            let f = racine.join(nom);
            std::fs::write(&f, format!("#!/bin/sh\n{corps}\n")).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            f
        };
        let bon = script("bon", r#"[ "$1" = --version ] && echo "vanguard 0.80.0""#);
        assert_eq!(essayer(&bon, (0, 80, 0, 5)), Ok(()));
        assert!(essayer(&bon, (0, 81, 0, 5)).is_err());
        assert!(essayer(&script("plante", "echo vanguard 0.80.0; exit 3"), (0, 80, 0, 5)).is_err());
        let texte = racine.join("pas-un-programme");
        std::fs::write(&texte, "rien").unwrap();
        assert!(essayer(&texte, (0, 80, 0, 5)).is_err());
        let _ = std::fs::remove_dir_all(&racine);
    }
}
