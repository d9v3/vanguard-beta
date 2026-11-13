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

// Le programme sous Linux : ses parties Windows ne sont pas encore relues, et les essais en sont exemptés
// (y déborder fait échouer l'essai). L'en-tête vaut aussi pour les sous-modules.
#![cfg_attr(
    all(target_os = "linux", not(test)),
    warn(clippy::arithmetic_side_effects, clippy::as_conversions)
)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::ui::*;

pub(crate) mod apercu;
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
    std::hint::black_box(ENTETE_DECALE).map(|o| o.saturating_sub(1))
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
        let Some(apres) = reste.get(i.saturating_add(entete.len())..) else {
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
    f.take(max.saturating_add(1))
        .read_to_end(&mut octets)
        .map_err(|e| e.to_string())?;
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
        remplacable_pour(crate::socle::euid(), programme)
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

/// La version publiée et signée de ce système dont le programme a l'empreinte `sha256`, d'après l'historique signé ;
/// `Ok(None)` : il n'y est pas, ou seulement pour un autre système.
#[cfg(target_os = "linux")]
pub(crate) fn version_signee_ici(sha256: &[u8; 32]) -> Result<Option<String>, crate::modele::Echec> {
    let ici = systeme_publie(github::systeme())?;
    let vue = version_signee(sha256).map_err(|e| crate::modele::Echec::echoue("mise_a_jour/historique", e))?;
    Ok(vue.and_then(|(v, s)| (s == ici).then_some(v)))
}

/// Le système d'ici tel que l'historique le nomme ; aucun : refusé avant de lire l'historique, sans quoi tout
/// programme passerait pour « ni posé ni signé » et le geste échouerait après le oui.
#[cfg(target_os = "linux")]
fn systeme_publie(ici: Option<&'static str>) -> Result<&'static str, crate::modele::Echec> {
    ici.ok_or_else(|| {
        crate::modele::Echec::echoue(
            "mise_a_jour/historique",
            tr!(
                "pas de version publiée pour ce système",
                "no published version for this system"
            ),
        )
    })
}

/// Lot D7b, « Refaire » (`machine::defense_eleve`) : un programme de Vanguard publié et signé par l'auteur, à remettre
/// à la place d'un programme de tâche remplacé hors de Vanguard ; (version, octets). Ce Vanguard-ci, s'il est dans
/// l'historique signé pour ce système ; sinon la dernière version publiée, manifeste vérifié (Ed25519), jamais plus
/// vieille que ce Vanguard-ci, téléchargée en mémoire, taille et empreinte signées, version gravée relue. Rien n'est
/// écrit, ni sur le disque ni dans les sceaux ; l'appelant revérifie les octets dans l'historique signé.
#[cfg(target_os = "linux")]
pub(crate) fn programme_signe_a_remettre() -> Result<(String, Vec<u8>), crate::modele::Echec> {
    use crate::modele::Echec;
    use sha2::{Digest, Sha256};
    let ici =
        lire_octets(Path::new("/proc/self/exe"), TAILLE_MAX).map_err(|e| Echec::echoue("mise_a_jour/remise", e))?;
    let e: [u8; 32] = Sha256::digest(&ici).into();
    if let Some(v) = version_signee_ici(&e)? {
        return Ok((v, ici));
    }
    let courante = courante().ok_or_else(|| {
        Echec::echoue(
            "mise_a_jour/remise",
            tr!(
                "la version de ce Vanguard ne se lit pas",
                "this Vanguard's version cannot be read"
            ),
        )
    })?;
    let p = github::derniere_recue()?;
    if p.version < courante {
        return Err(Echec::refuse(
            "mise_a_jour/remise",
            trf!(
                "la dernière version publiée ({}) est plus vieille que ce Vanguard ({}) : refusée",
                "the latest published version ({}) is older than this Vanguard ({}): refused",
                ecrire(p.version),
                ecrire(courante)
            ),
        ));
    }
    let octets = github::programme_verifie(&p).map_err(|e| Echec::echoue("mise_a_jour/remise", e))?;
    if version_gravee(&octets) != Some(p.version) {
        return Err(Echec::refuse(
            "mise_a_jour/remise",
            tr!(
                "le programme reçu ne porte pas la version signée : refusé",
                "the received program does not carry the signed version: refused"
            ),
        ));
    }
    Ok((ecrire(p.version), octets))
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
    // La copie provisoire est tenue par son descripteur du début à la fin (G-2, campagne 0.95) : par son seul nom,
    // un programme du compte pouvait l'échanger entre la relecture et le renommage, et « fait » était dit sur un
    // autre fichier. Relue, essayée et revérifiée par le descripteur ; après le renommage, la cible doit être ce
    // même fichier, avec ces mêmes octets.
    let ecrite = (|| -> Result<(), String> {
        // Avant le renommage, rien n'est remplacé : chaque échec le dit (l'appelant ne dit plus « l'ancien reste »).
        let rien = |e: String| format!("{e} : {}", tr!("rien n'est remplacé", "nothing is replaced"));
        let _ = std::fs::remove_file(&provisoire);
        let f = ecrire_provisoire(&provisoire, octets).map_err(|e| {
            // R-4 (recontrôle 0.95) : un dossier (ou autre chose qui ne s'efface pas) sous ce nom ; dit avec le chemin
            // à retirer, jamais « File exists » seul.
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                rien(nom_occupe(&provisoire))
            } else {
                rien(e.to_string())
            }
        })?;
        if !meme_contenu(&f, octets).map_err(|e| rien(e.to_string()))? {
            return Err(rien(
                tr!("la copie relue ne correspond pas", "the copy read back does not match").into(),
            ));
        }
        essai(&chemin_de(&f, &provisoire), attendue)?;
        if !meme_contenu(&f, octets).map_err(|e| rien(e.to_string()))? {
            return Err(tr!(
                "la copie provisoire a changé pendant l'essai (un autre programme) : rien n'est remplacé",
                "the temporary copy changed during the test (another program): nothing is replaced"
            )
            .into());
        }
        // R-1 (recontrôle 0.95) : l'ancienne copie est mise de côté avant le renommage (un second nom, sans copie),
        // pour être remise si la copie posée n'est pas la montrée. Avant, l'échec laissait le fichier inconnu en place
        // et l'appelant disait « l'ancien reste en place ». N-1 (recontrôle 2, 0.95) : une ancienne copie qui ne se met
        // pas de côté arrête tout ici, avant le renommage ; avant, la mise à jour continuait sans rien à remettre, et
        // un nom de côté pris par un dossier suffisait à laisser installée la copie échangée (que l'entretien du mois
        // lance seul).
        let precedente = Precedente::retenir(cible).map_err(rien)?;
        let posee = mettre_en_place(&provisoire, cible)
            .map_err(|e| e.to_string())
            .and_then(|()| match posee_est_la_montree(&f, cible, octets) {
                Ok(true) => Ok(()),
                Ok(false) => Err(tr!(
                    "la copie posée n'est pas celle qui a été montrée (changée pendant la mise à jour par un autre programme)",
                    "the installed copy is not the one that was shown (changed during the update by another program)"
                )
                .to_string()),
                Err(e) => Err(e.to_string()),
            });
        match posee {
            Ok(()) => {
                precedente.oublier();
                Ok(())
            }
            Err(e) => Err(format!("{e} : {}", precedente.remettre(cible))),
        }
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

/// La copie provisoire créée neuve (O_EXCL : un lien posé à ce nom n'est jamais suivi, l'écriture échoue plutôt),
/// écrite, mise sur le disque, ses droits donnés par le descripteur. Sous Linux, rouverte en lecture seule par son
/// descripteur (`/proc/self/fd`, le même fichier même si le nom a changé) et le descripteur d'écriture fermé : un
/// programme ouvert en écriture ne se lance pas (ETXTBSY), et l'essai passe par ce descripteur.
fn ecrire_provisoire(provisoire: &Path, octets: &[u8]) -> std::io::Result<std::fs::File> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(provisoire)?;
    f.write_all(octets).and_then(|()| f.sync_all())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let lecture = std::fs::File::open(format!("/proc/self/fd/{}", f.as_raw_fd())).map_err(|e| {
            std::io::Error::other(trf!(
                "copie provisoire pas rouverte par son descripteur (/proc) : {e}",
                "temporary copy not reopened through its descriptor (/proc): {e}"
            ))
        })?;
        drop(f);
        Ok(lecture)
    }
    // Sous Windows, rouverte en lecture par son nom, en refusant l'écriture aux autres tant qu'elle est tenue
    // (FILE_SHARE_READ | FILE_SHARE_DELETE : sans le partage de suppression, le renommage échouerait). Un autre
    // programme qui l'aurait déjà ouverte en écriture fait échouer l'ouverture ; ce qui est ouvert est relu ensuite.
    #[cfg(windows)]
    {
        drop(f);
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, 1 | 4);
        options.open(provisoire)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    Ok(f)
}

/// Le chemin par lequel l'essai lance la copie provisoire : sous Linux, son descripteur (`/proc/self/fd/N`, hérité
/// par le processus lancé jusqu'à son exec), jamais le nom, qu'un autre programme peut échanger ; ailleurs, le nom.
fn chemin_de(f: &std::fs::File, provisoire: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let _ = provisoire;
        PathBuf::from(format!("/proc/self/fd/{}", f.as_raw_fd()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = f;
        provisoire.to_path_buf()
    }
}

/// Le fichier ouvert `f` contient-il exactement `octets` ? Relu depuis le début, jamais plus d'un octet de trop.
fn meme_contenu(mut f: &std::fs::File, octets: &[u8]) -> std::io::Result<bool> {
    use std::io::{Read, Seek};
    f.seek(std::io::SeekFrom::Start(0))?;
    let mut lu = Vec::with_capacity(octets.len());
    let borne = u64::try_from(octets.len()).unwrap_or(u64::MAX).saturating_add(1);
    f.take(borne).read_to_end(&mut lu)?;
    Ok(lu == octets)
}

/// L'ancienne copie, mise de côté sous un second nom (`<NOM>.precedent`, lien physique : rien n'est copié) juste avant
/// le renommage, avec ce qui la reconnaît : remise si la copie posée n'est pas la montrée (R-1, recontrôle 0.95).
struct Precedente {
    de_cote: PathBuf,
    /// `Aucune` : pas de copie avant. `Retenue` : mise de côté, avec ce qui la reconnaît. Il n'y a pas d'entre-deux :
    /// une copie qui ne se met pas de côté arrête la mise à jour (`retenir`).
    etat: EtatPrecedente,
}

enum EtatPrecedente {
    Aucune,
    Retenue(Identite),
}

/// Un nom dont Vanguard a besoin, pris par quelque chose qu'il n'efface pas (R-4 et N-1, recontrôles 0.95) : le chemin
/// à retirer et quoi faire, jamais « File exists » seul.
fn nom_occupe(chemin: &Path) -> String {
    trf!(
        "{} existe déjà et Vanguard ne l'efface pas (un dossier ?) : retirez-le, puis relancez la mise à jour",
        "{} already exists and Vanguard does not delete it (a folder?): remove it, then run the update again",
        affichable(&chemin.display().to_string())
    )
}

/// Ce qui reconnaît un fichier : appareil et inode sous Unix ; ses octets ailleurs (Windows : l'identité du fichier
/// demanderait l'API de Windows).
#[derive(PartialEq, Eq)]
struct Identite(#[cfg(unix)] (u64, u64), #[cfg(not(unix))] Vec<u8>);

fn identite(chemin: &Path) -> Option<Identite> {
    let m = std::fs::symlink_metadata(chemin).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(Identite((m.dev(), m.ino())))
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        lire_octets(chemin, TAILLE_MAX).ok().map(Identite)
    }
}

impl Precedente {
    /// L'ancienne copie mise de côté, ou pourquoi elle ne peut pas l'être : l'appelant refuse alors avant le
    /// renommage (N-1, recontrôle 2 0.95), jamais un remplacement sans copie à remettre.
    fn retenir(cible: &Path) -> Result<Self, String> {
        let de_cote = cible.with_file_name(format!("{NOM}.precedent"));
        let pas_de_cote = |pourquoi: &dyn std::fmt::Display| {
            trf!(
                "l'ancienne copie ne se met pas de côté sous {} ({pourquoi}), et ne pourrait donc pas être remise",
                "the old copy cannot be set aside as {} ({pourquoi}), so it could not be put back",
                affichable(&de_cote.display().to_string())
            )
        };
        let etat = match std::fs::symlink_metadata(cible) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => EtatPrecedente::Aucune,
            Err(e) => {
                return Err(trf!(
                    "la copie en place ne se lit pas ({}) : {e}",
                    "the copy in place cannot be read ({}): {e}",
                    affichable(&cible.display().to_string())
                ));
            }
            Ok(_) => {
                // Le reste d'une mise à jour interrompue ; un dossier à ce nom ne s'efface pas, et le lien échoue.
                let _ = std::fs::remove_file(&de_cote);
                match std::fs::hard_link(cible, &de_cote) {
                    Ok(()) => match identite(&de_cote) {
                        Some(i) => EtatPrecedente::Retenue(i),
                        None => {
                            let _ = std::fs::remove_file(&de_cote);
                            return Err(pas_de_cote(&tr!("pas relue", "not read back")));
                        }
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(nom_occupe(&de_cote)),
                    Err(e) => return Err(pas_de_cote(&e)),
                }
            }
        };
        Ok(Self { de_cote, etat })
    }

    /// La mise à jour est faite : le second nom part (l'ancienne copie, elle, n'existe plus que là).
    fn oublier(self) {
        if matches!(self.etat, EtatPrecedente::Retenue(_)) {
            let _ = std::fs::remove_file(&self.de_cote);
        }
    }

    /// La copie posée n'est pas la montrée (ou le renommage a échoué) : remettre l'ancienne, ou retirer ce qui est
    /// posé s'il n'y en avait pas. Rend ce qui est en place, vérifié après coup : jamais « l'ancienne » sans l'avoir
    /// reconnue à `cible`.
    fn remettre(self, cible: &Path) -> String {
        let ni_l_une_ni_l_autre = || {
            format!(
                "{} {}",
                tr!(
                    "la copie en place n'est ni l'ancienne ni celle montrée : ne la lancez pas, refaites la mise à jour.",
                    "the copy in place is neither the old one nor the one shown: do not run it, redo the update."
                ),
                affichable(&cible.display().to_string())
            )
        };
        match self.etat {
            EtatPrecedente::Retenue(avant) => {
                // Le renommage a échoué sans rien toucher : l'ancienne n'a pas bougé.
                if identite(cible).as_ref() == Some(&avant) {
                    let _ = std::fs::remove_file(&self.de_cote);
                    return tr!("l'ancienne copie reste en place", "the old copy stays in place").into();
                }
                // N-3 (recontrôle 2, 0.95) : le second nom n'est effacé qu'une fois l'ancienne reconnue à `cible`.
                // Avant, il l'était même si la remise avait échoué : la seule ancienne copie qui restait était perdue.
                match std::fs::rename(&self.de_cote, cible) {
                    Ok(()) if identite(cible).as_ref() == Some(&avant) => {
                        // Deux noms d'un même fichier : le renommage ne fait rien (POSIX) et le second nom reste.
                        if identite(&self.de_cote).as_ref() == Some(&avant) {
                            let _ = std::fs::remove_file(&self.de_cote);
                        }
                        tr!(
                            "l'ancienne copie est remise en place",
                            "the old copy is put back in place"
                        )
                        .into()
                    }
                    Ok(()) => ni_l_une_ni_l_autre(),
                    Err(e) => trf!(
                        "l'ancienne copie n'est pas remise ({e}), elle est gardée sous {} ; {}",
                        "the old copy is not put back ({e}), it is kept as {}; {}",
                        affichable(&self.de_cote.display().to_string()),
                        ni_l_une_ni_l_autre()
                    ),
                }
            }
            EtatPrecedente::Aucune => {
                let _ = std::fs::remove_file(cible);
                match std::fs::symlink_metadata(cible) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => tr!(
                        "aucune copie n'est posée, relancez la mise à jour",
                        "no copy is in place, run the update again"
                    )
                    .into(),
                    _ => ni_l_une_ni_l_autre(),
                }
            }
        }
    }
}

/// Après le renommage : `cible` est-elle bien la copie écrite (`f`) avec les octets montrés ? Sous Unix, ouverte
/// sans suivre de lien, le même fichier (appareil et inode) que `f`, puis relue. Sous Windows, relue par une poignée
/// qui refuse l'écriture et la suppression aux autres le temps de la lecture (l'identité du fichier n'y est pas
/// comparée : il faudrait l'API de Windows ; les octets, eux, le sont). Faux si elle ne s'ouvre pas ainsi, ou n'est
/// pas ce fichier avec ces octets : jamais « fait » sur un autre fichier.
fn posee_est_la_montree(f: &std::fs::File, cible: &Path, octets: &[u8]) -> std::io::Result<bool> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    // FILE_SHARE_READ seul.
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, 1);
    let Ok(posee) = options.open(cible) else {
        return Ok(false);
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (a, b) = (f.metadata()?, posee.metadata()?);
        if !b.is_file() || a.dev() != b.dev() || a.ino() != b.ino() {
            return Ok(false);
        }
    }
    #[cfg(not(unix))]
    let _ = f;
    meme_contenu(&posee, octets)
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
    let mut c = std::process::Command::new(programme);
    // Ni LD_PRELOAD ni le reste de l'environnement du compte ne choisissent ce que la copie répond (G-1).
    #[cfg(unix)]
    crate::commande::environnement_lecture(&mut c, std::env::vars_os());
    let r = crate::commande::lancer_borne_ou_pourquoi(c.arg("--version").env("VANGUARD_HORS_LIGNE", "1"), 30, 64 << 10);
    match r {
        Ok(r) if r.code == Some(0) && r.sortie.split_whitespace().any(|m| m == ecrire(attendue)) => Ok(()),
        // R-3 (recontrôle 0.95) : l'ordinateur n'y est pour rien, c'est dit.
        Err(Some(e)) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => Err(tr!(
            "la nouvelle copie est tenue ouverte en écriture par un autre programme (« Text file busy ») : elle ne se lance pas, l'ancienne reste en place ; relancez la mise à jour quand ce programme l'aura lâchée",
            "the new copy is held open for writing by another program (“Text file busy”): it does not start, the old one stays in place; run the update again once that program lets go of it"
        )
        .into()),
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
                "  ✖ {} n'est pas mis à jour :\n    {}",
                "  ✖ {} is not updated:\n    {}",
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
            "  ✖ Copie non mise à jour :\n    {}",
            "  ✖ Copy not updated:\n    {}",
            affichable(&e)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Relecture D7b : sans version publiée pour ce système, refusé (avant de lire l'historique, dans
    /// `version_signee_ici`) ; ici, le système publié.
    #[cfg(target_os = "linux")]
    #[test]
    fn version_signee_pour_ce_systeme_seulement() {
        assert!(systeme_publie(None).is_err());
        assert_eq!(systeme_publie(Some("linux-x86_64")), Ok("linux-x86_64"));
        assert_eq!(github::systeme(), Some("linux-x86_64"));
    }

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
        let d = crate::essais::temporaire().join(format!("vanguard-cible-root-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let exe = d.join("vanguard-linux-x86_64");
        // Hors de root : le compte ne risque que lui-même.
        assert!(remplacable_pour(1000, &exe));
        // Les refus qui suivent tiennent aussi au propriétaire, ici jamais root : hors de `unshare -r`, `d` est au
        // compte des tests ; dedans, il paraît à root, mais le dossier temporaire (à root pour de vrai) paraît au
        // compte « nobody ». Ils gardent le sens du résultat ; le droit d'écriture des autres, seul, est essayé plus
        // bas, sur le dossier temporaire du système quand root le possède.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!remplacable_pour(0, &exe));
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!remplacable_pour(0, &exe));
        let sous = d.join("sous");
        std::fs::create_dir_all(&sous).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!remplacable_pour(0, &sous.join("vanguard-linux-x86_64")));
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Un dossier de root ouvert à tous (/tmp, 1777) : refusé pour ses seuls droits, n'importe quel compte y
        // renommerait le programme.
        let ouvert = Path::new("/tmp");
        if std::fs::symlink_metadata(ouvert).is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o002 != 0)
            && std::fs::symlink_metadata("/").is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
        {
            assert!(!remplacable_pour(0, &ouvert.join("vanguard-linux-x86_64")));
        }
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

    /// Le dossier de l'essai d'échange en cours (G-2) : `Essai` est un simple `fn`, sans capture.
    static ECHANGE: Mutex<Option<PathBuf>> = Mutex::new(None);
    /// Tenu par chaque essai qui pose `ECHANGE` : les essais tournent en parallèle.
    static UN_A_LA_FOIS: Mutex<()> = Mutex::new(());

    fn dossier_de_l_echange() -> PathBuf {
        ECHANGE.lock().unwrap().clone().expect("dossier de l'échange posé")
    }

    /// Un programme du compte remplace la copie provisoire par son nom, juste après l'essai : un autre fichier, qui
    /// porte la bonne version.
    const ECHANGE_PAR_LE_NOM: Essai = |_, _| {
        let provisoire = dossier_de_l_echange().join(format!("{NOM}.nouveau"));
        match std::fs::remove_file(&provisoire) {
            // Sous Windows (Wine), l'effacement d'un fichier tenu reste en attente : le nom n'est pas libéré, et
            // l'écriture du faux est refusée.
            Ok(()) => match std::fs::write(&provisoire, avec_entete("faux ", "0.80.0; autre chose")) {
                Ok(()) => REECRITE.store(true, std::sync::atomic::Ordering::SeqCst),
                Err(e) if cfg!(windows) && e.raw_os_error() == Some(32) => {}
                Err(e) => panic!("{e}"),
            },
            // ERROR_SHARING_VIOLATION : refusé tant que la mise à jour tient la copie.
            Err(e) if cfg!(windows) && e.raw_os_error() == Some(32) => {}
            Err(e) => panic!("{e}"),
        }
        Ok(())
    };

    /// L'échange ou la réécriture a-t-il pu se faire ? Sous Windows, la poignée tenue par la mise à jour le refuse.
    static REECRITE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// Ou il réécrit le même fichier, en place, juste après l'essai.
    const REECRITE_EN_PLACE: Essai = |_, _| {
        use std::io::Write;
        let provisoire = dossier_de_l_echange().join(format!("{NOM}.nouveau"));
        match std::fs::OpenOptions::new().write(true).open(&provisoire) {
            Ok(mut f) => {
                f.write_all(b"FAUX").unwrap();
                REECRITE.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            // ERROR_SHARING_VIOLATION : refusée tant que la mise à jour tient la copie.
            Err(e) if cfg!(windows) && e.raw_os_error() == Some(32) => {}
            Err(e) => panic!("{e}"),
        }
        Ok(())
    };

    /// G-2 (campagne 0.95) : la copie provisoire échangée ou réécrite entre l'essai et la mise en place. Avant, la
    /// mise à jour disait « fait » et la copie installée était le faux fichier. Maintenant : réécrite avant la mise en
    /// place, rien n'est remplacé ; échangée par son nom, la copie posée n'est pas reconnue et c'est un échec dit.
    #[test]
    fn copie_provisoire_changee_avant_la_mise_en_place_jamais_dite_faite() {
        let racine = crate::socle::dossier_local().join("essai-echange-provisoire");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0"));
        let montre = std::fs::read(&source).unwrap();
        let _seul = UN_A_LA_FOIS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *ECHANGE.lock().unwrap() = Some(racine.join("bin"));

        faux_programme(&cible, Some("0.79.0"));
        let avant = std::fs::read(&cible).unwrap();
        REECRITE.store(false, std::sync::atomic::Ordering::SeqCst);
        let r = remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX, REECRITE_EN_PLACE);
        if REECRITE.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(r.is_err(), "réécrite en place, et dite faite");
            assert_eq!(std::fs::read(&cible).unwrap(), avant, "l'ancienne copie n'est plus là");
        } else {
            // Windows : la réécriture refusée, la copie montrée est posée telle quelle.
            assert_eq!(std::env::consts::OS, "windows", "réécriture ni faite ni refusée");
            assert_eq!(r, Ok(()));
            assert_eq!(std::fs::read(&cible).unwrap(), montre);
            faux_programme(&cible, Some("0.79.0"));
        }

        REECRITE.store(false, std::sync::atomic::Ordering::SeqCst);
        let r = remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX, ECHANGE_PAR_LE_NOM);
        if REECRITE.load(std::sync::atomic::Ordering::SeqCst) {
            let e = r.expect_err("échangée par son nom, et dite faite");
            // R-1 (recontrôle 0.95) : l'ancienne copie est remise, et c'est dit ; avant, le faux restait posé et
            // l'appelant disait « l'ancien reste en place ».
            assert_eq!(
                std::fs::read(&cible).unwrap(),
                avant,
                "l'ancienne copie n'est pas remise : {e}"
            );
            assert!(e.contains("remise en place"), "{e}");
            assert!(
                !racine.join("bin").join(format!("{NOM}.precedent")).exists(),
                "reste laissé"
            );
        } else {
            // Windows : l'échange refusé ; la copie montrée est posée, ou rien n'est remplacé (copie en attente
            // d'effacement), jamais autre chose.
            assert_eq!(std::env::consts::OS, "windows", "échange ni fait ni refusé");
            let posee = std::fs::read(&cible).unwrap();
            assert!(
                (r.is_ok() && posee == montre) || (r.is_err() && posee == avant),
                "{r:?}"
            );
        }
        *ECHANGE.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// R-1 (recontrôle 0.95) : sans ancienne copie, le faux posé à la place est retiré, jamais « l'ancienne reste en
    /// place ». (Une ancienne qui ne peut être mise de côté arrête la mise à jour avant : essai suivant.)
    #[test]
    fn copie_echangee_jamais_laissee_comme_l_ancienne() {
        let racine = crate::socle::dossier_local().join("essai-echange-remise");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0"));
        std::fs::create_dir_all(racine.join("bin")).unwrap();
        let _seul = UN_A_LA_FOIS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *ECHANGE.lock().unwrap() = Some(racine.join("bin"));

        REECRITE.store(false, std::sync::atomic::Ordering::SeqCst);
        let r = remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX, ECHANGE_PAR_LE_NOM);
        if REECRITE.load(std::sync::atomic::Ordering::SeqCst) {
            let e = r.expect_err("échangée par son nom, et dite faite");
            assert!(std::fs::symlink_metadata(&cible).is_err(), "le faux reste posé : {e}");
            assert!(e.contains("aucune copie"), "{e}");
            assert!(!e.contains("reste en place"), "{e}");
        }
        *ECHANGE.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// N-1 (recontrôle 2, 0.95) : le nom de côté (`<NOM>.precedent`) pris par un dossier, qui ne s'efface pas. Avant,
    /// l'ancienne copie n'était pas mise de côté et la mise à jour continuait : avec l'échange de R-1, la copie
    /// étrangère restait installée (« ne la lancez pas »), et l'entretien du mois la lance seul. Maintenant, refus
    /// avant le renommage, avec ou sans échange : rien n'est remplacé, le chemin à retirer est dit, le dossier n'est
    /// pas touché ; retiré, la mise à jour se fait.
    #[test]
    fn nom_de_cote_occupe_refuse_avant_de_remplacer() {
        let racine = crate::socle::dossier_local().join("essai-nom-de-cote");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        let provisoire = racine.join("bin").join(format!("{NOM}.nouveau"));
        let de_cote = racine.join("bin").join(format!("{NOM}.precedent"));
        faux_programme(&source, Some("0.80.0"));
        faux_programme(&cible, Some("0.79.0"));
        let avant = std::fs::read(&cible).unwrap();
        std::fs::create_dir_all(de_cote.join("occupe")).unwrap();
        let _seul = UN_A_LA_FOIS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *ECHANGE.lock().unwrap() = Some(racine.join("bin"));
        for essai in [ECHANGE_PAR_LE_NOM, SANS_ESSAI] {
            let e = remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX, essai).unwrap_err();
            assert_eq!(
                std::fs::read(&cible).unwrap(),
                avant,
                "la copie en place a changé : {e}"
            );
            assert!(e.contains("rien n'est remplacé"), "{e}");
            assert!(e.contains("retirez"), "{e}");
            assert!(e.contains(&format!("{NOM}.precedent")), "{e}");
            assert!(de_cote.join("occupe").is_dir(), "le dossier à ce nom est touché : {e}");
            assert!(
                std::fs::symlink_metadata(&provisoire).is_err(),
                "copie provisoire laissée : {e}"
            );
        }
        *ECHANGE.lock().unwrap() = None;

        // Une ancienne copie qui ne se met pas de côté pour une autre raison (ici, un dossier ne prend pas de lien
        // physique) : refus aussi, jamais un renommage sans copie à remettre.
        let autre = racine.join("ailleurs").join(NOM);
        std::fs::create_dir_all(autre.join("dedans")).unwrap();
        let e = remplacer(&source, &autre, (0, 80, 0, 0), TAILLE_MAX, SANS_ESSAI).unwrap_err();
        assert!(e.contains("rien n'est remplacé"), "{e}");
        assert!(autre.join("dedans").is_dir(), "{e}");

        std::fs::remove_dir_all(&de_cote).unwrap();
        remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX, SANS_ESSAI).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(std::fs::symlink_metadata(&de_cote).is_err(), "reste laissé");
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// N-3 (recontrôle 2, 0.95) : la remise de l'ancienne copie échoue (ce qui a pris sa place est un dossier plein,
    /// où le renommage ne passe pas). Avant, le second nom était effacé quand même : la seule ancienne copie qui
    /// restait était perdue. Maintenant elle est gardée, et son chemin est dit.
    #[test]
    fn remise_ratee_garde_la_copie_de_cote() {
        let racine = crate::socle::dossier_local().join("essai-remise-ratee");
        let _ = std::fs::remove_dir_all(&racine);
        let cible = racine.join("bin").join(NOM);
        let de_cote = cible.with_file_name(format!("{NOM}.precedent"));
        faux_programme(&cible, Some("0.79.0"));
        let ancienne = std::fs::read(&cible).unwrap();
        let precedente = Precedente::retenir(&cible).expect("mise de côté");
        std::fs::remove_file(&cible).unwrap();
        std::fs::create_dir_all(cible.join("occupe")).unwrap();
        let dit = precedente.remettre(&cible);
        assert_eq!(
            std::fs::read(&de_cote).ok(),
            Some(ancienne),
            "l'ancienne copie est perdue : {dit}"
        );
        assert!(dit.contains(&format!("{NOM}.precedent")), "{dit}");
        assert!(dit.contains("ne la lancez pas"), "{dit}");
        assert!(
            !dit.contains("remise en place") && !dit.contains("reste en place"),
            "{dit}"
        );
        assert!(cible.join("occupe").is_dir(), "{dit}");
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// L'essai d'un programme passe par son descripteur, pas par le nom de la copie provisoire : ce qu'il lance est
    /// ce qui a été écrit, même si le nom pointe ailleurs.
    #[cfg(target_os = "linux")]
    #[test]
    fn l_essai_lance_ce_qui_a_ete_ecrit() {
        fn regarde(chemin: &Path, _: Version) -> Result<(), String> {
            let provisoire = dossier_de_l_echange().join(format!("{NOM}.nouveau"));
            std::fs::remove_file(&provisoire).unwrap();
            std::fs::write(&provisoire, b"autre").unwrap();
            let lu = std::fs::read(chemin).map_err(|e| e.to_string())?;
            if version_gravee(&lu) == Some((0, 80, 0, 0)) {
                Ok(())
            } else {
                Err(format!("l'essai voit autre chose : {}", chemin.display()))
            }
        }
        let racine = crate::socle::dossier_local().join("essai-descripteur");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0"));
        faux_programme(&cible, Some("0.79.0"));
        let _seul = UN_A_LA_FOIS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *ECHANGE.lock().unwrap() = Some(racine.join("bin"));
        let r = remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX, regarde);
        // L'essai a vu la bonne copie ; la mise en place, elle, a pris le nom échangé : échec dit.
        let e = r.unwrap_err();
        assert!(!e.contains("l'essai voit autre chose"), "{e}");
        *ECHANGE.lock().unwrap() = None;
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

    /// R-4 (recontrôle 0.95) : un dossier au nom de la copie provisoire bloque la mise à jour ; l'échec dit lequel,
    /// et quoi faire, au lieu de « File exists (os error 17) ». Retiré, la mise à jour se fait.
    #[test]
    fn nom_provisoire_occupe_dit_comment_le_liberer() {
        let racine = crate::socle::dossier_local().join("essai-nom-provisoire");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0"));
        faux_programme(&cible, Some("0.79.0"));
        let avant = std::fs::read(&cible).unwrap();
        let provisoire = racine.join("bin").join(format!("{NOM}.nouveau"));
        std::fs::create_dir_all(provisoire.join("dedans")).unwrap();
        let e = remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX, SANS_ESSAI).unwrap_err();
        assert!(e.contains("retirez"), "{e}");
        assert!(e.contains(&format!("{NOM}.nouveau")), "{e}");
        assert_eq!(std::fs::read(&cible).unwrap(), avant);
        std::fs::remove_dir_all(&provisoire).unwrap();
        remplacer(&source, &cible, (0, 80, 0, 0), TAILLE_MAX, SANS_ESSAI).unwrap();
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// R-3 (recontrôle 0.95) : une copie tenue ouverte en écriture par un autre programme ne se lance pas (« Text file
    /// busy ») ; l'échec le dit, au lieu de « ne démarre pas sur cet ordinateur », qui accusait l'ordinateur.
    #[cfg(target_os = "linux")]
    #[test]
    fn copie_tenue_en_ecriture_dite_comme_telle() {
        let racine = crate::socle::dossier_local().join("essai-tenue");
        let _ = std::fs::remove_dir_all(&racine);
        std::fs::create_dir_all(&racine).unwrap();
        let copie = racine.join(NOM);
        // Un vrai programme (ELF) : le noyau refuse de lancer un fichier ouvert en écriture.
        std::fs::copy(std::env::current_exe().unwrap(), &copie).unwrap();
        let tenue = std::fs::OpenOptions::new().write(true).open(&copie).unwrap();
        let e = essayer(&copie, (0, 80, 0, 5)).unwrap_err();
        assert!(e.contains("un autre programme"), "{e}");
        assert!(!e.contains("ne démarre pas sur cet ordinateur"), "{e}");
        drop(tenue);
        let _ = std::fs::remove_dir_all(&racine);
    }
}
