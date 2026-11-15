//! Mettre Vanguard à jour sur cet ordinateur. La copie que la surveillance, l'entretien et le raccourci y lancent
//! (`reseau::surveillance::executable`) ne suit pas la clé, qui, elle, se met à jour chez son propriétaire. Lancé
//! depuis une clé plus récente, Vanguard le dit au menu et remplace la copie sur accord par le programme qui tourne :
//! copié à côté, sa version revérifiée, relu et comparé, puis mis en place d'un coup. Jamais vers une version plus
//! ancienne. La source est toujours le programme lancé depuis la clé, la confiance que la surveillance lui faisait
//! déjà en le copiant ; jamais un volume seulement branché, qui n'aurait qu'à porter le fichier témoin. La version
//! d'une copie se lit dans son fichier, sans la lancer : une vieille copie ne refait pas ses étapes de démarrage
//! (protection de la clé, passage à un nouveau nom). Sans clé, la dernière version publiée vient de GitHub, signée par
//! l'auteur et vérifiée (`github`) ; elle remplace la copie de cet ordinateur et le programme lancé, s'il n'est pas
//! sur la clé (la clé, elle, se met à jour chez son propriétaire). La fenêtre posée à côté d'un programme remplacé le
//! suit, vérifiée contre l'empreinte gravée dans le nouveau (`sa_fenetre`).

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
mod sa_fenetre;

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

/// La version `v` (« 0.88.0 », de l'historique signé) est-elle plus ancienne que ce programme ? Le numéro seul compte
/// (l'historique ne porte pas la date) ; illisible : non, rien n'est supposé.
pub(crate) fn plus_ancienne_que_ce_programme(v: &str) -> bool {
    matches!((lire_version(v), courante()), (Some(a), Some(c)) if (a.0, a.1, a.2) < (c.0, c.1, c.2))
}

/// La version `v` a-t-elle un numéro plus bas que `autre` (date de compilation ignorée, comme ci-dessus) ? `false` si
/// l'une des deux ne se lit pas.
pub(crate) fn plus_ancienne_que(v: &str, autre: &str) -> bool {
    matches!((lire_version(v), lire_version(autre)), (Some(a), Some(b)) if (a.0, a.1, a.2) < (b.0, b.1, b.2))
}

/// La version gravée dans `octets`, écrite en entier pour être notée (« 0.94.0+1760900000 », date comprise : deux
/// compilations d'un même numéro se départagent), et relue par `lire_version`. `None` : pas de version gravée.
pub(crate) fn version_notee(octets: &[u8]) -> Option<String> {
    version_gravee(octets).map(|v| {
        if v.3 == 0 {
            ecrire(v)
        } else {
            format!("{}+{}", ecrire(v), v.3)
        }
    })
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
    crate::protection::cle::exe_d_origine()
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
        // La clé du lancement compte même retirée : son programme n'est jamais une cible à remplacer.
        let sur_la_cle = crate::protection::cle::programme_ephemere(&exe);
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
/// interrompue ou abîmée ne remplace jamais celle qui marche, et ne reste pas sur le disque. La fenêtre posée à côté
/// du programme de la clé suit, si c'est bien la sienne (`sa_fenetre::de_la_source`), comme pour `poser_copie_dans`.
/// `vue` : la fenêtre dite avant la question (C-7, relecture 0.96) ; avec ou sans fenêtre, ce qui se pose est ce qui
/// a été dit, sinon rien.
/// `soi` : l'empreinte du programme qui tourne ; seuls ses octets se posent (voir `de_soi`).
/// `registre` : le dossier du registre scellé où Vanguard note les copies qu'il pose ; une copie plus récente que
/// `attendue` y est notée et le fichier là n'est plus elle (R3-C1) : refusé, rien n'est remplacé (`retour_en_arriere`).
#[allow(clippy::too_many_arguments)] // chacun une garde : la liste des copies (registre) et la copie de cet ordinateur s'ajoutent
fn remplacer(
    source: &Path,
    cible: &Path,
    attendue: Version,
    soi: Option<&str>,
    max: u64,
    registre: &Path,
    essai: Essai,
    vue: &sa_fenetre::Vue,
) -> Result<(), String> {
    let octets = lire_octets(source, max)?;
    gardes_de_la_cle(&octets, cible, attendue, soi, registre, derniere_publiee)?;
    let fenetre = sa_fenetre::de_la_source(source, &octets).zip(sa_fenetre::pour(cible));
    vue.dite(fenetre.as_ref().map(|(_, chemin)| chemin.as_path()))?;
    match fenetre {
        Some((f, chemin)) => sa_fenetre::installer_avec(
            &octets,
            cible,
            attendue,
            registre,
            &copie_de_cet_ordinateur(),
            essai,
            &f,
            &chemin,
            vue,
        ),
        None => installer(&octets, cible, attendue, registre, &copie_de_cet_ordinateur(), essai),
    }
}

/// Ce qui doit tenir avant que `octets`, lus sur la clé, remplacent `cible` : ce sont ceux du programme qui tourne
/// (`de_soi`), et la liste des copies du registre de `registre` ne dit pas que ce serait un retour en arrière
/// (`retour_en_arriere`, sortie prouvée par `sortie_du_doute`). Le terminal (`remplacer`) et l'aperçu de la fenêtre
/// (`apercu::plan`, rejoué après l'accord) passent par ici : aucun chemin ne pose la clé sans ces gardes.
/// `derniere` : la dernière version signée, demandée seulement devant une liste en doute. Le terminal la reçoit de
/// GitHub (`derniere_publiee`, qui retient le plancher) ; l'aperçu n'écrit rien avant l'accord et la refuse.
pub(super) fn gardes_de_la_cle(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    soi: Option<&str>,
    registre: &Path,
    derniere: impl FnOnce() -> Result<Version, crate::modele::Echec>,
) -> Result<(), String> {
    if !de_soi(octets, soi) {
        return Err(pas_de_soi(soi));
    }
    let sortie = || sortie_du_doute(attendue, derniere(), || historique_du_doute()(octets));
    match retour_en_arriere(registre, cible, attendue, &present(cible), sortie) {
        Some(refus) => Err(refus),
        None => Ok(()),
    }
}

/// Les octets relus au chemin de la clé sont-ils ceux du programme qui tourne (`soi` : leur empreinte, prise au
/// démarrage) ? Ce chemin n'est vérifié qu'une fois, au lancement : clé retirée puis une autre branchée au même
/// endroit, ou fichier réécrit depuis, et c'est un autre programme qui se poserait, se lancerait (`essayer`) et serait
/// scellé comme celui de Vanguard. Les octets comparés sont ceux, en mémoire, qui seront écrits : rien ne peut changer
/// entre la comparaison et la pose. Sans empreinte du programme qui tourne : refusé aussi, jamais cru.
fn de_soi(octets: &[u8], soi: Option<&str>) -> bool {
    soi.is_some_and(|s| blake3::hash(octets).to_hex().as_str() == s)
}

/// Le refus quand les octets lus ne sont pas `de_soi`. Deux causes, deux textes : sans empreinte du programme qui tourne
/// (`soi` absent : /proc/self/exe ou le fichier du départ illisible), rien ne dit que la clé a changé.
fn pas_de_soi(soi: Option<&str>) -> String {
    if soi.is_none() {
        return tr!(
            "le programme qui tourne ne se lit pas : rien ne peut être comparé à lui, rien n'est posé (non vérifié)",
            "the running program cannot be read: nothing can be compared with it, nothing is set up (not checked)"
        )
        .into();
    }
    tr!(
        "le programme de la clé a changé : ce n'est plus celui qui tourne (fichier réécrit, ou une autre clé, depuis le lancement) ; rien n'est posé",
        "the key's program has changed: it is no longer the one running (file rewritten, or another key, since launch); nothing is set up"
    )
    .into()
}

/// L'essai d'un programme posé à côté, avant qu'il remplace l'ancien (`essayer`, ou celui d'un test).
type Essai = fn(&Path, Version) -> Result<(), String>;

/// Les octets d'un programme à la place de `cible`, s'ils portent la version `attendue` et que l'essai les a vus
/// démarrer. `ici` est la copie de cet ordinateur (`copie_de_cet_ordinateur`, hors des essais) : seule une pose sur
/// `ici` lève le doute sur la liste (`programmes_poses::copie_posee_ici`).
fn installer(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    registre: &Path,
    ici: &Path,
    essai: Essai,
) -> Result<(), String> {
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
        // N-5 (recontrôle 2, 0.95) : « x: y » en anglais, jamais le « : » à la française.
        let rien = |e: String| trf!("{e} : rien n'est remplacé", "{e}: nothing is replaced");
        let _ = std::fs::remove_file(&provisoire);
        let f = ecrire_provisoire(&provisoire, octets).map_err(|e| {
            // R-4 (recontrôle 0.95) : un dossier (ou autre chose qui ne s'efface pas) sous ce nom ; dit avec le chemin
            // à retirer, jamais « File exists » seul. Un vrai Windows dit « Access is denied » (os error 5) pour un
            // dossier à ce nom, là où Wine et Linux disent « File exists » (CI de la 0.96.0).
            let dossier = || std::fs::symlink_metadata(&provisoire).is_ok_and(|m| m.is_dir());
            if e.kind() == std::io::ErrorKind::AlreadyExists
                || (e.kind() == std::io::ErrorKind::PermissionDenied && dossier())
            {
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
        let precedente = Precedente::retenir(cible).map_err(|e| rien(e.to_string()))?;
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
            Err(e) => Err(trf!("{e} : {}", "{e}: {}", precedente.remettre(cible))),
        }
    })();
    if ecrite.is_err() {
        let _ = std::fs::remove_file(&provisoire);
    } else {
        // Posée par Vanguard : chaque tâche qui la lance garde un sceau juste (`programmes_poses`), sans quoi le bilan
        // la dirait remplacée hors de Vanguard.
        let touchees = crate::programmes_poses::copie_posee_ici(registre, cible, octets, ici);
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
    Retenue(Tenue),
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

/// Le nom de côté pris par autre chose qu'un second nom de la copie en place (V-1, relecture du recontrôle 2 0.95) :
/// peut-être la seule ancienne copie, gardée là après une remise ratée. Jamais effacé : son chemin est dit, à mettre à
/// l'abri d'abord (« retirez-le » seul ferait perdre cette copie).
fn nom_garde(chemin: &Path) -> String {
    trf!(
        "{} existe déjà et n'est pas la copie en place (peut-être l'ancienne copie, gardée après une mise à jour ratée) : Vanguard ne l'efface pas ; mettez-le à l'abri ou retirez-le, puis relancez la mise à jour",
        "{} already exists and is not the copy in place (perhaps the old copy, kept after a failed update): Vanguard does not delete it; move it somewhere safe or remove it, then run the update again",
        affichable(&chemin.display().to_string())
    )
}

/// L'ancienne copie, tenue de sa mise de côté jusqu'à la fin de la mise à jour (V-3, relecture du recontrôle 2 0.95).
/// Avant, elle n'était reconnue que par son appareil et son inode, notés sans rien tenir d'ouvert : ses noms effacés,
/// ext4 redonne aussitôt ce numéro au fichier suivant, et un fichier étranger (ou un dossier) posé à la cible était dit
/// « l'ancienne copie ».
enum Tenue {
    /// Sous Unix, un fichier ordinaire tenu par un descripteur ouvert : un inode tenu ouvert n'est jamais redonné. Avec
    /// l'empreinte BLAKE3 de ses octets à sa mise de côté (C-1, contrôle 2 du sous-lot c2 de la 0.95) : le même inode
    /// peut être réécrit sur place (par son second nom, ou par la cible avant le renommage) ; sans l'empreinte, ce
    /// contenu étranger était dit « l'ancienne copie est remise en place ».
    #[cfg(unix)]
    Fichier(std::fs::File, blake3::Hash),
    /// Un lien symbolique : ce qu'il désigne (deux liens qui désignent la même chose se valent), et le fichier ordinaire
    /// au bout, tenu ouvert avec son empreinte comme `Fichier`. M-1 (relecture DEP-4 de la 0.95) : c'est ce fichier qui
    /// est lancé. Avant, seul le texte du lien était retenu : ce fichier réécrit (ou remplacé) pendant la mise à jour,
    /// le lien était encore dit « l'ancienne copie est remise en place » ou « reste en place ».
    #[cfg(unix)]
    Lien(PathBuf, std::fs::File, blake3::Hash),
    /// Ailleurs (Windows) : ses octets (l'identité du fichier demanderait l'API de Windows).
    #[cfg(not(unix))]
    Octets(Vec<u8>),
}

impl Tenue {
    /// La copie à `cible` (`m` : ce qu'en dit `symlink_metadata`), tenue ; ou pourquoi elle ne peut pas l'être.
    fn de(cible: &Path, m: &std::fs::Metadata) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            if m.file_type().is_symlink() {
                let vers = std::fs::read_link(cible)?;
                // Le fichier au bout, en suivant le lien ; puis le lien relu : changé entre-temps (un autre programme),
                // ce fichier n'est peut-être pas celui qu'il désigne.
                let f = ouvrir_ordinaire(cible, 0)?;
                if std::fs::read_link(cible)? != vers {
                    return Err(std::io::Error::other(tr!(
                        "le lien a changé pendant sa mise de côté",
                        "the link changed while being set aside"
                    )));
                }
                let empreinte = empreinte_tenue(&f)?;
                return Ok(Tenue::Lien(vers, f, empreinte));
            }
            if !m.is_file() {
                return Err(pas_un_fichier());
            }
            // Sans suivre de lien (posé entre-temps).
            let f = ouvrir_ordinaire(cible, libc::O_NOFOLLOW)?;
            let empreinte = empreinte_tenue(&f)?;
            Ok(Tenue::Fichier(f, empreinte))
        }
        #[cfg(not(unix))]
        {
            let _ = m;
            lire_octets(cible, TAILLE_MAX)
                .map(Tenue::Octets)
                .map_err(std::io::Error::other)
        }
    }

    /// `chemin` est-il elle, à l'instant ? Sous Unix, un fichier ordinaire du même appareil et du même inode que le
    /// descripteur tenu (ce numéro ne peut être celui d'aucun autre fichier tant qu'il est tenu), ou un lien qui désigne
    /// la même chose (le fichier au bout est vérifié par `intacte`). Ailleurs, les mêmes octets. Faux si `chemin` ne se
    /// lit pas.
    fn est(&self, chemin: &Path) -> bool {
        match self {
            #[cfg(unix)]
            Tenue::Fichier(f, _) => std::fs::symlink_metadata(chemin).is_ok_and(|b| b.is_file()) && tenu_est(f, chemin),
            #[cfg(unix)]
            Tenue::Lien(vers, _, _) => {
                std::fs::symlink_metadata(chemin).is_ok_and(|m| m.file_type().is_symlink())
                    && std::fs::read_link(chemin).ok().as_ref() == Some(vers)
            }
            #[cfg(not(unix))]
            Tenue::Octets(o) => lire_octets(chemin, TAILLE_MAX).ok().as_ref() == Some(o),
        }
    }

    /// Ce qu'elle contient : ses octets, relus depuis le début par ce qui la tient (même si plus aucun nom ne la
    /// désigne), jamais plus de `TAILLE_MAX`, et seulement s'ils sont encore ceux mis de côté (C-1) ; ou, lien
    /// symbolique, ce qu'il désigne, seulement si le fichier tenu au bout n'a pas changé (M-1).
    #[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))] // même signature que sous Unix, où la relecture peut échouer
    fn contenu(&self) -> std::io::Result<Contenu> {
        match self {
            #[cfg(unix)]
            Tenue::Fichier(f, empreinte) => {
                let o = relire(f)?;
                if blake3::hash(&o) != *empreinte {
                    return Err(std::io::Error::other(contenu_change()));
                }
                Ok(Contenu::Octets(o))
            }
            #[cfg(unix)]
            Tenue::Lien(vers, f, e) => {
                if empreinte_tenue(f)? != *e {
                    return Err(std::io::Error::other(designe_change()));
                }
                Ok(Contenu::Lien(vers.clone()))
            }
            #[cfg(not(unix))]
            Tenue::Octets(o) => Ok(Contenu::Octets(o.clone())),
        }
    }

    /// Ce qui est lancé à `ou` (où `est` l'a reconnue) est-il encore ce qu'elle était à sa mise de côté (C-1) ? Un
    /// fichier : ses octets, relus par ce qui le tient. Un lien (M-1) : le fichier qu'il désigne à `ou`, à l'instant, est
    /// celui tenu, et ses octets n'ont pas changé. Faux s'ils ne se relisent pas. Ailleurs, des octets gardés en mémoire
    /// ne changent pas.
    fn intacte(&self, ou: &Path) -> bool {
        match self {
            #[cfg(unix)]
            Tenue::Fichier(f, e) => empreinte_tenue(f).is_ok_and(|lu| lu == *e),
            #[cfg(unix)]
            Tenue::Lien(_, f, e) => {
                std::fs::metadata(ou).is_ok_and(|b| b.is_file())
                    && tenu_designe(f, ou)
                    && empreinte_tenue(f).is_ok_and(|lu| lu == *e)
            }
            #[cfg(not(unix))]
            Tenue::Octets(_) => {
                let _ = ou;
                true
            }
        }
    }

    /// Un lien symbolique ? (Réécrit à sa place, il ne désigne le fichier tenu que par son texte : `intacte` le revoit.)
    fn est_un_lien(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self, Tenue::Lien(..))
        }
        #[cfg(not(unix))]
        {
            let _ = self;
            false
        }
    }

    /// `ou` est elle (`est`), mais ce qui y est lancé a changé (`intacte`) : ce qui est dit, sans le conseil.
    fn changee(&self, ou: &Path) -> String {
        let ou = affichable(&ou.display().to_string());
        if self.est_un_lien() {
            trf!(
                "{ou} est le lien de l'ancienne copie, mais le fichier qu'il désigne a changé pendant la mise à jour (réécrit ou remplacé par un autre programme) : ce n'est plus sûrement l'ancienne copie ; ne le lancez pas",
                "{ou} is the old copy's link, but the file it points to changed during the update (rewritten or replaced by another program), so it is no longer surely the old copy; do not run it",
            )
        } else {
            trf!(
                "{ou} est le fichier de l'ancienne copie, mais {} ; ne le lancez pas",
                "{ou} is the old copy's file, but {}; do not run it",
                contenu_change()
            )
        }
    }
}

/// La copie en place n'est pas un fichier ordinaire.
#[cfg(unix)]
fn pas_un_fichier() -> std::io::Error {
    std::io::Error::other(tr!(
        "la copie en place n'est pas un fichier (un dossier ?)",
        "the copy in place is not a file (a folder?)"
    ))
}

/// `chemin` ouvert en lecture sans attendre (un tube nommé posé entre-temps), avec `drapeaux` en plus ; un fichier
/// ordinaire, ou une erreur.
#[cfg(unix)]
fn ouvrir_ordinaire(chemin: &Path, drapeaux: libc::c_int) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK | drapeaux);
    let f = options.open(chemin)?;
    if !f.metadata()?.is_file() {
        return Err(pas_un_fichier());
    }
    Ok(f)
}

/// Le fichier tenu par `f` est-il celui de `chemin` (même appareil, même inode), sans suivre de lien ?
#[cfg(unix)]
fn tenu_est(f: &std::fs::File, chemin: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (f.metadata(), std::fs::symlink_metadata(chemin)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Le fichier tenu par `f` est-il celui que désigne `chemin`, en suivant les liens ?
#[cfg(unix)]
fn tenu_designe(f: &std::fs::File, chemin: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (f.metadata(), std::fs::metadata(chemin)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Plus de `TAILLE_MAX` (R-9, relecture DEP-4 de la 0.95 : la cause dite, pour la refuser en connaissance).
#[cfg(unix)]
fn trop_grosse() -> std::io::Error {
    std::io::Error::other(tr!("elle dépasse 512 Mio", "it exceeds 512 MiB"))
}

/// Les octets du fichier tenu par `f`, relus depuis le début, jamais plus de `TAILLE_MAX`.
#[cfg(unix)]
fn relire(f: &std::fs::File) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek};
    let mut f = f;
    f.seek(std::io::SeekFrom::Start(0))?;
    let mut o = Vec::new();
    f.take(TAILLE_MAX.saturating_add(1)).read_to_end(&mut o)?;
    if u64::try_from(o.len()).unwrap_or(u64::MAX) > TAILLE_MAX {
        return Err(trop_grosse());
    }
    Ok(o)
}

/// L'empreinte BLAKE3 des octets du fichier tenu par `f`, relus depuis le début par morceaux, jamais plus de
/// `TAILLE_MAX`. R-9 (relecture DEP-4 de la 0.95) : à la mise de côté et à chaque vérification, sans tenir la copie
/// entière en mémoire (jusqu'à 512 Mio) ; seule la réécriture (`contenu`) la relit en entier, pour l'écrire.
#[cfg(unix)]
fn empreinte_tenue(f: &std::fs::File) -> std::io::Result<blake3::Hash> {
    use std::io::{Read, Seek};
    let mut f = f;
    f.seek(std::io::SeekFrom::Start(0))?;
    let mut hache = blake3::Hasher::new();
    let mut tampon = vec![0_u8; 1 << 16];
    let mut lu: u64 = 0;
    loop {
        let n = match f.read(&mut tampon) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        lu = lu.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if lu > TAILLE_MAX {
            return Err(trop_grosse());
        }
        hache.update(tampon.get(..n).unwrap_or_default());
    }
    Ok(hache.finalize())
}

/// Pourquoi le fichier de l'ancienne copie n'est plus elle (C-1).
fn contenu_change() -> &'static str {
    tr!(
        "son contenu a changé pendant la mise à jour (un autre programme l'a réécrit) : ce n'est plus sûrement l'ancienne copie",
        "its content changed during the update (another program rewrote it), so it is no longer surely the old copy"
    )
}

/// Pourquoi le lien de l'ancienne copie ne lance plus elle (M-1), dit sans sujet autour (raison d'un échec).
fn designe_change() -> &'static str {
    tr!(
        "le fichier que désigne son lien a changé pendant la mise à jour (réécrit ou remplacé par un autre programme) : ce n'est plus sûrement l'ancienne copie",
        "the file its link points to changed during the update (rewritten or replaced by another program), so it is no longer surely the old copy"
    )
}

/// Ce que contient l'ancienne copie tenue (`Tenue::contenu`).
enum Contenu {
    Octets(Vec<u8>),
    #[cfg(unix)]
    Lien(PathBuf),
}

/// Ce qu'a donné la réécriture de l'ancienne copie à sa place (V-2).
enum Reecrite {
    Faite,
    /// Écrite et relue sous ce nom neuf, mais pas posée à sa place (pourquoi) : gardée là.
    Gardee(PathBuf, std::io::Error),
    Ratee(String),
}

/// V-2 (relecture du recontrôle 2, 0.95) : l'ancienne copie réécrite à `cible` depuis ce qui la tient, quand son
/// second nom a disparu ou changé pendant la mise à jour (un autre programme). Écrite sous un nom neuf, créé exprès
/// (jamais un nom déjà pris, qui n'est donc jamais effacé), relue, puis renommée d'un coup ; à sa place, elle doit être
/// ce même fichier avec ces mêmes octets. La place reprise après le renommage : réessayé, trois fois au plus.
fn reecrire(tenue: &Tenue, cible: &Path) -> Reecrite {
    let contenu = match tenue.contenu() {
        Ok(c) => c,
        Err(e) => return Reecrite::Ratee(e.to_string()),
    };
    for _ in 0..3 {
        let neuf = cible.with_file_name(format!("{NOM}.remise-{}", crate::changements::nouvel_id()));
        // Le fichier écrit (relu ensuite par son descripteur) et ses octets ; rien pour un lien.
        let ecrite = match &contenu {
            Contenu::Octets(o) => ecrire_provisoire(&neuf, o).map(|f| Some((f, o))),
            #[cfg(unix)]
            Contenu::Lien(vers) => std::os::unix::fs::symlink(vers, &neuf).map(|()| None),
        };
        let ecrite = match ecrite {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                // Créé à l'instant sous ce nom neuf, mais son écriture (ou sa réouverture) a raté : retiré.
                let _ = std::fs::remove_file(&neuf);
                return Reecrite::Ratee(e.to_string());
            }
        };
        let est = |chemin: &Path| match &ecrite {
            Some((f, o)) => posee_est_la_montree(f, chemin, o).unwrap_or(false),
            None => tenue.est(chemin),
        };
        // M-1, N-2, N-3 (revérification de la ronde 2, DEP-4 de la 0.95) : un lien ne désigne le fichier tenu que par
        // son texte. Le fichier au bout remplacé pendant la mise à jour (un autre programme), le lien neuf lance ce
        // contenu étranger : avant, Vanguard le posait quand même à la cible (puis le disait changé), ou le disait
        // « gardé sous » son nom neuf. Revu avant d'être posé, et après un renommage raté : sinon retiré (s'il est
        // encore le lien créé à l'instant), jamais posé ni dit gardé.
        let lien_change = |chemin: &Path| ecrite.is_none() && !tenue.intacte(chemin);
        if lien_change(&neuf) {
            if tenue.est(&neuf) {
                let _ = std::fs::remove_file(&neuf);
            }
            return Reecrite::Ratee(designe_change().into());
        }
        match std::fs::rename(&neuf, cible) {
            Ok(()) if est(cible) => return Reecrite::Faite,
            Err(_) if est(&neuf) && lien_change(&neuf) => {
                let _ = std::fs::remove_file(&neuf);
                return Reecrite::Ratee(designe_change().into());
            }
            Err(e) if est(&neuf) => return Reecrite::Gardee(neuf, e),
            // Sa place reprise par un autre programme juste après le renommage, ou le nom neuf changé avant : réessayé.
            Ok(()) | Err(_) => {}
        }
    }
    Reecrite::Ratee(
        tr!(
            "sa place est reprise à chaque essai par un autre programme",
            "its place is taken again at each attempt by another program"
        )
        .into(),
    )
}

impl Precedente {
    /// L'ancienne copie mise de côté, ou pourquoi elle ne peut pas l'être : l'appelant refuse alors avant le
    /// renommage (N-1, recontrôle 2 0.95), jamais un remplacement sans copie à remettre.
    fn retenir(cible: &Path) -> Result<Self, crate::modele::Echec> {
        // La phrase telle quelle (le canal d'erreur commun : un refus se rend par sa seule phrase).
        let refus = |phrase: String| crate::modele::Echec::refuse("mise_a_jour/precedente", phrase);
        let de_cote = cible.with_file_name(format!("{NOM}.precedent"));
        let pas_de_cote = |pourquoi: &dyn std::fmt::Display| {
            refus(trf!(
                "l'ancienne copie ne se met pas de côté sous {} ({pourquoi}), et ne pourrait donc pas être remise",
                "the old copy cannot be set aside as {} ({pourquoi}), so it could not be put back",
                affichable(&de_cote.display().to_string())
            ))
        };
        let etat = match std::fs::symlink_metadata(cible) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => EtatPrecedente::Aucune,
            Err(e) => {
                return Err(refus(trf!(
                    "la copie en place ne se lit pas ({}) : {e}",
                    "the copy in place cannot be read ({}): {e}",
                    affichable(&cible.display().to_string())
                )));
            }
            Ok(m) => {
                // R-9 (relecture DEP-4 de la 0.95) : la copie en place nommée, avec le geste à faire. Avant, le
                // message nommait le nom de côté, alors que c'est elle qui ne se lit pas (ou dépasse 512 Mio).
                let tenue = Tenue::de(cible, &m).map_err(|e| {
                    refus(trf!(
                        "la copie en place, {}, ne se met pas de côté ({e}) et ne pourrait donc pas être remise : mettez-la à l'abri ou retirez-la, puis relancez la mise à jour",
                        "the copy in place, {}, cannot be set aside ({e}), so it could not be put back: move it somewhere safe or remove it, then run the update again",
                        affichable(&cible.display().to_string())
                    ))
                })?;
                // V-1 (relecture du recontrôle 2, 0.95) : ce nom n'est effacé que s'il est un second nom de la copie en
                // place (le reste d'une mise à jour interrompue avant le renommage : rien ne s'y perd). Avant, il
                // l'était toujours, avant même de savoir si le lien se ferait : l'ancienne copie gardée là après une
                // remise ratée était perdue par la tentative suivante, qui refusait ensuite (« rien n'est remplacé »).
                match std::fs::symlink_metadata(&de_cote) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(pas_de_cote(&e)),
                    Ok(_) if tenue.est(&de_cote) => {
                        std::fs::remove_file(&de_cote).map_err(|e| pas_de_cote(&e))?;
                    }
                    Ok(_) => return Err(refus(nom_garde(&de_cote))),
                }
                match std::fs::hard_link(cible, &de_cote) {
                    // La cible ou ce nom changés entre-temps (un autre programme) : refus ; ce qui est à ce nom n'est
                    // pas sûrement à Vanguard, il n'est pas effacé (la tentative suivante le dira, V-1).
                    Ok(()) if !tenue.est(&de_cote) => return Err(pas_de_cote(&tr!("pas relue", "not read back"))),
                    Ok(()) => EtatPrecedente::Retenue(tenue),
                    // Posé entre le regard et le lien (un autre programme) : jamais effacé non plus.
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        return Err(refus(nom_garde(&de_cote)));
                    }
                    Err(e) => return Err(pas_de_cote(&e)),
                }
            }
        };
        Ok(Self { de_cote, etat })
    }

    /// La mise à jour est faite : le second nom part (l'ancienne copie, elle, n'existe plus que là), s'il est encore
    /// elle : ce qu'un autre programme a mis à ce nom n'est pas effacé.
    fn oublier(self) {
        if let EtatPrecedente::Retenue(tenue) = &self.etat
            && tenue.est(&self.de_cote)
        {
            let _ = std::fs::remove_file(&self.de_cote);
        }
    }

    /// La copie posée n'est pas la montrée (ou le renommage a échoué) : remettre l'ancienne, ou retirer ce qui est
    /// posé s'il n'y en avait pas. Rend ce qui est en place, vérifié après coup : jamais « l'ancienne » sans l'avoir
    /// reconnue à `cible`, par son inode et par ses octets (C-1).
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
        // C-1 (contrôle 2 du sous-lot c2 de la 0.95) : le fichier de l'ancienne copie est à `ou`, mais ses octets ne
        // sont plus ceux mis de côté (réécrit sur place par un autre programme). Avant, il était dit « l'ancienne
        // copie », remise ou restée en place. M-1 : de même pour un lien dont le fichier au bout a changé.
        let changee =
            |tenue: &Tenue, ou: &Path| trf!("{}, refaites la mise à jour", "{}, redo the update", tenue.changee(ou));
        // R-5 (relecture DEP-4 de la 0.95) : l'ancienne copie changée, laissée sous son nom de côté (jamais posée à
        // la cible) : la mise à jour suivante refuse tant qu'elle y est, d'où le geste dit d'abord.
        let laissee = |tenue: &Tenue, pourquoi: String| {
            trf!(
                "l'ancienne copie n'est pas remise{pourquoi} ; {} ; déplacez-le ailleurs avant de refaire la mise à jour, qui refuse tant qu'il y est ; {}",
                "the old copy is not put back{pourquoi}; {}; move it elsewhere before redoing the update, which refuses while it is there; {}",
                tenue.changee(&self.de_cote),
                ni_l_une_ni_l_autre()
            )
        };
        match self.etat {
            EtatPrecedente::Retenue(tenue) => {
                // Le renommage a échoué sans rien toucher : l'ancienne n'a pas bougé (reconnue par ce qui la tient,
                // V-3 : jamais par un numéro que le système a pu redonner), si ses octets n'ont pas changé (C-1).
                if tenue.est(cible) {
                    if tenue.est(&self.de_cote) {
                        let _ = std::fs::remove_file(&self.de_cote);
                    }
                    if !tenue.intacte(cible) {
                        return changee(&tenue, cible);
                    }
                    return tr!("l'ancienne copie reste en place", "the old copy stays in place").into();
                }
                // N-3 (recontrôle 2, 0.95) : le second nom n'est effacé qu'une fois l'ancienne reconnue à `cible`.
                // Avant, il l'était même si la remise avait échoué : la seule ancienne copie qui restait était perdue.
                // V-2 (relecture du recontrôle 2, 0.95) : renommé seulement s'il est encore elle, et « gardée sous » ce
                // nom seulement s'il l'est encore après l'échec. Avant, le renommage était tenté quoi qu'il y ait : ce
                // nom effacé pendant la mise à jour (un autre programme), la copie étrangère restait installée, et le
                // message la disait « gardée sous » un nom vide (ou un fichier étranger).
                if tenue.est(&self.de_cote) {
                    // R-5 : vérifiée avant d'être renommée à la cible. Avant, elle l'était seulement après : un contenu
                    // changé était posé à la place du programme par Vanguard lui-même, puis dit « changé ». Limite
                    // (revérification de la ronde 2) : un fichier que le compte peut écrire peut changer dans l'instant
                    // entre ce contrôle et le renommage ; ce changement-là n'est vu qu'après (`changee`, plus bas), dit
                    // comme tel, jamais « remise ».
                    if !tenue.intacte(&self.de_cote) {
                        return laissee(&tenue, String::new());
                    }
                    match std::fs::rename(&self.de_cote, cible) {
                        Ok(()) if tenue.est(cible) => {
                            // Deux noms d'un même fichier : le renommage ne fait rien (POSIX) et le second nom reste.
                            if tenue.est(&self.de_cote) {
                                let _ = std::fs::remove_file(&self.de_cote);
                            }
                            // Revérifiée : son contenu a pu changer entre les deux.
                            if !tenue.intacte(cible) {
                                return changee(&tenue, cible);
                            }
                            return tr!(
                                "l'ancienne copie est remise en place",
                                "the old copy is put back in place"
                            )
                            .into();
                        }
                        Err(e) if tenue.est(&self.de_cote) && !tenue.intacte(&self.de_cote) => {
                            return laissee(&tenue, format!(" ({e})"));
                        }
                        // La mise à jour suivante refuse tant que ce nom est pris (V-1) : à mettre à l'abri avant.
                        Err(e) if tenue.est(&self.de_cote) => {
                            return trf!(
                                "l'ancienne copie n'est pas remise ({e}), elle est gardée sous {} : copiez-la ailleurs avant de refaire la mise à jour, qui refuse tant qu'elle y est ; {}",
                                "the old copy is not put back ({e}), it is kept as {}: copy it elsewhere before redoing the update, which refuses while it is there; {}",
                                affichable(&self.de_cote.display().to_string()),
                                ni_l_une_ni_l_autre()
                            );
                        }
                        // Sa place reprise juste après, ou ce nom changé juste avant (un autre programme) : réécrite,
                        // ci-dessous.
                        Ok(()) | Err(_) => {}
                    }
                }
                // Ce qui est à ce nom, s'il y a quelque chose, n'est pas elle : ni effacé, ni dit « l'ancienne ».
                let etranger = if std::fs::symlink_metadata(&self.de_cote).is_ok() && !tenue.est(&self.de_cote) {
                    trf!(
                        " ({} n'est pas l'ancienne copie : un autre programme l'a mis là, Vanguard ne l'efface pas, ne le lancez pas)",
                        " ({} is not the old copy: another program put it there, Vanguard does not delete it, do not run it)",
                        affichable(&self.de_cote.display().to_string())
                    )
                } else {
                    String::new()
                };
                match reecrire(&tenue, cible) {
                    // M-1 : un lien réécrit ne désigne le fichier tenu que par son texte : revu à la cible.
                    Reecrite::Faite if tenue.est_un_lien() && !tenue.intacte(cible) => changee(&tenue, cible),
                    Reecrite::Faite => trf!(
                        "l'ancienne copie est réécrite à sa place, depuis ce que Vanguard en tenait (un autre programme a changé ses noms pendant la mise à jour){etranger}",
                        "the old copy is rewritten in its place, from what Vanguard held of it (another program changed its names during the update){etranger}",
                    ),
                    Reecrite::Gardee(neuf, e) => trf!(
                        "l'ancienne copie n'est pas remise ({e}), elle est gardée sous {} : mettez-la à l'abri{etranger} ; {}",
                        "the old copy is not put back ({e}), it is kept as {}: move it somewhere safe{etranger}; {}",
                        affichable(&neuf.display().to_string()),
                        ni_l_une_ni_l_autre()
                    ),
                    Reecrite::Ratee(e) => trf!(
                        "l'ancienne copie est perdue, ni remise ni gardée ({e}){etranger} ; {}",
                        "the old copy is lost, neither put back nor kept ({e}){etranger}; {}",
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
/// sinon rien n'est remplacé (l'ancienne copie, s'il y en a une, n'est pas touchée : N-5, recontrôle 2 0.95, à la
/// première pose il n'y en a pas). Sous Windows, pas d'essai : le fichier provisoire n'a pas l'extension .exe, et
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
            "la nouvelle copie est tenue ouverte en écriture par un autre programme (« Text file busy ») : elle ne se lance pas, rien n'est remplacé ; réessayez quand ce programme l'aura lâchée",
            "the new copy is held open for writing by another program (“Text file busy”): it does not start, nothing is replaced; try again once that program lets go of it"
        )
        .into()),
        _ => Err(tr!(
            "la nouvelle copie ne démarre pas sur cet ordinateur : rien n'est remplacé",
            "the new copy does not start on this computer: nothing is replaced"
        )
        .into()),
    }
}

/// La copie de cet ordinateur posée depuis `source`, le programme lancé sur la clé (surveillance, entretien,
/// raccourci, veilleur), par le même chemin que la mise à jour : à côté, version revérifiée, essayée, relue, puis
/// mise en place d'un coup. Jamais par-dessus une copie plus récente (« jamais vers une version plus ancienne ») :
/// posée par Vanguard, elle est gardée, et c'est elle que la surveillance lancera ; inconnue, elle n'est ni gardée ni
/// remplacée, rien n'est posé et c'est dit, non vérifié (`poser_copie_dans`). Rend le chemin de la copie, ou pourquoi
/// elle n'a pas pu se faire : jamais celui de la clé, qu'une minuterie ne retrouverait plus une fois débranchée.
///
/// Avec le chemin, ce qui n'a pas pu se faire sans arrêter la copie : la fenêtre qui n'a pas pu être posée (C-5,
/// relecture 0.96 : l'échec était passé sous silence, « fait » sans un mot).
pub(crate) fn poser_copie(source: &Path) -> Result<(PathBuf, Option<String>), String> {
    let cible = copie_de_cet_ordinateur();
    let soi = crate::protection::cle::image_qui_tourne();
    let note = poser_copie_dans(
        source,
        &cible,
        soi.as_deref(),
        &crate::socle::dossier_local(),
        signee_pour_ce_systeme,
        essayer,
    )?;
    Ok((cible, note))
}

/// Les octets d'un programme sont-ils une version publiée et signée pour ce système, à la version qu'ils portent ?
/// D'après l'historique signé (`version_signee`) ; `Err` : on ne sait pas (hors ligne, pas de réponse), jamais compté
/// comme oui.
type Historique = fn(&[u8]) -> Result<bool, crate::modele::Echec>;

fn signee_pour_ce_systeme(octets: &[u8]) -> Result<bool, crate::modele::Echec> {
    use sha2::{Digest, Sha256};
    let ici = github::systeme().ok_or_else(|| {
        crate::modele::Echec::echoue(
            "mise_a_jour/historique",
            tr!(
                "pas de version publiée pour ce système",
                "no published version for this system"
            ),
        )
    })?;
    let Some(v) = version_gravee(octets) else {
        return Ok(false);
    };
    let sha: [u8; 32] = Sha256::digest(octets).into();
    let vue = version_signee(&sha).map_err(|e| crate::modele::Echec::echoue("mise_a_jour/historique", e))?;
    Ok(signee_ici(vue, ici, v))
}

/// Ce que l'historique signé dit (`vue` : la version et le système publiés pour ces octets) vaut-il « publiée et signée
/// pour ce système (`ici`), à la version gravée `v` » ? Le même numéro pour un autre système, ou un autre numéro (des
/// octets d'une version renommée), ne compte pas.
fn signee_ici(vue: Option<(String, String)>, ici: &str, v: Version) -> bool {
    vue.is_some_and(|(n, s)| s == ici && n == ecrire(v))
}

/// Le fichier à la place de la copie, lu une fois.
enum Present {
    Absent,
    Illisible(String),
    Lu(Vec<u8>),
}

fn present(cible: &Path) -> Present {
    if std::fs::symlink_metadata(cible).is_err() {
        return Present::Absent;
    }
    lire_octets(cible, TAILLE_MAX).map_or_else(Present::Illisible, Present::Lu)
}

/// R3-C1 : Vanguard a noté à `cible` une copie plus récente que `ici` (sa version notée avec son empreinte), et le
/// fichier là n'est plus elle : effacé, illisible, sans version gravée ou d'une version plus basse. Ce programme plus
/// ancien ne s'y pose pas, sans quoi effacer ou abîmer la copie suffisait à faire revenir en arrière sans un mot ;
/// le refus, non vérifié. `None` : rien de tel (aucune copie notée, notée sans version, pas plus récente, toujours
/// là, ou un autre fichier au moins aussi récent, jugé ensuite comme une copie plus récente inconnue).
///
/// Un registre qui ne peut pas être cru (R4-REGISTRE-1 : effacé, abîmé ou réécrit alors qu'un sceau l'attendait, ou
/// réécrit depuis par-dessus ce doute) ne dit pas « rien de noté » : une copie plus récente y était peut-être notée.
/// Refusé, non vérifié, sauf preuve signée (`sortie`, voir `sortie_du_doute`) : ce programme est au moins la dernière
/// version publiée et signée, et ses octets mêmes sont dans l'historique signé pour ce système. Rien de plus récent
/// n'a pu être perdu : c'est la sortie de l'utilisateur légitime, dite dans le refus. Tout effacer d'un
/// coup, sceaux compris, ne laisse pas de témoin : limite écrite (MODELE-DE-MENACE, T3).
fn retour_en_arriere(
    registre: &Path,
    cible: &Path,
    ici: Version,
    la: &Present,
    sortie: impl FnOnce() -> Result<(), crate::modele::Echec>,
) -> Option<String> {
    let notee = match crate::programmes_poses::copie_notee_dans(registre, cible) {
        Ok(n) => n?,
        Err(d) => return registre_douteux(d, ici, sortie()),
    };
    let n = notee.version.as_deref().and_then(lire_version)?;
    if n <= ici {
        return None;
    }
    let (posee, ce_programme) = cote_a_cote(n, ici);
    let etat = match la {
        Present::Absent => tr!("effacée", "deleted").to_string(),
        Present::Illisible(e) => trf!("illisible : {}", "unreadable: {}", e),
        Present::Lu(octets) if blake3::hash(octets).to_hex().as_str() == notee.empreinte => return None,
        Present::Lu(octets) => match version_gravee(octets) {
            None => tr!(
                "remplacée par un fichier sans version gravée",
                "replaced by a file without an engraved version"
            )
            .to_string(),
            Some(v) if v < n => trf!(
                "remplacée par un fichier de version {}",
                "replaced by a file of version {}",
                ecrire(v)
            ),
            Some(_) => return None,
        },
    };
    Some(trf!(
        "non vérifié : Vanguard a posé sur cet ordinateur une copie plus récente ({}) que ce programme ({}), et elle n'y est plus ({}) ; ce programme plus ancien ne la remplace pas (ce serait un retour en arrière), rien n'est posé. Remettez la clé à jour ({} au moins), puis relancez la commande depuis la clé",
        "not checked: Vanguard set up a newer copy ({}) than this program ({}) on this computer, and it is no longer there ({}); this older program does not replace it (that would be a rollback), nothing is set up. Update the key ({} at least), then run the command again from the key",
        posee,
        ce_programme,
        etat,
        ecrire(n)
    ))
}

/// Le refus devant un registre en doute (`retour_en_arriere`), sauf preuve (`sortie` : `Ok`, voir `sortie_du_doute`) :
/// `None`, la pose continue et refait la liste des copies.
fn registre_douteux(
    d: crate::voulues::Doute,
    ici: Version,
    sortie: Result<(), crate::modele::Echec>,
) -> Option<String> {
    let raison = String::from(sortie.err()?);
    Some(trf!(
        "non vérifié : la liste des copies posées par Vanguard {} ; rien ne dit qu'une copie plus récente que ce programme ({}) n'y était pas notée, et ce programme ne se pose pas à sa place (ce serait peut-être un retour en arrière) : rien n'est posé ({}). Remettez la clé à la dernière version publiée, puis relancez la commande depuis la clé avec Internet : Vanguard vérifie qu'elle est la dernière version signée (son numéro et ses octets, dans l'historique signé), et refait la liste",
        "not checked: the list of copies set up by Vanguard {}; nothing shows that a copy newer than this program ({}) was not noted in it, and this program does not set itself up in its place (it might be a rollback): nothing is set up ({}). Update the key to the latest published version, then run the command again from the key with Internet: Vanguard checks that it is the latest signed version (its number and its bytes, in the signed history), and rebuilds the list",
        d.texte(),
        ecrire(ici),
        raison
    ))
}

/// R5 (règle stricte) : la seule sortie d'une liste des copies en doute est une preuve signée sur ce programme même :
/// son numéro (`ici`) est au moins celui de la dernière version signée (`derniere`), ET ses octets sont dans
/// l'historique signé pour ce système, à ce numéro (`signee`). Le numéro seul (R5-ORIGINE-DOC-2) laissait passer une
/// compilation non signée au même numéro. `Err` : pourquoi la preuve manque, dit dans le refus ; une réponse absente
/// n'est jamais comptée comme oui.
fn sortie_du_doute(
    ici: Version,
    derniere: Result<Version, crate::modele::Echec>,
    signee: impl FnOnce() -> Result<bool, crate::modele::Echec>,
) -> Result<(), crate::modele::Echec> {
    const OU: &str = "mise_a_jour/sortie-du-doute";
    match derniere {
        Ok(p) if ici >= p => {}
        Ok(p) => {
            return Err(crate::modele::Echec::refuse(
                OU,
                trf!(
                    "la dernière version signée est {}",
                    "the latest signed version is {}",
                    ecrire(p)
                ),
            ));
        }
        Err(e) => {
            return Err(crate::modele::Echec::refuse(
                OU,
                trf!(
                    "dernière version signée inconnue : {}",
                    "latest signed version unknown: {}",
                    e.to_string()
                ),
            ));
        }
    }
    match signee() {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::modele::Echec::refuse(
            OU,
            tr!(
                "ce programme n'est pas dans l'historique signé des versions pour ce système",
                "this program is not in the signed version history for this system"
            ),
        )),
        Err(e) => Err(crate::modele::Echec::refuse(OU, historique_muet(&e.to_string()))),
    }
}

/// L'historique signé que consulte la sortie du doute de `remplacer` (`poser_copie_dans` reçoit le sien). Aux essais :
/// la réponse que l'essai a donnée (`tests::SIGNEE`), sinon « hors ligne », jamais GitHub.
fn historique_du_doute() -> Historique {
    #[cfg(test)]
    {
        |_| {
            tests::SIGNEE
                .with(std::cell::Cell::get)
                .ok_or_else(|| crate::modele::Echec::echoue("mise_a_jour/historique", "hors ligne (essai)"))
        }
    }
    #[cfg(not(test))]
    {
        signee_pour_ce_systeme
    }
}

/// La dernière version publiée et signée, demandée seulement devant un registre en doute (`registre_douteux`). Aux
/// essais : celle que l'essai a donnée (`tests::DERNIERE`), sinon « hors ligne », jamais GitHub.
fn derniere_publiee() -> Result<Version, crate::modele::Echec> {
    #[cfg(test)]
    {
        tests::DERNIERE
            .with(std::cell::Cell::get)
            .ok_or_else(|| crate::modele::Echec::echoue("mise_a_jour/historique", "hors ligne (essai)"))
    }
    #[cfg(not(test))]
    {
        // R5-ORIGINE-DOC-1 : sans versions vues crues, `derniere` ne répond jamais ; le geste qui en sort est dit.
        if github::versions_vues_douteuses() {
            return Err(crate::modele::Echec::echoue(
                "mise_a_jour/historique",
                tr!(
                    "les versions déjà vues ici ont été changées hors de Vanguard ; lancez « vanguard se-mettre-a-jour » avec Internet et acceptez de repartir de la version signée reçue",
                    "the versions already seen here were changed outside Vanguard; run “vanguard se-mettre-a-jour” with Internet and agree to start over from the signed version received"
                ),
            ));
        }
        github::derniere().map(|p| p.version).map_err(|e| {
            let texte = match &e {
                github::EchecRepartir::NonRecu(e) => e.to_string(),
                _ => echec_dit(&e, Repartir::Non).0.trim().to_string(),
            };
            crate::modele::Echec::echoue("mise_a_jour/historique", texte)
        })
    }
}

/// `poser_copie` vers `cible` ; seuls les octets du programme qui tourne (`soi`) se posent (`de_soi`). Une copie déjà
/// là n'est gardée que si ses octets sont connus : ceux du programme qui tourne ; plus récente, une copie que Vanguard
/// y a posée lui-même (notée dans la liste des copies du registre scellé de `registre` par
/// `programmes_poses::copie_posee_ici` : d'une mise à jour signée ou d'une clé plus récente ; un sceau de tâche ne compte
/// pas, R1-M1) ; ou, plus récente et absente de la liste, une version publiée et signée pour ce système
/// (`historique` : une copie posée avant que la liste existe, N3-O3). Sinon, une copie plus récente n'est jamais
/// remplacée par ce programme plus ancien (R1-M2) ni gardée : refusé, dit non vérifié, rien n'est posé. Il en va de
/// même d'une copie illisible, et d'une copie plus récente notée dont le fichier n'est plus là tel quel (R3-C1).
fn poser_copie_dans(
    source: &Path,
    cible: &Path,
    soi: Option<&str>,
    registre: &Path,
    historique: Historique,
    essai: Essai,
) -> Result<Option<String>, String> {
    let octets = lire_octets(source, TAILLE_MAX)?;
    if !de_soi(&octets, soi) {
        return Err(pas_de_soi(soi));
    }
    let Some(version) = version_gravee(&octets) else {
        return Err(tr!(
            "pas de version gravée dans le programme",
            "no engraved version in the program"
        )
        .into());
    };
    // La fenêtre posée à côté du programme de la clé suit la copie, si c'est bien la sienne.
    let fenetre = sa_fenetre::de_la_source(source, &octets).zip(sa_fenetre::pour(cible));
    let la = present(cible);
    // Gardée : ses octets, lus une fois, notés comme posés par Vanguard, avec leur version (la tâche posée ensuite les
    // reconnaît, et une pose plus ancienne saura qu'une copie plus récente était là).
    let garder = |la: &[u8]| {
        crate::programmes_poses::copie_posee_dans(registre, cible, la);
        Ok(None)
    };
    // D'abord : une copie plus récente notée n'est plus là telle quelle. Même les octets du programme qui tourne ne
    // sont pas gardés à sa place : ce serait bénir un retour en arrière déjà fait sur le disque.
    let sortie = || sortie_du_doute(version, derniere_publiee(), || historique(&octets));
    if let Some(refus) = retour_en_arriere(registre, cible, version, &la, sortie) {
        return Err(refus);
    }
    if let Present::Lu(la) = &la {
        if la == &octets {
            crate::programmes_poses::copie_posee_dans(registre, cible, la);
            // La même copie : sa fenêtre seule, si elle manque ou diffère. Un échec n'arrête pas la copie, que la
            // surveillance lance : sans sa fenêtre, le raccourci ouvre le menu.
            let Some((f, chemin)) = &fenetre else {
                return Ok(None);
            };
            return Ok(sa_fenetre::poser_si_autre(f, chemin).err().map(|e| {
                trf!(
                    "la fenêtre n'a pas pu être posée à côté de la copie ({}) : le raccourci ouvrira le menu",
                    "the window could not be placed next to the copy ({}): the shortcut will open the menu",
                    e
                )
            }));
        }
        let plus_recente = version_gravee(la).is_some_and(|v| v > version);
        if plus_recente
            && crate::programmes_poses::copie_connue_dans(registre, cible, blake3::hash(la).to_hex().as_str())
        {
            return garder(la);
        }
    }
    match &la {
        // Jamais remplacée sans avoir été lue : sa version n'a pas pu être vérifiée (comme `plus_ancien`).
        Present::Illisible(e) => return Err(copie_illisible(e)),
        Present::Lu(la) => {
            if let Some(v) = version_gravee(la).filter(|&v| v > version) {
                // Plus récente et pas dans la liste : une vraie version publiée (posée par une version d'avant la
                // liste, N3-O3), ou un fichier d'un autre programme. L'historique signé départage ; sans réponse,
                // refusé, jamais cédé en silence.
                return match historique(la) {
                    Ok(true) => garder(la),
                    Ok(false) => Err(plus_recente_inconnue(
                        v,
                        version,
                        tr!(
                            "absente de l'historique signé des versions pour ce système",
                            "not in the signed version history for this system"
                        ),
                    )),
                    Err(e) => Err(plus_recente_inconnue(v, version, &historique_muet(&e.to_string()))),
                };
            }
        }
        Present::Absent => {}
    }
    if let Some(d) = cible.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    match &fenetre {
        Some((f, chemin)) => sa_fenetre::installer_avec_sinon_seul(
            &octets,
            cible,
            version,
            registre,
            &copie_de_cet_ordinateur(),
            essai,
            f,
            chemin,
        ),
        None => installer(&octets, cible, version, registre, &copie_de_cet_ordinateur(), essai).map(|()| None),
    }
}

/// Le refus devant une copie plus récente que Vanguard ne reconnaît ni comme la sienne (pas dans la liste de son
/// registre) ni comme une version publiée signée (`pourquoi`) : ni gardée (elle pourrait venir d'un autre programme du
/// compte), ni remplacée (ce serait un retour en arrière, peut-être d'une vraie version dont le registre est perdu).
/// Dit non vérifié, jamais sain ni tu, et sans jamais conseiller de lancer ce fichier inconnu (R3-C4).
fn plus_recente_inconnue(la: Version, ici: Version, pourquoi: &str) -> String {
    trf!(
        "non vérifié : la copie de cet ordinateur ({}) est plus récente que ce programme ({}), mais Vanguard ne la reconnaît ni comme celle qu'il a posée (registre absent, illisible ou sans elle) ni comme une version publiée ({}) ; elle n'est ni gardée ni remplacée par une version plus ancienne, rien n'est posé. Retirez-la si vous ne l'avez pas posée vous-même ; sinon, remettez la clé à jour ({} au moins), puis relancez la commande depuis la clé",
        "not checked: the copy on this computer ({}) is newer than this program ({}), but Vanguard recognizes it neither as the one it set up (register missing, unreadable or without it) nor as a published version ({}); it is neither kept nor replaced by an older version, nothing is set up. Remove it if you did not put it there yourself; otherwise, update the key ({} at least), then run the command again from the key",
        ecrire(la),
        ecrire(ici),
        pourquoi,
        ecrire(la)
    )
}

/// Pourquoi l'historique signé n'a rien dit.
fn historique_muet(e: &str) -> String {
    trf!(
        "historique signé non consulté : {}",
        "signed history not checked: {}",
        e
    )
}

/// Le refus devant une copie qui ne se lit pas (droits retirés, démesurée, pas un fichier ordinaire) : sa version n'a
/// pas pu être vérifiée, elle n'est pas remplacée à l'aveugle.
fn copie_illisible(e: &str) -> String {
    trf!(
        "non vérifié : la copie de cet ordinateur ne se lit pas ({}) ; sa version n'a pas pu être vérifiée, elle n'est pas remplacée sans avoir été lue, rien n'est posé. Retirez-la si vous ne l'avez pas posée vous-même, puis relancez la commande",
        "not checked: the copy on this computer cannot be read ({}); its version could not be checked, it is not replaced unread, nothing is set up. Remove it if you did not put it there yourself, then run the command again",
        e
    )
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
    mettre_en_place_sous(provisoire, cible, &cible.with_file_name(format!("{NOM}.ancien")))
}

/// `mettre_en_place`, l'ancien mis de côté sous le nom `ancien` (la fenêtre a le sien, `sa_fenetre`).
fn mettre_en_place_sous(provisoire: &Path, cible: &Path, ancien: &Path) -> std::io::Result<()> {
    let erreur = match std::fs::rename(provisoire, cible) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    if !cfg!(windows) {
        return Err(erreur);
    }
    // Celui d'une mise à jour précédente tourne peut-être encore : rien ne se remplace, et c'est dit clairement.
    if std::fs::symlink_metadata(ancien).is_ok() && std::fs::remove_file(ancien).is_err() {
        return Err(std::io::Error::other(tr!(
            "l'ancienne copie tourne encore (surveillance) : réessayez dans une minute",
            "the old copy is still running (monitoring): try again in a minute"
        )));
    }
    std::fs::rename(cible, ancien)?;
    std::fs::rename(provisoire, cible).inspect_err(|_| {
        let _ = std::fs::rename(ancien, cible);
    })
}

/// « vanguard se-mettre-a-jour » et l'entrée du menu : l'état, puis la mise à jour sur accord. `false` (R4-REGISTRE-5) :
/// un refus ou un doute a été dit (copie illisible ou non reconnue, pose refusée, programme dit non vérifié, mise à
/// jour manquée) ; un « n » de la personne et GitHub injoignable ne sont pas des refus.
pub fn commande() -> bool {
    titre(tr!("Mettre Vanguard à jour", "Update Vanguard"));
    trp!(
        "  {GRIS}La copie de Vanguard posée sur cet ordinateur (surveillance, entretien,\n  raccourci) ne suit pas la clé : elle se met à jour d'ici, sur accord.{RESET}\n",
        "  {GRIS}The copy of Vanguard placed on this computer (monitoring, maintenance,\n  shortcut) does not follow the key: it is updated from here, on your OK.{RESET}\n"
    );
    let cible = copie_de_cet_ordinateur();
    // Le reste d'une mise à jour faite pendant que la copie (ou sa fenêtre) tournait (Windows).
    let _ = std::fs::remove_file(cible.with_file_name(format!("{NOM}.ancien")));
    sa_fenetre::effacer_l_ancienne(&cible);
    let mut sans_refus = true;
    match etat() {
        Etat::Rien => trp!(
            "  Pas de copie de Vanguard posée sur cet ordinateur (la surveillance,\n  l'entretien et le raccourci en posent une).",
            "  No copy of Vanguard placed on this computer (monitoring, maintenance\n  and the shortcut place one)."
        ),
        Etat::PasDepuisLaCle => trp!(
            "  {GRIS}Vanguard ne tourne pas depuis la clé VANGUARD : la mise à jour vient de GitHub.{RESET}",
            "  {GRIS}Vanguard is not running from the VANGUARD key: the update comes from GitHub.{RESET}"
        ),
        Etat::Illisible(e) => {
            sans_refus = false;
            trp!(
                "  ✖ La copie de cet ordinateur ne se lit pas : sa version reste inconnue.\n    {GRIS}{} : {}{RESET}",
                "  ✖ The copy on this computer cannot be read: its version is unknown.\n    {GRIS}{}: {}{RESET}",
                affichable(&cible.display().to_string()),
                affichable(&e)
            );
        }
        Etat::AJour(v) => trp!(
            "  {VERT}✔{RESET} La copie de cet ordinateur est à jour ({}).",
            "  {VERT}✔{RESET} The copy on this computer is up to date ({}).",
            ecrire(v)
        ),
        Etat::ClePlusAncienne { copie, cle } => {
            let (copie, cle) = cote_a_cote(copie, cle);
            // Sa version gravée ne dit pas qu'elle vient de Vanguard (R3-C3) : seulement la liste des copies qu'il a
            // posées, ou l'historique signé.
            match reconnue_ici(&cible) {
                Ok(()) => trp!(
                    "  La copie d'ici ({copie}) est plus récente que la clé ({cle}).\n  Remettez la clé à jour chez vous : Vanguard ne revient jamais en arrière.",
                    "  The copy on this computer ({copie}) is newer than the key ({cle}).\n  Update the key at home: Vanguard never goes back to an older version."
                ),
                Err(pourquoi) => {
                    sans_refus = false;
                    trp!(
                        "  Non vérifié : la copie d'ici se dit plus récente ({copie}) que la clé ({cle}),\n  mais Vanguard ne la reconnaît ni comme celle qu'il a posée ni comme une version publiée\n  ({}). Elle n'est pas remplacée : Vanguard ne revient jamais en arrière.\n  Retirez-la si vous ne l'avez pas posée vous-même ; sinon, remettez la clé à jour.",
                        "  Not checked: the copy on this computer claims to be newer ({copie}) than the key ({cle}),\n  but Vanguard recognizes it neither as the one it set up nor as a published version\n  ({}). It is not replaced: Vanguard never goes back to an older version.\n  Remove it if you did not put it there yourself; otherwise, update the key.",
                        affichable(&pourquoi.to_string())
                    );
                }
            }
        }
        Etat::AMettreAJour { source, copie, cle } => sans_refus = proposer(&source, &cible, copie, cle),
    }
    // R5-CODES-1 : une question qui suit (GitHub) et trouve l'entrée finie ne rend jamais 0 par-dessus ce refus.
    if !sans_refus {
        crate::ui::refus_dit();
    }
    depuis_github() && sans_refus
}

/// La copie de cet ordinateur, à `cible`, est-elle reconnue comme venant de Vanguard : notée dans la liste des copies
/// qu'il a posées, ou publiée et signée pour ce système ? `Err` : pourquoi non, ou pourquoi on ne sait pas.
pub(super) fn reconnue_ici(cible: &Path) -> Result<(), crate::modele::Echec> {
    let la = lire_octets(cible, TAILLE_MAX).map_err(|e| crate::modele::Echec::echoue("mise_a_jour/historique", e))?;
    if crate::programmes_poses::copie_connue_dans(
        &crate::socle::dossier_local(),
        cible,
        blake3::hash(&la).to_hex().as_str(),
    ) {
        return Ok(());
    }
    // R4-ORIGINE-DOC-6 (b) : une liste en doute n'est pas dite « absente de la liste » : elle n'a pas pu être crue.
    let liste = match crate::programmes_poses::copie_notee_dans(&crate::socle::dossier_local(), cible) {
        Err(d) => trf!(
            "la liste des copies posées par Vanguard {}",
            "the list of copies set up by Vanguard {}",
            d.texte()
        ),
        Ok(_) => tr!(
            "absente de la liste des copies posées",
            "not in the list of copies set up"
        )
        .to_string(),
    };
    match signee_pour_ce_systeme(&la) {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::modele::Echec::refuse(
            "mise_a_jour/historique",
            trf!(
                "{} ; absente de l'historique signé",
                "{}; not in the signed history",
                liste
            ),
        )),
        Err(e) => Err(crate::modele::Echec::echoue(
            "mise_a_jour/historique",
            trf!("{} ; {}", "{}; {}", liste, historique_muet(&e.to_string())),
        )),
    }
}

/// Ce que la mise à jour depuis GitHub fait de chaque programme d'ici, la version publiée étant `publiee` : (planchers,
/// à remplacer, doutes à dire). Le programme lancé et les copies d'ici servent de plancher : une version plus récente
/// que la dernière signée sur GitHub (passée par la clé VANGUARD, sans jamais voir GitHub) trahit un ancien manifeste
/// remis en place. Une copie de cet ordinateur (`copie`) qui se dit plus récente sans être reconnue comme venant de
/// Vanguard (`reconnue`, R3-C3) ne sert pas de plancher : un simple numéro gravé ferait soupçonner GitHub à tort ; elle
/// est dite non vérifiée, et n'est pas remplacée. Une copie plus récente que la version publiée, notée dans le registre
/// de `registre` et qui n'est plus là telle quelle (R3-C1), n'est pas remplacée par cette version plus ancienne. Une
/// liste des copies en doute est toujours dite (R5-REGISTRE-3) : seule une copie plus ancienne que la version publiée
/// est remplacée ; au même numéro, ou absente, rien ne l'est.
pub(super) fn juger_cibles(
    cibles: Vec<PathBuf>,
    publiee: Version,
    copie: &Path,
    registre: &Path,
    reconnue: impl Fn(&Path) -> Result<(), crate::modele::Echec>,
) -> (Vec<Version>, Vec<PathBuf>, Vec<String>) {
    let mut ici: Vec<Version> = courante().into_iter().collect();
    let mut doutes = Vec::new();
    let mut a_remplacer = Vec::new();
    // R5-REGISTRE-3 : une liste des copies en doute est dite à chaque fois, copie absente ou au même numéro compris ;
    // jamais une coche verte ni un silence par-dessus.
    let doute = crate::programmes_poses::copie_notee_dans(registre, copie).err();
    if let Some(d) = doute
        && !cibles.iter().any(|c| meme_fichier(c, copie))
    {
        doutes.push(doute_sans_copie(d));
    }
    for c in cibles {
        if let Lu::Version(v) = lire_programme(&c, TAILLE_MAX) {
            if v > publiee
                && meme_fichier(&c, copie)
                && let Err(pourquoi) = reconnue(&c)
            {
                doutes.push(trf!(
                    "  Non vérifié : la copie de cet ordinateur se dit plus récente ({}) que la dernière\n  version signée ({}), mais Vanguard ne la reconnaît pas ({}).\n  Elle n'est ni crue ni remplacée. Retirez-la si vous ne l'avez pas posée vous-même.",
                    "  Not checked: the copy on this computer claims to be newer ({}) than the latest\n  signed version ({}), but Vanguard does not recognize it ({}).\n  It is neither trusted nor replaced. Remove it if you did not put it there yourself.",
                    ecrire(v),
                    ecrire(publiee),
                    affichable(&pourquoi.to_string())
                ));
                continue;
            }
            ici.push(v);
        }
        // R4-REGISTRE-1 : la liste des copies en doute ne dit pas qu'une copie plus récente n'était pas notée ; la
        // dernière version signée, elle, ne revient sur rien de publié : elle remplace une copie plus ancienne et
        // refait la liste, et c'est dit. Au même numéro : dite, gardée, la liste reste en doute.
        if meme_fichier(&c, copie)
            && let Some(d) = doute
        {
            if !plus_ancien(&c, publiee) {
                doutes.push(trf!(
                    "  Non vérifié : la liste des copies posées par Vanguard {} ; rien ne dit\n  qu'une copie plus récente n'y était pas notée. La copie d'ici n'est pas plus ancienne que\n  la dernière version signée ({}) : rien n'est remplacé, et la liste reste en doute.\n  Reposez-la depuis une clé à la dernière version signée.",
                    "  Not checked: the list of copies set up by Vanguard {}; nothing shows\n  that a newer copy was not noted in it. The copy here is not older than the latest\n  signed version ({}): nothing is replaced, and the list stays in doubt.\n  Set it up again from a key at the latest signed version.",
                    d.texte(),
                    ecrire(publiee)
                ));
                continue;
            }
            doutes.push(trf!(
                "  Non vérifié : la liste des copies posées par Vanguard {} ; rien ne dit\n  qu'une copie plus récente n'y était pas notée. Seule la dernière version signée ({})\n  la remplace, et la liste est refaite.",
                "  Not checked: the list of copies set up by Vanguard {}; nothing shows\n  that a newer copy was not noted in it. Only the latest signed version ({})\n  replaces it, and the list is rebuilt.",
                d.texte(),
                ecrire(publiee)
            ));
            a_remplacer.push(c);
            continue;
        }
        if !plus_ancien(&c, publiee) {
            continue;
        }
        if let Some(refus) = retour_en_arriere(registre, &c, publiee, &present(&c), || Ok(())) {
            doutes.push(format!("  {}", affichable(&refus)));
            continue;
        }
        a_remplacer.push(c);
    }
    (ici, a_remplacer, doutes)
}

/// Le doute sur la liste des copies quand la copie de cet ordinateur n'est pas là (R5-REGISTRE-3, R5-ORIGINE-DOC-1).
pub(super) fn doute_sans_copie(d: crate::voulues::Doute) -> String {
    trf!(
        "  Non vérifié : la liste des copies posées par Vanguard {} ; rien ne dit\n  qu'une copie plus récente n'y était pas notée, et la copie de cet ordinateur n'est pas là.\n  Une clé plus ancienne ne s'y pose pas. Posez-la depuis une clé à la dernière version signée.",
        "  Not checked: the list of copies set up by Vanguard {}; nothing shows\n  that a newer copy was not noted in it, and the copy on this computer is not there.\n  An older key does not set itself up there. Set it up from a key at the latest signed version.",
        d.texte()
    )
}

/// GitHub pas consulté (injoignable, ou dossier d'un autre compte) : sans doute sur la liste des copies, ce n'est pas
/// un refus (`true`, écrit) ; liste en doute, le doute est dit et le code est non nul (`false`).
fn sans_github(doute: Option<crate::voulues::Doute>) -> bool {
    let Some(d) = doute else {
        return true;
    };
    crate::ui::refus_dit();
    println!("\n{}", doute_hors_github(d));
    false
}

fn doute_hors_github(d: crate::voulues::Doute) -> String {
    trf!(
        "  Non vérifié : la liste des copies posées par Vanguard {} ; rien ne dit\n  qu'une copie plus récente n'y était pas notée, et GitHub n'a pas été consulté :\n  rien n'est remplacé, et la liste reste en doute. Relancez « vanguard se-mettre-a-jour »\n  avec Internet, ou reposez la copie depuis une clé à la dernière version signée.",
        "  Not checked: the list of copies set up by Vanguard {}; nothing shows\n  that a newer copy was not noted in it, and GitHub was not reached:\n  nothing is replaced, and the list stays in doubt. Run “vanguard se-mettre-a-jour”\n  again with Internet, or set the copy up again from a key at the latest signed version.",
        d.texte()
    )
}

/// Ce que la personne a choisi pour des versions déjà vues changées hors de Vanguard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Repartir {
    /// Les versions vues sont crues : rien à demander.
    PasBesoin,
    /// « o » : repartir de la version signée reçue (`github::derniere_en_repartant`) ; le code reste non nul.
    Oui,
    /// « n » : rien n'est reçu ni oublié.
    Non,
}

/// Les versions déjà vues ici, changées hors de Vanguard, ne protègent plus d'un vieux manifeste : dit, puis demande
/// s'il faut repartir de la version signée qui sera reçue. Rien n'est oublié ici : seulement une fois un manifeste
/// signé reçu (`github::derniere_en_repartant`).
fn repartir_des_versions_vues() -> Repartir {
    if !github::versions_vues_douteuses() {
        return Repartir::PasBesoin;
    }
    trp!(
        "\n  ✖ Les versions déjà vues ici ont été changées hors de Vanguard :\n    elles ne protègent plus d'un vieux manifeste remis sur GitHub.\n    Rien n'est vérifié tant qu'elles ne repartent pas de zéro.",
        "\n  ✖ The versions already seen here were changed outside Vanguard:\n    they no longer protect against an old manifest put back on GitHub.\n    Nothing is checked until they start over."
    );
    // R6-CODES-1, R7-CODES-1 : dit avant la question, qui quitte en fin d'entrée ; même reparti, un changement hors de
    // Vanguard a été vu : le code reste non nul (`depuis_github`).
    crate::ui::refus_dit();
    if demander(tr!(
        "  Repartir de la version signée que GitHub va envoyer ? [o/N] : ",
        "  Start over from the signed version GitHub will send? [y/N]: "
    ))
    .oui()
    {
        Repartir::Oui
    } else {
        Repartir::Non
    }
}

/// Ce que donne `derniere_selon`.
enum Reception {
    Recue(github::Publiee),
    /// GitHub en erreur ou manifeste refusé, dit : rien n'a été vérifié.
    SansGithub,
    /// Manifeste signé reçu, mais l'état local pas écrit ou pas scellé jusqu'au bout (en repartant, ou la révocation de
    /// la principale), dit avec le fichier en cause (jamais « GitHub n'a pas été consulté »).
    NonEcrit,
}

/// La dernière version signée reçue de GitHub, en repartant des versions vues si la personne l'a voulu ; reparti, c'est
/// dit, et chaque échec aussi (rien n'est oublié).
fn derniere_selon(repartir: Repartir) -> Reception {
    let recue = if repartir == Repartir::Oui {
        github::derniere_en_repartant()
    } else {
        github::derniere()
    };
    let publiee = match recue {
        Ok(p) => p,
        Err(e) => {
            let (texte, reception) = echec_dit(&e, repartir);
            crate::ui::imprimer(&texte);
            return reception;
        }
    };
    if repartir == Repartir::Oui {
        trp!(
            "  Les versions déjà vues repartent de la version signée reçue ({}).",
            "  The versions already seen start over from the signed version received ({}).",
            ecrire(publiee.version)
        );
    }
    Reception::Recue(publiee)
}

/// Un échec de `github::derniere` ou de `github::derniere_en_repartant`, dit (une ligne en retrait), et ce qu'il donne.
/// Seul un manifeste pas reçu ou refusé parle de GitHub ; un fichier d'ici pas écrit est nommé, avec son dossier.
fn echec_dit(e: &github::EchecRepartir, repartir: Repartir) -> (String, Reception) {
    use github::EchecRepartir::{NonEcrit, NonRecu, Revocation};
    let dossier = crate::socle::dossier_local();
    match e {
        NonRecu(e) if repartir == Repartir::Oui => (
            trf!(
                "  GitHub : {}. Rien n'a été vérifié, et rien n'est oublié : les versions vues restent en doute.",
                "  GitHub: {}. Nothing was checked, and nothing is forgotten: the versions seen stay in doubt.",
                affichable(&e.to_string())
            ),
            Reception::SansGithub,
        ),
        NonRecu(e) => (
            trf!(
                "  GitHub : {}. Rien n'a été vérifié.",
                "  GitHub: {}. Nothing was checked.",
                affichable(&e.to_string())
            ),
            Reception::SansGithub,
        ),
        NonEcrit(v, fichier, e) => (
            non_ecrit(*v, fichier, &dossier, &e.to_string(), github::versions_vues_douteuses()),
            Reception::NonEcrit,
        ),
        Revocation(v, fichier, e) => (
            revocation_non_retenue(*v, fichier, &dossier, &e.to_string()),
            Reception::NonEcrit,
        ),
    }
}

/// Manifeste de secours reçu, révocation de la principale pas retenue jusqu'au bout (`github::EchecRepartir::Revocation`) :
/// rien n'est installé, la passe suivante reprend là.
fn revocation_non_retenue(v: Version, fichier: &Path, dossier: &Path, e: &str) -> String {
    trf!(
        "  Version signée par la clé de secours reçue ({}), mais la révocation de la clé principale n'a pas pu être retenue jusqu'au bout : {} n'a pas pu être écrit, effacé ou scellé ({}). Rien n'est installé. Vérifiez ce fichier et le dossier {} (son registre des sceaux), puis relancez : la suite reprend là.",
        "  Version signed by the backup key received ({}), but the revocation of the main key could not be kept all the way: {} could not be written, erased or sealed ({}). Nothing is installed. Check this file and the folder {} (its seal register), then run again: it picks up from there.",
        ecrire(v),
        affichable(&fichier.display().to_string()),
        affichable(e),
        affichable(&dossier.display().to_string())
    )
}

/// Manifeste signé reçu, état local pas écrit ou pas scellé jusqu'au bout (`github::EchecRepartir::NonEcrit`). L'erreur
/// peut venir du fichier, de son verrou ou du registre des sceaux du dossier : les deux sont nommés. `doute` relu après
/// l'échec : « restent en doute » n'est dit que si c'est vrai (le fichier peut être écrit et seul son sceau manquer).
fn non_ecrit(v: Version, fichier: &Path, dossier: &Path, e: &str, doute: bool) -> String {
    let (f, d, e) = (
        affichable(&fichier.display().to_string()),
        affichable(&dossier.display().to_string()),
        affichable(e),
    );
    if doute {
        trf!(
            "  Version signée reçue ({}), mais {} n'a pas pu être écrit ou scellé ({}) : rien n'est oublié, les versions vues restent en doute. Vérifiez ce fichier et le dossier {} (son registre des sceaux), puis relancez.",
            "  Signed version received ({}), but {} could not be written or sealed ({}): nothing is forgotten, the versions seen stay in doubt. Check this file and the folder {} (its seal register), then run again.",
            ecrire(v),
            f,
            e,
            d
        )
    } else {
        trf!(
            "  Version signée reçue ({}) et retenue comme plus haute vue, mais le scellement de {} n'a pas fini ({}). Vérifiez le dossier {} (son registre des sceaux), puis relancez.",
            "  Signed version received ({}) and kept as the highest seen, but sealing {} did not finish ({}). Check the folder {} (its seal register), then run again.",
            ecrire(v),
            f,
            e,
            d
        )
    }
}

/// La dernière version publiée sur GitHub : montrée, puis téléchargée, vérifiée et installée après un « o », à la
/// place de chaque programme d'ici qui est plus ancien.
fn depuis_github() -> bool {
    if let Some(exe) = programme_ecarte_en_root() {
        trp!(
            "\n  {GRIS}Lancé en root depuis un dossier que d'autres comptes peuvent changer :\n  {}\n  Ce programme n'est pas remplacé d'ici : posez-le dans un dossier à root,\n  ou mettez-le à jour sans sudo.{RESET}",
            "\n  {GRIS}Started as root from a folder other accounts can change:\n  {}\n  This program is not replaced from here: put it in a root-owned folder,\n  or update it without sudo.{RESET}",
            chemin_affichable(&exe)
        );
    }
    let cibles = cibles_github();
    if cibles.is_empty() {
        // R5-ORIGINE-DOC-1 : rien à remplacer, mais une liste des copies en doute est dite (code non nul), et la
        // sortie offerte : sans versions vues crues, la clé à la dernière version ne pourrait pas prouver qu'elle
        // l'est (`sortie_du_doute`), et la personne resterait bloquée sans geste indiqué.
        let registre = crate::socle::dossier_local();
        return match crate::programmes_poses::copie_notee_dans(&registre, &copie_de_cet_ordinateur()) {
            Err(d) => {
                crate::ui::refus_dit();
                println!("\n{}", doute_sans_copie(d));
                // R6-ORIGINE-DOC-2 : « o » reçoit vraiment la version signée avant d'oublier quoi que ce soit.
                if github::dossier_sur() && repartir_des_versions_vues() == Repartir::Oui {
                    let _ = derniere_selon(Repartir::Oui);
                }
                false
            }
            Ok(_) => true,
        };
    }
    // R6-REGISTRE-3 : le doute sur la liste est un fait d'ici, connu sans réseau ; GitHub muet ne le tait jamais.
    let doute =
        crate::programmes_poses::copie_notee_dans(&crate::socle::dossier_local(), &copie_de_cet_ordinateur()).err();
    if !github::dossier_sur() {
        trp!(
            "\n  {GRIS}Lancé en root avec le dossier d'un autre compte : pas de mise à jour depuis GitHub.\n  Relancez Vanguard depuis ce compte.{RESET}",
            "\n  {GRIS}Started as root with another account's folder: no update from GitHub.\n  Start Vanguard again from that account.{RESET}"
        );
        return sans_github(doute);
    }
    // R7-REGISTRE-1 : le doute sur la liste est dit avant la question, qui peut quitter (fin d'entrée).
    if let Some(d) = doute
        && github::versions_vues_douteuses()
    {
        crate::ui::refus_dit();
        println!("\n{}", doute_de_la_liste(d));
    }
    let repartir = repartir_des_versions_vues();
    if repartir == Repartir::Non {
        return false;
    }
    // Reparti : un changement hors de Vanguard a été vu ; jamais compté comme une réussite (R7-CODES-1).
    depuis_github_vers(cibles, doute, repartir) && repartir == Repartir::PasBesoin
}

fn doute_de_la_liste(d: crate::voulues::Doute) -> String {
    trf!(
        "  Non vérifié : la liste des copies posées par Vanguard {} ; rien ne dit\n  qu'une copie plus récente n'y était pas notée.",
        "  Not checked: the list of copies set up by Vanguard {}; nothing shows\n  that a newer copy was not noted in it.",
        d.texte()
    )
}

/// La suite de `depuis_github`, une fois les versions vues crues ou la personne d'accord pour en repartir.
fn depuis_github_vers(cibles: Vec<PathBuf>, doute: Option<crate::voulues::Doute>, repartir: Repartir) -> bool {
    trp!(
        "\n  {GRIS}Dernière version publiée sur GitHub…{RESET}",
        "\n  {GRIS}Latest version published on GitHub…{RESET}"
    );
    let publiee = match derniere_selon(repartir) {
        Reception::Recue(p) => p,
        Reception::SansGithub => return sans_github(doute),
        // GitHub a répondu : seul le doute sur la liste est redit, sans « GitHub n'a pas été consulté ».
        Reception::NonEcrit => {
            crate::ui::refus_dit();
            if let Some(d) = doute {
                println!("\n{}", doute_de_la_liste(d));
            }
            return false;
        }
    };
    let (ici, a_remplacer, doutes) = juger_cibles(
        cibles,
        publiee.version,
        &copie_de_cet_ordinateur(),
        &crate::socle::dossier_local(),
        reconnue_ici,
    );
    if !doutes.is_empty() {
        crate::ui::refus_dit();
    }
    for d in &doutes {
        println!("{d}");
    }
    if a_remplacer.is_empty() {
        dire_a_jour(publiee.version, &ici, maintenant(), !doutes.is_empty());
        return doutes.is_empty();
    }
    trp!(
        "  Vanguard {} est publié, signé par son auteur (signature vérifiée).\n  Il remplacerait :",
        "  Vanguard {} is published, signed by its author (signature checked).\n  It would replace:",
        ecrire(publiee.version)
    );
    // Chaque fenêtre telle que montrée : la pose la compare à ce qui est là (C-7, relecture 0.96).
    let mut vues = Vec::with_capacity(a_remplacer.len());
    for c in &a_remplacer {
        let v = match lire_programme(c, TAILLE_MAX) {
            Lu::Version(v) => ecrire(v),
            _ => version_affichee(None),
        };
        println!("    {} {GRIS}({v}){RESET}", affichable(&c.display().to_string()));
        // Sa fenêtre : remplacée par celle de la nouvelle version, vérifiée contre l'empreinte qu'elle grave.
        let vue = sa_fenetre::a_cote(c);
        if let Some(f) = &vue {
            trp!(
                "    {} {GRIS}(sa fenêtre){RESET}",
                "    {} {GRIS}(its window){RESET}",
                affichable(&f.display().to_string())
            );
        }
        vues.push(sa_fenetre::Vue::de(vue));
    }
    if !demander(tr!(
        "  Le télécharger et l'installer ? [o/N] : ",
        "  Download and install it? [y/N]: "
    ))
    .oui()
    {
        return doutes.is_empty();
    }
    let octets = match github::programme_verifie(&publiee) {
        Ok(o) => o,
        Err(e) => {
            trp!("  ✖ {}", "  ✖ {}", affichable(&e));
            return false;
        }
    };
    // La fenêtre de la nouvelle version : téléchargée une fois, et seulement si une fenêtre est posée à côté d'un
    // programme remplacé (`sa_fenetre`).
    let mut recue: Option<Vec<u8>> = None;
    let mut recevoir = || -> Result<Vec<u8>, String> {
        if let Some(f) = &recue {
            return Ok(f.clone());
        }
        let f = github::fenetre_recue()?;
        recue = Some(f.clone());
        Ok(f)
    };
    let mut sans_refus = doutes.is_empty();
    for (c, vue) in a_remplacer.iter().zip(&vues) {
        match sa_fenetre::installer_avec_sa_fenetre(
            &octets,
            c,
            publiee.version,
            &crate::socle::dossier_local(),
            &copie_de_cet_ordinateur(),
            essayer,
            vue,
            &mut recevoir,
        ) {
            Ok(()) => trp!(
                "  {VERT}✔{RESET} {} : Vanguard {}.",
                "  {VERT}✔{RESET} {}: Vanguard {}.",
                affichable(&c.display().to_string()),
                ecrire(publiee.version)
            ),
            Err(e) => {
                sans_refus = false;
                trp!(
                    "  ✖ {} n'est pas remplacé, l'ancien reste en place :\n    {}",
                    "  ✖ {} is not replaced, the old one stays in place:\n    {}",
                    affichable(&c.display().to_string()),
                    affichable(&e)
                );
            }
        }
    }
    sans_refus
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
    /// R4-REGISTRE-3 : un programme d'ici a été dit non vérifié (ci-dessus) : jamais de coche verte après.
    Doutes,
}

/// Le verdict d'après la dernière version signée, les versions des programmes d'ici et l'heure. Seul le numéro
/// compte pour le plancher, pas la date : une compilation de développement porte le numéro publié et une date
/// plus récente, sans rien trahir.
fn verdict(publiee: Version, ici: &[Version], maintenant: u64, doutes: bool) -> Verdict {
    let numero = |v: Version| (v.0, v.1, v.2);
    if let Some(&v) = ici.iter().filter(|v| numero(**v) > numero(publiee)).max() {
        return Verdict::PlusRecenteIci(v);
    }
    if doutes {
        return Verdict::Doutes;
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
fn dire_a_jour(publiee: Version, ici: &[Version], maintenant: u64, doutes: bool) {
    match verdict(publiee, ici, maintenant, doutes) {
        Verdict::Doutes => trp!(
            "  Non vérifié : rien n'est remplacé depuis GitHub (dernière version : {}),\n  mais ce qui est dit ci-dessus reste à régler.",
            "  Not checked: nothing is replaced from GitHub (latest version: {}),\n  but what is said above still needs fixing.",
            ecrire(publiee)
        ),
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

/// Où la fenêtre de la clé serait posée à côté de `cible`, si c'est bien celle du programme de la clé : ce que
/// `proposer` dit avant la question.
fn fenetre_de_la_cle(source: &Path, cible: &Path) -> Option<PathBuf> {
    lire_octets(source, TAILLE_MAX)
        .ok()
        .and_then(|o| sa_fenetre::de_la_source(source, &o))
        .and(sa_fenetre::pour(cible))
}

/// Montre les deux versions et d'où vient la nouvelle, puis remplace la copie après un « o ». `false` : refusé.
fn proposer(source: &Path, cible: &Path, copie: Option<Version>, cle: Version) -> bool {
    let (ici, sur_la_cle) = match copie {
        Some(c) => cote_a_cote(c, cle),
        None => (version_affichee(None), ecrire(cle)),
    };
    trp!(
        "  Copie de cet ordinateur : {ici}\n  Clé VANGUARD           : {sur_la_cle}\n  {GRIS}Depuis {}{RESET}\n",
        "  Copy on this computer: {ici}\n  VANGUARD key         : {sur_la_cle}\n  {GRIS}From {}{RESET}\n",
        affichable(&source.display().to_string())
    );
    // Sa fenêtre suit, si celle de la clé est la sienne : dite avant la question (`remplacer` la revérifie).
    let fenetre = fenetre_de_la_cle(source, cible);
    if let Some(f) = &fenetre {
        trp!(
            "  Sa fenêtre aussi, vérifiée : {}\n",
            "  Its window too, verified: {}\n",
            affichable(&f.display().to_string())
        );
    }
    let vue = sa_fenetre::Vue::de(fenetre);
    if !demander(tr!(
        "  La remplacer par celle de la clé ? [o/N] : ",
        "  Replace it with the key's? [y/N]: "
    ))
    .oui()
    {
        return true;
    }
    // Comparée à l'image qui tourne, pas à la source elle-même (R1-N2).
    let soi = crate::protection::cle::image_qui_tourne();
    match remplacer(
        source,
        cible,
        cle,
        soi.as_deref(),
        TAILLE_MAX,
        &crate::socle::dossier_local(),
        essayer,
        &vue,
    ) {
        Ok(()) => {
            trp!(
                "  {VERT}✔{RESET} Copie de cet ordinateur mise à jour : Vanguard {}.\n    La surveillance, l'entretien et le raccourci lancent cette version.",
                "  {VERT}✔{RESET} Copy on this computer updated: Vanguard {}.\n    Monitoring, maintenance and the shortcut start this version.",
                ecrire(cle)
            );
            true
        }
        Err(e) => {
            trp!(
                "  ✖ Copie non mise à jour, l'ancienne reste en place :\n    {}",
                "  ✖ Copy not updated, the old one stays in place:\n    {}",
                affichable(&e)
            );
            false
        }
    }
}

/// Pour les essais d'autres modules (le module d'essais reste privé : les comptes du dépôt s'arrêtent à lui).
#[cfg(test)]
pub(crate) use tests::grave;

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// La dernière version publiée et signée que voit `derniere_publiee` dans cet essai (`None` : hors ligne).
        pub(super) static DERNIERE: std::cell::Cell<Option<Version>> = const { std::cell::Cell::new(None) };
        /// Ce que dit l'historique signé à `historique_du_doute` dans cet essai (`None` : hors ligne).
        pub(super) static SIGNEE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    /// Vérification 0.94, R9-CODES-DOC-2 et 3 : le message d'un état local pas écrit nomme le fichier ET le dossier du
    /// registre des sceaux, ne parle jamais de GitHub, et ne dit « restent en doute » que si c'est vrai.
    #[test]
    fn non_ecrit_dit_vrai() {
        let (f, d) = (Path::new("/d/versions/plus-haute-vue.txt"), Path::new("/d"));
        for doute in [true, false] {
            let t = non_ecrit((0, 94, 0, 1), f, d, "disque plein", doute);
            assert!(
                t.contains("0.94.0") && t.contains("/d/versions/plus-haute-vue.txt"),
                "{t}"
            );
            assert!(t.contains("dossier /d ") && t.contains("disque plein"), "{t}");
            assert!(!t.contains("GitHub") && !t.contains("Rien n'a été vérifié"), "{t}");
            assert_eq!(t.contains("restent en doute"), doute, "{t}");
        }
    }

    /// Vérification 0.94, R10-ECRITURE-2 : une révocation pas retenue nomme son fichier et son dossier, sans « GitHub » ;
    /// un manifeste pas reçu, lui, parle de GitHub.
    #[test]
    fn echec_de_revocation_dit_vrai() {
        let (fichier, dossier) = (Path::new("/d/versions/principale-revoquee.txt"), Path::new("/d"));
        let texte = revocation_non_retenue((0, 95, 0, 1), fichier, dossier, "disque plein");
        assert!(
            texte.contains("0.95.0") && texte.contains("/d/versions/principale-revoquee.txt"),
            "{texte}"
        );
        assert!(
            texte.contains("dossier /d ") && texte.contains("disque plein") && texte.contains("clé de secours"),
            "{texte}"
        );
        assert!(
            !texte.contains("GitHub") && !texte.contains("Rien n'a été vérifié"),
            "{texte}"
        );
        let erreur = std::io::Error::other("disque plein");
        let e = github::EchecRepartir::Revocation((0, 95, 0, 1), fichier.to_path_buf(), erreur);
        let (texte, reception) = echec_dit(&e, Repartir::Non);
        assert!(
            !texte.contains("GitHub") && matches!(reception, Reception::NonEcrit),
            "{texte}"
        );
        let e = github::EchecRepartir::NonRecu(crate::modele::Echec::echoue("essai", "hors ligne"));
        let (texte, reception) = echec_dit(&e, Repartir::Non);
        assert!(
            texte.contains("GitHub") && matches!(reception, Reception::SansGithub),
            "{texte}"
        );
    }

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
        use crate::programmes_poses::{Tache, empreinte_notee_dans};
        let racine = crate::essais::temporaire().join(crate::essais::nom_unique("renote"));
        let _ = std::fs::remove_dir_all(&racine);
        std::fs::create_dir_all(&racine).unwrap();
        let (source, cible) = (racine.join("source"), racine.join(NOM));
        // Un registre à lui : le vrai dossier local est écrit en même temps par d'autres essais (lire, changer,
        // réécrire, sans verrou entre eux), qui y perdraient la tâche notée ici.
        let registre = inconnue();
        faux_programme(&cible, None);
        crate::programmes_poses::noter_dans(&registre, Tache::Entretien, &cible, &Ok(b"[Service]".to_vec()));
        let avant = empreinte_notee_dans(&registre, Tache::Entretien).expect("notée");
        faux_programme(&source, Some("0.81.0"));
        poser_copie_dans(
            &source,
            &cible,
            soi_de(&source).as_deref(),
            &registre,
            HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        let apres = empreinte_notee_dans(&registre, Tache::Entretien).expect("notée");
        assert_ne!(avant, apres);
        assert_eq!(apres, crate::programmes_poses::empreinte_de(&cible).unwrap());
        let _ = std::fs::remove_dir_all(&racine);
        let _ = std::fs::remove_dir_all(&registre);
    }

    /// R6-ESSAIS-1 : `installer` ne lève le doute sur la liste que pour la copie de cet ordinateur ; un autre programme
    /// mis à jour depuis GitHub le laisse, et la copie posée n'y est pas crue.
    #[test]
    fn installer_ailleurs_ne_leve_jamais_le_doute() {
        use crate::programmes_poses::{FICHIER, copie_notee_dans, copie_posee_dans};
        let racine = crate::essais::temporaire().join(crate::essais::nom_unique("installer-ailleurs"));
        let registre = inconnue();
        let (source, cible) = (racine.join("source"), racine.join("bin").join(NOM));
        assert_ne!(cible, copie_de_cet_ordinateur());
        faux_programme(&cible, Some("0.80.0+1"));
        copie_posee_dans(&registre, &cible, &std::fs::read(&cible).unwrap());
        std::fs::remove_file(registre.join(FICHIER)).unwrap();
        assert!(
            copie_notee_dans(&registre, &cible).is_err(),
            "liste pas en doute au départ"
        );
        faux_programme(&source, Some("0.81.0"));
        let octets = std::fs::read(&source).unwrap();
        installer(
            &octets,
            &cible,
            version_gravee(&octets).unwrap(),
            &registre,
            &copie_de_cet_ordinateur(),
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), octets, "pas posée");
        assert!(
            copie_notee_dans(&registre, &cible).is_err(),
            "doute levé par une pose ailleurs que la copie de cet ordinateur"
        );
        let _ = std::fs::remove_dir_all(&racine);
        let _ = std::fs::remove_dir_all(&registre);
    }

    /// R7-ESSAIS-1 : une pose par `installer` sur la copie de cet ordinateur (`ici`, injectée) lève le doute sur la
    /// liste ; c'est la seule sortie du doute (numéro et octets signés, vérifiés avant `installer`).
    #[test]
    fn installer_sur_la_copie_d_ici_leve_le_doute() {
        use crate::programmes_poses::{FICHIER, copie_notee_dans, copie_posee_dans};
        let racine = crate::essais::temporaire().join(crate::essais::nom_unique("installer-ici"));
        let registre = inconnue();
        let (source, cible) = (racine.join("source"), racine.join("bin").join(NOM));
        faux_programme(&cible, Some("0.80.0+1"));
        copie_posee_dans(&registre, &cible, &std::fs::read(&cible).unwrap());
        std::fs::remove_file(registre.join(FICHIER)).unwrap();
        assert!(
            copie_notee_dans(&registre, &cible).is_err(),
            "liste pas en doute au départ"
        );
        faux_programme(&source, Some("0.81.0"));
        let octets = std::fs::read(&source).unwrap();
        installer(
            &octets,
            &cible,
            version_gravee(&octets).unwrap(),
            &registre,
            &cible,
            SANS_ESSAI,
        )
        .unwrap();
        assert!(
            matches!(copie_notee_dans(&registre, &cible), Ok(Some(_))),
            "doute pas levé par la pose sur la copie d'ici"
        );
        let _ = std::fs::remove_dir_all(&racine);
        let _ = std::fs::remove_dir_all(&registre);
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
        assert_eq!(verdict(v, &[], v.3 + 45 * jour, false), Verdict::AJour);
        let Verdict::Perimee(dit) = verdict(v, &[], v.3 + 46 * jour, false) else {
            panic!("46 jours : périmée");
        };
        assert!(dit.contains("46"), "{dit}");
        assert!(matches!(verdict((0, 85, 0, 0), &[], v.3, false), Verdict::Perimee(_)));
        // Horloge revenue en 2020 : l'âge est inconnu, jamais « à jour ».
        assert!(matches!(verdict(v, &[], 1_577_836_800, false), Verdict::Perimee(_)));
        // Une heure de décalage juste après la publication : à jour.
        assert_eq!(verdict(v, &[], v.3 - 3_600, false), Verdict::AJour);
    }

    /// Une copie passée à la 0.86 par la clé, et GitHub qui rend le manifeste de la 0.85 : jamais la coche verte.
    #[test]
    fn une_copie_plus_recente_que_github_n_est_pas_a_jour() {
        let v = (0, 85, 0, 1_792_540_000);
        let ici = (0, 86, 0, 1_792_600_000);
        assert_eq!(verdict(v, &[ici, v], v.3, false), Verdict::PlusRecenteIci(ici));
        // Même numéro : à jour, même si la compilation d'ici est plus récente (développement).
        assert_eq!(verdict(v, &[(0, 85, 0, 1_792_700_000)], v.3, false), Verdict::AJour);
        assert_eq!(verdict(v, &[(0, 84, 2, 1)], v.3, false), Verdict::AJour);
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

    /// R3-C1 : une copie plus récente posée par Vanguard est notée avec sa version ; le fichier là n'est plus elle
    /// (effacé, sans version gravée, d'une version plus basse, illisible), et ce programme plus ancien ne s'y pose
    /// pas, ni par la pose d'une tâche (`poser_copie_dans`) ni par la mise à jour depuis la clé (`remplacer`) : refusé,
    /// non vérifié, rien n'est écrit. Une entrée d'avant, sans version, ne bloque rien (sa version est inconnue).
    #[test]
    fn copie_plus_recente_notee_jamais_remplacee_par_plus_ancienne() {
        let racine = crate::socle::dossier_local().join("essai-retour-note");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0+5"));
        let soi = soi_de(&source);
        let registre = inconnue();
        faux_programme(&cible, Some("0.90.0+7"));
        let posee = std::fs::read(&cible).unwrap();
        crate::programmes_poses::copie_posee_dans(&registre, &cible, &posee);
        assert_eq!(
            crate::programmes_poses::copie_notee_dans(&registre, &cible)
                .unwrap()
                .and_then(|c| c.version),
            Some("0.90.0+7".to_string())
        );
        let refuse = |etat: &str| {
            let e = poser_copie_dans(
                &source,
                &cible,
                soi.as_deref(),
                &registre,
                HORS_HISTORIQUE,
                ESSAI_INTERDIT,
            )
            .unwrap_err();
            assert!(e.starts_with("non vérifié") || e.starts_with("not checked"), "{e}");
            assert!(e.contains("0.90.0") && e.contains(etat), "{etat} : {e}");
            assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
        };
        // Effacée : rien n'est reposé.
        std::fs::remove_file(&cible).unwrap();
        refuse(tr!("effacée", "deleted"));
        assert!(
            std::fs::symlink_metadata(&cible).is_err(),
            "reposée par-dessus une copie plus récente effacée"
        );
        // Abîmée, sans version gravée : ni la tâche ni la mise à jour depuis la clé ne la remplacent.
        std::fs::write(&cible, b"abime").unwrap();
        refuse(tr!("sans version gravée", "without an engraved version"));
        let e = remplacer(
            &source,
            &cible,
            (0, 80, 0, 5),
            soi.as_deref(),
            TAILLE_MAX,
            &registre,
            ESSAI_INTERDIT,
            &dite(&source, &cible),
        )
        .unwrap_err();
        assert!(e.starts_with("non vérifié") || e.starts_with("not checked"), "{e}");
        assert_eq!(std::fs::read(&cible).unwrap(), b"abime");
        // D'une version plus basse que la notée (même plus haute que ce programme).
        faux_programme(&cible, Some("0.85.0+1"));
        refuse("0.85.0");
        faux_programme(&cible, Some("0.70.0+1"));
        refuse("0.70.0");
        // Les octets mêmes de ce programme, mis à sa place : pas gardés (le retour en arrière est déjà sur le disque).
        std::fs::copy(&source, &cible).unwrap();
        refuse("0.80.0");
        // Illisible (droits retirés) : jamais remplacée à l'aveugle.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cible, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(&cible).is_err() {
                refuse(tr!("illisible", "unreadable"));
                // Sans copie notée non plus : illisible, refusé.
                let e = poser_copie_dans(
                    &source,
                    &cible,
                    soi.as_deref(),
                    &inconnue(),
                    HORS_HISTORIQUE,
                    ESSAI_INTERDIT,
                )
                .unwrap_err();
                assert!(e.starts_with("non vérifié") || e.starts_with("not checked"), "{e}");
            }
            std::fs::set_permissions(&cible, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        // La copie notée, remise telle quelle : gardée.
        std::fs::write(&cible, &posee).unwrap();
        poser_copie_dans(
            &source,
            &cible,
            soi.as_deref(),
            &registre,
            HORS_HISTORIQUE,
            ESSAI_INTERDIT,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), posee);
        // Une clé au moins aussi récente que la copie notée la remplace (ce n'est pas un retour en arrière).
        std::fs::write(&cible, b"abime").unwrap();
        let recente = racine.join("cle-recente").join(NOM);
        faux_programme(&recente, Some("0.90.0+9"));
        poser_copie_dans(
            &recente,
            &cible,
            soi_de(&recente).as_deref(),
            &registre,
            HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&recente).unwrap());
        let _ = std::fs::remove_dir_all(&registre);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// R4-REGISTRE-1 : la liste des copies effacée, vidée (« {} ») ou abîmée alors qu'un sceau l'attendait, et la
    /// copie plus récente notée effacée : ni la pose d'une tâche (`poser_copie_dans`) ni la mise à jour depuis la clé
    /// (`remplacer`) ne comptent « rien de noté ». Refusé, non vérifié, rien n'est posé ; hors ligne comme devant une
    /// version signée plus récente que ce programme. La sortie : ce programme est la dernière version signée ; il est
    /// posé, et la liste des copies refaite.
    #[test]
    fn registre_en_doute_jamais_compte_comme_rien_de_note() {
        let racine = crate::socle::dossier_local().join("essai-registre-doute");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0+5"));
        let soi = soi_de(&source);
        let registre = inconnue();
        let liste = registre.join(crate::programmes_poses::FICHIER);
        let effacer = |p: &Path| std::fs::remove_file(p).unwrap();
        let vider = |p: &Path| std::fs::write(p, b"{}").unwrap();
        let abimer = |p: &Path| std::fs::write(p, b"{pas du json").unwrap();
        let falsifications: [&dyn Fn(&Path); 3] = [&effacer, &vider, &abimer];
        for falsifier in falsifications {
            let _ = std::fs::remove_dir_all(&registre);
            faux_programme(&cible, Some("0.90.0+7"));
            crate::programmes_poses::copie_posee_dans(&registre, &cible, &std::fs::read(&cible).unwrap());
            std::fs::remove_file(&cible).unwrap();
            falsifier(&liste);
            for (derniere, dit) in [(None, "hors ligne (essai)"), (Some((0, 81, 0, 9)), "0.81.0")] {
                DERNIERE.with(|d| d.set(derniere));
                let e = poser_copie_dans(
                    &source,
                    &cible,
                    soi.as_deref(),
                    &registre,
                    HORS_HISTORIQUE,
                    ESSAI_INTERDIT,
                )
                .unwrap_err();
                assert!(e.starts_with("non vérifié") || e.starts_with("not checked"), "{e}");
                assert!(
                    e.contains(tr!("la liste des copies", "the list of copies"))
                        && e.contains("0.80.0")
                        && e.contains(dit),
                    "{e}"
                );
                let e = remplacer(
                    &source,
                    &cible,
                    (0, 80, 0, 5),
                    soi.as_deref(),
                    TAILLE_MAX,
                    &registre,
                    ESSAI_INTERDIT,
                    &dite(&source, &cible),
                )
                .unwrap_err();
                assert!(e.contains(tr!("la liste des copies", "the list of copies")), "{e}");
                assert!(
                    std::fs::symlink_metadata(&cible).is_err(),
                    "posée par-dessus un registre en doute"
                );
                assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
            }
        }
        // La sortie : ce programme est la dernière version signée. La copie (ses octets mêmes) est gardée, et la
        // liste refaite la note. R5 : le numéro seul ne suffit plus, les octets doivent être dans l'historique signé.
        DERNIERE.with(|d| d.set(Some((0, 80, 0, 5))));
        std::fs::copy(&source, &cible).unwrap();
        for (historique, dit) in [
            (HORS_HISTORIQUE, "hors ligne (essai)"),
            (
                NON_SIGNEE,
                tr!("pas dans l'historique signé", "not in the signed version history"),
            ),
        ] {
            let e =
                poser_copie_dans(&source, &cible, soi.as_deref(), &registre, historique, ESSAI_INTERDIT).unwrap_err();
            assert!(
                e.contains(tr!("la liste des copies", "the list of copies")) && e.contains(dit),
                "{e}"
            );
            assert!(crate::programmes_poses::copie_notee_dans(&registre, &cible).is_err());
        }
        for signee in [None, Some(false)] {
            SIGNEE.with(|s| s.set(signee));
            let e = remplacer(
                &source,
                &cible,
                (0, 80, 0, 5),
                soi.as_deref(),
                TAILLE_MAX,
                &registre,
                ESSAI_INTERDIT,
                &dite(&source, &cible),
            )
            .unwrap_err();
            assert!(e.contains(tr!("la liste des copies", "the list of copies")), "{e}");
        }
        SIGNEE.with(|s| s.set(None));
        poser_copie_dans(&source, &cible, soi.as_deref(), &registre, SIGNEE_ICI, ESSAI_INTERDIT).unwrap();
        DERNIERE.with(|d| d.set(None));
        assert_eq!(
            crate::programmes_poses::copie_notee_dans(&registre, &cible)
                .unwrap()
                .and_then(|c| c.version),
            Some("0.80.0+5".to_string())
        );
        let _ = std::fs::remove_dir_all(&registre);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// R4-REGISTRE-1, depuis GitHub (`juger_cibles`) : la liste des copies en doute est dite ; seule la dernière
    /// version signée remplace la copie (elle ne revient sur rien de publié), et la liste est refaite après.
    #[test]
    fn mise_a_jour_github_dit_le_registre_en_doute() {
        let racine = crate::socle::dossier_local().join("essai-juger-doute");
        let _ = std::fs::remove_dir_all(&racine);
        let copie = racine.join("bin").join(NOM);
        let registre = inconnue();
        faux_programme(&copie, Some("0.90.0+7"));
        crate::programmes_poses::copie_posee_dans(&registre, &copie, &std::fs::read(&copie).unwrap());
        std::fs::write(&copie, b"abime").unwrap();
        std::fs::remove_file(registre.join(crate::programmes_poses::FICHIER)).unwrap();
        let (_, a_remplacer, doutes) = juger_cibles(vec![copie.clone()], (0, 95, 0, 0), &copie, &registre, |_| Ok(()));
        assert_eq!(a_remplacer, vec![copie.clone()]);
        assert!(
            doutes.len() == 1
                && doutes[0].contains("0.95.0")
                && (doutes[0].contains("Non vérifié") || doutes[0].contains("Not checked")),
            "{doutes:?}"
        );
        let _ = std::fs::remove_dir_all(&registre);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// R5-ORIGINE-DOC-2 : sortir du doute exige les deux preuves, le numéro (pas plus ancien que la dernière version
    /// signée) ET les octets (dans l'historique signé pour ce système) ; toute réponse manquante refuse.
    #[test]
    fn sortie_du_doute_exige_numero_et_octets_signes() {
        let v = (0, 90, 0, 7);
        let echec = || crate::modele::Echec::refuse("essai", "muet");
        assert_eq!(sortie_du_doute(v, Ok((0, 90, 0, 0)), || Ok(true)), Ok(()));
        assert_eq!(sortie_du_doute((0, 95, 0, 0), Ok((0, 90, 0, 0)), || Ok(true)), Ok(()));
        let e = sortie_du_doute(v, Ok((0, 95, 0, 0)), || Ok(true))
            .unwrap_err()
            .to_string();
        assert!(e.contains("0.95.0"), "{e}");
        assert!(sortie_du_doute(v, Err(echec()), || Ok(true)).is_err());
        assert!(sortie_du_doute(v, Ok((0, 90, 0, 0)), || Ok(false)).is_err());
        assert!(sortie_du_doute(v, Ok((0, 90, 0, 0)), || Err(echec())).is_err());
    }

    /// R5-REGISTRE-3 : côté GitHub, une liste en doute est toujours dite : copie au numéro de la dernière version
    /// signée (rien n'est remplacé, la liste reste en doute) ou copie absente des cibles.
    #[test]
    fn mise_a_jour_github_dit_le_doute_meme_sans_rien_a_remplacer() {
        let racine = crate::socle::dossier_local().join("essai-juger-doute-meme");
        let _ = std::fs::remove_dir_all(&racine);
        let copie = racine.join("bin").join(NOM);
        let registre = inconnue();
        faux_programme(&copie, Some("0.95.0+7"));
        crate::programmes_poses::copie_posee_dans(&registre, &copie, &std::fs::read(&copie).unwrap());
        std::fs::remove_file(registre.join(crate::programmes_poses::FICHIER)).unwrap();
        let publiee = (0, 95, 0, 0);
        let (_, a_remplacer, doutes) = juger_cibles(vec![copie.clone()], publiee, &copie, &registre, |_| Ok(()));
        assert!(a_remplacer.is_empty(), "{a_remplacer:?}");
        assert!(doutes.len() == 1 && doutes[0].contains("0.95.0"), "{doutes:?}");
        let autre = racine.join("ailleurs").join(NOM);
        faux_programme(&autre, Some("0.80.0+1"));
        let (_, _, doutes) = juger_cibles(vec![autre], publiee, &copie, &registre, |_| Ok(()));
        assert!(
            doutes
                .iter()
                .any(|d| d == &doute_sans_copie(crate::voulues::Doute::HorsVanguard)),
            "{doutes:?}"
        );
        let _ = std::fs::remove_dir_all(&registre);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// R4-REGISTRE-3 : un programme dit non vérifié pendant la mise à jour depuis GitHub, et rien à remplacer : jamais
    /// la coche verte après.
    #[test]
    fn pas_de_coche_verte_apres_un_doute() {
        let v = (0, 85, 0, 1_792_540_000);
        assert_eq!(verdict(v, &[], v.3, true), Verdict::Doutes);
        assert_eq!(verdict(v, &[], v.3, false), Verdict::AJour);
    }

    /// R4-ESSAIS-1 : seuls la même version et le même système que l'historique signé valent « publiée et signée pour
    /// ce système ».
    #[test]
    fn signee_ici_exige_version_et_systeme() {
        let v = (0, 85, 0, 1_792_540_000);
        let vue = |n: &str, s: &str| Some((n.to_string(), s.to_string()));
        assert!(signee_ici(vue(&ecrire(v), "linux-x86_64"), "linux-x86_64", v));
        assert!(!signee_ici(vue(&ecrire(v), "windows-x86_64"), "linux-x86_64", v));
        assert!(!signee_ici(vue("0.84.0", "linux-x86_64"), "linux-x86_64", v));
        assert!(!signee_ici(None, "linux-x86_64", v));
    }

    /// N3-O3 : une copie plus récente absente de la liste (posée par une version d'avant la liste) est gardée si
    /// l'historique signé la dit publiée pour ce système ; absente de l'historique, ou sans réponse : refusée, non
    /// vérifiée, jamais cédée en silence ni remplacée.
    #[test]
    fn copie_plus_recente_hors_liste_jugee_par_l_historique_signe() {
        let racine = crate::socle::dossier_local().join("essai-hors-liste");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0+5"));
        let soi = soi_de(&source);
        faux_programme(&cible, Some("0.90.0+7"));
        let la = std::fs::read(&cible).unwrap();
        let vide = inconnue();
        let signee: Historique = |_| Ok(true);
        let pas_signee: Historique = |_| Ok(false);
        let e = poser_copie_dans(&source, &cible, soi.as_deref(), &vide, pas_signee, ESSAI_INTERDIT).unwrap_err();
        assert!(e.starts_with("non vérifié") || e.starts_with("not checked"), "{e}");
        assert!(!crate::programmes_poses::copie_connue_dans(
            &vide,
            &cible,
            blake3::hash(&la).to_hex().as_str()
        ));
        let e = poser_copie_dans(&source, &cible, soi.as_deref(), &vide, HORS_HISTORIQUE, ESSAI_INTERDIT).unwrap_err();
        assert!(e.contains("hors ligne (essai)"), "{e}");
        assert_eq!(std::fs::read(&cible).unwrap(), la);
        poser_copie_dans(&source, &cible, soi.as_deref(), &vide, signee, ESSAI_INTERDIT).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), la);
        assert!(
            crate::programmes_poses::copie_connue_dans(&vide, &cible, blake3::hash(&la).to_hex().as_str()),
            "copie signée gardée non notée"
        );
        let _ = std::fs::remove_dir_all(&vide);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// R3-C3 et R3-C1, mise à jour depuis GitHub (`juger_cibles`, sans réseau) : une copie qui se dit plus récente que
    /// la version publiée sans être reconnue n'est ni un plancher (pas de faux soupçon sur GitHub) ni remplacée, et
    /// c'est dit non vérifié ; reconnue, elle sert de plancher. Une copie notée plus récente que la version publiée,
    /// abîmée depuis, n'est pas remplacée par cette version plus ancienne ; sans note, une copie abîmée l'est.
    #[test]
    fn mise_a_jour_github_juge_chaque_copie() {
        let racine = crate::socle::dossier_local().join("essai-juger-cibles");
        let _ = std::fs::remove_dir_all(&racine);
        let copie = racine.join("bin").join(NOM);
        let publiee = (0, 85, 0, 0);
        let pas_reconnue = |_: &Path| Err(crate::modele::Echec::refuse("essai", "absente de la liste"));
        let vide = inconnue();
        faux_programme(&copie, Some("99.0.0+1"));
        let (ici, remplacer, doutes) = juger_cibles(vec![copie.clone()], publiee, &copie, &vide, pas_reconnue);
        assert!(!ici.contains(&(99, 0, 0, 1)), "copie inconnue prise pour plancher");
        assert_eq!(remplacer, Vec::<PathBuf>::new());
        assert!(
            doutes.len() == 1 && (doutes[0].contains("Non vérifié") || doutes[0].contains("Not checked")),
            "{doutes:?}"
        );
        let (ici, _, doutes) = juger_cibles(vec![copie.clone()], publiee, &copie, &vide, |_| Ok(()));
        assert!(ici.contains(&(99, 0, 0, 1)) && doutes.is_empty());
        // Notée en 0.90.0, puis abîmée : la version publiée 0.85.0 ne la remplace pas.
        let registre = inconnue();
        faux_programme(&copie, Some("0.90.0+7"));
        crate::programmes_poses::copie_posee_dans(&registre, &copie, &std::fs::read(&copie).unwrap());
        std::fs::write(&copie, b"abime").unwrap();
        let (_, remplacer, doutes) = juger_cibles(vec![copie.clone()], publiee, &copie, &registre, pas_reconnue);
        assert!(
            remplacer.is_empty(),
            "retour en arrière par la mise à jour depuis GitHub"
        );
        assert!(doutes.len() == 1 && doutes[0].contains("0.90.0"), "{doutes:?}");
        // Sans note : remplacée.
        let (_, remplacer, doutes) = juger_cibles(vec![copie.clone()], publiee, &copie, &vide, pas_reconnue);
        assert_eq!(remplacer, vec![copie.clone()]);
        assert!(doutes.is_empty(), "{doutes:?}");
        let _ = std::fs::remove_dir_all(&registre);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Les octets d'un faux programme à la version `v`, pour les essais d'autres modules.
    pub(crate) fn grave(v: &str) -> Vec<u8> {
        avec_entete("prog ", &format!("{v}; fin"))
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
        remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &dite(&source, &cible),
        )
        .unwrap();
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
        assert!(
            remplacer(
                &source,
                &cible,
                (0, 80, 0, 0),
                soi_de(&source).as_deref(),
                TAILLE_MAX,
                &inconnue(),
                SANS_ESSAI,
                &dite(&source, &cible)
            )
            .is_err()
        );
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 70, 0, 0)));
        // Une source absente ou démesurée : l'ancienne copie reste, rien ne traîne à côté.
        assert!(
            remplacer(
                &racine.join("absente"),
                &cible,
                (0, 80, 0, 0),
                Some("0"),
                TAILLE_MAX,
                &inconnue(),
                SANS_ESSAI,
                &dite(&racine.join("absente"), &cible)
            )
            .is_err()
        );
        faux_programme(&source, Some("0.80.0"));
        assert!(
            remplacer(
                &source,
                &cible,
                (0, 80, 0, 0),
                soi_de(&source).as_deref(),
                4,
                &inconnue(),
                SANS_ESSAI,
                &dite(&source, &cible)
            )
            .is_err()
        );
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 70, 0, 0)));
        assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// La copie remplacée depuis la clé au terminal (`proposer`) emporte la fenêtre de la clé si c'est celle que
    /// grave son programme ; une autre reste sur la clé, la copie se fait sans elle.
    #[test]
    fn remplacer_emporte_la_fenetre_de_la_cle() {
        use crate::demarrage::empreinte_fenetre::marque_d_essai;
        use sha2::{Digest, Sha256};
        let racine = crate::socle::dossier_local().join("essai-remplacement-fenetre");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        let (fenetre_cle, fenetre_ici) = (sa_fenetre::pour(&source).unwrap(), sa_fenetre::pour(&cible).unwrap());
        let neuve = b"fenetre 0.80".to_vec();
        let mut neuf = avec_entete("prog ", "0.80.0; ");
        neuf.extend(marque_d_essai(&Sha256::digest(&neuve).into()));
        faux_programme(&cible, None);
        faux_programme(&source, None);
        std::fs::write(&source, &neuf).unwrap();
        std::fs::write(&fenetre_ici, b"ancienne fenetre").unwrap();
        // Une autre fenêtre à la clé : le programme seul.
        std::fs::write(&fenetre_cle, b"fenetre plantee").unwrap();
        remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &dite(&source, &cible),
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), neuf);
        assert_eq!(std::fs::read(&fenetre_ici).unwrap(), b"ancienne fenetre");
        // La sienne : posée avec le programme.
        faux_programme(&cible, None);
        std::fs::write(&fenetre_cle, &neuve).unwrap();
        remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &dite(&source, &cible),
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), neuf);
        assert_eq!(std::fs::read(&fenetre_ici).unwrap(), neuve);
        // C-7 : dite sans fenêtre (celle de la clé n'était pas la sienne), devenue la sienne avant la pose : rien.
        faux_programme(&cible, None);
        let ancien = std::fs::read(&cible).unwrap();
        std::fs::write(&fenetre_ici, b"ancienne fenetre").unwrap();
        std::fs::write(&fenetre_cle, b"fenetre plantee").unwrap();
        let vue = dite(&source, &cible);
        std::fs::write(&fenetre_cle, &neuve).unwrap();
        let e = remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &vue,
        )
        .expect_err("pas dite");
        assert!(
            e.contains("depuis ce qui a été montré") || e.contains("since what was shown"),
            "{e}"
        );
        assert_eq!(std::fs::read(&cible).unwrap(), ancien);
        assert_eq!(std::fs::read(&fenetre_ici).unwrap(), b"ancienne fenetre");
        // Dite avec sa fenêtre, qui n'est plus la sienne avant la pose : pas le programme seul non plus.
        let vue = dite(&source, &cible);
        std::fs::write(&fenetre_cle, b"fenetre plantee").unwrap();
        let e = remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &vue,
        )
        .expect_err("pas dit");
        assert!(
            e.contains("depuis ce qui a été montré") || e.contains("since what was shown"),
            "{e}"
        );
        assert_eq!(std::fs::read(&cible).unwrap(), ancien);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// La fenêtre telle que `proposer` la dirait maintenant.
    fn dite(source: &Path, cible: &Path) -> sa_fenetre::Vue {
        sa_fenetre::Vue::de(fenetre_de_la_cle(source, cible))
    }

    /// L'empreinte d'un faux programme, comme s'il était celui qui tourne.
    fn soi_de(p: &Path) -> Option<String> {
        crate::programmes_poses::empreinte_de(p).ok()
    }

    /// MOYENNE (campagne d'attaque, COPIE-1, DONNEES-2, SORTIES-1) : la clé n'est vérifiée qu'au lancement. Son
    /// programme changé depuis (fichier réécrit, ou une autre clé branchée au même endroit, à la même version gravée)
    /// ne se pose jamais dans bin/ : ni par la surveillance, l'entretien, le raccourci ou le veilleur
    /// (`poser_copie_dans`), ni par la mise à jour depuis la clé (`remplacer`) ; rien n'est lancé ni scellé, la copie
    /// d'avant reste. Sans empreinte du programme qui tourne, rien non plus.
    #[test]
    fn programme_de_la_cle_change_depuis_le_lancement_jamais_pose() {
        let racine = crate::socle::dossier_local().join("essai-cle-changee");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0+5"));
        let soi = soi_de(&source);
        // Une autre clé, ou le fichier réécrit : même version gravée, d'autres octets.
        std::fs::write(&source, [&std::fs::read(&source).unwrap()[..], b"hostile"].concat()).unwrap();
        assert_eq!(lire_programme(&source, TAILLE_MAX), Lu::Version((0, 80, 0, 5)));
        let essai_interdit: Essai = |_, _| panic!("un programme qui n'est pas celui qui tourne a été lancé");
        let e = poser_copie_dans(
            &source,
            &cible,
            soi.as_deref(),
            &inconnue(),
            HORS_HISTORIQUE,
            essai_interdit,
        )
        .unwrap_err();
        assert!(e.contains("rien n'est posé") || e.contains("nothing is set up"), "{e}");
        assert!(!cible.exists(), "posé depuis une clé changée");
        faux_programme(&cible, Some("0.79.0+1"));
        let avant = std::fs::read(&cible).unwrap();
        assert!(
            remplacer(
                &source,
                &cible,
                (0, 80, 0, 5),
                soi.as_deref(),
                TAILLE_MAX,
                &inconnue(),
                essai_interdit,
                &dite(&source, &cible)
            )
            .is_err()
        );
        assert!(poser_copie_dans(&source, &cible, None, &inconnue(), HORS_HISTORIQUE, essai_interdit).is_err());
        assert_eq!(std::fs::read(&cible).unwrap(), avant, "copie d'avant changée");
        assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// BASSE (relecture adverse, R1-N1) : un fichier mis dans bin/ par un autre programme du compte, à une version
    /// gravée plus haute, était gardé sans comparaison, puis lancé par les tâches et scellé comme Vanguard. Il n'est
    /// plus gardé que si Vanguard l'y a posé lui-même (noté dans son registre) ; sinon il n'est ni gardé ni remplacé
    /// (R1-M2 : pas de retour en arrière), refusé et dit non vérifié. Une copie gardée est notée comme posée par
    /// Vanguard.
    #[test]
    fn copie_plus_recente_gardee_seulement_si_posee_par_vanguard() {
        let racine = crate::socle::dossier_local().join("essai-copie-etrangere");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0+5"));
        let soi = soi_de(&source);
        // Posée par un autre programme : plus récente, jamais vue par Vanguard. Ni gardée (refus, rien de noté), ni
        // remplacée par ce programme plus ancien (R1-M2) : non vérifié, dit.
        faux_programme(&cible, Some("9.0.0+1"));
        let etranger = std::fs::read(&cible).unwrap();
        let vide = inconnue();
        let e = poser_copie_dans(&source, &cible, soi.as_deref(), &vide, HORS_HISTORIQUE, SANS_ESSAI).unwrap_err();
        assert_eq!(
            e,
            plus_recente_inconnue((9, 0, 0, 1), (0, 80, 0, 5), &historique_muet("hors ligne (essai)"))
        );
        assert!(e.starts_with("non vérifié") || e.starts_with("not checked"), "{e}");
        assert_eq!(std::fs::read(&cible).unwrap(), etranger, "fichier étranger remplacé");
        assert!(
            !crate::programmes_poses::copie_connue_dans(&vide, &cible, blake3::hash(&etranger).to_hex().as_str()),
            "fichier étranger noté comme posé"
        );
        // Registre illisible : jamais « inconnue donc remplacée » ; le registre en doute est dit d'abord (R4-REGISTRE-1).
        std::fs::create_dir_all(&vide).unwrap();
        std::fs::write(vide.join("programmes-planifies.json"), b"{pas du json").unwrap();
        let e = poser_copie_dans(&source, &cible, soi.as_deref(), &vide, HORS_HISTORIQUE, SANS_ESSAI).unwrap_err();
        assert!(
            e.starts_with(tr!(
                "non vérifié : la liste des copies",
                "not checked: the list of copies"
            )),
            "{e}"
        );
        assert_eq!(
            std::fs::read(&cible).unwrap(),
            etranger,
            "remplacée, registre illisible"
        );
        let _ = std::fs::remove_dir_all(&vide);
        // Posée par Vanguard (une mise à jour signée, une clé plus récente), notée dans son registre : gardée.
        faux_programme(&cible, Some("9.0.0+1"));
        let la = std::fs::read(&cible).unwrap();
        let registre = inconnue();
        crate::programmes_poses::copie_posee_dans(&registre, &cible, &la);
        poser_copie_dans(&source, &cible, soi.as_deref(), &registre, HORS_HISTORIQUE, SANS_ESSAI).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), la);
        // Les octets du programme qui tourne déjà là : gardés, et notés comme posés par Vanguard.
        let neuf = inconnue();
        std::fs::copy(&source, &cible).unwrap();
        poser_copie_dans(&source, &cible, soi.as_deref(), &neuf, HORS_HISTORIQUE, SANS_ESSAI).unwrap();
        let empreinte = blake3::hash(&std::fs::read(&source).unwrap()).to_hex().to_string();
        assert!(
            crate::programmes_poses::copie_connue_dans(&neuf, &cible, &empreinte),
            "copie gardée non notée"
        );
        let _ = std::fs::remove_dir_all(&registre);
        let _ = std::fs::remove_dir_all(&neuf);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// BASSE (relecture adverse, R1-N2) : la pose réelle (`poser_copie`, celle de la surveillance) et la mise à jour
    /// depuis la clé (`remplacer` avec l'image qui tourne, comme dans `proposer`) comparent la source à l'image qui
    /// tourne, pas à elle-même : un fichier qui n'est pas le programme lancé (ici celui des essais) est refusé, avant tout essai.
    #[test]
    fn la_pose_reelle_compare_a_l_image_qui_tourne() {
        let racine = crate::socle::dossier_local().join("essai-image-qui-tourne");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        faux_programme(&source, Some("0.80.0+5"));
        let image = crate::protection::cle::image_qui_tourne();
        assert!(image.is_some(), "image des essais illisible");
        let refus = pas_de_soi(image.as_deref());
        assert_eq!(poser_copie(&source).err().as_deref(), Some(refus.as_str()));
        let cible = racine.join("bin").join(NOM);
        faux_programme(&cible, Some("0.79.0+1"));
        let avant = std::fs::read(&cible).unwrap();
        assert_eq!(
            remplacer(
                &source,
                &cible,
                (0, 80, 0, 5),
                image.as_deref(),
                TAILLE_MAX,
                &inconnue(),
                essayer,
                &dite(&source, &cible)
            )
            .err()
            .as_deref(),
            Some(refus.as_str())
        );
        assert_eq!(std::fs::read(&cible).unwrap(), avant);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// BASSE (relecture adverse, R1-N3) : le programme qui tourne illisible n'est pas dit « clé changée » : deux causes,
    /// deux textes, dans les deux langues ; `remplacer` sans empreinte refuse aussi.
    #[test]
    fn refus_sans_empreinte_distinct_de_la_cle_changee() {
        let (illisible, changee) = (pas_de_soi(None), pas_de_soi(Some("abc")));
        assert_ne!(illisible, changee);
        assert!(
            illisible.contains("ne se lit pas") || illisible.contains("cannot be read"),
            "{illisible}"
        );
        assert!(
            changee.contains("a changé") || changee.contains("has changed"),
            "{changee}"
        );
        let racine = crate::socle::dossier_local().join("essai-sans-empreinte");
        let _ = std::fs::remove_dir_all(&racine);
        let (source, cible) = (racine.join("cle").join(NOM), racine.join("bin").join(NOM));
        faux_programme(&source, Some("0.80.0+5"));
        let essai_interdit: Essai = |_, _| panic!("lancé sans empreinte du programme qui tourne");
        assert_eq!(
            remplacer(
                &source,
                &cible,
                (0, 80, 0, 5),
                None,
                TAILLE_MAX,
                &inconnue(),
                essai_interdit,
                &dite(&source, &cible)
            ),
            Err(illisible)
        );
        assert!(!cible.exists());
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Un registre neuf, à lui seul (le dossier local des essais est partagé par les essais qui tournent en même
    /// temps) : aucune copie n'y est notée comme posée par Vanguard.
    pub(super) fn inconnue() -> PathBuf {
        crate::essais::temporaire().join(crate::essais::nom_unique("registre"))
    }

    /// Les faux programmes des tests ne se lancent pas : l'essai réel a son propre test.
    const SANS_ESSAI: Essai = |_, _| Ok(());

    /// Un essai qui ne doit jamais être lancé : rien ne doit se poser.
    const ESSAI_INTERDIT: Essai = |_, _| panic!("un programme a été lancé alors que rien ne devait se poser");

    /// L'historique signé des tests : jamais consulté pour de vrai, il ne répond pas (comme hors ligne).
    pub(super) const HORS_HISTORIQUE: Historique = |_| Err(crate::modele::Echec::echoue("essai", "hors ligne (essai)"));
    const NON_SIGNEE: Historique = |_| Ok(false);
    const SIGNEE_ICI: Historique = |_| Ok(true);

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
        poser_copie_dans(
            &source,
            &cible,
            soi_de(&source).as_deref(),
            &inconnue(),
            HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 80, 0, 5)));
        // Une copie plus récente que la clé, posée par Vanguard : gardée telle quelle (une vieille clé ne fait pas
        // revenir en arrière).
        faux_programme(&cible, Some("0.81.0+1"));
        let connue = inconnue();
        crate::programmes_poses::copie_posee_dans(&connue, &cible, &std::fs::read(&cible).unwrap());
        poser_copie_dans(
            &source,
            &cible,
            soi_de(&source).as_deref(),
            &connue,
            HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 81, 0, 1)));
        // Une copie plus ancienne : remplacée, sauf si la nouvelle ne démarre pas.
        faux_programme(&cible, Some("0.79.0+1"));
        assert!(
            poser_copie_dans(
                &source,
                &cible,
                soi_de(&source).as_deref(),
                &inconnue(),
                HORS_HISTORIQUE,
                essai_rate
            )
            .is_err()
        );
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 79, 0, 1)));
        assert!(!cible.with_file_name(format!("{NOM}.nouveau")).exists());
        poser_copie_dans(
            &source,
            &cible,
            soi_de(&source).as_deref(),
            &inconnue(),
            HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        // Une source sans version gravée : rien n'est posé.
        faux_programme(&source, None);
        assert!(
            poser_copie_dans(
                &source,
                &cible,
                soi_de(&source).as_deref(),
                &inconnue(),
                HORS_HISTORIQUE,
                SANS_ESSAI
            )
            .is_err()
        );
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
        let r = remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            REECRITE_EN_PLACE,
            &dite(&source, &cible),
        );
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
        let r = remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            ECHANGE_PAR_LE_NOM,
            &dite(&source, &cible),
        );
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
        let r = remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            ECHANGE_PAR_LE_NOM,
            &dite(&source, &cible),
        );
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
            let e = remplacer(
                &source,
                &cible,
                (0, 80, 0, 0),
                soi_de(&source).as_deref(),
                TAILLE_MAX,
                &inconnue(),
                essai,
                &dite(&source, &cible),
            )
            .unwrap_err();
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
        let e = remplacer(
            &source,
            &autre,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &dite(&source, &autre),
        )
        .unwrap_err();
        assert!(e.contains("rien n'est remplacé"), "{e}");
        assert!(autre.join("dedans").is_dir(), "{e}");

        std::fs::remove_dir_all(&de_cote).unwrap();
        remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &dite(&source, &cible),
        )
        .unwrap();
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
        // La mise à jour suivante réutilise ce nom : le message dit de mettre la copie gardée à l'abri avant.
        assert!(dit.contains("avant de refaire la mise à jour"), "{dit}");
        assert!(
            !dit.contains("remise en place") && !dit.contains("reste en place"),
            "{dit}"
        );
        assert!(cible.join("occupe").is_dir(), "{dit}");
        let dit = crate::langue::en_anglais(|| {
            std::fs::remove_file(&de_cote).unwrap();
            faux_programme(&de_cote, Some("0.79.0"));
            let precedente = Precedente {
                de_cote: de_cote.clone(),
                etat: EtatPrecedente::Retenue(
                    Tenue::de(&de_cote, &std::fs::symlink_metadata(&de_cote).unwrap()).unwrap(),
                ),
            };
            precedente.remettre(&cible)
        });
        assert!(dit.contains("before redoing the update"), "{dit}");
        assert!(!dit.contains(" : "), "{dit}");
        assert!(de_cote.is_file(), "{dit}");
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// V-1 (relecture du recontrôle 2, 0.95) : après une remise ratée, l'ancienne copie est gardée sous
    /// `<NOM>.precedent`. Avant, la tentative suivante (la pose de la surveillance, ou « refaites la mise à jour »)
    /// effaçait ce nom avant de mettre de côté la copie en place, puis refusait en disant « rien n'est remplacé » : la
    /// seule ancienne copie était perdue. Maintenant, ce nom n'est effacé que s'il est un second nom de la copie en
    /// place ; sinon, refus, avec le chemin à mettre à l'abri. Un second nom (reste d'une mise à jour interrompue
    /// avant le renommage) s'efface, et la mise à jour se fait.
    #[test]
    fn copie_gardee_jamais_effacee_par_la_tentative_suivante() {
        let racine = crate::socle::dossier_local().join("essai-copie-gardee");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        let de_cote = cible.with_file_name(format!("{NOM}.precedent"));
        let gardee = || std::fs::read(&de_cote).ok();
        faux_programme(&source, Some("0.80.0"));
        faux_programme(&cible, Some("0.79.0"));
        let ancienne = Some(std::fs::read(&cible).unwrap());
        let precedente = Precedente::retenir(&cible).expect("mise de côté");
        std::fs::remove_file(&cible).unwrap();
        std::fs::create_dir_all(cible.join("occupe")).unwrap();
        let dit = precedente.remettre(&cible);
        assert_eq!(gardee(), ancienne, "{dit}");
        // La pose de la surveillance, puis « refaites la mise à jour » : refusées, la copie gardée reste.
        let pose = poser_copie_dans(
            &source,
            &cible,
            soi_de(&source).as_deref(),
            &inconnue(),
            HORS_HISTORIQUE,
            SANS_ESSAI,
        )
        .unwrap_err();
        assert_eq!(gardee(), ancienne, "copie gardée effacée par la pose : {pose}");
        let maj = remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &dite(&source, &cible),
        )
        .unwrap_err();
        assert_eq!(gardee(), ancienne, "copie gardée effacée par la mise à jour : {maj}");
        // La pose refuse plus tôt : une copie qui ne se lit pas (ici un dossier) n'est jamais remplacée sans avoir été
        // lue (`copie_illisible`). La mise à jour, elle, refuse à la mise de côté.
        assert!(pose.contains("rien n'est posé"), "{pose}");
        assert!(maj.contains("rien n'est remplacé"), "{maj}");
        assert!(cible.join("occupe").is_dir());
        // Ce qui bloquait retiré, une autre copie à la place : le nom de côté n'en est pas un second nom ; il reste, et
        // son chemin est dit, à mettre à l'abri (pas seulement « à retirer »).
        std::fs::remove_dir_all(&cible).unwrap();
        faux_programme(&cible, Some("0.79.5"));
        let e = remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &dite(&source, &cible),
        )
        .unwrap_err();
        assert_eq!(gardee(), ancienne, "{e}");
        assert!(e.contains(&format!("{NOM}.precedent")), "{e}");
        assert!(e.contains("à l'abri") && e.contains("rien n'est remplacé"), "{e}");
        assert_eq!(lire_programme(&cible, TAILLE_MAX), Lu::Version((0, 79, 5, 0)), "{e}");
        let en = crate::langue::en_anglais(|| {
            remplacer(
                &source,
                &cible,
                (0, 80, 0, 0),
                soi_de(&source).as_deref(),
                TAILLE_MAX,
                &inconnue(),
                SANS_ESSAI,
                &dite(&source, &cible),
            )
        })
        .unwrap_err();
        assert!(en.contains("somewhere safe") && !en.contains(" : "), "{en}");
        assert_eq!(gardee(), ancienne, "{en}");
        // Un second nom de la copie en place (mise à jour interrompue avant le renommage) : effacé, la mise à jour se
        // fait.
        std::fs::remove_file(&de_cote).unwrap();
        std::fs::hard_link(&cible, &de_cote).unwrap();
        remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &dite(&source, &cible),
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(std::fs::symlink_metadata(&de_cote).is_err(), "reste laissé");
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// V-3 (relecture du recontrôle 2, 0.95) : l'ancienne copie était reconnue par son appareil et son inode seuls,
    /// sans rien tenir d'ouvert. Son second nom effacé, puis elle-même remplacée, ext4 redonne aussitôt son numéro au
    /// fichier suivant : un fichier étranger (ou un dossier) posé à la cible était pris pour elle, « l'ancienne copie
    /// reste en place ». Maintenant elle est tenue ouverte jusqu'à la fin : son numéro n'est pas redonné, et seul un
    /// fichier ordinaire peut être elle. (btrfs et tmpfs ne redonnent pas un numéro tout de suite : l'essai n'y tombe
    /// pas ; les essais tournent sous la cible de compilation, sur ext4 ici.)
    #[cfg(unix)]
    #[test]
    fn inode_repris_jamais_pris_pour_l_ancienne() {
        use std::os::unix::fs::MetadataExt;
        let racine = crate::socle::dossier_local().join("essai-inode-repris");
        let _ = std::fs::remove_dir_all(&racine);
        let cible = racine.join("bin").join(NOM);
        let de_cote = cible.with_file_name(format!("{NOM}.precedent"));
        let mut repris = 0;
        for tour in 0..40 {
            faux_programme(&cible, Some("0.79.0"));
            let ancienne = std::fs::read(&cible).unwrap();
            let numero = std::fs::metadata(&cible).unwrap().ino();
            let precedente = Precedente::retenir(&cible).expect("mise de côté");
            std::fs::remove_file(&de_cote).unwrap();
            std::fs::remove_file(&cible).unwrap();
            if tour % 2 == 0 {
                std::fs::write(&cible, avec_entete("faux ", "0.80.0; etranger")).unwrap();
            } else {
                std::fs::create_dir(&cible).unwrap();
            }
            repris += usize::from(std::fs::symlink_metadata(&cible).unwrap().ino() == numero);
            let dit = precedente.remettre(&cible);
            // Ce qui est dit « l'ancienne » à la cible doit l'être : un fichier ordinaire, avec ses octets.
            if dit.contains("reste en place") || dit.contains("remise en place") || dit.contains("réécrite") {
                assert_eq!(
                    std::fs::read(&cible).ok(),
                    Some(ancienne),
                    "tour {tour}, pris pour l'ancienne : {dit}"
                );
            }
            if cible.is_dir() {
                std::fs::remove_dir_all(&cible).unwrap();
            } else {
                std::fs::remove_file(&cible).unwrap();
            }
            for reste in std::fs::read_dir(racine.join("bin")).unwrap() {
                let _ = std::fs::remove_file(reste.unwrap().path());
            }
        }
        eprintln!("numéro repris par ce qui a pris la place : {repris} sur 40");
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// V-2 (relecture du recontrôle 2, 0.95) : le second nom de l'ancienne copie (`<NOM>.precedent`) effacé, ou
    /// remplacé par un fichier étranger, pendant la mise à jour (un programme du compte). Avant, la remise échouait
    /// (« No such file or directory ») : la copie étrangère restait installée, et le message disait « elle est gardée
    /// sous …precedent », où il n'y avait rien, ou le fichier étranger. Maintenant, l'ancienne copie est réécrite à sa
    /// place depuis ce qui la tient ; si sa place est bloquée (un dossier plein), elle est gardée sous un nom neuf,
    /// dit, qui a ses octets. Jamais un fichier étranger dit « l'ancienne », et il n'est pas effacé.
    #[cfg(unix)]
    #[test]
    fn second_nom_perdu_l_ancienne_reecrite_depuis_ce_qui_la_tient() {
        let racine = crate::socle::dossier_local().join("essai-second-nom-perdu");
        let _ = std::fs::remove_dir_all(&racine);
        let bin = racine.join("bin");
        let cible = bin.join(NOM);
        let de_cote = cible.with_file_name(format!("{NOM}.precedent"));
        let etranger = avec_entete("faux ", "0.80.0; etranger");
        let vider = || {
            for reste in std::fs::read_dir(&bin).unwrap() {
                let reste = reste.unwrap().path();
                if reste.is_dir() {
                    std::fs::remove_dir_all(&reste).unwrap();
                } else {
                    std::fs::remove_file(&reste).unwrap();
                }
            }
        };
        // Le second nom effacé (ou remplacé par un fichier étranger), et la place prise par un fichier étranger (ou
        // bloquée par un dossier plein) : ce qui est dit, et les noms du dossier qui ont les octets de l'ancienne.
        let remise = |de_cote_etranger: bool, place_bloquee: bool| {
            faux_programme(&cible, Some("0.79.0"));
            let ancienne = std::fs::read(&cible).unwrap();
            let precedente = Precedente::retenir(&cible).expect("mise de côté");
            std::fs::remove_file(&de_cote).unwrap();
            if de_cote_etranger {
                std::fs::write(&de_cote, &etranger).unwrap();
            }
            std::fs::remove_file(&cible).unwrap();
            if place_bloquee {
                std::fs::create_dir_all(cible.join("occupe")).unwrap();
            } else {
                std::fs::write(&cible, &etranger).unwrap();
            }
            let dit = precedente.remettre(&cible);
            let ont: Vec<PathBuf> = std::fs::read_dir(&bin)
                .unwrap()
                .map(|n| n.unwrap().path())
                .filter(|n| std::fs::symlink_metadata(n).unwrap().is_file())
                .filter(|n| std::fs::read(n).unwrap() == ancienne)
                .collect();
            (dit, ont)
        };
        for (de_cote_etranger, place_bloquee) in [(false, false), (true, false), (false, true), (true, true)] {
            let cas = format!("second nom étranger {de_cote_etranger}, place bloquée {place_bloquee}");
            let (dit, ont) = remise(de_cote_etranger, place_bloquee);
            assert_eq!(ont.len(), 1, "{cas} : l'ancienne copie perdue, ou en double : {dit}");
            if place_bloquee {
                assert!(
                    dit.contains("gardée sous") && dit.contains(&ont[0].display().to_string()),
                    "{cas} : {dit}"
                );
                assert!(dit.contains("ne la lancez pas"), "{cas} : {dit}");
            } else {
                assert_eq!(ont[0], cible, "{cas}, la copie étrangère reste installée : {dit}");
                assert!(dit.contains("réécrite"), "{cas} : {dit}");
                assert!(!dit.contains("gardée sous"), "{cas} : {dit}");
            }
            assert!(
                !dit.contains(&format!("gardée sous {}", de_cote.display())),
                "{cas}, « gardée » sous un nom qui n'a pas l'ancienne copie : {dit}"
            );
            if de_cote_etranger {
                assert_eq!(
                    std::fs::read(&de_cote).unwrap(),
                    etranger,
                    "{cas}, le fichier étranger est touché"
                );
                assert!(dit.contains("n'est pas l'ancienne copie"), "{cas} : {dit}");
            }
            vider();
        }
        for place_bloquee in [false, true] {
            let (dit, ont) = crate::langue::en_anglais(|| remise(false, place_bloquee));
            assert_eq!(ont.len(), 1, "{dit}");
            assert!(
                dit.contains(if place_bloquee { "kept as" } else { "rewritten" }),
                "{dit}"
            );
            assert!(!dit.contains(" : ") && !dit.contains(" ; "), "{dit}");
            vider();
        }
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// C-1 (contrôle 2 du sous-lot c2 de la 0.95) : le fichier de l'ancienne copie réécrit sur place pendant la mise à
    /// jour (un autre programme, par son second nom : même inode, autres octets). Avant, il était reconnu par son seul
    /// inode, et dit « l'ancienne copie reste en place » ou « est remise en place ». Maintenant ses octets sont
    /// comparés à l'empreinte prise à sa mise de côté : jamais dit l'ancienne, jamais « gardée », et rien d'étranger
    /// n'est réécrit à sa place. Témoins : sans réécriture, « reste » et « remise en place » sont dits.
    #[cfg(unix)]
    #[test]
    fn ancienne_changee_jamais_dite_remise() {
        let racine = crate::socle::dossier_local().join("essai-ancienne-changee");
        let _ = std::fs::remove_dir_all(&racine);
        let cible = racine.join("bin").join(NOM);
        let de_cote = cible.with_file_name(format!("{NOM}.precedent"));
        let etranger = avec_entete("faux ", "0.80.0; etranger");
        // `renomme` : la copie posée a pris la place ; `bloquee` : un dossier plein à la place ; `perdu` : le second
        // nom effacé ensuite ; `change` : l'ancienne réécrite sur place. Rend ce qui est dit.
        let remise = |renomme: bool, bloquee: bool, perdu: bool, change: bool| {
            let _ = std::fs::remove_dir_all(&racine);
            faux_programme(&cible, Some("0.79.0"));
            let precedente = Precedente::retenir(&cible).expect("mise de côté");
            if change {
                std::fs::write(&de_cote, &etranger).unwrap();
            }
            if perdu {
                std::fs::remove_file(&de_cote).unwrap();
            }
            if renomme || bloquee {
                std::fs::remove_file(&cible).unwrap();
            }
            if bloquee {
                std::fs::create_dir_all(cible.join("occupe")).unwrap();
            } else if renomme {
                faux_programme(&cible, Some("0.80.0"));
            }
            precedente.remettre(&cible)
        };
        for (renomme, bloquee, perdu) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (true, false, true),
        ] {
            let cas = format!("renommée {renomme}, bloquée {bloquee}, second nom perdu {perdu}");
            let dit = remise(renomme, bloquee, perdu, true);
            for faux in ["reste en place", "remise en place", "réécrite", "gardée sous"] {
                assert!(!dit.contains(faux), "{cas}, « {faux} » d'un contenu changé : {dit}");
            }
            assert!(dit.contains("contenu a changé"), "{cas} : {dit}");
            assert!(
                dit.contains("ne le lancez pas") || dit.contains("ne la lancez pas"),
                "{cas} : {dit}"
            );
            if perdu || renomme {
                // Rien d'étranger réécrit ni renommé à sa place (R-5) : la copie posée y est encore.
                assert_ne!(std::fs::read(&cible).ok(), Some(etranger.clone()), "{cas} : {dit}");
            }
            if (renomme || bloquee) && !perdu {
                // R-5 : laissée sous son nom de côté, avec le geste à faire avant la mise à jour suivante.
                assert_eq!(std::fs::read(&de_cote).ok(), Some(etranger.clone()), "{cas} : {dit}");
                assert!(dit.contains("avant de refaire la mise à jour"), "{cas} : {dit}");
            }
        }
        assert_eq!(remise(false, false, false, false), "l'ancienne copie reste en place");
        assert_eq!(
            remise(true, false, false, false),
            "l'ancienne copie est remise en place"
        );
        let dit = crate::langue::en_anglais(|| remise(true, false, false, true));
        assert!(
            dit.contains("content changed") && !dit.contains("put back in place"),
            "{dit}"
        );
        assert!(!dit.contains(" : ") && !dit.contains(" ; "), "{dit}");
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// M-1 (relecture DEP-4 de la 0.95) : la copie en place est un lien symbolique, et le fichier qu'il désigne est
    /// réécrit sur place, ou remplacé par un autre, pendant la mise à jour (un autre programme). Avant, seul le texte du
    /// lien était retenu : « l'ancienne copie est remise en place » (L1), « reste en place » (L2) ou « réécrite », alors
    /// que ce qui serait lancé était le contenu étranger. Maintenant le fichier au bout est tenu ouvert avec son
    /// empreinte, et revu à la fin. Témoins : sans changement, les trois sont dits.
    ///
    /// M-1, N-2, N-3 (revérification de la ronde 2) : le second nom perdu et le fichier au bout remplacé, le lien réécrit
    /// était posé à la cible (lançant le contenu étranger), ou, la cible prise par un dossier (`bloquee`), « gardé sous »
    /// son nom neuf. Maintenant, ni la cible ni aucun nom de remise ne lance le contenu étranger.
    #[cfg(unix)]
    #[test]
    fn lien_vers_un_fichier_change_jamais_dit_l_ancienne() {
        let racine = crate::socle::dossier_local().join("essai-lien-change");
        let cible = racine.join("bin").join(NOM);
        let de_cote = cible.with_file_name(format!("{NOM}.precedent"));
        let reel = racine.join("ailleurs").join("vanguard-reel");
        let etranger = avec_entete("faux ", "0.80.0; etranger");
        // `renomme` : la copie posée a pris la place ; `perdu` : le second nom effacé ensuite ; `change` : le fichier
        // désigné réécrit sur place ; `remplace` : remplacé par un autre fichier, sous le même nom ; `bloquee` : la
        // cible prise par un dossier non vide (le renommage à la cible échoue). Rend ce qui est dit et ce que lancerait
        // la cible.
        let remise = |renomme: bool, perdu: bool, change: bool, remplace: bool, bloquee: bool| {
            let _ = std::fs::remove_dir_all(&racine);
            faux_programme(&reel, Some("0.79.0"));
            std::fs::create_dir_all(racine.join("bin")).unwrap();
            std::os::unix::fs::symlink(&reel, &cible).unwrap();
            let precedente = Precedente::retenir(&cible).expect("mise de côté");
            if change {
                std::fs::write(&reel, &etranger).unwrap();
            }
            if remplace {
                std::fs::remove_file(&reel).unwrap();
                std::fs::write(&reel, &etranger).unwrap();
            }
            if perdu {
                std::fs::remove_file(&de_cote).unwrap();
            }
            if renomme {
                std::fs::remove_file(&cible).unwrap();
                faux_programme(&cible, Some("0.80.0"));
            }
            if bloquee {
                std::fs::remove_file(&cible).unwrap();
                faux_programme(&cible.join("dedans"), Some("0.80.0"));
            }
            let dit = precedente.remettre(&cible);
            (dit, std::fs::read(&cible).ok())
        };
        for (renomme, perdu, bloquee) in [
            (false, false, false),
            (true, false, false),
            (true, true, false),
            (false, true, true),
        ] {
            for (change, remplace) in [(true, false), (false, true)] {
                let cas = format!(
                    "renommée {renomme}, second nom perdu {perdu}, bloquée {bloquee}, réécrit {change}, remplacé {remplace}"
                );
                let (dit, lance) = remise(renomme, perdu, change, remplace, bloquee);
                for faux in ["reste en place", "remise en place", "réécrite", "gardée sous"] {
                    assert!(
                        !dit.contains(faux),
                        "{cas}, « {faux} » d'un lien vers un contenu changé : {dit}"
                    );
                }
                assert!(
                    dit.contains("le fichier qu'il désigne a changé")
                        || dit.contains("le fichier que désigne son lien a changé"),
                    "{cas} : {dit}"
                );
                assert!(
                    dit.contains("ne le lancez pas") || dit.contains("ne la lancez pas"),
                    "{cas} : {dit}"
                );
                // R-5, N-3 : jamais posé à la cible par Vanguard (sans renommage, la cible est le lien d'origine, que
                // l'autre programme a changé : dit, ci-dessus) ; N-2 : jamais gardé sous un nom de remise.
                if renomme || bloquee {
                    assert_ne!(lance, Some(etranger.clone()), "{cas} : {dit}");
                }
                let remises: Vec<_> = std::fs::read_dir(racine.join("bin"))
                    .unwrap()
                    .flatten()
                    .filter(|e| e.file_name().to_string_lossy().starts_with(&format!("{NOM}.remise-")))
                    .map(|e| e.path())
                    .collect();
                assert!(
                    remises.iter().all(|r| std::fs::read(r).ok() != Some(etranger.clone())),
                    "{cas} : {remises:?} ; {dit}"
                );
                if renomme && !perdu {
                    // R-5 : le lien laissé de côté, jamais posé à la cible.
                    assert!(dit.contains("avant de refaire la mise à jour"), "{cas} : {dit}");
                }
            }
        }
        let ancienne = Some(avec_entete("prog ", "0.79.0; fin"));
        let temoins = [
            ((false, false), "l'ancienne copie reste en place"),
            ((true, false), "l'ancienne copie est remise en place"),
        ];
        for ((renomme, perdu), attendu) in temoins {
            assert_eq!(
                remise(renomme, perdu, false, false, false),
                (attendu.to_string(), ancienne.clone())
            );
        }
        let (dit, lance) = remise(true, true, false, false, false);
        assert!(dit.starts_with("l'ancienne copie est réécrite à sa place"), "{dit}");
        assert_eq!(lance, ancienne, "{dit}");
        let (dit, _) = crate::langue::en_anglais(|| remise(true, false, false, true, false));
        assert!(dit.contains("the file it points to changed"), "{dit}");
        assert!(!dit.contains(" : ") && !dit.contains(" ; "), "{dit}");
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// R-9 (relecture DEP-4 de la 0.95) : une copie en place qui ne se tient pas (plus de 512 Mio, ou un lien vers
    /// rien) arrête la mise à jour avant de rien remplacer. Avant, le message nommait le nom de côté (`…precedent`),
    /// sans geste à faire ; maintenant il nomme la copie en place, la cause, et dit de la mettre à l'abri.
    #[cfg(unix)]
    #[test]
    fn copie_qui_ne_se_tient_pas_nommee_avec_le_geste() {
        let racine = crate::socle::dossier_local().join("essai-copie-pas-tenue");
        let _ = std::fs::remove_dir_all(&racine);
        let cible = racine.join("bin").join(NOM);
        let de_cote = cible.with_file_name(format!("{NOM}.precedent"));
        // Un fichier creux : 512 Mio et un octet, sans les écrire sur le disque.
        faux_programme(&cible, Some("0.79.0"));
        std::fs::OpenOptions::new()
            .write(true)
            .open(&cible)
            .unwrap()
            .set_len(TAILLE_MAX + 1)
            .unwrap();
        let gros = Precedente::retenir(&cible)
            .err()
            .expect("une copie de plus de 512 Mio retenue")
            .to_string();
        std::fs::remove_file(&cible).unwrap();
        std::os::unix::fs::symlink(racine.join("rien"), &cible).unwrap();
        let vers_rien = Precedente::retenir(&cible)
            .err()
            .expect("un lien vers rien retenu")
            .to_string();
        for (cas, dit) in [("plus de 512 Mio", &gros), ("lien vers rien", &vers_rien)] {
            assert!(
                dit.contains(&format!("la copie en place, {},", cible.display())),
                "{cas} : {dit}"
            );
            assert!(
                dit.contains("à l'abri") && !dit.contains(&format!("{NOM}.precedent")),
                "{cas} : {dit}"
            );
        }
        assert!(gros.contains("512 Mio"), "{gros}");
        assert!(std::fs::symlink_metadata(&de_cote).is_err(), "{vers_rien}");
        let en = crate::langue::en_anglais(|| Precedente::retenir(&cible).err().unwrap().to_string());
        assert!(en.contains("somewhere safe") && !en.contains(" : "), "{en}");
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// V-2 (relecture du recontrôle 2, 0.95), par la mise à jour entière : la copie provisoire échangée par son nom
    /// (R-1) et un fil qui efface le second nom de l'ancienne copie dès qu'il paraît. Avant, environ une fois sur cinq,
    /// la copie étrangère restait installée (le message disait « gardée sous » un nom où il n'y avait rien).
    /// Maintenant, à chaque tour, l'ancienne copie est à sa place à la fin : refus avant le renommage, remise, ou
    /// réécrite ; et aucun nom provisoire de la remise ne traîne.
    #[cfg(unix)]
    #[test]
    fn second_nom_efface_pendant_la_mise_a_jour_jamais_l_etrangere_installee() {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        let racine = crate::socle::dossier_local().join("essai-second-nom-efface");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        let de_cote = cible.with_file_name(format!("{NOM}.precedent"));
        faux_programme(&source, Some("0.80.0"));
        let _seul = UN_A_LA_FOIS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *ECHANGE.lock().unwrap() = Some(racine.join("bin"));
        let fin = std::sync::Arc::new(AtomicBool::new(false));
        let fil = {
            let (fin, de_cote) = (fin.clone(), de_cote.clone());
            std::thread::spawn(move || {
                while !fin.load(SeqCst) {
                    let _ = std::fs::remove_file(&de_cote);
                }
            })
        };
        let (mut refus, mut remises, mut reecrites) = (0, 0, 0);
        let mut echec = None;
        for tour in 0..200 {
            faux_programme(&cible, Some("0.79.0"));
            let avant = std::fs::read(&cible).unwrap();
            let e = match remplacer(
                &source,
                &cible,
                (0, 80, 0, 0),
                soi_de(&source).as_deref(),
                TAILLE_MAX,
                &inconnue(),
                ECHANGE_PAR_LE_NOM,
                &dite(&source, &cible),
            ) {
                Ok(()) => {
                    echec = Some(format!("tour {tour} : échangée, et dite faite"));
                    break;
                }
                Err(e) => e,
            };
            if std::fs::read(&cible).ok().as_ref() != Some(&avant) {
                echec = Some(format!("tour {tour}, l'ancienne copie n'est pas à sa place : {e}"));
                break;
            }
            let traine = std::fs::read_dir(racine.join("bin"))
                .unwrap()
                .map(|n| n.unwrap().file_name().to_string_lossy().into_owned())
                .find(|n| n.contains("remise"));
            if let Some(n) = traine {
                echec = Some(format!("tour {tour}, {n} traîne : {e}"));
                break;
            }
            if e.contains("rien n'est remplacé") {
                refus += 1;
            } else if e.contains("réécrite") {
                reecrites += 1;
            } else {
                remises += 1;
            }
        }
        fin.store(true, SeqCst);
        fil.join().unwrap();
        *ECHANGE.lock().unwrap() = None;
        eprintln!("refus avant le renommage {refus}, remises {remises}, réécrites {reecrites}");
        let _ = std::fs::remove_dir_all(&racine);
        assert_eq!(echec, None);
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
        let r = remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            regarde,
            &dite(&source, &cible),
        );
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
        let e = remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &dite(&source, &cible),
        )
        .unwrap_err();
        assert!(e.contains("retirez"), "{e}");
        assert!(e.contains(&format!("{NOM}.nouveau")), "{e}");
        assert_eq!(std::fs::read(&cible).unwrap(), avant);
        std::fs::remove_dir_all(&provisoire).unwrap();
        remplacer(
            &source,
            &cible,
            (0, 80, 0, 0),
            soi_de(&source).as_deref(),
            TAILLE_MAX,
            &inconnue(),
            SANS_ESSAI,
            &dite(&source, &cible),
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// N-5 (recontrôle 2, 0.95) : en anglais, un échec de la mise à jour se lit « x: y », jamais avec le « : » à la
    /// française : quand rien n'est remplacé (ici R-4) comme quand l'ancienne copie est remise (R-1).
    #[test]
    fn echecs_en_anglais_sans_deux_points_a_la_francaise() {
        let racine = crate::socle::dossier_local().join("essai-anglais-deux-points");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0"));
        faux_programme(&cible, Some("0.79.0"));
        let provisoire = racine.join("bin").join(format!("{NOM}.nouveau"));
        std::fs::create_dir_all(provisoire.join("dedans")).unwrap();
        let r = crate::langue::en_anglais(|| {
            remplacer(
                &source,
                &cible,
                (0, 80, 0, 0),
                soi_de(&source).as_deref(),
                TAILLE_MAX,
                &inconnue(),
                SANS_ESSAI,
                &dite(&source, &cible),
            )
        });
        let e = r.unwrap_err();
        assert!(e.contains("again: nothing is replaced"), "{e}");
        assert!(!e.contains(" : "), "{e}");
        std::fs::remove_dir_all(&provisoire).unwrap();

        let _seul = UN_A_LA_FOIS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *ECHANGE.lock().unwrap() = Some(racine.join("bin"));
        REECRITE.store(false, std::sync::atomic::Ordering::SeqCst);
        let r = crate::langue::en_anglais(|| {
            remplacer(
                &source,
                &cible,
                (0, 80, 0, 0),
                soi_de(&source).as_deref(),
                TAILLE_MAX,
                &inconnue(),
                ECHANGE_PAR_LE_NOM,
                &dite(&source, &cible),
            )
        });
        if REECRITE.load(std::sync::atomic::Ordering::SeqCst) {
            let e = r.expect_err("échangée par son nom, et dite faite");
            assert!(e.contains("another program): the old copy is put back"), "{e}");
            assert!(!e.contains(" : "), "{e}");
        }
        *ECHANGE.lock().unwrap() = None;
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
        assert!(!e.contains("reste en place"), "{e}");
        assert!(e.contains("rien n'est remplacé"), "{e}");
        drop(tenue);
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// N-5 (recontrôle 2, 0.95) : à la première pose (aucune copie avant), une nouvelle copie qui ne démarre pas ne
    /// dit pas « l'ancienne reste en place » : il n'y en a pas. Rien n'est remplacé, et rien n'est laissé à la place.
    #[cfg(unix)]
    #[test]
    fn premiere_pose_ratee_ne_parle_pas_d_une_ancienne() {
        let racine = crate::socle::dossier_local().join("essai-premiere-pose");
        let _ = std::fs::remove_dir_all(&racine);
        let source = racine.join("cle").join(NOM);
        let cible = racine.join("bin").join(NOM);
        faux_programme(&source, Some("0.80.0"));
        for anglais in [false, true] {
            let pose = || {
                poser_copie_dans(
                    &source,
                    &cible,
                    soi_de(&source).as_deref(),
                    &inconnue(),
                    HORS_HISTORIQUE,
                    essayer,
                )
            };
            let e = if anglais {
                crate::langue::en_anglais(pose)
            } else {
                pose()
            }
            .unwrap_err();
            assert!(!e.contains("reste en place") && !e.contains("stays in place"), "{e}");
            assert!(
                e.contains(if anglais {
                    "nothing is replaced"
                } else {
                    "rien n'est remplacé"
                }),
                "{e}"
            );
            assert!(std::fs::symlink_metadata(&cible).is_err(), "{e}");
            let provisoire = cible.with_file_name(format!("{NOM}.nouveau"));
            assert!(std::fs::symlink_metadata(provisoire).is_err(), "{e}");
        }
        let _ = std::fs::remove_dir_all(&racine);
    }
}
