//! La base ClamAV de l'ordinateur, trouvée, jugée digne de confiance, chargée, et l'examen d'un fichier par elle.
//!
//! Confiance (P17) : aucune vérification de la signature RSA des .cvd (freshclam l'a faite en l'installant) ; la base
//! est crue parce que seul le système a pu l'écrire. Sous Linux, son dossier, chacun de ses parents et chaque fichier
//! lu appartiennent à root ou au compte du service (clamav, clamupdate), jamais au compte qui lit ; ni le dossier ni
//! un fichier ne s'écrit par « autres », ni par ce compte (le noyau en juge, ACL comprises), et ce compte n'est pas
//! membre de leur groupe (un compte du groupe clamav peut, un jour, y écrire) ; un parent écrivable par tous n'est
//! admis que collant (/tmp). Chaque fichier est ouvert sans suivre de lien et jugé sur ce qui a été ouvert. Sous
//! Windows (P16), la base de ClamAV pour Windows (`Program Files\ClamAV\database`), dont le dossier et chaque fichier
//! sont réservés aux administrateurs ; Vanguard ne télécharge jamais de base lui-même. Un seul fichier douteux : toute
//! la base est « non fiable : non lue ».
//!
//! Jamais en administrateur (P22) : un défaut d'un lecteur de format, devant une base ou un fichier piégés, y
//! deviendrait une prise de contrôle de l'ordinateur. Le garde, en root, ne reçoit que la liste binaire des
//! empreintes (`Signatures::liste_sha256`), produite ici par le compte.
//!
//! Mémoire (P21) : la base complète (`Mode::Complete`) pour une analyse à la demande ; les empreintes seules
//! (`Mode::Empreintes`) pour ce qui tourne en continu. Le garde (L3) et le veilleur prendront `charger` et
//! `par_empreintes` (la base est surtout faite de MD5 : 542 000 empreintes en nov. 2026, dont 227 SHA-256 seulement),
//! `par_sha256` et `liste_sha256` n'en couvrant qu'une part ; le moteur commun (AV4), `examiner`. Rien ne les appelle
//! encore.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::commun::Cible;
use super::corps::Cadre;
use super::cvd::{self, Cvd};
use super::signatures::{self, Chargement, Options, Signatures, Verdict};
use crate::analyse::{self, Bornes, Details, Partie, Type};
use crate::protection::moteur;
use crate::{tr, trf};

/// Les entrées du dossier parcourues, au plus : il en a une dizaine.
const ENTREES_MAX: usize = 4096;
/// Les fichiers lus, au plus (bases .cvd/.cld et fichiers de signatures à part).
const FICHIERS_MAX: usize = 256;
/// Les octets gardés en mémoire pendant le chargement, au plus : main.cvd décompressé et daily.cld font 322 Mo.
const TOTAL_MAX: usize = 1 << 30;

/// Pourquoi la base n'est pas chargée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Aucune base sur l'ordinateur.
    Absente,
    /// Vanguard tourne en administrateur (root) : aucune lecture de format (P22).
    Administrateur,
    /// Un fichier ou un dossier que d'autres que le système ont pu écrire : rien n'est lu.
    NonFiable(PathBuf, String),
    /// Le dossier ne se lit pas.
    Illisible(PathBuf, String),
    /// Plus que `TOTAL_MAX` octets, ou plus de `FICHIERS_MAX` fichiers.
    TropGrosse,
    /// Aucun fichier de signatures lisible, avec les bases écartées (nom, raison) s'il y en a.
    Vide(Vec<(String, String)>),
}

impl std::fmt::Display for Refus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refus::Absente => f.write_str(tr!(
                "aucune base ClamAV sur l'ordinateur",
                "no ClamAV database on this computer"
            )),
            Refus::Administrateur => f.write_str(tr!(
                "base ClamAV non lue en administrateur (lecture de données hostiles)",
                "ClamAV database not read as administrator (hostile data)"
            )),
            Refus::NonFiable(chemin, pourquoi) => f.write_str(&trf!(
                "base ClamAV non fiable, non lue : {} ({pourquoi})",
                "untrusted ClamAV database, not read: {} ({pourquoi})",
                chemin.display()
            )),
            Refus::Illisible(chemin, pourquoi) => f.write_str(&trf!(
                "base ClamAV illisible : {} ({pourquoi})",
                "unreadable ClamAV database: {} ({pourquoi})",
                chemin.display()
            )),
            Refus::TropGrosse => f.write_str(tr!("base ClamAV trop grosse", "ClamAV database too large")),
            Refus::Vide(ecartes) => {
                f.write_str(tr!(
                    "base ClamAV sans signatures lisibles",
                    "ClamAV database without readable signatures"
                ))?;
                for (k, (nom, raison)) in ecartes.iter().enumerate() {
                    write!(f, "{}{nom} ({raison})", if k == 0 { " : " } else { " ; " })?;
                }
                Ok(())
            }
        }
    }
}

/// Un fichier .cvd ou .cld chargé.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Source {
    pub nom: String,
    pub en_tete: cvd::EnTete,
}

/// Une base chargée.
pub(crate) struct Base {
    pub dossier: PathBuf,
    pub options: Options,
    /// Les .cvd et .cld chargés.
    pub sources: Vec<Source>,
    /// Les fichiers de signatures à part (local.hdb, local.ign2…).
    pub a_part: Vec<String>,
    /// Les fichiers sautés, avec leur raison (base coupée, abîmée, liste .info fausse) : dits avec le résultat.
    pub ecartes: Vec<(String, String)>,
    pub signatures: Signatures,
}

/// Ce que la confiance exige, sous Linux : qui peut posséder la base, qui la lit.
#[cfg(unix)]
pub(crate) struct Regles {
    /// root et les comptes du service ClamAV, hors le compte qui lit.
    proprietaires: Vec<u32>,
    /// Le compte réel et effectif qui lit.
    comptes: Vec<u32>,
    /// Ses groupes (principal et supplémentaires).
    groupes: Vec<u32>,
    /// Le compte peut-il écrire à ce chemin (le noyau en juge) ?
    ecrivable: fn(&Path) -> bool,
}

/// Ce que la confiance exige, sous Windows : un dossier et des fichiers réservés aux administrateurs.
#[cfg(windows)]
pub(crate) struct Regles {
    /// D'autres que SYSTEM et les administrateurs peuvent-ils écrire à ce chemin (ou ses droits sont-ils illisibles) ?
    ecrivable: fn(&Path) -> bool,
}

#[cfg(unix)]
impl Regles {
    fn de_la_machine() -> Result<Regles, Refus> {
        let comptes = vec![crate::socle::uid(), crate::socle::euid()];
        let status = Path::new("/proc/self/status");
        let groupes = crate::socle::lire_texte_ordinaire(status, 1 << 20)
            .ok()
            .and_then(|t| groupes_du_processus(&t))
            .ok_or_else(|| {
                Refus::NonFiable(
                    status.to_path_buf(),
                    tr!("groupes du compte illisibles", "account groups unreadable").into(),
                )
            })?;
        let mut proprietaires = vec![0];
        if let Ok(passwd) = crate::socle::lire_texte_ordinaire(Path::new("/etc/passwd"), 4 << 20) {
            proprietaires.extend(comptes_du_service(&passwd));
        }
        proprietaires.retain(|p| !comptes.contains(p));
        Ok(Regles {
            proprietaires,
            comptes,
            groupes,
            ecrivable: crate::socle::ecrivable,
        })
    }

    /// Ce que reproche la confiance à `m` (`strict` : le dossier de la base et ses fichiers ; sinon un parent).
    fn juger(&self, m: &std::fs::Metadata, strict: bool) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let mode = m.mode();
        if !self.proprietaires.contains(&m.uid()) || self.comptes.contains(&m.uid()) {
            return Err(trf!(
                "appartient au compte n° {}, ni root ni le service ClamAV",
                "owned by account #{}, neither root nor the ClamAV service",
                m.uid()
            ));
        }
        let collant = !strict && m.is_dir() && mode & 0o1000 != 0;
        if mode & 0o002 != 0 && !collant {
            return Err(tr!("écrivable par tous", "writable by everyone").into());
        }
        if self.groupes.contains(&m.gid()) && (strict || mode & 0o020 != 0) {
            return Err(trf!(
                "ce compte est membre de son groupe (n° {})",
                "this account is a member of its group (#{})",
                m.gid()
            ));
        }
        Ok(())
    }
}

/// Le groupe principal et les groupes supplémentaires du processus, d'après /proc/self/status.
#[cfg(unix)]
fn groupes_du_processus(status: &str) -> Option<Vec<u32>> {
    let mut groupes: Vec<u32> = Vec::new();
    let mut vus = 0u8;
    for l in status.lines() {
        let Some((cle, valeur)) = l.split_once(':') else {
            continue;
        };
        if matches!(cle, "Gid" | "Groups") {
            for g in valeur.split_whitespace() {
                groupes.push(g.parse().ok()?);
            }
            vus = vus.saturating_add(1);
        }
    }
    (vus == 2).then_some(groupes)
}

/// Les comptes du service ClamAV d'un /etc/passwd (clamav ; clamupdate chez Fedora).
#[cfg(unix)]
fn comptes_du_service(passwd: &str) -> Vec<u32> {
    passwd
        .lines()
        .filter_map(|l| {
            let mut champs = l.split(':');
            let nom = champs.next()?;
            let numero = champs.nth(1)?.parse().ok()?;
            matches!(nom, "clamav" | "clamupdate").then_some(numero)
        })
        .collect()
}

#[cfg(windows)]
impl Regles {
    fn de_la_machine() -> Regles {
        Regles {
            ecrivable: |p| {
                !crate::machine::windows::securite::proprietaire_et_droits(p)
                    .is_some_and(|d| crate::machine::windows::securite::reserve_aux_administrateurs(&d))
            },
        }
    }
}

/// Vanguard tourne-t-il en administrateur ? Sous Windows, un jeton illisible compte pour oui (échouer fermé).
fn administrateur() -> bool {
    #[cfg(unix)]
    {
        crate::socle::euid() == 0
    }
    #[cfg(windows)]
    {
        crate::machine::windows::processus::eleve_ou_inconnu()
    }
}

/// Le dossier de la base de cet ordinateur, s'il en a une.
fn dossier() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        crate::protection::antivirus::dossier_de_base()
    }
    #[cfg(windows)]
    {
        let d = crate::machine::windows::environnement::dossiers();
        let programmes = d.program_files_x64.as_ref().or(d.program_files.as_ref())?;
        Some(programmes.join("ClamAV").join("database")).filter(|p| p.is_dir())
    }
}

/// Charge la base de l'ordinateur, si elle est digne de confiance (voir le haut du module).
pub(crate) fn charger(options: Options) -> Result<Base, Refus> {
    if administrateur() {
        return Err(Refus::Administrateur);
    }
    let dossier = dossier().ok_or(Refus::Absente)?;
    #[cfg(unix)]
    let regles = Regles::de_la_machine()?;
    #[cfg(windows)]
    let regles = Regles::de_la_machine();
    charger_dans(&dossier, options, &regles)
}

/// Le dossier de la base, vérifié, en chemin canonique : lui et (sous Linux) chacun de ses parents.
fn verifier_dossier(dossier: &Path, regles: &Regles) -> Result<PathBuf, Refus> {
    let illisible = |e: std::io::Error| Refus::Illisible(dossier.to_path_buf(), e.to_string());
    let canonique = std::fs::canonicalize(dossier).map_err(illisible)?;
    if (regles.ecrivable)(&canonique) {
        return Err(Refus::NonFiable(
            canonique,
            tr!("écrivable par ce compte", "writable by this account").into(),
        ));
    }
    #[cfg(unix)]
    {
        // Le chemin canonique n'a plus de lien ; ses parents, écrits par le système seul, ne peuvent pas être
        // échangés entre ce regard et la lecture.
        for (k, d) in canonique.ancestors().enumerate() {
            let m = std::fs::symlink_metadata(d).map_err(|e| Refus::Illisible(d.to_path_buf(), e.to_string()))?;
            regles
                .juger(&m, k == 0)
                .map_err(|p| Refus::NonFiable(d.to_path_buf(), p))?;
        }
    }
    #[cfg(windows)]
    {
        // Le dossier de ClamAV aussi : qui y écrit pourrait remplacer `database` entier.
        if let Some(parent) = canonique.parent()
            && (regles.ecrivable)(parent)
        {
            return Err(Refus::NonFiable(
                parent.to_path_buf(),
                tr!(
                    "écrivable par d'autres que les administrateurs",
                    "writable by non-administrators"
                )
                .into(),
            ));
        }
    }
    Ok(canonique)
}

/// Un fichier de la base, s'il est digne de confiance, lu en entier (`max` octets au plus).
#[cfg(unix)]
fn lire_fiable(chemin: &Path, max: usize, regles: &Regles) -> Result<Vec<u8>, Refus> {
    use std::os::unix::fs::OpenOptionsExt;
    let non_fiable = |p: String| Refus::NonFiable(chemin.to_path_buf(), p);
    let illisible = |e: std::io::Error| Refus::Illisible(chemin.to_path_buf(), e.to_string());
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(chemin)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                non_fiable(tr!("lien symbolique", "symbolic link").into())
            } else {
                illisible(e)
            }
        })?;
    let m = f.metadata().map_err(illisible)?;
    if !m.file_type().is_file() {
        return Err(non_fiable(tr!("pas un simple fichier", "not a plain file").into()));
    }
    regles.juger(&m, true).map_err(non_fiable)?;
    if (regles.ecrivable)(chemin) {
        return Err(non_fiable(
            tr!("écrivable par ce compte", "writable by this account").into(),
        ));
    }
    lire_borne(f, m.len(), max).map_err(illisible)
}

#[cfg(windows)]
fn lire_fiable(chemin: &Path, max: usize, regles: &Regles) -> Result<Vec<u8>, Refus> {
    if (regles.ecrivable)(chemin) {
        return Err(Refus::NonFiable(
            chemin.to_path_buf(),
            tr!(
                "écrivable par d'autres que les administrateurs",
                "writable by non-administrators"
            )
            .into(),
        ));
    }
    // Ni lien ni jonction suivis, ni tube : un simple fichier, borné.
    let max = u64::try_from(max).unwrap_or(u64::MAX);
    crate::socle::lire_ordinaire(chemin, max).map_err(|e| Refus::Illisible(chemin.to_path_buf(), e.to_string()))
}

#[cfg(unix)]
fn lire_borne(f: std::fs::File, taille: u64, max: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let max64 = u64::try_from(max).unwrap_or(u64::MAX);
    if taille > max64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            tr!("trop gros", "too large"),
        ));
    }
    let mut octets = Vec::with_capacity(usize::try_from(taille).unwrap_or(0));
    f.take(max64.saturating_add(1)).read_to_end(&mut octets)?;
    if octets.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            tr!("trop gros", "too large"),
        ));
    }
    Ok(octets)
}

/// Pourquoi un .cvd ou .cld est sauté.
fn raison_cvd(e: &cvd::Erreur) -> String {
    match e {
        cvd::Erreur::EnTete => tr!("en-tête illisible", "unreadable header").into(),
        cvd::Erreur::TropGrosse => tr!("trop grosse", "too large").into(),
        cvd::Erreur::Compression => tr!("compression abîmée", "damaged compression").into(),
        cvd::Erreur::Archive => tr!("archive abîmée", "damaged archive").into(),
        cvd::Erreur::SansListe => tr!("sans liste .info", "no .info list").into(),
        cvd::Erreur::ListeFausse(nom) => trf!(
            "{nom} ne correspond pas à la liste .info",
            "{nom} does not match the .info list"
        ),
    }
}

/// Charge la base du dossier `dossier`, jugée par `regles`.
pub(crate) fn charger_dans(dossier: &Path, options: Options, regles: &Regles) -> Result<Base, Refus> {
    let dossier = verifier_dossier(dossier, regles)?;
    let illisible = |e: std::io::Error| Refus::Illisible(dossier.clone(), e.to_string());
    let mut noms: Vec<String> = Vec::new();
    for (k, entree) in std::fs::read_dir(&dossier).map_err(illisible)?.enumerate() {
        if k >= ENTREES_MAX {
            return Err(Refus::Illisible(
                dossier.clone(),
                tr!("trop d'entrées", "too many entries").into(),
            ));
        }
        // Un nom qui n'est pas de l'UTF-8 n'est pas celui d'un fichier de ClamAV : pas ouvert.
        if let Some(nom) = entree.map_err(illisible)?.file_name().to_str() {
            noms.push(nom.to_owned());
        }
    }
    noms.sort_unstable();
    // Extension en minuscules, comme `signatures::sorte` : freshclam ne les écrit pas autrement.
    let conteneur = |n: &str| n.rsplit_once('.').is_some_and(|(_, e)| matches!(e, "cvd" | "cld"));
    let lus = noms.iter().filter(|n| conteneur(n) || signatures::a_lire(n)).count();
    if lus > FICHIERS_MAX {
        return Err(Refus::TropGrosse);
    }
    let mut total = 0usize;
    let mut compter = |n: usize| {
        total = total
            .checked_add(n)
            .filter(|&t| t <= TOTAL_MAX)
            .ok_or(Refus::TropGrosse)?;
        Ok::<(), Refus>(())
    };
    // Par nom sans extension, la base la plus récente (freshclam laisse daily.cld, ou daily.cvd, rarement les deux).
    let mut choisies: BTreeMap<String, (String, Vec<u8>)> = BTreeMap::new();
    let mut ecartes: Vec<(String, String)> = Vec::new();
    for nom in noms.iter().filter(|n| conteneur(n)) {
        let octets = lire_fiable(&dossier.join(nom), cvd::FICHIER_MAX, regles)?;
        let Some(en_tete) = cvd::en_tete(&octets) else {
            ecartes.push((nom.clone(), raison_cvd(&cvd::Erreur::EnTete)));
            continue;
        };
        let racine = nom.rsplit_once('.').map_or(nom.as_str(), |(r, _)| r).to_owned();
        let plus_recente = choisies
            .get(&racine)
            .and_then(|(_, o)| cvd::en_tete(o))
            .is_none_or(|e| en_tete.version > e.version);
        if plus_recente {
            choisies.insert(racine, (nom.clone(), octets));
        }
    }
    let mut cvds: Vec<(String, Cvd)> = Vec::new();
    for (_, (nom, octets)) in choisies {
        match cvd::lire(octets) {
            Ok(c) => {
                compter(c.membres().fold(0usize, |t, (_, o)| t.saturating_add(o.len())))?;
                cvds.push((nom, c));
            }
            Err(e) => ecartes.push((nom, raison_cvd(&e))),
        }
    }
    let mut a_part: Vec<(String, Vec<u8>)> = Vec::new();
    for nom in noms.iter().filter(|n| !conteneur(n) && signatures::a_lire(n)) {
        let octets = lire_fiable(&dossier.join(nom), cvd::FICHIER_MAX, regles)?;
        compter(octets.len())?;
        a_part.push((nom.clone(), octets));
    }
    if cvds.is_empty() && a_part.is_empty() {
        return Err(Refus::Vide(ecartes));
    }
    // Les ignorées de tous les fichiers d'abord : celles de daily valent pour main.
    let mut chargement = Chargement::nouveau(options);
    let tous = || {
        cvds.iter()
            .flat_map(|(_, c)| c.membres())
            .chain(a_part.iter().map(|(n, o)| (n.as_str(), o.as_slice())))
    };
    for (nom, contenu) in tous() {
        chargement.ignorer(nom, contenu);
    }
    for (nom, contenu) in tous() {
        chargement.ajouter(nom, contenu);
    }
    let mut signatures = chargement.finir();
    for (_, c) in &cvds {
        signatures.comptes.hors_liste = signatures.comptes.hors_liste.saturating_add(c.hors_liste);
    }
    Ok(Base {
        dossier,
        options,
        sources: cvds
            .into_iter()
            .map(|(nom, c)| Source {
                nom,
                en_tete: c.en_tete,
            })
            .collect(),
        a_part: a_part.into_iter().map(|(n, _)| n).collect(),
        ecartes,
        signatures,
    })
}

/// Une signature trouvée dans une partie d'un fichier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Trouvaille {
    /// La partie, depuis le fichier (« archive.zip › programme.exe »).
    pub partie: String,
    pub nom: String,
}

/// Ce que la base a vu dans un fichier lu.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Constat {
    pub trouvailles: Vec<Trouvaille>,
    /// Ce qui n'a pas été lu, une phrase par manque, comme `moteur::Constat`. Vide : tout le fichier a été vérifié.
    pub non_verifie: Vec<String>,
}

/// La sorte de fichier que visent les signatures, d'après ce que le socle a reconnu.
fn cible(t: Type) -> Cible {
    match t {
        Type::Pe => Cible::Pe,
        Type::Elf => Cible::Elf,
        Type::MachO | Type::MachOUniversel => Cible::MachO,
        Type::Cfb
        | Type::DocWord
        | Type::ClasseurExcel
        | Type::PresentationPowerPoint
        | Type::Msi
        | Type::FluxOle
        | Type::SourceVba => Cible::Ole,
        Type::Image => Cible::Image,
        Type::Pdf => Cible::Pdf,
        Type::ClasseJava => Cible::Java,
        _ => Cible::Tout,
    }
}

/// Le point d'entrée (place dans le fichier) et les sections d'un programme, comme ClamAV les compte : sections PE
/// (données brutes), table des sections ELF (toutes, la nulle comprise : `S0` est la première).
fn cadre(p: &Partie) -> Cadre {
    let cible = cible(p.type_);
    match &p.details {
        Details::Pe(s) => Cadre {
            cible,
            point_entree: point_entree_pe(s),
            sections: s
                .sections
                .iter()
                .map(|x| (u64::from(x.position), u64::from(x.taille_brute)))
                .collect(),
        },
        Details::Elf(e) => Cadre {
            cible,
            // Le point d'entrée est une adresse : sa place est dans le segment chargé (PT_LOAD) qui la contient.
            point_entree: e.segments.iter().filter(|s| s.type_ == 1).find_map(|s| {
                let ecart = e.point_entree.checked_sub(s.adresse)?;
                (ecart < s.taille_fichier)
                    .then(|| s.position.checked_add(ecart))
                    .flatten()
            }),
            sections: e.sections.iter().map(|s| (s.position, s.taille)).collect(),
        },
        _ => Cadre::simple(cible),
    }
}

/// La place du point d'entrée d'un programme PE : dans la section qui le contient, ou dans les en-têtes (avant la
/// première section, à la même place que l'adresse).
fn point_entree_pe(s: &crate::pe::StructurePe) -> Option<u64> {
    let ep = s.point_entree;
    if s.sections.iter().all(|x| ep < x.adresse) {
        return Some(u64::from(ep));
    }
    s.sections.iter().find_map(|x| {
        let ecart = ep.checked_sub(x.adresse)?;
        (ecart < x.taille_brute).then(|| u64::from(x.position).checked_add(u64::from(ecart)))?
    })
}

/// Le fichier à `chemin`, lu par le socle d'analyse, chaque partie jugée par la base, le tout en moins de `delai`.
/// `Err` : Vanguard tourne en administrateur (P22), le fichier n'a pas pu être lu, ou l'examen n'a pas fini à temps :
/// rien n'est conclu. Une partie dans une liste blanche de la base retire ce qui est trouvé en elle et dans ce
/// qu'elle contient.
pub(crate) fn examiner(chemin: &Path, base: &Base, delai: Duration) -> Result<Constat, ()> {
    if administrateur() {
        return Err(());
    }
    examiner_sans_garde(chemin, base, delai)
}

/// Ce qui désigne une partie dans l'arbre de l'analyse : son parent, son chemin et son empreinte.
type Designation = (Option<usize>, String, Option<[u8; 32]>);

fn examiner_sans_garde(chemin: &Path, base: &Base, delai: Duration) -> Result<Constat, ()> {
    let echeance = Instant::now().checked_add(delai);
    let bornes = Bornes {
        delai,
        ..Bornes::default()
    };
    // Chaque partie jugée, par ce qui la désigne dans l'arbre (le visiteur ne reçoit pas son numéro).
    let mut vues: Vec<(Designation, Verdict)> = Vec::new();
    let mut echec = false;
    let mut visiteur = |p: &Partie, octets: &[u8]| {
        if echec {
            return;
        }
        match base.signatures.juger(octets, &cadre(p), echeance) {
            Ok(Verdict::Trouvees(n)) if n.is_empty() => {}
            Ok(v) => vues.push(((p.parent, p.chemin.clone(), p.sha256), v)),
            Err(_) => echec = true,
        }
    };
    let analyse = analyse::analyser_fichier(chemin, &bornes, &mut visiteur).map_err(|_| ())?;
    if echec {
        return Err(());
    }
    let numero = |cle: &(Option<usize>, String, Option<[u8; 32]>)| {
        analyse
            .parties
            .iter()
            .position(|p| p.parent == cle.0 && p.chemin == cle.1 && p.sha256 == cle.2)
    };
    let blanches: Vec<usize> = vues
        .iter()
        .filter(|(_, v)| *v == Verdict::Blanche)
        .filter_map(|(c, _)| numero(c))
        .collect();
    let sous_une_blanche = |i: usize| {
        let mut k = Some(i);
        // Chaque parent précède son enfant : la remontée finit en autant de pas qu'il y a de parties.
        for _ in 0..=analyse.parties.len() {
            let Some(j) = k else { return false };
            if blanches.contains(&j) {
                return true;
            }
            k = analyse.parties.get(j).and_then(|p| p.parent);
        }
        false
    };
    let mut trouvailles: Vec<Trouvaille> = Vec::new();
    for (cle, v) in &vues {
        let (Verdict::Trouvees(noms), Some(i)) = (v, numero(cle)) else {
            continue;
        };
        if sous_une_blanche(i) {
            continue;
        }
        let partie = analyse.chemin_complet(i);
        for nom in noms {
            let t = Trouvaille {
                partie: partie.clone(),
                nom: nom.clone(),
            };
            if !trouvailles.contains(&t) {
                trouvailles.push(t);
            }
        }
    }
    let mut non_verifie: Vec<String> = Vec::new();
    for (i, r) in analyse.manques() {
        if moteur::laisse_non_verifie(r) && !sous_une_blanche(i) {
            let phrase = format!("{} : {}", analyse.chemin_complet(i), moteur::raison(r));
            if !non_verifie.contains(&phrase) {
                non_verifie.push(phrase);
            }
        }
    }
    Ok(Constat {
        trouvailles,
        non_verifie,
    })
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::clamav::commun::hex;
    use crate::protection::clamav::cvd::essais::base as cvd_de;
    use crate::protection::clamav::hashes::Empreintes;
    use crate::protection::clamav::signatures::Mode;

    /// La chaîne d'essai EICAR, assemblée à l'exécution : ni le source ni un programme compilé ne la contiennent d'un
    /// bloc (P23).
    fn eicar() -> Vec<u8> {
        [
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$",
            "EICAR-STANDARD-",
            "ANTIVIRUS-TEST-FILE!$H+H*",
        ]
        .concat()
        .into_bytes()
    }

    const COMPLETE: Options = Options {
        mode: Mode::Complete,
        pua: false,
    };

    /// Des règles d'essai : les fichiers sont à nous, le compte qui lit est inventé, sans groupe ; les propriétaires
    /// admis sont ceux des parents du dossier (root, ou un compte inconnu dans l'espace de noms de verifier.sh) et le
    /// nôtre ; rien n'est écrivable par lui.
    #[cfg(unix)]
    fn regles(dossier: &Path) -> Regles {
        use std::os::unix::fs::MetadataExt;
        let mut proprietaires = vec![crate::socle::uid()];
        for parent in std::fs::canonicalize(dossier).unwrap().ancestors() {
            proprietaires.push(std::fs::symlink_metadata(parent).unwrap().uid());
        }
        Regles {
            proprietaires,
            comptes: vec![u32::MAX - 7],
            groupes: Vec::new(),
            ecrivable: |_| false,
        }
    }

    #[cfg(windows)]
    fn regles(_: &Path) -> Regles {
        Regles { ecrivable: |_| false }
    }

    /// Une base miniature : main.cvd (gzip) et daily.cld (tar seul, plus récent que le daily.cvd laissé à côté),
    /// un fichier à part, une base abîmée, et ce que freshclam laisse sans signatures.
    fn poser_base(dossier: &Path) {
        let e = Empreintes::de(&eicar());
        let ignoree = Empreintes::de(b"contenu ignore");
        let pua = Empreintes::de(b"contenu pua");
        let hdb = format!("{}:{}:Essai.Eicar-1\n", hex(&e.md5), eicar().len());
        let ndb = format!("Essai.Corps-1:0:*:{}\n", hex(b"marque-corps"));
        let hdu = format!("{}:11:Essai.Pua-1\n", hex(&pua.md5));
        let main = cvd_de(
            "main",
            3,
            &[
                ("main.hdb", hdb.as_bytes()),
                ("main.ndb", ndb.as_bytes()),
                ("main.hdu", hdu.as_bytes()),
            ],
            true,
        );
        std::fs::write(dossier.join("main.cvd"), main).unwrap();
        let hsb = format!("{}:14:Essai.Ignoree-1\n", hex(&ignoree.sha256));
        let daily = cvd_de(
            "daily",
            9,
            &[("daily.hsb", hsb.as_bytes()), ("daily.ign2", b"Essai.Ignoree-1\n")],
            false,
        );
        std::fs::write(dossier.join("daily.cld"), daily).unwrap();
        let vieux = format!("{}:12:Essai.Vieille-1\n", hex(&Empreintes::de(b"contenu vieux").md5));
        let vieille = cvd_de("daily", 8, &[("daily.hdb", vieux.as_bytes())], true);
        std::fs::write(dossier.join("daily.cvd"), vieille).unwrap();
        let local = format!("{}:13:Essai.Local-1\n", hex(&Empreintes::de(b"contenu local").sha256));
        std::fs::write(dossier.join("local.hsb"), local).unwrap();
        let mut abimee = cvd_de("abime", 1, &[("abime.hdb", b"x")], true);
        abimee.truncate(abimee.len() - 9);
        std::fs::write(dossier.join("abime.cvd"), abimee).unwrap();
        std::fs::write(dossier.join("freshclam.dat"), b"\x00\x01").unwrap();
        std::fs::write(dossier.join("main-3.cvd.sign"), b"signature").unwrap();
    }

    fn noms(c: &Constat) -> Vec<&str> {
        c.trouvailles.iter().map(|t| t.nom.as_str()).collect()
    }

    fn examiner_octets(base: &Base, dossier: &Path, nom: &str, octets: &[u8]) -> Constat {
        let f = dossier.join(nom);
        std::fs::write(&f, octets).unwrap();
        examiner_sans_garde(&f, base, Duration::from_secs(60)).unwrap()
    }

    #[test]
    fn chargement_et_examen() {
        let jet = crate::essais::Jetable::nouveau("clamav-base");
        let b = jet.join("base");
        std::fs::create_dir(&b).unwrap();
        poser_base(&b);
        let base = charger_dans(&b, COMPLETE, &regles(&b)).unwrap();
        let sources: Vec<(&str, u32)> = base
            .sources
            .iter()
            .map(|s| (s.nom.as_str(), s.en_tete.version))
            .collect();
        assert_eq!(sources, [("daily.cld", 9), ("main.cvd", 3)]);
        assert_eq!(base.dossier, std::fs::canonicalize(&b).unwrap());
        assert_eq!(base.options, COMPLETE);
        assert_eq!(base.a_part, ["local.hsb"]);
        assert_eq!(base.ecartes.len(), 1);
        assert_eq!(base.ecartes[0].0, "abime.cvd");
        assert_eq!(base.signatures.nombre(), 3);
        let f = jet.join("f");
        std::fs::create_dir(&f).unwrap();
        let c = examiner_octets(&base, &f, "eicar.com", &eicar());
        assert_eq!(noms(&c), ["Essai.Eicar-1"]);
        assert_eq!(c.trouvailles[0].partie, "eicar.com");
        assert!(c.non_verifie.is_empty(), "{:?}", c.non_verifie);
        // Dans une archive : la partie est nommée depuis le fichier.
        let zip = crate::archives::zip::essais::archive_controlee(&[("lisezmoi.txt", 0, &eicar())]);
        let c = examiner_octets(&base, &f, "a.zip", &zip);
        assert_eq!(
            c.trouvailles,
            [Trouvaille {
                partie: "a.zip › lisezmoi.txt".into(),
                nom: "Essai.Eicar-1".into()
            }]
        );
        assert_eq!(
            noms(&examiner_octets(&base, &f, "corps", b"xx marque-corps xx")),
            ["Essai.Corps-1"]
        );
        assert_eq!(
            noms(&examiner_octets(&base, &f, "local", b"contenu local")),
            ["Essai.Local-1"]
        );
        // Ignorée par daily.ign2, du daily.cvd plus ancien, ou PUA : rien.
        for contenu in [
            &b"contenu ignore"[..],
            b"contenu vieux",
            b"contenu pua",
            b"rien du tout",
        ] {
            assert_eq!(examiner_octets(&base, &f, "x", contenu), Constat::default());
        }
        // Les empreintes seules : pas les signatures de contenu.
        let base = charger_dans(
            &b,
            Options {
                mode: Mode::Empreintes,
                pua: false,
            },
            &regles(&b),
        )
        .unwrap();
        assert_eq!(base.signatures.nombre(), 2);
        assert_eq!(
            noms(&examiner_octets(&base, &f, "corps", b"xx marque-corps xx")),
            [] as [&str; 0]
        );
        // Par empreinte seule, ce que le garde demandera : EICAR n'est connue que par son MD5, local par son SHA-256.
        let e = Empreintes::de(&eicar());
        let taille = u64::try_from(eicar().len()).unwrap();
        assert_eq!(base.signatures.par_empreintes(&e, taille), Some("Essai.Eicar-1"));
        assert_eq!(base.signatures.par_empreintes(&e, taille + 1), None);
        assert_eq!(base.signatures.par_sha256(&e.sha256), None);
        let local = Empreintes::de(b"contenu local");
        assert_eq!(base.signatures.par_sha256(&local.sha256), Some("Essai.Local-1"));
        assert_eq!(
            base.signatures.par_sha256(&Empreintes::de(b"contenu ignore").sha256),
            None
        );
        assert_eq!(base.signatures.liste_sha256(), local.sha256);
    }

    /// Une partie dans une liste blanche n'est plus rien : ni ce qu'elle a, ni ce qu'elle contient.
    #[test]
    fn liste_blanche_d_une_partie() {
        let jet = crate::essais::Jetable::nouveau("clamav-blanche");
        let b = jet.join("base");
        std::fs::create_dir(&b).unwrap();
        let interieur = crate::archives::zip::essais::archive_controlee(&[("e.com", 0, &eicar())]);
        let exterieur = crate::archives::zip::essais::archive_controlee(&[("dedans.zip", 0, &interieur)]);
        let e = Empreintes::de(&eicar());
        let blanche = Empreintes::de(&interieur);
        let hsb = format!("{}:{}:Essai.Eicar-1\n", hex(&e.sha256), eicar().len());
        std::fs::write(b.join("essai.hsb"), &hsb).unwrap();
        let f = jet.join("f");
        std::fs::create_dir(&f).unwrap();
        let base = charger_dans(&b, COMPLETE, &regles(&b)).unwrap();
        let c = examiner_octets(&base, &f, "a.zip", &exterieur);
        assert_eq!(noms(&c), ["Essai.Eicar-1"]);
        assert_eq!(c.trouvailles[0].partie, "a.zip › dedans.zip › e.com");
        std::fs::write(
            b.join("essai.fp"),
            format!("{}:{}:Blanche-1\n", hex(&blanche.md5), interieur.len()),
        )
        .unwrap();
        let base = charger_dans(&b, COMPLETE, &regles(&b)).unwrap();
        assert_eq!(examiner_octets(&base, &f, "a.zip", &exterieur), Constat::default());
        // La liste blanche vise l'archive intérieure, pas EICAR : seule, EICAR reste trouvée et listée.
        assert_eq!(base.signatures.liste_sha256(), e.sha256);
        assert_eq!(base.signatures.par_sha256(&blanche.sha256), None);
    }

    /// Le point d'entrée et les sections d'un programme fabriqué, PE puis ELF, à la place que ClamAV leur donne.
    #[test]
    fn programmes_point_d_entree_et_sections() {
        let jet = crate::essais::Jetable::nouveau("clamav-programmes");
        let b = jet.join("base");
        std::fs::create_dir(&b).unwrap();
        let marque = b"marque-ep!";
        // PE : section à RVA 0x1000, à 0x200 du fichier, 0x200 octets ; point d'entrée à RVA 0x11F0, soit 0x3F0.
        let mut pe = crate::pe::essais::pe(&crate::pe::essais::Fabrique::default());
        pe[0x68..0x6C].copy_from_slice(&0x11F0u32.to_le_bytes());
        pe[0x3F0..0x3F0 + marque.len()].copy_from_slice(marque);
        let section = Empreintes::de(&pe[0x200..0x400]);
        // ELF : PT_LOAD de tout le fichier à 0x400000 ; .text (S1) à 0x180 ; point d'entrée 0x400180.
        let mut elf = crate::analyse::elf::essais::elf64(5, false, 0x40_0180, b"");
        elf[0x180..0x180 + marque.len()].copy_from_slice(marque);
        let m = hex(marque);
        let ndb = format!(
            "Essai.PeEp-1:1:EP+0:{m}\nEssai.PeS0-1:1:S0+496:{m}\nEssai.ElfEp-1:6:EP+0:{m}\nEssai.ElfS1-1:6:S1+0:{m}\n\
             Essai.PeLoin-1:1:EP+1:{m}\nEssai.ElfS2-1:6:S2+0:{m}\n"
        );
        std::fs::write(b.join("essai.ndb"), ndb).unwrap();
        std::fs::write(
            b.join("essai.mdb"),
            format!("512:{}:Essai.Section-1\n", hex(&section.md5)),
        )
        .unwrap();
        let base = charger_dans(&b, COMPLETE, &regles(&b)).unwrap();
        let f = jet.join("f");
        std::fs::create_dir(&f).unwrap();
        let mut n = noms(&examiner_octets(&base, &f, "p.exe", &pe))
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        n.sort();
        assert_eq!(n, ["Essai.PeEp-1", "Essai.PeS0-1", "Essai.Section-1"]);
        let mut n = noms(&examiner_octets(&base, &f, "p", &elf))
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        n.sort();
        assert_eq!(n, ["Essai.ElfEp-1", "Essai.ElfS1-1"]);
    }

    #[cfg(unix)]
    #[test]
    fn base_non_fiable_non_lue() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let jet = crate::essais::Jetable::nouveau("clamav-confiance");
        let b = jet.join("base");
        std::fs::create_dir(&b).unwrap();
        poser_base(&b);
        let r = regles(&b);
        assert!(charger_dans(&b, COMPLETE, &r).is_ok());
        let non_fiable = |r: &Regles| match charger_dans(&b, COMPLETE, r) {
            Err(Refus::NonFiable(chemin, pourquoi)) => (chemin, pourquoi),
            Err(autre) => panic!("{autre}"),
            Ok(_) => panic!("base lue"),
        };
        // À un compte qui n'est ni root ni le service : le dossier d'abord.
        let mut autre = regles(&b);
        autre.proprietaires.retain(|&p| p != crate::socle::uid());
        if !autre.proprietaires.contains(&std::fs::metadata(&b).unwrap().uid()) {
            assert_eq!(non_fiable(&autre).0, std::fs::canonicalize(&b).unwrap());
        }
        // Au compte qui lit.
        let mut lecteur = regles(&b);
        lecteur.comptes.push(std::fs::metadata(&b).unwrap().uid());
        non_fiable(&lecteur);
        // Le compte est membre du groupe des fichiers (clamav).
        let mut groupe = regles(&b);
        groupe
            .groupes
            .push(std::fs::metadata(b.join("main.cvd")).unwrap().gid());
        non_fiable(&groupe);
        // Écrivable par lui (ACL).
        let mut acl = regles(&b);
        acl.ecrivable = |_| true;
        non_fiable(&acl);
        // Un fichier écrivable par tous.
        let main = b.join("main.cvd");
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o646)).unwrap();
        let (chemin, pourquoi) = non_fiable(&r);
        assert_eq!(chemin, std::fs::canonicalize(&b).unwrap().join("main.cvd"));
        assert!(pourquoi.contains(tr!("tous", "everyone")), "{pourquoi}");
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o644)).unwrap();
        // Un lien à la place d'une base.
        std::os::unix::fs::symlink(&main, b.join("lien.cvd")).unwrap();
        assert!(non_fiable(&r).1.contains(tr!("lien", "link")));
        std::fs::remove_file(b.join("lien.cvd")).unwrap();
        // Le dossier écrivable par tous, même collant.
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o1777)).unwrap();
        non_fiable(&r);
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(charger_dans(&b, COMPLETE, &r).is_ok());
    }

    /// Vide, absente, illisible : jamais une base vide prise pour une base saine.
    #[test]
    fn base_vide_ou_absente() {
        let jet = crate::essais::Jetable::nouveau("clamav-vide");
        let b = jet.join("base");
        std::fs::create_dir(&b).unwrap();
        std::fs::write(b.join("COPYING"), b"licence").unwrap();
        assert_eq!(
            charger_dans(&b, COMPLETE, &regles(&b)).err(),
            Some(Refus::Vide(Vec::new()))
        );
        // Les bases écartées sont dites : sans elles, le refus ne dirait pas pourquoi rien n'est lu.
        std::fs::write(b.join("abime.cld"), b"pas une base").unwrap();
        let Some(Refus::Vide(ecartes)) = charger_dans(&b, COMPLETE, &regles(&b)).err() else {
            panic!("une base sans signatures lisibles est refusée");
        };
        assert_eq!(
            ecartes,
            vec![("abime.cld".to_owned(), raison_cvd(&cvd::Erreur::EnTete))]
        );
        assert!(Refus::Vide(ecartes).to_string().contains("abime.cld"));
        let absent = jet.join("absent");
        assert!(matches!(
            charger_dans(&absent, COMPLETE, &regles(&b)),
            Err(Refus::Illisible(..))
        ));
        for r in [
            Refus::Absente,
            Refus::Administrateur,
            Refus::TropGrosse,
            Refus::Vide(Vec::new()),
        ] {
            assert_ne!(r.to_string(), "");
        }
    }

    /// En administrateur (root, ou root de l'espace de noms de verifier.sh), rien n'est lu ni examiné (P22).
    #[test]
    fn rien_en_administrateur() {
        if !administrateur() {
            return crate::essais::saute("pas en administrateur : la garde ne se déclenche pas ici");
        }
        assert!(matches!(charger(COMPLETE), Err(Refus::Administrateur)));
        let jet = crate::essais::Jetable::nouveau("clamav-admin");
        let b = jet.join("base");
        std::fs::create_dir(&b).unwrap();
        poser_base(&b);
        let base = charger_dans(&b, COMPLETE, &regles(&b)).unwrap();
        let f = jet.join("eicar.com");
        std::fs::write(&f, eicar()).unwrap();
        assert_eq!(examiner(&f, &base, Duration::from_secs(60)), Err(()));
    }

    #[cfg(unix)]
    #[test]
    fn groupes_et_comptes_du_service() {
        let status =
            "Name:\tvanguard\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t992 998 1000 \n";
        assert_eq!(
            groupes_du_processus(status),
            Some(vec![1000, 1000, 1000, 1000, 992, 998, 1000])
        );
        assert_eq!(groupes_du_processus("Gid:\t1000\n"), None, "sans Groups, illisible");
        assert_eq!(groupes_du_processus("Gid:\tx\nGroups:\t\n"), None);
        let passwd = "root:x:0:0::/root:/bin/bash\nclamav:x:64:64:Clam AntiVirus:/:/usr/bin/nologin\n\
                      alice:x:1000:1000::/home/alice:/bin/bash\nclamupdate:x:977:977::/var/lib/clamav:/sbin/nologin\n";
        assert_eq!(comptes_du_service(passwd), [64, 977]);
    }

    /// Le banc de la vraie base de cet ordinateur (lecture seule, rien gardé) : temps de chargement, mémoire, ce qui
    /// est appliqué et ce qui ne l'est pas, et la marque d'essai EICAR. À la main :
    /// `cargo test -q -- --ignored --exact protection::clamav::base::tests::banc_de_la_vraie_base --nocapture`
    #[test]
    #[ignore = "à la main : lit la vraie base ClamAV (lecture seule)"]
    fn banc_de_la_vraie_base() {
        for options in [
            Options {
                mode: Mode::Empreintes,
                pua: false,
            },
            COMPLETE,
        ] {
            let debut = Instant::now();
            let base = match charger(options) {
                Ok(b) => b,
                Err(e) => return crate::essais::saute(&e.to_string()),
            };
            let duree = debut.elapsed();
            let s = &base.signatures;
            println!(
                "{:?} : {:.1} s, {} appliquées, {:?} empreintes/blanches, {} approchées, {} hors liste",
                options.mode,
                duree.as_secs_f64(),
                s.nombre(),
                s.empreintes(),
                s.comptes.approchees,
                s.comptes.hors_liste
            );
            for src in &base.sources {
                println!("  {} : {:?}", src.nom, src.en_tete);
            }
            println!("  écartés : {:?} ; à part : {:?}", base.ecartes, base.a_part);
            println!("  non lues : {:?}", s.comptes.non_lues);
            if let Ok(t) = std::fs::read_to_string("/proc/self/status") {
                for l in t.lines().filter(|l| l.starts_with("VmHWM") || l.starts_with("VmRSS")) {
                    println!("  {l}");
                }
            }
            let jet = crate::essais::Jetable::nouveau("clamav-banc");
            let debut = Instant::now();
            let c = examiner_octets(&base, &jet, "eicar.com", &eicar());
            println!("  EICAR : {:?} en {:?}", c.trouvailles, debut.elapsed());
            assert!(!c.trouvailles.is_empty(), "la vraie base a une signature d'essai EICAR");
            println!("  liste binaire : {} empreintes", s.liste_sha256().len() / 32);
        }
    }
}
