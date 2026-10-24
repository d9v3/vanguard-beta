//! Manifeste de la clé VANGUARD : l'empreinte BLAKE3 de chaque fichier de la partition VANGUARD, écrite au déploiement
//! (outils/deployer.sh lance `vanguard manifeste --ecrire`) et gardée sur l'ordinateur du propriétaire, pas sur la clé
//! (qui change la clé changerait aussi un manifeste qui y vivrait ; sa présence dit aussi « on est chez le
//! propriétaire »). Au bilan chez lui, la clé revenue de chez quelqu'un est comparée : fichiers ajoutés (un
//! autorun.inf planté), modifiés (un programme remplacé), disparus. La lecture seule arrête Windows, pas un Linux
//! démarré en direct sur l'ordinateur de l'ami. Ce qui change normalement n'y entre pas : donnees/. Les images ISO/
//! (leur taille : plusieurs Gio chacune) et le menu ventoy/ (son empreinte) y entrent : un ventoy.json réécrit (une
//! image démarrée d'office, un script injecté dans une image par ailleurs signée) ou une image plantée s'y voient.
//! outils/images-cle.sh, qui les met à jour chez le propriétaire après avoir vérifié leur signature, redit à la
//! référence ce qu'il a posé (`vanguard manifeste --images`) : seulement les images qu'il vient de copier et le menu
//! qu'il vient d'écrire, jamais une image qu'il n'a pas posée. Une référence d'avant (`Manifeste::images` faux) les
//! laisse de côté, comme alors, jusqu'au prochain déploiement.
//!
//! Une clé dont le jeton est celui d'une référence d'ici, mais dont l'identifiant de volume ne correspond plus à
//! aucune n'est pas « une autre clé » : quatre octets du secteur d'amorce changés suffisaient à faire sauter la
//! comparaison, qui ne disait plus qu'une information. Elle est signalée comme une possible altération (élevé). Une
//! clé VANGUARD sans référence, là où d'autres clés ont la leur, reste un avertissement moyen : changer aussi le
//! jeton (un simple fichier texte) la fait passer pour une autre clé, et rien n'a été comparé.
//!
//! Et « Vérifier Vanguard lui-même » : version, date de compilation (celle du dernier commit, jamais l'horloge : un
//! même code donne le même programme), empreinte SHA-256 du programme par l'outil du système, comme pour un fichier
//! téléchargé, à comparer à la page de la version ; sur la clé du propriétaire, au manifeste. Une barrière, pas un
//! coffre : qui remplace le programme peut mentir sur tout cela ; c'est pourquoi la référence reste chez le
//! propriétaire et l'empreinte est publiée ailleurs.

use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::machine::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::*;

const CAT: &str = "Clé USB";
const FORMAT: &str = "vanguard-manifeste";
/// Dossiers de la clé qui changent sans que personne n'y touche, et ceux que les systèmes y posent eux-mêmes.
const EXCLUS: &[&str] = &[
    "donnees",
    "System Volume Information",
    "$RECYCLE.BIN",
    ".Trashes",
    ".Spotlight-V100",
    ".fseventsd",
    ".TemporaryItems",
];
/// Au-delà, le fichier n'est pas lu : sa taille seulement (une image disque se lit en une minute).
const GROS: u64 = 64 << 20;
/// Une copie de Vanguard plus vieille que ça mérite une mise à jour.
const PERIME_JOURS: i64 = 180;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Entree {
    /// Chemin dans la clé, séparé par « / » quel que soit le système.
    chemin: String,
    taille: u64,
    /// Absente pour un gros fichier, comparé par sa taille.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blake3: Option<String>,
}

/// Les dossiers des images de secours (taille) et du menu de Ventoy (empreinte), relevés depuis la 0.86.
const IMAGES: [&str; 2] = ["ISO", "ventoy"];

#[derive(Serialize, Deserialize)]
struct Manifeste {
    format: String,
    version_vanguard: String,
    /// « AAAA-MM-JJ HH:MM » de l'écriture.
    date: String,
    fichiers: Vec<Entree>,
    /// ISO/ et ventoy/ relevés (`IMAGES`) ; faux dans une référence d'avant, qui les laissait de côté.
    #[serde(default)]
    images: bool,
    /// Le jeton de la clé décrite (`cles_connues`), depuis la 0.86 : seule une référence qui le porte prouve qu'une
    /// clé à ce jeton a déjà été comparée ici. Absent dans une référence d'avant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jeton: Option<String>,
}

/// Ce qui a changé sur la clé depuis le manifeste.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ecart {
    pub verifies: usize,
    pub nouveaux: Vec<String>,
    pub modifies: Vec<String>,
    pub disparus: Vec<String>,
    /// Les images ISO/ (par leur taille) et le menu ventoy/ ont été comparés (référence de la 0.86 ou d'après).
    pub images: bool,
}

impl Ecart {
    pub fn vide(&self) -> bool {
        self.nouveaux.is_empty() && self.modifies.is_empty() && self.disparus.is_empty()
    }
}

/// L'unique référence des 0.59 : une seule clé connue, et une deuxième clé VANGUARD paraissait tout entière changée.
const ANCIENNE_REFERENCE: &str = "manifeste-cle.json";
/// Une référence par clé depuis la 0.60, nommée par l'identifiant du volume.
const REFERENCES: &str = "manifestes-cle";

/// L'identifiant du système de fichiers de la clé (UUID que le formatage lui donne, « 1A2B-3C4D » en exFAT), d'après
/// le périphérique monté et /dev/disk/by-uuid. Sous Windows et macOS, aucun : le déploiement, qui écrit les
/// références, se fait sous Linux ; l'ancienne référence unique y sert encore.
#[cfg(target_os = "linux")]
pub(crate) fn identifiant_volume(racine: &Path) -> Option<String> {
    let (source, _) = crate::protection::cle::montage(racine)?;
    let peripherique = std::fs::canonicalize(&source).ok()?;
    let id = std::fs::read_dir("/dev/disk/by-uuid")
        .ok()?
        .flatten()
        .find(|e| std::fs::canonicalize(e.path()).ok().as_ref() == Some(&peripherique))?
        .file_name();
    nom_de_reference(&id.to_string_lossy())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn identifiant_volume(_racine: &Path) -> Option<String> {
    None
}

/// L'identifiant gardé tel quel s'il ne contient que des lettres, des chiffres et des tirets : il devient un nom de
/// fichier, et une étiquette choisie par n'importe qui ne doit pas sortir du dossier des références.
#[cfg(any(target_os = "linux", test))]
fn nom_de_reference(id: &str) -> Option<String> {
    let id = id.trim();
    (!id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .then(|| id.to_string())
}

/// Les références de clé déjà écrites dans `base` (le dossier de Vanguard).
fn fichiers_de_reference(base: &Path) -> impl Iterator<Item = PathBuf> {
    std::fs::read_dir(base.join(REFERENCES))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
}

fn references_par_cle(base: &Path) -> usize {
    fichiers_de_reference(base).count()
}

/// Cet ordinateur a déjà déployé au moins une clé (une référence par clé, ou l'unique des 0.59) : une clé VANGUARD
/// sans référence n'y est plus « le premier usage ».
pub(crate) fn a_des_references(base: &Path) -> bool {
    references_par_cle(base) > 0 || base.join(ANCIENNE_REFERENCE).is_file()
}

/// Une référence d'ici porte ce jeton : une clé à ce jeton y a déjà été comparée.
fn jeton_a_reference(base: &Path, jeton: &str) -> bool {
    fichiers_de_reference(base).any(|r| lire(&r).is_ok_and(|m| m.jeton.as_deref() == Some(jeton)))
}

/// L'identifiant de volume `id` a été lu, n'a pas de référence ici, et le jeton de la clé est celui d'une référence
/// d'ici : le numéro de série a été changé sur la clé déjà comparée. « Connue » ne suffit pas à le dire : toute clé
/// dont Vanguard écrit le carnet le devient, même déployée sur un autre ordinateur ; et un identifiant illisible
/// (udev en retard au branchement) n'est pas un identifiant changé.
fn identifiant_change_dans(base: &Path, id: Option<&str>, jeton: Option<&str>) -> bool {
    id.is_some() && reference_lue(base, id).is_none() && jeton.is_some_and(|j| jeton_a_reference(base, j))
}

fn identifiant_change(base: &Path, cle: &Path) -> bool {
    identifiant_change_dans(
        base,
        identifiant_volume(cle).as_deref(),
        crate::protection::cles_connues::jeton_de(cle).as_deref(),
    )
}

/// La référence de la clé `id` : la sienne ; sinon l'ancienne référence unique, tant qu'aucune clé n'a la sienne
/// (avant le premier déploiement en 0.60). `None` : cette clé n'a pas de référence ici.
fn reference_lue(base: &Path, id: Option<&str>) -> Option<PathBuf> {
    if let Some(id) = id {
        let propre = base.join(REFERENCES).join(format!("{id}.json"));
        if propre.is_file() {
            return Some(propre);
        }
    }
    let ancienne = base.join(ANCIENNE_REFERENCE);
    (ancienne.is_file() && (id.is_none() || references_par_cle(base) == 0)).then_some(ancienne)
}

/// Où écrire la référence de la clé `id`.
fn reference_ecrite(base: &Path, id: Option<&str>) -> PathBuf {
    match id {
        Some(id) => base.join(REFERENCES).join(format!("{id}.json")),
        None => base.join(ANCIENNE_REFERENCE),
    }
}

/// La référence de la clé branchée à `racine`, sur l'ordinateur du propriétaire.
fn reference(racine: &Path) -> Option<PathBuf> {
    reference_lue(&crate::socle::dossier_local(), identifiant_volume(racine).as_deref())
}

/// Un chemin de la clé qui ne compte pas : dossier exclu, corbeille d'un gestionnaire de fichiers (« .Trash-1000 »,
/// créée dès qu'on supprime quelque chose sur la clé), fichiers que macOS pose sur une clé (« ._x », .DS_Store), copie
/// d'image en cours d'images-cle.sh (« ISO/.nom.iso.part », que Ventoy ne montre jamais).
fn exclu(relatif: &str) -> bool {
    let premier = relatif.split('/').next().unwrap_or_default();
    let nom = relatif.rsplit('/').next().unwrap_or_default();
    EXCLUS.contains(&premier)
        || premier.starts_with(".Trash-")
        || nom.starts_with("._")
        || nom == ".DS_Store"
        || (premier == "ISO"
            && nom.starts_with('.')
            && Path::new(nom)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("part")))
}

/// Un chemin des images de secours ou du menu de Ventoy (`IMAGES`).
fn d_images(relatif: &str) -> bool {
    IMAGES.contains(&relatif.split('/').next().unwrap_or_default())
}

/// Les fichiers de la clé (chemin relatif, taille), sans les liens ni les dossiers exclus, triés ; sans ISO/ ni
/// ventoy/ pour une référence d'avant qui ne les relevait pas.
fn parcourir(racine: &Path, avec_images: bool) -> Vec<(String, u64)> {
    let mut liste = parcourir_tout(racine);
    if !avec_images {
        liste.retain(|(c, _)| !d_images(c));
    }
    liste
}

fn parcourir_tout(racine: &Path) -> Vec<(String, u64)> {
    fn descendre(dossier: &Path, prefixe: &str, liste: &mut Vec<(String, u64)>) {
        for e in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
            let nom = e.file_name().to_string_lossy().into_owned();
            let relatif = if prefixe.is_empty() {
                nom
            } else {
                format!("{prefixe}/{nom}")
            };
            if exclu(&relatif) {
                continue;
            }
            let Ok(meta) = e.metadata() else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                descendre(&e.path(), &relatif, liste);
            } else if meta.is_file() {
                liste.push((relatif, meta.len()));
            }
        }
    }
    let mut liste = Vec::new();
    descendre(racine, "", &mut liste);
    liste.sort();
    liste
}

/// L'empreinte BLAKE3 d'un fichier, lu par morceaux.
fn empreinte(chemin: &Path) -> Option<String> {
    let mut fichier = std::fs::File::open(chemin).ok()?;
    let mut hacheur = blake3::Hasher::new();
    std::io::copy(&mut fichier, &mut hacheur).ok()?;
    Some(hacheur.finalize().to_hex().to_string())
}

fn entree(racine: &Path, chemin: String, taille: u64, gros: u64) -> Entree {
    Entree {
        blake3: (taille < gros).then(|| empreinte(&racine.join(&chemin))).flatten(),
        chemin,
        taille,
    }
}

fn relever(racine: &Path, gros: u64) -> Vec<Entree> {
    parcourir(racine, true)
        .into_iter()
        .map(|(chemin, taille)| entree(racine, chemin, taille, gros))
        .collect()
}

fn ecrire_dans(racine: &Path, reference: &Path, gros: u64) -> Result<usize, String> {
    let fichiers = relever(racine, gros);
    let manifeste = Manifeste {
        format: FORMAT.to_string(),
        version_vanguard: env!("CARGO_PKG_VERSION").to_string(),
        date: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        fichiers,
        images: true,
        jeton: crate::protection::cles_connues::jeton_de(racine),
    };
    enregistrer(reference, &manifeste).map_err(|e| e.to_string())?;
    Ok(manifeste.fichiers.len())
}

fn enregistrer(reference: &Path, manifeste: &Manifeste) -> std::io::Result<()> {
    let texte = serde_json::to_string_pretty(manifeste).map_err(std::io::Error::other)?;
    crate::socle::ecrire_atomique(reference, texte)
}

/// Redit à la référence les images et le menu qu'outils/images-cle.sh vient de poser sur la clé, après avoir vérifié
/// leur signature (`nouvelles` : les noms des images copiées). Le menu ventoy/ est repris tel qu'il est (images-cle.sh
/// vient de le réécrire d'après ISO/) ; dans ISO/, une image déjà relevée et de même taille reste, une image copiée
/// entre, une image retirée sort, et toute autre reste hors de la référence : le bilan la dira nouvelle. Rend le
/// nombre d'images relevées.
fn rafraichir_images_dans(racine: &Path, reference: &Path, nouvelles: &[String], gros: u64) -> std::io::Result<usize> {
    let mut m = lire(reference).map_err(std::io::Error::other)?;
    if !m.images {
        return Err(std::io::Error::other(tr!(
            "référence écrite avant que la clé relève ses images : redéploie la clé (outils/deployer.sh)",
            "reference written before the key recorded its images: redeploy the key (outils/deployer.sh)"
        )));
    }
    let avant: Vec<Entree> = m.fichiers.iter().filter(|e| d_images(&e.chemin)).cloned().collect();
    m.fichiers.retain(|e| !d_images(&e.chemin));
    let mut images = 0;
    for (chemin, taille) in parcourir(racine, true).into_iter().filter(|(c, _)| d_images(c)) {
        let nom = chemin.rsplit('/').next().unwrap_or_default();
        let e = if chemin.starts_with("ventoy/") || nouvelles.iter().any(|n| n == nom) {
            entree(racine, chemin, taille, gros)
        } else if let Some(e) = avant.iter().find(|e| e.chemin == chemin && e.taille == taille) {
            e.clone()
        } else {
            continue;
        };
        images += usize::from(e.chemin.starts_with("ISO/"));
        m.fichiers.push(e);
    }
    m.fichiers.sort_by(|a, b| a.chemin.cmp(&b.chemin));
    m.date = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    enregistrer(reference, &m)?;
    Ok(images)
}

/// `rafraichir_images_dans` pour la clé `racine` et sa référence sur cet ordinateur.
pub fn rafraichir_images(racine: &Path, nouvelles: &[String]) -> std::io::Result<usize> {
    let reference = reference(racine)
        .ok_or_else(|| std::io::Error::other(tr!("aucune référence pour cette clé", "no reference for this key")))?;
    rafraichir_images_dans(racine, &reference, nouvelles, GROS)
}

/// Écrit le manifeste de la clé `racine` dans sa référence sur cet ordinateur ; rend le nombre de fichiers et la
/// référence. L'ancienne référence unique part dès qu'une clé a la sienne : elle décrivait la clé déployée jusque-là,
/// et gardée, elle servirait de référence à une autre.
pub fn ecrire(racine: &Path) -> Result<(usize, PathBuf), String> {
    let base = crate::socle::dossier_local();
    let id = identifiant_volume(racine);
    let chemin = reference_ecrite(&base, id.as_deref());
    let n = ecrire_dans(racine, &chemin, GROS)?;
    if id.is_some() {
        let _ = std::fs::remove_file(base.join(ANCIENNE_REFERENCE));
    }
    // Déployée ici, la clé est reconnue de cet ordinateur, et son carnet tel qu'il est devient la référence.
    crate::protection::cles_connues::noter(racine);
    Ok((n, chemin))
}

fn lire(reference: &Path) -> Result<Manifeste, String> {
    let texte = crate::socle::lire_texte_ordinaire(reference, 64 << 20).map_err(|e| e.to_string())?;
    let mut valeur: serde_json::Value =
        serde_json::from_str(texte.trim_start_matches('\u{feff}')).map_err(|e| e.to_string())?;
    // Manifeste écrit avant le changement de nom (`passage`).
    crate::passage::reprendre_format(&mut valeur, FORMAT);
    let m: Manifeste = serde_json::from_value(valeur).map_err(|e| e.to_string())?;
    if m.format != FORMAT {
        return Err(tr!("ce n'est pas un manifeste Vanguard", "this is not a Vanguard manifest").to_string());
    }
    Ok(m)
}

fn comparer_avec(racine: &Path, manifeste: &Manifeste, gros: u64) -> Ecart {
    let mut ecart = Ecart {
        images: manifeste.images,
        ..Ecart::default()
    };
    let presents = parcourir(racine, manifeste.images);
    for (chemin, taille) in &presents {
        match manifeste.fichiers.iter().find(|e| e.chemin == *chemin) {
            None => ecart.nouveaux.push(chemin.clone()),
            Some(attendu) => {
                let pareil = attendu.taille == *taille
                    && match &attendu.blake3 {
                        Some(h) if *taille < gros => empreinte(&racine.join(chemin)).as_deref() == Some(h.as_str()),
                        _ => true,
                    };
                if pareil {
                    ecart.verifies += 1;
                } else {
                    ecart.modifies.push(chemin.clone());
                }
            }
        }
    }
    for attendu in manifeste
        .fichiers
        .iter()
        .filter(|e| manifeste.images || !d_images(&e.chemin))
    {
        if !presents.iter().any(|(c, _)| *c == attendu.chemin) {
            ecart.disparus.push(attendu.chemin.clone());
        }
    }
    ecart
}

/// Compare la clé `racine` à sa référence sur cet ordinateur.
pub fn comparer(racine: &Path) -> Result<Ecart, String> {
    let reference = reference(racine)
        .ok_or_else(|| tr!("aucune référence pour cette clé", "no reference for this key").to_string())?;
    Ok(comparer_avec(racine, &lire(&reference)?, GROS))
}

/// Les changements, en une liste courte : « autorun.inf (nouveau), Windows/vanguard.exe (modifié)… ».
fn resume_ecart(ecart: &Ecart) -> String {
    let (n, m, d) = (
        tr!("nouveau", "new"),
        tr!("modifié", "modified"),
        tr!("disparu", "missing"),
    );
    let tous: Vec<String> = ecart
        .nouveaux
        .iter()
        .map(|c| format!("{} ({n})", affichable(c)))
        .chain(ecart.modifies.iter().map(|c| format!("{} ({m})", affichable(c))))
        .chain(ecart.disparus.iter().map(|c| format!("{} ({d})", affichable(c))))
        .collect();
    resume(&tous, 5, ", ")
}

/// Au bilan, chez le propriétaire (la référence existe) avec la clé branchée.
pub fn constat() -> Option<Constat> {
    let cle = crate::reseau::cle_usb()?;
    let base = crate::socle::dossier_local();
    if reference(&cle).is_none() {
        let sans = if identifiant_change(&base, &cle) {
            SansReference::IdentifiantChange
        } else if identifiant_volume(&cle).is_none() {
            SansReference::IdentifiantIllisible
        } else {
            SansReference::Inconnue
        };
        return sans_reference(a_des_references(&base), sans);
    }
    Some(match comparer(&cle) {
        Err(e) => impossible(CAT, &trf!("manifeste de la clé illisible : {e}", "key manifest unreadable: {e}")),
        Ok(ecart) if ecart.vide() && ecart.images => ok(
            CAT,
            trf!(
                "La clé VANGUARD n'a pas changé depuis son écriture ({} fichiers vérifiés, menu Ventoy compris, images ISO par leur taille ; données mises à part).",
                "The VANGUARD key has not changed since it was written ({} files checked, Ventoy menu included, ISO images by their size; data aside).",
                ecart.verifies
            ),
        ),
        Ok(ecart) if ecart.vide() => ok(
            CAT,
            trf!(
                "La clé VANGUARD n'a pas changé depuis son écriture ({} fichiers vérifiés ; données, images ISO et menu Ventoy mis à part : redéployez-la pour qu'ils le soient).",
                "The VANGUARD key has not changed since it was written ({} files checked; data, ISO images and Ventoy menu aside: redeploy it so they are).",
                ecart.verifies
            ),
        ),
        Ok(ecart) => alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "La clé VANGUARD a changé depuis son écriture : {}. Un fichier ajouté ou remplacé sur une clé qui a voyagé peut être un piège (autorun, programme remplacé).",
                "The VANGUARD key has changed since it was written: {}. A file added or replaced on a key that traveled may be a trap (autorun, replaced program).",
                resume_ecart(&ecart)
            ),
        )
        .manuel(
            tr!(
                "Ne lancez plus Vanguard depuis cette clé avant de l'avoir réécrite : chez vous, outils/deployer.sh la remet à neuf",
                "Do not run Vanguard from this key until it is rewritten: at home, outils/deployer.sh restores it"
            ),
            &[],
        ),
    })
}

/// Pourquoi une clé VANGUARD n'a pas de référence ici.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SansReference {
    /// Son jeton est celui d'une référence d'ici, sous un autre identifiant de volume (`identifiant_change`).
    IdentifiantChange,
    /// Identifiant de volume pas lu (udev en retard, montage non résolu ; toujours sous Windows et macOS).
    IdentifiantIllisible,
    /// Ni son identifiant ni son jeton n'ont de référence ici.
    Inconnue,
}

/// Une clé VANGUARD sans référence ici, chez le propriétaire (`d_autres` : d'autres clés y ont la leur). Son jeton
/// dans une référence d'ici sous un autre identifiant : la même clé, dont l'identifiant de volume a changé sans
/// reformatage, le geste qui fait sauter la comparaison (quatre octets du secteur d'amorce) ; élevé. Inconnue : une
/// autre clé que celles déployées ici, ou celle-ci dont on a changé aussi le jeton (un fichier texte) ; rien n'a été
/// comparé, et une clé qui a voyagé ne se lance pas à l'aveugle ; moyen. Identifiant illisible : rien ne prouve
/// quoi que ce soit, information.
fn sans_reference(d_autres: bool, sans: SansReference) -> Option<Constat> {
    if !d_autres {
        return None;
    }
    let (niveau, message, consigne) = match sans {
        SansReference::IdentifiantChange => (
            Niveau::Eleve,
            tr!(
                "Cette clé VANGUARD porte le jeton d'une clé déployée ici, mais son identifiant de volume ne correspond plus à celui de son manifeste : il a été changé sans reformater la clé. C'est ce qu'il faut pour que son contenu ne soit plus comparé : possible piège, rien n'a été vérifié.",
                "This VANGUARD key carries the token of a key deployed here, but its volume identifier no longer matches its manifest: it was changed without reformatting the key. That is what it takes for its content to no longer be compared: possible trap, nothing was checked."
            ),
            tr!(
                "Ne lancez rien depuis cette clé ; chez vous, outils/deployer.sh la réécrit (et son manifeste). Clé recopiée sur une autre à dessein : la redéployer suffit",
                "Do not run anything from this key; at home, outils/deployer.sh rewrites it (and its manifest). Key copied onto another on purpose: redeploying it is enough"
            ),
        ),
        SansReference::Inconnue => (
            Niveau::Moyen,
            tr!(
                "Cette clé VANGUARD n'a pas de manifeste sur cet ordinateur : autre clé que celles déployées ici, ou clé dont le jeton et l'identifiant de volume ont été changés. Rien n'a été comparé : ne lancez rien depuis elle avant de l'avoir redéployée.",
                "This VANGUARD key has no manifest on this computer: a key other than those deployed here, or a key whose token and volume identifier were changed. Nothing was compared: do not run anything from it before redeploying it."
            ),
            tr!(
                "Redéployez-la avec outils/deployer.sh (il écrit son manifeste)",
                "Redeploy it with outils/deployer.sh (it writes its manifest)"
            ),
        ),
        SansReference::IdentifiantIllisible => (
            Niveau::Info,
            tr!(
                "L'identifiant de volume de cette clé VANGUARD n'a pas pu être lu : son manifeste n'a pas été trouvé, et son contenu n'a pas pu être comparé.",
                "The volume identifier of this VANGUARD key could not be read: its manifest was not found, and its content could not be compared."
            ),
            tr!(
                "Rebranchez-la et relancez le bilan ; sinon outils/deployer.sh écrit son manifeste en la mettant à jour",
                "Plug it in again and rerun the check-up; otherwise outils/deployer.sh writes its manifest when it updates the key"
            ),
        ),
    };
    Some(Constat {
        verifie: false,
        ..alerte(CAT, niveau, message).manuel(consigne, &[])
    })
}

// ───────────────────────────── Vérifier Vanguard lui-même ─────────────────────────────

/// Date du dernier commit compilé (build.rs), `None` hors d'un dépôt git.
pub fn date_compilation() -> Option<NaiveDate> {
    NaiveDate::parse_from_str(env!("VANGUARD_COMPILE"), "%Y-%m-%d").ok()
}

fn age_jours(aujourd_hui: NaiveDate) -> Option<i64> {
    date_compilation().map(|d| (aujourd_hui - d).num_days())
}

/// La ligne d'avertissement du menu quand cette copie a plus de six mois, sinon rien.
pub fn avertissement_perime() -> Option<String> {
    avertissement(age_jours(chrono::Local::now().date_naive())?)
}

fn avertissement(jours: i64) -> Option<String> {
    (jours >= PERIME_JOURS).then(|| {
        let mois = jours / 30;
        trf!(
            "Cette copie de Vanguard a {mois} mois : remettez la clé à jour chez vous.",
            "This copy of Vanguard is {mois} months old: update the key at home."
        )
    })
}

/// Le programme tel que lancé (sur la clé, même quand c'est sa copie temporaire qui tourne).
fn programme() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        crate::protection::cle::exe_d_origine()
    }
    #[cfg(windows)]
    {
        std::env::current_exe().ok()
    }
}

/// « vanguard verifier-moi » : version, date, empreinte SHA-256, et le manifeste sur la clé du propriétaire ; après
/// accord, l'historique signé des versions publiées. « vanguard verifier-moi <programme> » : une autre copie de
/// Vanguard (celle d'une autre clé, une version d'avant), par son empreinte et l'historique.
pub fn verifier_moi(autre: Option<&Path>) {
    if let Some(copie) = autre {
        verifier_une_copie(copie);
        return;
    }
    titre(tr!("Vérifier Vanguard lui-même", "Check Vanguard itself"));
    println!(
        "  {GRIS}{}{RESET}  {}",
        tr!("Version   ", "Version   "),
        env!("CARGO_PKG_VERSION")
    );
    let aujourd_hui = chrono::Local::now().date_naive();
    match (date_compilation(), age_jours(aujourd_hui)) {
        (Some(d), Some(jours)) => {
            let depuis = match jours {
                0 => tr!("aujourd'hui", "today").to_string(),
                1 => tr!("hier", "yesterday").to_string(),
                _ => trf!("il y a {jours} jours", "{jours} days ago"),
            };
            println!("  {GRIS}{}{RESET}  {d} ({depuis})", tr!("Compilé le", "Built on  "));
            if let Some(a) = avertissement(jours) {
                println!("  ⚠ {a}");
            }
        }
        _ => trp!(
            "  {GRIS}Compilé le{RESET}  inconnu (compilé hors d'un dépôt git)",
            "  {GRIS}Built on  {RESET}  unknown (built outside a git repository)"
        ),
    }
    let Some(exe) = programme() else {
        trp!(
            "  ✖ Impossible de savoir quel fichier est en train de tourner.",
            "  ✖ Could not tell which file is running."
        );
        return;
    };
    println!(
        "  {GRIS}{}{RESET}  {}",
        tr!("Programme ", "Program   "),
        chemin_affichable(&exe)
    );
    let sha256 =
        match crate::protection::telechargement::calculer(&exe, crate::protection::telechargement::Algo::Sha256) {
            Ok(h) => {
                println!("  {GRIS}SHA-256   {RESET}  {h}");
                Some(h)
            }
            Err(e) => {
                trp!("  ✖ Empreinte impossible ({e}).", "  ✖ Checksum impossible ({e}).");
                None
            }
        };
    if let Some(cle) = crate::reseau::cle_usb()
        && let Ok(relatif) = exe.strip_prefix(&cle)
    {
        let relatif = relatif.to_string_lossy().replace('\\', "/");
        let base = crate::socle::dossier_local();
        let identifiant_change = identifiant_change(&base, &cle);
        match reference(&cle).ok_or(()).and_then(|r| lire(&r).map_err(|_| ())) {
            // Reconnue mais sans référence : la comparaison a sauté parce que l'identifiant du volume a changé.
            Err(()) if identifiant_change => trp!(
                "  ✖ Jeton d'une clé déployée ici, mais son identifiant de volume ne correspond plus à son manifeste : rien n'a pu être comparé. Possible piège : ne lancez rien depuis elle, réécrivez-la (outils/deployer.sh).",
                "  ✖ Token of a key deployed here, but its volume identifier no longer matches its manifest: nothing could be compared. Possible trap: do not run anything from it, rewrite it (outils/deployer.sh)."
            ),
            // Chez le propriétaire (d'autres clés ont leur référence) : une clé sans la sienne n'est pas « hors de
            // chez lui », c'est une clé à redéployer avant de s'en servir.
            Err(()) if a_des_references(&base) => trp!(
                "  ⚠ Pas de manifeste ici pour cette clé, alors que d'autres clés y ont le leur : autre clé, ou jeton et identifiant changés. Rien n'a été comparé : ne lancez rien depuis elle avant de l'avoir redéployée.",
                "  ⚠ No manifest here for this key, while other keys have theirs: another key, or token and identifier changed. Nothing was compared: do not run anything from it before redeploying it."
            ),
            Err(()) => trp!(
                "  {GRIS}Lancé depuis la clé, hors de l'ordinateur du propriétaire : pas de manifeste à comparer.{RESET}",
                "  {GRIS}Started from the key, away from the owner's computer: no manifest to compare.{RESET}"
            ),
            Ok(m) => match m.fichiers.iter().find(|e| e.chemin == relatif) {
                Some(e) if e.blake3.is_some() && e.blake3 == empreinte(&exe) => trp!(
                    "  {VERT}✔{RESET} Identique au manifeste de la clé écrit le {}.",
                    "  {VERT}✔{RESET} Identical to the key manifest written on {}.",
                    m.date
                ),
                Some(_) => trp!(
                    "  ✖ DIFFÈRE du manifeste écrit le {} : ce n'est pas le programme posé sur la clé. Réécrivez la clé (outils/deployer.sh) avant de vous en servir.",
                    "  ✖ DIFFERS from the manifest written on {}: this is not the program put on the key. Rewrite the key (outils/deployer.sh) before using it.",
                    m.date
                ),
                None => trp!(
                    "  ⚠ Absent du manifeste de la clé : ce fichier n'y était pas quand elle a été écrite.",
                    "  ⚠ Missing from the key manifest: this file was not there when it was written."
                ),
            },
        }
    }
    if let Some(h) = sha256 {
        comparer_a_l_historique(&h);
    }
    println!();
    for ligne in envelopper(
        tr!(
            "Comparez l'empreinte SHA-256 à celle de la page de la version de Vanguard, ou à celle que vous a donnée la personne qui vous a remis le programme. Si elles diffèrent, ne l'utilisez pas.",
            "Compare the SHA-256 checksum with the one on Vanguard's release page, or the one given by the person who handed you the program. If they differ, do not use it."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
}

/// Une autre copie de Vanguard, par son empreinte SHA-256 et l'historique signé des versions publiées.
fn verifier_une_copie(copie: &Path) {
    titre(tr!("Vérifier une copie de Vanguard", "Check a copy of Vanguard"));
    println!(
        "  {GRIS}{}{RESET}  {}",
        tr!("Programme ", "Program   "),
        chemin_affichable(copie)
    );
    match crate::protection::telechargement::calculer(copie, crate::protection::telechargement::Algo::Sha256) {
        Ok(h) => {
            println!("  {GRIS}SHA-256   {RESET}  {h}");
            comparer_a_l_historique(&h);
        }
        Err(e) => trp!("  ✖ Empreinte impossible ({e}).", "  ✖ Checksum impossible ({e})."),
    }
}

/// L'empreinte comparée à l'historique signé des versions publiées (GitHub), après accord : le fichier entier est
/// téléchargé, rien de cet ordinateur ni l'empreinte cherchée ne part. Absente, ou l'historique inaccessible : c'est
/// dit, jamais compté comme vérifié.
fn comparer_a_l_historique(hex: &str) {
    let Some(sha256) = (hex.len() == 64)
        .then(|| {
            let mut o = [0u8; 32];
            for (i, c) in o.iter_mut().enumerate() {
                *c = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
            }
            Some(o)
        })
        .flatten()
    else {
        return;
    };
    if crate::parametres::hors_ligne() {
        trp!(
            "  {GRIS}Historique signé des versions : non comparé (travail sans Internet).{RESET}",
            "  {GRIS}Signed version history: not compared (offline mode).{RESET}"
        );
        return;
    }
    // Sans terminal (script, tâche planifiée, entrée vide), demander lirait la fin de l'entrée et quitterait le
    // programme : l'avertissement final (« Si elles diffèrent, ne l'utilise pas ») ne s'afficherait jamais.
    if !std::io::IsTerminal::is_terminal(&std::io::stdin())
        || !demander(tr!(
        "  Comparer à l'historique signé des versions publiées, sur GitHub (rien de cet ordinateur n'est envoyé) ? [o/N] : ",
        "  Compare with the signed history of published versions, on GitHub (nothing from this computer is sent)? [y/N]: "
    ))
    .oui()
    {
        trp!(
            "  {GRIS}Historique signé des versions : non comparé.{RESET}",
            "  {GRIS}Signed version history: not compared.{RESET}"
        );
        return;
    }
    match crate::mise_a_jour::version_signee(&sha256) {
        Ok(Some((version, systeme))) => trp!(
            "  {VERT}✔{RESET} Version {version} publiée et signée par l'auteur ({systeme}).",
            "  {VERT}✔{RESET} Version {version} published and signed by the author ({systeme})."
        ),
        Ok(None) => trp!(
            "  ⚠ Absente de l'historique signé : une version intermédiaire, une version d'avant l'historique (0.84 et plus anciennes), ou un programme changé. Ne vous en servez que si vous savez d'où il vient.",
            "  ⚠ Missing from the signed history: an intermediate version, a version older than the history (0.84 and earlier), or a changed program. Only use it if you know where it comes from."
        ),
        Err(e) => trp!(
            "  {GRIS}Historique signé des versions : non vérifié ({e}).{RESET}",
            "  {GRIS}Signed version history: not checked ({e}).{RESET}"
        ),
    }
}

/// « vanguard manifeste [--ecrire DOSSIER | --images DOSSIER --image NOM…] » : écrit la référence (déploiement),
/// y redit les images posées par outils/images-cle.sh, ou compare la clé branchée.
pub fn commande(ecrire_dossier: Option<&Path>, accepter: bool, images: Option<(&Path, &[String])>) {
    if accepter {
        crate::protection::cles_connues::accepter();
        return;
    }
    if let Some((racine, nouvelles)) = images {
        match rafraichir_images(racine, nouvelles) {
            Ok(n) => trp!(
                "Images de la clé redites à sa référence : {n} image(s) relevée(s), menu de Ventoy compris.",
                "Key images restated to its reference: {n} image(s) recorded, Ventoy menu included."
            ),
            Err(e) => {
                trp!("✖ Images non relevées : {e}", "✖ Images not recorded: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if let Some(racine) = ecrire_dossier {
        match ecrire(racine) {
            Ok((n, reference)) => trp!(
                "Manifeste de la clé écrit : {n} fichiers, référence {}",
                "Key manifest written: {n} files, reference {}",
                chemin_affichable(&reference)
            ),
            Err(e) => {
                trp!("✖ Manifeste non écrit : {e}", "✖ Manifest not written: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    titre(tr!("Manifeste de la clé", "Key manifest"));
    let Some(cle) = crate::reseau::cle_usb() else {
        trp!("  Clé VANGUARD non branchée.", "  VANGUARD key not plugged in.");
        return;
    };
    match comparer(&cle) {
        Err(e) => trp!(
            "  ✖ Pas de référence lisible sur cet ordinateur ({e}) : le manifeste s'écrit au déploiement, chez le propriétaire.",
            "  ✖ No readable reference on this computer ({e}): the manifest is written at deployment, on the owner's computer."
        ),
        Ok(ecart) if ecart.vide() => trp!(
            "  {VERT}✔{RESET} La clé n'a pas changé depuis son écriture ({} fichiers vérifiés).",
            "  {VERT}✔{RESET} The key has not changed since it was written ({} files checked).",
            ecart.verifies
        ),
        Ok(ecart) => {
            for (liste, mot) in [
                (&ecart.nouveaux, tr!("nouveau", "new")),
                (&ecart.modifies, tr!("modifié", "modified")),
                (&ecart.disparus, tr!("disparu", "missing")),
            ] {
                for c in liste {
                    println!("  {}✖{RESET} {} ({mot})", couleur(Niveau::Eleve), affichable(c));
                }
            }
            trp!(
                "  {} fichiers inchangés. Réécrivez la clé chez vous (outils/deployer.sh) avant de vous en servir.",
                "  {} files unchanged. Rewrite the key at home (outils/deployer.sh) before using it.",
                ecart.verifies
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier_jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-manifeste-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn exclusions() {
        assert!(exclu("donnees/appareils.json"));
        // Les images et le menu de Ventoy comptent (relevés à part) ; une copie d'image en cours, non.
        assert!(!exclu("ISO/omarchy.iso"));
        assert!(!exclu("ventoy/ventoy.json"));
        assert!(exclu("ISO/.omarchy.iso.part"));
        assert!(exclu("Linux/._vanguard"));
        assert!(exclu(".DS_Store"));
        assert!(exclu(".Trash-1000/files/vieux.txt"));
        assert!(exclu(".TemporaryItems/x"));
        assert!(!exclu("Linux/vanguard"));
        assert!(!exclu("autorun.inf"));
        assert!(!exclu("source/outils/images-cle.sh"));
    }

    /// Un PC hostile réécrit le menu de Ventoy (une image démarrée d'office) et plante une image : la clé « a
    /// changé ». Une référence d'avant les images les laisse de côté, comme alors.
    #[test]
    fn menu_ventoy_et_images_dans_le_manifeste() {
        let racine = dossier_jetable("ventoy");
        let reference = dossier_jetable("ventoy-ref")
            .join("manifestes-cle")
            .join("1A2B-3C4D.json");
        std::fs::create_dir_all(racine.join("ISO")).unwrap();
        std::fs::create_dir_all(racine.join("ventoy")).unwrap();
        std::fs::write(racine.join("autorun.sh"), b"#!/bin/sh").unwrap();
        std::fs::write(racine.join("ISO/systemrescue-12.0-amd64.iso"), b"0123456789abcdef").unwrap();
        std::fs::write(racine.join("ventoy/ventoy.json"), br#"{"control":[]}"#).unwrap();
        ecrire_dans(&racine, &reference, 10).unwrap();
        let m = lire(&reference).unwrap();
        assert!(comparer_avec(&racine, &m, 10).vide());
        std::fs::write(
            racine.join("ventoy/ventoy.json"),
            br#"{"control":[{"VTOY_DEFAULT_IMAGE":"/ISO/x.iso"}]}"#,
        )
        .unwrap();
        std::fs::write(racine.join("ISO/x.iso"), b"piege").unwrap();
        let ecart = comparer_avec(&racine, &m, 10);
        assert_eq!(
            (ecart.nouveaux, ecart.modifies),
            (vec!["ISO/x.iso".to_string()], vec!["ventoy/ventoy.json".to_string()])
        );
        // Une référence d'avant (sans « images ») : ISO/ et ventoy/ hors de la comparaison.
        let mut ancienne = m;
        ancienne.images = false;
        ancienne.fichiers.retain(|e| !d_images(&e.chemin));
        let ecart = comparer_avec(&racine, &ancienne, 10);
        assert!(ecart.vide() && !ecart.images, "{ecart:?}");
        let _ = std::fs::remove_dir_all(&racine);
        let _ = std::fs::remove_dir_all(reference.parent().unwrap().parent().unwrap());
    }

    /// images-cle.sh met une image à jour chez le propriétaire et réécrit le menu : redits à la référence, la clé
    /// n'a pas changé. Une image qu'il n'a pas posée (plantée ailleurs) reste dite nouvelle.
    #[test]
    fn images_mises_a_jour_redites_a_la_reference() {
        let racine = dossier_jetable("images");
        let reference = dossier_jetable("images-ref").join("ref.json");
        std::fs::create_dir_all(racine.join("ISO")).unwrap();
        std::fs::create_dir_all(racine.join("ventoy")).unwrap();
        std::fs::write(racine.join("Linux"), b"programme").unwrap();
        std::fs::write(racine.join("ISO/archlinux-2026.10.01-x86_64.iso"), b"0123456789abcdef").unwrap();
        std::fs::write(racine.join("ventoy/ventoy.json"), b"{1}").unwrap();
        ecrire_dans(&racine, &reference, 10).unwrap();
        // La nouvelle version copiée, l'ancienne retirée, le menu réécrit ; et une image plantée par ailleurs.
        std::fs::remove_file(racine.join("ISO/archlinux-2026.10.01-x86_64.iso")).unwrap();
        std::fs::write(racine.join("ISO/archlinux-2026.11.01-x86_64.iso"), b"0123456789abcdefg").unwrap();
        std::fs::write(racine.join("ISO/archlinux-2026.11.02-x86_64.iso"), b"piege").unwrap();
        std::fs::write(racine.join("ventoy/ventoy.json"), b"{2}").unwrap();
        let copiee = vec!["archlinux-2026.11.01-x86_64.iso".to_string()];
        assert_eq!(rafraichir_images_dans(&racine, &reference, &copiee, 10).unwrap(), 1);
        let ecart = comparer_avec(&racine, &lire(&reference).unwrap(), 10);
        assert_eq!(ecart.nouveaux, ["ISO/archlinux-2026.11.02-x86_64.iso"]);
        assert!(ecart.modifies.is_empty() && ecart.disparus.is_empty(), "{ecart:?}");
        // Une référence d'avant les images : refusé (le déploiement la refait).
        let mut m = lire(&reference).unwrap();
        m.images = false;
        enregistrer(&reference, &m).unwrap();
        assert!(rafraichir_images_dans(&racine, &reference, &copiee, 10).is_err());
        let _ = std::fs::remove_dir_all(&racine);
        let _ = std::fs::remove_dir_all(reference.parent().unwrap());
    }

    /// Sans référence chez le propriétaire : le jeton d'une référence d'ici sous un autre identifiant est un numéro
    /// de série changé (élevé) ; une clé inconnue, ou dont on a aussi changé le jeton, n'est plus une simple
    /// information (moyen) ; un identifiant illisible ne prouve rien (information). Premier usage : rien.
    #[test]
    fn identifiant_de_volume_change_sur_une_cle_reconnue() {
        assert!(sans_reference(false, SansReference::IdentifiantChange).is_none());
        assert!(sans_reference(false, SansReference::Inconnue).is_none());
        let c = sans_reference(true, SansReference::IdentifiantChange).unwrap();
        assert_eq!((c.probleme, c.verifie), (Some(Niveau::Eleve), false));
        assert!(
            c.message.contains("identifiant") || c.message.contains("identifier"),
            "{}",
            c.message
        );
        let c = sans_reference(true, SansReference::Inconnue).unwrap();
        assert_eq!((c.probleme, c.verifie), (Some(Niveau::Moyen), false));
        assert!(
            c.message.contains("jeton") || c.message.contains("token"),
            "{}",
            c.message
        );
        let c = sans_reference(true, SansReference::IdentifiantIllisible).unwrap();
        assert_eq!((c.probleme, c.verifie), (Some(Niveau::Info), false));
    }

    /// « Identifiant changé » seulement quand une référence d'ici porte le jeton de la clé : une clé connue sans
    /// référence à son jeton (déployée sur un autre ordinateur, référence d'avant le champ), ou dont l'identifiant
    /// n'a pas été lu, n'est pas accusée.
    #[test]
    fn identifiant_change_prouve_par_le_jeton_de_la_reference() {
        const JETON: &str = "0123456789abcdef0123456789abcdef";
        let base = dossier_jetable("jeton-ref");
        let racine = dossier_jetable("jeton-cle");
        std::fs::write(racine.join(crate::protection::cles_connues::JETON), JETON).unwrap();
        std::fs::write(racine.join("a.txt"), b"a").unwrap();
        // Une référence d'une autre clé, sans jeton : la clé connue n'y a pas la sienne.
        ecrire_dans(&racine, &reference_ecrite(&base, Some("AAAA-1111")), GROS).unwrap();
        let mut m = lire(&reference_ecrite(&base, Some("AAAA-1111"))).unwrap();
        assert_eq!(m.jeton.as_deref(), Some(JETON));
        m.jeton = None;
        enregistrer(&reference_ecrite(&base, Some("AAAA-1111")), &m).unwrap();
        assert!(!identifiant_change_dans(&base, Some("BBBB-2222"), Some(JETON)));
        // La référence porte le jeton de la clé, sous un autre identifiant : changé.
        ecrire_dans(&racine, &reference_ecrite(&base, Some("CCCC-3333")), GROS).unwrap();
        assert!(identifiant_change_dans(&base, Some("BBBB-2222"), Some(JETON)));
        // Sous son propre identifiant, rien n'a changé ; illisible ou sans jeton, rien n'est prouvé.
        assert!(!identifiant_change_dans(&base, Some("CCCC-3333"), Some(JETON)));
        assert!(!identifiant_change_dans(&base, None, Some(JETON)));
        assert!(!identifiant_change_dans(&base, Some("BBBB-2222"), None));
        assert!(a_des_references(&base));
        assert!(!a_des_references(&racine));
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&racine);
    }

    #[test]
    fn ecriture_puis_comparaison() {
        let racine = dossier_jetable("cle");
        let reference = dossier_jetable("ref").join("manifeste-cle.json");
        std::fs::create_dir_all(racine.join("Linux")).unwrap();
        std::fs::create_dir_all(racine.join("donnees")).unwrap();
        std::fs::create_dir_all(racine.join("ISO")).unwrap();
        std::fs::write(racine.join("Linux/vanguard"), b"programme").unwrap();
        std::fs::write(racine.join("LISEZMOI.txt"), b"lis-moi").unwrap();
        std::fs::write(racine.join("gros.img"), b"0123456789abcdef").unwrap();
        std::fs::write(racine.join("donnees/appareils.json"), b"{}").unwrap();
        std::fs::write(racine.join("ISO/x.iso"), b"iso").unwrap();
        // Au-delà de 10 octets, la taille seulement.
        assert_eq!(ecrire_dans(&racine, &reference, 10).unwrap(), 4);
        let m = lire(&reference).unwrap();
        assert_eq!(m.format, FORMAT);
        let gros = m.fichiers.iter().find(|e| e.chemin == "gros.img").unwrap();
        assert!(gros.blake3.is_none() && gros.taille == 16);
        assert!(
            m.fichiers
                .iter()
                .find(|e| e.chemin == "Linux/vanguard")
                .unwrap()
                .blake3
                .is_some()
        );
        let ecart = comparer_avec(&racine, &m, 10);
        assert!(ecart.vide() && ecart.images, "{ecart:?}");
        assert_eq!(ecart.verifies, 4);

        // La clé revient : un autorun planté, le programme remplacé (même taille), le guide disparu, les données
        // changées (normal), une image plantée, le gros fichier changé à taille égale (pas vu : dit dans la doc).
        std::fs::write(racine.join("autorun.inf"), b"[autorun]").unwrap();
        std::fs::write(racine.join("Linux/vanguard"), b"PROGRAMME").unwrap();
        std::fs::remove_file(racine.join("LISEZMOI.txt")).unwrap();
        std::fs::write(racine.join("donnees/appareils.json"), b"{\"x\":1}").unwrap();
        std::fs::write(racine.join("ISO/y.iso"), b"iso2").unwrap();
        std::fs::write(racine.join("gros.img"), b"fedcba9876543210").unwrap();
        let ecart = comparer_avec(&racine, &m, 10);
        assert_eq!(ecart.nouveaux, ["ISO/y.iso", "autorun.inf"]);
        assert_eq!(ecart.modifies, ["Linux/vanguard"]);
        assert_eq!(ecart.disparus, ["LISEZMOI.txt"]);
        assert_eq!(ecart.verifies, 2);
        std::fs::remove_file(racine.join("ISO/y.iso")).unwrap();
        let ecart = comparer_avec(&racine, &m, 10);
        assert!(
            resume_ecart(&ecart).starts_with("autorun.inf (nouveau), Linux/vanguard (modifié), LISEZMOI.txt (disparu)")
        );
        // Le gros fichier qui change de taille, lui, se voit.
        std::fs::write(racine.join("gros.img"), b"court").unwrap();
        assert!(
            comparer_avec(&racine, &m, 10)
                .modifies
                .contains(&"gros.img".to_string())
        );

        // Une référence qui n'est pas un manifeste est refusée.
        std::fs::write(
            &reference,
            b"{\"format\":\"autre\",\"version_vanguard\":\"\",\"date\":\"\",\"fichiers\":[]}",
        )
        .unwrap();
        assert!(lire(&reference).is_err());
        let _ = std::fs::remove_dir_all(&racine);
        let _ = std::fs::remove_dir_all(reference.parent().unwrap());
    }

    #[test]
    fn une_reference_par_cle() {
        let base = dossier_jetable("refs");
        // Rien d'écrit : aucune référence, pour aucune clé.
        assert_eq!(reference_lue(&base, Some("1A2B-3C4D")), None);
        assert_eq!(reference_lue(&base, None), None);
        // L'ancienne référence unique (0.59) sert encore, tant qu'aucune clé n'a la sienne.
        std::fs::write(base.join(ANCIENNE_REFERENCE), b"{}").unwrap();
        assert_eq!(
            reference_lue(&base, Some("1A2B-3C4D")),
            Some(base.join(ANCIENNE_REFERENCE))
        );
        // La clé A a la sienne : la clé B n'emprunte plus l'ancienne, qui décrivait peut-être A.
        let a = reference_ecrite(&base, Some("1A2B-3C4D"));
        assert_eq!(a, base.join(REFERENCES).join("1A2B-3C4D.json"));
        std::fs::create_dir_all(a.parent().unwrap()).unwrap();
        std::fs::write(&a, b"{}").unwrap();
        assert_eq!(reference_lue(&base, Some("1A2B-3C4D")), Some(a));
        assert_eq!(reference_lue(&base, Some("5E6F-7A8B")), None);
        // Sans identifiant (Windows, macOS) : l'ancienne.
        assert_eq!(reference_lue(&base, None), Some(base.join(ANCIENNE_REFERENCE)));
        assert_eq!(reference_ecrite(&base, None), base.join(ANCIENNE_REFERENCE));
        // L'identifiant devient un nom de fichier : rien qui sorte du dossier.
        assert_eq!(nom_de_reference(" 1A2B-3C4D\n").as_deref(), Some("1A2B-3C4D"));
        assert_eq!(
            nom_de_reference("0f1e2d3c-aaaa-bbbb-cccc-0123456789ab").as_deref(),
            Some("0f1e2d3c-aaaa-bbbb-cccc-0123456789ab")
        );
        assert_eq!(nom_de_reference("../../x"), None);
        assert_eq!(nom_de_reference(""), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn date_de_compilation_et_copie_perimee() {
        // Compilé depuis le dépôt : la date du dernier commit est là.
        let d = date_compilation().expect("VANGUARD_COMPILE posée par build.rs");
        assert!(d.format("%Y").to_string().starts_with("20"));
        assert_eq!(avertissement(10), None);
        assert_eq!(avertissement(179), None);
        assert_eq!(
            avertissement(210).as_deref(),
            Some("Cette copie de Vanguard a 7 mois : remettez la clé à jour chez vous.")
        );
    }
}
