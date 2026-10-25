//! Plugins : des programmes ajoutés à Vanguard sans changer son code (un essai, un outil expérimental), chacun dans
//! son sous-dossier de `<dossier local>/plugins/`, décrit par un `plugin.toml` (voir `manifeste`).
//!
//! Un plugin n'est pas du code de Vanguard : il ne tourne qu'à la demande (`vanguard plugins <nom>`, menu
//! Extensions), jamais en administrateur, et ses constats ne touchent jamais la note. Avec le bilan complet ou la
//! surveillance, seulement s'il le demande et que la personne l'a accordé par une question à part (sans restrictions,
//! pour ce dossier tel qu'il est : `reglages`) ; jamais avec l'entretien. Il doit avoir été approuvé : `vanguard plugins ajouter` montre ce qu'il
//! lancera et note l'empreinte SHA-256 du manifeste et de chaque programme ; une empreinte qui change ensuite le fait
//! refuser jusqu'à une nouvelle approbation. Au lancement, le programme est copié en même temps qu'il est haché, et
//! c'est la copie vérifiée qui tourne : le remplacer entre la vérification et le lancement ne sert à rien. La
//! conception (menaces et garde-fous) est résumée dans CONTRIBUTING.md, section Plugins.

mod archive;
pub mod labo;
pub mod manifeste;
mod menu;
pub mod reglages;
pub mod sortie;

pub use menu::extensions;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use manifeste::{Manifeste, Systeme};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::langue::Reponse;
use crate::ui::*;
use crate::{tr, trf, trp};

const MANIFESTE: &str = "plugin.toml";
/// La signature de l'auteur, à la racine du dossier, quand le manifeste donne `cle_auteur` (voir `auteur_verifie`).
const SIGNATURE: &str = "plugin.sig";
/// Ce qui précède l'empreinte dans le message signé : une signature faite pour autre chose ne vaut pas ici.
const DOMAINE_PLUGIN: &str = "vanguard-plugin 1";
const APPROUVES: &str = "approuves.json";
/// Le nom scellé des approbations sous le dossier de Vanguard (`modele::inventaire`, `sceau`).
pub(crate) const APPROUVES_SCELLE: &str = "plugins/approuves.json";
/// Les constats gardés par `--rapport`, un fichier par plugin, repris par le rapport HTML.
pub(crate) const CONSTATS: &str = ".constats";
/// Ce qu'un plugin peut écrire (chaque sortie) avant d'être arrêté, et la taille d'un programme.
const SORTIE_MAX: usize = 1 << 20;
const PROGRAMME_MAX: u64 = 200 << 20;
/// Un plugin ajouté : fichiers, octets et profondeur au plus.
const COPIE_FICHIERS_MAX: usize = 500;
const COPIE_OCTETS_MAX: u64 = 300 << 20;
const PROFONDEUR_MAX: usize = 8;
/// Les arguments passés en ligne de commande : nombre et longueur.
const ARGUMENTS_MAX: usize = 32;
const ARGUMENT_MAX: usize = 1000;

/// Le dossier des plugins : `<dossier local>/plugins`, créé à soi seul (0700) s'il manque, et refusé s'il est
/// partagé, sur la clé VANGUARD ou hors du profil (Windows). Jamais le dossier du programme ni la clé : un plugin ne
/// voyage pas, et un dossier que d'autres comptes peuvent écrire leur ferait lancer ce qu'ils veulent sous ce compte.
pub fn dossier() -> Result<PathBuf, String> {
    let local = crate::socle::dossier_local();
    // Sans HOME ni XDG_DATA_HOME (LOCALAPPDATA sous Windows), le dossier local serait relatif : le dossier courant.
    if !local.is_absolute() {
        return Err(tr!(
            "Dossier local de Vanguard inconnu (ni HOME ni XDG_DATA_HOME, ou LOCALAPPDATA) : extensions refusées.",
            "Vanguard's local folder is unknown (no HOME nor XDG_DATA_HOME, or LOCALAPPDATA): extensions refused."
        )
        .to_string());
    }
    let d = local.join("plugins");
    creer_prive(&d).map_err(|e| {
        trf!(
            "Dossier des plugins impossible à créer ({}) : {e}",
            "Could not create the plugins folder ({}): {e}",
            chemin_affichable(&d)
        )
    })?;
    if let Some(cle) = crate::reseau::cle_usb()
        && (d.starts_with(&cle) || std::fs::canonicalize(&d).is_ok_and(|c| c.starts_with(&cle)))
    {
        return Err(trf!(
            "Le dossier des plugins ({}) est sur la clé VANGUARD : refusé, un plugin ne voyage pas sur la clé.",
            "The plugins folder ({}) is on the VANGUARD key: refused, a plugin does not travel on the key.",
            chemin_affichable(&d)
        ));
    }
    dossier_sur(&d)?;
    Ok(d)
}

/// Crée un dossier (et ses parents) réservé à son compte. Déjà là, il n'est pas touché : `dossier_sur` le juge.
fn creer_prive(d: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(d)
}

/// Le compte de ce processus (Unix).
#[cfg(unix)]
fn moi() -> u32 {
    // SAFETY : getuid ne prend aucun argument, ne touche aucune mémoire et ne peut pas échouer.
    unsafe { libc::getuid() }
}

/// Un dossier où lire et lancer un plugin. Unix : à soi, ni lien ni ouvert en écriture au groupe ou aux autres ; chaque
/// parent à soi ou à root, et s'il est ouvert en écriture, collant (/tmp) : sinon un autre compte pourrait renommer le
/// dossier et en mettre un autre à sa place.
#[cfg(unix)]
fn dossier_sur(d: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let refus = |pourquoi: &str| {
        trf!(
            "Dossier refusé ({}) : {pourquoi}.",
            "Folder refused ({}): {pourquoi}.",
            chemin_affichable(d)
        )
    };
    let m = std::fs::symlink_metadata(d).map_err(|e| refus(&e.to_string()))?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(refus(tr!("un lien ou pas un dossier", "a link or not a folder")));
    }
    if m.uid() != moi() {
        return Err(refus(tr!(
            "il appartient à un autre compte",
            "it belongs to another account"
        )));
    }
    if m.mode() & 0o022 != 0 {
        return Err(refus(tr!(
            "d'autres comptes peuvent y écrire (chmod go-w)",
            "other accounts can write to it (chmod go-w)"
        )));
    }
    // Les parents du chemin réel : un élément qui est un lien (/home → /var/home) mène à d'autres parents.
    let reel = std::fs::canonicalize(d).map_err(|e| refus(&e.to_string()))?;
    for parent in reel.ancestors().skip(1).filter(|p| !p.as_os_str().is_empty()) {
        let Ok(m) = std::fs::metadata(parent) else {
            return Err(refus(&trf!("{} illisible", "{} unreadable", chemin_affichable(parent))));
        };
        let ouvert = m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0;
        if (m.uid() != moi() && m.uid() != 0) || ouvert {
            return Err(refus(&trf!(
                "{} est à un autre compte ou ouvert en écriture",
                "{} belongs to another account or is open for writing",
                chemin_affichable(parent)
            )));
        }
    }
    Ok(())
}

/// Windows : le dossier doit être dans le profil de la personne (les droits par défaut l'y réservent à son compte), et
/// ni lui ni son parent ne doivent être un point d'analyse (lien, jonction) qui mènerait ailleurs.
#[cfg(windows)]
fn dossier_sur(d: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    const POINT_D_ANALYSE: u32 = 0x400;
    let refus = |pourquoi: &str| {
        trf!(
            "Dossier refusé ({}) : {pourquoi}.",
            "Folder refused ({}): {pourquoi}.",
            chemin_affichable(d)
        )
    };
    for p in [Some(d), d.parent()].into_iter().flatten() {
        let m = std::fs::symlink_metadata(p).map_err(|e| refus(&e.to_string()))?;
        if m.file_attributes() & POINT_D_ANALYSE != 0 || (p == d && !m.is_dir()) {
            return Err(refus(tr!(
                "un lien, une jonction ou pas un dossier",
                "a link, a junction or not a folder"
            )));
        }
    }
    let profil = std::env::var_os("USERPROFILE").and_then(|p| std::fs::canonicalize(p).ok());
    let ici = std::fs::canonicalize(d).ok();
    match (profil, ici) {
        (Some(profil), Some(ici)) if ici.starts_with(&profil) => Ok(()),
        _ => Err(refus(tr!(
            "il n'est pas dans le profil de ce compte",
            "it is not in this account's profile"
        ))),
    }
}

/// Lancé en administrateur ? Unix : root, ou un programme setuid (compte effectif ≠ compte réel) ; Windows : jeton
/// élevé. Un plugin ne tourne jamais ainsi : il aurait tous les droits sur l'ordinateur.
fn eleve() -> bool {
    #[cfg(unix)]
    {
        // SAFETY : geteuid ne prend aucun argument, ne touche aucune mémoire et ne peut pas échouer.
        let effectif = unsafe { libc::geteuid() };
        effectif == 0 || effectif != moi()
    }
    #[cfg(windows)]
    {
        crate::machine::windows::processus::eleve_ou_inconnu()
    }
}

fn refus_eleve() -> String {
    tr!(
        "Vanguard tourne en administrateur : les plugins sont refusés. Un plugin n'est pas du code de Vanguard ; lancé ainsi, il aurait tous les droits sur l'ordinateur. Relancez Vanguard sans droits d'administrateur (sans sudo, ou pas « en tant qu'administrateur ») pour ajouter, approuver ou lancer un plugin.",
        "Vanguard is running as administrator: plugins are refused. A plugin is not Vanguard's code; run like this, it would have every right on the computer. Start Vanguard again without administrator rights (no sudo, or not “as administrator”) to add, approve or run a plugin."
    )
    .to_string()
}

/// Ce que la personne a approuvé : pour chaque plugin, l'empreinte de tout son dossier (chaque fichier, pas seulement
/// le programme : un script qui lit `./lib.sh`, un programme qui charge une DLL posée à côté, changeraient sans cela).
#[derive(Serialize, Deserialize, Default, Debug)]
struct Approbations {
    #[serde(default)]
    plugins: BTreeMap<String, Approbation>,
    /// Les scripts du laboratoire : nom du fichier → son empreinte.
    #[serde(default)]
    labo: BTreeMap<String, labo::Approbation>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
struct Approbation {
    /// L'empreinte de l'arbre (`empreinte_arbre`).
    arbre: String,
    /// Chemin relatif → SHA-256 de chaque fichier : pour dire ce qui a changé.
    fichiers: Fichiers,
    le: String,
    /// La clé de l'auteur vérifiée à l'approbation (hexadécimal), s'il en avait une : une mise à jour signée par une
    /// autre, ou plus signée du tout, se voit à l'approbation suivante.
    #[serde(default)]
    cle_auteur: Option<String>,
}

/// Les fichiers d'un plugin : chemin relatif (séparateur « / ») → SHA-256.
pub(crate) type Fichiers = BTreeMap<String, String>;

/// Les approbations ; un fichier illisible n'approuve rien (tout est alors refusé, jamais tout permis), ni un fichier
/// changé hors de Vanguard ou accepté tel quel par les sceaux (`approbations_jugees`).
fn approbations(racine: &Path) -> Approbations {
    approbations_jugees(racine).0
}

/// Les approbations, et pourquoi celles du fichier ont été ignorées quand il en portait. approuves.json est scellé
/// (`sceau`) : un programme du compte qui y inscrivait l'empreinte de son propre plugin le faisait lancer sans
/// question. Changé hors de Vanguard, ou accepté tel quel (après des sceaux refaits, ou repris d'une version d'avant
/// le sceau : rien ne prouve que la personne l'a donné), il n'approuve rien ; chaque extension est redemandée, et
/// c'est dit (`douteux`).
fn approbations_jugees(racine: &Path) -> (Approbations, Option<Douteux>) {
    match lire_scelle(racine, APPROUVES, 1 << 20) {
        Ok(Some((o, douteux))) => {
            let a: Approbations = serde_json::from_slice(&o).unwrap_or_default();
            match douteux {
                None => (a, None),
                // Dit seulement si une approbation ignorée vaudrait encore pour un plugin ou un script présent :
                // celle d'un plugin retiré n'accorde plus rien.
                Some(d) => {
                    let portait = !approuves_presents(racine, &a).is_empty();
                    (Approbations::default(), portait.then_some(d))
                }
            }
        }
        Ok(None) | Err(_) => (Approbations::default(), None),
    }
}

/// Les plugins et scripts du labo encore là que ces approbations approuvent.
fn approuves_presents(racine: &Path, a: &Approbations) -> Vec<String> {
    let plugins = a.plugins.keys().filter(|n| racine.join(n).is_dir());
    let labo = a.labo.keys().filter(|f| racine.join(labo::DOSSIER).join(f).is_file());
    plugins.chain(labo).cloned().collect()
}

/// Les éléments à qui un fichier ignoré accordait encore quelque chose (« à moi », approbation) : pour dire à la
/// personne quoi refaire. Le contenu ignoré se lit encore ; il n'accorde rien, il nomme seulement.
pub(crate) fn a_refaire(racine: &Path) -> Vec<String> {
    let mut noms = std::collections::BTreeSet::new();
    if let Ok(Some((o, Some(_)))) = lire_scelle(racine, reglages::FICHIER, 64 << 10)
        && let Ok(r) = serde_json::from_slice::<reglages::Reglages>(&o)
    {
        noms.extend(r.plugins_a_moi.into_iter().chain(r.labo_a_moi).map(|k| k.nom));
    }
    if let Ok(Some((o, Some(_)))) = lire_scelle(racine, APPROUVES, 1 << 20)
        && let Ok(a) = serde_json::from_slice::<Approbations>(&o)
    {
        noms.extend(approuves_presents(racine, &a));
    }
    noms.into_iter().map(|n| affichable(&n)).collect()
}

/// approuves.json d'une version d'avant le sceau (sous `dossier`, celui des sceaux), accepté tel quel à la mise à
/// jour : rescellé s'il n'approuve rien
/// qui soit encore là (vide, ou seulement des plugins retirés depuis), réécrit vide pour qu'aucune approbation
/// d'un plugin remis plus tard n'en revienne. Jamais après l'effacement des sceaux.
pub(crate) fn resceller_dans(dossier: &Path) {
    let racine = dossier.join("plugins");
    if crate::sceau::refaits_dans(dossier) {
        return;
    }
    if let crate::sceau::Lecture::Adopte(o) = crate::sceau::lire_dans(dossier, APPROUVES_SCELLE)
        && let Ok(a) = serde_json::from_slice::<Approbations>(&o)
        && approuves_presents(&racine, &a).is_empty()
        && let Ok(texte) = serde_json::to_string_pretty(&Approbations::default())
    {
        let _ = crate::sceau::ecrire_dans(dossier, APPROUVES_SCELLE, texte.as_bytes());
    }
}

/// Pourquoi un fichier des extensions (réglages, approbations) n'est pas cru.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Douteux {
    /// Accepté tel quel par les sceaux : une version d'avant le sceau, ou des sceaux refaits.
    Adopte,
    /// Changé hors de Vanguard.
    HorsVanguard,
}

impl Douteux {
    pub(crate) fn texte(self) -> &'static str {
        match self {
            Douteux::Adopte => tr!(
                "fichier repris tel quel d'une version d'avant de Vanguard, ou après l'effacement de ses sceaux",
                "file taken as it was from an earlier version of Vanguard, or after its seals were deleted"
            ),
            Douteux::HorsVanguard => tr!("fichier changé hors de Vanguard", "file changed outside Vanguard"),
        }
    }
}

/// Le dossier des sceaux et le nom scellé d'un fichier des extensions : le parent de `racine` (le dossier de
/// Vanguard) et « plugins/<fichier> » (`modele::inventaire`).
fn lieu_scelle(racine: &Path, fichier: &str) -> Result<(PathBuf, String), crate::modele::Echec> {
    let parent = racine.parent().filter(|p| !p.as_os_str().is_empty());
    let nom = racine.file_name().and_then(|n| n.to_str());
    match (parent, nom) {
        (Some(p), Some(n)) => Ok((p.to_path_buf(), format!("{n}/{fichier}"))),
        _ => Err(crate::modele::Echec::refuse(
            "plugins/sceau",
            trf!(
                "{} : pas un dossier des extensions",
                "{}: not an extensions folder",
                chemin_affichable(racine)
            ),
        )),
    }
}

/// Un fichier scellé lu : son contenu, et pourquoi il n'est pas cru (`None` : tel que Vanguard l'a écrit).
pub(crate) type Lu = (Vec<u8>, Option<Douteux>);

/// Un fichier scellé du dossier des extensions, `max` octets au plus : `Ok(None)` s'il n'y est pas (ou effacé hors de
/// Vanguard : rien n'est alors accordé), le contenu et, s'il n'est pas tel que Vanguard l'a écrit, pourquoi. Le
/// fichier doit d'abord être à soi et fermé aux autres comptes (`ouvrir_sur`), comme avant le sceau.
pub(crate) fn lire_scelle(racine: &Path, fichier: &str, max: usize) -> Result<Option<Lu>, crate::modele::Echec> {
    use crate::modele::{Echec, Raison};
    use crate::sceau::Lecture;
    const OU: &str = "plugins/lire";
    let chemin = racine.join(fichier);
    if std::fs::symlink_metadata(&chemin).is_ok() {
        ouvrir_sur(&chemin).map_err(|e| Echec::refuse(OU, e))?;
    }
    let (dossier, nom) = lieu_scelle(racine, fichier)?;
    let (octets, douteux) = match crate::sceau::lire_dans(&dossier, &nom) {
        Lecture::Absent | Lecture::Inconnu | Lecture::Falsifie(None) => return Ok(None),
        Lecture::Illisible(e) => return Err(Echec::new(OU, Raison::Illisible(e))),
        Lecture::Intact(o) => (o, None),
        // Jamais un feu vert : repris d'une version d'avant le sceau, il a pu être écrit par n'importe quel
        // programme du compte, comme après des sceaux refaits.
        Lecture::Adopte(o) => (o, Some(Douteux::Adopte)),
        Lecture::Falsifie(Some(o)) => (o, Some(Douteux::HorsVanguard)),
    };
    if octets.len() > max {
        return Err(Echec::refuse(
            OU,
            trf!("{} : trop gros", "{}: too large", chemin_affichable(&chemin)),
        ));
    }
    Ok(Some((octets, douteux)))
}

/// Écrit un fichier du dossier des extensions, et son sceau.
pub(crate) fn ecrire_scelle(racine: &Path, fichier: &str, octets: &[u8]) -> Result<(), crate::modele::Echec> {
    let (dossier, nom) = lieu_scelle(racine, fichier)?;
    crate::sceau::ecrire_dans(&dossier, &nom, octets).map_err(|e| crate::modele::Echec::ecriture("plugins/ecrire", &e))
}

/// Ce que la personne doit savoir des réglages et des approbations ignorés (menu Extensions, `vanguard plugins`,
/// bilan complet) : pourquoi, ce que ça coupe, quoi taper, et les éléments à refaire.
pub(crate) fn douteux(racine: &Path) -> Vec<String> {
    let mut dit = Vec::new();
    if let Some(d) = reglages::douteux(racine) {
        dit.push(trf!(
            "Réglages des extensions ignorés : {}. Aucune restriction n'est coupée, aucun élément n'est « à moi », rien ne tourne tout seul. Si c'était vous, refaites-les dans le menu Extensions (« vanguard extensions »).",
            "Extension settings ignored: {}. No restriction is lifted, no item is “mine”, nothing runs on its own. If it was you, set them again in the Extensions menu (“vanguard extensions”).",
            d.texte()
        ));
    }
    if let Some(d) = approbations_jugees(racine).1 {
        dit.push(trf!(
            "Approbations des extensions ignorées : {}. Chaque extension est redemandée : « vanguard plugins approuver <nom> ».",
            "Extension approvals ignored: {}. Each extension is asked again: “vanguard plugins approve <name>”.",
            d.texte()
        ));
    }
    let noms = a_refaire(racine);
    if !dit.is_empty() && !noms.is_empty() {
        dit.push(trf!("À refaire : {}.", "To redo: {}.", noms.join(", ")));
    }
    dit
}

/// Le constat du bilan (COM-ETA-001) pour les fichiers des extensions changés hors de Vanguard ou acceptés tels
/// quels, à la place du constat commun des sceaux, dont le « à faire » (Ce que Vanguard a appris, la référence des
/// fichiers critiques) ne les réécrit pas. Rien s'ils n'accordaient rien (rescellés, ou ignorés sans rien couper).
pub(crate) fn constat_sceaux(falsifies: bool) -> Option<crate::machine::Constat> {
    use crate::risk::Niveau;
    // Lu aussi en administrateur (rien n'y est écrit : `sceau::lire_dans` ne note rien dans le dossier d'un autre).
    let local = crate::socle::dossier_local();
    if !local.is_absolute() {
        return None;
    }
    let mut dit = douteux(&local.join("plugins"));
    let niveau = match (dit.is_empty(), falsifies) {
        (false, true) => Niveau::Eleve,
        (false, false) => Niveau::Moyen,
        // Changé hors de Vanguard sans rien accorder : rien n'est coupé, mais c'est une falsification, dite.
        (true, true) => {
            dit.push(
                tr!(
                    "Les réglages ou les approbations des extensions ont été changés hors de Vanguard ; ils n'accordaient rien, et ils sont ignorés.",
                    "Extension settings or approvals were changed outside Vanguard; they granted nothing, and they are ignored."
                )
                .to_string(),
            );
            Niveau::Moyen
        }
        (true, false) => return None,
    };
    Some(
        crate::machine::alerte(crate::sceau::CAT, niveau, dit.join(" ")).manuel(
            tr!(
                "Menu Extensions (« vanguard extensions »), ou « vanguard plugins approuver <nom> » pour chaque extension à refaire",
                "Extensions menu (“vanguard extensions”), or “vanguard plugins approve <name>” for each extension to redo"
            ),
            &[],
        ),
    )
}

/// Montre ce que `douteux` a à dire, en alerte.
pub(crate) fn dire_douteux(racine: &Path) {
    for texte in douteux(racine) {
        let marque = format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve));
        afficher_aligne(&marque, &texte, 4, GRAS);
    }
}

fn enregistrer(racine: &Path, a: &Approbations) -> Result<(), String> {
    let texte = serde_json::to_string_pretty(a).map_err(|e| e.to_string())?;
    ecrire_scelle(racine, APPROUVES, texte.as_bytes()).map_err(|e| {
        trf!(
            "Approbation impossible à écrire : {e}",
            "Could not write the approval: {e}"
        )
    })
}

/// Ouvre un fichier sans suivre de lien (Unix : O_NOFOLLOW ; Windows : le point d'analyse lui-même, puis refusé), sans
/// bloquer sur un tube nommé (O_NONBLOCK), et le refuse s'il n'est pas un fichier ordinaire ; avec `proprietaire`
/// (Unix), aussi s'il est à un autre compte ou modifiable par d'autres. Les vérifications portent sur le fichier
/// ouvert, pas sur son nom : celui-ci peut changer entre deux appels.
fn ouvrir_sans_lien(chemin: &Path, proprietaire: bool) -> Result<std::fs::File, String> {
    let refus = |pourquoi: &str| {
        trf!(
            "{} refusé : {pourquoi}",
            "{} refused: {pourquoi}",
            chemin_affichable(chemin)
        )
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, 0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    let f = options.open(chemin).map_err(|e| refus(&e.to_string()))?;
    let m = f.metadata().map_err(|e| refus(&e.to_string()))?;
    if !m.is_file() {
        return Err(refus(tr!("pas un fichier ordinaire", "not a regular file")));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if proprietaire && (m.uid() != moi() || m.mode() & 0o022 != 0) {
            return Err(refus(tr!(
                "à un autre compte, ou modifiable par d'autres",
                "owned by another account, or writable by others"
            )));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let _ = proprietaire;
        if m.file_attributes() & 0x400 != 0 {
            return Err(refus(tr!("un lien", "a link")));
        }
    }
    Ok(f)
}

fn ouvrir_sur(chemin: &Path) -> Result<std::fs::File, String> {
    ouvrir_sans_lien(chemin, true)
}

/// Le fichier entier, `max` octets au plus.
fn lire_sur(chemin: &Path, max: usize) -> Result<Vec<u8>, String> {
    let f = ouvrir_sur(chemin)?;
    let mut octets = Vec::new();
    f.take(max as u64 + 1)
        .read_to_end(&mut octets)
        .map_err(|e| e.to_string())?;
    if octets.len() > max {
        return Err(trf!("{} : trop gros", "{}: too large", chemin_affichable(chemin)));
    }
    Ok(octets)
}

fn hex(octets: &[u8]) -> String {
    use std::fmt::Write as _;
    octets.iter().fold(String::new(), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    })
}

/// Copie `source` vers `copie` (créé, jamais écrasé) en la hachant au passage ; `None` pour `copie` : seulement haché.
/// `max` octets au plus. Rend l'empreinte de ce qui a été lu, donc de ce qui a été écrit, et sa taille.
fn copier_hache(source: &Path, copie: Option<&Path>, proprietaire: bool, max: u64) -> Result<(String, u64), String> {
    let mut f = ouvrir_sans_lien(source, proprietaire)?;
    let mut vers = match copie {
        None => None,
        Some(c) => {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o700);
            Some(o.open(c).map_err(|e| e.to_string())?)
        }
    };
    let mut h = sha2::Sha256::new();
    let mut tampon = vec![0u8; 64 << 10];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut tampon).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max {
            return Err(trf!("{} : trop gros", "{}: too large", chemin_affichable(source)));
        }
        h.update(&tampon[..n]);
        if let Some(v) = vers.as_mut() {
            v.write_all(&tampon[..n]).map_err(|e| e.to_string())?;
        }
    }
    if let Some(v) = vers {
        v.sync_all().map_err(|e| e.to_string())?;
    }
    Ok((hex(&h.finalize()), total))
}

/// Un seul fichier à soi (un script du labo), haché et copié si `copie` est donnée.
fn hacher_et_copier(source: &Path, copie: Option<&Path>) -> Result<String, String> {
    copier_hache(source, copie, true, PROGRAMME_MAX).map(|(e, _)| e)
}

/// Parcourt le dossier d'un plugin, sans suivre de lien (refusé), et rend l'empreinte de chaque fichier ; avec `vers`,
/// le recopie en même temps (seulement des fichiers et des dossiers ordinaires). Borné en fichiers, en octets et en
/// profondeur. Ce que la compilation ou git laissent à sa racine (`target/`, `.git/`) n'en fait pas partie.
/// `proprietaire` (Unix) : chaque fichier doit être à soi et fermé aux autres (le dossier des plugins) ; pas pour une
/// source à ajouter (une clé USB, une archive dépliée).
fn arbre(d: &Path, vers: Option<&Path>, proprietaire: bool) -> Result<Fichiers, String> {
    let mut fichiers = Fichiers::new();
    let mut compte = (0usize, 0u64);
    parcourir(d, "", vers, proprietaire, &mut fichiers, &mut compte, 0)?;
    Ok(fichiers)
}

fn parcourir(
    de: &Path,
    relatif: &str,
    vers: Option<&Path>,
    proprietaire: bool,
    fichiers: &mut Fichiers,
    compte: &mut (usize, u64),
    profondeur: usize,
) -> Result<(), String> {
    if profondeur > PROFONDEUR_MAX {
        return Err(tr!("dossiers trop imbriqués", "folders nested too deep").to_string());
    }
    let entrees = std::fs::read_dir(de).map_err(|e| format!("{} : {e}", chemin_affichable(de)))?;
    for entree in entrees {
        let entree = entree.map_err(|e| e.to_string())?;
        let nom = entree.file_name().into_string().map_err(|n| {
            trf!(
                "nom de fichier illisible : {}",
                "unreadable file name: {}",
                affichable(&n.to_string_lossy())
            )
        })?;
        if profondeur == 0 && matches!(nom.as_str(), "target" | ".git") {
            continue;
        }
        let source = entree.path();
        let chemin = if relatif.is_empty() {
            nom.clone()
        } else {
            format!("{relatif}/{nom}")
        };
        let cible = vers.map(|v| v.join(&nom));
        let meta = std::fs::symlink_metadata(&source).map_err(|e| e.to_string())?;
        compte.0 += 1;
        if compte.0 > COPIE_FICHIERS_MAX {
            return Err(trf!(
                "plus de {COPIE_FICHIERS_MAX} fichiers",
                "more than {COPIE_FICHIERS_MAX} files"
            ));
        }
        if meta.file_type().is_symlink() {
            return Err(trf!(
                "{} est un lien : refusé",
                "{} is a link: refused",
                chemin_affichable(&source)
            ));
        } else if meta.is_dir() {
            if let Some(c) = &cible {
                creer_prive(c).map_err(|e| e.to_string())?;
            }
            parcourir(
                &source,
                &chemin,
                cible.as_deref(),
                proprietaire,
                fichiers,
                compte,
                profondeur + 1,
            )?;
        } else if meta.is_file() {
            let reste = COPIE_OCTETS_MAX.saturating_sub(compte.1);
            // Le reste des octets permis : un fichier qui grossit pendant la lecture ne passe pas la borne.
            let (empreinte, octets) = copier_hache(&source, cible.as_deref(), proprietaire, reste)?;
            compte.1 += octets;
            fichiers.insert(chemin, empreinte);
        } else {
            return Err(trf!(
                "{} n'est pas un fichier ordinaire : refusé",
                "{} is not a regular file: refused",
                chemin_affichable(&source)
            ));
        }
    }
    Ok(())
}

/// L'empreinte d'un arbre : le SHA-256 de la liste triée « empreinte  chemin », une ligne par fichier.
fn empreinte_arbre(fichiers: &Fichiers) -> String {
    let mut h = sha2::Sha256::new();
    for (chemin, empreinte) in fichiers {
        h.update(format!("{empreinte}  {chemin}\n").as_bytes());
    }
    hex(&h.finalize())
}

/// L'auteur du plugin, vérifié : quand le manifeste donne `cle_auteur`, `plugin.sig` doit être la signature Ed25519,
/// par cette clé, de « vanguard-plugin 1 », d'un saut de ligne, de l'empreinte de l'arbre sans `plugin.sig`
/// (`empreinte_arbre`) et d'un saut de ligne ; en 128 chiffres hexadécimaux. `Ok(None)` : le plugin ne dit pas de clé
/// (son auteur reste « non vérifié ») ; `Err` : une clé dite et une signature absente ou fausse, refusé. La clé, elle,
/// vient du manifeste : elle prouve que tout le dossier vient de qui tient la clé privée, pas qui c'est. D'où la
/// comparaison avec la clé notée à l'approbation d'avant, qui voit un autre auteur prendre la place du premier.
fn auteur_verifie(m: &Manifeste, copie: &Path, fichiers: &Fichiers) -> Result<Option<[u8; 32]>, String> {
    let Some(cle) = m.cle_auteur else {
        return Ok(None);
    };
    let refus = || {
        tr!(
            "« cle_auteur » est donnée, mais plugin.sig manque ou n'est pas la signature de ce dossier par cette clé : refusé (dossier changé après sa signature ?).",
            "“cle_auteur” is given, but plugin.sig is missing or is not this folder's signature by that key: refused (folder changed after it was signed?)."
        )
        .to_string()
    };
    let texte = lire_sur(&copie.join(SIGNATURE), 1024).map_err(|_| refus())?;
    let hex_sig = String::from_utf8(texte).map_err(|_| refus())?;
    let hex_sig = hex_sig.trim();
    let mut signature = [0u8; 64];
    let lue = hex_sig.len() == 128
        && signature.iter_mut().enumerate().all(|(i, o)| {
            hex_sig
                .get(2 * i..2 * i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .map(|v| *o = v)
                .is_some()
        });
    let sans_signature: Fichiers = fichiers
        .iter()
        .filter(|(f, _)| f.as_str() != SIGNATURE)
        .map(|(f, e)| (f.clone(), e.clone()))
        .collect();
    let message = format!("{DOMAINE_PLUGIN}\n{}\n", empreinte_arbre(&sans_signature));
    let valide = lue
        && ed25519_dalek::VerifyingKey::from_bytes(&cle).is_ok_and(|k| {
            k.verify_strict(message.as_bytes(), &ed25519_dalek::Signature::from_bytes(&signature))
                .is_ok()
        });
    if valide { Ok(Some(cle)) } else { Err(refus()) }
}

/// Ce que l'approbation dit de l'auteur, comparé à celle d'avant : même clé, autre clé, plus de clé.
fn comparer_auteur(avant: Option<&Approbation>, cle: Option<&[u8; 32]>) {
    let Some(a) = avant else {
        return;
    };
    let ici = cle.map(|c| hex(c));
    match (&a.cle_auteur, &ici) {
        (Some(x), Some(y)) if x == y => trp!(
            "  {VERT}✔{RESET} Même auteur que lors de l'approbation du {} (même clé).",
            "  {VERT}✔{RESET} Same author as at the approval of {} (same key).",
            affichable(&a.le)
        ),
        (Some(_), _) => afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
            &trf!(
                "Il n'est plus signé par la clé de l'auteur approuvé le {} : quelqu'un d'autre a pu le remplacer. Ne l'approuvez que si vous savez pourquoi.",
                "It is no longer signed by the key of the author approved on {}: someone else may have replaced it. Only approve it if you know why.",
                affichable(&a.le)
            ),
            4,
            "",
        ),
        (None, _) => {}
    }
}

/// Ce qui a changé entre deux arbres : fichiers changés, ajoutés ou retirés.
fn changements(avant: &Fichiers, apres: &Fichiers) -> Vec<String> {
    let mut c: Vec<String> = apres
        .iter()
        .filter(|(f, e)| avant.get(*f) != Some(*e))
        .map(|(f, _)| affichable(f))
        .collect();
    c.extend(
        avant
            .keys()
            .filter(|f| !apres.contains_key(*f))
            .map(|f| trf!("{} (retiré)", "{} (removed)", affichable(f))),
    );
    c
}

/// Le manifeste d'un dossier de plugin, lu une seule fois : l'empreinte est celle des octets mêmes qui sont analysés.
fn lire_manifeste(d: &Path) -> Result<(Manifeste, String), String> {
    let octets = lire_sur(&d.join(MANIFESTE), manifeste::OCTETS_MAX)?;
    let empreinte = hex(&sha2::Sha256::digest(&octets));
    let texte = String::from_utf8(octets)
        .map_err(|_| tr!("plugin.toml n'est pas en UTF-8", "plugin.toml is not UTF-8").to_string())?;
    let m = manifeste::lire(&texte).map_err(|e| format!("plugin.toml, {e}"))?;
    Ok((m, empreinte))
}

/// Le chemin d'un programme du manifeste dans son dossier (`chemin_valide` l'a déjà gardé dedans).
fn chemin_du_programme(d: &Path, programme: &str) -> PathBuf {
    programme.split(['/', '\\']).fold(d.to_path_buf(), |c, p| c.join(p))
}

/// Sans restrictions, le programme lancé est l'original : chaque élément de son chemin sous `d` doit être un vrai
/// dossier (ni lien ni jonction qui mènerait ailleurs), fermé aux autres comptes, et le programme un fichier à soi.
fn verifier_chemin(d: &Path, programme: &str) -> Result<(), String> {
    let mut ici = d.to_path_buf();
    let parties: Vec<&str> = programme.split(['/', '\\']).collect();
    for p in &parties[..parties.len().saturating_sub(1)] {
        ici.push(p);
        dossier_sur(&ici)?;
    }
    ouvrir_sur(&chemin_du_programme(d, programme)).map(|_| ())
}

/// L'état d'un plugin du dossier.
#[derive(Debug, PartialEq, Eq)]
pub enum Etat {
    Pret,
    NonApprouve,
    /// Un fichier a changé (ou a été ajouté, retiré) depuis l'approbation.
    Change,
    /// Il ne vise pas ce système.
    AutreSysteme,
    Invalide(String),
}

pub struct Plugin {
    pub nom: String,
    pub manifeste: Option<Manifeste>,
    /// L'empreinte de son dossier tel qu'il est maintenant.
    pub empreinte: Option<String>,
    pub etat: Etat,
}

/// Les plugins du dossier, dans l'ordre des noms (100 au plus). Les dossiers cachés (copies en cours, constats
/// gardés) n'en sont pas.
pub fn inventaire(racine: &Path) -> Vec<Plugin> {
    let approuves = approbations(racine);
    let mut noms: Vec<String> = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        // Le laboratoire a son dossier à lui, sans manifeste : ce n'est pas un plugin.
        .filter(|n| !n.starts_with('.') && n != labo::DOSSIER)
        .take(100)
        .collect();
    noms.sort();
    noms.into_iter()
        .map(|nom| {
            let d = racine.join(&nom);
            let lu = if manifeste::nom_valide(&nom) {
                dossier_sur(&d)
                    .and_then(|()| lire_manifeste(&d))
                    .and_then(|(m, _)| Ok((m, empreinte_arbre(&arbre(&d, None, true)?))))
            } else {
                Err(tr!("nom de dossier refusé", "folder name refused").to_string())
            };
            match lu {
                Err(e) => Plugin {
                    nom,
                    manifeste: None,
                    empreinte: None,
                    etat: Etat::Invalide(e),
                },
                Ok((m, empreinte)) => {
                    let etat = if m.nom == nom {
                        match approuves.plugins.get(&nom) {
                            None => Etat::NonApprouve,
                            Some(a) if a.arbre != empreinte => Etat::Change,
                            Some(_) if m.commande(Systeme::ici()).is_none() => Etat::AutreSysteme,
                            Some(_) => Etat::Pret,
                        }
                    } else {
                        Etat::Invalide(trf!(
                            "le manifeste dit « {} »",
                            "the manifest says “{}”",
                            affichable(&m.nom)
                        ))
                    };
                    Plugin {
                        nom,
                        manifeste: Some(m),
                        empreinte: Some(empreinte),
                        etat,
                    }
                }
            }
        })
        .collect()
}

/// Les variables d'un plugin : le PATH du système (jamais celui de la personne, qu'un programme peut allonger), LANG,
/// HOME ; sous Windows, en plus, ce sans quoi PowerShell et la plupart des programmes ne démarrent pas. Aucune variable
/// de Vanguard (VANGUARD_*), ni rien d'autre de son environnement.
fn environnement(c: &mut Command) {
    c.env_clear();
    // La langue de l'interface de Vanguard (VANGUARD_LANG compris) : celle du système si elle est la même, pour
    // garder sa région (fr_CA), sinon la sienne.
    let langue = std::env::var("LANG")
        .ok()
        .filter(|l| l.starts_with(tr!("fr", "en")))
        .unwrap_or_else(|| tr!("fr_FR.UTF-8", "en_US.UTF-8").to_string());
    c.env("LANG", langue);
    c.env("PATH", path_systeme());
    #[cfg(unix)]
    {
        if let Some(h) = crate::socle::personnel::dossier_personnel() {
            c.env("HOME", h);
        }
    }
    #[cfg(windows)]
    {
        let racine = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        c.env("SystemRoot", &racine).env("windir", &racine);
        for v in [
            "SystemDrive",
            "USERPROFILE",
            "TEMP",
            "TMP",
            "APPDATA",
            "LOCALAPPDATA",
            "COMPUTERNAME",
            "USERNAME",
        ] {
            if let Some(x) = std::env::var_os(v) {
                c.env(v, x);
            }
        }
        if let Some(h) = std::env::var_os("USERPROFILE") {
            c.env("HOME", h);
        }
    }
}

/// Le PATH du système : jamais celui de la personne, qu'un programme peut allonger.
fn path_systeme() -> String {
    #[cfg(unix)]
    {
        PATH_SYSTEME.to_string()
    }
    #[cfg(windows)]
    {
        let racine = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        format!(r"{racine}\System32;{racine};{racine}\System32\Wbem;{racine}\System32\WindowsPowerShell\v1.0")
    }
}

/// Un programme du PATH du système (sous Windows, son « .exe »).
fn dans_le_path_systeme(nom: &str) -> Option<PathBuf> {
    let nom = if cfg!(windows) {
        format!("{nom}.exe")
    } else {
        nom.to_string()
    };
    let separateur = if cfg!(windows) { ';' } else { ':' };
    path_systeme()
        .split(separateur)
        .map(|d| Path::new(d).join(&nom))
        .find(|p| p.is_file() && du_systeme(p))
}

/// Un interpréteur du système : sous Unix, lui et chacun de ses dossiers (chemin réel) à root et fermés aux autres
/// comptes ; un pwsh ou un python3 qu'un compte peut remplacer n'est pas pris.
fn du_systeme(programme: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(reel) = std::fs::canonicalize(programme) else {
            return false;
        };
        reel.ancestors()
            .all(|p| std::fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0))
    }
    #[cfg(windows)]
    {
        let _ = programme;
        true
    }
}

// Sans /usr/local/bin ni /opt/homebrew/bin : sous macOS, Homebrew les donne au compte qui l'a installé, qui y
// poserait un faux pwsh ou python3 lancé ensuite sous un autre compte.
#[cfg(target_os = "macos")]
const PATH_SYSTEME: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
#[cfg(all(unix, not(target_os = "macos")))]
const PATH_SYSTEME: &str = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin";

/// Ce qui lance `programme` : un script shell par /bin/sh (une copie depuis une clé exFAT perd le droit d'exécution),
/// un script PowerShell par le PowerShell de System32 (Windows) ou pwsh (ailleurs), le reste directement. Rend le
/// programme à lancer et ses premiers arguments.
fn interprete(programme: &Path) -> Result<(PathBuf, Vec<String>), String> {
    let extension = programme
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    let chemin = programme.to_string_lossy().into_owned();
    match extension.as_deref() {
        #[cfg(unix)]
        Some("sh") => Ok(("/bin/sh".into(), vec![chemin])),
        // La stratégie d'exécution (Restricted par défaut sur un poste Windows) refuserait tout script : Bypass ne vaut
        // que pour ce processus, et ce script-là vient d'être vérifié par son empreinte.
        #[cfg(windows)]
        Some("ps1") => Ok((
            crate::machine::windows::powershell().get_program().into(),
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]
                .map(String::from)
                .into_iter()
                .chain([chemin])
                .collect(),
        )),
        #[cfg(unix)]
        Some("bash") => Ok(("/bin/bash".into(), vec![chemin])),
        #[cfg(unix)]
        Some("ps1") => dans_le_path_systeme("pwsh")
            .map(|p| {
                (
                    p,
                    vec!["-NoProfile".into(), "-NonInteractive".into(), "-File".into(), chemin],
                )
            })
            .ok_or_else(|| {
                tr!(
                    "pwsh est introuvable : un script PowerShell ne peut pas tourner ici",
                    "pwsh not found: a PowerShell script cannot run here"
                )
                .to_string()
            }),
        // Le python3 du système seulement : un python posé plus tôt dans le PATH de la personne ne sera pas pris.
        Some("py") => dans_le_path_systeme("python3")
            .map(|p| (p, vec![chemin]))
            .ok_or_else(|| tr!("python3 introuvable : non lancé", "python3 not found: not run").to_string()),
        _ => Ok((programme.to_path_buf(), Vec::new())),
    }
}

/// La commande telle qu'elle sera lancée, prête à montrer.
fn decrire(programme: &str, arguments: &[String]) -> String {
    let premier = interprete(Path::new(programme)).map_or_else(
        |_| programme.to_string(),
        |(p, a)| {
            let p = if a.is_empty() {
                programme.to_string()
            } else {
                p.file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
            };
            std::iter::once(p)
                .chain(a.into_iter().map(|x| {
                    if x.ends_with(programme) {
                        programme.to_string()
                    } else {
                        x
                    }
                }))
                .collect::<Vec<_>>()
                .join(" ")
        },
    );
    std::iter::once(premier)
        .chain(arguments.iter().map(|a| {
            if a.is_empty() || a.contains(char::is_whitespace) {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        }))
        .map(|t| commande_affichable(&t))
        .collect::<Vec<_>>()
        .join(" ")
}

/// L'analyse d'un plugin ou d'un script avant l'accord : les règles YARA et les empreintes de MalwareBazaar de
/// Vanguard, sur la copie qui sera approuvée. Une correspondance : `Err`, avec la règle (refusé). Une analyse
/// impossible : dite, et l'accord reste à demander. Rend la ligne à montrer.
fn analyser_avant_accord(chemin: &Path) -> Result<String, String> {
    use crate::protection::antivirus::Examen;
    let bazaar = crate::protection::empreintes::connues();
    match crate::protection::yara::examiner(chemin) {
        Examen::Trouve(regles) => Err(trf!(
            "Refusé : l'analyse de Vanguard reconnaît un logiciel malveillant ({}). Rien n'a été approuvé.",
            "Refused: Vanguard's scan recognizes malware ({}). Nothing was approved.",
            regles.iter().map(|r| affichable(r)).collect::<Vec<_>>().join(", ")
        )),
        Examen::Impossible(pourquoi) => Ok(trf!(
            "⚠ analyse impossible ({}) : rien ne dit qu'il est sain",
            "⚠ scan not possible ({}): nothing says it is safe",
            affichable(&pourquoi)
        )),
        Examen::Sain => Ok(match bazaar {
            Ok(e) => match &e.avertissement {
                None => tr!(
                    "aucune règle YARA ni empreinte MalwareBazaar ne correspond",
                    "no YARA rule nor MalwareBazaar fingerprint matches"
                )
                .to_string(),
                Some(a) => trf!(
                    "aucune règle YARA ni empreinte MalwareBazaar ne correspond (⚠ {a})",
                    "no YARA rule nor MalwareBazaar fingerprint matches (⚠ {a})"
                ),
            },
            Err(raison) => trf!(
                "aucune règle YARA ne correspond (⚠ empreintes MalwareBazaar {raison} : non comparées)",
                "no YARA rule matches (⚠ MalwareBazaar fingerprints {raison}: not compared)"
            ),
        }),
    }
}

/// Les fichiers d'un dossier et leur taille, chemins relatifs, dans l'ordre (sans suivre de lien).
fn fichiers_et_tailles(d: &Path) -> Vec<(String, u64)> {
    let mut liste = Vec::new();
    let mut a_voir = vec![d.to_path_buf()];
    while let Some(x) = a_voir.pop() {
        for e in std::fs::read_dir(&x).into_iter().flatten().flatten() {
            let Ok(m) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            if m.is_dir() {
                a_voir.push(e.path());
            } else {
                let relatif = e.path().strip_prefix(d).map_or_else(|_| e.path(), Path::to_path_buf);
                liste.push((relatif.to_string_lossy().into_owned(), m.len()));
            }
        }
    }
    liste.sort();
    liste
}

/// Une taille lisible : « 812 o », « 4,2 Kio », « 1,3 Mio ».
fn taille(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)] // une taille à montrer, au dixième
    let f = octets as f64;
    if octets < 1024 {
        trf!("{octets} o", "{octets} B")
    } else if octets < 1 << 20 {
        trf!("{} Kio", "{} KiB", crate::langue::decimal(f / 1024.0, 1))
    } else {
        trf!("{} Mio", "{} MiB", crate::langue::decimal(f / f64::from(1u32 << 20), 1))
    }
}

/// Le rappel montré avant chaque accord.
fn rappel(texte: &str) {
    for (i, l) in envelopper(texte, LARGEUR - 4).iter().enumerate() {
        let marque = if i == 0 {
            format!("{}⚠{RESET}", couleur(crate::risk::Niveau::Moyen))
        } else {
            " ".to_string()
        };
        println!("  {marque} {l}");
    }
}

/// Ce que l'approbation montre : nom, auteur et source (non vérifiés), ce qu'il lancera, ses fichiers et leur taille,
/// les empreintes notées, ce que le manifeste demande, et le résultat de l'analyse. `copie` : le dossier tel qu'il
/// sera approuvé.
fn presenter(
    copie: &Path,
    destination: &Path,
    m: &Manifeste,
    fichiers: &Fichiers,
    analyse: &str,
    cle_auteur: Option<&[u8; 32]>,
) {
    println!();
    trp!(
        "  {GRAS}Plugin « {} »{RESET} ({})",
        "  {GRAS}Plugin “{}”{RESET} ({})",
        affichable(m.titre()),
        affichable(&m.nom)
    );
    afficher_aligne("  ", &affichable(m.description()), 2, GRIS);
    let non_verifie = tr!("non vérifié par Vanguard", "not checked by Vanguard");
    // Signé : le nom reste celui que le manifeste dit, mais tout le dossier vient de qui tient cette clé.
    let signe = cle_auteur.map(|c| {
        let h = hex(c);
        trf!(
            "signé par la clé {}…, signature vérifiée",
            "signed by key {}…, signature checked",
            &h[..16]
        )
    });
    for (libelle, valeur, verifie) in [
        (tr!("  Auteur     : ", "  Author     : "), &m.auteur, signe.as_deref()),
        (tr!("  Source     : ", "  Source     : "), &m.source, None),
    ] {
        let etat = verifie.unwrap_or(non_verifie);
        let texte = valeur.as_deref().map_or_else(
            || trf!("non dit ({etat})", "not given ({etat})"),
            |v| format!("{} ({etat})", affichable(v)),
        );
        afficher_aligne(libelle, &texte, 15, "");
    }
    let systemes: Vec<&str> = m.systemes.iter().map(|s| s.nom()).collect();
    trp!("  Systèmes   : {}", "  Systems    : {}", systemes.join(", "));
    match m.commande(Systeme::ici()) {
        Some(c) => afficher_aligne(
            &trf!("  Lancera    : ", "  Will run   : "),
            &decrire(&c.programme, &c.arguments),
            15,
            "",
        ),
        None => trp!(
            "  Lancera    : rien ici (ne vise pas ce système)",
            "  Will run   : nothing here (does not target this system)"
        ),
    }
    trp!(
        "  Au plus    : {} s, sans droits d'administrateur",
        "  At most    : {} s, without administrator rights",
        m.delai
    );
    afficher_aligne(
        &trf!("  Dossier    : ", "  Folder     : "),
        &chemin_affichable(destination),
        15,
        "",
    );
    let tailles = fichiers_et_tailles(copie);
    trp!(
        "  Fichiers ({}, {}) :",
        "  Files ({}, {}):",
        tailles.len(),
        taille(tailles.iter().map(|f| f.1).sum())
    );
    for (f, o) in tailles.iter().take(30) {
        println!("    {}  {GRIS}{}{RESET}", couper(&affichable(f), 56), taille(*o));
    }
    if tailles.len() > 30 {
        trp!("    … et {} autre(s)", "    … and {} more", tailles.len() - 30);
    }
    trp!(
        "  Empreinte du dossier (SHA-256 de chaque fichier) :",
        "  Folder fingerprint (SHA-256 of each file):"
    );
    println!("    {GRIS}{}{RESET}", empreinte_arbre(fichiers));
    if let Some(c) = m.commande(Systeme::ici())
        && let Some(e) = fichiers.get(&c.programme)
    {
        trp!("  Programme  : {}", "  Program    : {}", affichable(&c.programme));
        println!("    {GRIS}{e}{RESET}");
    }
    // Ce que le manifeste demande n'est jamais accordé par lui : une question à part, après l'approbation.
    let mut demandes = Vec::new();
    if m.confiance_totale {
        demandes.push(tr!(
            "la confiance totale (sans restrictions)",
            "full trust (no restrictions)"
        ));
    }
    if m.dans_le_bilan {
        demandes.push(tr!("tourner avec le bilan", "running with the check-up"));
    }
    if m.dans_la_surveillance {
        demandes.push(tr!("tourner avec la surveillance", "running with monitoring"));
    }
    if !demandes.is_empty() {
        afficher_aligne(
            &format!(
                "  {}{}{RESET}",
                couleur(crate::risk::Niveau::Eleve),
                tr!("Il demande : ", "It asks for: ")
            ),
            &trf!(
                "{} — rien de cela n'est accordé sans votre réponse à une question à part",
                "{} — none of it is granted without your answer to a separate question",
                demandes.join(", ")
            ),
            15,
            "",
        );
    }
    afficher_aligne(&trf!("  Analyse    : ", "  Scan       : "), analyse, 15, "");
    println!();
    rappel(tr!(
        "Un plugin n'est pas du code de Vanguard : ce programme pourra lire et modifier vos fichiers, comme vous, et parler au réseau. N'approuvez que ce que vous avez écrit ou relu. S'il change, Vanguard le refusera jusqu'à une nouvelle approbation.",
        "A plugin is not Vanguard's code: this program will be able to read and change your files, like you, and talk to the network. Only approve what you wrote or reviewed. If it changes, Vanguard will refuse it until approved again."
    ));
}

/// Une copie en cours (ajout ou lancement), retirée quoi qu'il arrive.
struct Temporaire(PathBuf);

impl Temporaire {
    /// Un dossier caché du dossier des plugins, réservé à son compte, qui ne doit pas déjà exister : rien de posé
    /// d'avance n'est repris.
    fn creer(racine: &Path, quoi: &str) -> Result<Temporaire, String> {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = racine.join(format!(".{quoi}-{}-{n}", std::process::id()));
        #[cfg_attr(windows, allow(unused_mut))]
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&d).map_err(|e| e.to_string())?;
        Ok(Temporaire(d))
    }
}

impl Drop for Temporaire {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Les copies laissées par un Vanguard arrêté net (plus d'une heure) : retirées.
fn menage(racine: &Path) {
    let vieux = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    for e in std::fs::read_dir(racine).into_iter().flatten().flatten() {
        let nom = e.file_name().to_string_lossy().into_owned();
        if (nom.starts_with(".lancement-") || nom.starts_with(".ajout-"))
            && e.metadata().and_then(|m| m.modified()).is_ok_and(|t| t < vieux)
        {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// `vanguard plugins ajouter <dossier ou archive.zip>` : copie le plugin dans le dossier des plugins, l'analyse, montre
/// ce qu'il lancera, et l'approuve sur accord. Ce qui est montré, analysé et haché est la copie, pas l'original : c'est
/// elle qui tournera. Une archive est d'abord dépliée à l'écart (`archive`). Rend le nom.
fn ajouter(racine: &Path, source: &Path, accord: impl FnMut(&str) -> bool) -> Result<String, String> {
    if eleve() {
        return Err(refus_eleve());
    }
    menage(racine);
    let est_zip = source.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip"));
    if !est_zip {
        let source_reelle =
            std::fs::canonicalize(source).map_err(|e| trf!("{} : {e}", "{}: {e}", chemin_affichable(source)))?;
        if std::fs::canonicalize(racine).is_ok_and(|r| source_reelle.starts_with(r)) {
            return Err(tr!(
                "Ce dossier est déjà dans celui des plugins : « vanguard plugins approuver <nom> ».",
                "This folder is already in the plugins folder: “vanguard plugins approve <name>”."
            )
            .to_string());
        }
        return ajouter_dossier(racine, source, accord);
    }
    let depliage = Temporaire::creer(racine, "ajout")?;
    archive::deplier(source, &depliage.0).map_err(|e| trf!("Plugin non ajouté : {e}.", "Plugin not added: {e}."))?;
    // Le manifeste à la racine de l'archive, ou dans son seul dossier (une archive faite d'un dossier entier).
    let mut d = depliage.0.clone();
    if !d.join(MANIFESTE).exists() {
        let dossiers: Vec<PathBuf> = std::fs::read_dir(&d)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        if let [seul] = &dossiers[..] {
            d.clone_from(seul);
        }
    }
    ajouter_dossier(racine, &d, accord)
}

fn ajouter_dossier(racine: &Path, source: &Path, mut accord: impl FnMut(&str) -> bool) -> Result<String, String> {
    let essai = Temporaire::creer(racine, "ajout")?;
    let copie = essai.0.join("plugin");
    creer_prive(&copie).map_err(|e| e.to_string())?;
    let fichiers =
        arbre(source, Some(&copie), false).map_err(|e| trf!("Plugin non ajouté : {e}.", "Plugin not added: {e}."))?;
    let (m, _) = lire_manifeste(&copie)?;
    let destination = racine.join(&m.nom);
    let cle =
        auteur_verifie(&m, &copie, &fichiers).map_err(|e| trf!("Plugin non ajouté : {e}", "Plugin not added: {e}"))?;
    let analyse = analyser_avant_accord(&copie)?;
    presenter(&copie, &destination, &m, &fichiers, &analyse, cle.as_ref());
    if destination.exists() {
        comparer_auteur(approbations(racine).plugins.get(&m.nom), cle.as_ref());
    }
    let question = if destination.exists() {
        trf!(
            "\n  Un plugin « {} » est déjà là : le remplacer par celui-ci et l'approuver ? [o/N] : ",
            "\n  A plugin “{}” is already there: replace it with this one and approve it? [y/N]: ",
            m.nom
        )
    } else {
        trf!(
            "\n  Ajouter ce plugin et l'approuver ? [o/N] : ",
            "\n  Add this plugin and approve it? [y/N]: "
        )
    };
    if !accord(&question) {
        return Err(tr!("Rien n'a été ajouté.", "Nothing was added.").to_string());
    }
    if destination.exists() {
        let ancien = Temporaire::creer(racine, "ajout")?;
        std::fs::rename(&destination, ancien.0.join("ancien")).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&copie, &destination).map_err(|e| e.to_string())?;
    // Un plugin remplacé perd la confiance de l'ancien.
    reglages::oublier(racine, false, &m.nom)?;
    noter(racine, &m.nom, fichiers.clone(), cle.as_ref())?;
    demander_confiance(racine, &m, &empreinte_arbre(&fichiers), &mut accord)?;
    Ok(m.nom)
}

/// Ce que le manifeste demande (confiance totale, bilan, surveillance), accordé seulement par une question à part, et
/// noté avec l'empreinte du dossier : s'il change, la confiance tombe.
fn demander_confiance(
    racine: &Path,
    m: &Manifeste,
    empreinte: &str,
    accord: &mut impl FnMut(&str) -> bool,
) -> Result<(), String> {
    if !(m.confiance_totale || m.dans_le_bilan || m.dans_la_surveillance) {
        return Ok(());
    }
    let mut quoi = vec![tr!("sans restrictions", "without restrictions")];
    if m.dans_le_bilan {
        quoi.push(tr!("avec chaque bilan complet", "with each full check-up"));
    }
    if m.dans_la_surveillance {
        quoi.push(tr!("avec chaque passe de la surveillance", "with each monitoring pass"));
    }
    if accord(&trf!(
        "  Ce plugin demande de tourner {}, avec tous vos droits. L'accorder (tant qu'il ne change pas) ? [o/N] : ",
        "  This plugin asks to run {}, with all your rights. Grant it (as long as it does not change)? [y/N]: ",
        quoi.join(", ")
    )) {
        reglages::accorder(
            racine,
            false,
            &m.nom,
            empreinte,
            m.dans_le_bilan,
            m.dans_la_surveillance,
        )?;
    }
    Ok(())
}

fn noter(racine: &Path, nom: &str, fichiers: Fichiers, cle_auteur: Option<&[u8; 32]>) -> Result<(), String> {
    let mut a = approbations(racine);
    a.plugins.insert(
        nom.to_string(),
        Approbation {
            arbre: empreinte_arbre(&fichiers),
            fichiers,
            le: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
            cle_auteur: cle_auteur.map(|c| hex(c)),
        },
    );
    enregistrer(racine, &a)
}

/// `vanguard plugins approuver <nom>` : le plugin tel qu'il est maintenant dans son dossier, copié, remontré, puis
/// approuvé (ce qui est approuvé est ce qui a été montré).
fn approuver(racine: &Path, nom: &str, mut accord: impl FnMut(&str) -> bool) -> Result<(), String> {
    if eleve() {
        return Err(refus_eleve());
    }
    let d = dossier_du_plugin(racine, nom)?;
    menage(racine);
    let essai = Temporaire::creer(racine, "ajout")?;
    let copie = essai.0.join(nom);
    creer_prive(&copie).map_err(|e| e.to_string())?;
    let fichiers = arbre(&d, Some(&copie), true)?;
    let (m, _) = lire_manifeste(&copie)?;
    if m.nom != nom {
        return Err(trf!(
            "Le manifeste de « {nom} » dit « {} » : refusé.",
            "The manifest of “{nom}” says “{}”: refused.",
            affichable(&m.nom)
        ));
    }
    let avant = approbations(racine).plugins.get(nom).cloned();
    let cle = auteur_verifie(&m, &copie, &fichiers)?;
    let analyse = analyser_avant_accord(&copie)?;
    presenter(&copie, &d, &m, &fichiers, &analyse, cle.as_ref());
    comparer_auteur(avant.as_ref(), cle.as_ref());
    if let Some(a) = &avant {
        let changes = changements(&a.fichiers, &fichiers);
        if changes.is_empty() {
            trp!(
                "\n  Rien n'a changé depuis l'approbation du {}.",
                "\n  Nothing changed since the approval of {}.",
                affichable(&a.le)
            );
            return Ok(());
        }
        trp!(
            "\n  Changé depuis l'approbation du {} : {}",
            "\n  Changed since the approval of {}: {}",
            affichable(&a.le),
            changes.join(", ")
        );
    }
    if !accord(&trf!(
        "\n  Approuver ce plugin tel quel ? [o/N] : ",
        "\n  Approve this plugin as it is? [y/N]: "
    )) {
        return Err(tr!("Rien n'a été approuvé.", "Nothing was approved.").to_string());
    }
    let empreinte = empreinte_arbre(&fichiers);
    noter(racine, nom, fichiers, cle.as_ref())?;
    demander_confiance(racine, &m, &empreinte, &mut accord)
}

/// Le dossier d'un plugin, jugé : un nom valide, un dossier sûr.
fn dossier_du_plugin(racine: &Path, nom: &str) -> Result<PathBuf, String> {
    if !manifeste::nom_valide(nom) {
        return Err(trf!(
            "« {} » n'est pas un nom de plugin.",
            "“{}” is not a plugin name.",
            affichable(nom)
        ));
    }
    let d = racine.join(nom);
    if std::fs::symlink_metadata(&d).is_err() {
        return Err(trf!(
            "Aucun plugin « {nom} » : « vanguard plugins liste ».",
            "No plugin “{nom}”: “vanguard plugins list”."
        ));
    }
    dossier_sur(&d)?;
    Ok(d)
}

/// `vanguard plugins retirer <nom>` : son dossier, son approbation, sa confiance et ses constats gardés, sur accord.
fn retirer(racine: &Path, nom: &str, accord: impl FnOnce(&str) -> bool) -> Result<bool, String> {
    if !manifeste::nom_valide(nom) {
        return Err(trf!(
            "« {} » n'est pas un nom de plugin.",
            "“{}” is not a plugin name.",
            affichable(nom)
        ));
    }
    let d = racine.join(nom);
    let mut a = approbations(racine);
    if std::fs::symlink_metadata(&d).is_err() && !a.plugins.contains_key(nom) {
        return Err(trf!("Aucun plugin « {nom} ».", "No plugin “{nom}”."));
    }
    if !accord(&trf!(
        "  Retirer le plugin « {nom} » (son dossier et son approbation) ? [o/N] : ",
        "  Remove the plugin “{nom}” (its folder and its approval)? [y/N]: "
    )) {
        return Ok(false);
    }
    // Un lien posé à la place du dossier est retiré lui-même, sans suivre ce qu'il désigne.
    match std::fs::symlink_metadata(&d) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(&d).map_err(|e| e.to_string())?,
        Ok(_) => std::fs::remove_file(&d).map_err(|e| e.to_string())?,
        Err(_) => {}
    }
    let _ = std::fs::remove_file(racine.join(CONSTATS).join(format!("{nom}.json")));
    reglages::oublier(racine, false, nom)?;
    if a.plugins.remove(nom).is_some() {
        enregistrer(racine, &a)?;
    }
    Ok(true)
}

/// Un plugin qui a tourné.
pub struct Issue {
    pub manifeste: Manifeste,
    pub borne: crate::commande::Borne,
}

/// Lancé tout seul, avec le bilan complet ou la surveillance : seulement si la personne l'a accordé pour ce plugin
/// tel qu'il est.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auto {
    Bilan,
    Surveillance,
}

/// Comment lancer : `isole` (Linux : bubblewrap ; macOS : sandbox-exec) sans réseau, dossier personnel invisible ;
/// `auto`, sans personne devant l'écran.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Facon {
    pub isole: bool,
    pub auto: Option<Auto>,
}

/// La commande d'un programme d'extension : son interpréteur, ses arguments, son dossier comme dossier courant ;
/// l'environnement minimal sauf sans restrictions (`libre`) ; dans bubblewrap avec `isole` (alors `jetable` reçoit
/// la seule écriture permise). Le programme perd le terminal (nouvelle session sous Unix, pas de console sous
/// Windows) : il ne peut plus y écrire en passant à côté du filtre de sa sortie, ni y lire les frappes.
fn commande_de(
    programme: &Path,
    arguments: &[String],
    dossier: &Path,
    libre: bool,
    isole: Option<&Path>,
) -> Result<Command, String> {
    let (p, premiers) = interprete(programme)?;
    let tout: Vec<String> = premiers.into_iter().chain(arguments.iter().cloned()).collect();
    let mut c = match isole {
        None => {
            let mut c = Command::new(p);
            c.args(&tout);
            c
        }
        #[cfg(target_os = "linux")]
        Some(jetable) => {
            let ligne: Vec<String> = std::iter::once(p.to_string_lossy().into_owned()).chain(tout).collect();
            let a = crate::protection::isoler::arguments_extension(jetable, dossier, &ligne).ok_or_else(|| {
                tr!(
                    "Isolement impossible : bubblewrap (bwrap) n'est pas installé.",
                    "Isolation not possible: bubblewrap (bwrap) is not installed."
                )
                .to_string()
            })?;
            let mut c = Command::new(dans_le_path_systeme("bwrap").unwrap_or_else(|| "bwrap".into()));
            c.args(a);
            c
        }
        // macOS : sandbox-exec, le bac à sable du système, avec le profil de `isoler` (pas de réseau, dossier
        // personnel illisible, écriture dans le jetable seulement).
        #[cfg(target_os = "macos")]
        Some(jetable) => {
            let ligne: Vec<String> = std::iter::once(p.to_string_lossy().into_owned()).chain(tout).collect();
            let a = crate::protection::isoler::arguments_extension(jetable, dossier, &ligne).ok_or_else(|| {
                tr!(
                    "Isolement impossible : sandbox-exec n'est pas là.",
                    "Isolation not possible: sandbox-exec is not there."
                )
                .to_string()
            })?;
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.args(a);
            c
        }
        // Windows Sandbox est une machine à part, effacée à la fermeture : la sortie de l'extension n'en reviendrait
        // pas à Vanguard (ni son filtre, ni ses constats). Sans équivalent léger dans le système, l'isolement est dit
        // indisponible, jamais promis.
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Some(_) => {
            return Err(tr!(
                "Isolement non disponible sous Windows : Windows Sandbox est une machine à part, d'où la sortie de l'extension ne reviendrait pas.",
                "Isolation not available on Windows: Windows Sandbox is a separate machine, from which the extension's output would not come back."
            )
            .to_string());
        }
    };
    c.current_dir(dossier);
    if !libre {
        environnement(&mut c);
    }
    // Isolée sous macOS, l'extension écrit chez elle dans le jetable : son dossier personnel est illisible.
    #[cfg(target_os = "macos")]
    if let Some(j) = isole {
        c.env("HOME", j).env("TMPDIR", j);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY : entre fork et exec, seul setsid est appelé ; il est sûr dans ce contexte (async-signal-safe, il
        // n'alloue rien et ne prend aucun verrou). Son échec (déjà chef de groupe) ne change rien : on continue.
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut c, 0x0800_0000); // CREATE_NO_WINDOW
    Ok(c)
}

/// En administrateur, rien de ce que contient le dossier des extensions ne peut lever une garde (tout processus du
/// compte peut l'écrire, sous Windows même sans élévation) : chaque lancement est montré, avec son empreinte, et
/// demandé à la personne, à chaque fois.
fn accord_administrateur(nom: &str, empreinte: &str) -> bool {
    trp!(
        "\n  {}⚠ Vanguard est en administrateur.{RESET} « {} » tournerait avec tous les droits sur l'ordinateur.",
        "\n  {}⚠ Vanguard is running as administrator.{RESET} “{}” would run with every right on the computer.",
        couleur(crate::risk::Niveau::Eleve),
        affichable(nom)
    );
    trp!("  Empreinte : {}", "  Fingerprint: {}", empreinte);
    demander(tr!(
        "  Le lancer quand même, cette fois seulement ? [o/N] : ",
        "  Run it anyway, this time only? [y/N]: "
    ))
    .oui()
}

/// Lance le plugin `nom`, avec `arguments` après ses arguments fixes. Tout son dossier est copié en étant haché, et
/// c'est la copie qui tourne, son dossier comme dossier courant : l'empreinte doit être celle de l'approbation, ou
/// celle que la personne a marquée « à moi » (alors sans restrictions : environnement complet, bornes larges).
/// En administrateur : rien n'est lancé tout seul, et chaque lancement est demandé (`accord_administrateur`).
/// Interrupteur général coupé (jamais en administrateur, jamais tout seul) : l'original, sans copie ni empreinte.
pub fn lancer(racine: &Path, nom: &str, arguments: &[String], facon: Facon) -> Result<Issue, String> {
    if arguments.len() > ARGUMENTS_MAX || arguments.iter().any(|a| a.len() > ARGUMENT_MAX || a.contains('\0')) {
        return Err(trf!(
            "Trop d'arguments, ou trop longs ({ARGUMENTS_MAX} de {ARGUMENT_MAX} caractères au plus).",
            "Too many arguments, or too long ({ARGUMENTS_MAX} of {ARGUMENT_MAX} characters at most)."
        ));
    }
    let administrateur = eleve();
    if administrateur && facon.auto.is_some() {
        return Err(refus_eleve());
    }
    let d = dossier_du_plugin(racine, nom)?;
    let refuse_change = || {
        trf!(
            "Le plugin « {nom} » a changé depuis son approbation : refusé. Relisez-le, puis « vanguard plugins approuver {nom} ».",
            "The plugin “{nom}” changed since it was approved: refused. Review it, then “vanguard plugins approve {nom}”."
        )
    };
    let commande_ici = |m: &Manifeste| {
        if m.nom != nom {
            return Err(refuse_change());
        }
        m.commande(Systeme::ici()).cloned().ok_or_else(|| {
            trf!(
                "Le plugin « {nom} » ne vise pas ce système ({}).",
                "The plugin “{nom}” does not target this system ({}).",
                Systeme::ici().nom()
            )
        })
    };
    // En administrateur, les réglages (écrits par n'importe quel processus du compte) ne lèvent rien.
    let reglages = if administrateur {
        reglages::Reglages::default()
    } else {
        reglages::charger(racine)
    };
    menage(racine);
    let essai = Temporaire::creer(racine, "lancement")?;
    let isole = facon.isole.then_some(essai.0.as_path());
    let mut commande;
    let (manifeste, delai, sortie);
    if reglages.sans_restrictions && facon.auto.is_none() {
        let (m, _) = lire_manifeste(&d)?;
        let c = commande_ici(&m)?;
        verifier_chemin(&d, &c.programme)?;
        let tous: Vec<String> = c.arguments.iter().chain(arguments).cloned().collect();
        commande = commande_de(&chemin_du_programme(&d, &c.programme), &tous, &d, true, isole)?;
        (delai, sortie) = (reglages::DELAI_LIBRE.max(m.delai), reglages::SORTIE_LIBRE);
        manifeste = m;
    } else {
        let copie = essai.0.join(nom);
        creer_prive(&copie).map_err(|e| e.to_string())?;
        let fichiers = arbre(&d, Some(&copie), true)?;
        let empreinte = empreinte_arbre(&fichiers);
        let (m, _) = lire_manifeste(&copie)?;
        let c = commande_ici(&m)?;
        let confiance = reglages.plugin_a_moi(nom, &empreinte);
        let approuve = approbations(racine).plugins.get(nom).map(|a| a.arbre == empreinte);
        let libre = match facon.auto {
            Some(quand) => {
                let accorde = confiance.is_some_and(|k| match quand {
                    Auto::Bilan => k.bilan && m.dans_le_bilan,
                    Auto::Surveillance => k.surveillance && m.dans_la_surveillance,
                });
                if !accorde {
                    return Err(tr!("non accordé", "not granted").to_string());
                }
                true
            }
            None if administrateur => {
                if !accord_administrateur(nom, &empreinte) {
                    return Err(tr!("Non lancé.", "Not run.").to_string());
                }
                false
            }
            None if confiance.is_some() => true,
            None => match approuve {
                Some(true) => false,
                Some(false) => return Err(refuse_change()),
                None => {
                    let mut refus = trf!(
                        "Le plugin « {nom} » n'est pas approuvé : « vanguard plugins approuver {nom} » montre ce qu'il lancera.",
                        "The plugin “{nom}” is not approved: “vanguard plugins approve {nom}” shows what it will run."
                    );
                    // Une approbation ignorée (fichier changé hors de Vanguard) : dite, pour que la personne sache
                    // pourquoi on la redemande.
                    if let Some(d) = approbations_jugees(racine).1 {
                        refus += &trf!(
                            " Les approbations ont été ignorées : {}.",
                            " The approvals were ignored: {}.",
                            d.texte()
                        );
                    }
                    return Err(refus);
                }
            },
        };
        let tous: Vec<String> = c.arguments.iter().chain(arguments).cloned().collect();
        commande = commande_de(&chemin_du_programme(&copie, &c.programme), &tous, &copie, libre, isole)?;
        (delai, sortie) = if libre {
            (reglages::DELAI_LIBRE.max(m.delai), reglages::SORTIE_LIBRE)
        } else {
            (m.delai, SORTIE_MAX)
        };
        manifeste = m;
    }
    let borne = crate::commande::lancer_borne(&mut commande, delai, sortie).ok_or_else(|| {
        trf!(
            "Le plugin « {nom} » n'a pas pu démarrer.",
            "The plugin “{nom}” could not start."
        )
    })?;
    drop(essai);
    Ok(Issue { manifeste, borne })
}

/// `vanguard plugins …` : rend le code de sortie (celui du plugin lancé, sinon 0 ou 1).
pub fn commande(quoi: &[String]) -> i32 {
    let Some(mot) = quoi.first().map(String::as_str) else {
        return match dossier() {
            Ok(r) => {
                menu::plugins(&r);
                0
            }
            Err(e) => echec(&e),
        };
    };
    if matches!(mot, "liste" | "list") {
        return match dossier() {
            Ok(r) => {
                liste(&r);
                0
            }
            Err(e) => echec(&e),
        };
    }
    // Ajouter et approuver refusent l'administrateur d'eux-mêmes ; retirer reste permis : ça n'exécute rien.
    let racine = match dossier() {
        Ok(r) => r,
        Err(e) => return echec(&e),
    };
    let accord = |q: &str| demander(q).oui();
    let deuxieme = quoi.get(1).map(String::as_str);
    let resultat = match (mot, deuxieme) {
        ("ajouter" | "add", Some(source)) => ajouter(&racine, Path::new(source), accord).map(|nom| {
            trp!(
                "  {VERT}✔{RESET} Plugin « {nom} » ajouté et approuvé : « vanguard plugins {nom} » le lance.",
                "  {VERT}✔{RESET} Plugin “{nom}” added and approved: “vanguard plugins {nom}” runs it."
            );
        }),
        ("approuver" | "approve", Some(nom)) => approuver(&racine, nom, accord).map(|()| {
            trp!("  {VERT}✔{RESET} Approuvé.", "  {VERT}✔{RESET} Approved.");
        }),
        ("retirer" | "remove", Some(nom)) => retirer(&racine, nom, accord).map(|fait| {
            if fait {
                trp!("  {VERT}✔{RESET} Retiré.", "  {VERT}✔{RESET} Removed.");
            }
        }),
        ("ajouter" | "add" | "approuver" | "approve" | "retirer" | "remove", None) => Err(trf!(
            "Il manque le dossier ou le nom : « vanguard plugins {mot} <…> ».",
            "The folder or the name is missing: “vanguard plugins {mot} <…>”."
        )),
        (nom, _) => {
            let (rapport, facon, arguments) = options_de_lancement(&quoi[1..]);
            return executer(&racine, nom, &arguments, rapport, facon);
        }
    };
    match resultat {
        Ok(()) => 0,
        Err(e) => echec(&e),
    }
}

/// `--rapport` (n'importe où avant `--`) est pour Vanguard ; tout le reste, et tout ce qui suit `--`, pour le plugin.
fn options_de_lancement(args: &[String]) -> (bool, Facon, Vec<String>) {
    let mut rapport = false;
    let mut facon = Facon::default();
    let mut pour_le_plugin = Vec::new();
    let mut apres = false;
    for a in args {
        match a.as_str() {
            "--" if !apres => apres = true,
            "--rapport" | "--report" if !apres => rapport = true,
            "--isole" | "--isolated" if !apres => facon.isole = true,
            _ => pour_le_plugin.push(a.clone()),
        }
    }
    (rapport, facon, pour_le_plugin)
}

fn echec(e: &str) -> i32 {
    afficher_aligne(&format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)), e, 4, "");
    1
}

/// Lance un plugin et montre ce qu'il a dit ; avec `rapport`, ses constats sont gardés pour le rapport HTML.
fn executer(racine: &Path, nom: &str, arguments: &[String], rapport: bool, facon: Facon) -> i32 {
    if let Ok(d) = dossier_du_plugin(racine, nom)
        && let Ok((m, _)) = lire_manifeste(&d)
    {
        titre(&trf!(
            "Plugin « {} » — hors code de Vanguard",
            "Plugin “{}” — not Vanguard's code",
            affichable(m.titre())
        ));
        trp!(
            "  {GRIS}En cours (au plus {} s)…{RESET}",
            "  {GRIS}Running (at most {} s)…{RESET}",
            m.delai
        );
    }
    match lancer(racine, nom, arguments, facon) {
        Err(e) => echec(&e),
        Ok(issue) => {
            let lu = sortie::analyser(&issue.borne.sortie);
            sortie::afficher(
                &format!("plugin {nom}"),
                issue.manifeste.titre(),
                issue.manifeste.delai,
                &issue.borne,
                &lu,
            );
            if rapport {
                match sortie::garder(racine, &issue.manifeste, &lu.constats) {
                    Ok(()) => trp!(
                        "\n  {GRIS}Constats gardés pour le rapport HTML (section Plugins) : menu 3, ou « vanguard bilan --html ».{RESET}",
                        "\n  {GRIS}Findings kept for the HTML report (Plugins section): menu 3, or “vanguard check --html”.{RESET}"
                    ),
                    Err(e) => {
                        echec(&e);
                    }
                }
            }
            issue.borne.code.unwrap_or(1)
        }
    }
}

/// `vanguard plugins liste` : chaque plugin du dossier et son état.
fn liste(racine: &Path) {
    titre(tr!("Plugins", "Plugins"));
    afficher_aligne(
        &trf!("  {GRIS}Dossier : ", "  {GRIS}Folder: "),
        &chemin_affichable(racine),
        4,
        GRIS,
    );
    dire_douteux(racine);
    let plugins = inventaire(racine);
    if plugins.is_empty() {
        aide_ajout();
        return;
    }
    let approuves = approbations(racine);
    for p in &plugins {
        let (marque, etat) = match &p.etat {
            Etat::Pret => (
                format!("{VERT}✔{RESET}"),
                trf!(
                    "approuvé le {}",
                    "approved on {}",
                    approuves.plugins.get(&p.nom).map_or("?", |a| a.le.as_str())
                ),
            ),
            Etat::NonApprouve => (
                format!("{}•{RESET}", couleur(crate::risk::Niveau::Moyen)),
                trf!(
                    "pas approuvé : vanguard plugins approuver {}",
                    "not approved: vanguard plugins approve {}",
                    p.nom
                ),
            ),
            Etat::Change => (
                format!("{}✖{RESET}", couleur(crate::risk::Niveau::Eleve)),
                trf!(
                    "a changé depuis son approbation : refusé (vanguard plugins approuver {})",
                    "changed since its approval: refused (vanguard plugins approve {})",
                    p.nom
                ),
            ),
            Etat::AutreSysteme => (
                format!("{GRIS}–{RESET}"),
                tr!(
                    "approuvé, ne vise pas ce système",
                    "approved, does not target this system"
                )
                .to_string(),
            ),
            Etat::Invalide(e) => (
                format!("{}✖{RESET}", couleur(crate::risk::Niveau::Eleve)),
                affichable(e),
            ),
        };
        let titre = p
            .manifeste
            .as_ref()
            .map(|m| format!(" — {}", affichable(m.titre())))
            .unwrap_or_default();
        afficher_aligne(&format!("  {marque} "), &format!("{}{titre}", p.nom), 4, GRAS);
        afficher_aligne("    ", &etat, 4, GRIS);
    }
}

fn aide_ajout() {
    trp!(
        "  Aucun plugin. Un plugin est un programme à vous (script, programme) dans un dossier avec un plugin.toml ; « vanguard plugins ajouter <dossier> » le copie ici et l'approuve. Un exemple : extensions/exemples/exemple dans les sources de Vanguard.",
        "  No plugin. A plugin is a program of yours (script, program) in a folder with a plugin.toml; “vanguard plugins add <folder>” copies it here and approves it. An example: extensions/exemples/exemple in Vanguard's sources."
    );
}

/// Les plugins à qui la personne a accordé de tourner avec le bilan (ou la surveillance, selon `surveillance`) et
/// qui le demandent encore, tels qu'ils étaient quand elle l'a accordé (`Facon::auto`), lancés l'un après l'autre.
/// Jamais en administrateur : le dossier serait alors un moyen de faire lancer du code avec tous les droits. Rien si
/// le dossier n'est pas sûr.
fn opt_in(surveillance: bool) -> Vec<(Manifeste, Vec<sortie::ConstatPlugin>)> {
    if eleve() {
        return Vec::new();
    }
    let Ok(racine) = dossier() else {
        return Vec::new();
    };
    let reglages = reglages::charger(&racine);
    let quand = if surveillance { Auto::Surveillance } else { Auto::Bilan };
    inventaire(&racine)
        .into_iter()
        .filter(|p| {
            p.empreinte
                .as_deref()
                .and_then(|e| reglages.plugin_a_moi(&p.nom, e))
                .is_some_and(|k| if surveillance { k.surveillance } else { k.bilan })
        })
        .filter_map(|p| {
            let issue = lancer(
                &racine,
                &p.nom,
                &[],
                Facon {
                    isole: false,
                    auto: Some(quand),
                },
            )
            .ok()?;
            let lu = sortie::analyser(&issue.borne.sortie);
            if !surveillance {
                let _ = sortie::garder(&racine, &issue.manifeste, &lu.constats);
            }
            Some((issue.manifeste, lu.constats))
        })
        .collect()
}

/// Avec le bilan complet : les plugins qui l'ont demandé, et leurs constats, à part et hors de la note.
pub fn avec_le_bilan() {
    // Des extensions qui ne tournent plus avec le bilan parce que leurs réglages sont ignorés : dit ici aussi, là où
    // on les attendait.
    if let Ok(racine) = dossier() {
        dire_douteux(&racine);
    }
    for (m, constats) in opt_in(false) {
        sortie::afficher_constats(&format!("extension {}", m.nom), m.titre(), &constats);
    }
}

/// Avec la surveillance : une notification par plugin qui l'a demandé et signale un problème élevé ou critique.
pub fn a_signaler() -> Vec<(String, String)> {
    opt_in(true)
        .into_iter()
        .filter_map(|(m, constats)| {
            let graves: Vec<String> = constats
                .iter()
                .filter(|c| {
                    matches!(
                        c.probleme(),
                        Some(crate::risk::Niveau::Eleve | crate::risk::Niveau::Critique)
                    )
                })
                // Le corps d'une notification est du balisage pour la plupart des serveurs (lien, image) : échappé.
                .map(|c| {
                    format!("{} : {}", c.categorie, c.message)
                        .replace('&', "&amp;")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;")
                })
                .collect();
            (!graves.is_empty()).then(|| {
                (
                    trf!(
                        "Vanguard : extension « {} »",
                        "Vanguard: extension “{}”",
                        affichable(m.titre())
                    ),
                    graves.join("\n"),
                )
            })
        })
        .collect()
}

/// Où lire l'interrupteur des restrictions sans créer le dossier (Paramètres le montre) ; `None` en administrateur,
/// où les réglages ne lèvent rien, ou sans dossier local connu.
pub fn reglages_lisibles() -> Option<PathBuf> {
    let local = crate::socle::dossier_local();
    (!eleve() && local.is_absolute()).then(|| local.join("plugins"))
}

/// Le dossier où l'interrupteur se règle (`dossier`), refusé en administrateur : l'interrupteur n'y vaut rien.
pub fn dossier_des_reglages() -> Result<PathBuf, String> {
    if eleve() {
        return Err(refus_eleve());
    }
    dossier().map_err(|e| trf!("Le réglage reste inactif : {e}", "The setting stays off: {e}"))
}

pub use menu::dire_restrictions;

/// `vanguard extensions --sans-restrictions on|off`, par `reglages::regler` comme Paramètres.
pub fn regler_restrictions(sans: bool) -> i32 {
    match dossier_des_reglages().and_then(|racine| reglages::regler(&racine, sans, |q| demander(q).oui())) {
        Ok((_, etat)) => {
            menu::dire_restrictions(etat);
            i32::from(etat != sans)
        }
        Err(e) => echec(&e),
    }
}

#[cfg(test)]
mod tests;
