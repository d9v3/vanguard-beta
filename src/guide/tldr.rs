//! Les commandes de tldr-pages (tldr.sh, licence CC BY 4.0) : des milliers d'exemples pour Linux, Windows, macOS et
//! d'autres systèmes, écrits et tenus à jour par une communauté. Vanguard télécharge leurs archives (anglais et
//! français) au plus une fois par semaine, en arrière-plan quand le guide s'ouvre, ou pendant la surveillance et
//! l'entretien du mois, et les lit sans rien exécuter : ces commandes se copient, elles ne se lancent jamais d'ici,
//! Vanguard ne les ayant pas vérifiées (`Obstacle::NonVerifiee`). Tout texte de l'archive passe par `ui::affichable` :
//! une page piégée ne pilote pas le terminal. Le déploiement en met aussi une copie sur la clé (`vanguard deploiement
//! tldr`, `cle`) : lancé depuis la clé, Vanguard les a dès le premier lancement, même sur un ordinateur sans Internet.
//! Des deux copies, la plus récente sert.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use super::{Commande, Obstacle, Programme, Systeme};
use crate::ui::affichable;

pub(crate) mod cle;

/// Les archives de tldr-pages : le projet les refait chaque jour, sous une page de version au numéro inchangé.
const ADRESSE: &str = "https://github.com/tldr-pages/tldr/releases/latest/download/";

/// L'anglais a toutes les pages ; le français, une partie, qui passe devant quand l'interface est en français.
const LANGUES: [&str; 2] = ["en", "fr"];

/// Âge au-delà duquel une archive se télécharge à nouveau.
const UNE_SEMAINE: Duration = Duration::from_hours(7 * 24);

/// Limites contre une archive démesurée ou piégée : taille téléchargée ou lue, taille d'une page, taille et nombre de
/// pages.
const TAILLE_ARCHIVE: u64 = 40 << 20;
const TAILLE_PAGE: usize = 256 << 10;
const TAILLE_TOTALE: usize = 64 << 20;
const PAGES_MAX: usize = 50_000;

/// Une page de tldr-pages : son système, sous lequel elle s'affiche, et la plateforme dont elle vient (« linux »).
pub(super) struct PageTldr {
    pub systeme: Systeme,
    pub plateforme: &'static str,
    pub programme: Programme,
}

fn dossier() -> PathBuf {
    crate::socle::dossier_local().join("tldr")
}

fn nom_d_archive(langue: &str) -> String {
    format!("tldr-pages.{langue}.zip")
}

/// L'archive de cet ordinateur, que le guide télécharge.
fn archive(langue: &str) -> PathBuf {
    dossier().join(nom_d_archive(langue))
}

/// Le dossier `tldr` de la clé d'où tourne Vanguard, cherché une fois : la clé ne change pas en cours de route, et le
/// guide demande ses pages à chaque écran. Jamais pendant les tests : la vraie clé peut être branchée.
fn dossier_de_la_cle() -> Option<&'static Path> {
    static DOSSIER: OnceLock<Option<PathBuf>> = OnceLock::new();
    if cfg!(test) {
        return None;
    }
    DOSSIER
        .get_or_init(|| crate::reseau::cle_du_programme().map(|c| c.join("tldr")))
        .as_deref()
}

/// Les dossiers où chercher les archives : celui de cet ordinateur, puis celui de la clé.
fn dossiers() -> Vec<PathBuf> {
    std::iter::once(dossier())
        .chain(dossier_de_la_cle().map(Path::to_path_buf))
        .collect()
}

/// Une archive trouvée : où, de quand, de quelle taille. Une autre date ou une autre taille, c'est une autre archive.
#[derive(Clone, PartialEq)]
struct Archive {
    chemin: PathBuf,
    date: SystemTime,
    taille: u64,
}

/// Les archives déjà lues, et si elles se lisaient : chacune n'est lue qu'une fois par session. Le guide demande la
/// date des archives à chaque écran ; une archive abîmée connue n'y compte plus, sans être relue.
static CONNUES: Mutex<Vec<(Archive, bool)>> = Mutex::new(Vec::new());

fn connue(archive: &Archive) -> Option<bool> {
    CONNUES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(a, _)| a == archive)
        .map(|(_, lisible)| *lisible)
}

/// Les archives d'une langue dans `dossiers`, la plus récente d'abord. La suivante sert quand la première ne se lit
/// pas (copie interrompue par une clé retirée trop tôt). Seulement les métadonnées : une archive démesurée (système
/// de fichiers abîmé, fichier remplacé) ou déjà lue sans succès est laissée de côté sans être ouverte.
fn archives(langue: &str, dossiers: &[PathBuf]) -> Vec<Archive> {
    let mut archives: Vec<Archive> = dossiers
        .iter()
        .map(|d| d.join(nom_d_archive(langue)))
        .filter_map(|chemin| {
            let meta = std::fs::metadata(&chemin).ok()?;
            let archive = Archive {
                date: meta.modified().ok()?,
                taille: meta.len(),
                chemin,
            };
            (archive.taille <= TAILLE_ARCHIVE && connue(&archive) != Some(false)).then_some(archive)
        })
        .collect();
    // La plus récente d'abord, une date dans le futur en dernier : sur une clé, elle ne prend pas la place de la
    // copie de cet ordinateur (campagne d'attaque n° 3).
    archives.sort_by_key(|a| (a.date.elapsed().is_err(), std::cmp::Reverse(a.date)));
    archives
}

/// Les fichiers d'une archive ; vide si elle ne se lit pas, ce qui est retenu. Jamais plus de `TAILLE_ARCHIVE` lus,
/// même si le fichier a grossi depuis `archives` : un fichier démesuré ne remplit pas la mémoire.
fn lire(archive: &Archive) -> Vec<(String, Vec<u8>)> {
    use std::io::Read;
    let mut octets = Vec::new();
    let entiere = std::fs::File::open(&archive.chemin)
        .and_then(|f| f.take(TAILLE_ARCHIVE + 1).read_to_end(&mut octets))
        .is_ok_and(|n| u64::try_from(n).is_ok_and(|n| n <= TAILLE_ARCHIVE));
    let fichiers = if entiere { lire_zip(&octets) } else { Vec::new() };
    let mut connues = CONNUES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if !connues.iter().any(|(a, _)| a == archive) {
        connues.push((archive.clone(), !fichiers.is_empty()));
    }
    fichiers
}

/// Les fichiers de la plus récente archive lisible d'une langue ; vide s'il n'y en a aucune.
fn fichiers_de(langue: &str, dossiers: &[PathBuf]) -> Vec<(String, Vec<u8>)> {
    archives(langue, dossiers)
        .iter()
        .map(lire)
        .find(|fichiers| !fichiers.is_empty())
        .unwrap_or_default()
}

/// La date de l'archive la plus récente ; `None` : aucune encore.
fn date_des_archives() -> Option<SystemTime> {
    let dossiers = dossiers();
    LANGUES
        .iter()
        .filter_map(|l| archives(l, &dossiers).first().map(|a| a.date))
        .max()
}

/// Une langue sans archive, ou dont la plus récente a plus d'une semaine : à retélécharger. Une langue dont l'archive
/// est fraîche n'est pas reprise parce qu'une autre a échoué (le français, partiel, peut manquer sans que l'anglais le
/// soit), ni quand la clé en a apporté une fraîche. Rien n'est lu : seulement les dates, et ce que `a_telecharger` a
/// déjà appris des archives.
fn a_renouveler(langue: &str, dossiers: &[PathBuf]) -> bool {
    archives(langue, dossiers)
        .first()
        .and_then(|a| a.date.elapsed().ok())
        .is_none_or(|age| age > UNE_SEMAINE)
}

/// La plus récente archive d'une langue n'a pas encore été lue : fraîche, elle peut être abîmée.
fn a_verifier(langue: &str, dossiers: &[PathBuf]) -> bool {
    archives(langue, dossiers).first().is_some_and(|a| connue(a).is_none())
}

/// La décision du fil d'arrière-plan : les archives lues de la plus récente à la première qui se lit, puis
/// `a_renouveler`. Une archive fraîche mais abîmée ne bloque donc pas le téléchargement pendant une semaine. Lent (une
/// archive fait plusieurs Mo) : jamais sur le fil principal.
fn a_telecharger(langue: &str, dossiers: &[PathBuf]) -> bool {
    for archive in archives(langue, dossiers) {
        if connue(&archive).unwrap_or_else(|| !lire(&archive).is_empty()) {
            break;
        }
    }
    a_renouveler(langue, dossiers)
}

/// Le téléchargement d'arrière-plan tourne déjà.
static EN_COURS: AtomicBool = AtomicBool::new(false);

/// Les langues dont l'archive est à renouveler, ou pas encore lue (fraîche, elle peut être abîmée).
fn langues_a_voir(dossiers: &[PathBuf]) -> Vec<&'static str> {
    LANGUES
        .into_iter()
        .filter(|l| a_renouveler(l, dossiers) || a_verifier(l, dossiers))
        .collect()
}

/// Renouvelle les archives qui en ont besoin, en arrière-plan : le guide s'ouvre sans les attendre, et les lit à son
/// prochain affichage. Seulement dans un vrai terminal (pas pour un script ni pour les tests) ; sans Internet, la
/// demande échoue vite et rien ne change. Le fil principal ne regarde que les dates ; une archive pas encore lue l'est
/// dans le fil, qui décide alors.
pub(super) fn renouveler_en_fond() {
    use std::io::IsTerminal;
    let dossiers = dossiers();
    let a_voir = langues_a_voir(&dossiers);
    if !std::io::stdin().is_terminal() || a_voir.is_empty() || EN_COURS.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(move || {
        renouveler(&a_voir, &dossiers);
        EN_COURS.store(false, Ordering::SeqCst);
    });
}

/// Sans attendre qu'on ouvre le guide : la surveillance de chaque heure et l'entretien du mois renouvellent les
/// archives de plus d'une semaine, pour que le guide les ait fraîches à son ouverture, même alors hors ligne.
/// Seulement sur un ordinateur où le guide en a déjà téléchargé : qui ne s'en sert pas ne télécharge rien. Jamais
/// pendant les tests.
pub(super) fn renouveler_maintenant() {
    if cfg!(test) || !LANGUES.iter().any(|l| archive(l).exists()) {
        return;
    }
    let dossiers = dossiers();
    let a_voir = langues_a_voir(&dossiers);
    if a_voir.is_empty() || EN_COURS.swap(true, Ordering::SeqCst) {
        return;
    }
    renouveler(&a_voir, &dossiers);
    EN_COURS.store(false, Ordering::SeqCst);
}

/// Télécharge les archives de `a_voir` qui en ont besoin. Lent : jamais sur le fil du guide.
fn renouveler(a_voir: &[&str], dossiers: &[PathBuf]) {
    // Les restes d'un téléchargement interrompu (Vanguard quitté avant la fin) partent d'abord. Seulement ceux qui
    // n'avancent plus : celui d'un autre Vanguard ouvert en même temps peut encore arriver (abandonné après 2 min).
    if let Ok(fichiers) = std::fs::read_dir(dossier()) {
        for f in fichiers.flatten() {
            let immobile = f
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|date| date.elapsed().ok())
                .is_some_and(|age| age > Duration::from_mins(10));
            if immobile && f.file_name().to_string_lossy().contains(".zip.") {
                let _ = std::fs::remove_file(f.path());
            }
        }
    }
    for langue in a_voir {
        if a_telecharger(langue, dossiers) {
            telecharger(langue);
        }
    }
}

/// Le téléchargement est-il en cours ?
pub(super) fn en_cours() -> bool {
    EN_COURS.load(Ordering::SeqCst)
}

/// Télécharge une archive et la met à la place de l'ancienne si elle se lit : une page d'erreur ou un fichier
/// tronqué ne remplace jamais la bonne. Écrite par l'écriture atomique du socle (disque forcé, essais répétés quand
/// Defender tient l'ancienne), plus par un renommage fait ici.
fn telecharger(langue: &str) -> bool {
    let fin = archive(langue);
    let adresse = format!("{ADRESSE}tldr-pages.{langue}.zip");
    let demande = crate::http::Demande {
        taille_max: TAILLE_ARCHIVE,
        ..crate::http::Demande::get(&adresse, std::time::Duration::from_secs(120))
    };
    crate::http::envoyer(demande)
        .filter(|r| r.code == 200 && !lire_zip(&r.corps).is_empty())
        .is_some_and(|r| crate::socle::ecrire_atomique(&fin, &r.corps).is_ok())
}

/// Les fichiers d'une archive de tldr-pages : (nom, contenu), par le lecteur commun (`archives::zip`), avec les
/// limites des pages. Une archive illisible donne une liste vide.
pub(super) fn lire_zip(octets: &[u8]) -> Vec<(String, Vec<u8>)> {
    crate::archives::zip::lire(
        octets,
        &crate::archives::Bornes {
            entrees: PAGES_MAX,
            fichier: TAILLE_PAGE,
            total: TAILLE_TOTALE,
        },
    )
}

/// « {{chemin/du/fichier}} » devient « <chemin/du/fichier> », comme les mots à remplacer du guide ; un choix d'option
/// (« {{[-r|--recursive]}} ») garde sa forme longue.
fn remplacer_les_espaces_reserves(commande: &str) -> String {
    let mut sortie = String::with_capacity(commande.len());
    let mut reste = commande;
    while let Some(debut) = reste.find("{{") {
        sortie.push_str(&reste[..debut]);
        let Some(fin) = reste[debut..].find("}}") else {
            sortie.push_str(&reste[debut..]);
            return sortie;
        };
        let dedans = &reste[debut + 2..debut + fin];
        match dedans.strip_prefix('[').and_then(|d| d.strip_suffix(']')) {
            Some(choix) if choix.contains('|') => sortie.push_str(choix.rsplit('|').next().unwrap_or(choix)),
            _ => {
                sortie.push('<');
                sortie.push_str(dedans);
                sortie.push('>');
            }
        }
        reste = &reste[debut + fin + 2..];
    }
    sortie.push_str(reste);
    sortie
}

/// Une page de tldr-pages, lue : son titre, sa description, ses exemples (explication, commande).
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PageLue {
    titre: String,
    description: String,
    exemples: Vec<(String, String)>,
}

/// Une page au format de tldr-pages : son titre (« # tar »), sa description (lignes « > »), puis ses exemples (« - ce
/// que ça fait : » suivi de « `la commande` »). Les liens et renvois de la description sont laissés.
pub(super) fn lire_page(texte: &str) -> Option<PageLue> {
    let mut titre = None;
    let mut description = Vec::new();
    let mut exemples = Vec::new();
    let mut en_attente: Option<String> = None;
    for ligne in texte.lines().map(str::trim) {
        if let Some(t) = ligne.strip_prefix("# ") {
            titre.get_or_insert_with(|| t.trim().to_string());
        } else if let Some(d) = ligne.strip_prefix('>') {
            let d = d.trim();
            let renvoi = [
                "More information",
                "Plus d'informations",
                "Plus d’informations",
                "See also",
                "Voir aussi",
            ]
            .iter()
            .any(|r| d.starts_with(r))
                || d.contains("<http");
            if !renvoi && !d.is_empty() {
                description.push(d.to_string());
            }
        } else if let Some(e) = ligne.strip_prefix("- ") {
            en_attente = Some(e.trim().trim_end_matches(':').trim().to_string());
        } else if let Some(c) = ligne.strip_prefix('`').and_then(|c| c.strip_suffix('`'))
            && let Some(explication) = en_attente.take()
        {
            exemples.push((explication, remplacer_les_espaces_reserves(c)));
        }
    }
    let titre = titre?;
    (!exemples.is_empty()).then(|| PageLue {
        titre,
        description: description.join(" "),
        exemples,
    })
}

/// Le système du guide d'une plateforme de tldr-pages, et son nom à l'écran.
fn systeme_de(plateforme: &str) -> (Systeme, &'static str) {
    match plateforme {
        "common" => (Systeme::Tous, crate::tr!("tous", "all")),
        "linux" => (Systeme::Linux, "linux"),
        "osx" => (Systeme::MacOs, "macOS"),
        "windows" => (Systeme::Windows, "windows"),
        "android" => (Systeme::Tldr, "android"),
        "freebsd" => (Systeme::Tldr, "freebsd"),
        "openbsd" => (Systeme::Tldr, "openbsd"),
        "netbsd" => (Systeme::Tldr, "netbsd"),
        "sunos" => (Systeme::Tldr, "sunos"),
        "dos" => (Systeme::Tldr, "dos"),
        _ => (Systeme::Tldr, "autre"),
    }
}

/// Un texte de l'archive gardé pour toute la session : les pages se chargent une fois (et à nouveau seulement après
/// un téléchargement), et le guide les manie comme ses propres programmes, aux textes « 'static ».
fn garder(texte: &str) -> &'static str {
    affichable(texte).leak()
}

/// Les pages des archives téléchargées, dans la langue de l'interface (l'anglais quand une page n'est pas traduite),
/// rangées par plateforme puis par nom.
fn charger() -> &'static [PageTldr] {
    // Par (rang de la plateforme, « plateforme/nom ») : la plateforme, et la page.
    let mut pages: BTreeMap<(u8, String), (String, PageLue)> = BTreeMap::new();
    let ordre = |plateforme: &str| match plateforme {
        "linux" => 0,
        "common" => 1,
        "windows" => 2,
        "osx" => 3,
        _ => 4,
    };
    let dossiers = dossiers();
    let langues: &[&str] = if crate::langue::anglais() { &["en"] } else { &LANGUES };
    for langue in langues {
        for (nom, contenu) in fichiers_de(langue, &dossiers) {
            let Some((plateforme, fichier)) = nom.split_once('/') else {
                continue;
            };
            let Some(base) = fichier.strip_suffix(".md") else {
                continue;
            };
            if let Some(page) = lire_page(&String::from_utf8_lossy(&contenu)) {
                // Le français, lu après l'anglais, prend sa place.
                pages.insert(
                    (ordre(plateforme), format!("{plateforme}/{base}")),
                    (plateforme.to_string(), page),
                );
            }
        }
    }
    let pages: Vec<PageTldr> = pages
        .into_values()
        .map(
            |(
                plateforme,
                PageLue {
                    titre,
                    description,
                    exemples,
                },
            )| {
                let (systeme, plateforme) = systeme_de(&plateforme);
                let description = garder(&description);
                let commandes: Vec<Commande> = exemples
                    .iter()
                    .map(|(explication, commande)| {
                        let explication = garder(explication);
                        Commande {
                            ligne: garder(commande),
                            ligne_en: "",
                            texte: (explication, explication),
                            modifie: false,
                            obstacle: Obstacle::NonVerifiee,
                        }
                    })
                    .collect();
                let executable = titre.split_whitespace().next().unwrap_or_default();
                PageTldr {
                    systeme,
                    plateforme,
                    programme: Programme {
                        nom: garder(&titre),
                        role: (description, description),
                        executable: garder(executable),
                        commandes: commandes.leak(),
                    },
                }
            },
        )
        .collect();
    pages.leak()
}

/// Les pages chargées, et la date des archives d'où elles viennent.
static CHARGEES: Mutex<Option<(Option<SystemTime>, &'static [PageTldr])>> = Mutex::new(None);

/// Les pages de tldr-pages, chargées à la première demande, et à nouveau quand une archive plus récente arrive.
/// Vide tant que rien n'est téléchargé.
pub(super) fn pages() -> &'static [PageTldr] {
    let date = date_des_archives();
    let mut chargees = CHARGEES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((quand, pages)) = *chargees
        && quand == date
    {
        return pages;
    }
    let pages = if date.is_some() { charger() } else { &[] };
    *chargees = Some((date, pages));
    pages
}

/// La plateforme d'un programme de tldr-pages (« linux »), ou `None` pour un programme du guide.
pub(super) fn plateforme(p: &Programme) -> Option<&'static str> {
    pages()
        .iter()
        .find(|page| std::ptr::eq(std::ptr::from_ref(&page.programme), p))
        .map(|page| page.plateforme)
}

/// La date des archives en clair (« 19/10/2026 »), pour dire à quel point les commandes sont fraîches.
pub(super) fn date_en_clair() -> Option<String> {
    let date: chrono::DateTime<chrono::Local> = date_des_archives()?.into();
    Some(date.format(crate::tr!("%d/%m/%Y", "%Y-%m-%d")).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une archive zip faite à la main : chaque fichier stocké tel quel, ou compressé (deflate).
    fn zip(fichiers: &[(&str, &str, bool)]) -> Vec<u8> {
        let mut octets = Vec::new();
        let mut central = Vec::new();
        for (nom, contenu, compresse) in fichiers {
            let donnees = if *compresse {
                miniz_oxide::deflate::compress_to_vec(contenu.as_bytes(), 6)
            } else {
                contenu.as_bytes().to_vec()
            };
            let methode: u16 = if *compresse { 8 } else { 0 };
            let local = u32::try_from(octets.len()).unwrap();
            let entete = |sig: u32, central: bool| {
                let mut e = sig.to_le_bytes().to_vec();
                if central {
                    e.extend([20, 0]);
                }
                e.extend([20, 0, 0, 0]);
                e.extend(methode.to_le_bytes());
                e.extend([0, 0, 0, 0, 0, 0, 0, 0]);
                e.extend(u32::try_from(donnees.len()).unwrap().to_le_bytes());
                e.extend(u32::try_from(contenu.len()).unwrap().to_le_bytes());
                e.extend(u16::try_from(nom.len()).unwrap().to_le_bytes());
                e.extend([0, 0]);
                if central {
                    e.extend([0; 10]);
                    e.extend(local.to_le_bytes());
                }
                e.extend(nom.as_bytes());
                e
            };
            octets.extend(entete(0x0403_4b50, false));
            octets.extend(&donnees);
            central.extend(entete(0x0201_4b50, true));
        }
        let debut = u32::try_from(octets.len()).unwrap();
        let taille = u32::try_from(central.len()).unwrap();
        octets.extend(&central);
        let n = u16::try_from(fichiers.len()).unwrap();
        octets.extend(0x0605_4b50u32.to_le_bytes());
        octets.extend([0, 0, 0, 0]);
        octets.extend(n.to_le_bytes());
        octets.extend(n.to_le_bytes());
        octets.extend(taille.to_le_bytes());
        octets.extend(debut.to_le_bytes());
        octets.extend([0, 0]);
        octets
    }

    #[test]
    fn une_archive_se_lit_stockee_ou_compressee() {
        let a = zip(&[("linux/a.md", "# a\n", false), ("common/b.md", &"x".repeat(5000), true)]);
        let fichiers = lire_zip(&a);
        assert_eq!(fichiers.len(), 2);
        assert_eq!(fichiers[0], ("linux/a.md".to_string(), b"# a\n".to_vec()));
        assert_eq!(fichiers[1].1.len(), 5000);
        // Rien de lisible : une page d'erreur, une archive tronquée, du vide.
        assert_eq!(lire_zip(b"<html>Not Found</html>"), []);
        assert_eq!(lire_zip(&a[..a.len() / 2]), []);
        assert_eq!(lire_zip(&[]), []);
        // Une page trop grosse est sautée, les autres restent.
        let grosse = zip(&[
            ("common/c.md", &"y".repeat(TAILLE_PAGE + 1), true),
            ("linux/a.md", "# a\n", false),
        ]);
        assert_eq!(lire_zip(&grosse).len(), 1);
    }

    #[test]
    fn une_page_donne_titre_description_et_exemples() {
        let page = "# tar\n\n> Utilitaire d'archivage.\n> Souvent combiné avec gzip.\n> Plus d'informations : <https://www.gnu.org/software/tar>.\n\n- Crée une archive :\n\n`tar cf {{chemin/vers/cible.tar}} {{fichier1 fichier2}}`\n\n- Extrait en détaillant :\n\n`tar {{[-x|--extract]}} {{[-v|--verbose]}} -f {{archive.tar}}`\n";
        let PageLue {
            titre,
            description,
            exemples,
        } = lire_page(page).unwrap();
        assert_eq!(titre, "tar");
        assert_eq!(description, "Utilitaire d'archivage. Souvent combiné avec gzip.");
        assert_eq!(
            exemples,
            [
                (
                    "Crée une archive".to_string(),
                    "tar cf <chemin/vers/cible.tar> <fichier1 fichier2>".to_string()
                ),
                (
                    "Extrait en détaillant".to_string(),
                    "tar --extract --verbose -f <archive.tar>".to_string()
                ),
            ]
        );
        assert_eq!(lire_page("pas une page"), None);
        assert_eq!(lire_page("# vide\n> Rien à montrer.\n"), None);
        assert_eq!(remplacer_les_espaces_reserves("a {{b"), "a {{b");
    }

    #[test]
    fn plateformes_rangees_dans_le_guide() {
        assert_eq!(systeme_de("linux").0, Systeme::Linux);
        assert_eq!(systeme_de("osx").0, Systeme::MacOs);
        assert_eq!(systeme_de("windows").0, Systeme::Windows);
        assert_eq!(systeme_de("common").0, Systeme::Tous);
        assert_eq!(systeme_de("android").0, Systeme::Tldr);
    }

    /// Deux dossiers d'essai, l'un pour cet ordinateur, l'autre pour la clé.
    fn deux_copies(nom: &str) -> (PathBuf, [PathBuf; 2]) {
        let racine = crate::socle::dossier_local().join(nom);
        let dossiers = [racine.join("ordinateur"), racine.join("cle")];
        for d in &dossiers {
            std::fs::create_dir_all(d).unwrap();
        }
        (racine, dossiers)
    }

    /// Écrit l'archive d'une langue dans un dossier, datée d'il y a `age`.
    fn ecrire(dossier: &Path, langue: &str, octets: &[u8], age: Duration) {
        let chemin = dossier.join(nom_d_archive(langue));
        std::fs::write(&chemin, octets).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&chemin)
            .unwrap()
            .set_modified(SystemTime::now() - age)
            .unwrap();
    }

    /// Des deux copies (cet ordinateur, la clé), la plus récente sert ; abîmée, l'autre prend le relais ; une copie de
    /// moins d'une semaine n'est pas retéléchargée.
    #[test]
    fn la_plus_recente_des_deux_copies() {
        let (racine, dossiers) = deux_copies("essai-copies-tldr");
        let [ordinateur, cle] = &dossiers;
        let ecrire = |dossier: &Path, octets: &[u8], age: Duration| ecrire(dossier, "fr", octets, age);
        let contenu = |dossiers: &[PathBuf]| fichiers_de("fr", dossiers).first().map(|f| f.1.clone());
        // Aucune copie : à télécharger, rien à lire.
        assert!(a_renouveler("fr", &dossiers) && contenu(&dossiers).is_none());
        // Une copie de dix jours : lue en attendant, mais à retélécharger.
        ecrire(
            ordinateur,
            &zip(&[("linux/a.md", "# ancienne\n", false)]),
            Duration::from_hours(240),
        );
        assert!(a_renouveler("fr", &dossiers));
        assert_eq!(contenu(&dossiers).as_deref(), Some(&b"# ancienne\n"[..]));
        // La clé en apporte une fraîche : elle sert, et rien ne se télécharge.
        let recente = zip(&[("linux/a.md", "# recente\n", false)]);
        ecrire(cle, &recente, Duration::from_hours(1));
        assert!(!a_renouveler("fr", &dossiers) && a_verifier("fr", &dossiers));
        assert_eq!(contenu(&dossiers).as_deref(), Some(&b"# recente\n"[..]));
        // Lue pour l'affichage (guide::menu charge les pages avant de lancer le fil), elle n'est plus à vérifier : le
        // fil d'arrière-plan ne la relit pas.
        assert!(!a_verifier("fr", &dossiers));
        // Abîmée (clé retirée pendant la copie), la plus récente laisse la place à l'autre.
        ecrire(cle, &recente[..recente.len() / 2], Duration::from_hours(1));
        assert_eq!(contenu(&dossiers).as_deref(), Some(&b"# ancienne\n"[..]));
        // L'anglais, absent des deux, reste à télécharger : chaque langue a son compte.
        assert!(a_renouveler("en", &dossiers));
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Une archive fraîche mais abîmée (clé retirée pendant la copie) ne retient pas le téléchargement une semaine. Le
    /// fil principal ne la lit pas : il voit seulement qu'elle reste à vérifier, et le fil d'arrière-plan décide.
    #[test]
    fn une_archive_fraiche_mais_abimee_se_retelecharge() {
        let (racine, dossiers) = deux_copies("essai-tldr-abimee");
        let [ordinateur, cle] = &dossiers;
        let bonne = zip(&[("linux/a.md", "# a\n", false)]);
        // Chez quelqu'un d'autre : rien sur l'ordinateur, la clé en apporte une tronquée, datée de l'heure.
        ecrire(cle, "en", &bonne[..bonne.len() / 2], Duration::from_hours(1));
        assert!(!a_renouveler("en", &dossiers) && a_verifier("en", &dossiers));
        assert!(a_telecharger("en", &dossiers));
        // Ensuite, elle ne compte plus, sans être relue : ni pour la date du guide, ni pour la décision.
        assert!(archives("en", &dossiers).is_empty());
        assert!(a_renouveler("en", &dossiers) && !a_verifier("en", &dossiers));
        // Une copie de dix jours sur l'ordinateur sert en attendant, et se renouvelle.
        ecrire(ordinateur, "en", &bonne, Duration::from_hours(240));
        assert!(a_verifier("en", &dossiers) && a_telecharger("en", &dossiers));
        assert_eq!(fichiers_de("en", &dossiers).len(), 1);
        // Une archive saine et fraîche, elle, ne se retélécharge pas.
        ecrire(cle, "en", &bonne, Duration::from_hours(2));
        assert!(!a_telecharger("en", &dossiers) && !a_verifier("en", &dossiers));
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Une archive démesurée sur la clé n'est jamais ouverte : sa taille suffit à l'écarter, et une archive qui grossit
    /// après coup n'est pas lue au-delà de la limite.
    #[test]
    fn une_archive_demesuree_n_est_pas_lue() {
        let (racine, dossiers) = deux_copies("essai-tldr-demesuree");
        let [ordinateur, cle] = &dossiers;
        ecrire(
            ordinateur,
            "fr",
            &zip(&[("linux/a.md", "# a\n", false)]),
            Duration::from_hours(240),
        );
        // Un fichier creux : sa taille dépasse la limite sans rien occuper sur le disque.
        let demesuree = cle.join(nom_d_archive("fr"));
        std::fs::File::create(&demesuree)
            .unwrap()
            .set_len(TAILLE_ARCHIVE + 1)
            .unwrap();
        let trouvees = archives("fr", &dossiers);
        assert_eq!(trouvees.len(), 1);
        assert_eq!(trouvees[0].chemin, ordinateur.join(nom_d_archive("fr")));
        assert_eq!(fichiers_de("fr", &dossiers).len(), 1);
        // Vue plus petite qu'elle n'est (elle a grossi depuis) : la lecture s'arrête à la limite et la rejette.
        let grossie = Archive {
            chemin: demesuree,
            date: SystemTime::now(),
            taille: 0,
        };
        assert_eq!(lire(&grossie), []);
        assert_eq!(connue(&grossie), Some(false));
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Sans archive (le dossier des tests est jetable), le guide n'a aucune page de tldr-pages.
    #[test]
    fn sans_archive_aucune_page() {
        assert_eq!(pages().len(), 0);
        assert!(date_en_clair().is_none());
    }
}

/// Archives au hasard : jamais de plantage, jamais plus que les limites.
#[cfg(test)]
mod tests_au_hasard {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn une_archive_piegee_ne_fait_rien_planter(octets in prop::collection::vec(any::<u8>(), 0..2048), page in "\\PC{0,400}") {
            for (_, contenu) in lire_zip(&octets) {
                prop_assert!(contenu.len() <= TAILLE_PAGE);
            }
            let _ = lire_page(&page);
            let _ = remplacer_les_espaces_reserves(&page);
        }
    }
}
