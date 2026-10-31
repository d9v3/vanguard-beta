//! Nettoyer le système : libérer de la place sans rien perdre d'important. Chaque élément montre la place qu'il
//! libère, mesurée avant ; ce qui se refait seul (caches, fichiers temporaires, paquets téléchargés, vieux journaux)
//! est coché d'office, la corbeille jamais. On voit les commandes, on accepte, puis la place libre relue dit ce qui a
//! vraiment été gagné. Aucun document, aucune photo, aucun réglage n'est touché.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as systeme;
#[cfg(target_os = "macos")]
use macos as systeme;
#[cfg(windows)]
use windows as systeme;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::selection::{Case, cocher};
#[cfg(target_os = "linux")]
use crate::socle::personnel::statvfs;
use crate::socle::taille_lisible;
#[cfg(unix)]
use crate::socle::{maison, volume};
use crate::ui::*;

/// En dessous, il n'y a rien à gagner : l'élément s'affiche « déjà propre ».
const PRESQUE_RIEN: u64 = 1 << 20;

/// Une chose à nettoyer.
pub struct Element {
    pub titre: &'static str,
    /// Ce qui est effacé, et pourquoi ça ne fait rien perdre.
    pub effet: String,
    /// Le revers, s'il y en a un.
    pub prudence: Option<&'static str>,
    /// Place à libérer, mesurée avant ; `None` : connue seulement une fois fait (paquets à retirer, Windows Update…).
    pub taille: Option<u64>,
    pub commandes: Vec<String>,
    /// Coché d'office : tout se refait seul, rien n'est perdu.
    pub recommande: bool,
    /// Windows : demande les droits d'administrateur (une seule fenêtre pour tous) ; sans, la commande est lancée dans
    /// le compte de la personne (sa corbeille, son dossier temporaire : ceux du compte qui ouvrirait la fenêtre
    /// administrateur seraient d'autres).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub admin: bool,
}

impl Element {
    fn propre(&self) -> bool {
        self.taille.is_some_and(|t| t < PRESQUE_RIEN)
    }
}

/// Somme de tailles, plafonnée à `u64::MAX`. Un fichier creux (btrfs, XFS, tmpfs, APFS) annonce jusqu'à 8 Eio sans
/// rien occuper, et n'importe quel programme du compte peut en poser dans un cache ou dans la corbeille : trois
/// suffisent à dépasser un u64. La version publiée vérifie les dépassements de capacité : une somme ordinaire y
/// paniquerait (nettoyer, entretien du mois, dépannage, copie), là où le total plafonné reste un minimum vrai, comme
/// celui d'une mesure interrompue à l'échéance.
fn somme(tailles: impl IntoIterator<Item = u64>) -> u64 {
    tailles.into_iter().fold(0, u64::saturating_add)
}

/// Ce que mesurer dans un dossier.
#[derive(Clone, Copy)]
pub enum Age {
    Tout,
    /// Fichiers non modifiés depuis ce nombre de jours.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    NonModifieDepuis(u64),
}

/// Taille d'un dossier en octets, sous-dossiers compris, sans ceux de `exclus` ; `None` s'il ne peut pas être lu du
/// tout (droits) : « vide » et « illisible » ne se confondent pas. Arrêt après deux secondes (un cache de millions
/// de fichiers) : le total est alors un minimum, comme quand il atteint `u64::MAX` (voir `somme`).
pub fn taille_dossier(dossier: &Path, age: Age, exclus: &[PathBuf]) -> Option<u64> {
    let echeance = Instant::now() + Duration::from_secs(2);
    let limite = match age {
        Age::Tout => None,
        Age::NonModifieDepuis(j) => Some(SystemTime::now() - Duration::from_secs(j * 86_400)),
    };
    let mut total = 0_u64;
    let mut a_voir = vec![std::fs::read_dir(dossier).ok()?];
    while let Some(entrees) = a_voir.pop() {
        if Instant::now() > echeance {
            break;
        }
        for e in entrees.flatten() {
            let chemin = e.path();
            // Un lien symbolique n'est pas suivi : sa cible n'est pas dans le dossier.
            let Ok(m) = std::fs::symlink_metadata(&chemin) else {
                continue;
            };
            if m.is_dir() {
                if !exclus.contains(&chemin)
                    && let Ok(sous) = std::fs::read_dir(&chemin)
                {
                    a_voir.push(sous);
                }
            } else if limite.is_none_or(|l| m.modified().is_ok_and(|d| d < l)) {
                total = total.saturating_add(m.len());
            }
        }
    }
    Some(total)
}

/// Les caches d'applications (dossiers ou fichiers posés directement dans `dossier`) dont aucun fichier n'a été lu
/// ni écrit depuis `jours` jours : ceux des applications qu'on n'utilise plus, avec leur taille. Un cache part en
/// entier ou pas du tout : vidé à moitié, un environnement Python, un navigateur de test ou un dépôt git rangé là
/// casserait son application. Un cache illisible, ou pas mesuré en entier avant l'échéance, est gardé : rien ne dit
/// qu'il dort. Un lien symbolique est gardé aussi : il mène souvent le cache sur un autre disque, exprès.
#[cfg(unix)]
fn caches_endormis(dossier: &Path, jours: u64, exclus: &[&str]) -> Vec<(String, u64)> {
    let echeance = Instant::now() + Duration::from_secs(3);
    let limite = SystemTime::now() - Duration::from_secs(jours * 86_400);
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return Vec::new();
    };
    let mut l: Vec<(String, u64)> = entrees
        .flatten()
        .filter_map(|e| {
            let nom = e.file_name().into_string().ok()?;
            if exclus.contains(&nom.as_str()) || e.file_type().ok()?.is_symlink() {
                return None;
            }
            let (taille, recent) = dernier_usage(&e.path(), echeance)?;
            (taille > 0 && recent < limite).then_some((nom, taille))
        })
        .collect();
    l.sort();
    l
}

/// Taille des fichiers sous `chemin` (lui compris) et leur dernière lecture ou écriture ; `None` si un dossier ne se
/// lit pas ou si l'échéance passe avant la fin. Les dates des dossiers ne comptent pas : les parcourir les change.
#[cfg(unix)]
fn dernier_usage(chemin: &Path, echeance: Instant) -> Option<(u64, SystemTime)> {
    let mut total = 0_u64;
    let mut recent = SystemTime::UNIX_EPOCH;
    let mut a_voir = vec![chemin.to_path_buf()];
    while let Some(p) = a_voir.pop() {
        if Instant::now() > echeance {
            return None;
        }
        // Un lien symbolique n'est pas suivi : sa cible n'est pas dans le cache.
        let Ok(m) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if m.is_dir() {
            a_voir.extend(std::fs::read_dir(&p).ok()?.flatten().map(|e| e.path()));
        } else {
            total = total.saturating_add(m.len());
            recent = [m.accessed(), m.modified()]
                .into_iter()
                .flatten()
                .fold(recent, SystemTime::max);
        }
    }
    Some((total, recent))
}

/// « rm -rf -- ~/.cache/a ~/.cache/'b c' » : les caches à effacer, entre apostrophes quand leur nom l'exige.
#[cfg(unix)]
fn effacer_caches(dossier: &str, caches: &[(String, u64)]) -> String {
    let mut commande = String::from("rm -rf --");
    for (nom, _) in caches {
        commande.push(' ');
        commande.push_str(dossier);
        commande.push('/');
        if nom
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-+@%,=:".contains(c))
        {
            commande.push_str(nom);
        } else {
            commande.push_str(&crate::commande::sh_chaine(nom));
        }
    }
    commande
}

/// La date de dernière lecture est-elle tenue à jour sur le volume de `chemin` ? Monté en `noatime` (conseil courant
/// pour les SSD), elle ne bouge plus : un cache lu chaque jour mais jamais réécrit passerait pour oublié. Les options
/// du volume illisibles : non, dans le doute.
#[cfg(target_os = "linux")]
pub fn lectures_datees(chemin: &Path) -> bool {
    statvfs(chemin).is_some_and(|s| s.f_flag & libc::ST_NOATIME == 0)
}

/// Sous macOS, statvfs ne dit rien de `noatime` : statfs, si.
#[cfg(target_os = "macos")]
// FFI de libc : statfs (option noatime sous macOS).
#[allow(unsafe_code)]
pub fn lectures_datees(chemin: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(chemin.as_os_str().as_bytes()) else {
        return false;
    };
    let mut s = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c` est une chaîne C valide pendant tout l'appel ; statfs remplit `s` en entier quand elle réussit
    // (retour 0), et `s` n'est lue qu'après.
    let s = unsafe {
        if libc::statfs(c.as_ptr(), s.as_mut_ptr()) != 0 {
            return false;
        }
        s.assume_init()
    };
    u32::try_from(libc::MNT_NOATIME).is_ok_and(|noatime| s.f_flags & noatime == 0)
}

/// « Caches d'applications inutilisées » dans `cache` (écrit `affiche` dans la commande montrée), sans les dossiers
/// comptés à part. Sans dates de lecture tenues à jour, pas proposé : un cache lu chaque jour pourrait y figurer.
#[cfg(unix)]
pub fn caches_inutilises(cache: &Path, affiche: &str, exclus: &[&str], lectures_datees: bool) -> Option<Element> {
    if !lectures_datees {
        return None;
    }
    let endormis = caches_endormis(cache, 90, exclus);
    Some(Element {
        titre: tr!("Caches d'applications inutilisées", "Caches of unused apps"),
        effet: tr!(
            "Caches que rien n'a lus ni écrits depuis 90 jours, chacun effacé en entier : vidé à moitié, un cache casserait son application, qui le refait si elle revient.",
            "Caches nothing has read or written for 90 days, each removed entirely: half emptied, a cache would break its app, which rebuilds it if it comes back."
        )
        .into(),
        prudence: None,
        taille: Some(somme(endormis.iter().map(|(_, t)| *t))),
        commandes: vec![effacer_caches(affiche, &endormis)],
        recommande: true,
        admin: false,
    })
}

/// Place libre et taille du volume du système (pour l'afficher), puis la place libre de tous les volumes que le
/// nettoyage touche (pour mesurer le gain).
fn place() -> Option<(u64, u64, u64)> {
    systeme::place()
}

fn ligne_place(libre: u64, total: u64) -> String {
    let occupe = total.saturating_sub(libre).saturating_mul(100) / total.max(1);
    trf!(
        "  {GRIS}Disque du système : {} libres sur {} (occupé à {occupe} %).{RESET}",
        "  {GRIS}System disk: {} free of {} ({occupe}% used).{RESET}",
        taille_lisible(libre),
        taille_lisible(total)
    )
}

fn precision(e: &Element) -> String {
    match e.taille {
        _ if e.propre() => tr!("déjà propre", "already clean").into(),
        Some(t) => taille_lisible(t),
        None => tr!("mesuré après", "measured after").into(),
    }
}

fn detail(e: &Element) -> String {
    match e.prudence {
        Some(p) => format!("{} ⚠ {p}", e.effet),
        None => e.effet.clone(),
    }
}

fn mesurer() -> Vec<Element> {
    trp!(
        "  {GRIS}Mesure de la place à libérer…{RESET}",
        "  {GRIS}Measuring the space to free…{RESET}"
    );
    systeme::elements()
}

/// Place que le nettoyage recommandé (ce qui se refait seul) libérerait, mesurée sans rien afficher ni effacer :
/// pour l'entretien du mois.
pub fn place_a_liberer() -> u64 {
    somme(
        systeme::elements()
            .iter()
            .filter(|e| e.recommande && !e.propre())
            .filter_map(|e| e.taille),
    )
}

/// Ce qui va être nettoyé, montré avant de demander : titre et place, commandes, et le revers coupé pour tenir dans
/// `LARGEUR` (d'une traite, le terminal le coupait au milieu des mots).
fn a_nettoyer(choisis: &[&Element]) -> Vec<String> {
    let mut lignes = Vec::new();
    for e in choisis {
        lignes.push(format!("    {VERT}−{RESET} {}  {GRIS}{}{RESET}", e.titre, precision(e)));
        lignes.extend(
            e.commandes
                .iter()
                .map(|c| format!("        {GRIS}{}{RESET}", crate::ui::commande_affichable(c))),
        );
        if let Some(p) = e.prudence {
            let morceaux = envelopper(p, LARGEUR - 10);
            for (i, m) in morceaux.iter().enumerate() {
                lignes.push(format!("{}{m}", if i == 0 { "        ⚠ " } else { "          " }));
            }
        }
    }
    lignes
}

/// « vanguard nettoyer » : liste à cocher, puis nettoyage après accord et bilan de la place gagnée.
pub fn menu() {
    let elements = mesurer();
    let avant = place();
    let mut entete = vec![
        String::new(),
        ligne_titre(tr!("Nettoyer le système", "Clean up the system")),
    ];
    if let Some((libre, total, _)) = avant {
        entete.push(ligne_place(libre, total));
    }
    entete.push(trf!(
        "  {GRIS}Coché d'office : ce qui se refait seul. Rien de personnel n'est touché.{RESET}",
        "  {GRIS}Checked by default: what rebuilds itself. Nothing personal is touched.{RESET}"
    ));
    entete.push(String::new());
    let cases: Vec<Case> = elements
        .iter()
        .map(|e| Case {
            texte: e.titre.to_string(),
            precision: precision(e),
            detail: detail(e),
            cochee: e.recommande && !e.propre(),
            recommandee: e.recommande,
            fixe: e.propre(),
        })
        .collect();
    let Some(voulu) = cocher(&entete, &cases) else {
        return;
    };
    let choisis: Vec<&Element> = elements
        .iter()
        .zip(&voulu)
        .filter(|(e, v)| **v && !e.propre())
        .map(|(e, _)| e)
        .collect();
    if choisis.is_empty() {
        trp!("  {GRIS}Rien à nettoyer.{RESET}", "  {GRIS}Nothing to clean.{RESET}");
        return;
    }
    trp!("\n  {GRAS}À nettoyer{RESET}", "\n  {GRAS}To clean{RESET}");
    for l in a_nettoyer(&choisis) {
        println!("{l}");
    }
    let connu = somme(choisis.iter().filter_map(|e| e.taille));
    if connu >= PRESQUE_RIEN {
        trp!(
            "\n  Au moins {} à libérer.",
            "\n  At least {} to free.",
            taille_lisible(connu)
        );
    }
    if !demander(tr!("\n  Nettoyer ? [o/N] : ", "\n  Clean up? [y/N]: ")).oui() {
        trp!("  Annulé.", "  Cancelled.");
        return;
    }
    let resultats = systeme::executer(&choisis);
    println!();
    for (e, ok) in choisis.iter().zip(&resultats) {
        if *ok {
            println!("  {VERT}✔{RESET} {}", e.titre);
        } else {
            trp!(
                "  ✖ {} : pas fait en entier, voir le message ci-dessus",
                "  ✖ {}: not fully done, see the message above",
                e.titre
            );
        }
    }
    // Ce qui a vraiment été gagné : la place libre relue, pas la somme des estimations.
    if let (Some((_, _, avant_cumul)), Some((libre, total, apres_cumul))) = (avant, place()) {
        let gagne = apres_cumul.saturating_sub(avant_cumul);
        trp!(
            "\n  {VERT}Place libérée : {}.{RESET}",
            "\n  {VERT}Space freed: {}.{RESET}",
            taille_lisible(gagne)
        );
        println!("{}", ligne_place(libre, total));
    }
}

/// « vanguard nettoyer --liste » : ce qui pourrait être nettoyé et la place à gagner, sans rien effacer.
pub fn liste() {
    let elements = mesurer();
    titre(tr!("Nettoyer le système", "Clean up the system"));
    if let Some((libre, total, _)) = place() {
        println!("{}", ligne_place(libre, total));
    }
    println!();
    for e in &elements {
        let marque = if e.propre() {
            format!("{VERT}✔{RESET}")
        } else if e.recommande {
            "+".to_string()
        } else {
            "·".to_string()
        };
        println!("    {marque} {}{GRIS}{}{RESET}", ajuster(e.titre, 40), precision(e));
    }
    let a_liberer = |reco: bool| {
        somme(
            elements
                .iter()
                .filter(|e| !e.propre() && (e.recommande || !reco))
                .filter_map(|e| e.taille),
        )
    };
    let bilan = trf!(
        "« + » : coché d'office, au moins {} à libérer ({} avec le reste).",
        "“+”: checked by default, at least {} to free ({} with the rest).",
        taille_lisible(a_liberer(true)),
        taille_lisible(a_liberer(false))
    );
    println!();
    afficher_aligne("  ", &bilan, 2, "");
    // Sur sa ligne : coupée en deux, la phrase ne se lirait plus d'un trait.
    trp!("  Rien n'a été effacé.", "  Nothing was deleted.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailles_lisibles() {
        assert!(taille_lisible(0).contains('1'));
        assert_eq!(taille_lisible(340 << 20), trf!("340 Mo", "340 MB"));
        assert_eq!(taille_lisible((3 << 30) / 2), trf!("1,5 Go", "1.5 GB"));
    }

    #[test]
    fn taille_d_un_dossier_avec_exclusions() {
        let racine = std::env::temp_dir().join(format!("vanguard-nettoyer-{}", std::process::id()));
        let garde = racine.join("garde");
        std::fs::create_dir_all(&garde).unwrap();
        std::fs::create_dir_all(racine.join("sous")).unwrap();
        std::fs::write(racine.join("a"), vec![0u8; 1000]).unwrap();
        std::fs::write(racine.join("sous/b"), vec![0u8; 500]).unwrap();
        std::fs::write(garde.join("c"), vec![0u8; 7000]).unwrap();
        assert_eq!(taille_dossier(&racine, Age::Tout, &[]), Some(8500));
        assert_eq!(
            taille_dossier(&racine, Age::Tout, std::slice::from_ref(&garde)),
            Some(1500)
        );
        // Rien d'assez vieux : des fichiers écrits à l'instant.
        assert_eq!(taille_dossier(&racine, Age::NonModifieDepuis(7), &[]), Some(0));
        assert_eq!(taille_dossier(&racine.join("absent"), Age::Tout, &[]), None);
        std::fs::remove_dir_all(&racine).unwrap();
    }

    /// Des fichiers creux annoncent chacun 4 Eio sans rien occuper (tmpfs, btrfs, XFS, APFS) : à quatre, leur somme
    /// dépasse un u64. Les tests vérifient les dépassements comme la version publiée : une somme ordinaire paniquait
    /// ici, et avec elle nettoyer, l'entretien du mois (corbeille et caches sont toujours mesurés) et le dépannage.
    /// Un système de fichiers qui refuse une telle taille (ext4, NTFS) ne peut pas porter le piège : rien à mesurer.
    #[cfg(unix)]
    #[test]
    fn des_fichiers_creux_ne_font_pas_deborder_les_tailles() {
        assert_eq!(somme([u64::MAX - 1, 1, u64::MAX]), u64::MAX);
        let racine = std::env::temp_dir().join(format!("vanguard-creux-{}", std::process::id()));
        let cache = racine.join("cache");
        let oublie = SystemTime::now() - Duration::from_hours(200 * 24);
        let creux = |f: &str| {
            let chemin = cache.join(f);
            std::fs::create_dir_all(chemin.parent().unwrap()).unwrap();
            std::fs::File::create(&chemin)
                .and_then(|fichier| {
                    fichier.set_len(1 << 62)?;
                    fichier.set_times(std::fs::FileTimes::new().set_accessed(oublie).set_modified(oublie))
                })
                .is_ok()
        };
        if ["a/1", "a/2", "a/3", "a/4", "b/1"].into_iter().all(creux) {
            assert_eq!(taille_dossier(&racine, Age::Tout, &[]), Some(u64::MAX));
            let echeance = Instant::now() + Duration::from_secs(10);
            assert_eq!(
                dernier_usage(&cache.join("a"), echeance).map(|(t, _)| t),
                Some(u64::MAX)
            );
            // Deux caches oubliés, dont un déjà plafonné : leur somme l'est aussi.
            let e = caches_inutilises(&cache, "~/.cache", &[], true).unwrap();
            assert_eq!(e.taille, Some(u64::MAX));
        }
        std::fs::remove_dir_all(&racine).unwrap();
    }

    /// Un faux ~/.cache : une application oubliée, une encore servie (un seul fichier lu récemment), un dossier
    /// compté à part, un lien vers un autre disque. Seule l'oubliée part, en entier, par la vraie commande.
    #[cfg(unix)]
    #[test]
    fn un_cache_part_en_entier_ou_pas_du_tout() {
        let racine = std::env::temp_dir().join(format!("vanguard-caches-{}", std::process::id()));
        let cache = racine.join("cache");
        let ecrire = |f: &str, jours: u64| {
            let chemin = cache.join(f);
            std::fs::create_dir_all(chemin.parent().unwrap()).unwrap();
            std::fs::write(&chemin, "abc").unwrap();
            let date = SystemTime::now() - Duration::from_secs(jours * 86_400);
            let dates = std::fs::FileTimes::new().set_accessed(date).set_modified(date);
            std::fs::File::options()
                .write(true)
                .open(&chemin)
                .unwrap()
                .set_times(dates)
                .unwrap();
        };
        ecrire("oubliee/venv/lib/module.py", 200);
        ecrire("oubliee/venv/bin/python", 120);
        ecrire("servie/navigateur/chrome", 300);
        ecrire("servie/navigateur/lu-hier", 1);
        ecrire("comptee-a-part/vieux", 200);
        ecrire("fichier seul", 100);
        std::fs::create_dir_all(cache.join("vide")).unwrap();
        std::os::unix::fs::symlink(racine.join("ailleurs"), cache.join("lien")).unwrap();

        let endormis = caches_endormis(&cache, 90, &["comptee-a-part"]);
        assert_eq!(endormis, [("fichier seul".to_string(), 3), ("oubliee".to_string(), 6)]);
        let affiche = cache.display().to_string();
        let commande = effacer_caches(&affiche, &endormis);
        assert_eq!(
            commande,
            format!("rm -rf -- {affiche}/'fichier seul' {affiche}/oubliee")
        );
        let lancee = std::process::Command::new("bash").args(["-c", &commande]).status();
        assert!(lancee.is_ok_and(|s| s.success()));
        assert!(!cache.join("oubliee").exists() && !cache.join("fichier seul").exists());
        for garde in ["servie/navigateur/chrome", "comptee-a-part/vieux", "vide", "lien"] {
            assert!(cache.join(garde).symlink_metadata().is_ok(), "{garde} effacé");
        }
        // Dates de lecture pas tenues (noatime) : l'élément n'est pas proposé du tout.
        assert!(caches_inutilises(&cache, "~/.cache", &[], false).is_none());
        let e = caches_inutilises(&cache, "~/.cache", &["comptee-a-part"], true).unwrap();
        assert_eq!(e.taille, Some(0), "plus rien d'oublié après le nettoyage");
        std::fs::remove_dir_all(&racine).unwrap();
    }

    /// Les messages de Nettoyer tiennent dans `LARGEUR` colonnes, dans les deux langues (les fichiers de chaque
    /// système ne font que décrire les éléments).
    #[test]
    fn messages_dans_la_largeur() {
        let larges = crate::ui::textes_trop_larges(include_str!("mod.rs"));
        assert_eq!(larges, Vec::<String>::new());
    }

    /// Avant de demander, la liste de ce qui va être nettoyé montre le revers de chaque élément, coupé pour tenir
    /// dans `LARGEUR` ; les commandes, elles, restent entières (elles se copient).
    #[test]
    fn resume_dans_la_largeur() {
        let e = Element {
            titre: "Paquets devenus inutiles",
            effet: "Paquets installés pour un autre que plus rien n'utilise.".into(),
            prudence: Some(
                "La liste s'affiche et se confirme avant : vérifiez qu'elle ne contient rien que vous utilisez.",
            ),
            taille: None,
            commandes: vec!["sudo apt-get autoremove --purge".into()],
            recommande: false,
            admin: true,
        };
        let lignes = a_nettoyer(&[&e]);
        let commande = format!("        {GRIS}");
        for l in lignes.iter().filter(|l| !l.starts_with(&commande)) {
            assert!(largeur_affichee(l) <= LARGEUR, "{} colonnes : {l}", largeur_affichee(l));
        }
        assert!(
            lignes.iter().any(|l| l.starts_with("        ⚠ La liste")),
            "{lignes:#?}"
        );
    }

    #[test]
    fn chaque_element_tient_dans_la_liste() {
        for e in systeme::elements() {
            assert!(largeur_affichee(e.titre) <= 38, "{} : titre trop long", e.titre);
            assert!(!e.effet.is_empty() && !e.commandes.is_empty(), "{}", e.titre);
            assert!(largeur_affichee(&precision(&e)) <= 33);
            assert!(
                envelopper(&detail(&e), LARGEUR - 4).len() <= 3,
                "{} : explication trop longue",
                e.titre
            );
        }
    }
}
