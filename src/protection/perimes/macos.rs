//! L'inventaire sous macOS : les applications de `/Applications` et `~/Applications` (en root, celles de chaque compte,
//! `/Users/*/Applications`), reconnues à leur identifiant exact (`CFBundleIdentifier`) ; les Java de
//! `/Library/Java/JavaVirtualMachines` ; 7-Zip et PuTTY, sans application, dans le `Cellar` de Homebrew. Le parcours ne
//! suit aucun lien, ne descend que d'un dossier ordinaire sous la racine (Utilities, « Adobe Acrobat DC »), jamais dans
//! une application, et ne touche ni Téléchargements, ni Bureau, ni Documents (protégés par TCC). Une application lancée
//! depuis une image disque passe inaperçue.
//!
//! Compilé aussi pour les tests sous Linux (arbre jetable).

use std::io::Read;
use std::path::{Path, PathBuf};

use super::inventaire::{Branche, Installe, Inventaire, NonLu, Plateforme, java_dans};
use super::produits::{self, CleMac, Produit};
use super::version::{self, Version};
use crate::plist::{Lu, Valeur};

/// Entrées lues au plus par dossier.
const ENTREES_MAX: usize = 2000;
/// Applications examinées au plus en tout.
const APPS_MAX: usize = 1000;

/// Un dossier d'applications et le compte à qui il appartient (`None` : celui de la machine).
#[derive(Debug, Clone)]
pub(crate) struct Racine {
    pub dossier: PathBuf,
    pub compte: Option<String>,
}

/// Les dossiers d'applications : `/Applications`, celui du compte (`maison`), et en root ceux de chaque compte
/// sous `utilisateurs` (sauf `Shared`).
pub(crate) fn racines(maison: &Path, utilisateurs: Option<&Path>) -> Vec<Racine> {
    let compte = |d: &Path| d.file_name().map(|n| crate::ui::affichable(&n.to_string_lossy()));
    let mut racines = vec![Racine {
        dossier: PathBuf::from("/Applications"),
        compte: None,
    }];
    let mut maisons = Vec::new();
    if maison.is_absolute() && maison != Path::new("/") {
        maisons.push(maison.to_path_buf());
    }
    if let Some(utilisateurs) = utilisateurs {
        for (chemin, est_dossier) in entrees(utilisateurs).unwrap_or_default() {
            if est_dossier && chemin.file_name().is_some_and(|n| n != "Shared") && !maisons.contains(&chemin) {
                maisons.push(chemin);
            }
        }
    }
    racines.extend(maisons.into_iter().map(|m| Racine {
        compte: compte(&m),
        dossier: m.join("Applications"),
    }));
    racines
}

/// Les entrées d'un dossier (bornées) : (chemin, dossier ordinaire ?), sans suivre de lien. `Err` : le dossier
/// existe mais ne s'ouvre pas.
fn entrees(dossier: &Path) -> std::io::Result<Vec<(PathBuf, bool)>> {
    Ok(std::fs::read_dir(dossier)?
        .take(ENTREES_MAX)
        .flatten()
        .map(|e| {
            let chemin = e.path();
            let est_dossier = std::fs::symlink_metadata(&chemin).is_ok_and(|m| m.is_dir());
            (chemin, est_dossier)
        })
        .collect())
}

fn est_app(chemin: &Path) -> bool {
    chemin.extension().is_some_and(|e| e == "app")
}

/// Les applications d'une racine : `X.app` au premier niveau, ou dans un dossier ordinaire du premier niveau ;
/// jamais dans une application, jamais par un lien. `apps` compte les applications vues, toutes racines confondues.
fn applications(racine: &Path, apps: &mut usize, inv: &mut Inventaire) -> Vec<PathBuf> {
    let mut trouvees = Vec::new();
    let premier = match entrees(racine) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return trouvees,
        Err(_) => {
            inv.non_lu(NonLu::Dossier(racine.to_path_buf()));
            return trouvees;
        }
    };
    let mut garder = |chemin: PathBuf, inv: &mut Inventaire| {
        if *apps >= APPS_MAX {
            inv.trop(1);
        } else {
            *apps += 1;
            trouvees.push(chemin);
        }
    };
    for (chemin, est_dossier) in premier {
        if !est_dossier {
            continue;
        }
        if est_app(&chemin) {
            garder(chemin, inv);
            continue;
        }
        for (sous, sous_dossier) in entrees(&chemin).unwrap_or_default() {
            if sous_dossier && est_app(&sous) {
                garder(sous, inv);
            }
        }
    }
    trouvees
}

/// L'architecture d'un exécutable Mach-O d'après ses premiers octets : fin (« fat ») avec Intel et Apple Silicon,
/// ou d'une seule architecture. Lecteur pur, borné aux 8 + 20 × 8 premiers octets.
pub(crate) fn plateforme_macho(octets: &[u8]) -> Plateforme {
    const X86_64: u32 = 0x0100_0007;
    const ARM64: u32 = 0x0100_000C;
    let mot = |a: usize, gros: bool| {
        let o: [u8; 4] = octets.get(a..a + 4)?.try_into().ok()?;
        Some(if gros {
            u32::from_be_bytes(o)
        } else {
            u32::from_le_bytes(o)
        })
    };
    let une = |cpu: u32| match cpu {
        X86_64 => Plateforme::X64,
        ARM64 => Plateforme::Arm64,
        _ => Plateforme::Inconnue,
    };
    match mot(0, true) {
        // Fin : magique en gros-boutiste, puis le nombre d'architectures et leurs entrées de 20 octets.
        Some(0xCAFE_BABE) => {
            let n = usize::try_from(mot(4, true).unwrap_or(0).min(8)).unwrap_or(0);
            let cpus: Vec<Plateforme> = (0..n).filter_map(|i| mot(8 + 20 * i, true)).map(une).collect();
            match (cpus.contains(&Plateforme::X64), cpus.contains(&Plateforme::Arm64)) {
                (true, true) => Plateforme::Universel,
                (true, false) => Plateforme::X64,
                (false, true) => Plateforme::Arm64,
                (false, false) => Plateforme::Inconnue,
            }
        }
        // Mach-O 64 bits en petit-boutiste (0xFEEDFACF lu à l'envers).
        Some(0xCFFA_EDFE) => mot(4, false).map_or(Plateforme::Inconnue, une),
        _ => Plateforme::Inconnue,
    }
}

/// L'architecture de l'exécutable de l'application (`CFBundleExecutable`, un nom simple dans `Contents/MacOS`).
fn plateforme(app: &Path, plist: &Valeur) -> Plateforme {
    let Some(nom) = plist.cle("CFBundleExecutable").and_then(Valeur::texte) else {
        return Plateforme::Inconnue;
    };
    if nom.is_empty() || nom.contains('/') || nom == ".." || nom == "." {
        return Plateforme::Inconnue;
    }
    let chemin = app.join("Contents").join("MacOS").join(nom);
    if !std::fs::symlink_metadata(&chemin).is_ok_and(|m| m.is_file()) {
        return Plateforme::Inconnue;
    }
    // Ouvert sans attendre, puis vérifié sur le descripteur : un compte qui change le fichier en tube nommé entre
    // la vérification du chemin et l'ouverture bloquerait sinon le parcours, lancé en root, pour toujours.
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let Ok(fichier) = options.open(&chemin) else {
        return Plateforme::Inconnue;
    };
    if !fichier.metadata().is_ok_and(|m| m.is_file()) {
        return Plateforme::Inconnue;
    }
    let mut octets = Vec::new();
    match fichier.take(8 + 20 * 8).read_to_end(&mut octets) {
        Ok(_) => plateforme_macho(&octets),
        Err(_) => Plateforme::Inconnue,
    }
}

/// La version d'une application suivie, rendue comparable selon son produit ; `None` : forme inconnue.
fn normaliser(produit: Produit, cle: CleMac, texte: &str) -> Option<Version> {
    match (produit, cle) {
        (Produit::Chrome | Produit::Edge, _) => version::chrome_edge(texte),
        (Produit::Firefox, _) => version::firefox(texte),
        (Produit::Brave, _) => version::brave(texte),
        (Produit::Acrobat | Produit::Reader, _) => version::adobe(texte),
        (Produit::Slack, _) => Version::lire(texte).filter(|v| v.longueur() == 3),
        // « 16.114.26102031 », comparé à « Update Version » de Microsoft AutoUpdate.
        (Produit::Office, CleMac::Build) => Version::lire(texte).filter(|v| v.longueur() == 3),
        (Produit::Office, CleMac::Courte) | (Produit::Java(_) | Produit::SevenZip | Produit::PuTTY, _) => None,
    }
}

/// Une application : suivie si son identifiant est dans la table (sinon rien d'autre n'est lu). `Err` : son
/// Info.plist n'a pas pu être lu.
fn application(app: &Path) -> Result<Option<Installe>, ()> {
    let plist = match crate::plist::lire_fichier(&app.join("Contents").join("Info.plist")) {
        Ok(Lu::Plist(v)) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => return Err(()),
    };
    let Some((produit, fiche)) = plist
        .cle("CFBundleIdentifier")
        .and_then(Valeur::texte)
        .and_then(produits::app_mac)
    else {
        return Ok(None);
    };
    let brute = plist.cle(fiche.cle.nom()).and_then(Valeur::texte).unwrap_or_default();
    let mut i = Installe::nouveau(produit, brute, normaliser(produit, fiche.cle, brute), app);
    i.app = Some(fiche);
    i.plateforme = plateforme(app, &plist);
    i.branche = if std::fs::symlink_metadata(app.join("Contents").join("_MASReceipt").join("receipt")).is_ok() {
        Branche::Canal("App Store".into())
    } else if produit == Produit::Firefox {
        let prefs = app
            .join("Contents")
            .join("Resources")
            .join("defaults")
            .join("pref")
            .join("channel-prefs.js");
        match super::lecteurs::texte_borne(&prefs)
            .and_then(|t| super::lecteurs::canal_prefs(&t))
            .as_deref()
        {
            Some("esr") => Branche::Esr,
            Some("release") => Branche::Release,
            Some(autre) => Branche::Canal(autre.to_string()),
            None => Branche::Inconnue,
        }
    } else {
        let classic = matches!(produit, Produit::Acrobat | Produit::Reader)
            && i.version
                .is_some_and(|v| v.champs().get(2).is_some_and(|&c| c >= 30000));
        if classic { Branche::Classic } else { Branche::Release }
    };
    Ok(Some(i))
}

/// Les préfixes de Homebrew : Apple Silicon, puis Intel.
#[cfg(target_os = "macos")]
const HOMEBREW: [&str; 2] = ["/opt/homebrew", "/usr/local"];

/// La version d'un dossier du `Cellar` (« 26.05 », « 0.85_1 » : la révision de la formule, après « _ », n'est pas
/// celle du logiciel).
fn version_cellar(nom: &str) -> Option<Version> {
    let base = match nom.rsplit_once('_') {
        Some((base, revision)) if !revision.is_empty() && revision.bytes().all(|o| o.is_ascii_digit()) => base,
        _ => nom,
    };
    Version::lire(base)
}

/// Les logiciels installés par une formule de Homebrew sous `prefixe` : la version liée (`opt/<formule>`, un lien
/// relatif lu sans être suivi, vers `../Cellar/<formule>/<version>`), sinon la plus haute du `Cellar` (une vieille
/// version reste tant que Homebrew ne fait pas le ménage).
fn homebrew_dans(prefixe: &Path, inv: &mut Inventaire) {
    for fiche in produits::FICHES {
        for formule in fiche.homebrew {
            let cellar = prefixe.join("Cellar").join(formule);
            let version_liee = std::fs::read_link(prefixe.join("opt").join(formule))
                .ok()
                .and_then(|cible| Some(cible.file_name()?.to_str()?.to_string()))
                .filter(|n| std::fs::symlink_metadata(cellar.join(n)).is_ok_and(|m| m.is_dir()));
            let nom = version_liee.or_else(|| {
                entrees(&cellar)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|(_, d)| *d)
                    .filter_map(|(c, _)| {
                        let n = c.file_name()?.to_str()?.to_string();
                        Some((version_cellar(&n)?, n))
                    })
                    .max_by_key(|(v, _)| *v)
                    .map(|(_, n)| n)
            });
            let Some(nom) = nom else { continue };
            let lieu = cellar.join(&nom);
            let brute = nom.rsplit_once('_').map_or(nom.as_str(), |(b, _)| b);
            let mut i = Installe::nouveau(fiche.produit, brute, version_cellar(&nom), &lieu);
            i.branche = Branche::Release;
            inv.ajouter(i);
        }
    }
}

/// L'inventaire de ces racines, des Java installés sous `jvm` (fichier `release` du dossier `Contents/Home` de
/// chaque `*.jdk`) et des formules suivies sous chaque préfixe de Homebrew.
pub(crate) fn inventaire_dans(racines: &[Racine], jvm: &Path, homebrew: &[&Path]) -> Inventaire {
    let mut inv = Inventaire::default();
    let mut apps = 0;
    for racine in racines {
        for app in applications(&racine.dossier, &mut apps, &mut inv) {
            match application(&app) {
                Ok(Some(mut i)) => {
                    i.compte.clone_from(&racine.compte);
                    inv.ajouter(i);
                }
                Ok(None) => {}
                Err(()) => inv.non_lu(NonLu::Illisible(app)),
            }
        }
    }
    for (jdk, est_dossier) in entrees(jvm).unwrap_or_default() {
        if est_dossier && jdk.extension().is_some_and(|e| e == "jdk") {
            let home = jdk.join("Contents").join("Home");
            if let Some(mut i) = java_dans(&home) {
                i.lieu = jdk;
                inv.ajouter(i);
            }
        }
    }
    for prefixe in homebrew {
        homebrew_dans(prefixe, &mut inv);
    }
    inv
}

/// Les comptes sous `utilisateurs` dont les applications ne sont pas lues sans root : tous sauf celui de `maison`
/// (et `Shared`), avec le même filtre que `racines`.
pub(crate) fn comptes_non_lus(maison: &Path, utilisateurs: &Path) -> usize {
    racines(maison, Some(utilisateurs))
        .len()
        .saturating_sub(racines(maison, None).len())
}

/// L'inventaire de ce Mac : en root, les applications de chaque compte aussi.
#[cfg(target_os = "macos")]
pub(crate) fn inventaire() -> Inventaire {
    // SAFETY: geteuid ne prend aucun argument et ne peut pas échouer.
    let root = unsafe { libc::geteuid() } == 0;
    let maison = crate::socle::maison();
    let utilisateurs = Path::new("/Users");
    let racines = racines(&maison, root.then_some(utilisateurs));
    let homebrew = HOMEBREW.map(Path::new);
    let mut inv = inventaire_dans(&racines, Path::new("/Library/Java/JavaVirtualMachines"), &homebrew);
    if !root {
        // Sans root, les ~/Applications des autres comptes ne sont pas lues : le dire, jamais le taire.
        let autres = comptes_non_lus(&maison, utilisateurs);
        if autres > 0 {
            inv.non_lu(NonLu::Comptes(autres));
        }
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-perimes-mac-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Une application inventée : son Info.plist XML (identifiant, version courte, build, exécutable) et son
    /// exécutable (les premiers octets d'un Mach-O).
    fn app(dossier: &Path, id: &str, courte: &str, build: &str, macho: &[u8]) -> PathBuf {
        let contenu = dossier.join("Contents");
        std::fs::create_dir_all(contenu.join("MacOS")).unwrap();
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>{id}</string>\
             <key>CFBundleShortVersionString</key><string>{courte}</string>\
             <key>CFBundleVersion</key><string>{build}</string>\
             <key>CFBundleExecutable</key><string>principal</string></dict></plist>"
        );
        std::fs::write(contenu.join("Info.plist"), plist).unwrap();
        std::fs::write(contenu.join("MacOS").join("principal"), macho).unwrap();
        dossier.to_path_buf()
    }

    fn fin(cpus: &[u32]) -> Vec<u8> {
        let mut o = 0xCAFE_BABEu32.to_be_bytes().to_vec();
        o.extend(u32::try_from(cpus.len()).unwrap().to_be_bytes());
        for c in cpus {
            o.extend(c.to_be_bytes());
            o.extend([0u8; 16]);
        }
        o
    }

    #[test]
    fn architectures() {
        assert_eq!(
            plateforme_macho(&fin(&[0x0100_0007, 0x0100_000C])),
            Plateforme::Universel
        );
        assert_eq!(plateforme_macho(&fin(&[0x0100_000C])), Plateforme::Arm64);
        let mut mince = 0xFEED_FACFu32.to_le_bytes().to_vec();
        mince.extend(0x0100_0007u32.to_le_bytes());
        assert_eq!(plateforme_macho(&mince), Plateforme::X64);
        assert_eq!(plateforme_macho(b""), Plateforme::Inconnue);
        assert_eq!(plateforme_macho(&0xCAFE_BABEu32.to_be_bytes()), Plateforme::Inconnue);
        let mut menteur = 0xCAFE_BABEu32.to_be_bytes().to_vec();
        menteur.extend(u32::MAX.to_be_bytes());
        assert_eq!(plateforme_macho(&menteur), Plateforme::Inconnue);
    }

    /// Un arbre jetable : Chrome universel, Word (build), Firefox ESR, Brave d'une forme inconnue, Reader dans un
    /// sous-dossier, une application hors table, une de l'App Store, un .app dans un .app, un Info.plist illisible,
    /// un lien vers la racine et un Java.
    #[test]
    fn inventaire_d_un_arbre_jetable() {
        let d = jetable("arbre");
        let apps = d.join("Applications");
        let universel = fin(&[0x0100_0007, 0x0100_000C]);
        app(
            &apps.join("Google Chrome.app"),
            "com.google.Chrome",
            "156.0.8078.48",
            "8078.48",
            &universel,
        );
        app(
            &apps.join("Microsoft Word.app"),
            "com.microsoft.Word",
            "16.114.1",
            "16.114.26102031",
            &universel,
        );
        let firefox = app(
            &apps.join("Firefox.app"),
            "org.mozilla.firefox",
            "153.5.1esr",
            "15326.10.20",
            b"",
        );
        let prefs = firefox.join("Contents").join("Resources").join("defaults").join("pref");
        std::fs::create_dir_all(&prefs).unwrap();
        std::fs::write(prefs.join("channel-prefs.js"), "pref(\"app.update.channel\", \"esr\");").unwrap();
        app(
            &apps.join("Brave Browser.app"),
            "com.brave.Browser",
            "198.60",
            "198.60",
            b"",
        );
        app(
            &apps.join("Adobe Acrobat DC").join("Adobe Acrobat Reader.app"),
            "com.adobe.Reader",
            "26.002.22031",
            "26.002.22031",
            b"",
        );
        app(&apps.join("Example.app"), "com.example.Editeur", "1.0", "1", b"");
        let magasin = app(
            &apps.join("Microsoft Excel.app"),
            "com.microsoft.Excel",
            "16.114",
            "16.114.26102031",
            b"",
        );
        std::fs::create_dir_all(magasin.join("Contents").join("_MASReceipt")).unwrap();
        std::fs::write(magasin.join("Contents").join("_MASReceipt").join("receipt"), b"").unwrap();
        app(
            &apps.join("Hote.app").join("Contents").join("Edge.app"),
            "com.microsoft.edgemac",
            "156.0.4314.42",
            "1",
            b"",
        );
        app(
            &apps.join("Profond").join("Plus").join("Edge.app"),
            "com.microsoft.edgemac",
            "156.0.4314.42",
            "1",
            b"",
        );
        let abime = apps.join("Abime.app").join("Contents");
        std::fs::create_dir_all(&abime).unwrap();
        std::fs::write(abime.join("Info.plist"), b"<plist><dict><key>").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/", apps.join("Racine.app")).unwrap();
        let jvm = d.join("JavaVirtualMachines");
        let home = jvm.join("temurin-21.jdk").join("Contents").join("Home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("release"),
            "IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"21.0.13\"\nOS_ARCH=\"aarch64\"\n",
        )
        .unwrap();
        let racines = [Racine {
            dossier: apps.clone(),
            compte: Some("alice".into()),
        }];
        let inv = inventaire_dans(&racines, &jvm, &[]);
        let trouve = |p: Produit| {
            inv.installes
                .iter()
                .find(|i| i.produit == p)
                .unwrap_or_else(|| panic!("{p:?} : {inv:?}"))
        };
        let chrome = trouve(Produit::Chrome);
        assert_eq!(
            (chrome.version.map(|v| v.to_string()), chrome.plateforme),
            (Some("156.0.8078.48".into()), Plateforme::Universel)
        );
        assert_eq!(chrome.compte.as_deref(), Some("alice"));
        let words: Vec<&Installe> = inv.installes.iter().filter(|i| i.produit == Produit::Office).collect();
        assert_eq!(words.len(), 2);
        let word = words
            .iter()
            .find(|i| i.app.is_some_and(|a| a.source == Some("mau-MSWD2019")))
            .unwrap();
        assert_eq!(
            (word.brute.as_str(), word.branche.clone()),
            ("16.114.26102031", Branche::Release)
        );
        let excel = words
            .iter()
            .find(|i| i.app.is_some_and(|a| a.source == Some("mau-XCEL2019")))
            .unwrap();
        assert_eq!(excel.branche, Branche::Canal("App Store".into()));
        let firefox_lu = trouve(Produit::Firefox);
        assert_eq!(
            (firefox_lu.version.map(|v| v.to_string()), firefox_lu.branche.clone()),
            (Some("153.5.1".into()), Branche::Esr)
        );
        let brave = trouve(Produit::Brave);
        assert_eq!((brave.brute.as_str(), brave.version), ("198.60", None));
        assert_eq!(
            trouve(Produit::Reader).version.map(|v| v.to_string()).as_deref(),
            Some("26.2.22031")
        );
        let java = trouve(Produit::Java(super::super::produits::Distribution::Temurin));
        assert_eq!(
            (java.plateforme, java.lieu.clone()),
            (Plateforme::Arm64, jvm.join("temurin-21.jdk"))
        );
        // Ni le .app dans un .app, ni celui de deux niveaux, ni le lien : pas d'Edge.
        assert!(inv.installes.iter().all(|i| i.produit != Produit::Edge), "{inv:?}");
        assert_eq!(inv.installes.len(), 7, "{inv:?}");
        assert_eq!(inv.non_lus, vec![NonLu::Illisible(apps.join("Abime.app"))]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Slack par son application ; 7-Zip et PuTTY par le Cellar de Homebrew : la version liée, sinon la plus haute,
    /// révision de la formule retirée.
    #[test]
    fn slack_et_formules_de_homebrew() {
        let d = jetable("homebrew");
        let apps = d.join("Applications");
        app(
            &apps.join("Slack.app"),
            "com.tinyspeck.slackmacgap",
            "4.52.182",
            "452182",
            b"",
        );
        let brew = d.join("homebrew");
        for v in ["26.04", "26.05_1"] {
            std::fs::create_dir_all(brew.join("Cellar").join("sevenzip").join(v).join("bin")).unwrap();
        }
        for v in ["0.84", "0.85"] {
            std::fs::create_dir_all(brew.join("Cellar").join("putty").join(v)).unwrap();
        }
        std::fs::create_dir_all(brew.join("opt")).unwrap();
        // Liée à la 0.84 (pas encore relancée après la mise à jour) : c'est celle qui tourne.
        #[cfg(unix)]
        std::os::unix::fs::symlink("../Cellar/putty/0.84", brew.join("opt").join("putty")).unwrap();
        std::fs::create_dir_all(brew.join("Cellar").join("p7zip").join("17.06")).unwrap();
        let racines = [Racine {
            dossier: apps.clone(),
            compte: None,
        }];
        let inv = inventaire_dans(&racines, &d.join("jvm"), &[&brew, &d.join("absent")]);
        let trouve = |p: Produit| {
            inv.installes
                .iter()
                .find(|i| i.produit == p)
                .unwrap_or_else(|| panic!("{p:?} : {inv:?}"))
        };
        let slack = trouve(Produit::Slack);
        assert_eq!(
            (slack.version.map(|v| v.to_string()), slack.branche.clone()),
            (Some("4.52.182".into()), Branche::Release)
        );
        let sept = trouve(Produit::SevenZip);
        assert_eq!(
            (sept.brute.as_str(), sept.version.map(|v| v.to_string())),
            ("26.05", Some("26.5".into()))
        );
        assert_eq!(sept.lieu, brew.join("Cellar").join("sevenzip").join("26.05_1"));
        #[cfg(unix)]
        assert_eq!(trouve(Produit::PuTTY).brute, "0.84");
        assert_eq!(inv.installes.len(), 3, "{inv:?}");
        assert_eq!(version_cellar("0.85_12"), Version::lire("0.85"));
        assert_eq!(version_cellar("0.85_"), None);
        assert_eq!(version_cellar("HEAD-1a2b3c"), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn racines_des_comptes() {
        let d = jetable("racines");
        for c in ["alice", "Shared", "bob"] {
            std::fs::create_dir_all(d.join(c)).unwrap();
        }
        std::fs::write(d.join("fichier"), b"").unwrap();
        let seule = racines(&d.join("alice"), None);
        assert_eq!(seule.len(), 2);
        assert_eq!(seule[0].dossier, PathBuf::from("/Applications"));
        assert_eq!(
            (seule[1].dossier.clone(), seule[1].compte.as_deref()),
            (d.join("alice").join("Applications"), Some("alice"))
        );
        let mut tous: Vec<String> = racines(&d.join("alice"), Some(&d))
            .iter()
            .filter_map(|r| r.compte.clone())
            .collect();
        tous.sort();
        assert_eq!(tous, ["alice", "bob"]);
        assert_eq!(racines(Path::new("/"), None).len(), 1);
        assert_eq!(racines(Path::new(""), None).len(), 1);
        // Sans root, bob n'est pas lu : il se compte, Shared et son propre compte non.
        assert_eq!(comptes_non_lus(&d.join("alice"), &d), 1);
        assert_eq!(comptes_non_lus(Path::new("/var/root"), &d), 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn borne_des_applications() {
        let d = jetable("borne");
        for i in 0..5 {
            std::fs::create_dir_all(d.join(format!("A{i}.app"))).unwrap();
        }
        let mut inv = Inventaire::default();
        let mut vues = APPS_MAX - 2;
        assert_eq!(applications(&d, &mut vues, &mut inv).len(), 2);
        assert_eq!(inv.non_lus, vec![NonLu::Trop(3)]);
        let mut vues = 0;
        assert_eq!(
            applications(&d.join("absent"), &mut vues, &mut inv),
            Vec::<PathBuf>::new()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'inventaire de ce Mac (celui de GitHub), en lecture seule : dans ses bornes, chaque lieu absolu.
    #[cfg(target_os = "macos")]
    #[test]
    fn inventaire_reel() {
        let inv = inventaire();
        assert!(inv.installes.len() <= 64);
        assert!(inv.installes.iter().all(|i| i.lieu.is_absolute()));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn macho_sans_plantage(octets in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200), fat in proptest::prelude::any::<bool>()) {
            let mut o = if fat { 0xCAFE_BABEu32.to_be_bytes().to_vec() } else { Vec::new() };
            o.extend(octets);
            let _ = plateforme_macho(&o);
        }
    }
}
