//! L'inventaire sous Windows, de la lecture la plus sûre à la moins sûre : la version écrite dans l'exécutable même
//! (Chrome, Edge, Brave, Acrobat, 7-Zip, PuTTY, Slack, par `pe`), puis les fichiers propres à l'éditeur
//! (`application.ini` de Firefox, `release` de Java), puis le registre (Office Click-to-Run, clés Uninstall en dernier
//! recours). Chaque compte : le sien, et en administrateur les autres (ruches chargées, dossiers `AppData` des
//! profils), sans jamais charger la ruche d'une session fermée.
//!
//! La partie fichiers se compile aussi pour les tests sous Linux (arbre jetable) ; le registre, sous Windows et Wine.

use std::path::{Path, PathBuf};

use super::inventaire::{Branche, Installe, Inventaire, Plateforme, java_dans};
use super::lecteurs;
use super::produits::{FICHES, Produit};
use super::version::{self, Version};

/// Entrées lues au plus par dossier parcouru.
const ENTREES_MAX: usize = 2000;
/// Le troisième champ des pistes Classic d'Adobe (2020, 2024) : 30000 et plus ; Continuous reste en dessous.
const ADOBE_CLASSIC: u32 = 30000;

/// Un compte dont les dossiers sont lus.
#[derive(Debug, Clone)]
pub(crate) struct Profil {
    pub compte: String,
    /// Son `AppData\Local`.
    pub local: PathBuf,
}

/// Où chercher : les dossiers `Program Files` et les profils lisibles.
#[derive(Debug, Clone, Default)]
pub(crate) struct Lieux {
    pub programmes: Vec<PathBuf>,
    pub profils: Vec<Profil>,
}

/// Une version telle que l'éditeur l'écrit dans son exécutable, son dossier ou sa clé Uninstall, rendue
/// comparable ; `None` : forme inconnue.
pub(crate) fn normaliser(produit: Produit, texte: &str) -> Option<Version> {
    match produit {
        Produit::Chrome | Produit::Edge | Produit::Office => version::chrome_edge(texte),
        Produit::Brave => version::brave(texte),
        Produit::Firefox => version::firefox(texte),
        Produit::Acrobat | Produit::Reader => version::adobe(texte),
        Produit::Java(_) => version::java_release(texte),
        // « 26.5.0.0 » dans l'exécutable de 7-Zip, « 26.05 » dans sa clé Uninstall ; PuTTY « 0.85.0.0 » ; Slack
        // « 4.52.182.0 ». Les champs à zéro ajoutés ne changent rien à la comparaison.
        Produit::SevenZip | Produit::PuTTY | Produit::Slack => Version::lire(texte).filter(|v| v.longueur() <= 4),
    }
}

/// Le nom de la dernière partie d'un chemin, s'il est en UTF-8.
fn nom(chemin: &Path) -> Option<&str> {
    chemin.file_name()?.to_str()
}

/// Les entrées d'un dossier (bornées), sans suivre de lien : (chemin, dossier ordinaire ?). `Err` : le dossier
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

fn existe(chemin: &Path) -> bool {
    std::fs::symlink_metadata(chemin).is_ok()
}

/// Les quatre nombres d'une version de fichier, écrits.
fn quatre(q: [u16; 4]) -> String {
    format!("{}.{}.{}.{}", q[0], q[1], q[2], q[3])
}

/// Un navigateur de la famille Chromium (Chrome, Edge, Brave) par son exécutable : sa version de fichier et son
/// architecture. Contrôle : les dossiers de version voisins (`Application\156.0.8078.48\`). Une mise à jour posée en
/// attente (`new_chrome.exe`) garde la version qui tourne ; sinon, si un dossier dit plus récent, le plus récent est
/// gardé et l'autre noté. `None` : pas d'exécutable à cet endroit.
pub(crate) fn navigateur(produit: Produit, exe: &Path) -> Option<Installe> {
    let meta = std::fs::symlink_metadata(exe).ok()?;
    let dossier = exe.parent()?;
    let mut i = Installe::nouveau(produit, "", None, dossier);
    if !meta.is_file() {
        return Some(i);
    }
    if let Ok(info) = crate::pe::version(exe) {
        let brute = quatre(info.fichier);
        i = Installe::nouveau(produit, &brute, normaliser(produit, &brute), dossier);
        i.plateforme = Plateforme::de_pe(info.machine);
    }
    i.attente = nom(exe).is_some_and(|n| existe(&dossier.join(format!("new_{n}"))));
    let voisine = entrees(dossier)
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, d)| *d)
        .filter_map(|(c, _)| normaliser(produit, nom(&c)?))
        .max();
    if let (Some(v), Some(d)) = (i.version, voisine)
        && d != v
    {
        if d > v && !i.attente {
            i.brute = d.to_string();
            i.version = Some(d);
            i.ecart = Some(v);
        } else {
            i.ecart = Some(d);
        }
    }
    Some(i)
}

/// Un logiciel par son seul exécutable (7-Zip, PuTTY) : sa version de fichier et son architecture. `None` : pas
/// d'exécutable à cet endroit ; illisible, il est trouvé sans version (« non vérifié »).
pub(crate) fn executable(produit: Produit, exe: &Path) -> Option<Installe> {
    let meta = std::fs::symlink_metadata(exe).ok()?;
    let dossier = exe.parent()?;
    let mut i = Installe::nouveau(produit, "", None, dossier);
    if meta.is_file()
        && let Ok(info) = crate::pe::version(exe)
    {
        let brute = quatre(info.fichier);
        i = Installe::nouveau(produit, &brute, normaliser(produit, &brute), dossier);
        i.plateforme = Plateforme::de_pe(info.machine);
    }
    i.branche = Branche::Release;
    Some(i)
}

/// La version d'un dossier `app-4.52.182` de Squirrel (Slack par compte).
fn version_squirrel(nom: &str) -> Option<Version> {
    Version::lire(nom.strip_prefix("app-")?).filter(|v| v.longueur() == 3)
}

/// Slack installé dans `dossier`. Par compte (Squirrel), `slack.exe` n'est qu'un lanceur : la version est celle du
/// plus haut dossier `app-<version>` qui contient un `slack.exe` (celui qui tourne ; l'ancien reste parfois à côté),
/// lue dans cet exécutable, sinon dans le nom du dossier. Par machine (MSI), `slack.exe` lui-même. `None` : ni l'un
/// ni l'autre.
pub(crate) fn slack_dans(dossier: &Path) -> Option<Installe> {
    let squirrel = entrees(dossier)
        .unwrap_or_default()
        .into_iter()
        .filter(|(c, d)| *d && existe(&c.join("slack.exe")))
        .filter_map(|(c, _)| Some((version_squirrel(nom(&c)?)?, c)))
        .max_by_key(|(v, _)| *v);
    let Some((v, app)) = squirrel else {
        return executable(Produit::Slack, &dossier.join("slack.exe"));
    };
    let mut i = executable(Produit::Slack, &app.join("slack.exe"))?;
    if i.version.is_none() {
        i = Installe::nouveau(Produit::Slack, &v.to_string(), Some(v), &app);
        i.branche = Branche::Release;
    }
    i.lieu = dossier.to_path_buf();
    Some(i)
}

/// 7-Zip ou PuTTY, d'après le nom affiché et l'éditeur exacts d'une clé Uninstall : « 7-Zip », « 7-Zip 26.05 »,
/// « 7-Zip 26.05 (x64) » d'Igor Pavlov ; « PuTTY release 0.85 », « PuTTY release 0.85 (64-bit) » de Simon Tatham.
/// Pour un logiciel installé ailleurs que dans `Program Files`.
pub(crate) fn produit_par_cle(nom: &str, editeur: &str) -> Option<Produit> {
    let (produit, reste) = match editeur.trim() {
        "Igor Pavlov" => (Produit::SevenZip, nom.trim().strip_prefix("7-Zip")?),
        "Simon Tatham" => (Produit::PuTTY, nom.trim().strip_prefix("PuTTY release ")?),
        _ => return None,
    };
    let mut morceaux = reste.split_whitespace();
    let version_ou_rien = morceaux.next().is_none_or(|v| Version::lire(v).is_some());
    let suffixe = morceaux.collect::<Vec<_>>().join(" ");
    let bon = version_ou_rien
        && matches!(
            suffixe.as_str(),
            "" | "(x64)" | "(x64 edition)" | "(64-bit)" | "(arm64)"
        )
        && (produit == Produit::SevenZip || !reste.trim().is_empty());
    bon.then_some(produit)
}

/// 7-Zip ou PuTTY trouvé par sa clé Uninstall : son exécutable sous l'emplacement d'installation, sinon
/// `DisplayVersion`.
pub(crate) fn par_cle(produit: Produit, affichee: &str, emplacement: Option<&Path>, cle: &str) -> Installe {
    let exe = match produit {
        Produit::SevenZip => "7z.exe",
        _ => "putty.exe",
    };
    if let Some(i) = emplacement.and_then(|d| executable(produit, &d.join(exe)))
        && i.version.is_some()
    {
        return i;
    }
    let lieu = emplacement.map_or_else(|| PathBuf::from(cle), Path::to_path_buf);
    let mut i = Installe::nouveau(produit, affichee, normaliser(produit, affichee), &lieu);
    i.branche = Branche::Release;
    i
}

/// Firefox installé dans `dossier` : la version de `application.ini`, la branche de `channel-prefs.js` (sinon
/// « ESR » dans le nom affiché, `esr_nomme`, ou le suffixe de la version ; à défaut, l'étape des verdicts en décide
/// par la version), l'architecture de `firefox.exe`. `None` : ni l'un ni l'autre fichier.
pub(crate) fn firefox_dans(dossier: &Path, esr_nomme: bool) -> Option<Installe> {
    let ini = lecteurs::texte_borne(&dossier.join("application.ini"));
    let exe = dossier.join("firefox.exe");
    if ini.is_none() && !existe(&exe) {
        return None;
    }
    let brute = ini.as_deref().and_then(lecteurs::application_ini).unwrap_or_default();
    let mut i = Installe::nouveau(Produit::Firefox, &brute, version::firefox(&brute), dossier);
    let canal = lecteurs::texte_borne(&dossier.join("defaults").join("pref").join("channel-prefs.js"))
        .and_then(|t| lecteurs::canal_prefs(&t));
    i.branche = match canal.as_deref() {
        Some("esr") => Branche::Esr,
        Some("release") => Branche::Release,
        Some(autre) => Branche::Canal(autre.to_string()),
        None if esr_nomme || brute.trim().ends_with("esr") => Branche::Esr,
        None => Branche::Inconnue,
    };
    if let Ok(info) = crate::pe::version(&exe) {
        i.plateforme = Plateforme::de_pe(info.machine);
    }
    Some(i)
}

/// Les dossiers des distributions de Java connues sous un `Program Files` : `Java\*`, `Eclipse Adoptium\*`,
/// `Amazon Corretto\*`, `Microsoft\jdk-*`, `Zulu\*`. Seuls ceux qui ont un fichier `release` compteront.
pub(crate) fn dossiers_java(programmes: &Path) -> Vec<PathBuf> {
    let mut dossiers = Vec::new();
    for (editeur, prefixe) in [
        ("Java", ""),
        ("Eclipse Adoptium", ""),
        ("Amazon Corretto", ""),
        ("Microsoft", "jdk-"),
        ("Zulu", ""),
    ] {
        for (chemin, est_dossier) in entrees(&programmes.join(editeur)).unwrap_or_default() {
            if est_dossier && nom(&chemin).is_some_and(|n| n.starts_with(prefixe)) {
                dossiers.push(chemin);
            }
        }
    }
    dossiers
}

/// Acrobat ou Reader, d'après le nom affiché et l'éditeur exacts d'une clé Uninstall : « Adobe Acrobat », suivi
/// au plus de « Reader », de « DC » ou d'une année de piste Classic, de « (64-bit) » et de « MUI ». L'installeur
/// unifié de 2021 et après nomme Reader « Adobe Acrobat (64-bit) » : il est compté comme Acrobat, comparé à la
/// même piste. Rend aussi si le nom désigne une piste Classic.
pub(crate) fn produit_adobe(nom: &str, editeur: &str) -> Option<(Produit, bool)> {
    if !matches!(editeur.trim(), "Adobe Inc." | "Adobe Systems Incorporated") {
        return None;
    }
    let reste = nom.trim().strip_prefix("Adobe Acrobat")?;
    let (reader, reste) = reste.strip_prefix(" Reader").map_or((false, reste), |r| (true, r));
    let (classic, reste) = if let Some(r) = reste.strip_prefix(" DC") {
        (false, r)
    } else if let Some(annee) = reste.get(1..5)
        && reste.starts_with(' ')
        && annee.starts_with("20")
        && annee.bytes().all(|o| o.is_ascii_digit())
    {
        (true, &reste[5..])
    } else {
        (false, reste)
    };
    let reste = reste.strip_prefix(" (64-bit)").unwrap_or(reste);
    let reste = reste.strip_prefix(" MUI").unwrap_or(reste);
    reste
        .is_empty()
        .then_some((if reader { Produit::Reader } else { Produit::Acrobat }, classic))
}

/// Acrobat ou Reader trouvé par sa clé Uninstall : la version de `Acrobat.exe` ou `AcroRd32.exe` sous
/// l'emplacement d'installation (sans les zéros en tête du nom affiché), sinon `DisplayVersion`. Le troisième champ
/// à 30000 et plus, ou une année dans le nom, désigne une piste Classic, sans source fixe.
pub(crate) fn acrobat(
    (produit, classic): (Produit, bool),
    affichee: &str,
    emplacement: Option<&Path>,
    cle: &str,
) -> Installe {
    let lieu = emplacement.map_or_else(|| PathBuf::from(cle), Path::to_path_buf);
    let exe = emplacement.and_then(|d| {
        [["Acrobat", "Acrobat.exe"], ["Reader", "AcroRd32.exe"]]
            .iter()
            .find_map(|[a, b]| crate::pe::version(&d.join(a).join(b)).ok())
    });
    let mut i = match exe {
        Some(info) => {
            let brute = quatre(info.fichier);
            let v = Version::lire(&brute).map(|v| v.tronquee(3));
            let mut i = Installe::nouveau(produit, &brute, v, &lieu);
            i.plateforme = Plateforme::de_pe(info.machine);
            i
        }
        None => Installe::nouveau(produit, affichee, normaliser(produit, affichee), &lieu),
    };
    let piste_classic = i
        .version
        .is_some_and(|v| v.champs().get(2).is_some_and(|&c| c >= ADOBE_CLASSIC));
    i.branche = if classic || piste_classic {
        Branche::Classic
    } else {
        Branche::Release
    };
    i
}

/// Le canal d'Office Click-to-Run, dans l'ordre de priorité de Microsoft : stratégie `updatepath`, puis
/// `updatebranch` (celle du nuage, Cloud Update ou centre d'administration, si elle en donne une, sinon la GPO :
/// `office_dans` choisit), puis `UpdateUrl`, `UnmanagedUpdateURL` et `CDNBaseUrl` de la configuration. Une adresse donne le
/// GUID qui la termine (reconnu ensuite par les adresses d'OfficeReleases elle-même, sans table écrite ici) ; la
/// première valeur présente décide : un partage réseau ou une adresse sans GUID laisse le canal inconnu.
pub(crate) fn canal_office(valeurs: [Option<&str>; 5]) -> Branche {
    let [chemin, branche, url, non_gere, cdn] = valeurs;
    let adresse = |a: &str| super::sources::editeurs::guid_de(a.trim()).map_or(Branche::Inconnue, Branche::Canal);
    if let Some(c) = chemin {
        return adresse(c);
    }
    if let Some(b) = branche {
        let b = b.trim();
        let bon = !b.is_empty() && b.len() <= 64 && b.bytes().all(|o| o.is_ascii_alphanumeric());
        return if bon {
            Branche::Canal(b.to_string())
        } else {
            Branche::Inconnue
        };
    }
    [url, non_gere, cdn]
        .into_iter()
        .flatten()
        .next()
        .map_or(Branche::Inconnue, adresse)
}

/// Le canal d'Edge réglé par la stratégie « Target Channel override » (valeur de la stratégie, en minuscules) ;
/// une valeur inconnue ne vaut rien.
pub(crate) fn canal_edge(valeur: Option<&str>) -> Branche {
    match valeur.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some(c @ ("stable" | "beta" | "dev" | "extended")) => Branche::Canal(c.to_string()),
        _ => Branche::Inconnue,
    }
}

/// Les fichiers : navigateurs et Firefox aux chemins de la table, sous chaque `Program Files` et chaque
/// `AppData\Local`, puis Java dans les dossiers de ses distributions et `java_home` (du registre).
pub(crate) fn fichiers(lieux: &Lieux, java_home: &[PathBuf], inv: &mut Inventaire) {
    let racines = lieux
        .programmes
        .iter()
        .map(|d| (d, None))
        .chain(lieux.profils.iter().map(|p| (&p.local, Some(&p.compte))));
    for (racine, compte) in racines {
        for fiche in FICHES {
            for morceaux in fiche.windows {
                let chemin = morceaux.iter().fold(racine.clone(), |c, m| c.join(m));
                let trouve = match fiche.produit {
                    Produit::Firefox => chemin.parent().and_then(|d| firefox_dans(d, false)),
                    Produit::Slack => chemin.parent().and_then(slack_dans),
                    Produit::SevenZip | Produit::PuTTY => executable(fiche.produit, &chemin),
                    produit => navigateur(produit, &chemin),
                };
                if let Some(mut i) = trouve {
                    i.compte = compte.cloned();
                    inv.ajouter(i);
                }
            }
        }
    }
    let dossiers = lieux.programmes.iter().flat_map(|p| dossiers_java(p));
    for dossier in dossiers.chain(java_home.iter().cloned()) {
        if let Some(i) = java_dans(&dossier) {
            inv.ajouter(i);
        }
    }
}

// ───────────────────────────── Registre ─────────────────────────────

#[cfg(windows)]
mod registre {
    use std::path::{Path, PathBuf};

    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

    use super::super::inventaire::{Branche, Installe, Inventaire, NonLu, Plateforme};
    use super::super::produits::Produit;
    use super::{Lieux, Profil};
    use crate::machine::windows::installes::{self, Portee, ouvrir, sous_cles, texte};

    const CLICK_TO_RUN: &str = r"Microsoft\Office\ClickToRun";
    const STRATEGIE_OFFICE: &str = r"Policies\Microsoft\office\16.0\common\officeupdate";
    /// La même, posée par Cloud Update ou le centre d'administration de Microsoft 365 Apps : elle passe avant la GPO.
    const STRATEGIE_CLOUD: &str = r"Policies\Microsoft\cloud\office\16.0\common\officeupdate";
    const STRATEGIE_EDGE: &str = r"Policies\Microsoft\EdgeUpdate";
    /// La stratégie « Target Channel override » d'Edge Stable (identifiant d'application d'Edge).
    const CANAL_EDGE: &str = "TargetChannel{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}";

    /// Office Click-to-Run, d'après `software` (la clé `HKLM\SOFTWARE`, ou une clé de test) : `VersionToReport`,
    /// `Platform`, le canal (`canal_office`), l'emplacement (`InstallPath`). `None` : pas d'Office Click-to-Run.
    pub(crate) fn office_dans(software: &RegKey, vue: u32) -> Option<Installe> {
        let c2r = ouvrir(software, CLICK_TO_RUN, vue)?;
        let config = ouvrir(&c2r, "Configuration", vue)?;
        let lieu = texte(&c2r, "InstallPath").map_or_else(
            || PathBuf::from(r"HKLM\SOFTWARE\Microsoft\Office\ClickToRun"),
            PathBuf::from,
        );
        let brute = texte(&config, "VersionToReport").unwrap_or_default();
        let mut i = Installe::nouveau(
            Produit::Office,
            &brute,
            super::normaliser(Produit::Office, &brute),
            &lieu,
        );
        i.plateforme = texte(&config, "Platform").map_or(Plateforme::Inconnue, |p| Plateforme::de_nom(&p));
        let lire = |cle: &str| {
            let s = ouvrir(software, cle, vue);
            let p = |n: &str| s.as_ref().and_then(|s| texte(s, n));
            (p("updatepath"), p("updatebranch"))
        };
        // Office passé d'un canal à l'autre par le nuage garde l'ancien dans CDNBaseUrl : sans cette stratégie, il
        // serait comparé au canal de son installation.
        let cloud = lire(STRATEGIE_CLOUD);
        let (chemin, branche) = if cloud.0.is_some() || cloud.1.is_some() {
            cloud
        } else {
            lire(STRATEGIE_OFFICE)
        };
        let (url, non_gere, cdn) = (
            texte(&config, "UpdateUrl"),
            texte(&config, "UnmanagedUpdateURL"),
            texte(&config, "CDNBaseUrl"),
        );
        i.branche = super::canal_office([
            chemin.as_deref(),
            branche.as_deref(),
            url.as_deref(),
            non_gere.as_deref(),
            cdn.as_deref(),
        ]);
        Some(i)
    }

    /// Le canal d'Edge réglé par stratégie, sous `software`.
    pub(crate) fn canal_edge_dans(software: &RegKey, vue: u32) -> Branche {
        super::canal_edge(
            ouvrir(software, STRATEGIE_EDGE, vue)
                .and_then(|k| texte(&k, CANAL_EDGE))
                .as_deref(),
        )
    }

    /// Les `JavaHome` des clés de Java (`JavaSoft\{JDK, JRE, …}\<version>`) sous `software`.
    pub(crate) fn java_home_dans(software: &RegKey, vue: u32) -> Vec<PathBuf> {
        let mut dossiers = Vec::new();
        for famille in ["JDK", "JRE", "Java Runtime Environment", "Java Development Kit"] {
            let Some(cle) = ouvrir(software, &format!(r"JavaSoft\{famille}"), vue) else {
                continue;
            };
            for sous in sous_cles(&cle).into_iter().take(64) {
                if let Some(home) = ouvrir(&cle, &sous, vue).and_then(|k| texte(&k, "JavaHome")) {
                    let home = PathBuf::from(home);
                    if home.is_absolute() && !dossiers.contains(&home) {
                        dossiers.push(home);
                    }
                }
            }
        }
        dossiers
    }

    /// Le dernier morceau d'un dossier de profil : le nom du compte.
    fn compte_de(dossier: &Path) -> String {
        crate::ui::affichable(
            &dossier
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        )
    }

    /// Les dossiers à lire : `Program Files` (64 et 32 bits), le profil de ce compte, et en administrateur ceux des
    /// autres comptes de personnes. Sans droits, les autres comptes sont comptés comme non lus ; en administrateur, un
    /// profil illisible ou une session fermée (registre non lu) le sont aussi.
    pub(crate) fn lieux(inv: &mut Inventaire) -> (Lieux, Vec<(String, String)>) {
        let env = |v: &str| std::env::var_os(v).map(PathBuf::from).filter(|p| p.is_absolute());
        let mut lieux = Lieux::default();
        for v in ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(d) = env(v)
                && !lieux
                    .programmes
                    .iter()
                    .any(|p| p.to_string_lossy().eq_ignore_ascii_case(&d.to_string_lossy()))
            {
                lieux.programmes.push(d);
            }
        }
        let moi = env("USERPROFILE");
        if let Some(local) = env("LOCALAPPDATA") {
            let compte = moi.as_deref().map_or_else(String::new, compte_de);
            lieux.profils.push(Profil { compte, local });
        }
        let moi_sid = crate::machine::windows::processus::sid();
        let autres: Vec<(String, PathBuf)> = installes::profils()
            .into_iter()
            .filter(|(sid, dossier)| {
                moi_sid.as_deref() != Some(sid)
                    && moi
                        .as_ref()
                        .is_none_or(|m| !m.to_string_lossy().eq_ignore_ascii_case(&dossier.to_string_lossy()))
                    && dossier.is_dir()
            })
            .collect();
        let mut comptes = Vec::new();
        if !crate::machine::windows::processus::eleve() {
            if !autres.is_empty() {
                inv.non_lu(NonLu::Comptes(autres.len()));
            }
            return (lieux, comptes);
        }
        let chargees = installes::ruches_chargees();
        for (sid, dossier) in autres {
            let compte = compte_de(&dossier);
            let local = dossier.join("AppData").join("Local");
            if std::fs::read_dir(&local).is_err() {
                inv.non_lu(NonLu::Dossier(local));
                continue;
            }
            if !chargees.contains(&sid) {
                inv.non_lu(NonLu::Registre(compte.clone()));
            }
            comptes.push((sid, compte.clone()));
            lieux.profils.push(Profil { compte, local });
        }
        (lieux, comptes)
    }

    /// L'inventaire de cet ordinateur.
    pub(crate) fn inventaire() -> Inventaire {
        let mut inv = Inventaire::default();
        let (lieux, comptes) = lieux(&mut inv);
        let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
        let software = ouvrir(&machine, "SOFTWARE", KEY_WOW64_64KEY);
        let software_32 = ouvrir(&machine, "SOFTWARE", KEY_WOW64_32KEY);
        let mut java_home = Vec::new();
        for (cle, vue) in [(&software, KEY_WOW64_64KEY), (&software_32, KEY_WOW64_32KEY)] {
            if let Some(cle) = cle {
                java_home.extend(java_home_dans(cle, vue));
            }
        }
        super::fichiers(&lieux, &java_home, &mut inv);
        // Les clés Uninstall : Firefox, 7-Zip et PuTTY installés ailleurs qu'aux chemins connus, Acrobat et Reader.
        let nom_du_compte = |p: &Portee| match p {
            Portee::Machine => None,
            Portee::CompteCourant => lieux.profils.first().map(|p| p.compte.clone()),
            Portee::Compte(sid) => comptes.iter().find(|(s, _)| s == sid).map(|(_, c)| c.clone()),
        };
        for p in installes::programmes() {
            let compte = nom_du_compte(&p.portee);
            let trouve = if p.nom.starts_with("Mozilla Firefox") {
                p.emplacement
                    .as_deref()
                    .and_then(|d| super::firefox_dans(d, p.nom.contains(" ESR")))
            } else if let Some(produit) = super::produit_par_cle(&p.nom, &p.editeur) {
                Some(super::par_cle(produit, &p.version, p.emplacement.as_deref(), &p.cle))
            } else {
                super::produit_adobe(&p.nom, &p.editeur)
                    .map(|a| super::acrobat(a, &p.version, p.emplacement.as_deref(), &p.cle))
            };
            if let Some(mut i) = trouve {
                if !matches!(p.portee, Portee::Machine) {
                    i.compte = compte;
                }
                inv.ajouter(i);
            }
        }
        if let Some(software) = &software {
            if let Some(office) = office_dans(software, KEY_WOW64_64KEY) {
                inv.ajouter(office);
            }
            let canal = canal_edge_dans(software, KEY_WOW64_64KEY);
            for i in inv.installes.iter_mut().filter(|i| i.produit == Produit::Edge) {
                i.branche = canal.clone();
            }
        }
        inv
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use winreg::enums::HKEY_CURRENT_USER;

        /// Une clé jetable `HKCU\Software\VanguardTest-<pid>-<nom>` qui tient lieu de `HKLM\SOFTWARE`, effacée en fin
        /// de test (HKCU\Software n'a qu'une vue, partagée).
        struct Jetable(String, RegKey);

        impl Jetable {
            fn nouvelle(nom: &str) -> Option<Jetable> {
                let chemin = format!(r"Software\VanguardTest-{}-{nom}", std::process::id());
                let (cle, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(&chemin).ok()?;
                Some(Jetable(chemin, cle))
            }

            fn ecrire(&self, chemin: &str, valeurs: &[(&str, &str)]) {
                let (k, _) = self.1.create_subkey(chemin).unwrap();
                for (n, v) in valeurs {
                    k.set_value(n, &(*v).to_string()).unwrap();
                }
            }
        }

        impl Drop for Jetable {
            fn drop(&mut self) {
                let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
            }
        }

        #[test]
        fn office_click_to_run() {
            let Some(j) = Jetable::nouvelle("office") else {
                return crate::essais::saute("registre inaccessible");
            };
            assert!(office_dans(&j.1, KEY_WOW64_64KEY).is_none());
            j.ecrire(CLICK_TO_RUN, &[("InstallPath", r"C:\Program Files\Microsoft Office")]);
            j.ecrire(
                &format!(r"{CLICK_TO_RUN}\Configuration"),
                &[
                    ("VersionToReport", "16.0.19127.20264"),
                    ("Platform", "x64"),
                    (
                        "CDNBaseUrl",
                        "http://officecdn.microsoft.com/pr/492350F6-3A01-4F97-B9C0-C7C6DDF67D60",
                    ),
                ],
            );
            let o = office_dans(&j.1, KEY_WOW64_64KEY).unwrap();
            assert_eq!(o.version.map(|v| v.to_string()).as_deref(), Some("16.0.19127.20264"));
            assert_eq!(o.plateforme, Plateforme::X64);
            assert_eq!(o.lieu, PathBuf::from(r"C:\Program Files\Microsoft Office"));
            assert_eq!(o.branche, Branche::Canal("492350f6-3a01-4f97-b9c0-c7c6ddf67d60".into()));
            // La stratégie passe avant la configuration.
            j.ecrire(STRATEGIE_OFFICE, &[("updatebranch", "MonthlyEnterprise")]);
            assert_eq!(
                office_dans(&j.1, KEY_WOW64_64KEY).unwrap().branche,
                Branche::Canal("MonthlyEnterprise".into())
            );
            j.ecrire(STRATEGIE_OFFICE, &[("updatepath", r"\\serveur\office")]);
            assert_eq!(office_dans(&j.1, KEY_WOW64_64KEY).unwrap().branche, Branche::Inconnue);
            // La stratégie du nuage passe avant la GPO et la configuration.
            j.ecrire(STRATEGIE_CLOUD, &[("updatebranch", "Current")]);
            assert_eq!(
                office_dans(&j.1, KEY_WOW64_64KEY).unwrap().branche,
                Branche::Canal("Current".into())
            );
        }

        #[test]
        fn edge_et_java_par_le_registre() {
            let Some(j) = Jetable::nouvelle("edge-java") else {
                return crate::essais::saute("registre inaccessible");
            };
            assert_eq!(canal_edge_dans(&j.1, KEY_WOW64_64KEY), Branche::Inconnue);
            j.ecrire(STRATEGIE_EDGE, &[(CANAL_EDGE, "extended")]);
            assert_eq!(
                canal_edge_dans(&j.1, KEY_WOW64_64KEY),
                Branche::Canal("extended".into())
            );
            j.ecrire(
                r"JavaSoft\JDK\21",
                &[("JavaHome", r"C:\Program Files\Eclipse Adoptium\jdk-21.0.13.9-hotspot")],
            );
            j.ecrire(
                r"JavaSoft\Java Runtime Environment\1.8.0_511",
                &[("JavaHome", r"C:\Program Files\Java\jre1.8.0_511")],
            );
            j.ecrire(r"JavaSoft\JRE\relatif", &[("JavaHome", r"jre\relatif")]);
            let homes = java_home_dans(&j.1, KEY_WOW64_64KEY);
            assert_eq!(homes.len(), 2, "{homes:?}");
            assert!(homes.contains(&PathBuf::from(r"C:\Program Files\Java\jre1.8.0_511")));
        }

        /// L'inventaire du vrai registre (Wine ici, la VM ensuite) : lu sans erreur, dans ses bornes.
        #[test]
        fn inventaire_reel() {
            let inv = inventaire();
            assert!(inv.installes.len() <= 64);
            assert!(inv.installes.iter().all(|i| !i.lieu.as_os_str().is_empty()));
        }
    }
}

#[cfg(windows)]
pub(crate) use registre::inventaire;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::essais::{Fabrique, pe};
    use crate::protection::perimes::produits::Distribution;

    fn jetable(nom: &str) -> PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-perimes-win-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn poser(chemin: &Path, contenu: &[u8]) {
        std::fs::create_dir_all(chemin.parent().unwrap()).unwrap();
        std::fs::write(chemin, contenu).unwrap();
    }

    fn exe(fichier: [u16; 4], machine: u16) -> Vec<u8> {
        pe(&Fabrique {
            machine,
            fichier,
            ..Fabrique::default()
        })
    }

    /// Un arbre jetable à la forme de Windows : Chrome (machine, ARM64, mise à jour en attente), Edge par compte,
    /// Brave illisible, Firefox ESR, Java Temurin et un Java sans IMPLEMENTOR.
    #[test]
    fn fichiers_d_un_arbre_jetable() {
        let d = jetable("arbre");
        let pf = d.join("Program Files");
        let local = d.join("Users").join("alice").join("AppData").join("Local");
        let chrome = pf.join("Google").join("Chrome").join("Application");
        poser(&chrome.join("chrome.exe"), &exe([156, 0, 8078, 48], 0xAA64));
        std::fs::create_dir_all(chrome.join("156.0.8078.48")).unwrap();
        std::fs::create_dir_all(chrome.join("157.0.8100.1")).unwrap();
        poser(&chrome.join("new_chrome.exe"), b"");
        let edge = local.join("Microsoft").join("Edge").join("Application");
        poser(&edge.join("msedge.exe"), &exe([156, 0, 4314, 42], 0x8664));
        std::fs::create_dir_all(edge.join("156.0.4314.48")).unwrap();
        poser(
            &pf.join("BraveSoftware")
                .join("Brave-Browser")
                .join("Application")
                .join("brave.exe"),
            b"MZ pas un PE",
        );
        let firefox = pf.join("Mozilla Firefox");
        poser(
            &firefox.join("application.ini"),
            b"[App]\nName=Firefox\nVersion=153.5.1\n",
        );
        poser(
            &firefox.join("defaults").join("pref").join("channel-prefs.js"),
            b"pref(\"app.update.channel\", \"esr\");\n",
        );
        poser(&firefox.join("firefox.exe"), &exe([153, 5, 1, 9000], 0x8664));
        poser(
            &pf.join("Eclipse Adoptium")
                .join("jdk-21.0.13.9-hotspot")
                .join("release"),
            b"IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"21.0.13\"\nOS_ARCH=\"x86_64\"\n",
        );
        poser(
            &pf.join("Microsoft").join("Edge").join("pas-un-jdk").join("release"),
            b"JAVA_VERSION=\"1\"\n",
        );
        let java_home = d.join("ailleurs").join("jre1.8.0_511");
        poser(
            &java_home.join("release"),
            b"JAVA_VERSION=\"1.8.0_511\"\nOS_ARCH=\"amd64\"\n",
        );
        let lieux = Lieux {
            programmes: vec![pf.clone()],
            profils: vec![Profil {
                compte: "alice".into(),
                local: local.clone(),
            }],
        };
        let mut inv = Inventaire::default();
        fichiers(&lieux, &[java_home.clone(), java_home.clone()], &mut inv);
        let trouve = |p: Produit| {
            inv.installes
                .iter()
                .find(|i| i.produit == p)
                .unwrap_or_else(|| panic!("{p:?}"))
        };
        let lu_chrome = trouve(Produit::Chrome);
        assert_eq!(
            lu_chrome.version.map(|v| v.to_string()).as_deref(),
            Some("156.0.8078.48")
        );
        assert!(lu_chrome.attente);
        assert_eq!(lu_chrome.ecart.map(|v| v.to_string()).as_deref(), Some("157.0.8100.1"));
        assert_eq!(
            (
                lu_chrome.plateforme,
                lu_chrome.compte.as_deref(),
                lu_chrome.lieu.as_path()
            ),
            (Plateforme::Arm64, None, chrome.as_path())
        );
        // Sans mise à jour en attente, le dossier le plus récent l'emporte, l'exécutable est noté.
        let lu_edge = trouve(Produit::Edge);
        assert_eq!(lu_edge.version.map(|v| v.to_string()).as_deref(), Some("156.0.4314.48"));
        assert_eq!(lu_edge.ecart.map(|v| v.to_string()).as_deref(), Some("156.0.4314.42"));
        assert_eq!(lu_edge.compte.as_deref(), Some("alice"));
        let lu_brave = trouve(Produit::Brave);
        assert_eq!((lu_brave.version, lu_brave.brute.as_str()), (None, ""));
        let lu_firefox = trouve(Produit::Firefox);
        assert_eq!(
            (
                lu_firefox.brute.as_str(),
                lu_firefox.branche.clone(),
                lu_firefox.plateforme
            ),
            ("153.5.1", Branche::Esr, Plateforme::X64)
        );
        let temurin = trouve(Produit::Java(Distribution::Temurin));
        assert_eq!(
            (temurin.version.map(|v| v.to_string()), temurin.plateforme),
            (Some("21.0.13".into()), Plateforme::X64)
        );
        let autre = trouve(Produit::Java(Distribution::Autre));
        assert_eq!(autre.version.map(|v| v.to_string()).as_deref(), Some("8.0.511"));
        assert_eq!(inv.installes.len(), 6, "{:?}", inv.installes);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 7-Zip et PuTTY par leur exécutable ; Slack par machine (son exécutable) et par compte (Squirrel : le plus
    /// haut dossier `app-<version>` qui a un exécutable, pas le lanceur).
    #[test]
    fn sept_zip_putty_slack_d_un_arbre() {
        let d = jetable("longue-traine");
        let pf = d.join("Program Files");
        let local = d.join("Users").join("alice").join("AppData").join("Local");
        poser(&pf.join("7-Zip").join("7z.exe"), &exe([26, 5, 0, 0], 0x8664));
        poser(&pf.join("PuTTY").join("putty.exe"), &exe([0, 81, 0, 0], 0xAA64));
        poser(&pf.join("slack").join("slack.exe"), &exe([4, 52, 182, 0], 0x8664));
        let squirrel = local.join("slack");
        poser(&squirrel.join("slack.exe"), &exe([1, 0, 0, 0], 0x8664));
        poser(
            &squirrel.join("app-4.41.105").join("slack.exe"),
            &exe([4, 41, 105, 0], 0x8664),
        );
        poser(&squirrel.join("app-4.47.69").join("slack.exe"), b"pas un PE");
        // Un dossier plus haut sans exécutable (mise à jour interrompue) ne compte pas.
        std::fs::create_dir_all(squirrel.join("app-4.60.1")).unwrap();
        std::fs::create_dir_all(squirrel.join("packages")).unwrap();
        let lieux = Lieux {
            programmes: vec![pf.clone()],
            profils: vec![Profil {
                compte: "alice".into(),
                local: local.clone(),
            }],
        };
        let mut inv = Inventaire::default();
        fichiers(&lieux, &[], &mut inv);
        let lu = |p: Produit, compte: Option<&str>| {
            inv.installes
                .iter()
                .find(|i| i.produit == p && i.compte.as_deref() == compte)
                .unwrap_or_else(|| panic!("{p:?} {compte:?} : {:?}", inv.installes))
        };
        let sept = lu(Produit::SevenZip, None);
        assert_eq!(
            (sept.version, sept.plateforme, sept.branche.clone()),
            (Version::lire("26.5"), Plateforme::X64, Branche::Release)
        );
        assert_eq!(lu(Produit::PuTTY, None).plateforme, Plateforme::Arm64);
        assert_eq!(lu(Produit::Slack, None).version, Version::lire("4.52.182"));
        // Le dossier 4.47.69 a un exécutable illisible : son nom suffit, et c'est le plus haut.
        let par_compte = lu(Produit::Slack, Some("alice"));
        assert_eq!(par_compte.version, Version::lire("4.47.69"));
        assert_eq!(par_compte.lieu, squirrel);
        std::fs::remove_file(squirrel.join("app-4.47.69").join("slack.exe")).unwrap();
        let i = slack_dans(&squirrel).unwrap();
        assert_eq!(
            (i.brute.as_str(), i.plateforme, i.lieu.as_path()),
            ("4.41.105.0", Plateforme::X64, squirrel.as_path())
        );
        // Ni lanceur ni dossier de version : rien.
        assert!(slack_dans(&d.join("absent")).is_none());
        assert_eq!(inv.installes.len(), 4, "{:?}", inv.installes);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sept_zip_et_putty_par_leur_cle() {
        let sept = |n: &str| produit_par_cle(n, "Igor Pavlov");
        for bon in [
            "7-Zip",
            "7-Zip 26.05",
            "7-Zip 26.05 (x64)",
            "7-Zip 9.20 (x64 edition)",
            " 7-Zip 24.09 (arm64) ",
        ] {
            assert_eq!(sept(bon), Some(Produit::SevenZip), "{bon}");
        }
        let putty = |n: &str| produit_par_cle(n, "Simon Tatham");
        assert_eq!(putty("PuTTY release 0.85 (64-bit)"), Some(Produit::PuTTY));
        assert_eq!(putty("PuTTY release 0.85"), Some(Produit::PuTTY));
        for faux in ["7-Zipper", "7-Zip 26.05 Extra", "7-Zip beta", "7-Zip 26.05 (x64) (x64)"] {
            assert_eq!(sept(faux), None, "{faux}");
        }
        for faux in ["PuTTY release", "PuTTY release x", "PuTTY", "KiTTY release 0.76"] {
            assert_eq!(putty(faux), None, "{faux}");
        }
        assert_eq!(produit_par_cle("7-Zip 26.05", "Igor Pavlov Ltd"), None);
        assert_eq!(produit_par_cle("PuTTY release 0.85", "Igor Pavlov"), None);
        // Par l'exécutable de l'emplacement ; sinon DisplayVersion, la clé tenant lieu d'emplacement.
        let d = jetable("cles");
        poser(&d.join("7z.exe"), &exe([26, 5, 0, 0], 0x8664));
        let i = par_cle(Produit::SevenZip, "24.09", Some(&d), "HKLM");
        assert_eq!((i.version, i.lieu.as_path()), (Version::lire("26.5"), d.as_path()));
        let i = par_cle(Produit::PuTTY, "0.85.0.0", Some(&d), r"HKLM\x\Uninstall\PuTTY");
        assert_eq!((i.version, i.lieu.as_path()), (Version::lire("0.85"), d.as_path()));
        let i = par_cle(Produit::PuTTY, "pas une version", None, "HKLM");
        assert_eq!((i.version, i.branche), (None, Branche::Release));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn firefox_absent_ou_partiel() {
        let d = jetable("firefox");
        assert!(firefox_dans(&d, false).is_none());
        poser(&d.join("firefox.exe"), b"");
        let f = firefox_dans(&d, true).unwrap();
        assert_eq!((f.version, f.branche), (None, Branche::Esr));
        poser(&d.join("application.ini"), b"[App]\nVersion=158.0.1\n");
        let f = firefox_dans(&d, false).unwrap();
        assert_eq!((f.brute.as_str(), f.branche), ("158.0.1", Branche::Inconnue));
        poser(&d.join("application.ini"), b"[App]\nVersion=153.5.1esr\n");
        assert_eq!(firefox_dans(&d, false).unwrap().branche, Branche::Esr);
        poser(
            &d.join("defaults").join("pref").join("channel-prefs.js"),
            b"pref(\"app.update.channel\", \"beta\");",
        );
        assert_eq!(firefox_dans(&d, false).unwrap().branche, Branche::Canal("beta".into()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn acrobat_et_reader() {
        let adobe = |n: &str| produit_adobe(n, "Adobe Inc.");
        assert_eq!(adobe("Adobe Acrobat (64-bit)"), Some((Produit::Acrobat, false)));
        assert_eq!(adobe("Adobe Acrobat Reader DC MUI"), Some((Produit::Reader, false)));
        assert_eq!(adobe("Adobe Acrobat DC"), Some((Produit::Acrobat, false)));
        assert_eq!(adobe("Adobe Acrobat Reader 2020"), Some((Produit::Reader, true)));
        assert_eq!(adobe("Adobe Acrobat 2024 (64-bit)"), Some((Produit::Acrobat, true)));
        assert_eq!(
            produit_adobe("Adobe Acrobat DC", "Adobe Systems Incorporated"),
            Some((Produit::Acrobat, false))
        );
        for faux in [
            "Adobe Acrobat Sign",
            "Adobe Acrobat DC Extra",
            "Adobe Acrobat 20ab",
            "Adobe Acrobat 2",
            "Adobe Reader XI",
            "Acrobat",
        ] {
            assert_eq!(adobe(faux), None, "{faux}");
        }
        assert_eq!(produit_adobe("Adobe Acrobat DC", "Adobe Inc"), None);
        assert_eq!(produit_adobe("Adobe Acrobat DC", "Pas Adobe"), None);
        // Par l'exécutable, sans zéros en tête ; sinon par DisplayVersion.
        let d = jetable("acrobat");
        poser(&d.join("Acrobat").join("Acrobat.exe"), &exe([26, 2, 22031, 0], 0x8664));
        let a = acrobat((Produit::Acrobat, false), "26.001.21662", Some(&d), "HKLM");
        assert_eq!(
            (a.version.map(|v| v.to_string()), a.branche, a.plateforme),
            (Some("26.2.22031".into()), Branche::Release, Plateforme::X64)
        );
        let r = acrobat(
            (Produit::Reader, false),
            "20.005.30774",
            None,
            r"HKLM\x\Uninstall\{AC76}",
        );
        assert_eq!(
            (r.version.map(|v| v.to_string()), r.branche),
            (Some("20.5.30774".into()), Branche::Classic)
        );
        assert_eq!(r.lieu, PathBuf::from(r"HKLM\x\Uninstall\{AC76}"));
        let r = acrobat((Produit::Reader, true), "pas une version", None, "HKLM");
        assert_eq!((r.version, r.branche), (None, Branche::Classic));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn canaux_office_et_edge() {
        let guid = "http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6";
        let c = |v: [Option<&str>; 5]| canal_office(v);
        assert_eq!(
            c([None, None, None, None, Some(guid)]),
            Branche::Canal("55336b82-a18d-4dd6-b5f6-9e5095c314a6".into())
        );
        assert_eq!(
            c([None, Some("Current"), Some(guid), None, None]),
            Branche::Canal("Current".into())
        );
        assert_eq!(
            c([Some(r"\\serveur\partage"), Some("Current"), None, None, Some(guid)]),
            Branche::Inconnue
        );
        assert_eq!(
            c([None, None, Some("https://example.com/office"), None, Some(guid)]),
            Branche::Inconnue
        );
        assert_eq!(c([None, Some("Current; x"), None, None, None]), Branche::Inconnue);
        assert_eq!(c([None; 5]), Branche::Inconnue);
        assert_eq!(canal_edge(Some(" Extended ")), Branche::Canal("extended".into()));
        assert_eq!(canal_edge(Some("autre")), Branche::Inconnue);
        assert_eq!(canal_edge(None), Branche::Inconnue);
    }

    #[test]
    fn normalisations() {
        assert_eq!(
            normaliser(Produit::Brave, "156.1.98.60")
                .map(|v| v.to_string())
                .as_deref(),
            Some("1.98.60")
        );
        assert_eq!(normaliser(Produit::Chrome, "156.0.8078"), None);
        assert_eq!(
            normaliser(Produit::SevenZip, "26.05"),
            normaliser(Produit::SevenZip, "26.5.0.0")
        );
        assert_eq!(normaliser(Produit::Slack, "4.52.182.0.1"), None);
        assert_eq!(normaliser(Produit::PuTTY, "Release 0.85"), None);
        assert_eq!(
            normaliser(Produit::Office, "16.0.19127.20264")
                .map(|v| v.to_string())
                .as_deref(),
            Some("16.0.19127.20264")
        );
        assert_eq!(
            normaliser(Produit::Java(Distribution::Oracle), "1.8.0_511")
                .map(|v| v.to_string())
                .as_deref(),
            Some("8.0.511")
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 1000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn noms_et_canaux_sans_plantage(nom in ".{0,40}", editeur in "(Adobe Inc\\.|.{0,10})", url in ".{0,60}") {
            let _ = produit_adobe(&nom, &editeur);
            let _ = produit_adobe(&format!("Adobe Acrobat{nom}"), "Adobe Inc.");
            let _ = canal_office([None, None, Some(&url), None, None]);
            let _ = canal_office([None, Some(&url), None, None, None]);
            let _ = canal_edge(Some(&url));
            let _ = produit_par_cle(&nom, "Igor Pavlov");
            let _ = produit_par_cle(&format!("PuTTY release {nom}"), "Simon Tatham");
            let _ = version_squirrel(&nom);
        }
    }
}
