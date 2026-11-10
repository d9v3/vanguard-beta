//! Failles des images de conteneurs : trivy (libre, licence Apache 2.0), lancé s'il est installé, relit les paquets de
//! chaque image Docker (ou Podman) de cet ordinateur et dit ceux qui ont une faille connue, grave ou critique. Une image
//! ne se met pas à jour toute seule : un conteneur lancé il y a un an garde les failles de ce jour-là. Lecture seule ;
//! trivy télécharge sa base des failles (plusieurs dizaines de Mo) avant la première analyse.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::protection::outil::{self, Externe, Linux};
use crate::ui::*;

mod resultat;

/// Bornes de `--json` : un examen lancé par la fenêtre ou un script ne tourne pas une heure.
const IMAGES_MAX: usize = 30;
const BUDGET_S: u64 = 600;
const PAR_IMAGE_S: u64 = 300;

const TRIVY: Externe = Externe {
    nom: "trivy",
    presentation: (
        "trivy (libre, licence Apache 2.0) cherche les failles connues des images ; il n'est pas installé.",
        "trivy (open source, Apache 2.0 license) looks for known flaws in images; it is not installed.",
    ),
    linux: Linux::Arch,
    winget: "AquaSecurity.Trivy",
    site: "https://trivy.dev",
};

/// Les images d'un `image ls --format '{{.Repository}}:{{.Tag}}'`. Celles sans nom (« `<none>` », restes d'une
/// construction) sont sautées ; un nom qui commencerait par « - » aussi, qui passerait pour une option.
pub(crate) fn images(sortie: &str) -> Vec<String> {
    let mut images: Vec<String> = sortie
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains("<none>") && !l.starts_with('-'))
        .map(String::from)
        .collect();
    images.sort();
    images.dedup();
    images
}

/// Une faille connue d'un paquet de l'image.
#[derive(Debug, PartialEq)]
pub(crate) struct Faille {
    pub id: String,
    pub paquet: String,
    pub critique: bool,
    /// Une version du paquet la corrige : mettre l'image à jour suffit.
    pub corrigee: bool,
}

/// Le rapport JSON de trivy ; `None` s'il ne se lit pas. Une image sans faille a des résultats sans
/// « Vulnerabilities ».
pub(crate) fn lire_rapport(json: &str) -> Option<Vec<Faille>> {
    let valeur: serde_json::Value = serde_json::from_str(json).ok()?;
    let resultats = valeur
        .get("Results")
        .map_or(Some(&[][..]), |r| r.as_array().map(Vec::as_slice))?;
    Some(
        resultats
            .iter()
            .filter_map(|r| r["Vulnerabilities"].as_array())
            .flatten()
            .map(|v| Faille {
                id: affichable(v["VulnerabilityID"].as_str().unwrap_or("?")),
                paquet: affichable(v["PkgName"].as_str().unwrap_or("?")),
                critique: v["Severity"].as_str() == Some("CRITICAL"),
                corrigee: v["FixedVersion"].as_str().is_some_and(|f| !f.is_empty()),
            })
            .collect(),
    )
}

/// Les images de Docker par son API (/var/run/docker.sock), une par ligne comme la CLI les écrit ; `None` : Podman,
/// un autre hôte ou contexte réglé, ou le démon injoignable (la CLI dira).
#[cfg(target_os = "linux")]
fn images_par_l_api(source: &str) -> Option<String> {
    use crate::machine::linux::docker_api;
    if source != "docker" || !docker_api::hote_par_defaut() {
        return None;
    }
    docker_api::images_sur(Path::new(docker_api::PRISE))
        .ok()
        .map(|v| v.join("\n"))
}

#[cfg(not(target_os = "linux"))]
fn images_par_l_api(_: &str) -> Option<String> {
    None
}

/// Le moteur de conteneurs de cet ordinateur : Docker, sinon Podman.
fn moteur() -> Option<(&'static str, PathBuf)> {
    ["docker", "podman"]
        .into_iter()
        .find_map(|nom| outil::trouver(nom).map(|chemin| (nom, chemin)))
}

/// Les images de Docker ou de Podman, une par ligne ; `None` : liste illisible.
fn lister(source: &str, moteur: &Path) -> Option<String> {
    // Docker : son API locale d'abord (lecture seule), la CLI quand un autre hôte ou un contexte est réglé.
    images_par_l_api(source).or_else(|| {
        crate::commande::lancer(
            Command::new(moteur).args(["image", "ls", "--format", "{{.Repository}}:{{.Tag}}"]),
            30,
        )
        .filter(|r| r.code == Some(0))
        .map(|r| r.sortie)
    })
}

/// `hors_ligne` (pour `--json`) : rien ne se télécharge (ni la base Java, ni les dépendances en ligne), rien ne
/// s'écrit dans le cache de trivy, et trivy ne cherche pas sa propre mise à jour.
fn analyser_image(trivy: &Path, source: &str, image: &str, hors_ligne: bool, secondes: u64) -> Option<Vec<Faille>> {
    let mut commande = Command::new(trivy);
    if hors_ligne {
        commande
            .args(["--skip-java-db-update", "--offline-scan", "--cache-backend", "memory"])
            .env("TRIVY_SKIP_VERSION_CHECK", "true");
    }
    let r = crate::commande::lancer(
        commande.args([
            "image",
            "--quiet",
            "--skip-db-update",
            "--scanners",
            "vuln",
            "--severity",
            "HIGH,CRITICAL",
            "--format",
            "json",
            "--image-src",
            source,
            image,
        ]),
        secondes,
    )?;
    if r.code != Some(0) {
        return None;
    }
    lire_rapport(&r.sortie)
}

/// La date de la base des failles de trivy, sans rien télécharger ; `None` : pas de base, ou illisible.
fn base_de(trivy: &Path) -> Option<chrono::DateTime<chrono::Utc>> {
    let r = crate::commande::lancer(
        Command::new(trivy)
            .args(["version", "--format", "json"])
            .env("TRIVY_SKIP_VERSION_CHECK", "true"),
        30,
    )?;
    (r.code == Some(0))
        .then(|| resultat::date_de_la_base(&r.sortie))
        .flatten()
}

/// Ce que voit l'examen de `--json`, sans rien proposer, installer ni télécharger.
fn relever() -> resultat::Releve {
    use resultat::Releve;
    let Some((source, moteur)) = moteur() else {
        return Releve::SansMoteur;
    };
    let Some(sortie) = lister(source, &moteur) else {
        return Releve::ListeIllisible;
    };
    let images = images(&sortie);
    if images.is_empty() {
        return Releve::SansImage;
    }
    let total = images.len();
    let Some(trivy) = outil::trouver("trivy") else {
        return Releve::SansTrivy { images: total };
    };
    let Some(base) = base_de(&trivy) else {
        return Releve::SansBase { images: total };
    };
    let depart = std::time::Instant::now();
    let mut analysees = Vec::new();
    for image in images.iter().take(IMAGES_MAX) {
        // Moins de 10 s de reste : l'image ne serait pas analysée à temps ; elle est comptée non analysée.
        let reste = BUDGET_S.saturating_sub(depart.elapsed().as_secs());
        if reste < 10 {
            break;
        }
        let failles = analyser_image(&trivy, source, image, true, reste.min(PAR_IMAGE_S));
        analysees.push((affichable(image), failles));
    }
    Releve::Analyse {
        images: total,
        base,
        analysees,
    }
}

/// `vanguard conteneurs --json` : les images analysées par trivy, s'il est là avec sa base des failles. Rien n'est
/// proposé, installé ni téléchargé ; borné à 30 images et 10 minutes.
pub fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let r = resultat::resultat(&relever(), debut);
    crate::modele::resultat::verser(&r);
    println!("{}", crate::modele::resultat::json(&r));
}

/// Menu Antivirus et protection › Failles des images Docker, et « vanguard conteneurs ».
pub fn analyser() {
    titre(tr!("Failles des images Docker", "Flaws in Docker images"));
    let Some((source, moteur)) = moteur() else {
        trp!(
            "  Ni Docker ni Podman sur cet ordinateur : rien à analyser.",
            "  Neither Docker nor Podman on this computer: nothing to scan."
        );
        return;
    };
    let Some(sortie) = lister(source, &moteur) else {
        // Le plus souvent, le démon de Docker réservé à root et au groupe docker (qui vaut root : le bilan le dit).
        trp!(
            "  ✖ Liste des images illisible : Docker est peut-être réservé à root (sudo vanguard conteneurs), ou arrêté.",
            "  ✖ Image list unreadable: Docker may be reserved to root (sudo vanguard containers), or stopped."
        );
        return;
    };
    let images = images(&sortie);
    if images.is_empty() {
        trp!("  Aucune image sur cet ordinateur.", "  No image on this computer.");
        return;
    }
    let Some(trivy) = outil::trouver("trivy").or_else(|| outil::proposer(&TRIVY)) else {
        return;
    };
    trp!(
        "  Base des failles de trivy : mise à jour (plusieurs dizaines de Mo la première fois)…",
        "  trivy's flaw database: updating (several tens of MB the first time)…"
    );
    let base = crate::commande::lancer(
        Command::new(&trivy).args(["image", "--download-db-only", "--quiet"]),
        600,
    );
    if base.is_none_or(|r| r.code != Some(0)) {
        trp!(
            "  ✖ Base des failles impossible à télécharger (Internet ?) : rien n'est conclu.",
            "  ✖ Flaw database could not be downloaded (Internet?): nothing is concluded."
        );
        return;
    }
    let rouge = couleur(crate::risk::Niveau::Eleve);
    let mut a_mettre_a_jour = 0usize;
    for image in &images {
        let nom = affichable(image);
        let Some(failles) = analyser_image(&trivy, source, image, false, 600) else {
            println!(
                "  ⚠ {}",
                trf!(
                    "{nom} : pas pu être analysée, rien n'est conclu pour elle.",
                    "{nom}: could not be scanned, nothing is concluded for it."
                )
            );
            continue;
        };
        if failles.is_empty() {
            println!(
                "  {VERT}✔{RESET} {}",
                trf!("{nom} : aucune faille grave connue", "{nom}: no known serious flaw")
            );
            continue;
        }
        a_mettre_a_jour = a_mettre_a_jour.saturating_add(1);
        let critiques = failles.iter().filter(|f| f.critique).count();
        let corrigees = failles.iter().filter(|f| f.corrigee).count();
        println!(
            "  {rouge}✖{RESET} {}",
            trf!(
                "{nom} : {critiques} critique(s), {} grave(s) ; {corrigees} corrigée(s) par une version plus récente",
                "{nom}: {critiques} critical, {} serious; {corrigees} fixed by a newer version",
                failles.len().saturating_sub(critiques)
            )
        );
        for f in failles.iter().filter(|f| f.critique).take(5) {
            println!("      {GRIS}{} ({}){RESET}", f.id, f.paquet);
        }
    }
    if a_mettre_a_jour > 0 {
        println!();
        for ligne in envelopper(
            tr!(
                "Une image ne se met pas à jour toute seule. Récupérez sa dernière version (docker pull <image>), puis recréez les conteneurs qui s'en servent ; une image que son auteur ne suit plus est à remplacer. Rien n'a été changé.",
                "An image does not update by itself. Fetch its latest version (docker pull <image>), then recreate the containers that use it; an image its author no longer maintains should be replaced. Nothing was changed."
            ),
            LARGEUR - 2,
        ) {
            println!("  {ligne}");
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liste_des_images() {
        let sortie = "nginx:1.21\n<none>:<none>\nredis:7\nnginx:1.21\n--piege:x\n\n";
        assert_eq!(images(sortie), ["nginx:1.21", "redis:7"]);
    }

    /// La forme du rapport JSON de trivy (SchemaVersion 2), réduite à ce que Vanguard lit ; valeurs inventées.
    #[test]
    fn rapport_de_trivy() {
        let rapport = r#"{"SchemaVersion":2,"ArtifactName":"nginx:1.21","Results":[
            {"Target":"nginx:1.21 (debian 11.3)","Class":"os-pkgs","Vulnerabilities":[
                {"VulnerabilityID":"CVE-2022-1292","PkgName":"openssl","InstalledVersion":"1.1.1n","FixedVersion":"1.1.1o","Severity":"CRITICAL"},
                {"VulnerabilityID":"CVE-2023-0001","PkgName":"zlib","InstalledVersion":"1.2.11","FixedVersion":"","Severity":"HIGH"}]},
            {"Target":"app/package-lock.json","Class":"lang-pkgs"}]}"#;
        let f = lire_rapport(rapport).unwrap();
        assert_eq!(f.len(), 2);
        assert!(f[0].critique && f[0].corrigee && f[0].paquet == "openssl");
        assert!(!f[1].critique && !f[1].corrigee);
        // Image sans faille : pas de « Results », ou des résultats sans failles.
        assert_eq!(lire_rapport(r#"{"SchemaVersion":2,"ArtifactName":"x"}"#).unwrap(), []);
        assert_eq!(lire_rapport(r#"{"Results":[{"Target":"x"}]}"#).unwrap(), []);
        assert!(lire_rapport("").is_none() && lire_rapport(r#"{"Results":3}"#).is_none());
    }
}
