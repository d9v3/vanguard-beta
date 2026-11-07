//! Les sorties du garde, que le Vanguard du compte lit : etat.json (le battement, réécrit chaque seconde) et
//! evenements.jsonl (une ligne JSON par événement, bornée : à `EVENEMENTS_TAILLE_MAX`, l'ancien fichier devient
//! evenements.1.jsonl). Le garde n'a pas de bus de session : c'est le compte qui notifie, après `affichable`.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// La taille d'evenements.jsonl avant rotation.
pub(crate) const EVENEMENTS_TAILLE_MAX: u64 = 512 << 10;
/// La taille d'etat.json relue, au plus.
pub(crate) const ETAT_TAILLE_MAX: u64 = 64 << 10;
/// Un chemin noté, au plus (en octets).
pub(crate) const CHEMIN_MAX: usize = 4096;

/// Les compteurs depuis le démarrage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Compteurs {
    /// Demandes reçues.
    pub demandes: u64,
    /// Servies par le cache.
    pub cache: u64,
    /// Hachées.
    pub hachees: u64,
    /// Certaines, permises par une exception, la personne, l'observation ou la pause.
    pub notees: u64,
    /// Refusées (EPERM).
    pub refusees: u64,
    /// Permises faute de verdict à temps (250 ms).
    pub delais: u64,
    /// Permises sans hachage : plus de 64 Mio, ou illisibles.
    pub non_verifiees: u64,
    /// Permises parce que la file des fils de décision était pleine.
    pub file_pleine: u64,
    /// Débordements de la file du noyau.
    pub debordements: u64,
}

/// etat.json.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Etat {
    /// La version de Vanguard du garde.
    pub version: String,
    pub pid: u32,
    pub demarre: u64,
    /// Le dernier battement du fil lecteur (secondes depuis 1970).
    pub battement: u64,
    /// `true` : refus ; `false` : observation.
    pub refus: bool,
    pub pause_jusqu_a: Option<u64>,
    /// Les empreintes de l'ensemble CERTAIN chargées.
    pub certain: u64,
    /// Ce qui empêche de lire les listes ou les réglages, s'il y a quelque chose.
    pub alertes: Vec<String>,
    /// Les systèmes de fichiers marqués.
    pub marques: u64,
    pub compteurs: Compteurs,
}

impl Etat {
    /// Relu par le compte ; `None` s'il ne se lit pas.
    pub(crate) fn lire(octets: &[u8]) -> Option<Etat> {
        serde_json::from_slice(octets).ok()
    }
}

/// Un événement.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Evenement {
    /// Secondes depuis 1970.
    pub t: u64,
    /// `refuse`, `observe`, `epargne`, `permise` (un verdict), ou `delai`, `non-verifie`, `file-pleine`,
    /// `debordement`, `demarrage`, `alerte`.
    pub genre: String,
    /// `liste` ou `essai` pour un verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certitude: Option<String>,
    /// L'exception P11 d'un verdict `epargne`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception: Option<String>,
    #[serde(default)]
    pub pid: i32,
    /// Le chemin du fichier lancé, tel que le noyau le donne (à passer par `affichable` avant de le montrer).
    #[serde(default)]
    pub chemin: String,
    #[serde(default)]
    pub sha256: String,
    /// Une précision (le nombre de demandes d'un débordement, l'alerte…).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// Un chemin borné à `CHEMIN_MAX` octets, coupé sur un caractère.
pub(crate) fn borner(chemin: &str) -> String {
    let mut fin = chemin.len().min(CHEMIN_MAX);
    while !chemin.is_char_boundary(fin) {
        fin = fin.saturating_sub(1);
    }
    chemin.get(..fin).unwrap_or_default().to_string()
}

/// La ligne d'un événement (sans retour à la ligne dedans : JSON l'échappe).
pub(crate) fn ligne(e: &Evenement) -> String {
    let mut l = serde_json::to_string(e).unwrap_or_default();
    l.push('\n');
    l
}

/// Les événements d'un fichier lu ; les lignes illisibles (une écriture coupée par un redémarrage) sont sautées.
pub(crate) fn evenements(texte: &str) -> Vec<Evenement> {
    texte.lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// Ajoute des lignes à `chemin`, et passe à `ancien` au-delà de `EVENEMENTS_TAILLE_MAX`.
pub(crate) fn ajouter(chemin: &Path, ancien: &Path, lignes: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let taille = std::fs::symlink_metadata(chemin).map_or(0, |m| m.len());
    if taille >= EVENEMENTS_TAILLE_MAX {
        std::fs::rename(chemin, ancien)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(chemin)?;
    f.write_all(lignes.as_bytes())
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
    fn etat_et_evenements_relus() {
        let e = Etat {
            version: "0.90.0".into(),
            pid: 42,
            battement: 1_700_000_000,
            alertes: vec!["liste".into()],
            ..Etat::default()
        };
        assert_eq!(Etat::lire(serde_json::to_string(&e).unwrap().as_bytes()), Some(e));
        assert_eq!(Etat::lire(b"{"), None);
        let ev = Evenement {
            t: 1,
            genre: "observe".into(),
            certitude: Some("essai".into()),
            pid: 7,
            chemin: "/home/alice/a\nb".into(),
            ..Evenement::default()
        };
        let l = ligne(&ev);
        assert_eq!(
            l.matches('\n').count(),
            1,
            "un retour à la ligne du chemin casserait le fichier"
        );
        let texte = format!("{l}pas du json\n{l}");
        assert_eq!(evenements(&texte), vec![ev.clone(), ev]);
    }

    #[test]
    fn chemin_borne_sur_un_caractere() {
        assert_eq!(borner("/usr/bin/true"), "/usr/bin/true");
        let long = format!("/{}", "é".repeat(CHEMIN_MAX));
        let b = borner(&long);
        assert!(b.len() <= CHEMIN_MAX && b.starts_with('/'));
    }

    #[test]
    fn evenements_bornes_par_rotation() {
        let d = crate::essais::Jetable::nouveau("garde-sortie");
        let (f, ancien) = (d.join("e.jsonl"), d.join("e.1.jsonl"));
        let gros = "x".repeat(usize::try_from(EVENEMENTS_TAILLE_MAX).unwrap());
        ajouter(&f, &ancien, &gros).unwrap();
        ajouter(&f, &ancien, "a\n").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "a\n");
        assert_eq!(std::fs::metadata(&ancien).unwrap().len(), EVENEMENTS_TAILLE_MAX);
        // Un lien à la place du fichier n'est pas suivi.
        let lien = d.join("lien.jsonl");
        std::os::unix::fs::symlink(&ancien, &lien).unwrap();
        assert!(ajouter(&lien, &d.join("l.1"), "b\n").is_err());
    }
}
