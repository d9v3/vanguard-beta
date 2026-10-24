//! Les logiciels pas à jour, sous Windows et macOS : la version installée des navigateurs, d'Office, d'Acrobat et
//! de Java comparée à la dernière publiée, d'après des fichiers publics fixes, téléchargés en entier et les mêmes pour
//! tous (`sources`). Les versions se comparent sans rien deviner (`version`). Les logiciels suivis forment une table
//! fermée (`produits`), trouvés par l'inventaire de chaque système (`windows`, `macos`, vers `inventaire`), puis
//! jugés une règle par produit (`verdicts`). Firefox l'est aussi faille par faille, d'après les avis de sécurité de
//! Mozilla (`mozilla_avis`) ; les autres reçoivent le nombre de failles exploitées de leur produit au catalogue de la
//! CISA, sans conclure pour leur version (`rapport`).
//!
//! Sous Linux, le gestionnaire de paquets tient les versions : la commande le dit et rend la main.

#[cfg(any(windows, target_os = "macos", test))]
pub(crate) mod inventaire;
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) mod lecteurs;
#[cfg(any(target_os = "macos", test))]
pub(crate) mod macos;
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) mod mozilla_avis;
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) mod produits;
#[cfg(any(windows, target_os = "macos", test))]
mod rapport;
pub(crate) mod resultat;
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) mod sources;
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) mod verdicts;
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) mod version;
#[cfg(any(windows, test))]
pub(crate) mod windows;

#[cfg(any(windows, target_os = "macos"))]
pub(crate) use rapport::constats;

/// Avis lus au moins dans l'archive de Mozilla : au-dessous, ce n'est pas l'archive attendue (plus de 1 000 avis
/// utiles le 23 oct. 2026).
#[cfg(any(windows, target_os = "macos", test))]
const AVIS_MIN: usize = 100;

/// L'index des avis de sécurité de Mozilla, tiré de l'archive tar du dépôt (`announce/<année>/mfsa*.yml` ou `.md`).
/// `None` : archive coupée, abîmée, ou trop peu d'avis.
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) fn avis_de_l_archive(tar: &[u8]) -> Option<mozilla_avis::Index> {
    avis_au_moins(tar, AVIS_MIN)
}

#[cfg(any(windows, target_os = "macos", test))]
fn avis_au_moins(tar: &[u8], minimum: usize) -> Option<mozilla_avis::Index> {
    let bornes = crate::archives::Bornes {
        entrees: 20_000,
        fichier: mozilla_avis::AVIS_MAX,
        total: 64 << 20,
    };
    let garder = |nom: &str| {
        let fichier = nom.rsplit('/').next().unwrap_or_default();
        nom.contains("/announce/") && fichier.starts_with("mfsa") && mozilla_avis::format(fichier).is_some()
    };
    let lus = crate::archives::tar::fichiers(tar, &bornes, garder)?;
    let mut index = mozilla_avis::Index::default();
    for (nom, octets) in &lus.fichiers {
        if let Some(avis) = mozilla_avis::avis(nom, octets) {
            index.ajouter(&avis);
        }
    }
    (index.avis >= minimum).then_some(index)
}

/// `vanguard logiciels-perimes`, et le menu (qui demande Entrée ensuite, comme pour chaque outil).
pub fn afficher() {
    #[cfg(any(windows, target_os = "macos"))]
    rapport::afficher();
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        use crate::tr;
        crate::ui::titre(tr!("Logiciels pas à jour", "Outdated software"));
        crate::ui::afficher_aligne(
            "  ",
            tr!(
                "Ce contrôle vise Windows et macOS. Sous Linux, le gestionnaire de paquets tient les versions : vanguard mises-a-jour, et le bilan (Failles connues) avec le catalogue de la CISA.",
                "This check is for Windows and macOS. On Linux, the package manager keeps the versions: vanguard updates, and the check-up (Known flaws) with CISA's catalog."
            ),
            2,
            "",
        );
    }
}

/// `vanguard logiciels-perimes --json` : le résultat de l'examen, versé comme celui de l'écran.
pub fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    #[cfg(any(windows, target_os = "macos"))]
    let r = rapport::resultat_verse(debut);
    #[cfg(not(any(windows, target_os = "macos")))]
    let r = resultat::hors_portee(debut);
    println!("{}", crate::modele::resultat::json(&r));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une entrée tar ustar faite à la main.
    pub(crate) fn entree(tar: &mut Vec<u8>, nom: &str, contenu: &[u8]) {
        let mut entete = [0u8; 512];
        entete[..nom.len()].copy_from_slice(nom.as_bytes());
        entete[124..135].copy_from_slice(format!("{:011o}", contenu.len()).as_bytes());
        entete[156] = b'0';
        entete[257..263].copy_from_slice(b"ustar\0");
        tar.extend(entete);
        tar.extend(contenu);
        tar.extend(vec![0u8; contenu.len().div_ceil(512) * 512 - contenu.len()]);
    }

    /// Une archive comme celle de codeload, avis inventés : seuls les avis d'`announce/` comptent, et il en faut
    /// assez ; coupée, elle ne vaut rien.
    #[test]
    fn archive_des_avis() {
        let mut tar = Vec::new();
        entree(
            &mut tar,
            "depot-main/README.md",
            b"---\nfixed_in:\n- Firefox 1\n---\nCVE-2099-0001\n",
        );
        for i in 0..3 {
            let avis = format!(
                "fixed_in:\n- Firefox 15{i}.0.1\nadvisories:\n  CVE-2099-{:04}:\n    title: x\n",
                1000 + i
            );
            entree(
                &mut tar,
                &format!("depot-main/announce/2099/mfsa2099-{i:02}.yml"),
                avis.as_bytes(),
            );
        }
        entree(
            &mut tar,
            "depot-main/announce/2099/autre.yml",
            b"fixed_in:\n- Firefox 9\nadvisories:\n  CVE-2099-0002:\n",
        );
        tar.extend([0u8; 1024]);
        let index = avis_au_moins(&tar, 3).unwrap();
        assert_eq!(index.avis, 3);
        assert!(index.cves.contains_key("CVE-2099-1002") && !index.cves.contains_key("CVE-2099-0001"));
        assert!(avis_au_moins(&tar, 4).is_none());
        assert!(avis_de_l_archive(&tar).is_none(), "trop peu d'avis");
        assert!(avis_au_moins(&tar[..tar.len() - 1536], 1).is_none(), "coupée");
    }
}
