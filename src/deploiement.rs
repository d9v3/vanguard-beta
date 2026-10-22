//! Les étapes de `outils/deployer.sh` confiées au programme (`vanguard deploiement …`, commande cachée) : elles
//! étaient en bash et en Python, à côté d'un code Rust qui faisait la même chose et pouvait en diverger. Le programme
//! n'écrit rien de lui-même : chaque étape n'est lancée que par le déploiement, sur l'ordinateur de l'auteur.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::ui::*;

/// Une étape du déploiement.
#[derive(clap::Subcommand)]
pub(crate) enum Etape {
    /// Vérifier que vanguard.exe ne charge ses DLL importées que depuis System32 (DependentLoadFlags).
    #[command(name = "verifier-pe")]
    VerifierPe {
        /// Le programme Windows compilé, lu sans être lancé.
        fichier: PathBuf,
    },
}

/// 0 : l'étape a réussi ; 1 : elle a échoué, et l'a dit.
pub(crate) fn executer(etape: Etape) -> i32 {
    let reussi = match etape {
        Etape::VerifierPe { fichier } => verifier_pe(&fichier),
    };
    i32::from(!reussi)
}

/// Au-delà, ce n'est pas un programme de Vanguard : il n'est pas lu (la même borne que la mise à jour).
const PROGRAMME_MAX: u64 = 512 << 20;

/// Le contenu entier d'un fichier ordinaire de `max` octets au plus.
fn lire_entier(chemin: &Path, max: u64) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(chemin).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(tr!("pas un fichier ordinaire", "not a regular file").into());
    }
    if meta.len() > max {
        return Err(tr!("démesuré", "oversized").into());
    }
    let mut octets = Vec::new();
    std::fs::File::open(chemin)
        .and_then(|f| f.take(max + 1).read_to_end(&mut octets))
        .map_err(|e| e.to_string())?;
    if u64::try_from(octets.len()).is_ok_and(|n| n > max) {
        return Err(tr!("démesuré", "oversized").into());
    }
    Ok(octets)
}

/// Le programme Windows porte-t-il la garde qui ferme le chargement d'une DLL posée à côté de lui
/// (`machine::windows::chargement`) ? Lu, jamais lancé. Un fichier absent ou illisible est refusé : ce qui n'est pas
/// vérifié ne part pas.
fn verifier_pe(fichier: &Path) -> bool {
    let f = fichier.display();
    let octets = match lire_entier(fichier, PROGRAMME_MAX) {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "{}",
                trf!(
                    "✖ {f} illisible ({e}) : ne pas le livrer",
                    "✖ {f} unreadable ({e}): do not ship it"
                )
            );
            return false;
        }
    };
    let lu = crate::machine::pe::lire_load_config(&octets);
    if crate::machine::pe::system32_seulement(lu) {
        println!(
            "{}",
            trf!(
                "✔ {f} : DLL importées depuis System32 seulement",
                "✔ {f}: imported DLLs from System32 only"
            )
        );
        return true;
    }
    let config = match lu {
        None => tr!("absent", "missing").to_string(),
        Some((taille, drapeaux)) => trf!(
            "taille {taille}, drapeaux 0x{drapeaux:X}",
            "size {taille}, flags 0x{drapeaux:X}"
        ),
    };
    eprintln!(
        "{}",
        trf!(
            "✖ {f} : DLL importées pas limitées à System32 (Load Config : {config}) ; ne pas le livrer",
            "✖ {f}: imported DLLs not limited to System32 (Load Config: {config}); do not ship it"
        )
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::pe::tests::pe_d_essai;

    fn dossier() -> PathBuf {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn verifier_pe_accepte_et_refuse() {
        let d = dossier();
        let bon = d.join("bon.exe");
        std::fs::write(&bon, pe_d_essai(148, 0x800)).unwrap();
        assert!(verifier_pe(&bon));
        assert_eq!(executer(Etape::VerifierPe { fichier: bon }), 0);
        let sans = d.join("sans.exe");
        std::fs::write(&sans, pe_d_essai(148, 0)).unwrap();
        assert!(!verifier_pe(&sans));
        let court = d.join("court.exe");
        std::fs::write(&court, pe_d_essai(64, 0x800)).unwrap();
        assert!(!verifier_pe(&court));
        // Absent, ou un dossier : refusé, jamais compté comme vérifié.
        assert!(!verifier_pe(&d.join("absent.exe")));
        assert!(!verifier_pe(&d));
        assert_eq!(
            executer(Etape::VerifierPe {
                fichier: d.join("absent.exe")
            }),
            1
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
