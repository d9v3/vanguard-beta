//! Les étapes de `outils/deployer.sh` confiées au programme (`vanguard deploiement …`, commande cachée) : elles
//! étaient en bash et en Python, à côté d'un code Rust qui faisait la même chose et pouvait en diverger. Le programme
//! n'écrit rien de lui-même : chaque étape n'est lancée que par le déploiement, sur l'ordinateur de l'auteur.

use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::ui::*;

/// Une étape du déploiement.
#[derive(clap::Subcommand)]
pub(crate) enum Etape {
    /// Mettre à jour les archives de tldr-pages de la clé (anglais, français), vérifiées comme zipfile.testzip.
    Tldr {
        /// Le dossier tldr de la clé.
        dossier: PathBuf,
    },
    /// Vérifier que vanguard.exe ne charge ses DLL importées que depuis System32 (DependentLoadFlags).
    #[command(name = "verifier-pe")]
    VerifierPe {
        /// Le programme Windows compilé, lu sans être lancé.
        fichier: PathBuf,
    },
    /// Écrire les témoins de la clé : son jeton d'identité (tiré une fois) et l'empreinte de cet ordinateur.
    Temoins {
        /// La racine de la clé.
        racine: PathBuf,
    },
}

/// 0 : l'étape a réussi ; 1 : elle a échoué, et l'a dit.
pub(crate) fn executer(etape: Etape) -> i32 {
    let reussi = match etape {
        Etape::Tldr { dossier } => crate::guide::tldr_sur_la_cle(&dossier),
        Etape::VerifierPe { fichier } => verifier_pe(&fichier),
        Etape::Temoins { racine } => match temoins(&racine, crate::machine::empreinte_machine()) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("{e}");
                false
            }
        },
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

/// Les deux témoins de la clé, que le bash du déploiement écrivait à côté du code qui les relit :
/// - `vanguard.jeton` (`protection::cles_connues`), tiré une seule fois : 16 octets du hasard du système en 32
///   caractères hexadécimaux minuscules et un saut de ligne, comme `head -c 16 /dev/urandom | od`. Un jeton que le
///   programme lit déjà (`cles_connues::jeton_de`) est gardé tel quel, même en majuscules : cet ordinateur et la
///   partition des journaux le connaissent ainsi ;
/// - `vanguard.cle`, l'empreinte de cet ordinateur (`machine::empreinte_d_identifiant`, celle que la clé compare),
///   réécrit seulement s'il change (une écriture de moins sur la clé à chaque déploiement).
///
/// Chacun s'écrit à côté, sur le disque, puis prend sa place (`socle::ecrire_atomique`) : une clé retirée pendant
/// l'écriture ne garde pas un témoin à moitié écrit, qui la ferait prendre pour une autre. Sans empreinte lisible,
/// rien n'est écrit : un témoin faux remonterait la clé en lecture seule chez son propriétaire. `Ok(true)` : un jeton
/// a été tiré.
fn temoins(racine: &Path, empreinte: Option<String>) -> Result<bool, String> {
    let Some(empreinte) = empreinte else {
        return Err(tr!(
            "✖ Empreinte de cet ordinateur illisible : témoins de la clé non écrits",
            "✖ This computer's fingerprint is unreadable: key markers not written"
        )
        .into());
    };
    let non_ecrit = |nom: &str, e: std::io::Error| {
        trf!(
            "✖ {nom} non écrit sur la clé : {e}",
            "✖ {nom} not written to the key: {e}"
        )
    };
    let jeton = crate::protection::cles_connues::JETON;
    let tire = crate::protection::cles_connues::jeton_de(racine).is_none();
    if tire {
        let mut octets = [0u8; 16];
        getrandom::fill(&mut octets).map_err(|e| non_ecrit(jeton, std::io::Error::other(e.to_string())))?;
        let mut texte = String::with_capacity(33);
        for o in octets {
            let _ = write!(texte, "{o:02x}");
        }
        texte.push('\n');
        crate::socle::ecrire_atomique(&racine.join(jeton), texte.as_bytes()).map_err(|e| non_ecrit(jeton, e))?;
        // Le jeton lui-même n'est pas affiché : il identifie la clé, et la sortie du déploiement se garde.
        println!(
            "{}",
            trf!(
                "Jeton de la clé tiré : {}",
                "Key token drawn: {}",
                racine.join(jeton).display()
            )
        );
    }
    let temoin = racine.join(crate::reseau::TEMOIN_CLE);
    let attendu = format!("{empreinte}\n");
    if crate::socle::lire_ordinaire(&temoin, 256).ok().as_deref() != Some(attendu.as_bytes()) {
        crate::socle::ecrire_atomique(&temoin, attendu.as_bytes())
            .map_err(|e| non_ecrit(crate::reseau::TEMOIN_CLE, e))?;
    }
    Ok(tire)
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

    /// La valeur de `printf '%s' 0123456789abcdef0123456789abcdef | sha1sum`, calculée à côté : le témoin est le même
    /// octet pour octet que celui de l'ancien bash, avec ou sans saut de ligne final dans /etc/machine-id.
    const SHA1_DE_L_ESSAI: &str = "b1775a785f09a6ebaf2dc33d6eaeb98974d9cdb8";

    #[test]
    fn empreinte_comme_sha1sum() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            crate::machine::empreinte_d_identifiant(id).as_deref(),
            Some(SHA1_DE_L_ESSAI)
        );
        assert_eq!(
            crate::machine::empreinte_d_identifiant(&format!("{id}\n")).as_deref(),
            Some(SHA1_DE_L_ESSAI)
        );
        assert_eq!(crate::machine::empreinte_d_identifiant(" \n"), None);
    }

    #[test]
    fn temoins_jeton_tire_ou_garde() {
        let d = dossier();
        let empreinte = || crate::machine::empreinte_d_identifiant("0123456789abcdef0123456789abcdef");
        // Absent : tiré, 32 caractères hexadécimaux minuscules et un saut de ligne, relisible par le programme.
        assert_eq!(temoins(&d, empreinte()), Ok(true));
        let texte = std::fs::read_to_string(d.join("vanguard.jeton")).unwrap();
        assert_eq!(texte.len(), 33);
        assert!(texte.ends_with('\n'));
        assert!(texte[..32].chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_eq!(
            crate::protection::cles_connues::jeton_de(&d).as_deref(),
            Some(&texte[..32])
        );
        assert_eq!(
            std::fs::read_to_string(d.join("vanguard.cle")).unwrap(),
            format!("{SHA1_DE_L_ESSAI}\n")
        );
        // Déjà là : gardé.
        assert_eq!(temoins(&d, empreinte()), Ok(false));
        assert_eq!(std::fs::read_to_string(d.join("vanguard.jeton")).unwrap(), texte);
        // Valide en majuscules : gardé tel quel.
        std::fs::write(d.join("vanguard.jeton"), "0123456789ABCDEF0123456789ABCDEF\n").unwrap();
        assert_eq!(temoins(&d, empreinte()), Ok(false));
        assert_eq!(
            std::fs::read_to_string(d.join("vanguard.jeton")).unwrap(),
            "0123456789ABCDEF0123456789ABCDEF\n"
        );
        // Invalide : retiré au profit d'un nouveau.
        std::fs::write(d.join("vanguard.jeton"), "pas un jeton\n").unwrap();
        assert_eq!(temoins(&d, empreinte()), Ok(true));
        assert!(crate::protection::cles_connues::jeton_de(&d).is_some());
        // Aucun temporaire de l'écriture atomique ne reste sur la clé.
        let restes: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .map(|f| f.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(restes.is_empty(), "{restes:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn temoins_sans_empreinte_rien_n_est_touche() {
        let d = dossier();
        std::fs::write(d.join("vanguard.cle"), "ancien\n").unwrap();
        assert!(temoins(&d, None).is_err());
        assert_eq!(std::fs::read_to_string(d.join("vanguard.cle")).unwrap(), "ancien\n");
        assert!(!d.join("vanguard.jeton").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
