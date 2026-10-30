//! La lecture seule de l'autodiagnostic : un interrupteur du processus qui fait refuser les écritures d'état, et la
//! preuve par empreintes que rien n'a changé dans le dossier de Vanguard pendant l'essai.
//!
//! Pourquoi un interrupteur et pas un paramètre passé aux règles : trois règles écrivent leur « déjà vu » à chaque
//! bilan (administrateurs, appareils Bluetooth, logiciels installés). Relancées par l'autotest sans lui, elles
//! accepteraient comme connu un nouvel administrateur ou un logiciel arrivé, et le bilan suivant se tairait. Trois
//! points d'entrée (`socle::ecrire_atomique`, `socle::ecriture_sure`, `modele::journal::noter`) au lieu des règles
//! une à une ; les empreintes attrapent ce qui passerait à côté.
//!
//! L'interrupteur n'est jamais relevé : une règle hors délai reste vivante dans son fil (rien ne peut l'arrêter) et
//! écrirait son « déjà vu » après coup. Les fichiers de l'autotest lui-même s'écrivent par un chemin exempté nommé
//! (`ecrire_resultat`), dans le seul fil qui l'ouvre, et pour une liste fermée de fichiers.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::Path;

/// Posé pour tout le processus (programme seulement : voir `POSE_ICI`).
#[cfg(not(test))]
static POSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
thread_local! {
    /// Sous `cargo test`, les tests tournent en fils parallèles du même processus : un interrupteur commun ferait
    /// échouer les écritures des autres tests. Il vaut donc pour le fil, et passe aux fils des règles (`Heritage`).
    static POSE_ICI: Cell<bool> = const { Cell::new(false) };
}

thread_local! {
    /// Le fil qui écrit le résultat de l'autotest, le temps de l'écrire.
    static EXEMPTE: Cell<bool> = const { Cell::new(false) };
}

/// Ce que l'autotest écrit lui-même, une fois l'essai fini : son résultat, la date du dernier essai, l'événement du
/// journal (sa tête scellée), et le registre des sceaux qui scelle ces fichiers, avec son témoin. Rien d'autre, même
/// exempté.
const EXEMPTES: &[&str] = &[
    "examens/AUT-VAN-001.json",
    super::DERNIER,
    crate::modele::journal::TETE,
    "sceaux.json",
    crate::sceau::TEMOIN,
];

/// Pose l'interrupteur : à partir de là, aucune écriture d'état ne passe, jusqu'à la fin du processus.
pub(crate) fn poser() {
    #[cfg(test)]
    POSE_ICI.set(true);
    #[cfg(not(test))]
    POSE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// L'interrupteur est-il posé ?
pub(crate) fn active() -> bool {
    #[cfg(test)]
    {
        POSE_ICI.get()
    }
    #[cfg(not(test))]
    {
        POSE.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Retire l'interrupteur du fil (tests seulement : le programme ne le relève jamais).
#[cfg(test)]
pub(crate) fn relever_pour_le_test() {
    POSE_ICI.set(false);
}

/// L'état de l'interrupteur, à reprendre dans un fil lancé pour une règle. Sans effet hors des tests, où
/// l'interrupteur vaut pour tout le processus.
#[derive(Clone, Copy)]
pub(crate) struct Heritage(#[cfg_attr(not(test), allow(dead_code))] bool); // lu sous cfg(test) seulement, voulu (voir plus haut)

pub(crate) fn heritage() -> Heritage {
    Heritage(active())
}

impl Heritage {
    #[cfg_attr(not(test), allow(clippy::unused_self))] // l'héritage ne sert que par fil, sous les tests
    pub(crate) fn poser_ici(self) {
        #[cfg(test)]
        if self.0 {
            POSE_ICI.set(true);
        }
    }
}

/// Un fichier de l'autotest (un de `EXEMPTES`, sous n'importe quel dossier).
fn exempte(chemin: &Path) -> bool {
    let texte = chemin.to_string_lossy().replace('\\', "/");
    EXEMPTES
        .iter()
        .any(|e| texte == *e || texte.ends_with(&format!("/{e}")))
}

/// L'écriture de ce fichier est-elle refusée ? Oui sous l'interrupteur, sauf dans le fil qui écrit le résultat de
/// l'autotest, pour l'un de ses fichiers.
pub(crate) fn refuse_fichier(chemin: &Path) -> bool {
    active() && !(EXEMPTE.get() && exempte(chemin))
}

/// Écrire dans un dossier d'état est-il refusé (journal des événements, sceaux) ? Le détail par fichier suit dans
/// `refuse_fichier`.
pub(crate) fn refuse_dossier() -> bool {
    active() && !EXEMPTE.get()
}

/// L'erreur rendue à une écriture refusée : ses appelants l'ignorent ou la notent, comme un disque en lecture seule.
pub(crate) fn refus() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "lecture seule (autotest) / read only (self-test)",
    )
}

/// Écrit le résultat de l'autotest : seul ce fil, le temps de `ecrire`, passe l'interrupteur, et seulement pour les
/// fichiers de `EXEMPTES`. Une règle hors délai qui écrirait en même temps reste refusée.
pub(crate) fn ecrire_resultat<T>(ecrire: impl FnOnce() -> T) -> T {
    struct Fin;
    impl Drop for Fin {
        fn drop(&mut self) {
            EXEMPTE.set(false);
        }
    }
    EXEMPTE.set(true);
    let _fin = Fin;
    ecrire()
}

/// Au-delà, un fichier n'est haché que sur son début (avec sa taille) : un fichier énorme ne fait pas durer l'essai.
const OCTETS_PAR_FICHIER: u64 = 64 << 20;
/// Au-delà, l'empreinte s'arrête et le dit (`bornee`).
const FICHIERS_MAX: usize = 50_000;
const OCTETS_MAX: u64 = 1 << 30;

/// Ce qui ne compte pas dans la comparaison (liste fermée) : les listes téléchargées (elles se renouvellent seules),
/// les fichiers de l'autotest, et le journal des erreurs (ouvert en ajout hors de `ecrire_atomique` : une règle qui
/// note une erreur pendant l'essai le change, ce n'est pas un défaut). Les verrous et les temporaires d'une écriture
/// en cours ne sont pas de l'état.
const HORS_COMPARAISON: &[&str] = &[
    "autotest",
    "examens/AUT-VAN-001.json",
    "journal-erreurs.txt",
    "empreintes",
    "malwarebazaar",
    "echap",
    "kev",
    "feodo",
    "threatfox",
    "urlhaus",
    "loldrivers",
    "tldr",
];

fn hors_comparaison(relatif: &str) -> bool {
    let premier = relatif.split('/').next().unwrap_or_default();
    HORS_COMPARAISON
        .iter()
        .any(|h| relatif == *h || premier == *h || relatif.starts_with(&format!("{h}/")))
        || relatif.ends_with(".verrou")
        || std::path::Path::new(relatif).extension().is_some_and(|e| e == "lock")
        || relatif.contains(".tmp-")
}

/// L'empreinte d'un dossier : chaque fichier (chemin relatif → empreinte BLAKE3 de sa taille et de son contenu).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Empreinte {
    pub fichiers: BTreeMap<String, String>,
    /// L'empreinte n'a pas tout lu (trop de fichiers, trop d'octets) : la preuve n'est pas complète.
    pub bornee: bool,
    /// Le dossier n'existe pas (jamais rien écrit ici).
    pub absent: bool,
}

/// L'empreinte de `dossier`. Les liens symboliques ne sont jamais suivis (leur cible compte comme leur contenu) ; un
/// tube nommé ou un périphérique n'est jamais ouvert (son genre compte seul).
pub(crate) fn empreinte_dossier(dossier: &Path) -> Empreinte {
    let mut e = Empreinte {
        absent: std::fs::symlink_metadata(dossier).is_err(),
        ..Empreinte::default()
    };
    let mut octets = 0u64;
    let mut a_voir = vec![dossier.to_path_buf()];
    while let Some(d) = a_voir.pop() {
        let Ok(entrees) = std::fs::read_dir(&d) else { continue };
        for entree in entrees.flatten() {
            let chemin = entree.path();
            let Ok(relatif) = chemin.strip_prefix(dossier) else {
                continue;
            };
            let relatif = relatif.to_string_lossy().replace('\\', "/");
            if hors_comparaison(&relatif) {
                continue;
            }
            let Ok(m) = std::fs::symlink_metadata(&chemin) else {
                continue;
            };
            if m.is_dir() {
                a_voir.push(chemin);
                continue;
            }
            if e.fichiers.len() >= FICHIERS_MAX || octets >= OCTETS_MAX {
                e.bornee = true;
                return e;
            }
            let valeur = if m.file_type().is_symlink() {
                format!(
                    "lien:{}",
                    std::fs::read_link(&chemin)
                        .map(|c| c.to_string_lossy().into_owned())
                        .unwrap_or_default()
                )
            } else if m.is_file() {
                octets += m.len().min(OCTETS_PAR_FICHIER);
                hacher(&chemin, m.len())
            } else {
                "special".to_string()
            };
            e.fichiers.insert(relatif, valeur);
        }
    }
    e
}

/// L'empreinte d'un simple fichier : sa taille, puis ses `OCTETS_PAR_FICHIER` premiers octets. Ouvert sans suivre de
/// lien ni attendre (un tube posé entre le regard et l'ouverture ne fige rien).
fn hacher(chemin: &Path, taille: u64) -> String {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut h = blake3::Hasher::new_derive_key("vanguard autotest empreinte 1");
    h.update(&taille.to_le_bytes());
    match options.open(chemin) {
        Ok(f) => {
            if h.update_reader(f.take(OCTETS_PAR_FICHIER)).is_err() {
                return "illisible".into();
            }
        }
        Err(_) => return "illisible".into(),
    }
    h.finalize().to_hex().to_string()
}

/// Ce qui a changé d'une empreinte à l'autre.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Changement {
    Ajoute,
    Change,
    Retire,
}

impl Changement {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Changement::Ajoute => "ajoute",
            Changement::Change => "change",
            Changement::Retire => "retire",
        }
    }
}

/// Les fichiers ajoutés, changés ou retirés entre `avant` et `apres`, dans l'ordre des chemins.
pub(crate) fn ecarts(avant: &Empreinte, apres: &Empreinte) -> Vec<(String, Changement)> {
    let mut tous = Vec::new();
    for (nom, e) in &apres.fichiers {
        match avant.fichiers.get(nom) {
            None => tous.push((nom.clone(), Changement::Ajoute)),
            Some(a) if a != e => tous.push((nom.clone(), Changement::Change)),
            Some(_) => {}
        }
    }
    for nom in avant.fichiers.keys() {
        if !apres.fichiers.contains_key(nom) {
            tous.push((nom.clone(), Changement::Retire));
        }
    }
    tous.sort();
    tous
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jetable(nom: &str) -> std::path::PathBuf {
        let d = crate::socle::dossier_local().join(format!("essai-lecture-seule-{nom}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Sous l'interrupteur, `ecrire_atomique`, les sceaux et le journal des événements refusent ; un événement
    /// d'essai passe par le chemin exempté et n'apparaît ni dans les alertes ni dans `dernier`.
    #[test]
    fn ecritures_refusees_sous_l_interrupteur() {
        use crate::modele::evenement::{Evenement, Genre, Source};
        let d = jetable("refus");
        poser();
        assert!(crate::socle::ecrire_atomique(&d.join("administrateurs.json"), b"[]").is_err());
        assert!(!d.join("administrateurs.json").exists());
        assert!(crate::sceau::ecrire_dans(&d, crate::sceau::LOGICIELS, b"{}").is_err());
        assert!(!d.join(crate::sceau::LOGICIELS).exists());
        assert!(!crate::socle::ecriture_sure(&d));
        let alerte = Evenement::nouveau(
            Source::Outil,
            Genre::Examen {
                outil: "AUT-VAN-001".into(),
                verdict: "sain".into(),
                problemes: 0,
                non_verifies: 0,
            },
        );
        assert_eq!(crate::modele::journal::noter(alerte.clone()), None);
        // Le chemin exempté : seulement les fichiers de l'autotest, et un événement d'essai.
        let mut essai = alerte.clone();
        essai.essai = true;
        ecrire_resultat(|| {
            assert!(crate::socle::ecrire_atomique(&d.join("administrateurs.json"), b"[]").is_err());
            crate::sceau::ecrire_dans(&d, "examens/AUT-VAN-001.json", b"{}").unwrap();
            assert!(crate::modele::journal::noter_dans(&d, essai.clone(), chrono::Utc::now()).is_ok());
            assert!(crate::modele::journal::noter_dans(&d, alerte.clone(), chrono::Utc::now()).is_err());
        });
        assert!(!d.join("administrateurs.json").exists());
        let lus = crate::modele::journal::lire_dans(&d);
        // Le premier passage de version se note avec lui (une décision, pas une alerte) ; un seul examen, d'essai.
        let examens: Vec<_> = lus
            .evenements
            .iter()
            .filter(|e| matches!(e.quoi, Genre::Examen { .. }))
            .collect();
        assert_eq!(examens.len(), 1, "{lus:?}");
        assert!(examens[0].essai);
        assert_eq!(crate::modele::journal::alertes(&lus.evenements).count(), 0);
        // Hors du chemin exempté, de nouveau refusé.
        assert!(crate::sceau::ecrire_dans(&d, "examens/AUT-VAN-001.json", b"{}").is_err());
        relever_pour_le_test();
        assert!(crate::socle::ecrire_atomique(&d.join("administrateurs.json"), b"[]").is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une règle hors délai qui écrit après coup, pendant puis après l'écriture du résultat : rien n'est écrit.
    #[test]
    fn regle_hors_delai_n_ecrit_jamais() {
        let d = jetable("delai");
        poser();
        let heritage = heritage();
        let (va, attends) = std::sync::mpsc::channel::<()>();
        let cible = d.join("bluetooth.json");
        let fil = {
            let cible = cible.clone();
            std::thread::spawn(move || {
                heritage.poser_ici();
                let _ = attends.recv();
                crate::socle::ecrire_atomique(&cible, b"[\"appris\"]").is_err()
            })
        };
        // Le résultat de l'autotest s'écrit (exempté dans ce fil) pendant que la règle écrit.
        ecrire_resultat(|| {
            va.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        assert!(fil.join().unwrap(), "la règle a pu écrire");
        assert!(!cible.exists());
        relever_pour_le_test();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'empreinte voit un fichier ajouté, changé, retiré ; elle ignore la liste fermée ; un lien n'est pas suivi.
    #[test]
    fn empreinte_voit_ajout_changement_retrait() {
        let d = jetable("empreinte");
        std::fs::write(d.join("historique.json"), b"[1]").unwrap();
        std::fs::write(d.join("appris.json"), b"{}").unwrap();
        std::fs::create_dir_all(d.join("kev")).unwrap();
        let avant = empreinte_dossier(&d);
        assert_eq!(avant.fichiers.len(), 2, "{avant:?}");
        std::fs::write(d.join("historique.json"), b"[2]").unwrap();
        std::fs::remove_file(d.join("appris.json")).unwrap();
        std::fs::write(d.join("nouveau.json"), b"x").unwrap();
        // Hors comparaison : listes téléchargées, journal des erreurs, fichiers de l'autotest, verrous.
        std::fs::write(d.join("kev/liste.json"), b"x").unwrap();
        std::fs::write(d.join("journal-erreurs.txt"), b"x").unwrap();
        std::fs::create_dir_all(d.join("autotest")).unwrap();
        std::fs::write(d.join("autotest/mesures.json"), b"{}").unwrap();
        std::fs::write(d.join("sceaux.verrou"), b"").unwrap();
        let apres = empreinte_dossier(&d);
        assert_eq!(
            ecarts(&avant, &apres),
            vec![
                ("appris.json".to_string(), Changement::Retire),
                ("historique.json".to_string(), Changement::Change),
                ("nouveau.json".to_string(), Changement::Ajoute),
            ]
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/dev/zero", d.join("lien")).unwrap();
            let e = empreinte_dossier(&d);
            assert_eq!(e.fichiers.get("lien").map(String::as_str), Some("lien:/dev/zero"));
        }
        assert!(!apres.bornee && !apres.absent);
        assert!(empreinte_dossier(&d.join("absent")).absent);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Garde structurelle : aucune écriture directe dans src/machine (hors des tests), sauf les exceptions nommées,
    /// toutes hors du bilan. Une règle qui écrirait à côté de l'interrupteur se voit ici, pas seulement aux empreintes.
    #[test]
    fn aucune_ecriture_directe_dans_les_regles() {
        const EXCEPTIONS: &[(&str, usize, &str)] = &[
            (
                "machine/macos/corpus.rs",
                1,
                "module de tests (cfg(test)) : pose le fichier d'agent fabriqué d'un cas du corpus dans un dossier jetable",
            ),
            (
                "machine/linux/corpus.rs",
                1,
                "module de tests (cfg(test)) : pose l'arborescence fabriquée d'un cas du corpus dans un dossier jetable",
            ),
            (
                "machine/mod.rs",
                1,
                "ports bloqués : après une correction acceptée, hors bilan",
            ),
            (
                "machine/windows/mod.rs",
                3,
                "script de correction en administrateur, hors bilan",
            ),
            (
                "machine/windows/eleve.rs",
                2,
                "processus élevé d'une correction, hors bilan",
            ),
            (
                "machine/linux/veilleur.rs",
                10,
                "veilleur : son état et le « chiffrement voulu » de l'anti-rançongiciel, hors bilan",
            ),
        ];
        const ECRITURES: &[&str] = &[
            "fs::write(",
            "File::create(",
            ".write(true)",
            ".append(true)",
            "fs::rename(",
            "fs::remove_file(",
            "fs::copy(",
        ];
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut a_voir = vec![racine.join("machine")];
        let mut trouves = std::collections::BTreeMap::new();
        while let Some(d) = a_voir.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    a_voir.push(p);
                    continue;
                }
                let texte = std::fs::read_to_string(&p).unwrap();
                let code = texte.find("#[cfg(test)]\nmod ").map_or(texte.as_str(), |t| &texte[..t]);
                let n = code
                    .lines()
                    .filter(|l| !l.trim_start().starts_with("//") && ECRITURES.iter().any(|x| l.contains(x)))
                    .count();
                if n > 0 {
                    let nom = p.strip_prefix(&racine).unwrap().to_string_lossy().replace('\\', "/");
                    trouves.insert(nom, n);
                }
            }
        }
        for (nom, n) in &trouves {
            let permis = EXCEPTIONS.iter().find(|(f, _, _)| f == nom).map_or(0, |e| e.1);
            assert!(
                *n <= permis,
                "{nom} : {n} écriture(s) directe(s), {permis} permise(s) : passer par socle::ecrire_atomique ou sceau"
            );
        }
        assert!(!trouves.is_empty(), "la lecture des sources ne trouve plus rien");
    }

    /// Un fichier énorme est haché sur son début seulement, et vite.
    #[test]
    fn empreinte_bornee_pour_un_gros_fichier() {
        let d = jetable("gros");
        std::fs::File::create(d.join("gros.bin"))
            .unwrap()
            .set_len(4 << 30)
            .unwrap();
        let debut = std::time::Instant::now();
        let e = empreinte_dossier(&d);
        assert_eq!(e.fichiers.len(), 1);
        assert!(debut.elapsed() < std::time::Duration::from_secs(20));
        let _ = std::fs::remove_dir_all(&d);
    }
}
