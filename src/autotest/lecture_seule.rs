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

// Sous Linux seulement : les parties Windows et macOS ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

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
                octets = octets.saturating_add(m.len().min(OCTETS_PAR_FICHIER));
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

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
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
                "machine/vidage.rs",
                2,
                "actes du processus élevé de Windows (vider un dossier de Windows, mettre un cache de côté) : des fichiers retirés ou renommés, pas un fichier de Vanguard à écrire",
            ),
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
                "machine/linux/http_unix.rs",
                1,
                "module d'essais (cfg(test)) : retire la prise Unix d'un faux démon laissée par un ancien processus",
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
                "machine/windows/reseau_ecriture.rs",
                6,
                "processus élevé : le hosts (temporaire neuf du dossier etc, puis ReplaceFileW ; créé sans écraser s'il manquait ; la copie d'avant remise si l'échange échoue à mi-chemin), hors bilan",
            ),
            (
                "machine/windows/ssh_ecriture.rs",
                4,
                "processus élevé : sshd_config (nouvelle version créée sans écraser dans le dossier de sshd réservé aux administrateurs, éprouvée par sshd -t, puis ReplaceFileW qui garde l'ancienne en copie ; le temporaire retiré s'il échoue ; l'ancienne remise si l'échange échoue à mi-chemin), hors bilan",
            ),
            (
                "machine/windows/eleve.rs",
                2,
                "processus élevé d'une correction, hors bilan",
            ),
            (
                "machine/windows/quarantaine.rs",
                3,
                "processus élevé : copie d'une racine ou d'un fichier du Démarrage commun retiré, créée sans écraser (create_new) dans un dossier réservé aux administrateurs, retirée si l'écriture échoue ou une fois remise à sa place, hors bilan",
            ),
            (
                "machine/windows/demarrage_ecriture.rs",
                4,
                "Démarrage commun (processus élevé) ou de la personne (Vanguard non élevé, son compte) : remise d'un fichier depuis sa copie de quarantaine vérifiée, créé sans écraser (create_new) dans un dossier relu (ni lien ni jonction) ; copie déposée sans écraser (create_new, jamais à travers un lien) dans la quarantaine vérifiée, retirée si l'écriture échoue ; la plus ancienne copie retirée après une question non annulable (« non » par défaut), hors bilan",
            ),
            (
                "machine/assistant.rs",
                1,
                "terminal de la personne (/dev/tty) ouvert pour demander l'accord d'un geste : rien n'est écrit sur le disque",
            ),
            (
                "machine/defense_eleve.rs",
                9,
                "enfant élevé de Défense (Linux) : fichier créé sans écraser ni suivre de lien (create_new, O_NOFOLLOW), avec son propriétaire et ses droits, écrit jusqu'au disque, dans un dossier de root fermé aux autres comptes ; remplacé par un voisin renommé seulement si le fichier n'a pas changé depuis la question ; un lien dur pour déplacer (rien n'est remplacé) ; la note d'avant retirée une fois le geste défait ; jamais sous les essais, hors bilan",
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

    /// Le code d'un fichier sans ses modules d'essais : `#[cfg(test)]` puis `mod … {` jusqu'à la première `}` en
    /// colonne 0 (rustfmt n'en met une qu'à la fin d'un élément de premier niveau). Le code qui suit un module
    /// d'essais est lu comme le reste ; un module déclaré ailleurs (`mod essais;`) ne retire que sa ligne.
    fn hors_essais(texte: &str) -> String {
        const DEBUT: &str = "#[cfg(test)]\nmod ";
        let mut code = String::new();
        let mut reste = texte;
        while let Some(t) = reste.find(DEBUT) {
            let (avant, apres) = reste.split_at(t);
            code.push_str(avant);
            let module = apres.strip_prefix("#[cfg(test)]\n").unwrap_or(apres);
            let (ligne, suite) = module.split_once('\n').unwrap_or((module, ""));
            reste = if ligne.trim_end().ends_with(';') {
                suite
            } else {
                module.split_once("\n}").map_or("", |(_, s)| s)
            };
        }
        code.push_str(reste);
        code
    }

    /// Le code après un module d'essais compte ; le module lui-même, non.
    #[test]
    fn essais_retires_le_reste_lu() {
        let texte = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn b() {\n    }\n}\nfn c() {}\n#[cfg(test)]\nmod autres;\nfn d() {}\n#[cfg(test)]\nmod e {\n    fn f() {}\n}\n";
        let code = hors_essais(texte);
        for x in ["fn a()", "fn c()", "fn d()"] {
            assert!(code.contains(x), "{x} : {code:?}");
        }
        for x in ["fn b()", "mod autres", "fn f()"] {
            assert!(!code.contains(x), "{x} : {code:?}");
        }
    }

    /// Garde structurelle des baisses : une ligne de choix exact (qui peut baisser une protection de Defender ou un
    /// réglage du pare-feu), une exclusion, un programme permis ou une note « c'est moi » ne s'écrit que depuis les
    /// Options de défense, où la personne l'a choisie elle-même (et le pare-feu Public recoupé à la sortie du mode
    /// Wi-Fi public, à sa question) ; ni le bilan, ni une correction, ni « Tout remettre » (qui n'a que
    /// `ligne_rallumer`) n'en fabriquent. Hors des tests, les seuls fichiers qui nomment ces fonctions ou ces verbes
    /// sont leur définition et l'écran des Options ; les constructeurs des Options (`ligne_choix`, `ligne_exclure`…)
    /// ne servent que dans ses fichiers, et leurs entrées seulement à la ligne de commande (`--choisir`,
    /// `--exclure`, `--permettre`, `--noter`, `--remettre`). Un acte nommé pour être rangé ou lu (motif `(..)`, `if let`, bras
    /// `Acte::X(a, b) =>`) ne fabrique rien et ne compte pas.
    #[test]
    fn les_baisses_ne_viennent_que_des_options() {
        const PERMIS: &[&str] = &[
            "machine/windows/gestes.rs",
            "options_defense.rs",
            "options_defense/ecran.rs",
        ];
        const OPTIONS: &[&str] = &["options_defense.rs", "options_defense/ecran.rs"];
        // Le pare-feu (D5) : l'écran des Options a son module ; la sortie du mode Wi-Fi public recoupe le pare-feu
        // Public, à la question explicite, par la seule ligne de baisse d'un profil.
        const PARE_FEU: &[&str] = &[
            "machine/windows/gestes.rs",
            "options_defense.rs",
            "options_defense/ecran.rs",
            "options_defense/ecran/pare_feu.rs",
        ];
        const PARE_FEU_ET_WIFI: &[&str] = &[
            "machine/windows/gestes.rs",
            "options_defense.rs",
            "options_defense/ecran.rs",
            "options_defense/ecran/pare_feu.rs",
            "reseau/wifi_public/mod.rs",
        ];
        // La sortie du mode Wi-Fi public (D0) : la remise du profil Public et de la catégorie du réseau.
        const WIFI: &[&str] = &["machine/windows/gestes.rs", "reseau/wifi_public/windows.rs"];
        // Les remises de la persistance (D6d) : la ligne de commande des Options, et le processus élevé qui les
        // fait, où la ligne ne sert qu'à nommer la note d'« avant ».
        const PERSISTANCE: &[&str] = &[
            "machine/windows/gestes.rs",
            "options_defense.rs",
            "machine/windows/taches_ecriture.rs",
            "machine/windows/demarrage_ecriture.rs",
            "machine/windows/wmi_ecriture.rs",
        ];
        // La coupure d'un pare-feu Linux (D7c) : les Options, la grammaire des gestes, l'enfant (qui la compare à
        // sa note, sans rien envoyer) et ses essais (`defense_eleve/tests/`, déclarés dans `mod tests`).
        const COUPER_LINUX: &[&str] = &[
            "options_defense/linux.rs",
            "machine/gestes_unix.rs",
            "machine/defense_eleve.rs",
            "machine/defense_eleve/pare_feu.rs",
            "machine/defense_eleve/tests/d7c.rs",
        ];
        // Un fichier qui n'est tout entier qu'un module d'essais (déclaré sous `#[cfg(test)]` par son parent, ce que
        // l'essai vérifie) : ses lignes ne partent jamais dans le programme.
        const ESSAIS_SEULS: &[(&str, &str, &str)] = &[(
            "modele/corpus.rs",
            "modele/mod.rs",
            "#[cfg(test)]\npub(crate) mod corpus;\n",
        )];
        // Chaque mot, et les seuls fichiers où il peut paraître.
        const MOTS: &[(&str, &[&str])] = &[
            ("ligne_baisse_defender(", PERMIS),
            ("ligne_baisse_asr(", PERMIS),
            ("DEFENDER_CHOIX", PERMIS),
            ("DEFENDER_ASR_CHOIX", PERMIS),
            ("defender-choix ", PERMIS),
            ("defender-asr-choix ", PERMIS),
            ("Acte::DefenderChoix(", PERMIS),
            ("Acte::DefenderAsrChoix(", PERMIS),
            ("ligne_ajout_exclusion(", PERMIS),
            ("ligne_autoriser_dossiers(", PERMIS),
            ("DEFENDER_EXCLUSION_AJOUTER", PERMIS),
            ("DEFENDER_DOSSIERS_AUTORISER", PERMIS),
            ("CHOIX_NOTER", PERMIS),
            ("defender-exclusion-ajouter ", PERMIS),
            ("defender-dossiers-autoriser ", PERMIS),
            ("choix-noter ", PERMIS),
            ("Acte::DefenderExclusionAjouter(", PERMIS),
            ("Acte::DefenderDossiersAutoriser(", PERMIS),
            ("Acte::ChoixNoter(", PERMIS),
            ("ligne_baisse_pare_feu(", PARE_FEU_ET_WIFI),
            ("ligne_regle_etat(", PARE_FEU),
            ("PARE_FEU_PROFIL", PERMIS),
            ("PARE_FEU_REGLE_ETAT", PERMIS),
            ("pare-feu-profil ", PERMIS),
            ("pare-feu-regle-etat ", PERMIS),
            ("Acte::PareFeuProfil(", PERMIS),
            ("Acte::PareFeuRegleEtat(", PERMIS),
            ("ligne_choix(", &["options_defense.rs"]),
            ("ligne_exclure(", &["options_defense.rs"]),
            ("ligne_exclusion(", OPTIONS),
            ("ligne_permettre(", OPTIONS),
            ("options_defense::choisir(", &["main.rs"]),
            ("options_defense::exclure(", &["main.rs"]),
            ("options_defense::permettre(", &["main.rs"]),
            ("options_defense::noter(", &["main.rs"]),
            // Défense D6b : la remise d'un réglage du registre ou d'un chemin de service noté, une baisse.
            ("ligne_reglage_remettre(", PERMIS),
            ("REGLAGE_REMETTRE", PERMIS),
            ("reglage-remettre ", PERMIS),
            ("Acte::ReglageRemettre(", PERMIS),
            ("ligne_service_chemin_remettre(", PERMIS),
            ("SERVICE_CHEMIN_REMETTRE", PERMIS),
            ("service-chemin-remettre ", PERMIS),
            ("Acte::ServiceCheminRemettre(", PERMIS),
            // Défense D6c : la remise des droits d'avant d'un fichier SSH ou de la copie d'avant de sshd_config.
            ("ligne_ssh_droits_remettre(", PERMIS),
            ("ligne_sshd_reglage_remettre(", PERMIS),
            ("SSH_CLES_ADMIN_REMETTRE", PERMIS),
            ("SSH_CLE_REMETTRE", PERMIS),
            ("SSHD_REGLAGE_REMETTRE", PERMIS),
            ("ssh-cles-admin-remettre", PERMIS),
            ("ssh-cle-remettre ", PERMIS),
            ("sshd-reglage-remettre ", PERMIS),
            ("Acte::SshDroitsRemettre(", PERMIS),
            ("Acte::SshdReglageRemettre(", PERMIS),
            ("ligne_remettre(", &["options_defense.rs"]),
            ("options_defense::remettre(", &["main.rs"]),
            // Défense D8 (W1) : le profil Public moins bloqué et un réseau remis en Privé, que le processus élevé juge
            // comme des baisses (`Acte::baisse_par_type`) ; seule la sortie du mode Wi-Fi public les fabrique.
            ("ligne_pare_feu_public(", WIFI),
            ("ligne_reseau_categorie(", WIFI),
            ("PARE_FEU_PUBLIC", WIFI),
            ("RESEAU_CATEGORIE", WIFI),
            ("pare-feu-public ", WIFI),
            ("reseau-categorie ", WIFI),
            ("Acte::PareFeuPublic(", WIFI),
            ("Acte::ReseauCategorie(", WIFI),
            // Défense D8 (W2) : la remise d'un lancement jugé suspect (D6d), une baisse elle aussi : « --remettre
            // demarrage: » des Options, et le processus élevé qui la fait (le nom de sa note vient de la ligne).
            ("RUN_REMETTRE", PERSISTANCE),
            ("TACHE_REACTIVER", PERSISTANCE),
            ("DEMARRAGE_REMETTRE", PERSISTANCE),
            ("WMI_ABONNEMENT_REMETTRE", PERSISTANCE),
            ("run-remettre ", PERSISTANCE),
            ("tache-reactiver ", PERSISTANCE),
            ("demarrage-remettre ", PERSISTANCE),
            ("wmi-abonnement-remettre ", PERSISTANCE),
            ("ligne_demarrage_remettre(", PERSISTANCE),
            ("Acte::TacheReactiver(", PERSISTANCE),
            ("Acte::DemarrageRemettre(", PERSISTANCE),
            ("Acte::WmiAbonnementRemettre(", PERSISTANCE),
            // Défense D8 (L1) : la coupure d'un pare-feu Linux (D7c), une baisse que seules les Options fabriquent ;
            // la grammaire la lit, l'enfant la juge et la remet, ses essais la forgent.
            ("ligne_couper(", &["options_defense/linux.rs"]),
            ("Defense::CouperPareFeu(", COUPER_LINUX),
        ];
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for (fichier, parent, declaration) in ESSAIS_SEULS {
            let texte = std::fs::read_to_string(racine.join(parent)).unwrap();
            assert!(
                texte.contains(declaration),
                "{fichier} n'est plus déclaré sous #[cfg(test)] dans {parent} : il n'est plus exempté"
            );
        }
        let mut a_voir = vec![racine.clone()];
        let mut trouves = std::collections::BTreeMap::new();
        let mut lus = 0;
        let mut vus = std::collections::BTreeSet::new();
        while let Some(d) = a_voir.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    a_voir.push(p);
                    continue;
                }
                if p.extension().is_none_or(|x| x != "rs") {
                    continue;
                }
                lus += 1;
                let nom = p.strip_prefix(&racine).unwrap().to_string_lossy().replace('\\', "/");
                if ESSAIS_SEULS.iter().any(|(f, ..)| *f == nom) {
                    continue;
                }
                let code = hors_essais(&std::fs::read_to_string(&p).unwrap());
                for l in code.lines().filter(|l| !l.trim_start().starts_with("//")) {
                    for (mot, permis) in MOTS {
                        if l.contains(mot) && !motif(l, mot) {
                            vus.insert(*mot);
                            if !permis.contains(&nom.as_str()) {
                                *trouves.entry(format!("{nom} : {mot}")).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(lus > 100, "la lecture des sources ne trouve plus rien ({lus})");
        // Un mot qui ne paraît plus nulle part ne garde plus rien : renommé, il faut le suivre ici.
        for (mot, _) in MOTS {
            assert!(
                vus.contains(mot),
                "« {mot} » ne paraît plus dans les sources : la garde ne le voit plus"
            );
        }
        assert!(
            trouves.is_empty(),
            "lignes de baisse fabriquées hors des Options de défense : {trouves:?}"
        );
    }

    /// Un acte déjà là se nomme pour être rangé ou lu (pas de baisse, rien d'écrit) : seul ce qui le fabrique compte.
    /// Motif : `Acte::X(..)`, `Acte::X(_)`, `if let … Acte::X(…) =` (à gauche du `=`), ou un bras `Acte::X(a, b) =>` (la flèche après
    /// lui, pas avant : `y => Acte::X(a).ligne()` le fabrique).
    fn motif(ligne: &str, mot: &str) -> bool {
        // Un geste de défense Linux (`Defense::X(..)`) se lit comme un acte de Windows.
        if !mot.starts_with("Acte::") && !mot.starts_with("Defense::") {
            return false;
        }
        ligne.match_indices(mot).all(|(i, _)| {
            let (avant, apres) = (&ligne[..i], &ligne[i + mot.len()..]);
            apres.starts_with("..)")
                || apres.starts_with("_)")
                // Le motif d'un `if let`, avant son `=` : après lui, l'acte serait fabriqué.
                || (ligne.trim_start().starts_with("if let ") && !avant.contains('=') && apres.contains(" = "))
                || (apres.contains("=>") && !avant.contains("=>"))
        })
    }

    #[test]
    fn un_motif_d_acte_ne_fabrique_rien() {
        let m = "Acte::ChoixNoter(";
        assert!(motif("        | Acte::ChoixNoter(..)", m));
        assert!(motif("    if let Acte::ChoixNoter(_) = acte {", m));
        assert!(motif("        Acte::ChoixNoter(id) => {", m));
        assert!(motif("    if let Element::Acte(gestes::Acte::ChoixNoter(x)) = e {", m));
        assert!(!motif("        x => Acte::ChoixNoter(id).ligne(),", m));
        assert!(!motif("    let l = Acte::ChoixNoter(id).ligne();", m));
        assert!(!motif("    Acte::ChoixNoter(id).ligne()", m));
        // Dans un `if let`, seulement à gauche du `=` : à droite, il est fabriqué.
        assert!(!motif("    if let Some(l) = Some(Acte::ChoixNoter(id).ligne()) {", m));
        assert!(!motif("    if let Some(l) = Acte::ChoixNoter(id).ligne().get(..) {", m));
        let d = "Defense::CouperPareFeu(";
        assert!(motif(
            "            Defense::CouperPareFeu(_) => \"couper-pare-feu\",",
            d
        ));
        assert!(motif(
            "    Demande::Geste(GesteUnix::Defense(gestes_unix::Defense::CouperPareFeu(_), _))",
            d
        ));
        assert!(!motif(
            "    GesteUnix::Defense(Defense::CouperPareFeu(p), p.note()).ligne()",
            d
        ));
        // Un mot qui n'est pas un acte n'est jamais un motif.
        assert!(!motif("    ligne_noter(id) => 1", "ligne_noter("));
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
