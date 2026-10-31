//! Les sources de menaces, consultées par une seule voie : les empreintes de MalwareBazaar (un fichier connu, sans
//! doute possible), les outils d'attaque connus et les signes de COM-PRG-001 (`chasse`). Le blocage, le bilan et le
//! veilleur jugent un programme par les mêmes fonctions : un fichier « certain, à bloquer » pour l'un ne passe plus
//! sans bruit devant l'autre.
//!
//! Seule différence, dite : le veilleur est un service borné à 128 Mo de mémoire, où la liste complète de
//! MalwareBazaar (plus d'un million d'empreintes) ne tient pas. Il juge avec les empreintes des dernières 48 heures,
//! relues toutes les 6 heures ; la surveillance horaire et le bilan gardent la liste complète.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use crate::machine::chasse::{self, EnMarche};
use crate::machine::regles::Os;
use crate::protection::empreintes::{self, Empreintes};
use crate::{tr, trf};

/// Au-delà, un fichier n'est pas haché : un logiciel malveillant connu est presque toujours bien plus petit, et la
/// surveillance horaire ne doit pas relire des gigaoctets.
const TAILLE_MAX: u64 = 256 << 20;
/// Le veilleur hache chaque programme lancé : plus petit, et pas plus de tant de fichiers retenus.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const TAILLE_MAX_VEILLEUR: u64 = 64 << 20;
const RETENUS_MAX: usize = 4096;
/// Le temps laissé à un hachage. Le veilleur, une seule boucle, ne doit jamais rester pris sur un fichier qui ne
/// répond pas (un montage FUSE d'un programme du compte) : il ne lirait plus aucun lancement. Le bilan et le
/// blocage hachent jusqu'à 256 Mio, sur un disque parfois lent.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const DELAI_VEILLEUR: Duration = Duration::from_secs(2);
const DELAI: Duration = Duration::from_secs(30);

/// La liste d'empreintes d'une source.
enum Liste {
    /// Chargée une fois par lancement (`empreintes::connues`, `gardees`).
    Partagee(&'static Empreintes),
    /// Les récentes seulement, à soi (le veilleur).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Propre(Empreintes),
}

/// Les empreintes connues, et ce qui a déjà été haché : un même programme, lancé mille fois, ne l'est qu'une fois
/// tant qu'il ne change pas (taille et date gardées avec).
pub(crate) struct Fichiers {
    liste: Option<Liste>,
    taille_max: u64,
    deja: HashMap<(String, u64, Option<std::time::SystemTime>), bool>,
    delai: Duration,
    hacheur: fn(&Path) -> Option<[u8; 32]>,
    /// Le hachage parti dans son fil et resté sans réponse : tant qu'il n'a pas fini, rien d'autre n'est haché (au
    /// plus un fil pris, jamais une file qui s'allonge).
    en_cours: Option<mpsc::Receiver<Option<[u8; 32]>>>,
    /// Les fichiers qu'on n'a pas pu hacher à temps : non vérifiés, jamais comptés sains.
    non_haches: usize,
}

impl Fichiers {
    /// Pour le bilan et le blocage : la liste chargée une fois par lancement (`None` : aucune, déjà dit).
    pub(crate) fn de(liste: Option<&'static Empreintes>) -> Fichiers {
        Fichiers::avec(liste.map(Liste::Partagee), TAILLE_MAX, DELAI)
    }

    /// Pour le veilleur : les empreintes des dernières 48 heures, relues sur le disque.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn recentes() -> Fichiers {
        Fichiers::avec(
            empreintes::recentes_gardees().map(Liste::Propre),
            TAILLE_MAX_VEILLEUR,
            DELAI_VEILLEUR,
        )
    }

    /// Une liste inventée, pour les tests des autres modules.
    #[cfg(test)]
    pub(crate) fn pour_essai(empreintes: Vec<[u8; 32]>) -> Fichiers {
        Fichiers::avec(
            Some(Liste::Propre(Empreintes::depuis(empreintes))),
            TAILLE_MAX_VEILLEUR,
            DELAI_VEILLEUR,
        )
    }

    fn avec(liste: Option<Liste>, taille_max: u64, delai: Duration) -> Fichiers {
        Fichiers {
            liste,
            taille_max,
            deja: HashMap::new(),
            delai,
            hacheur: hacher_ordinaire,
            en_cours: None,
            non_haches: 0,
        }
    }

    /// Combien de fichiers n'ont pas pu être hachés à temps depuis la dernière fois : le compte repart à zéro.
    pub(crate) fn prendre_non_haches(&mut self) -> usize {
        std::mem::take(&mut self.non_haches)
    }

    /// Hache `chemin` dans un fil à lui, sans l'attendre plus que le délai. `Err` : pas haché (délai dépassé, ou un
    /// hachage d'avant toujours pris) ; `Ok(None)` : illisible.
    fn hacher(&mut self, chemin: &str) -> Result<Option<[u8; 32]>, ()> {
        if let Some(r) = &self.en_cours {
            match r.try_recv() {
                Err(mpsc::TryRecvError::Empty) => return Err(()),
                _ => self.en_cours = None,
            }
        }
        let (envoi, reception) = mpsc::channel();
        let (c, hacheur) = (PathBuf::from(chemin), self.hacheur);
        std::thread::Builder::new()
            .name("vanguard-hachage".into())
            .spawn(move || {
                let _ = envoi.send(hacheur(&c));
            })
            .map_err(|_| ())?;
        reception.recv_timeout(self.delai).map_err(|_| {
            self.en_cours = Some(reception);
        })
    }

    /// L'empreinte de ce fichier est-elle connue ? Seulement un vrai fichier, pas trop gros, haché à temps (sinon
    /// compté dans `non_haches`, et jugé seulement par les autres signes).
    pub(crate) fn connu(&mut self, chemin: &str) -> bool {
        if self.liste.is_none() {
            return false;
        }
        let Ok(m) = std::fs::metadata(chemin) else {
            return false;
        };
        if !m.is_file() || m.len() > self.taille_max {
            return false;
        }
        let cle = (chemin.to_string(), m.len(), m.modified().ok());
        if let Some(&connu) = self.deja.get(&cle) {
            return connu;
        }
        let Ok(h) = self.hacher(chemin) else {
            self.non_haches += 1;
            return false;
        };
        let connu = match (&self.liste, h) {
            (Some(Liste::Partagee(e)), Some(h)) => e.contient(&h),
            (Some(Liste::Propre(e)), Some(h)) => e.contient(&h),
            _ => false,
        };
        if self.deja.len() >= RETENUS_MAX {
            self.deja.clear();
        }
        self.deja.insert(cle, connu);
        connu
    }
}

/// Le hachage d'un fichier ordinaire : ouvert sans attendre (un tube nommé mis à sa place entre la vérification et
/// l'ouverture ne bloque pas), revérifié sur ce qui a été ouvert, puis haché depuis lui.
fn hacher_ordinaire(chemin: &Path) -> Option<[u8; 32]> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let f = options.open(chemin).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    empreintes::sha256_de(f)
}

/// La raison d'une empreinte connue, la même pour tous ceux qui jugent.
pub(crate) fn raison_empreinte() -> &'static str {
    tr!(
        "empreinte SHA-256 connue de MalwareBazaar",
        "SHA-256 fingerprint known to MalwareBazaar"
    )
}

/// Le jugement d'un programme en marche.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Jugement {
    /// Seul le certain se bloque tout seul.
    pub certaine: bool,
    pub raison: String,
    /// Le mot de la ligne de commande qui désigne le script, quand l'outil a été reconnu par un argument.
    pub script: Option<String>,
}

/// Le jugement d'un programme en marche, ou `None`. Certain : un outil d'attaque connu reconnu au programme lui-même
/// (son nom, son fichier, le premier mot de sa ligne), ou une empreinte connue de MalwareBazaar. Douteux : un outil
/// reconnu seulement par un argument d'un interpréteur (`python3 laZagne.py` : le processus est Python), et le reste
/// de COM-PRG-001 (commande qui télécharge ou se cache, dossier où rien ne s'installe).
pub(crate) fn juger_programme(p: &EnMarche, os: Os, connu: &mut impl FnMut(&str) -> bool) -> Option<Jugement> {
    if let Some((raison, origine)) = chasse::offensif(p) {
        let (certaine, script) = match origine {
            chasse::Origine::Programme => (true, None),
            chasse::Origine::Argument(mot) => (false, Some(mot)),
        };
        return Some(Jugement {
            certaine,
            raison: trf!("outil offensif : {raison}", "offensive tool: {raison}"),
            script,
        });
    }
    if p.chemin.as_deref().is_some_and(&mut *connu) {
        return Some(Jugement {
            certaine: true,
            raison: raison_empreinte().to_string(),
            script: None,
        });
    }
    chasse::juger_programme(p, os).map(|s| Jugement {
        certaine: false,
        raison: s.raison.to_string(),
        script: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un fichier connu l'est pour toutes les sources ; changé (autre taille), il est rehaché, pas cru d'avance.
    #[test]
    fn un_fichier_connu_est_rehache_s_il_change() {
        let d = std::env::temp_dir().join(format!("vanguard-sources-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("outil");
        std::fs::write(&f, b"charge malveillante inventee").unwrap();
        let h = empreintes::sha256(&f).unwrap();
        let mut fichiers = Fichiers::pour_essai(vec![h]);
        let chemin = f.to_string_lossy().into_owned();
        assert!(fichiers.connu(&chemin));
        std::fs::write(&f, b"autre contenu, plus long que le premier").unwrap();
        assert!(!fichiers.connu(&chemin));
        assert!(!fichiers.connu("/chemin/qui/n/existe/pas"));
        assert!(!Fichiers::de(None).connu(&chemin));
        let _ = std::fs::remove_dir_all(&d);
    }
    /// Un fichier qui ne répond pas (un montage qui ne rend jamais la main) : connu() rend la main après le délai,
    /// le compte comme non haché, puis ne hache plus rien tant que ce fil reste pris, sans attendre de nouveau.
    #[test]
    fn un_fichier_qui_ne_repond_pas_ne_bloque_pas() {
        let d = std::env::temp_dir().join(format!("vanguard-sources-fige-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("outil");
        std::fs::write(&f, b"contenu invente").unwrap();
        let chemin = f.to_string_lossy().into_owned();
        let mut fichiers = Fichiers::pour_essai(Vec::new());
        fichiers.delai = Duration::from_millis(100);
        fichiers.hacheur = |_| {
            std::thread::sleep(Duration::from_secs(3));
            None
        };
        let debut = std::time::Instant::now();
        assert!(!fichiers.connu(&chemin));
        assert!(!fichiers.connu(&chemin));
        assert!(debut.elapsed() < Duration::from_secs(2), "{:?}", debut.elapsed());
        assert_eq!(fichiers.prendre_non_haches(), 2);
        assert_eq!(fichiers.prendre_non_haches(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un tube nommé à la place du programme (posé entre la vérification et l'ouverture) : le hachage rend la main
    /// tout de suite, sans rien lire.
    #[cfg(unix)]
    #[test]
    fn un_tube_nomme_ne_se_hache_pas() {
        let d = std::env::temp_dir().join(format!("vanguard-sources-tube-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let tube = d.join("outil");
        crate::essais::tube_nomme(&tube).unwrap();
        let debut = std::time::Instant::now();
        assert_eq!(hacher_ordinaire(&tube), None);
        assert!(debut.elapsed() < Duration::from_secs(2));
        let _ = std::fs::remove_dir_all(&d);
    }
}
