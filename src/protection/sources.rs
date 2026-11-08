//! Les sources de menaces, consultées par une seule voie : les empreintes de MalwareBazaar (un fichier connu, sans
//! doute possible), les outils d'attaque connus et les signes de COM-PRG-001 (`chasse`). Le blocage, le bilan et le
//! veilleur jugent un programme par les mêmes fonctions : un fichier « certain, à bloquer » pour l'un ne passe plus
//! sans bruit devant l'autre.
//!
//! Seule différence, dite : le veilleur est un service borné à 128 Mo de mémoire, où la liste complète de
//! MalwareBazaar (plus d'un million d'empreintes) ne tient pas. Il juge avec les empreintes des dernières 48 heures,
//! relues toutes les 6 heures ; la surveillance horaire et le bilan gardent la liste complète.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

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
#[cfg(any(target_os = "linux", test))]
const TAILLE_MAX_VEILLEUR: u64 = 64 << 20;
const RETENUS_MAX: usize = 4096;
/// Le temps laissé à un hachage. Le veilleur, une seule boucle, ne doit jamais rester pris sur un fichier qui ne
/// répond pas (un montage FUSE d'un programme du compte) : il ne lirait plus aucun lancement. Le bilan et le
/// blocage hachent jusqu'à 256 Mio, sur un disque parfois lent.
#[cfg(any(target_os = "linux", test))]
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

/// Le verdict d'un programme lancé, et son empreinte (`None` : illisible).
#[cfg(target_os = "linux")]
type JugeLance = (Option<Certitude>, Option<[u8; 32]>);

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
    en_cours: Option<mpsc::Receiver<Option<Hache>>>,
    /// Les programmes lancés déjà jugés, par leur inode (`juger_tenu_avec_empreinte`) : appareil, inode, taille, date de
    /// modification et de changement (en secondes et nanosecondes). Un fichier réécrit change de date de changement,
    /// même remise à l'ancienne date de modification : il est rehaché.
    /// Avec le verdict, l'empreinte (`None` : illisible) : la surveillance rapprochée et la confiance accordée à un
    /// certain s'y reconnaissent (`juger_tenu_avec_empreinte`).
    #[cfg(target_os = "linux")]
    lances: HashMap<[i64; 7], JugeLance>,
    /// Les fichiers qu'on n'a pas pu hacher à temps : non vérifiés, jamais comptés sains.
    non_haches: usize,
}

impl Fichiers {
    /// Pour le bilan et le blocage : la liste chargée une fois par lancement (`None` : aucune, déjà dit).
    pub(crate) fn de(liste: Option<&'static Empreintes>) -> Fichiers {
        Fichiers::avec(liste.map(Liste::Partagee), TAILLE_MAX, DELAI)
    }

    /// Pour le veilleur : les empreintes des dernières 48 heures, relues sur le disque.
    #[cfg(target_os = "linux")]
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
            #[cfg(target_os = "linux")]
            lances: HashMap::new(),
        }
    }

    /// Combien de fichiers n'ont pas pu être hachés à temps depuis la dernière fois : le compte repart à zéro.
    pub(crate) fn prendre_non_haches(&mut self) -> usize {
        std::mem::take(&mut self.non_haches)
    }

    /// Fait `travail` (un hachage) dans un fil à lui, sans l'attendre plus que le délai. `Err` : pas haché (délai
    /// dépassé, ou un hachage d'avant toujours pris) ; `Ok(None)` : illisible.
    fn hacher(&mut self, travail: impl FnOnce() -> Option<Hache> + Send + 'static) -> Result<Option<Hache>, ()> {
        if let Some(r) = &self.en_cours {
            match r.try_recv() {
                Err(mpsc::TryRecvError::Empty) => return Err(()),
                _ => self.en_cours = None,
            }
        }
        let (envoi, reception) = mpsc::channel();
        std::thread::Builder::new()
            .name("vanguard-hachage".into())
            .spawn(move || {
                let _ = envoi.send(travail());
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
        let (c, hacheur) = (PathBuf::from(chemin), self.hacheur);
        let Ok(h) = self.hacher(move || {
            hacheur(&c).map(|empreinte| Hache {
                empreinte,
                essai: false,
            })
        }) else {
            self.non_haches = self.non_haches.saturating_add(1);
            return false;
        };
        let connu = h.is_some_and(|h| self.contient(&h.empreinte));
        if self.deja.len() >= RETENUS_MAX {
            self.deja.clear();
        }
        self.deja.insert(cle, connu);
        connu
    }

    fn contient(&self, empreinte: &[u8; 32]) -> bool {
        match &self.liste {
            Some(Liste::Partagee(e)) => e.contient(empreinte),
            Some(Liste::Propre(e)) => e.contient(empreinte),
            None => false,
        }
    }

    /// Le programme qu'un processus a VRAIMENT lancé est-il certain ? Haché depuis son inode tenu (`Tenu`), jamais
    /// depuis le chemin relu : un programme qui s'efface ou se réécrit après son lancement est jugé sur ce qui tourne,
    /// et un fichier remis à sa place ne fait jamais juger (ni arrêter) un autre programme. Certain : son empreinte
    /// est connue de MalwareBazaar, ou c'est un exécutable (ELF ou PE) qui porte la marque d'essai EICAR. Jugé sans
    /// liste aussi (la marque d'essai n'en dépend pas) ; un fichier pas haché à temps est compté non haché. Rend
    /// aussi l'empreinte SHA-256 de l'inode lancé (`None` : pas hachée, trop grosse ou illisible).
    #[cfg(target_os = "linux")]
    pub(crate) fn juger_tenu_avec_empreinte(
        &mut self,
        tenu: &crate::socle::processus::Tenu,
    ) -> (Option<Certitude>, Option<[u8; 32]>) {
        use std::os::unix::fs::MetadataExt;
        let Ok(m) = tenu.exe().metadata() else {
            return (None, None);
        };
        if !m.is_file() || m.len() > self.taille_max {
            return (None, None);
        }
        let cle = [
            i64::try_from(m.dev()).unwrap_or(-1),
            i64::try_from(m.ino()).unwrap_or(-1),
            i64::try_from(m.size()).unwrap_or(-1),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        ];
        if let Some(&c) = self.lances.get(&cle) {
            return c;
        }
        // Un double du descripteur, à lui seul : le fil peut survivre au délai et au `Tenu`, et ne doit jamais lire
        // un numéro de descripteur fermé puis repris par autre chose.
        let Ok(exe) = tenu.exe().try_clone() else {
            return (None, None);
        };
        let taille_max = self.taille_max;
        let Ok(h) = self.hacher(move || hacher_lance(&exe, taille_max)) else {
            self.non_haches = self.non_haches.saturating_add(1);
            return (None, None);
        };
        let certitude = h.as_ref().and_then(|h| {
            if self.contient(&h.empreinte) {
                Some(Certitude::Empreinte)
            } else {
                h.essai.then_some(Certitude::Essai)
            }
        });
        let verdict = (certitude, h.map(|h| h.empreinte));
        if self.lances.len() >= RETENUS_MAX {
            self.lances.clear();
        }
        self.lances.insert(cle, verdict);
        verdict
    }

    /// Le verdict seul (essais).
    #[cfg(all(target_os = "linux", test))]
    pub(crate) fn juger_tenu(&mut self, tenu: &crate::socle::processus::Tenu) -> Option<Certitude> {
        self.juger_tenu_avec_empreinte(tenu).0
    }
}

/// Ce que donne un hachage : l'empreinte, et (programme lancé seulement) si c'est un exécutable marqué pour l'essai.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Hache {
    empreinte: [u8; 32],
    essai: bool,
}

/// Pourquoi un programme lancé est certain (P10, P23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum Certitude {
    /// Son empreinte SHA-256 est connue de MalwareBazaar.
    Empreinte,
    /// Un exécutable qui porte la marque d'essai EICAR : jamais un programme légitime, et rien de dangereux.
    Essai,
}

impl Certitude {
    /// La raison, dite à la personne et gardée avec la quarantaine.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn raison(self) -> &'static str {
        match self {
            Certitude::Empreinte => raison_empreinte(),
            Certitude::Essai => tr!(
                "certain (essai) : marque d'essai EICAR dans un exécutable",
                "certain (test): EICAR test mark inside an executable"
            ),
        }
    }
}

/// La marque d'essai EICAR, masquée octet par octet : ni le dépôt ni le binaire compilé ne la contiennent d'un bloc
/// (un antivirus qui les lirait mettrait Vanguard en quarantaine). Démasquée à l'exécution par une clé que le
/// compilateur ne peut pas suivre (`black_box`) : il ne peut pas la ranger en clair parmi les constantes.
const MARQUE_MASQUEE: [u8; 68] = [
    0x02, 0x6f, 0x15, 0x7b, 0x0a, 0x7f, 0x1a, 0x1b, 0x0a, 0x01, 0x6e, 0x06, 0x0a, 0x00, 0x02, 0x6f, 0x6e, 0x72, 0x0a,
    0x04, 0x73, 0x6d, 0x19, 0x19, 0x73, 0x6d, 0x27, 0x7e, 0x1f, 0x13, 0x19, 0x1b, 0x08, 0x77, 0x09, 0x0e, 0x1b, 0x14,
    0x1e, 0x1b, 0x08, 0x1e, 0x77, 0x1b, 0x14, 0x0e, 0x13, 0x0c, 0x13, 0x08, 0x0f, 0x09, 0x77, 0x0e, 0x1f, 0x09, 0x0e,
    0x77, 0x1c, 0x13, 0x16, 0x1f, 0x7b, 0x7e, 0x12, 0x71, 0x12, 0x70,
];

/// La marque d'essai EICAR, démasquée.
pub(crate) fn marque_d_essai() -> Vec<u8> {
    let cle = std::hint::black_box(0x5Au8);
    MARQUE_MASQUEE.iter().map(|o| o ^ cle).collect()
}

/// Le début d'un exécutable ELF, ou PE (« MZ ») : la marque d'essai n'est certaine que là (P23), jamais dans un
/// texte (un document qui cite la chaîne, une page qui l'explique).
fn tete_executable(tete: &[u8]) -> bool {
    tete.starts_with(b"\x7fELF") || tete.starts_with(b"MZ")
}

/// Un contenu déjà en mémoire (une partie lue par le moteur commun) : un exécutable ELF ou PE qui porte la marque
/// d'essai, « certain (essai) » (P23). Le même jugement que le garde des lancements (`Guetteur`, qui le fait en
/// hachant), une recherche d'octets sans lecteur de format.
pub(crate) fn porte_la_marque_d_essai(octets: &[u8]) -> bool {
    if !tete_executable(octets) {
        return false;
    }
    let marque = marque_d_essai();
    octets.windows(marque.len()).any(|f| f == marque.as_slice())
}

/// Lit ce qui est haché et y cherche la marque d'essai au passage, sans relire le fichier : une fenêtre glissante
/// garde la fin du morceau d'avant (la marque peut être coupée entre deux lectures).
#[cfg(any(target_os = "linux", test))]
struct Guetteur<R> {
    dedans: R,
    marque: Vec<u8>,
    /// Les derniers octets lus (au plus la marque moins un), puis le morceau suivant à leur suite.
    fenetre: Vec<u8>,
    /// Les quatre premiers octets du fichier : ELF ou PE ?
    tete: Vec<u8>,
    trouvee: bool,
}

#[cfg(any(target_os = "linux", test))]
impl<R: std::io::Read> Guetteur<R> {
    fn new(dedans: R) -> Guetteur<R> {
        Guetteur {
            dedans,
            marque: marque_d_essai(),
            fenetre: Vec::new(),
            tete: Vec::new(),
            trouvee: false,
        }
    }

    /// Un exécutable (ELF, ou PE qui commence par « MZ ») qui porte la marque.
    fn marque(&self) -> bool {
        self.trouvee && tete_executable(&self.tete)
    }
}

#[cfg(any(target_os = "linux", test))]
impl<R: std::io::Read> std::io::Read for Guetteur<R> {
    fn read(&mut self, tampon: &mut [u8]) -> std::io::Result<usize> {
        let n = self.dedans.read(tampon)?;
        let lu = tampon.get(..n).unwrap_or_default();
        if self.tete.len() < 4 {
            let manque = 4usize.saturating_sub(self.tete.len());
            self.tete.extend(lu.iter().take(manque));
        }
        if !self.trouvee {
            self.fenetre.extend_from_slice(lu);
            self.trouvee = self
                .fenetre
                .windows(self.marque.len())
                .any(|f| f == self.marque.as_slice());
            let garder = self.marque.len().saturating_sub(1);
            let retirer = self.fenetre.len().saturating_sub(garder);
            self.fenetre.drain(..retirer);
        }
        Ok(n)
    }
}

/// Le SHA-256 de ce qui est lu, et la marque d'essai EICAR dans un exécutable (ELF ou PE) : le point d'entrée du garde
/// des lancements (Défense L3), qui « certain (essai) » comme `hacher_lance`. Une recherche d'octets, pas un lecteur de
/// format (P22).
#[cfg(target_os = "linux")]
pub(crate) fn hacher_et_guetter(lu: impl std::io::Read) -> Option<([u8; 32], bool)> {
    let mut g = Guetteur::new(lu);
    let empreinte = empreintes::sha256_de(&mut g)?;
    Some((empreinte, g.marque()))
}

/// Le hachage d'un programme lancé, depuis son lien `/proc/<pid>/exe` tenu en O_PATH : rouvert en lecture par
/// `/proc/self/fd/<n>` (le même inode, même effacé), sans attendre (un tube ne bloque pas), revérifié (un fichier
/// ordinaire, le même inode, pas trop gros), puis haché en y cherchant la marque d'essai.
#[cfg(target_os = "linux")]
fn hacher_lance(exe: &std::fs::File, taille_max: u64) -> Option<Hache> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let lu = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(format!("/proc/self/fd/{}", exe.as_raw_fd()))
        .ok()?;
    let (m, tenu) = (lu.metadata().ok()?, exe.metadata().ok()?);
    if !m.is_file() || (m.dev(), m.ino()) != (tenu.dev(), tenu.ino()) || m.len() > taille_max {
        return None;
    }
    let mut g = Guetteur::new(lu.take(taille_max));
    let empreinte = empreintes::sha256_de(&mut g)?;
    Some(Hache {
        empreinte,
        essai: g.marque(),
    })
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
    /// Le type d'alerte, qui choisit la suite du blocage ; `None` : douteux sans suite propre (COM-PRG-001).
    pub type_alerte: Option<crate::protection::blocage::suites::Type>,
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
            type_alerte: Some(crate::protection::blocage::suites::Type::OutilDAttaque),
        });
    }
    if p.chemin.as_deref().is_some_and(&mut *connu) {
        return Some(Jugement {
            certaine: true,
            raison: raison_empreinte().to_string(),
            script: None,
            type_alerte: Some(crate::protection::blocage::suites::Type::MalwareConnu),
        });
    }
    chasse::juger_programme(p, os).map(|s| Jugement {
        certaine: false,
        raison: s.raison.to_string(),
        script: None,
        type_alerte: None,
    })
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Un fichier connu l'est pour toutes les sources ; changé (autre taille), il est rehaché, pas cru d'avance.
    #[test]
    fn un_fichier_connu_est_rehache_s_il_change() {
        let d = crate::essais::temporaire().join(format!("vanguard-sources-{}", std::process::id()));
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
        let d = crate::essais::temporaire().join(format!("vanguard-sources-fige-{}", std::process::id()));
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

    /// La marque démasquée est bien la chaîne d'essai EICAR : son empreinte publiée (la chaîne n'est écrite nulle part).
    #[test]
    fn la_marque_d_essai_est_eicar() {
        let m = marque_d_essai();
        assert_eq!(m.len(), 68);
        assert_eq!(
            empreintes::hex(&empreintes::sha256_de(m.as_slice()).unwrap()),
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
    }

    /// Aucun source ne garde un morceau de la chaîne d'essai (12 octets ou plus) : des morceaux littéraux finissent bout
    /// à bout dans le programme compilé, qu'un antivirus met alors en quarantaine (P23).
    #[test]
    fn aucun_source_n_a_de_morceau_de_la_marque() {
        let m = marque_d_essai();
        let mut a_lire = vec![
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests"),
        ];
        let mut lus = 0;
        while let Some(d) = a_lire.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    a_lire.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let contenu = std::fs::read(&p).unwrap();
                    lus += 1;
                    for morceau in m.windows(12) {
                        assert!(
                            !contenu.windows(12).any(|w| w == morceau),
                            "{} garde un morceau de la marque d'essai",
                            p.display()
                        );
                    }
                }
            }
        }
        assert!(lus > 100, "{lus} sources lus");
    }

    /// Un lecteur qui rend peu à la fois : la marque, coupée entre deux lectures, est trouvée quand même.
    struct Goutte<'a>(&'a [u8], usize);

    impl std::io::Read for Goutte<'_> {
        fn read(&mut self, tampon: &mut [u8]) -> std::io::Result<usize> {
            let n = self.1.min(tampon.len()).min(self.0.len());
            tampon[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    fn guetter(octets: &[u8], morceau: usize) -> (bool, [u8; 32]) {
        let mut g = Guetteur::new(Goutte(octets, morceau));
        let e = empreintes::sha256_de(&mut g).unwrap();
        (g.marque(), e)
    }

    /// Certain (essai) : la marque dans un exécutable ELF ou PE, où qu'elle soit, même coupée entre deux lectures ;
    /// jamais dans un fichier qui n'est pas un exécutable, ni une marque incomplète. L'empreinte est la même que sans
    /// le guetteur.
    #[test]
    fn la_marque_d_essai_dans_un_executable_seulement() {
        let m = marque_d_essai();
        for tete in [&b"\x7fELF\x02\x01"[..], b"MZ\x90\x00"] {
            for morceau in [1, 7, 67, 68, 4096] {
                let octets = [tete, &[0u8; 300][..], &m, b"suite"].concat();
                let (marque, e) = guetter(&octets, morceau);
                assert!(marque, "{morceau}");
                assert_eq!(e, empreintes::sha256_de(octets.as_slice()).unwrap());
            }
            let incomplete = [tete, &m[..67], b"!"].concat();
            assert!(!guetter(&incomplete, 5).0);
        }
        // La marque seule (le fichier d'essai habituel), ou dans un texte : pas un exécutable, pas certain ici.
        assert!(!guetter(&m, 4096).0);
        assert!(!guetter(&[&b"#!/bin/sh\n"[..], &m].concat(), 3).0);
    }

    /// Une copie jetable d'un vrai programme du système (`sleep`), suivie de `en_plus`, rendue exécutable :
    /// `d/<nom>/sleep`.
    #[cfg(target_os = "linux")]
    pub(crate) fn programme_jetable(d: &Path, nom: &str, en_plus: &[u8]) -> Option<PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let source = ["/usr/bin/sleep", "/bin/sleep"]
            .into_iter()
            .map(Path::new)
            .find(|c| c.is_file())?;
        // Le fichier garde le nom « sleep », dans un dossier à son nom : un sleep à plusieurs usages (uutils, celui
        // d'Ubuntu depuis 25.10) choisit quoi faire d'après le nom sous lequel il est lancé, et sortirait aussitôt
        // sous un autre nom ; l'essai qui doit le garder en vie le verrait parti.
        let dossier = d.join(nom);
        std::fs::create_dir_all(&dossier).ok()?;
        let f = dossier.join("sleep");
        let mut octets = std::fs::read(source).ok()?;
        octets.extend_from_slice(en_plus);
        std::fs::write(&f, octets).ok()?;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o700)).ok()?;
        Some(f)
    }

    /// Lance `f` avec « 30 » (il dort). Un autre essai qui lance un programme au même moment peut garder, le temps de
    /// son exec, une copie du descripteur d'écriture de `f` : le noyau refuse alors de lancer `f` (ETXTBSY), un
    /// instant ; on réessaie.
    #[cfg(target_os = "linux")]
    pub(crate) fn lancer_jetable(f: &Path) -> std::process::Child {
        for _ in 0..50 {
            match std::process::Command::new(f).arg("30").spawn() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => std::thread::sleep(Duration::from_millis(20)),
                r => return r.unwrap(),
            }
        }
        panic!("{} ne se lance pas (ETXTBSY)", f.display());
    }

    /// Tient le processus `pid` une fois qu'il tourne `f` : avant la fin de son exec, /proc/<pid>/exe désigne encore
    /// le programme qui l'a lancé.
    #[cfg(target_os = "linux")]
    pub(crate) fn tenir_quand_lance(pid: u32, f: &Path) -> Option<crate::socle::processus::Tenu> {
        use std::os::unix::fs::MetadataExt;
        let voulu = std::fs::metadata(f).ok().map(|m| (m.dev(), m.ino()))?;
        for _ in 0..200 {
            if let Some(t) = crate::socle::processus::tenir(pid)
                && t.exe().metadata().ok().map(|m| (m.dev(), m.ino())) == Some(voulu)
            {
                return Some(t);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    /// Lance `f` (qui dort), le tient, et le juge ; l'enfant est toujours tué et attendu.
    #[cfg(target_os = "linux")]
    fn juger_lance_de(fichiers: &mut Fichiers, f: &Path, apres: impl FnOnce()) -> Option<Certitude> {
        let mut enfant = lancer_jetable(f);
        let tenu = tenir_quand_lance(enfant.id(), f);
        apres();
        let r = tenu.as_ref().and_then(|t| fichiers.juger_tenu(t));
        let _ = enfant.kill();
        let _ = enfant.wait();
        assert!(tenu.is_some(), "le programme lancé ne se tient pas");
        r
    }

    /// Le programme lancé est jugé sur l'inode qui tourne : connu par son empreinte, marqué pour l'essai, ou rien ;
    /// et un fichier mis à sa place après le lancement (effacé, puis un autre au même chemin) ne change pas le
    /// verdict, dans un sens comme dans l'autre.
    #[cfg(target_os = "linux")]
    #[test]
    fn le_programme_lance_est_juge_sur_son_inode() {
        let d = crate::essais::temporaire().join(format!("vanguard-sources-lance-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let Some(connu) = programme_jetable(&d, "connu", b"empreinte inventee") else {
            let _ = std::fs::remove_dir_all(&d);
            return crate::essais::saute("sleep absent");
        };
        let marque = programme_jetable(&d, "marque", &marque_d_essai()).unwrap();
        let sain = programme_jetable(&d, "sain", b"rien").unwrap();
        let h = empreintes::sha256(&connu).unwrap();
        let mut fichiers = Fichiers::pour_essai(vec![h]);
        assert_eq!(juger_lance_de(&mut fichiers, &connu, || {}), Some(Certitude::Empreinte));
        assert_eq!(juger_lance_de(&mut fichiers, &marque, || {}), Some(Certitude::Essai));
        assert_eq!(juger_lance_de(&mut fichiers, &sain, || {}), None);
        // Sans liste : la marque d'essai reste certaine, l'empreinte ne se juge plus.
        let mut sans_liste = Fichiers::de(None);
        assert_eq!(juger_lance_de(&mut sans_liste, &marque, || {}), Some(Certitude::Essai));
        assert_eq!(juger_lance_de(&mut sans_liste, &connu, || {}), None);

        // Un programme sain lancé, puis un fichier connu mis à son chemin : il reste sain.
        let lance_sain = programme_jetable(&d, "lance-sain", b"autre chose").unwrap();
        let remplace = || {
            let _ = std::fs::remove_file(&lance_sain);
            let _ = std::fs::copy(&connu, &lance_sain);
        };
        let mut fichiers = Fichiers::pour_essai(vec![h]);
        assert_eq!(juger_lance_de(&mut fichiers, &lance_sain, remplace), None);
        assert!(
            fichiers.connu(&lance_sain.to_string_lossy()),
            "le chemin, lui, désigne le connu"
        );
        // Un programme connu lancé, effacé puis remplacé par un fichier sain : il reste connu.
        let lance_connu = programme_jetable(&d, "lance-connu", b"empreinte inventee").unwrap();
        let mut fichiers = Fichiers::pour_essai(vec![h]);
        let efface = || {
            let _ = std::fs::remove_file(&lance_connu);
            let _ = std::fs::copy(&sain, &lance_connu);
        };
        assert_eq!(
            juger_lance_de(&mut fichiers, &lance_connu, efface),
            Some(Certitude::Empreinte)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un tube nommé à la place du programme (posé entre la vérification et l'ouverture) : le hachage rend la main
    /// tout de suite, sans rien lire.
    #[cfg(unix)]
    #[test]
    fn un_tube_nomme_ne_se_hache_pas() {
        let d = crate::essais::temporaire().join(format!("vanguard-sources-tube-{}", std::process::id()));
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
