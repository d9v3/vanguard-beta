//! « Ce processus est-il ce Vanguard ? » : une seule réponse, pour le bilan des programmes et le blocage
//! (`machine::chasse::de_vanguard`), le veilleur et les programmes sans fichier (`machine::linux::dissimulation`).
//!
//! Sous Windows, comme avant : par le chemin du programme qui tourne. Sous Linux, jamais par un nom ni par un chemin
//! seul, toujours par l'image que le noyau fait tourner :
//! - un nom de memfd ne reconnaît jamais Vanguard : `vanguard` lancé par la fenêtre tourne d'un memfd scellé nommé
//!   `vanguard` (« /memfd:vanguard (deleted) », `image_de_la_fenetre`), mais n'importe quel programme du compte peut
//!   donner ce nom au sien, et le prendre pour soi l'écartait du bilan et le rendait intouchable au blocage
//!   (relecture adverse du lot L2(b), constat A) ;
//! - un chemin ne fait que désigner un candidat (2e ronde, N2) : l'origine vérifiée (`exe_d_origine`), dans un dossier
//!   du compte, ou le chemin d'une copie temporaire effacée peuvent être refaits par un autre programme ;
//! - Vanguard, c'est le même fichier que `/proc/self/exe` (même périphérique, même inode), ou, pour un candidat (un de
//!   ses chemins, ou l'image scellée d'une autre fenêtre), les mêmes octets, lus sous des bornes de coût (`Soi::juger_image`).
//!
//! Ce qu'un Vanguard reconnu a lancé n'est écarté que s'il est de ce processus-ci (`de_vanguard`, N1) : un programme
//! qui lance un enfant puis se remplace par une image de Vanguard (exec) ne cache plus cet enfant.

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

/// Linux : les lectures d'octets permises par seconde (`Soi::juger_image`). Au-delà, la réponse est « pas Vanguard » :
/// le processus est jugé comme un autre (fausse alerte possible, jamais un programme caché). Une image de Vanguard se
/// lit en quelques dizaines de millisecondes ; quatre par seconde bornent ce que des copies de même taille peuvent
/// faire lire.
#[cfg(target_os = "linux")]
const LECTURES_PAR_SECONDE: u32 = 4;
/// Linux : les verdicts gardés au plus, et combien de temps ils sont repris sans relire (`Verdicts`).
#[cfg(target_os = "linux")]
const VERDICTS_MAX: usize = 64;
#[cfg(target_os = "linux")]
const DUREE_D_UN_VERDICT: std::time::Duration = std::time::Duration::from_secs(60);

/// Linux : un fichier tel que le noyau le désigne, sans rien y lire.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Image {
    dev: u64,
    ino: u64,
    taille: u64,
}

/// Linux : un fichier déjà comparé, tant qu'il n'a pas changé : périphérique, inode, taille et date du dernier
/// changement (ctime, que le compte ne peut pas reposer : toute écriture la change).
#[cfg(target_os = "linux")]
type Cle = (u64, u64, u64, i64, i64);

/// Linux : les verdicts par octets déjà rendus (repris une minute au plus), et les lectures de la seconde en cours.
///
/// Des copies de même taille qu'un autre programme du compte fait passer pour Vanguard (nommées « vanguard », de la
/// taille de son image) prennent chacune une lecture et laissent un verdict faux : elles ne doivent ni effacer un
/// verdict vrai (le plus vieux faux part d'abord) ni empêcher de reconfirmer un Vanguard déjà reconnu dont le verdict
/// a expiré (une lecture de plus par seconde lui est réservée). Un Vanguard jamais vu, lancé pendant une telle
/// inondation, peut ne pas être reconnu : il est alors jugé comme un autre (relecture adverse du lot L2(b), 3e ronde,
/// C).
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct Verdicts {
    connus: std::collections::HashMap<Cle, (bool, std::time::Instant)>,
    /// Le début de la seconde en cours, les lectures faites, et si la lecture réservée a été prise.
    seconde: Option<(std::time::Instant, u32, bool)>,
    /// Les lectures faites, pour les essais.
    #[cfg(test)]
    lues: u32,
}

#[cfg(target_os = "linux")]
impl Verdicts {
    /// Le verdict de `cle`, s'il date de moins de `DUREE_D_UN_VERDICT`. Expiré, il reste gardé (`deja_vrai`).
    fn connu(&self, cle: Cle, maintenant: std::time::Instant) -> Option<bool> {
        let (verdict, quand) = *self.connus.get(&cle)?;
        (maintenant.saturating_duration_since(quand) < DUREE_D_UN_VERDICT).then_some(verdict)
    }

    /// `cle` a-t-elle déjà été reconnue comme Vanguard, même il y a plus d'une minute ?
    fn deja_vrai(&self, cle: Cle) -> bool {
        self.connus.get(&cle).is_some_and(|&(verdict, _)| verdict)
    }

    /// Garde le verdict ; plein, la table perd d'abord son plus vieux verdict faux, et un vrai seulement s'il n'y a
    /// que des vrais.
    fn noter(&mut self, cle: Cle, verdict: bool, maintenant: std::time::Instant) {
        if !self.connus.contains_key(&cle) && self.connus.len() >= VERDICTS_MAX {
            let a_perdre = self
                .connus
                .iter()
                .min_by_key(|&(_, &(vrai, quand))| (vrai, quand))
                .map(|(&c, _)| c);
            if let Some(c) = a_perdre {
                self.connus.remove(&c);
            }
        }
        self.connus.insert(cle, (verdict, maintenant));
    }

    /// Une lecture de plus est-elle permise dans la seconde de `maintenant` ? Comptée si oui. `reconfirmer` : pour
    /// un fichier déjà reconnu vrai (`deja_vrai`), qui peut prendre, ses `LECTURES_PAR_SECONDE` épuisées, la lecture
    /// réservée de la seconde.
    fn lecture_permise(&mut self, maintenant: std::time::Instant, reconfirmer: bool) -> bool {
        let (debut, faites, reservee) = match self.seconde {
            Some((debut, faites, reservee))
                if maintenant.saturating_duration_since(debut) < std::time::Duration::from_secs(1) =>
            {
                (debut, faites, reservee)
            }
            _ => (maintenant, 0, false),
        };
        if faites < LECTURES_PAR_SECONDE {
            self.seconde = Some((debut, faites.saturating_add(1), reservee));
        } else if reconfirmer && !reservee {
            self.seconde = Some((debut, faites, true));
        } else {
            self.seconde = Some((debut, faites, reservee));
            return false;
        }
        #[cfg(test)]
        {
            self.lues = self.lues.saturating_add(1);
        }
        true
    }
}

/// Ce Vanguard, tel qu'il se reconnaît dans un autre processus.
pub(crate) struct Soi {
    /// Les chemins de son programme, comparés tels quels (sans casse sous Windows) : celui qui tourne, ou, dans l'image
    /// de la fenêtre, son origine vérifiée. Jamais un `/memfd:…`. Sous Linux, un chemin seul ne reconnaît rien : il
    /// désigne le fichier à comparer (`juger_image`).
    chemins: Vec<String>,
    /// Périphérique, inode et taille de son image (`/proc/self/exe`).
    #[cfg(target_os = "linux")]
    image: Option<Image>,
    /// L'empreinte de son image, lue au premier besoin (`image_qui_tourne`) : seulement devant un fichier candidat de
    /// la même taille.
    #[cfg(target_os = "linux")]
    empreinte: std::sync::OnceLock<Option<String>>,
    #[cfg(target_os = "linux")]
    verdicts: std::sync::Mutex<Verdicts>,
}

impl Soi {
    /// Ce Vanguard-ci, décidé une fois.
    pub(crate) fn courant() -> &'static Soi {
        static SOI: std::sync::OnceLock<Soi> = std::sync::OnceLock::new();
        SOI.get_or_init(|| {
            let lien = std::env::current_exe().ok().map(|c| c.to_string_lossy().into_owned());
            #[cfg(target_os = "linux")]
            {
                let image = Path::new("/proc/self/exe");
                let fenetre = super::image_de_la_fenetre(image);
                let origine = if fenetre { super::exe_d_origine() } else { None };
                Soi::decider(lien.as_deref(), fenetre, origine.as_deref(), identite(image))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Soi {
                    chemins: lien.into_iter().collect(),
                }
            }
        })
    }

    /// Linux : ce que vaut l'image qui tourne. `lien` : son chemin (`current_exe`) ; `fenetre` : c'est l'image de la
    /// fenêtre (`image_de_la_fenetre`), dont le nom n'est jamais cru : seule son `origine` vérifiée compte comme
    /// chemin. Hors de la fenêtre, le chemin qui tourne, sans la marque « (deleted) » d'une copie temporaire effacée,
    /// et jamais un memfd (lancé d'un memfd non scellé, un nom quelconque).
    #[cfg(target_os = "linux")]
    fn decider(lien: Option<&str>, fenetre: bool, origine: Option<&Path>, image: Option<Image>) -> Soi {
        let chemins = if fenetre {
            origine.map(|o| o.to_string_lossy().into_owned()).into_iter().collect()
        } else {
            lien.map(|l| l.strip_suffix(" (deleted)").unwrap_or(l))
                .filter(|l| !l.starts_with("/memfd:"))
                .map(str::to_string)
                .into_iter()
                .collect()
        };
        Soi {
            chemins,
            image,
            empreinte: std::sync::OnceLock::new(),
            verdicts: std::sync::Mutex::default(),
        }
    }

    /// Un Vanguard reconnu à son seul chemin (`chemin_a_moi`) : les essais du bilan, sans processus réel.
    #[cfg(test)]
    pub(crate) fn par_chemin(chemin: &str) -> Soi {
        Soi {
            chemins: vec![chemin.to_string()],
            #[cfg(target_os = "linux")]
            image: None,
            #[cfg(target_os = "linux")]
            empreinte: std::sync::OnceLock::from(None),
            #[cfg(target_os = "linux")]
            verdicts: std::sync::Mutex::default(),
        }
    }

    /// Le fichier de son programme, pour ne jamais le mettre en quarantaine (`blocage::gardes::fichier_intouchable`).
    pub(crate) fn programme(&self) -> Option<&str> {
        self.chemins.first().map(String::as_str)
    }

    /// `chemin` (le programme d'un processus, sans « (deleted) ») est-il un chemin de ce Vanguard ? Sous Linux, un
    /// candidat seulement (`juger_image`).
    pub(crate) fn chemin_a_moi(&self, chemin: Option<&str>) -> bool {
        chemin.is_some_and(|c| {
            self.chemins.iter().any(|m| {
                if cfg!(windows) {
                    m.eq_ignore_ascii_case(c)
                } else {
                    m == c
                }
            })
        })
    }

    /// Le processus `pid`, de programme `chemin` (tel que lu, sans « (deleted) »), est-il ce Vanguard ? Sous Windows,
    /// par son chemin. Sous Linux, jamais par son seul chemin (relecture adverse du lot L2(b), 2e ronde, N2) :
    /// l'origine, dans un dossier du compte, ou le chemin d'une copie temporaire effacée peuvent être refaits ou
    /// remplacés par un autre programme ; c'est son image qui répond (`meme_image`), et `chemin` n'y sert pas.
    pub(crate) fn est_moi(&self, pid: u32, chemin: Option<&str>) -> bool {
        #[cfg(target_os = "linux")]
        {
            let _ = chemin;
            self.meme_image(pid)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            self.chemin_a_moi(chemin)
        }
    }

    /// Linux : l'image du processus `pid` est-elle vraiment celle de ce Vanguard ? Le lien `/proc/<pid>/exe` est
    /// ouvert une seule fois (O_PATH, sans rien lire) et tout se juge sur ce que le noyau y tient (`juger_image`),
    /// jamais sur un chemin relu. Le départ du processus est lu avant et après : un numéro repris entre les deux
    /// (un autre processus) n'est pas reconnu. Illisible ou parti : pas Vanguard.
    #[cfg(target_os = "linux")]
    pub(crate) fn meme_image(&self, pid: u32) -> bool {
        use std::os::unix::fs::OpenOptionsExt;
        let Some(avant) = crate::socle::processus::debut(pid) else {
            return false;
        };
        let Ok(tenu) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(format!("/proc/{pid}/exe"))
        else {
            return false;
        };
        self.juger_image(&tenu) && crate::socle::processus::debut(pid) == Some(avant)
    }

    /// Linux : le fichier `tenu` (ouvert en O_PATH) est-il l'image de ce Vanguard ?
    /// - le même fichier que la sienne (périphérique et inode) : oui, sans rien lire (il tourne, donc ne s'écrit pas) ;
    /// - sinon, seulement un candidat est comparé octet par octet : un fichier à l'un de ses chemins (`chemin_a_moi`,
    ///   son origine dans la fenêtre), ou nommé comme l'image de la fenêtre et scellée comme elle (un autre `vanguard`
    ///   lancé par une autre fenêtre) ;
    /// - d'une autre taille que la sienne : non, sans rien lire ; un verdict déjà rendu pour ce fichier inchangé
    ///   (`Verdicts`) est repris ; au-delà de `LECTURES_PAR_SECONDE`, non (le processus est jugé).
    ///
    /// Le fichier lu est rouvert depuis `tenu` (/proc/self/fd), donc le même, jamais un chemin relu.
    #[cfg(target_os = "linux")]
    fn juger_image(&self, tenu: &std::fs::File) -> bool {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let Ok(m) = tenu.metadata() else {
            return false;
        };
        if !m.file_type().is_file() {
            return false;
        }
        if self.image.is_some_and(|i| (i.dev, i.ino) == (m.dev(), m.ino())) {
            return true;
        }
        let par_le_lien = PathBuf::from(format!("/proc/self/fd/{}", tenu.as_raw_fd()));
        let Ok(nom) = std::fs::read_link(&par_le_lien) else {
            return false;
        };
        let nom = nom.to_string_lossy();
        let fenetre = nom == super::IMAGE_DE_LA_FENETRE;
        if !fenetre && !self.chemin_a_moi(Some(nom.strip_suffix(" (deleted)").unwrap_or(&nom))) {
            return false;
        }
        if self.image.map(|i| i.taille) != Some(m.len()) {
            return false;
        }
        let cle = (m.dev(), m.ino(), m.len(), m.ctime(), m.ctime_nsec());
        let maintenant = std::time::Instant::now();
        {
            let mut verdicts = self.verdicts();
            if let Some(verdict) = verdicts.connu(cle, maintenant) {
                return verdict;
            }
            let reconfirmer = verdicts.deja_vrai(cle);
            if !verdicts.lecture_permise(maintenant, reconfirmer) {
                return false;
            }
        }
        let Ok(f) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&par_le_lien)
        else {
            return false;
        };
        let verdict = (!fenetre || super::scellee_comme_la_fenetre(&f))
            && self
                .empreinte
                .get_or_init(super::image_qui_tourne)
                .as_deref()
                .is_some_and(|soi| crate::programmes_poses::empreinte_du_fichier(&f).is_ok_and(|lu| lu == soi));
        self.verdicts().noter(cle, verdict, maintenant);
        verdict
    }

    #[cfg(target_os = "linux")]
    fn verdicts(&self) -> std::sync::MutexGuard<'_, Verdicts> {
        self.verdicts.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Linux : périphérique, inode et taille du fichier `image` (lien de /proc suivi).
#[cfg(target_os = "linux")]
fn identite(image: &Path) -> Option<Image> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(image).ok().map(|m| Image {
        dev: m.dev(),
        ino: m.ino(),
        taille: m.len(),
    })
}

/// Pour les essais d'ici et de `dissimulation` : de vrais processus, lancés depuis un memfd scellé nommé comme celui
/// de la fenêtre.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod essais {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::path::Path;

    /// Un programme qui attend, aux octets connus : `sleep` du système.
    pub(crate) const ATTEND: &str = "/usr/bin/sleep";

    /// Le nom du lien (`Lien`) par lequel `ATTEND` est lancé. Un `sleep` à programme unique (les coreutils d'Ubuntu
    /// 26.04, uutils, des liens durs d'un seul programme de 11 Mo) choisit l'outil par le nom du fichier lancé (celui
    /// donné à execve, puis `argv[0]`) et s'arrête aussitôt sous un autre (« coreutils: unknown program 'vanguard' ») :
    /// copié en `…/vanguard`, ou lancé par `/proc/<pid>/fd/<n>` sous `argv[0]` « vanguard », il ne tournait pas, et les
    /// essais qui le voulaient en marche échouaient sur la CI. Par un lien de ce nom, il tourne partout ; le noyau
    /// suit le lien, donc l'image du processus (`/proc/<pid>/exe`), seule lue par la reconnaissance, ne change pas.
    pub(crate) const NOM_DE_ATTEND: &str = "sleep";

    /// Un lien symbolique nommé `NOM_DE_ATTEND` vers `cible`, dans un dossier neuf des essais, effacé avec lui.
    pub(crate) struct Lien {
        dossier: std::path::PathBuf,
        pub(crate) chemin: std::path::PathBuf,
    }

    impl Lien {
        /// `None` si le dossier des essais refuse le lien.
        pub(crate) fn vers(cible: &Path) -> Option<Lien> {
            static NUMERO: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NUMERO.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dossier = crate::essais::temporaire().join(format!("vanguard-soi-lien-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dossier);
            std::fs::create_dir_all(&dossier).ok()?;
            let lien = Lien {
                chemin: dossier.join(NOM_DE_ATTEND),
                dossier,
            };
            std::os::unix::fs::symlink(cible, &lien.chemin).ok()?;
            Some(lien)
        }
    }

    impl Drop for Lien {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dossier);
        }
    }

    /// Un processus lancé, arrêté à la fin de l'essai même s'il échoue.
    pub(crate) struct Lance(pub std::process::Child);

    impl Drop for Lance {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `octets` (ceux d'`ATTEND`) lancés depuis un memfd scellé nommé `nom`, comme la fenêtre lance `vanguard` (`arg0`
    /// « vanguard »), par un `Lien` ; `None` si le noyau refuse (memfd non exécutable). Lancé mais arrêté : l'essai
    /// échoue (`arrete_trop_tot`), jamais sauté pour une autre raison que la sienne.
    pub(crate) fn depuis_un_memfd(nom: &str, octets: &[u8], args: &[&str]) -> Option<Lance> {
        let copie = crate::demarrage::memfd::scelle(nom, octets).ok()?;
        let lien = Lien::vers(Path::new(&format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            copie.as_raw_fd()
        )))?;
        let fils = std::process::Command::new(&lien.chemin)
            .arg0("vanguard")
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let mut fils = Lance(fils);
        let vu = attendre_l_image(fils.0.id(), Path::new(&format!("/memfd:{nom} (deleted)")));
        arrete_trop_tot(&mut fils);
        vu.then_some(fils)
    }

    /// Le programme lancé s'est-il arrêté (regardé pendant 100 ms) ? L'essai échoue alors, avec son code de sortie :
    /// un programme qui ne tourne pas ne prouve rien (un « ce n'est pas Vanguard » y serait vrai d'office), et ne doit
    /// pas passer pour un memfd refusé.
    pub(crate) fn arrete_trop_tot(fils: &mut Lance) {
        for _ in 0..5 {
            let fin = fils.0.try_wait().ok().flatten();
            assert!(
                fin.is_none(),
                "le programme lancé s'est arrêté ({fin:?}) : il ne prouve rien"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Le lien de /proc peut encore montrer le programme d'essai juste après le lancement (vu sous charge, avant
    /// l'exec) : attendu jusqu'à `image`, deux secondes au plus.
    pub(crate) fn attendre_l_image(pid: u32, image: &Path) -> bool {
        let lien = format!("/proc/{pid}/exe");
        for _ in 0..100 {
            if std::fs::read_link(&lien).is_ok_and(|l| l == image) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    /// Ce Vanguard dans l'image de la fenêtre, sans origine : son image est ce programme d'essai (périphérique et
    /// inode), mais de la taille de `semblable`, et ses octets `empreinte`.
    pub(crate) fn soi_de_la_fenetre(semblable: &Path, empreinte: String) -> super::Soi {
        let image = super::identite(Path::new("/proc/self/exe")).map(|i| super::Image {
            taille: std::fs::metadata(semblable).map_or(0, |m| m.len()),
            ..i
        });
        let soi = super::Soi::decider(Some("/memfd:vanguard (deleted)"), true, None, image);
        // Une cellule neuve : jamais déjà posée.
        let _ = soi.empreinte.set(Some(empreinte));
        soi
    }

    /// L'empreinte de `chemin`, comme celle de l'image qui tourne.
    pub(crate) fn empreinte(chemin: &Path) -> Option<String> {
        crate::programmes_poses::empreinte_de(chemin).ok()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::essais::{
        ATTEND, Lance, Lien, arrete_trop_tot, attendre_l_image, depuis_un_memfd, empreinte,
        soi_de_la_fenetre as dans_la_fenetre,
    };
    use super::*;
    use crate::machine::chasse::{de_vanguard, en_marche_de};

    /// Le bilan écarte-t-il `pid` (et ce qu'il a lancé) comme étant Vanguard ? Illisible : non (l'essai vérifie
    /// d'abord qu'il se lit).
    fn ecarte(soi: &Soi, pid: u32) -> bool {
        let Some(p) = en_marche_de(pid) else {
            return false;
        };
        assert_eq!(p.chemin.as_deref(), Some("/memfd:vanguard"), "{p:?}");
        let liste = [p];
        // Un `moi` hors de la liste : le fils de ce test n'est pas écarté pour être de sa descendance.
        de_vanguard(&liste, u32::MAX, &|p| soi.est_moi(p.pid, p.chemin.as_deref()), true).contains(&pid)
    }

    /// HAUTE (relecture adverse du lot L2(b), constat A) : dans l'image de la fenêtre, le nom « /memfd:vanguard » ne
    /// reconnaît jamais Vanguard. Un programme quelconque (`sleep`) lancé d'un memfd scellé nommé « vanguard » n'est
    /// ni écarté du bilan ni intouchable ; aux mêmes octets que l'image qui tourne, c'est bien ce Vanguard : écarté.
    #[test]
    fn un_memfd_nomme_vanguard_n_est_pas_vanguard() {
        let Ok(octets) = std::fs::read(ATTEND) else {
            return crate::essais::saute("sleep introuvable");
        };
        let Some(fils) = depuis_un_memfd("vanguard", &octets, &["30"]) else {
            return crate::essais::saute("memfd non exécutable ici");
        };
        let pid = fils.0.id();
        assert!(en_marche_de(pid).is_some(), "le processus lancé se lit");
        let autre = dans_la_fenetre(Path::new(ATTEND), "une autre empreinte".into());
        assert!(
            autre.programme().is_none(),
            "jamais le nom du memfd : {:?}",
            autre.chemins
        );
        assert!(!autre.est_moi(pid, Some("/memfd:vanguard")));
        assert!(
            !ecarte(&autre, pid),
            "un autre programme nommé vanguard, écarté du bilan"
        );
        let identique = dans_la_fenetre(Path::new(ATTEND), empreinte(Path::new(ATTEND)).unwrap());
        assert!(identique.est_moi(pid, Some("/memfd:vanguard")));
        assert!(ecarte(&identique, pid), "un vanguard aux mêmes octets, montré");
        drop(fils);
    }

    /// La variable qui fait attendre `attend_son_arret`.
    const ATTENDRE: &str = "VANGUARD_ESSAI_SOI_ATTEND";

    /// Attend d'être arrêté (30 s au plus) ; rien sans `ATTENDRE`.
    #[test]
    #[ignore = "lancé seulement par la_meme_image_est_vanguard"]
    fn attend_son_arret() {
        if std::env::var_os(ATTENDRE).is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    /// Le même fichier que l'image qui tourne (périphérique et inode) : ce Vanguard, quel que soit son nom ; sans
    /// image connue, un autre processus de ce fichier n'est pas reconnu par elle.
    #[test]
    fn la_meme_image_est_vanguard() {
        let fils = Lance(
            std::process::Command::new("/proc/self/exe")
                .args([
                    "--exact",
                    "protection::cle::soi::tests::attend_son_arret",
                    "--ignored",
                    "--test-threads=1",
                ])
                .env(ATTENDRE, "1")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let pid = fils.0.id();
        let soi = dans_la_fenetre(Path::new(ATTEND), "une autre empreinte".into());
        assert!(soi.meme_image(pid) && soi.est_moi(pid, None));
        assert!(soi.meme_image(std::process::id()));
        let sans_image = Soi {
            image: None,
            ..dans_la_fenetre(Path::new(ATTEND), "une autre empreinte".into())
        };
        assert!(!sans_image.est_moi(pid, None));
        drop(fils);
    }

    /// Les chemins reconnus : dans l'image de la fenêtre, l'origine vérifiée seulement ; ailleurs le programme qui
    /// tourne (sans « (deleted) »), jamais un memfd.
    #[test]
    fn chemins_reconnus() {
        let fenetre = Soi::decider(
            Some("/memfd:vanguard (deleted)"),
            true,
            Some(Path::new("/opt/outils/vanguard")),
            None,
        );
        assert_eq!(fenetre.chemins, ["/opt/outils/vanguard"]);
        assert!(fenetre.chemin_a_moi(Some("/opt/outils/vanguard")));
        assert!(!fenetre.chemin_a_moi(Some("/memfd:vanguard")));
        let sans_origine = Soi::decider(Some("/memfd:vanguard (deleted)"), true, None, None);
        assert_eq!(sans_origine.chemins, Vec::<String>::new());
        let copie = Soi::decider(
            Some("/run/user/1000/vanguard-1-2/vanguard (deleted)"),
            false,
            None,
            None,
        );
        assert_eq!(copie.chemins, ["/run/user/1000/vanguard-1-2/vanguard"]);
        let memfd = Soi::decider(Some("/memfd:vanguard (deleted)"), false, None, None);
        assert!(memfd.chemins.is_empty() && !memfd.chemin_a_moi(Some("/memfd:vanguard")));
    }

    /// Un Vanguard de chemin `chemin`, d'image de taille `taille` et d'empreinte `empreinte`, sans image connue (aucun
    /// processus n'est le même fichier que lui).
    fn soi_a(chemin: &Path, taille: u64, empreinte: Option<String>) -> Soi {
        Soi {
            chemins: vec![chemin.to_string_lossy().into_owned()],
            image: Some(Image { dev: 0, ino: 0, taille }),
            empreinte: std::sync::OnceLock::from(empreinte),
            verdicts: std::sync::Mutex::default(),
        }
    }

    fn dossier(nom: &str) -> std::path::PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-soi-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::create_dir_all(&d);
        d.canonicalize().unwrap_or(d)
    }

    fn tenu(chemin: &Path) -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(chemin)
    }

    /// MOYENNE (relecture adverse du lot L2(b), 2e ronde, N2) : un processus qui tourne d'un des chemins de ce
    /// Vanguard (l'origine, refaite dans un dossier du compte) n'est pas Vanguard pour autant : ses octets décident.
    /// Un autre programme à ce chemin est jugé ; une vraie copie, aux mêmes octets, est reconnue.
    #[test]
    fn le_chemin_seul_ne_reconnait_plus() {
        let d = dossier("chemin");
        let chemin = d.join("vanguard");
        if std::fs::copy(ATTEND, &chemin).is_err() {
            return crate::essais::saute("sleep introuvable");
        }
        let Some(lien) = Lien::vers(&chemin) else {
            return crate::essais::saute("dossier des essais refusé");
        };
        let Ok(fils) = std::process::Command::new(&lien.chemin)
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            return crate::essais::saute("dossier des essais non exécutable");
        };
        let mut fils = Lance(fils);
        let pid = fils.0.id();
        let vu = attendre_l_image(pid, &chemin);
        arrete_trop_tot(&mut fils);
        if !vu {
            return crate::essais::saute("le programme lancé n'a pas pris son image en deux secondes");
        }
        let taille = std::fs::metadata(&chemin).unwrap().len();
        let lu = chemin.to_string_lossy().into_owned();
        let autre = soi_a(&chemin, taille, Some("une autre empreinte".into()));
        assert!(autre.chemin_a_moi(Some(&lu)), "le chemin est bien le sien");
        assert!(
            !autre.est_moi(pid, Some(&lu)),
            "un autre programme au chemin de Vanguard, reconnu par son seul chemin"
        );
        let copie = soi_a(&chemin, taille, empreinte(&chemin));
        assert!(copie.est_moi(pid, Some(&lu)), "une vraie copie, aux mêmes octets");
        // Un processus parti : pas Vanguard.
        drop(fils);
        assert!(!copie.est_moi(pid, Some(&lu)));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// MOYENNE (2e ronde, N3) : les octets ne sont lus que sous des bornes. D'une autre taille : rien n'est lu. Un
    /// fichier déjà comparé et inchangé : le verdict est repris. Changé (même inode, même taille, autres octets) : relu,
    /// et refusé. Au-delà des lectures permises dans la seconde : refusé sans lire (le processus est jugé).
    #[test]
    fn octets_lus_sous_bornes() {
        let d = dossier("bornes");
        let chemin = d.join("vanguard");
        std::fs::write(&chemin, b"programme de vanguard").unwrap();
        let taille = 21;
        let soi = soi_a(&chemin, taille, empreinte(&chemin));
        assert!(soi.juger_image(&tenu(&chemin).unwrap()));
        assert!(soi.juger_image(&tenu(&chemin).unwrap()));
        assert_eq!(soi.verdicts().lues, 1, "un verdict gardé pour un fichier inchangé");
        // Le même fichier réécrit d'autres octets, de même taille : sa date de changement bouge, il est relu.
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&chemin, b"programme d'un autre!").unwrap();
        assert!(!soi.juger_image(&tenu(&chemin).unwrap()), "d'autres octets, reconnus");
        assert_eq!(soi.verdicts().lues, 2);
        // D'une autre taille : refusé sans lire.
        let plus_grand = soi_a(&chemin, taille + 1, empreinte(&chemin));
        assert!(!plus_grand.juger_image(&tenu(&chemin).unwrap()));
        assert_eq!(plus_grand.verdicts().lues, 0);
        // Hors de ses chemins et sans le nom de la fenêtre : jamais lu.
        let ailleurs = d.join("ailleurs");
        std::fs::write(&ailleurs, b"programme d'un autre!").unwrap();
        let soi = soi_a(&chemin, taille, empreinte(&chemin));
        assert!(!soi.juger_image(&tenu(&ailleurs).unwrap()));
        assert_eq!(soi.verdicts().lues, 0);
        // Les lectures de la seconde épuisées : refusé, même aux bons octets.
        soi.verdicts().seconde = Some((std::time::Instant::now(), LECTURES_PAR_SECONDE, false));
        assert!(
            !soi.juger_image(&tenu(&chemin).unwrap()),
            "au-delà de la borne, reconnu"
        );
        assert_eq!(soi.verdicts().lues, 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les lectures permises par seconde : `LECTURES_PAR_SECONDE`, puis plus rien jusqu'à la seconde suivante.
    #[test]
    fn lectures_par_seconde() {
        let mut v = Verdicts::default();
        let t0 = std::time::Instant::now();
        for _ in 0..LECTURES_PAR_SECONDE {
            assert!(v.lecture_permise(t0, false));
        }
        assert!(!v.lecture_permise(t0 + std::time::Duration::from_millis(999), false));
        assert!(v.lecture_permise(t0 + std::time::Duration::from_secs(1), false));
        // Un verdict vieux d'une minute n'est plus repris.
        v.noter((1, 2, 3, 4, 5), true, t0);
        assert_eq!(
            v.connu((1, 2, 3, 4, 5), t0 + std::time::Duration::from_secs(59)),
            Some(true)
        );
        assert_eq!(v.connu((1, 2, 3, 4, 5), t0 + DUREE_D_UN_VERDICT), None);
    }

    /// Relecture adverse du lot L2(b), 3e ronde, C : une inondation de copies de même taille (verdicts faux, une
    /// lecture chacune) n'efface pas un verdict vrai, et un Vanguard déjà reconnu dont le verdict a expiré se
    /// reconfirme par la lecture réservée, une par seconde, même quand les autres sont prises.
    #[test]
    fn une_inondation_ne_fait_pas_oublier_vanguard() {
        let mut v = Verdicts::default();
        let t0 = std::time::Instant::now();
        let ms = |n: u64| t0 + std::time::Duration::from_millis(n);
        let vrai = (1, 1, 9, 0, 0);
        v.noter(vrai, true, t0);
        for i in 0..3 * u64::try_from(VERDICTS_MAX).unwrap() {
            v.noter((2, i, 9, 0, 0), false, ms(i + 1));
        }
        assert!(v.connus.len() <= VERDICTS_MAX);
        assert_eq!(v.connu(vrai, ms(1000)), Some(true), "le verdict vrai effacé");
        // Les faux partent du plus vieux : le dernier noté reste.
        let dernier = 3 * u64::try_from(VERDICTS_MAX).unwrap() - 1;
        assert_eq!(v.connu((2, dernier, 9, 0, 0), ms(1000)), Some(false));
        assert_eq!(v.connu((2, 0, 9, 0, 0), ms(1000)), None);
        // Une minute plus tard : expiré, mais encore su vrai ; les lectures de la seconde prises par l'inondation.
        let plus_tard = t0 + DUREE_D_UN_VERDICT + std::time::Duration::from_secs(1);
        assert_eq!(v.connu(vrai, plus_tard), None);
        assert!(v.deja_vrai(vrai) && !v.deja_vrai((2, dernier, 9, 0, 0)));
        for _ in 0..LECTURES_PAR_SECONDE {
            assert!(v.lecture_permise(plus_tard, false));
        }
        assert!(
            !v.lecture_permise(plus_tard, false),
            "une copie inconnue prend la lecture réservée"
        );
        assert!(v.lecture_permise(plus_tard, true), "Vanguard ne se reconfirme pas");
        assert!(
            !v.lecture_permise(plus_tard, true),
            "deux lectures réservées dans la seconde"
        );
        // Toute la table vraie : le plus vieux vrai part, pour garder la borne.
        let mut w = Verdicts::default();
        for i in 0..=u64::try_from(VERDICTS_MAX).unwrap() {
            w.noter((3, i, 9, 0, 0), true, ms(i));
        }
        assert_eq!(w.connus.len(), VERDICTS_MAX);
        assert!(!w.deja_vrai((3, 0, 9, 0, 0)) && w.deja_vrai((3, 1, 9, 0, 0)));
    }

    /// Le parent de chaque processus, lu dans /proc.
    fn enfants_de(parent: u32) -> Vec<u32> {
        let Ok(entrees) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        entrees
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .filter(|&pid| {
                std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .ok()
                    .and_then(|stat| {
                        let (_, apres) = stat.rsplit_once(')')?;
                        apres.split_whitespace().nth(1)?.parse::<u32>().ok()
                    })
                    == Some(parent)
            })
            .collect()
    }

    /// Un processus arrêté à la fin de l'essai par son numéro (un petit-enfant, que `Child` ne tient pas).
    struct Tue(u32);

    impl Drop for Tue {
        fn drop(&mut self) {
            let _ = std::process::Command::new("kill").arg(self.0.to_string()).status();
        }
    }

    /// HAUTE (relecture adverse du lot L2(b), 2e ronde, N1) : un programme lance un enfant, puis se remplace (exec)
    /// par une image de Vanguard aux vrais octets. Le porteur est bien Vanguard, mais l'enfant né avant n'est pas de
    /// lui : il reste dans le bilan. `sh -c 'sleep 37 & exec <memfd vanguard> 30'`, rejoué pour de vrai ; le memfd est
    /// lancé par un `Lien`, sous lequel un `sleep` à programme unique tourne.
    #[test]
    fn un_porteur_ne_cache_pas_l_enfant_d_avant() {
        use std::os::fd::AsRawFd;
        let Ok(octets) = std::fs::read(ATTEND) else {
            return crate::essais::saute("sleep introuvable");
        };
        let Ok(copie) = crate::demarrage::memfd::scelle("vanguard", &octets) else {
            return crate::essais::saute("memfd refusé ici");
        };
        let image = format!("/proc/{}/fd/{}", std::process::id(), copie.as_raw_fd());
        let Some(lien) = Lien::vers(Path::new(&image)) else {
            return crate::essais::saute("dossier des essais refusé");
        };
        let mut porteur = Lance(
            std::process::Command::new("/bin/sh")
                .args(["-c", "sleep 37 & exec \"$0\" 30"])
                .arg(&lien.chemin)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let pid = porteur.0.id();
        // L'exec fait, et l'enfant d'avant visible.
        let mut enfants = Vec::new();
        let mut fait = false;
        for _ in 0..250 {
            let lien = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap_or_default();
            enfants = enfants_de(pid);
            fait = lien.as_os_str() == "/memfd:vanguard (deleted)";
            if fait && !enfants.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let gardes: Vec<Tue> = enfants.iter().map(|&e| Tue(e)).collect();
        arrete_trop_tot(&mut porteur);
        if !fait {
            return crate::essais::saute("memfd non exécutable ici");
        }
        assert_eq!(enfants.len(), 1, "l'enfant d'avant l'exec : {enfants:?}");
        let enfant = enfants[0];
        let liste: Vec<_> = [pid, enfant].into_iter().filter_map(en_marche_de).collect();
        assert_eq!(liste.len(), 2, "{liste:?}");
        assert_eq!(liste[1].parent, Some(pid));
        let soi = dans_la_fenetre(Path::new(ATTEND), empreinte(Path::new(ATTEND)).unwrap());
        let ecartes = de_vanguard(&liste, u32::MAX, &|p| soi.est_moi(p.pid, p.chemin.as_deref()), true);
        assert!(
            ecartes.contains(&pid),
            "le porteur, aux octets de Vanguard, est reconnu"
        );
        assert!(
            !ecartes.contains(&enfant),
            "l'enfant lancé avant l'exec, caché du bilan : {ecartes:?}"
        );
        drop(gardes);
        drop(porteur);
    }
}
