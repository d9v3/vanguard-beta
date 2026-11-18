//! « Ce processus est-il ce Vanguard ? » : une seule réponse, pour le bilan des programmes et le blocage
//! (`machine::chasse::de_vanguard`), le veilleur et les programmes sans fichier (`machine::linux::dissimulation`).
//!
//! Hors de l'image de la fenêtre, comme avant : par le chemin du programme qui tourne. Un `vanguard` lancé par la
//! fenêtre tourne d'un memfd scellé nommé `vanguard` (« /memfd:vanguard (deleted) », `image_de_la_fenetre`) ; ce nom,
//! n'importe quel programme du compte peut le donner à son propre memfd (`memfd_create("vanguard")`), et le prendre
//! pour soi écartait ce programme et tout ce qu'il lance du bilan « Programmes », et le rendait intouchable au blocage
//! (relecture adverse du lot L2(b), constat A). Un nom de memfd ne reconnaît donc jamais Vanguard. Dans l'image de la
//! fenêtre, Vanguard se reconnaît par l'origine vérifiée (`exe_d_origine`, le fichier aux mêmes octets d'où la fenêtre
//! l'a tiré) ; partout, par l'identité de l'image (le même fichier que `/proc/self/exe` : même périphérique, même
//! inode) ou, pour une image nommée comme celle de la fenêtre, par ses octets (même empreinte que l'image qui tourne :
//! un autre `vanguard` de ce programme, lancé par une autre fenêtre).

#[cfg(target_os = "linux")]
use std::path::Path;

/// Ce Vanguard, tel qu'il se reconnaît dans un autre processus.
pub(crate) struct Soi {
    /// Les chemins de son programme, comparés tels quels (sans casse sous Windows) : celui qui tourne, ou, dans l'image
    /// de la fenêtre, son origine vérifiée. Jamais un `/memfd:…`.
    chemins: Vec<String>,
    /// Périphérique et inode de son image (`/proc/self/exe`).
    #[cfg(target_os = "linux")]
    image: Option<(u64, u64)>,
    /// L'empreinte de son image, lue au premier besoin (`image_qui_tourne`) : seulement devant une image nommée comme
    /// celle de la fenêtre.
    #[cfg(target_os = "linux")]
    empreinte: std::sync::OnceLock<Option<String>>,
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
    fn decider(lien: Option<&str>, fenetre: bool, origine: Option<&Path>, image: Option<(u64, u64)>) -> Soi {
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
        }
    }

    /// Un Vanguard reconnu à son seul chemin : les essais du bilan, sans processus réel.
    #[cfg(test)]
    pub(crate) fn par_chemin(chemin: &str) -> Soi {
        Soi {
            chemins: vec![chemin.to_string()],
            #[cfg(target_os = "linux")]
            image: None,
            #[cfg(target_os = "linux")]
            empreinte: std::sync::OnceLock::from(None),
        }
    }

    /// Le fichier de son programme, pour ne jamais le mettre en quarantaine (`blocage::gardes::fichier_intouchable`).
    pub(crate) fn programme(&self) -> Option<&str> {
        self.chemins.first().map(String::as_str)
    }

    /// `chemin` (le programme d'un processus, sans « (deleted) ») est-il celui de ce Vanguard ?
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

    /// Le processus `pid`, de programme `chemin` (tel que lu, sans « (deleted) »), est-il ce Vanguard ? Son chemin
    /// (`chemin_a_moi`), puis, sous Linux, son image (`meme_image`).
    pub(crate) fn est_moi(&self, pid: u32, chemin: Option<&str>) -> bool {
        if self.chemin_a_moi(chemin) {
            return true;
        }
        #[cfg(target_os = "linux")]
        {
            self.meme_image(pid)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            false
        }
    }

    /// Linux : l'image du processus `pid` est-elle vraiment celle de ce Vanguard ? Le même fichier (périphérique et
    /// inode), ou, nommée comme celle de la fenêtre et scellée (`image_de_la_fenetre`), les mêmes octets. Jamais son
    /// seul nom. Les octets ne sont lus que là : les lire pour chaque processus coûterait trop, et une autre image n'a
    /// rien à gagner à les comparer (son chemin et son inode disent déjà qui elle est). Illisible : pas Vanguard.
    #[cfg(target_os = "linux")]
    pub(crate) fn meme_image(&self, pid: u32) -> bool {
        let exe = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
        if self.image.is_some_and(|soi| identite(&exe) == Some(soi)) {
            return true;
        }
        if !super::image_de_la_fenetre(&exe) {
            return false;
        }
        let Some(soi) = self.empreinte.get_or_init(super::image_qui_tourne) else {
            return false;
        };
        crate::programmes_poses::empreinte_de(&exe).is_ok_and(|lu| lu == *soi)
    }
}

/// Linux : périphérique et inode du fichier `image` (lien de /proc suivi).
#[cfg(target_os = "linux")]
fn identite(image: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(image).ok().map(|m| (m.dev(), m.ino()))
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

    /// Un processus lancé, arrêté à la fin de l'essai même s'il échoue.
    pub(crate) struct Lance(pub std::process::Child);

    impl Drop for Lance {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `octets` lancés depuis un memfd scellé nommé `nom`, comme la fenêtre lance `vanguard` (`arg0` « vanguard ») ;
    /// `None` si le noyau refuse (memfd non exécutable).
    pub(crate) fn depuis_un_memfd(nom: &str, octets: &[u8], args: &[&str]) -> Option<Lance> {
        let copie = crate::demarrage::memfd::scelle(nom, octets).ok()?;
        let fils = std::process::Command::new(format!("/proc/self/fd/{}", copie.as_raw_fd()))
            .arg0("vanguard")
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        Some(Lance(fils))
    }

    /// Ce Vanguard dans l'image de la fenêtre, sans origine : son image est ce programme d'essai, ses octets
    /// `empreinte`.
    pub(crate) fn soi_de_la_fenetre(empreinte: String) -> super::Soi {
        let soi = super::Soi::decider(
            Some("/memfd:vanguard (deleted)"),
            true,
            None,
            super::identite(Path::new("/proc/self/exe")),
        );
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
    use super::essais::{ATTEND, Lance, depuis_un_memfd, empreinte, soi_de_la_fenetre as dans_la_fenetre};
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
        de_vanguard(&liste, u32::MAX, &|p| soi.est_moi(p.pid, p.chemin.as_deref())).contains(&pid)
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
        let autre = dans_la_fenetre("une autre empreinte".into());
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
        let identique = dans_la_fenetre(empreinte(Path::new(ATTEND)).unwrap());
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
        let soi = dans_la_fenetre("une autre empreinte".into());
        assert!(soi.meme_image(pid) && soi.est_moi(pid, None));
        assert!(soi.meme_image(std::process::id()));
        let sans_image = Soi {
            image: None,
            ..dans_la_fenetre("une autre empreinte".into())
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
}
