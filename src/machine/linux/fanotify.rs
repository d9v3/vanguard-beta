//! fanotify, par libc : le groupe de permissions du garde (L3) et ses marques. Ce module ouvre le groupe, pose les
//! marques, lit le tampon du noyau et écrit les réponses ; il ne décide rien (pas de verdict, pas de service).
//!
//! Le groupe : FAN_CLOEXEC, FAN_CLASS_CONTENT (demandes de permission), FAN_REPORT_PIDFD (un PIDFD avec chaque
//! événement, pour ne pas confondre un numéro de processus repris ; noyau 5.15) et FAN_ENABLE_AUDIT (les refus notés
//! par l'audit du noyau ; exige CAP_AUDIT_WRITE), chacun retiré s'il est refusé. Jamais FAN_UNLIMITED_QUEUE : sans
//! borne, une rafale de lancements ferait grandir la mémoire du noyau sans fin. Une file pleine (16 384 demandes)
//! laisse donc passer ce qu'elle ne prend plus, sans descripteur à juger après coup : le garde le dit (alerte haute,
//! cache vidé), et le veilleur du compte reste la deuxième ligne. Pas de mode FID : l'identité d'un fichier vient
//! de `fstat` sur le descripteur rendu.
//!
//! Les marques : FAN_MARK_FILESYSTEM, sur les systèmes de fichiers locaux seulement (`lecture::local`), un par
//! major:minor ; les montages faits après (une clé USB) sont suivis par /proc/self/mountinfo (`Montages`, POLLPRI).
//!
//! Quand le groupe se ferme (le garde s'arrête, est tué ou figé puis tué), le noyau laisse passer toutes les demandes
//! en attente.

// Ni débordement ni `as` : chaque taille passée au noyau est convertie par `try_from`.
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

pub(crate) mod lecture;

use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// FAN_OPEN_EXEC_PERM : la demande de permission avant l'ouverture d'un fichier pour l'exécuter (execve, execveat,
/// uselib) : le programme, ou le script lancé directement et son interprète. Pas les bibliothèques (.so) que ld.so ou
/// dlopen ouvrent et projettent en mémoire, ni un programme passé à ld.so, ni un script passé à son interprète : ceux-là
/// sont de simples ouvertures (MODELE-DE-MENACE.md, « Ce que le garde des lancements ne voit pas »).
pub(crate) const OUVERTURE_EXEC_PERM: u64 = 0x0004_0000;
/// FAN_Q_OVERFLOW : la file du groupe a débordé ; des demandes sont passées sans être vues.
pub(crate) const DEBORDEMENT: u64 = 0x0000_4000;
/// La taille du tampon d'une lecture : plusieurs centaines d'événements.
pub(crate) const TAMPON: usize = 64 << 10;

/// Ce que le groupe a pu obtenir du noyau.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Options {
    pub pidfd: bool,
    pub audit: bool,
}

/// Un groupe fanotify de permissions.
#[derive(Debug)]
pub(crate) struct Groupe {
    fd: OwnedFd,
    pub options: Options,
}

/// L'erreur du dernier appel système.
fn erreur() -> io::Error {
    io::Error::last_os_error()
}

/// `fanotify_init` avec ces options en plus des fixes.
fn init(options: Options) -> io::Result<OwnedFd> {
    let mut drapeaux = libc::FAN_CLOEXEC | libc::FAN_CLASS_CONTENT;
    if options.pidfd {
        drapeaux |= libc::FAN_REPORT_PIDFD;
    }
    if options.audit {
        drapeaux |= libc::FAN_ENABLE_AUDIT;
    }
    init_brut(drapeaux)
}

/// `fanotify_init` avec ces drapeaux, le fichier des événements en lecture seule : le seul appel au noyau qui ouvre
/// un groupe, pour le garde comme pour le veilleur.
// FFI de libc : fanotify_init rend un descripteur neuf, pris en charge par OwnedFd ici même.
#[allow(unsafe_code)]
fn init_brut(drapeaux: libc::c_uint) -> io::Result<OwnedFd> {
    let ouverture = libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC;
    let ouverture = libc::c_uint::try_from(ouverture).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: fanotify_init ne lit que ses deux entiers ; le descripteur rendu (≥ 0) est neuf et n'appartient qu'à
    // l'OwnedFd qui le prend, qui le fermera une seule fois.
    unsafe {
        let fd = libc::fanotify_init(drapeaux, ouverture);
        if fd < 0 {
            return Err(erreur());
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Ce qu'une marque désigne : un chemin absolu (le garde : un point de montage), ou l'objet d'un descripteur ouvert
/// (le veilleur : le dossier qu'il a ouvert lui-même, sans que le chemin puisse changer entre-temps).
enum Objet<'a> {
    Chemin(&'a Path),
    Descripteur(BorrowedFd<'a>),
}

/// `fanotify_mark` sur le groupe `fd` : le seul appel au noyau qui pose une marque.
// FFI de libc : fanotify_mark sur le descripteur d'un groupe, avec un chemin en C vivant pendant l'appel, ou un
// descripteur emprunté et un chemin nul.
#[allow(unsafe_code)]
fn marquer_brut(fd: BorrowedFd<'_>, drapeaux: libc::c_uint, masque: u64, objet: &Objet<'_>) -> io::Result<()> {
    let r = match objet {
        Objet::Chemin(point) => {
            let chemin =
                CString::new(point.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            // SAFETY: le descripteur du groupe est emprunté pendant l'appel ; le chemin est une chaîne C terminée par
            // NUL, à nous, vivante pendant l'appel ; AT_FDCWD : le chemin est absolu (un point de montage de
            // mountinfo).
            unsafe { libc::fanotify_mark(fd.as_raw_fd(), drapeaux, masque, libc::AT_FDCWD, chemin.as_ptr()) }
        }
        // SAFETY: les deux descripteurs sont empruntés, ouverts pendant l'appel ; un chemin nul désigne l'objet du
        // second (fanotify_mark(2)), que le noyau ne garde pas.
        Objet::Descripteur(d) => unsafe {
            libc::fanotify_mark(fd.as_raw_fd(), drapeaux, masque, d.as_raw_fd(), std::ptr::null())
        },
    };
    if r < 0 { Err(erreur()) } else { Ok(()) }
}

/// Ce que le groupe de notification du veilleur demande pour chaque dossier marqué : un fichier fermé après écriture
/// (FAN_CLOSE_WRITE, sur les enfants : FAN_EVENT_ON_CHILD), un nom arrivé par renommage (FAN_MOVED_TO).
pub(crate) const NOTIFICATION_FICHIERS: u64 = libc::FAN_CLOSE_WRITE | libc::FAN_MOVED_TO | libc::FAN_EVENT_ON_CHILD;
/// FAN_ONDIR : l'objet de l'événement est un dossier.
pub(crate) const DOSSIER: u64 = libc::FAN_ONDIR;

impl Groupe {
    /// Un groupe d'essai sur un descripteur quelconque (/dev/null) : ses réponses ne vont nulle part.
    #[cfg(test)]
    pub(crate) fn pour_essai(fd: OwnedFd) -> Groupe {
        Groupe {
            fd,
            options: Options {
                pidfd: false,
                audit: false,
            },
        }
    }

    /// Ouvre le groupe, avec le PIDFD et l'audit si le noyau et les droits les donnent (`audit` : CAP_AUDIT_WRITE
    /// est là), sinon sans. Refusé (EPERM sans CAP_SYS_ADMIN, ENOSYS sans fanotify) : l'erreur du dernier essai.
    pub(crate) fn ouvrir(audit: bool) -> io::Result<Groupe> {
        let essais = [
            Options { pidfd: true, audit },
            Options { pidfd: false, audit },
            Options {
                pidfd: true,
                audit: false,
            },
            Options {
                pidfd: false,
                audit: false,
            },
        ];
        let mut derniere = io::Error::from(io::ErrorKind::Unsupported);
        for options in essais {
            if options.audit && !audit {
                continue;
            }
            match init(options) {
                Ok(fd) => return Ok(Groupe { fd, options }),
                // EINVAL : une option inconnue de ce noyau ; EPERM : l'audit sans CAP_AUDIT_WRITE (le suivant essaie
                // sans). Autre chose ne dépend pas des options.
                Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::EPERM)) => derniere = e,
                Err(e) => return Err(e),
            }
        }
        Err(derniere)
    }

    /// Marque le système de fichiers qui porte `point` : chaque exécution d'un fichier qu'il contient passe par le
    /// groupe.
    pub(crate) fn marquer(&self, point: &Path) -> io::Result<()> {
        marquer_brut(
            self.fd.as_fd(),
            libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
            OUVERTURE_EXEC_PERM,
            &Objet::Chemin(point),
        )
    }

    /// Un groupe de NOTIFICATION, sans droits (Linux 5.13 et plus) : FAN_CLASS_NOTIF (aucune permission demandée,
    /// rien n'attend Vanguard), FAN_REPORT_DFID_NAME (le dossier et le nom de l'enfant, la seule forme qu'un compte
    /// ordinaire peut lire : pas de descripteur ouvert par le noyau, FAN_NOFD), file bornée (jamais
    /// FAN_UNLIMITED_QUEUE, refusé sans droits). Le PID de l'événement est 0 sauf quand il vient de ce processus.
    /// Refusé : EPERM (noyau d'avant 5.13, ou sysctl qui le ferme), EINVAL (option inconnue), ENOSYS.
    pub(crate) fn ouvrir_notification() -> io::Result<Groupe> {
        let fd = init_brut(libc::FAN_CLOEXEC | libc::FAN_CLASS_NOTIF | libc::FAN_REPORT_DFID_NAME)?;
        Ok(Groupe {
            fd,
            options: Options {
                pidfd: false,
                audit: false,
            },
        })
    }

    /// Marque le dossier ouvert `dossier` (marque d'inode, la seule permise sans droits) : ses enfants DIRECTS fermés
    /// après écriture ou arrivés par renommage. Pas ses sous-dossiers : une marque d'inode ne descend pas.
    /// FAN_MARK_ONLYDIR : refusé si ce n'est pas un dossier.
    pub(crate) fn marquer_dossier(&self, dossier: BorrowedFd<'_>) -> io::Result<()> {
        marquer_brut(
            self.fd.as_fd(),
            libc::FAN_MARK_ADD | libc::FAN_MARK_INODE | libc::FAN_MARK_ONLYDIR,
            NOTIFICATION_FICHIERS,
            &Objet::Descripteur(dossier),
        )
    }

    /// Retire la marque du dossier ouvert `dossier` (remplacé sous son nom : ses événements ne doivent plus se lire
    /// sous le nouveau). Un dossier supprimé a déjà perdu la sienne : l'erreur se jette.
    pub(crate) fn retirer_dossier(&self, dossier: BorrowedFd<'_>) -> io::Result<()> {
        marquer_brut(
            self.fd.as_fd(),
            libc::FAN_MARK_REMOVE | libc::FAN_MARK_INODE | libc::FAN_MARK_ONLYDIR,
            NOTIFICATION_FICHIERS,
            &Objet::Descripteur(dossier),
        )
    }

    /// Lit ce que le noyau a d'événements (bloque jusqu'à au moins un) : le nombre d'octets écrits dans `tampon`.
    // FFI de libc : read dans un tampon à nous, de sa taille exacte.
    #[allow(unsafe_code)]
    pub(crate) fn lire(&self, tampon: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: `tampon` est à nous, inscriptible, de `tampon.len()` octets, vivant pendant l'appel ; le
            // descripteur du groupe vit autant que `self`.
            let n = unsafe { libc::read(self.fd.as_raw_fd(), tampon.as_mut_ptr().cast(), tampon.len()) };
            if let Ok(n) = usize::try_from(n) {
                return Ok(n.min(tampon.len()));
            }
            let e = erreur();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    /// Attend des événements au plus `delai_ms` : vrai s'il y en a à lire. Le fil lecteur du garde bat ainsi même
    /// quand rien ne se lance.
    pub(crate) fn attendre(&self, delai_ms: i32) -> io::Result<bool> {
        Ok(attendre_groupes(&[self], delai_ms)?.first().copied().unwrap_or(false))
    }

    /// Répond à la demande portée par `fd` : permise ou refusée, notée par l'audit du noyau si `noter` et que le
    /// groupe l'a. ENOENT : déjà répondue (ou le groupe ne la connaît pas).
    // FFI de libc : write d'une `struct fanotify_response` à nous sur le descripteur du groupe.
    #[allow(unsafe_code)]
    pub(crate) fn repondre(&self, fd: BorrowedFd<'_>, permettre: bool, noter: bool) -> io::Result<()> {
        let mut reponse = if permettre { libc::FAN_ALLOW } else { libc::FAN_DENY };
        if noter && self.options.audit {
            reponse |= libc::FAN_AUDIT;
        }
        let r = libc::fanotify_response {
            fd: fd.as_raw_fd(),
            response: reponse,
        };
        let taille = std::mem::size_of::<libc::fanotify_response>();
        // SAFETY: `r` est une structure à nous, de la taille passée, vivante pendant l'appel ; le descripteur du
        // groupe vit autant que `self`.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), (&raw const r).cast(), taille) };
        match usize::try_from(n) {
            Ok(n) if n == taille => Ok(()),
            Ok(_) => Err(io::Error::from(io::ErrorKind::WriteZero)),
            Err(_) => Err(erreur()),
        }
    }
}

/// Attend des événements sur l'un des `groupes` au plus `delai_ms` : pour chacun, vrai s'il y en a à lire. Un groupe
/// en erreur (POLLERR, POLLNVAL) rend l'erreur.
// FFI de libc : poll sur les descripteurs des groupes, un tableau de structures à nous.
#[allow(unsafe_code)]
pub(crate) fn attendre_groupes(groupes: &[&Groupe], delai_ms: i32) -> io::Result<Vec<bool>> {
    let mut p: Vec<libc::pollfd> = groupes
        .iter()
        .map(|g| libc::pollfd {
            fd: g.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let n = libc::nfds_t::try_from(p.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `p` est un tableau à nous de `n` structures pollfd, vivant pendant l'appel ; chaque descripteur vit
    // autant que le groupe emprunté.
    let r = unsafe { libc::poll(p.as_mut_ptr(), n, delai_ms) };
    if r < 0 {
        let e = erreur();
        return if e.kind() == io::ErrorKind::Interrupted {
            Ok(vec![false; p.len()])
        } else {
            Err(e)
        };
    }
    if r > 0 && p.iter().any(|x| (x.revents & (libc::POLLERR | libc::POLLNVAL)) != 0) {
        return Err(io::Error::other("groupe fanotify en erreur"));
    }
    Ok(p.iter().map(|x| r > 0 && (x.revents & libc::POLLIN) != 0).collect())
}

impl AsFd for Groupe {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Prend en charge un descripteur que le noyau vient d'ouvrir dans ce processus (le `fd` ou le `pidfd` d'un
/// événement) : fermé une seule fois, quand l'OwnedFd tombe. `None` pour un nombre négatif (FAN_NOFD).
// FFI : un descripteur ouvert par le noyau pour nous, rendu dans le tampon d'un `read` du groupe.
#[allow(unsafe_code)]
pub(crate) fn prendre(fd: i32) -> Option<OwnedFd> {
    // SAFETY: un `fd` ≥ 0 d'un événement est un descripteur neuf que le noyau a installé dans ce processus pour
    // cet événement ; rien d'autre ne le possède, et chaque événement n'est lu qu'une fois.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// /proc/self/mountinfo, ouvert une fois : `poll` y signale chaque montage et démontage (POLLPRI).
pub(crate) struct Montages {
    fichier: std::fs::File,
}

/// Au plus autant d'octets lus de mountinfo.
const MOUNTINFO_MAX: u64 = 4 << 20;

impl Montages {
    pub(crate) fn ouvrir() -> io::Result<Montages> {
        Ok(Montages {
            fichier: std::fs::File::open("/proc/self/mountinfo")?,
        })
    }

    /// Le texte de mountinfo maintenant (relu du début : c'est aussi ce qui remet le signal de `poll` à zéro).
    pub(crate) fn lire(&mut self) -> io::Result<String> {
        use std::io::{Read, Seek};
        self.fichier.seek(io::SeekFrom::Start(0))?;
        let mut texte = String::new();
        (&self.fichier).take(MOUNTINFO_MAX).read_to_string(&mut texte)?;
        Ok(texte)
    }

    /// Attend un changement des montages au plus `delai_ms` : vrai s'il y en a eu un.
    // FFI de libc : poll sur un descripteur à nous, une seule structure.
    #[allow(unsafe_code)]
    pub(crate) fn attendre(&self, delai_ms: i32) -> io::Result<bool> {
        let mut p = libc::pollfd {
            fd: self.fichier.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        // SAFETY: une seule structure pollfd à nous, vivante pendant l'appel ; le descripteur vit autant que `self`.
        let r = unsafe { libc::poll(&raw mut p, 1, delai_ms) };
        if r < 0 {
            let e = erreur();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(e)
            };
        }
        Ok(r > 0 && (p.revents & (libc::POLLPRI | libc::POLLERR)) != 0)
    }
}

/// Le résultat de marquer les systèmes de fichiers locaux.
#[derive(Debug, Default)]
pub(crate) struct Marques {
    /// Les major:minor marqués.
    pub marques: Vec<(u32, u32)>,
    /// Les points qui n'ont pas pu l'être, avec l'erreur.
    pub echecs: Vec<(String, String)>,
}

impl Marques {
    /// Marque ce que `mountinfo` a de systèmes de fichiers locaux pas encore marqués : rend ceux marqués cette fois.
    pub(crate) fn completer(&mut self, groupe: &Groupe, mountinfo: &str) -> Vec<lecture::Montage> {
        let mut nouveaux = Vec::new();
        for m in lecture::locaux(mountinfo) {
            if self.marques.contains(&m.dev) {
                continue;
            }
            match groupe.marquer(Path::new(&m.point)) {
                Ok(()) => {
                    self.marques.push(m.dev);
                    self.echecs.retain(|(p, _)| *p != m.point);
                    nouveaux.push(m);
                }
                Err(e) => {
                    if !self.echecs.iter().any(|(p, _)| *p == m.point) {
                        self.echecs.push((m.point.clone(), e.to_string()));
                    }
                }
            }
        }
        nouveaux
    }

    /// Oublie les systèmes de fichiers qui ne sont plus montés (le noyau a retiré leur marque avec eux) : remontés,
    /// ils seront marqués de nouveau.
    pub(crate) fn oublier_demontes(&mut self, mountinfo: &str) {
        let montes: Vec<(u32, u32)> = lecture::locaux(mountinfo).iter().map(|m| m.dev).collect();
        self.marques.retain(|d| montes.contains(d));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C7-4 : la description de FAN_OPEN_EXEC_PERM ne promet pas plus que ce que le noyau donne : les bibliothèques
    /// chargées par ld.so ou dlopen n'y passent pas.
    #[test]
    fn la_description_de_l_execution_ne_surevalue_rien() {
        let source = include_str!("fanotify.rs");
        let fin = source.find("pub(crate) const OUVERTURE_EXEC_PERM").unwrap();
        let debut = source[..fin].rfind("\n\n").unwrap();
        let doc = &source[debut..fin];
        assert!(doc.contains("Pas les bibliothèques"), "{doc}");
        assert!(!doc.contains("chargement par"), "{doc}");
    }

    /// Sans CAP_SYS_ADMIN (les essais ne tournent jamais en root sur ce PC), le noyau refuse le groupe de permissions :
    /// l'erreur est rendue, rien ne panique. Le groupe lui-même s'essaie en VM (essais-qemu-l2l3.md).
    #[test]
    fn sans_droits_le_groupe_est_refuse() {
        if crate::socle::euid() == 0 {
            return crate::essais::saute("en root : le groupe s'ouvrirait (essai fait en VM)");
        }
        let e = Groupe::ouvrir(true).unwrap_err();
        assert!(
            matches!(e.raw_os_error(), Some(libc::EPERM | libc::EINVAL | libc::ENOSYS)),
            "{e}"
        );
    }

    #[test]
    fn mountinfo_se_lit_et_se_surveille() {
        let mut m = Montages::ouvrir().unwrap();
        let texte = m.lire().unwrap();
        assert!(texte.lines().count() > 0);
        // Rien ne change en 10 ms (le plus souvent) ; l'appel rend sans erreur.
        let _ = m.attendre(10).unwrap();
        assert_eq!(m.lire().unwrap().lines().next(), texte.lines().next());
    }

    #[test]
    fn un_descripteur_negatif_n_est_pas_pris() {
        assert!(prendre(-1).is_none());
        assert!(prendre(-2).is_none());
    }
}
