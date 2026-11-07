//! fanotify, par libc : le groupe de permissions du garde (L3) et ses marques. Ce module ouvre le groupe, pose les
//! marques, lit le tampon du noyau et écrit les réponses ; il ne décide rien (pas de verdict, pas de service).
//!
//! Le groupe : FAN_CLOEXEC, FAN_CLASS_CONTENT (demandes de permission), FAN_REPORT_PIDFD (un PIDFD avec chaque
//! événement, pour ne pas confondre un numéro de processus repris ; noyau 5.15) et FAN_ENABLE_AUDIT (les refus notés
//! par l'audit du noyau ; exige CAP_AUDIT_WRITE), chacun retiré s'il est refusé. Jamais FAN_UNLIMITED_QUEUE : une file
//! pleine laisse passer (le veilleur du compte est la deuxième ligne). Pas de mode FID : l'identité d'un fichier vient
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

/// FAN_OPEN_EXEC_PERM : la demande de permission avant chaque exécution d'un fichier (et chargement par l'éditeur de
/// liens dynamiques).
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
// FFI de libc : fanotify_init rend un descripteur neuf, pris en charge par OwnedFd ici même.
#[allow(unsafe_code)]
fn init(options: Options) -> io::Result<OwnedFd> {
    let mut drapeaux = libc::FAN_CLOEXEC | libc::FAN_CLASS_CONTENT;
    if options.pidfd {
        drapeaux |= libc::FAN_REPORT_PIDFD;
    }
    if options.audit {
        drapeaux |= libc::FAN_ENABLE_AUDIT;
    }
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

impl Groupe {
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
    // FFI de libc : fanotify_mark sur le descripteur du groupe, avec un chemin en C vivant pendant l'appel.
    #[allow(unsafe_code)]
    pub(crate) fn marquer(&self, point: &Path) -> io::Result<()> {
        let chemin =
            CString::new(point.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let drapeaux = libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM;
        // SAFETY: le descripteur du groupe vit autant que `self` ; le chemin est une chaîne C terminée par NUL, à nous,
        // vivante pendant l'appel ; AT_FDCWD : le chemin est absolu (un point de montage de mountinfo).
        let r = unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                drapeaux,
                OUVERTURE_EXEC_PERM,
                libc::AT_FDCWD,
                chemin.as_ptr(),
            )
        };
        if r < 0 { Err(erreur()) } else { Ok(()) }
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
