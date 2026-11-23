//! Une seule fenêtre, côté fenêtre : écouter, sur un canal privé au compte, la demande « montre-toi » d'un second
//! lancement de `vanguard`, et revenir devant. La règle commune est `regle_une_fenetre` (src/socle/une_fenetre.rs).
//!
//! Ce qui arrive par le canal est un message fermé de `TAILLE` octets : `DEMANDE` suivi d'un nombre tiré au hasard
//! par `vanguard`. Il fait revenir la fenêtre devant, et la réponse renvoie ce nombre (un programme qui aurait lu une
//! demande ailleurs, ou répondu d'avance, ne peut donc pas faire passer sa réponse pour celle-ci). Tout autre message
//! ferme la connexion ; rien d'autre n'est lu ni interprété. Deux demandes sont espacées de `CADENCE` au moins : une
//! demande trop proche attend son tour (au plus `CADENCE`), elle n'est jamais répondue sans que la fenêtre revienne.
//! Pas de réponse tant que la fenêtre n'existe pas (le fil d'écoute démarre avant elle) : `vanguard` ouvre alors une
//! fenêtre de plus plutôt que de croire en avoir ramené une. Chaque connexion a `DELAI + VERIFICATION` au plus, en
//! tout, pour parler (le client vérifie la fenêtre entre l'accueil et sa demande), puis elle est fermée. L'écoute vit
//! dans un fil à elle : un client lent ou hostile ne fige jamais la fenêtre, au pire il occupe le canal ce temps-là
//! par connexion. Une acceptation qui échoue attend, de plus en plus, avant la suivante.
//!
//! Linux : une prise Unix dans `XDG_RUNTIME_DIR/vanguard` (0700, à ce compte, vérifié), créée avant le bac à sable
//! (qui interdit ensuite d'en créer), après la séparation du relais (qui n'en hérite donc pas). Un client d'un autre
//! compte (SO_PEERCRED) est fermé sans réponse. Une prise vivante n'est retirée que sur `--remplacer-prise` (donné par
//! `vanguard`, qui a vérifié qu'elle n'est pas une fenêtre de Vanguard qui répond) ; son nœud reste après la
//! fermeture. Windows : un tube nommé lié au compte (SID) et à la session, liste d'accès à ce compte seul, première
//! instance exigée (un tube du même nom déjà là, peut-être d'un imposteur : pas de canal, réessayé toutes les
//! `REESSAI` jusqu'à ce que le nom se libère), clients distants refusés ; un client d'une autre session est fermé sans
//! réponse.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::regle_une_fenetre as regle;

/// Au plus une demande prise en compte par intervalle : un client qui se rebranche en boucle ne fait pas clignoter
/// la fenêtre.
const CADENCE: Duration = Duration::from_millis(300);

/// Une demande reçue, pas encore traitée par l'image suivante.
static DEMANDEE: AtomicBool = AtomicBool::new(false);

/// Une demande « montre-toi » est-elle arrivée depuis la dernière fois ? (remise à faux)
pub fn demandee() -> bool {
    DEMANDEE.swap(false, Ordering::AcqRel)
}

/// Le temps laissé au dessin de la fenêtre pour exister, quand une demande arrive juste après le démarrage du fil
/// d'écoute (qui la précède) : sans fenêtre au bout, pas de réponse.
const ATTENTE_FENETRE: Duration = Duration::from_millis(750);

/// La première pause après une erreur d'acceptation.
const PAUSE: Duration = Duration::from_millis(100);

/// Le temps à attendre avant de servir une demande arrivée à `maintenant`, la précédente prise à `derniere` : zéro si
/// elle remonte à `CADENCE` ou plus, le reste de la cadence sinon (une demande trop proche attend, elle n'est jamais
/// sautée : sautée, elle serait répondue sans que la fenêtre revienne).
fn attente_du_tour(derniere: Option<Instant>, maintenant: Instant) -> Duration {
    derniere.map_or(Duration::ZERO, |d| {
        CADENCE.saturating_sub(maintenant.saturating_duration_since(d))
    })
}

/// La pause après une erreur d'acceptation de plus : le double de la précédente, `DELAI` au plus (pas de boucle
/// folle quand l'erreur dure : trop de descripteurs ouverts, mémoire).
fn pause_suivante(pause: Duration) -> Duration {
    pause.saturating_mul(2).min(regle::DELAI)
}

/// Fait revenir la fenêtre : `reveiller` dit si une fenêtre existe pour revenir. Réessayé `ATTENTE_FENETRE` au plus
/// (la fenêtre naît juste après le fil d'écoute). Faux : personne à ramener, rien n'est répondu.
fn faire_revenir(reveiller: &impl Fn() -> bool) -> bool {
    let fin = Instant::now().checked_add(ATTENTE_FENETRE).unwrap_or_else(Instant::now);
    loop {
        if reveiller() {
            return true;
        }
        if Instant::now() >= fin {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Une demande lue : attend son tour, fait revenir la fenêtre, et rend la réponse à écrire ; `None` (rien à
/// répondre) si aucune fenêtre n'existe.
fn servir_la_demande(
    jeton: &[u8; regle::JETON],
    derniere: &mut Option<Instant>,
    reveiller: &impl Fn() -> bool,
) -> Option<[u8; regle::TAILLE]> {
    std::thread::sleep(attente_du_tour(*derniere, Instant::now()));
    *derniere = Some(Instant::now());
    DEMANDEE.store(true, Ordering::Release);
    if !faire_revenir(reveiller) {
        return None;
    }
    Some(regle::reponse(jeton))
}

#[cfg(target_os = "linux")]
pub use linux::{demarrer, ecouter, permettre_remplacement, preparer};
#[cfg(windows)]
pub use windows::ecouter;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    use super::{PAUSE, pause_suivante, regle, servir_la_demande};

    /// La prise prête, en attendant le fil d'écoute (créé après le bac à sable, qui ne vaut que pour les fils nés
    /// après lui).
    static PRISE: Mutex<Option<UnixListener>> = Mutex::new(None);
    /// De quoi redessiner aussitôt une demande reçue, donné par la toile quand elle existe ; avant, la demande
    /// attend la première image.
    static REVEIL: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();
    /// `vanguard` a vérifié que ce qui écoute à la place de la prise n'est pas une fenêtre de Vanguard qui répond
    /// (`--remplacer-prise`) : la nouvelle fenêtre la remplace même vivante.
    static REMPLACER: AtomicBool = AtomicBool::new(false);

    /// Permet à `preparer` de remplacer une prise vivante (option `--remplacer-prise`, donnée par `vanguard`).
    pub fn permettre_remplacement() {
        REMPLACER.store(true, Ordering::Release);
    }

    /// Crée la prise. À appeler dans le processus de la fenêtre, avant le bac à sable. Sans dossier de session privé
    /// ou sans nom de session simple : pas de prise (et donc une fenêtre de plus au prochain lancement, comme avant).
    pub fn preparer() {
        let moi = systeme::uid();
        let Ok(dossier) = regle::dossier_prive(std::env::var_os("XDG_RUNTIME_DIR"), moi) else {
            return;
        };
        let variable = |nom: &str| std::env::var(nom).ok();
        let Some(nom) = regle::nom_prise(variable("WAYLAND_DISPLAY").as_deref(), variable("DISPLAY").as_deref()) else {
            return;
        };
        preparer_dans(&dossier.join(nom), REMPLACER.load(Ordering::Acquire));
    }

    /// Crée la prise à `chemin` (dans un dossier déjà vérifié). Une prise laissée par une fenêtre partie (plus
    /// personne n'écoute) est remplacée ; une prise où quelqu'un écoute encore ne l'est que si `remplacer` : sinon
    /// une fenêtre ouverte à la main retirerait la prise de celle qui marche, qui ne serait plus jamais ramenée.
    pub(crate) fn preparer_dans(chemin: &std::path::Path, remplacer: bool) {
        if !remplacer && systeme::quelqu_un_ecoute(chemin) {
            return;
        }
        let _ = std::fs::remove_file(chemin);
        if let Ok(prise) = UnixListener::bind(chemin) {
            *PRISE.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(prise);
        }
    }

    /// Lance le fil d'écoute, si la prise est prête : juste après le bac à sable, pour que la prise réponde dès
    /// qu'elle existe (un `vanguard` qui la trouve muette lancerait une seconde fenêtre).
    pub fn demarrer() {
        let Some(prise) = PRISE.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() else {
            return;
        };
        let _ = std::thread::Builder::new().name("une-fenetre".into()).spawn(move || {
            // Vrai seulement quand la toile existe : avant, personne ne reviendrait devant.
            servir(&prise, systeme::uid(), || REVEIL.get().map(|r| r()).is_some());
        });
    }

    /// Donne de quoi redessiner aussitôt une demande reçue (la toile reste dans `dessin/`), et lance l'écoute si ce
    /// n'est pas déjà fait.
    pub fn ecouter(reveiller: impl Fn() + Send + Sync + 'static) {
        let _ = REVEIL.set(Box::new(reveiller));
        demarrer();
    }

    /// Sert les connexions une à une, pour toujours (le fil finit avec la fenêtre). Une acceptation qui échoue
    /// (trop de descripteurs ouverts, mémoire) attend avant la suivante, de plus en plus : pas de boucle folle.
    pub(crate) fn servir(prise: &UnixListener, moi: u32, reveiller: impl Fn() -> bool) {
        let mut derniere: Option<Instant> = None;
        let mut pause = PAUSE;
        loop {
            let Ok((mut flux, _)) = prise.accept() else {
                std::thread::sleep(pause);
                pause = pause_suivante(pause);
                continue;
            };
            pause = PAUSE;
            let Some(jeton) = lire_la_demande(&mut flux, moi) else {
                continue;
            };
            if let Some(reponse) = servir_la_demande(&jeton, &mut derniere, &reveiller) {
                let _ = flux.write_all(&reponse);
            }
        }
    }

    /// Une connexion : du même compte ; l'accueil envoyé (il porte, par le noyau, ce processus-ci, que le client
    /// vérifie) ; la demande lue en entier (`DELAI + VERIFICATION` au plus, en tout : le client vérifie entre les
    /// deux, et un client qui goutte ses octets ne tient pas plus). Son nombre, si c'était bien une demande.
    fn lire_la_demande(flux: &mut UnixStream, moi: u32) -> Option<[u8; regle::JETON]> {
        if systeme::compte_d_en_face(flux) != Some(moi) || flux.set_write_timeout(Some(regle::DELAI)).is_err() {
            return None;
        }
        flux.write_all(&[regle::ACCUEIL]).ok()?;
        let fin = Instant::now().checked_add(regle::DELAI + regle::VERIFICATION)?;
        let mut lu = [0u8; regle::TAILLE];
        let mut n = 0;
        while n < lu.len() {
            let reste = fin.saturating_duration_since(Instant::now());
            if reste.is_zero() || flux.set_read_timeout(Some(reste)).is_err() {
                return None;
            }
            match flux.read(lu.get_mut(n..)?) {
                Ok(0) | Err(_) => return None,
                Ok(k) => n += k,
            }
        }
        regle::jeton_de_la_demande(&lu)
    }

    // raison : FFI de libc (getuid, getsockopt SO_PEERCRED, une connexion non bloquante), que std ne fait pas.
    #[allow(unsafe_code)]
    mod systeme {
        /// Quelqu'un écoute-t-il à la prise `chemin` ? Une connexion non bloquante (une écoute figée à la file
        /// pleine ne fige pas le démarrage) : refusée (ECONNREFUSED) ou sans fichier (ENOENT), personne ; acceptée,
        /// en attente (EAGAIN) ou toute autre réponse, oui (dans le doute, la prise n'est pas retirée).
        pub(super) fn quelqu_un_ecoute(chemin: &std::path::Path) -> bool {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            use std::os::unix::ffi::OsStrExt;
            let octets = chemin.as_os_str().as_bytes();
            // SAFETY: socket ne lit aucune mémoire à nous.
            let brut = unsafe {
                libc::socket(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                )
            };
            if brut < 0 {
                return true;
            }
            // SAFETY: `brut` vient d'être créé, valide, à personne d'autre : l'OwnedFd le referme une seule fois.
            let fd = unsafe { OwnedFd::from_raw_fd(brut) };
            // SAFETY: sockaddr_un est fait d'entiers et d'un tableau d'octets : tout à zéro est une valeur valide.
            let mut adresse: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            if octets.len() >= adresse.sun_path.len() || octets.contains(&0) {
                return true;
            }
            let (Ok(famille), Ok(taille)) = (
                libc::sa_family_t::try_from(libc::AF_UNIX),
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_un>()),
            ) else {
                return true;
            };
            adresse.sun_family = famille;
            for (case, &o) in adresse.sun_path.iter_mut().zip(octets) {
                *case = libc::c_char::from_ne_bytes([o]);
            }
            // SAFETY: connect lit `taille` octets à `adresse`, à nous et vivante pendant l'appel.
            let r = unsafe { libc::connect(fd.as_raw_fd(), (&raw const adresse).cast(), taille) };
            r == 0
                || !matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ECONNREFUSED | libc::ENOENT)
                )
        }

        /// Le compte réel du processus.
        pub(super) fn uid() -> u32 {
            // SAFETY: getuid ne prend aucun argument, ne touche aucune mémoire et ne peut pas échouer.
            unsafe { libc::getuid() }
        }

        /// Le compte du programme à l'autre bout de la prise ; `None` si la question échoue.
        pub(super) fn compte_d_en_face(s: &std::os::unix::net::UnixStream) -> Option<u32> {
            use std::os::fd::AsRawFd;
            let mut cred = libc::ucred {
                pid: 0,
                uid: u32::MAX,
                gid: 0,
            };
            let mut taille = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).ok()?;
            // SAFETY: getsockopt écrit au plus `taille` octets dans `cred`, une structure à nous vivante pendant
            // l'appel, sur une prise ouverte que `s` garde.
            let r = unsafe {
                libc::getsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&raw mut cred).cast(),
                    &raw mut taille,
                )
            };
            (r == 0).then_some(cred.uid)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;

        fn dossier(nom: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!("vanguard-une-fenetre-{nom}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            d
        }

        fn serveur(d: &std::path::Path) -> (std::path::PathBuf, std::sync::mpsc::Receiver<()>) {
            serveur_pour(d, systeme::uid(), true)
        }

        /// Un serveur qui n'accepte que le compte `moi` ; `fenetre` : une fenêtre existe-t-elle à ramener ?
        fn serveur_pour(
            d: &std::path::Path,
            moi: u32,
            fenetre: bool,
        ) -> (std::path::PathBuf, std::sync::mpsc::Receiver<()>) {
            let chemin = d.join("p.prise");
            let prise = UnixListener::bind(&chemin).unwrap();
            let (envoi, reception) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                servir(&prise, moi, move || {
                    if fenetre {
                        let _ = envoi.send(());
                    }
                    fenetre
                });
            });
            (chemin, reception)
        }

        /// Un nombre de demande d'essai, différent à chaque appel.
        fn jeton(n: u8) -> [u8; regle::JETON] {
            let mut j = [0x5A; regle::JETON];
            j[0] = n;
            j[regle::JETON - 1] = n.wrapping_mul(7);
            j
        }

        /// Se branche, lit l'accueil, envoie `octets`, rend la réponse (vide si rien n'est venu).
        fn demander(chemin: &std::path::Path, octets: &[u8]) -> Vec<u8> {
            let mut f = UnixStream::connect(chemin).unwrap();
            // Un client muet devant lui tient le serveur `DELAI + VERIFICATION` : l'accueil peut attendre autant.
            f.set_read_timeout(Some(regle::DELAI + regle::VERIFICATION + Duration::from_secs(2)))
                .unwrap();
            let mut accueil = [0u8; 1];
            if f.read_exact(&mut accueil).is_err() {
                return Vec::new();
            }
            assert_eq!(accueil, [regle::ACCUEIL]);
            f.write_all(octets).unwrap();
            let mut r = Vec::new();
            let _ = f.read_to_end(&mut r);
            r
        }

        /// La demande est répondue en renvoyant son nombre, et réveille la fenêtre ; un autre message (premier
        /// octet faux, flot d'octets), ou un client muet n'obtiennent rien et ne bloquent pas le suivant au-delà de
        /// `DELAI + VERIFICATION`.
        #[test]
        fn seule_la_demande_connue_est_repondue() {
            let d = dossier("serveur");
            let (chemin, reveil) = serveur(&d);
            assert_eq!(demander(&chemin, &regle::demande(&jeton(1))), regle::reponse(&jeton(1)));
            reveil.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(super::super::demandee());
            let mut faux = regle::demande(&jeton(2));
            faux[0] = b'X';
            assert_eq!(demander(&chemin, &faux), Vec::<u8>::new());
            assert_eq!(demander(&chemin, &[b'Z'; 4096]), Vec::<u8>::new());
            // Un client muet : tenu DELAI + VERIFICATION au plus, puis le suivant passe.
            let _muet = UnixStream::connect(&chemin).unwrap();
            let debut = Instant::now();
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(demander(&chemin, &regle::demande(&jeton(3))), regle::reponse(&jeton(3)));
            assert!(debut.elapsed() < regle::DELAI + regle::VERIFICATION + Duration::from_secs(2));
            // Rien d'autre n'a réveillé la fenêtre que les deux vraies demandes.
            reveil.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(reveil.try_recv().is_err());
            let _ = std::fs::remove_dir_all(&d);
        }

        /// Campagne, constat 6 : tant qu'aucune fenêtre n'existe (le fil d'écoute démarre avant elle), une demande
        /// n'est pas répondue : `vanguard` ouvre une fenêtre plutôt que de croire en avoir ramené une.
        #[test]
        fn sans_fenetre_rien_n_est_repondu() {
            let d = dossier("sans-fenetre");
            let (chemin, _reveil) = serveur_pour(&d, systeme::uid(), false);
            let debut = Instant::now();
            assert_eq!(demander(&chemin, &regle::demande(&jeton(4))), Vec::<u8>::new());
            assert!(
                debut.elapsed() >= super::super::ATTENTE_FENETRE,
                "la fenêtre a eu le temps de naître"
            );
            let _ = std::fs::remove_dir_all(&d);
        }

        /// Un client d'un autre compte (SO_PEERCRED) n'obtient ni réponse ni réveil.
        #[test]
        fn un_autre_compte_n_obtient_rien() {
            let d = dossier("autre-compte");
            let (chemin, reveil) = serveur_pour(&d, systeme::uid().wrapping_add(1), true);
            assert_eq!(demander(&chemin, &regle::demande(&jeton(5))), Vec::<u8>::new());
            assert!(reveil.recv_timeout(Duration::from_millis(300)).is_err());
            let _ = std::fs::remove_dir_all(&d);
        }

        /// Campagne, constat 14 : une rafale de demandes est espacée de CADENCE, jamais sautée : chacune est
        /// répondue et chacune a fait revenir la fenêtre (une réponse sans retour devant mentirait à `vanguard`).
        #[test]
        fn une_rafale_attend_son_tour() {
            let d = dossier("rafale");
            let (chemin, reveil) = serveur(&d);
            let debut = Instant::now();
            for n in 0..5 {
                assert_eq!(demander(&chemin, &regle::demande(&jeton(n))), regle::reponse(&jeton(n)));
            }
            assert!(
                debut.elapsed() >= super::super::CADENCE * 4,
                "cadence gardée : {:?}",
                debut.elapsed()
            );
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(reveil.try_iter().count(), 5, "un retour devant par réponse");
            let _ = std::fs::remove_dir_all(&d);
        }

        /// Les essais qui passent par `PRISE` (une seule pour le processus) passent un à un.
        static SERIE: Mutex<()> = Mutex::new(());

        /// Une prise d'une fenêtre partie (plus personne n'écoute) est remplacée par la nouvelle.
        #[test]
        fn l_ancienne_prise_est_remplacee() {
            let _seul = SERIE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let d = dossier("remplacee");
            let chemin = d.join("p.prise");
            drop(UnixListener::bind(&chemin).unwrap());
            assert!(chemin.exists(), "le nœud d'une prise fermée reste");
            preparer_dans(&chemin, false);
            let nouvelle = PRISE.lock().unwrap().take().expect("prise créée");
            let _client = UnixStream::connect(&chemin).unwrap();
            nouvelle.set_nonblocking(true).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            assert!(nouvelle.accept().is_ok(), "la nouvelle prise reçoit les connexions");
            let _ = std::fs::remove_dir_all(&d);
        }

        /// Une prise où une fenêtre écoute encore n'est pas retirée par une fenêtre ouverte à côté ; elle l'est
        /// seulement quand `vanguard` le demande (`--remplacer-prise`).
        #[test]
        fn une_prise_vivante_n_est_pas_retiree() {
            let _seul = SERIE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let d = dossier("vivante");
            let chemin = d.join("p.prise");
            let ancienne = UnixListener::bind(&chemin).unwrap();
            ancienne.set_nonblocking(true).unwrap();
            preparer_dans(&chemin, false);
            assert!(
                PRISE.lock().unwrap().take().is_none(),
                "la nouvelle fenêtre n'a pas pris la prise"
            );
            let _client = UnixStream::connect(&chemin).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            // La sonde de `preparer_dans`, puis ce client : l'ancienne reçoit toujours.
            assert!(ancienne.accept().is_ok(), "l'ancienne prise reçoit toujours");
            preparer_dans(&chemin, true);
            let nouvelle = PRISE.lock().unwrap().take().expect("remplacée sur demande");
            let _client = UnixStream::connect(&chemin).unwrap();
            nouvelle.set_nonblocking(true).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            assert!(nouvelle.accept().is_ok());
            let _ = std::fs::remove_dir_all(&d);
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::time::{Duration, Instant};

    use super::{PAUSE, pause_suivante, regle, servir_la_demande};

    /// Sans canal (le nom du tube est pris : une autre fenêtre de ce compte, ou un programme qui l'a créé avant),
    /// la création est réessayée à cet intervalle : quand le nom se libère, cette fenêtre prend le canal.
    const REESSAI: Duration = Duration::from_secs(2);

    /// Crée le tube et lance le fil d'écoute. `fenetre` : la poignée de la fenêtre (HWND), ramenée devant depuis ce
    /// fil (sans passer par winit : sa demande de focus simule la touche Alt). Sans compte ou session lisibles : pas
    /// de canal. Si le tube existe déjà : réessayé toutes les `REESSAI`, dans le fil d'écoute. La fenêtre n'a pas de
    /// console où le dire (`windows_subsystem`) : c'est `vanguard` qui le dit au lancement suivant (canal refusé ou
    /// fenêtre qui ne répond pas, une fenêtre de plus s'ouvre).
    pub fn ecouter(reveiller: impl Fn() + Send + 'static, fenetre: Option<isize>) {
        let Some(sid) = systeme::sid() else {
            return;
        };
        let Some(session) = systeme::session_de(std::process::id()) else {
            return;
        };
        let (Some(nom), Some(sddl)) = (regle::nom_tube(&sid, session), regle::sddl(&sid)) else {
            return;
        };
        // Premier essai ici, avant le premier dessin : le tube existe quand la fenêtre dit « ouverte » (fin du
        // verrou des lancements), un second lancement le trouve.
        let premier = systeme::Tube::creer(&nom, &sddl);
        let _ = std::thread::Builder::new().name("une-fenetre".into()).spawn(move || {
            let tube = match premier {
                Some(t) => t,
                None => loop {
                    std::thread::sleep(REESSAI);
                    if let Some(t) = systeme::Tube::creer(&nom, &sddl) {
                        break t;
                    }
                },
            };
            servir(&tube, session, || {
                // Sans poignée de fenêtre, personne à ramener : rien n'est répondu.
                let Some(h) = fenetre else {
                    return false;
                };
                systeme::lever(h);
                reveiller();
                true
            });
        });
    }

    /// Sert les connexions une à une, pour toujours (le fil finit avec la fenêtre).
    pub(crate) fn servir(tube: &systeme::Tube, session: u32, reveiller: impl Fn() -> bool) {
        let mut derniere: Option<Instant> = None;
        let mut pause = PAUSE;
        loop {
            if !tube.attendre_client() {
                // Un client venu et reparti avant l'attente (ERROR_NO_DATA) laisse l'instance branchée à rien : la
                // couper la rend utilisable. Une erreur durable : une pause qui double, pas de boucle folle.
                tube.couper();
                std::thread::sleep(pause);
                pause = pause_suivante(pause);
                continue;
            }
            pause = PAUSE;
            // Le client vérifie ce tube entre son branchement et sa demande : `VERIFICATION` de plus pour lui.
            let jeton = if tube.session_du_client() == Some(session) {
                tube.lire_message(regle::DELAI + regle::VERIFICATION)
                    .and_then(|lu| regle::jeton_de_la_demande(&lu))
            } else {
                None
            };
            if let Some(reponse) = jeton.and_then(|j| servir_la_demande(&j, &mut derniere, &reveiller)) {
                tube.ecrire(&reponse);
                // Le client lit puis ferme : attendu, borné, avant de couper (couper jette ce qui n'est pas lu).
                tube.attendre_fermeture(regle::DELAI);
            }
            tube.couper();
        }
    }

    // raison : FFI de kernel32, advapi32 et user32 (tube nommé, jeton, fenêtre au premier plan), écrite à la main :
    // la fenêtre n'a pas la caisse windows.
    #[allow(unsafe_code)]
    pub(crate) mod systeme {
        use std::ffi::c_void;
        use std::time::{Duration, Instant};

        type Poignee = *mut c_void;
        const INVALIDE: Poignee = -1isize as Poignee;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreateNamedPipeW(
                nom: *const u16,
                ouverture: u32,
                mode: u32,
                instances: u32,
                sortie: u32,
                entree: u32,
                delai: u32,
                securite: *const Securite,
            ) -> Poignee;
            fn ConnectNamedPipe(tube: Poignee, chevauchement: *mut c_void) -> i32;
            fn DisconnectNamedPipe(tube: Poignee) -> i32;
            fn GetNamedPipeClientProcessId(tube: Poignee, pid: *mut u32) -> i32;
            fn PeekNamedPipe(
                tube: Poignee,
                tampon: *mut c_void,
                taille: u32,
                lus: *mut u32,
                disponibles: *mut u32,
                restant: *mut u32,
            ) -> i32;
            fn ReadFile(f: Poignee, tampon: *mut u8, taille: u32, lus: *mut u32, chevauchement: *mut c_void) -> i32;
            fn WriteFile(
                f: Poignee,
                tampon: *const u8,
                taille: u32,
                ecrits: *mut u32,
                chevauchement: *mut c_void,
            ) -> i32;
            fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
            fn GetCurrentProcess() -> Poignee;
            fn CloseHandle(objet: Poignee) -> i32;
            fn LocalFree(memoire: *mut c_void) -> *mut c_void;
            fn GetLastError() -> u32;
        }

        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn OpenProcessToken(processus: Poignee, acces: u32, jeton: *mut Poignee) -> i32;
            fn GetTokenInformation(
                jeton: Poignee,
                classe: u32,
                information: *mut c_void,
                taille: u32,
                rendue: *mut u32,
            ) -> i32;
            fn ConvertSidToStringSidW(sid: *mut c_void, texte: *mut *mut u16) -> i32;
            fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                texte: *const u16,
                revision: u32,
                descripteur: *mut *mut c_void,
                taille: *mut u32,
            ) -> i32;
        }

        #[link(name = "user32")]
        unsafe extern "system" {
            fn IsIconic(fenetre: isize) -> i32;
            fn ShowWindowAsync(fenetre: isize, commande: i32) -> i32;
            fn SetForegroundWindow(fenetre: isize) -> i32;
        }

        /// SECURITY_ATTRIBUTES.
        #[repr(C)]
        struct Securite {
            taille: u32,
            descripteur: *mut c_void,
            heritable: i32,
        }

        /// PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE.
        const OUVERTURE: u32 = 0x3 | 0x0008_0000;
        /// PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS.
        const MODE: u32 = 0x8;
        /// ERROR_PIPE_CONNECTED : le client s'est branché entre la création et l'attente.
        const DEJA_BRANCHE: u32 = 535;
        /// SW_RESTORE.
        const RESTAURER: i32 = 9;

        /// La session Windows du processus `pid`.
        pub(crate) fn session_de(pid: u32) -> Option<u32> {
            let mut session = u32::MAX;
            // SAFETY: ProcessIdToSessionId écrit un u32 dans `session`, à nous et vivant pendant l'appel.
            let ok = unsafe { ProcessIdToSessionId(pid, &raw mut session) } != 0;
            ok.then_some(session)
        }

        /// Le SID du compte de ce processus (« S-1-5-21-… »), lu dans son jeton ; vérifié par `regle::sid_valide`.
        pub(crate) fn sid() -> Option<String> {
            const REQUETE: u32 = 0x0008;
            const UTILISATEUR: u32 = 1;
            let mut jeton: Poignee = std::ptr::null_mut();
            // SAFETY: GetCurrentProcess rend une pseudo-poignée ; OpenProcessToken écrit une poignée dans `jeton`, à
            // nous, refermée plus bas une seule fois.
            if unsafe { OpenProcessToken(GetCurrentProcess(), REQUETE, &raw mut jeton) } == 0 || jeton.is_null() {
                return None;
            }
            // u64 : TOKEN_USER commence par un pointeur, aligné sur 8.
            let mut tampon = vec![0u64; 64];
            let mut rendue = 0u32;
            let taille = u32::try_from(tampon.len() * 8).ok()?;
            // SAFETY: GetTokenInformation écrit au plus `taille` octets dans `tampon`, à nous et vivant ; la poignée
            // du jeton est ouverte, et refermée juste après, une seule fois.
            let lu = unsafe {
                let lu = GetTokenInformation(jeton, UTILISATEUR, tampon.as_mut_ptr().cast(), taille, &raw mut rendue);
                CloseHandle(jeton);
                lu
            };
            if lu == 0 {
                return None;
            }
            let mut texte: *mut u16 = std::ptr::null_mut();
            // SAFETY: TOKEN_USER commence par le pointeur du SID, dans le même tampon (vivant). ConvertSidToStringSidW
            // alloue la chaîne (terminée par un zéro), lue au plus 256 caractères, rendue une fois par LocalFree.
            let sid = unsafe {
                let pointeur = tampon.as_ptr().cast::<*mut c_void>().read();
                if pointeur.is_null() || ConvertSidToStringSidW(pointeur, &raw mut texte) == 0 || texte.is_null() {
                    return None;
                }
                let mut fin = 0;
                while fin < 256 && *texte.add(fin) != 0 {
                    fin += 1;
                }
                let sid = String::from_utf16_lossy(std::slice::from_raw_parts(texte, fin));
                LocalFree(texte.cast());
                sid
            };
            super::regle::sid_valide(&sid).then_some(sid)
        }

        fn large(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        /// Le tube nommé, une seule instance, tenu jusqu'à la fin de la fenêtre.
        pub(crate) struct Tube(Poignee);

        // SAFETY: une poignée de Windows peut servir depuis n'importe quel fil ; le tube n'est servi que par un seul
        // à la fois (celui d'écoute, qui le possède).
        unsafe impl Send for Tube {}

        impl Tube {
            /// Crée la première et seule instance du tube `nom`, avec la liste d'accès `sddl`. `None` si le tube
            /// existe déjà (une autre fenêtre, ou un programme qui l'a pris avant) ou si Windows refuse.
            pub(crate) fn creer(nom: &str, sddl: &str) -> Option<Tube> {
                let mut descripteur: *mut c_void = std::ptr::null_mut();
                let texte = large(sddl);
                // SAFETY: `texte` est terminé par un zéro et vit pendant l'appel ; le descripteur alloué est rendu
                // plus bas par LocalFree, une seule fois.
                let ok = unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        texte.as_ptr(),
                        1,
                        &raw mut descripteur,
                        std::ptr::null_mut(),
                    )
                } != 0;
                if !ok || descripteur.is_null() {
                    return None;
                }
                let securite = Securite {
                    taille: u32::try_from(std::mem::size_of::<Securite>()).unwrap_or(0),
                    descripteur,
                    heritable: 0,
                };
                let nom = large(nom);
                // SAFETY: `nom` (terminé par un zéro) et `securite` (dont le descripteur) vivent pendant l'appel ; la
                // poignée rendue est gardée par `Tube` et refermée une seule fois (Drop). Le descripteur est rendu
                // après : CreateNamedPipeW en a fait sa copie.
                let poignee = unsafe {
                    let p = CreateNamedPipeW(nom.as_ptr(), OUVERTURE, MODE, 1, 64, 64, 0, &raw const securite);
                    LocalFree(descripteur);
                    p
                };
                (!poignee.is_null() && poignee != INVALIDE).then_some(Tube(poignee))
            }

            /// Attend qu'un client se branche ; faux sur une erreur.
            pub(crate) fn attendre_client(&self) -> bool {
                // SAFETY: la poignée du tube est ouverte tant que `self` vit ; attente simple, sans chevauchement.
                unsafe { ConnectNamedPipe(self.0, std::ptr::null_mut()) != 0 || GetLastError() == DEJA_BRANCHE }
            }

            /// La session du client branché.
            pub(crate) fn session_du_client(&self) -> Option<u32> {
                let mut pid = 0u32;
                // SAFETY: la poignée est ouverte tant que `self` vit ; un u32 écrit dans `pid`, à nous.
                let ok = unsafe { GetNamedPipeClientProcessId(self.0, &raw mut pid) } != 0;
                if !ok || pid == 0 {
                    return None;
                }
                session_de(pid)
            }

            /// Octets en attente ; `None` si le client est parti.
            fn disponibles(&self) -> Option<u32> {
                let mut disponibles = 0u32;
                // SAFETY: la poignée est ouverte ; aucun tampon (nul, taille 0), seul un u32 à nous est écrit.
                let ok = unsafe {
                    PeekNamedPipe(
                        self.0,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &raw mut disponibles,
                        std::ptr::null_mut(),
                    )
                } != 0;
                ok.then_some(disponibles)
            }

            /// Un message de `TAILLE` octets, reçu en entier en `delai` au plus (sans quoi une lecture sur un client
            /// muet, ou qui goutte ses octets, ne rendrait jamais la main). Seuls les octets déjà là sont lus : la
            /// lecture ne bloque jamais.
            pub(crate) fn lire_message(&self, delai: Duration) -> Option<[u8; super::regle::TAILLE]> {
                let fin = Instant::now().checked_add(delai).unwrap_or_else(Instant::now);
                let mut lu = [0u8; super::regle::TAILLE];
                let mut n = 0usize;
                while n < lu.len() {
                    let disponibles = usize::try_from(self.disponibles()?).unwrap_or(0);
                    if disponibles == 0 {
                        if Instant::now() >= fin {
                            return None;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    let voulus = u32::try_from(disponibles.min(lu.len() - n)).ok()?;
                    let mut lus = 0u32;
                    // SAFETY: au plus `voulus` octets écrits à partir de `lu[n]`, et `n + voulus <= TAILLE` : dans le
                    // tableau, à nous ; ces octets sont déjà dans le tube (la lecture ne bloque pas).
                    let ok = unsafe {
                        ReadFile(
                            self.0,
                            lu.as_mut_ptr().add(n),
                            voulus,
                            &raw mut lus,
                            std::ptr::null_mut(),
                        )
                    } != 0;
                    if !ok || lus == 0 {
                        return None;
                    }
                    n += usize::try_from(lus).ok()?;
                }
                Some(lu)
            }

            /// Écrit `octets` (le tampon du tube en a la place : l'écriture ne bloque pas).
            pub(crate) fn ecrire(&self, octets: &[u8]) {
                let Ok(taille) = u32::try_from(octets.len()) else {
                    return;
                };
                let mut ecrits = 0u32;
                // SAFETY: `taille` octets lus depuis `octets`, à nous et vivant ; la poignée est ouverte.
                unsafe {
                    WriteFile(self.0, octets.as_ptr(), taille, &raw mut ecrits, std::ptr::null_mut());
                }
            }

            /// Attend, `delai` au plus, que le client ferme son bout.
            pub(crate) fn attendre_fermeture(&self, delai: Duration) {
                let fin = Instant::now().checked_add(delai).unwrap_or_else(Instant::now);
                while self.disponibles().is_some() && Instant::now() < fin {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }

            /// Coupe le client, pour en attendre un autre.
            pub(crate) fn couper(&self) {
                // SAFETY: la poignée est ouverte tant que `self` vit.
                unsafe {
                    DisconnectNamedPipe(self.0);
                }
            }
        }

        impl Drop for Tube {
            fn drop(&mut self) {
                // SAFETY: la poignée vient de CreateNamedPipeW (valide, vérifié) et n'est refermée qu'ici, une fois.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }

        /// Pour les essais : un tube de même nom posé par un autre programme, sans première instance exigée, autant
        /// d'instances que voulu (PIPE_UNLIMITED_INSTANCES), liste d'accès par défaut.
        #[cfg(test)]
        pub(crate) fn essai_imposteur(nom: &str) -> Option<Tube> {
            let nom = large(nom);
            // SAFETY: `nom` (terminé par un zéro) vit pendant l'appel ; aucun attribut de sécurité (nul) ; la
            // poignée est gardée par `Tube` et refermée une seule fois.
            let p = unsafe { CreateNamedPipeW(nom.as_ptr(), 0x3, MODE, 255, 64, 64, 0, std::ptr::null()) };
            (!p.is_null() && p != INVALIDE).then_some(Tube(p))
        }

        /// Ramène la fenêtre `h` devant : restaurée si elle est réduite (sans attendre son fil), puis au premier plan
        /// (permis par `vanguard`, qui l'a demandé : AllowSetForegroundWindow).
        pub(crate) fn lever(h: isize) {
            // SAFETY: des appels de user32 sur une poignée de fenêtre ; une poignée périmée est refusée par Windows,
            // sans rien toucher de notre mémoire.
            unsafe {
                if IsIconic(h) != 0 {
                    ShowWindowAsync(h, RESTAURER);
                }
                SetForegroundWindow(h);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};
        use std::time::Duration;

        fn nom(essai: &str) -> String {
            format!(r"\\.\pipe\vanguard-essai-{essai}-{}", std::process::id())
        }

        fn sddl() -> String {
            let sid = systeme::sid().expect("SID du compte");
            regle::sddl(&sid).expect("SID valide")
        }

        /// Le compte et la session se lisent ; le nom et la liste d'accès s'en déduisent.
        #[test]
        fn compte_et_session_lus() {
            let sid = systeme::sid().expect("SID du compte");
            assert!(regle::sid_valide(&sid), "{sid}");
            let session = systeme::session_de(std::process::id()).expect("session");
            assert!(regle::nom_tube(&sid, session).is_some());
        }

        /// Première instance exigée : un tube du même nom déjà là, pas de second. D'abord le nôtre (une instance
        /// au plus : refusé de toute façon), puis celui d'un imposteur qui en permet autant qu'il veut : là, seul
        /// FILE_FLAG_FIRST_PIPE_INSTANCE refuse. Wine ne l'applique pas : cette moitié ne se vérifie que sous
        /// Windows (dite sautée sous Wine, jamais comptée comme vérifiée).
        #[test]
        fn le_tube_ne_se_cree_qu_une_fois() {
            let n = nom("unique");
            let premier = systeme::Tube::creer(&n, &sddl()).expect("premier tube");
            assert!(
                systeme::Tube::creer(&n, &sddl()).is_none(),
                "un second tube du même nom"
            );
            drop(premier);
            let n = nom("imposteur");
            let imposteur = systeme::essai_imposteur(&n).expect("tube de l'imposteur");
            let derriere = systeme::Tube::creer(&n, &sddl());
            if derriere.is_some() && std::env::var_os("WINEPREFIX").is_some() {
                return crate::essais::sauter("Wine n'applique pas FILE_FLAG_FIRST_PIPE_INSTANCE");
            }
            assert!(derriere.is_none(), "un tube derrière celui d'un imposteur");
            drop(imposteur);
            assert!(
                systeme::Tube::creer(&n, &sddl()).is_some(),
                "libre après la fin de l'imposteur"
            );
        }

        /// Un client : ouvre le tube (occupé par le client d'avant, réessayé deux secondes au plus, comme
        /// `vanguard`), écrit `octets`, lit la réponse (vide si rien n'est venu).
        fn client(n: &str, octets: &[u8]) -> Vec<u8> {
            let fin = std::time::Instant::now() + Duration::from_secs(8);
            let mut f = loop {
                match std::fs::OpenOptions::new().read(true).write(true).open(n) {
                    Ok(f) => break f,
                    Err(e) if e.raw_os_error() == Some(231) && std::time::Instant::now() < fin => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => panic!("tube injoignable : {e}"),
                }
            };
            if f.write_all(octets).is_err() {
                return Vec::new();
            }
            let mut r = Vec::new();
            let _ = f.read_to_end(&mut r);
            r
        }

        fn jeton(n: u8) -> [u8; regle::JETON] {
            let mut j = [0xA5; regle::JETON];
            j[0] = n;
            j
        }

        /// Le vrai serveur sur le tube `n`, dans un fil ; `fenetre` : une fenêtre existe-t-elle à ramener ? `decaler`
        /// : la session attendue, décalée pour jouer un client d'une autre session.
        fn lancer(n: &str, fenetre: bool, decaler: u32) -> std::sync::mpsc::Receiver<()> {
            let tube = systeme::Tube::creer(n, &sddl()).expect("tube");
            let session = systeme::session_de(std::process::id()).expect("session");
            let (envoi, reveil) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                servir(&tube, session.wrapping_add(decaler), move || {
                    if fenetre {
                        let _ = envoi.send(());
                    }
                    fenetre
                });
            });
            reveil
        }

        /// La demande est répondue en renvoyant son nombre et réveille la fenêtre ; un autre message n'obtient rien.
        #[test]
        fn seule_la_demande_est_repondue() {
            let n = nom("demande");
            let reveil = lancer(&n, true, 0);
            assert_eq!(client(&n, &regle::demande(&jeton(1))), regle::reponse(&jeton(1)));
            reveil.recv_timeout(Duration::from_secs(3)).expect("réveil");
            let mut faux = regle::demande(&jeton(2));
            faux[0] = b'X';
            assert_eq!(client(&n, &faux), Vec::<u8>::new());
            assert!(reveil.recv_timeout(Duration::from_millis(300)).is_err());
        }

        /// Un client d'une autre session n'obtient rien.
        #[test]
        fn une_autre_session_n_obtient_rien() {
            let n = nom("session");
            let reveil = lancer(&n, true, 1);
            assert_eq!(client(&n, &regle::demande(&jeton(3))), Vec::<u8>::new());
            assert!(reveil.try_recv().is_err());
        }

        /// Campagne, constat 6 : sans fenêtre à ramener, rien n'est répondu.
        #[test]
        fn sans_fenetre_rien_n_est_repondu() {
            let n = nom("sans-fenetre");
            let _reveil = lancer(&n, false, 0);
            assert_eq!(client(&n, &regle::demande(&jeton(4))), Vec::<u8>::new());
        }

        /// Campagne, constat 14 : une rafale attend son tour ; chaque réponse a fait revenir la fenêtre.
        #[test]
        fn une_rafale_attend_son_tour() {
            let n = nom("rafale");
            let reveil = lancer(&n, true, 0);
            let debut = std::time::Instant::now();
            for k in 0..3 {
                assert_eq!(client(&n, &regle::demande(&jeton(k))), regle::reponse(&jeton(k)));
            }
            assert!(debut.elapsed() >= super::super::CADENCE * 2, "{:?}", debut.elapsed());
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(reveil.try_iter().count(), 3);
        }

        /// Campagne, constat 35 : un client venu et reparti avant que le serveur l'attende (ERROR_NO_DATA) ne
        /// bloque pas le tube : coupé, il sert le client suivant.
        #[test]
        fn un_client_deja_parti_ne_bloque_pas_le_tube() {
            let n = nom("parti");
            let tube = systeme::Tube::creer(&n, &sddl()).expect("tube");
            drop(
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&n)
                    .expect("client parti"),
            );
            let session = systeme::session_de(std::process::id()).expect("session");
            std::thread::spawn(move || servir(&tube, session, || true));
            assert_eq!(client(&n, &regle::demande(&jeton(5))), regle::reponse(&jeton(5)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une demande trop proche attend le reste de la cadence ; une demande assez loin, ou la première, n'attend pas.
    #[test]
    fn attente_du_tour_bornee() {
        let maintenant = Instant::now();
        assert_eq!(attente_du_tour(None, maintenant), Duration::ZERO);
        assert_eq!(attente_du_tour(Some(maintenant), maintenant), CADENCE);
        let il_y_a = |ms| maintenant.checked_sub(Duration::from_millis(ms)).unwrap();
        assert_eq!(
            attente_du_tour(Some(il_y_a(100)), maintenant),
            Duration::from_millis(200)
        );
        assert_eq!(attente_du_tour(Some(il_y_a(300)), maintenant), Duration::ZERO);
        assert_eq!(attente_du_tour(Some(il_y_a(5000)), maintenant), Duration::ZERO);
    }

    /// Campagne, constat 35 : après des acceptations ratées, la pause double, plafonnée à `DELAI`, jamais nulle
    /// (sans elle, une erreur qui dure ferait tourner le fil à fond).
    #[test]
    fn la_pause_double_et_plafonne() {
        let mut p = PAUSE;
        let mut vues = vec![p];
        for _ in 0..10 {
            p = pause_suivante(p);
            vues.push(p);
        }
        assert_eq!(vues[1], PAUSE * 2);
        assert_eq!(vues[2], PAUSE * 4);
        assert_eq!(*vues.last().unwrap(), regle::DELAI);
        assert!(vues.iter().all(|v| *v >= PAUSE && *v <= regle::DELAI));
    }

    /// Une fenêtre qui naît pendant l'attente est ramenée ; aucune fenêtre au bout de `ATTENTE_FENETRE` : non.
    #[test]
    fn faire_revenir_attend_la_fenetre() {
        let debut = Instant::now();
        assert!(!faire_revenir(&|| false));
        assert!(debut.elapsed() >= ATTENTE_FENETRE);
        let essais = std::sync::atomic::AtomicU32::new(0);
        assert!(faire_revenir(&|| essais.fetch_add(1, Ordering::Relaxed) >= 2));
    }
}
