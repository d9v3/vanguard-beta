//! Une seule fenêtre, côté fenêtre : écouter, sur un canal privé au compte, la demande « montre-toi » d'un second
//! lancement de `vanguard`, et revenir devant. La règle commune est `regle_une_fenetre` (src/socle/une_fenetre.rs).
//!
//! Ce qui arrive par le canal n'est qu'un octet : `DEMANDE` fait revenir la fenêtre devant (pas plus d'une fois par
//! `CADENCE`), tout autre octet ferme la connexion. Rien d'autre n'est lu ni interprété ; chaque connexion a `DELAI`
//! au plus pour parler, puis elle est fermée. L'écoute vit dans un fil à elle : un client lent ou hostile ne fige
//! jamais la fenêtre, au pire il occupe le canal `DELAI` par connexion.
//!
//! Linux : une prise Unix dans `XDG_RUNTIME_DIR/vanguard` (0700, à ce compte, vérifié), créée avant le bac à sable
//! (qui interdit ensuite d'en créer), après la séparation du relais (qui n'en hérite donc pas). Un client d'un autre
//! compte (SO_PEERCRED) est fermé sans réponse. Windows : un tube nommé lié au compte (SID) et à la session, liste
//! d'accès à ce compte seul, première instance exigée (un tube du même nom déjà là, peut-être d'un imposteur : pas
//! de canal), clients distants refusés ; un client d'une autre session est fermé sans réponse.

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

/// Garde la cadence : vrai si la dernière demande prise remonte à plus de `CADENCE`.
fn a_son_tour(derniere: &mut Option<Instant>) -> bool {
    let maintenant = Instant::now();
    if derniere.is_some_and(|d| maintenant.saturating_duration_since(d) < CADENCE) {
        return false;
    }
    *derniere = Some(maintenant);
    true
}

/// Ce qu'une connexion a dit : vrai seulement pour exactement l'octet `DEMANDE`.
fn juger(lu: Option<u8>) -> bool {
    lu == Some(regle::DEMANDE)
}

#[cfg(target_os = "linux")]
pub use linux::{ecouter, preparer};
#[cfg(windows)]
pub use windows::ecouter;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::Mutex;
    use std::time::Instant;

    use super::{DEMANDEE, a_son_tour, juger, regle};

    /// La prise prête, en attendant le fil d'écoute (créé après le bac à sable).
    static PRISE: Mutex<Option<UnixListener>> = Mutex::new(None);

    /// Crée la prise. À appeler dans le processus de la fenêtre, avant le bac à sable. Sans dossier de session privé
    /// ou sans nom de session simple : pas de prise (et donc une fenêtre de plus au prochain lancement, comme avant).
    /// Une prise laissée par une fenêtre précédente est remplacée : `vanguard` ne lance une fenêtre que s'il n'en a
    /// trouvé aucune qui réponde, sous son verrou.
    pub fn preparer() {
        let moi = systeme::uid();
        let Ok(dossier) = regle::dossier_prive(std::env::var_os("XDG_RUNTIME_DIR"), moi) else {
            return;
        };
        let variable = |nom: &str| std::env::var(nom).ok();
        let Some(nom) = regle::nom_prise(variable("WAYLAND_DISPLAY").as_deref(), variable("DISPLAY").as_deref()) else {
            return;
        };
        preparer_dans(&dossier.join(nom));
    }

    /// Crée la prise à `chemin` (dans un dossier déjà vérifié).
    pub(crate) fn preparer_dans(chemin: &std::path::Path) {
        let _ = std::fs::remove_file(chemin);
        if let Ok(prise) = UnixListener::bind(chemin) {
            *PRISE.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(prise);
        }
    }

    /// Lance le fil d'écoute, si la prise est prête. `reveiller` : pour redessiner aussitôt une demande reçue (la
    /// toile reste dans `dessin/`).
    pub fn ecouter(reveiller: impl Fn() + Send + 'static) {
        let Some(prise) = PRISE.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() else {
            return;
        };
        let _ = std::thread::Builder::new()
            .name("une-fenetre".into())
            .spawn(move || servir(&prise, systeme::uid(), reveiller));
    }

    /// Sert les connexions une à une, pour toujours (le fil finit avec la fenêtre).
    pub(crate) fn servir(prise: &UnixListener, moi: u32, reveiller: impl Fn()) {
        let mut derniere: Option<Instant> = None;
        for flux in prise.incoming() {
            let Ok(flux) = flux else {
                continue;
            };
            if repondre(flux, moi) && a_son_tour(&mut derniere) {
                DEMANDEE.store(true, std::sync::atomic::Ordering::Release);
                reveiller();
            }
        }
    }

    /// Une connexion : du même compte, un seul octet lu (`DELAI` au plus), « ok » répondu à la seule demande
    /// connue. Vrai si c'était elle.
    fn repondre(mut flux: UnixStream, moi: u32) -> bool {
        if systeme::compte_d_en_face(&flux) != Some(moi) {
            return false;
        }
        if flux.set_read_timeout(Some(regle::DELAI)).is_err() || flux.set_write_timeout(Some(regle::DELAI)).is_err() {
            return false;
        }
        let mut octet = [0u8; 1];
        let lu = flux.read_exact(&mut octet).ok().map(|()| octet[0]);
        if !juger(lu) {
            return false;
        }
        let _ = flux.write_all(&[regle::REPONSE]);
        true
    }

    // raison : FFI de libc (getuid, getsockopt SO_PEERCRED), que std ne fait pas en version stable.
    #[allow(unsafe_code)]
    mod systeme {
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
            serveur_pour(d, systeme::uid())
        }

        /// Un serveur qui n'accepte que le compte `moi`.
        fn serveur_pour(d: &std::path::Path, moi: u32) -> (std::path::PathBuf, std::sync::mpsc::Receiver<()>) {
            let chemin = d.join("p.prise");
            let prise = UnixListener::bind(&chemin).unwrap();
            let (envoi, reception) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                servir(&prise, moi, move || {
                    let _ = envoi.send(());
                });
            });
            (chemin, reception)
        }

        fn demander(chemin: &std::path::Path, octets: &[u8]) -> Option<u8> {
            let mut f = UnixStream::connect(chemin).unwrap();
            f.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            f.write_all(octets).unwrap();
            let mut r = [0u8; 1];
            f.read_exact(&mut r).ok().map(|()| r[0])
        }

        /// La seule demande connue est répondue « ok » et réveille la fenêtre ; un autre octet, un flot d'octets
        /// commençant autrement, ou un client muet n'obtiennent rien et ne bloquent pas le suivant au-delà de DELAI.
        #[test]
        fn seule_la_demande_connue_est_repondue() {
            let d = dossier("serveur");
            let (chemin, reveil) = serveur(&d);
            assert_eq!(demander(&chemin, &[regle::DEMANDE]), Some(regle::REPONSE));
            reveil.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(super::super::demandee());
            assert_eq!(demander(&chemin, b"X"), None);
            assert_eq!(demander(&chemin, &[b'Z'; 4096]), None);
            // Un client muet : tenu DELAI au plus, puis le suivant passe.
            let _muet = UnixStream::connect(&chemin).unwrap();
            let debut = Instant::now();
            std::thread::sleep(CADENCE_ESSAI);
            assert_eq!(demander(&chemin, &[regle::DEMANDE]), Some(regle::REPONSE));
            assert!(debut.elapsed() < regle::DELAI + Duration::from_secs(2));
            // Rien d'autre n'a réveillé la fenêtre que les deux vraies demandes.
            reveil.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(reveil.try_recv().is_err());
            let _ = std::fs::remove_dir_all(&d);
        }

        const CADENCE_ESSAI: Duration = Duration::from_millis(350);

        /// Un client d'un autre compte (SO_PEERCRED) n'obtient ni réponse ni réveil.
        #[test]
        fn un_autre_compte_n_obtient_rien() {
            let d = dossier("autre-compte");
            let (chemin, reveil) = serveur_pour(&d, systeme::uid().wrapping_add(1));
            assert_eq!(demander(&chemin, &[regle::DEMANDE]), None);
            assert!(reveil.recv_timeout(Duration::from_millis(300)).is_err());
            let _ = std::fs::remove_dir_all(&d);
        }

        /// Une rafale de demandes ne réveille la fenêtre qu'une fois par CADENCE.
        #[test]
        fn une_rafale_est_bornee() {
            let d = dossier("rafale");
            let (chemin, reveil) = serveur(&d);
            for _ in 0..20 {
                assert_eq!(demander(&chemin, &[regle::DEMANDE]), Some(regle::REPONSE));
            }
            std::thread::sleep(Duration::from_millis(100));
            let reveils = reveil.try_iter().count();
            assert!((1..=2).contains(&reveils), "{reveils} réveils pour une rafale de 20");
            let _ = std::fs::remove_dir_all(&d);
        }

        /// Une prise d'une fenêtre précédente est remplacée par la nouvelle.
        #[test]
        fn l_ancienne_prise_est_remplacee() {
            let d = dossier("remplacee");
            let chemin = d.join("p.prise");
            let ancienne = UnixListener::bind(&chemin).unwrap();
            preparer_dans(&chemin);
            let nouvelle = PRISE.lock().unwrap().take().expect("prise créée");
            drop(ancienne);
            let _client = UnixStream::connect(&chemin).unwrap();
            nouvelle.set_nonblocking(true).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            assert!(nouvelle.accept().is_ok(), "la nouvelle prise reçoit les connexions");
            let _ = std::fs::remove_dir_all(&d);
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::time::Instant;

    use super::{DEMANDEE, a_son_tour, juger, regle};

    /// Crée le tube et lance le fil d'écoute. `fenetre` : la poignée de la fenêtre (HWND), ramenée devant depuis ce
    /// fil (sans passer par winit : sa demande de focus simule la touche Alt). Sans compte ou session lisibles, ou si
    /// le tube existe déjà : pas de canal.
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
        let Some(tube) = systeme::Tube::creer(&nom, &sddl) else {
            return;
        };
        let _ = std::thread::Builder::new().name("une-fenetre".into()).spawn(move || {
            servir(&tube, session, || {
                if let Some(h) = fenetre {
                    systeme::lever(h);
                }
                reveiller();
            });
        });
    }

    /// Sert les connexions une à une, pour toujours (le fil finit avec la fenêtre).
    pub(crate) fn servir(tube: &systeme::Tube, session: u32, reveiller: impl Fn()) {
        let mut derniere: Option<Instant> = None;
        loop {
            if !tube.attendre_client() {
                // Une erreur durable : pas de boucle folle.
                std::thread::sleep(regle::DELAI);
                continue;
            }
            let demande = tube.session_du_client() == Some(session) && juger(tube.lire_un(regle::DELAI));
            if demande {
                let tour = a_son_tour(&mut derniere);
                if tour {
                    DEMANDEE.store(true, std::sync::atomic::Ordering::Release);
                    reveiller();
                }
                tube.ecrire_un(regle::REPONSE);
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

            /// Un octet, attendu `delai` au plus (sans quoi une lecture sur un client muet ne rendrait jamais la
            /// main).
            pub(crate) fn lire_un(&self, delai: Duration) -> Option<u8> {
                let fin = Instant::now().checked_add(delai).unwrap_or_else(Instant::now);
                loop {
                    match self.disponibles()? {
                        0 if Instant::now() < fin => std::thread::sleep(Duration::from_millis(20)),
                        0 => return None,
                        _ => break,
                    }
                }
                let mut octet = 0u8;
                let mut lus = 0u32;
                // SAFETY: un octet au plus écrit dans `octet`, à nous ; des octets sont disponibles (la lecture ne
                // bloque pas).
                let ok = unsafe { ReadFile(self.0, &raw mut octet, 1, &raw mut lus, std::ptr::null_mut()) } != 0;
                (ok && lus == 1).then_some(octet)
            }

            /// Écrit un octet (le tampon du tube en a la place : l'écriture ne bloque pas).
            pub(crate) fn ecrire_un(&self, octet: u8) {
                let mut ecrits = 0u32;
                // SAFETY: un octet lu depuis `octet`, à nous ; la poignée est ouverte.
                unsafe {
                    WriteFile(self.0, &raw const octet, 1, &raw mut ecrits, std::ptr::null_mut());
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
        /// `vanguard`), écrit `octets`, lit la réponse.
        fn client(n: &str, octets: &[u8]) -> Option<u8> {
            let fin = std::time::Instant::now() + Duration::from_secs(2);
            let mut f = loop {
                match std::fs::OpenOptions::new().read(true).write(true).open(n) {
                    Ok(f) => break f,
                    Err(e) if e.raw_os_error() == Some(231) && std::time::Instant::now() < fin => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => panic!("tube injoignable : {e}"),
                }
            };
            f.write_all(octets).ok()?;
            let mut r = [0u8; 1];
            f.read_exact(&mut r).ok().map(|()| r[0])
        }

        /// La seule demande connue est répondue « ok » et réveille la fenêtre ; un autre octet n'obtient rien.
        #[test]
        fn seule_la_demande_est_repondue() {
            let n = nom("demande");
            let tube = systeme::Tube::creer(&n, &sddl()).expect("tube");
            let session = systeme::session_de(std::process::id()).expect("session");
            let (envoi, reveil) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                servir(&tube, session, move || {
                    let _ = envoi.send(());
                });
            });
            assert_eq!(client(&n, &[regle::DEMANDE]), Some(regle::REPONSE));
            reveil.recv_timeout(Duration::from_secs(3)).expect("réveil");
            assert_eq!(client(&n, b"X"), None);
            assert!(reveil.recv_timeout(Duration::from_millis(300)).is_err());
        }

        /// Un client d'une autre session n'obtient rien.
        #[test]
        fn une_autre_session_n_obtient_rien() {
            let n = nom("session");
            let tube = systeme::Tube::creer(&n, &sddl()).expect("tube");
            let session = systeme::session_de(std::process::id()).expect("session");
            std::thread::spawn(move || servir(&tube, session.wrapping_add(1), || {}));
            assert_eq!(client(&n, &[regle::DEMANDE]), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seul_l_octet_de_demande_compte() {
        assert!(juger(Some(regle::DEMANDE)));
        for autre in [None, Some(0), Some(regle::REPONSE), Some(b'v'), Some(0xFF)] {
            assert!(!juger(autre), "{autre:?}");
        }
    }

    #[test]
    fn cadence_bornee() {
        let mut d = None;
        assert!(a_son_tour(&mut d));
        assert!(!a_son_tour(&mut d));
        d = Instant::now().checked_sub(CADENCE + Duration::from_millis(1));
        assert!(a_son_tour(&mut d));
    }
}
