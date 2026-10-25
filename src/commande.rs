//! Lancement des commandes système avec un délai maximal : un outil qui ne répond plus (systemctl, gsettings,
//! PowerShell, gestionnaire de paquets hors ligne…) ne doit jamais figer Vanguard.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct Resultat {
    /// Code de retour (`None` si le programme a été tué par un signal).
    pub code: Option<i32>,
    pub sortie: String,
    /// Sortie d'erreur : notée dans le journal quand PowerShell ou udisksctl échouent, et lue par les tests
    /// (certains outils répondent par là).
    pub erreurs: String,
}

/// Délai d'attente des sorties après la fin du programme : un sous-processus resté en arrière-plan peut garder
/// le canal ouvert, et la lecture ne finirait jamais.
const DELAI_LECTURE: Duration = Duration::from_secs(2);

fn lire_en_fond(mut flux: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (envoi, reception) = mpsc::channel();
    std::thread::spawn(move || {
        let mut octets = Vec::new();
        let _ = flux.read_to_end(&mut octets);
        let _ = envoi.send(String::from_utf8_lossy(&octets).into_owned());
    });
    reception
}

/// Lance la commande et attend au plus `secondes`. `None` si elle ne démarre pas, dépasse le délai
/// (elle est alors tuée) ou si ses sorties ne se terminent pas.
pub fn lancer(commande: &mut Command, secondes: u64) -> Option<Resultat> {
    lancer_entree(commande, None, secondes)
}

/// Comme `lancer`, avec `entree` écrite sur l'entrée du programme puis fermée (pfctl -f - y lit ses règles) : jamais
/// un shell pour la lui passer.
#[cfg(any(target_os = "macos", all(test, unix)))]
pub(crate) fn lancer_avec_entree(commande: &mut Command, entree: &[u8], secondes: u64) -> Option<Resultat> {
    lancer_entree(commande, Some(entree.to_vec()), secondes)
}

fn lancer_entree(commande: &mut Command, entree: Option<Vec<u8>>, secondes: u64) -> Option<Resultat> {
    let mut enfant = commande
        .stdin(if entree.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    if let (Some(entree), Some(mut flux)) = (entree, enfant.stdin.take()) {
        // Écrite en fond : un programme qui ne lit pas son entrée ne bloque pas l'attente du délai.
        std::thread::spawn(move || {
            let _ = flux.write_all(&entree);
        });
    }
    let sortie = lire_en_fond(enfant.stdout.take()?);
    let erreurs = lire_en_fond(enfant.stderr.take()?);
    let limite = Instant::now() + Duration::from_secs(secondes);
    // Attente qui double de 1 à 50 ms : la plupart des commandes finissent en quelques millisecondes, et une pause
    // fixe de 50 ms coûtait 50 ms à chacune (5 s pour la centaine de petites commandes des fichiers suspects).
    let mut pause = Duration::from_millis(1);
    let statut = loop {
        match enfant.try_wait() {
            Ok(Some(statut)) => break statut,
            Ok(None) if Instant::now() < limite => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(50));
            }
            _ => {
                arreter(&mut enfant);
                return None;
            }
        }
    };
    Some(Resultat {
        code: statut.code(),
        sortie: sortie.recv_timeout(DELAI_LECTURE).ok()?,
        erreurs: erreurs.recv_timeout(DELAI_LECTURE).unwrap_or_default(),
    })
}

/// Le dossier System32 de ce Windows, demandé à Windows lui-même (GetSystemDirectoryW) : la variable SystemRoot
/// se change d'un `set` avant de lancer Vanguard, la réponse de Windows non. Lu une fois.
#[cfg(windows)]
pub(crate) fn dossier_systeme() -> &'static std::path::Path {
    use std::os::windows::ffi::OsStringExt;
    static DOSSIER: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(tampon: *mut u16, taille: u32) -> u32;
    }
    DOSSIER.get_or_init(|| {
        let mut tampon = [0u16; 1024];
        // SAFETY : la taille passée est celle du tampon (1024 < u32::MAX) ; Windows y écrit au plus autant de
        // caractères et rend leur nombre, ou la taille qu'il faudrait (plus grande que le tampon), ou 0.
        let n = unsafe { GetSystemDirectoryW(tampon.as_mut_ptr(), 1024) } as usize;
        match tampon.get(..n) {
            Some(nom) if n > 0 => std::path::PathBuf::from(std::ffi::OsString::from_wide(nom)),
            // Jamais vu : un chemin écrit plutôt qu'un nom nu, que Windows chercherait d'abord à côté de Vanguard.
            _ => std::path::PathBuf::from(r"C:\Windows\System32"),
        }
    })
}

/// Un programme de Windows par son chemin complet dans System32 (« .exe » ajouté s'il manque). Par son seul nom,
/// Windows le chercherait d'abord dans le dossier de Vanguard puis dans le dossier courant (Téléchargements, une clé
/// écrite ailleurs) : un faux netstat.exe ou tasklist.exe posé là cacherait un port ou un processus.
#[cfg(windows)]
pub(crate) fn systeme32(nom: &str) -> std::path::PathBuf {
    let fichier = if std::path::Path::new(nom).extension().is_some() {
        nom.to_string()
    } else {
        format!("{nom}.exe")
    };
    dossier_systeme().join(fichier)
}

/// Un programme du système : sous Windows, par son chemin dans System32 (voir `systeme32`) ; ailleurs, par son nom,
/// cherché dans le PATH comme avant.
pub(crate) fn systeme(nom: &str) -> Command {
    #[cfg(windows)]
    let programme = systeme32(nom);
    #[cfg(not(windows))]
    let programme = nom;
    Command::new(programme)
}

/// cmd.exe par son chemin, pour une ligne dont les programmes sont écrits par leur chemin (voir `systeme32`).
/// NoDefaultCurrentDirectoryInExePath en garde-fou : un nom laissé nu sur la ligne n'est plus cherché dans le dossier
/// courant (Téléchargements, une clé), seulement dans le PATH, qui lui aussi se change d'un `set` ; la protection
/// reste donc le chemin écrit. La variable passe aux programmes de la ligne : pour ouvrir un fichier ou une page,
/// où elle ne servirait à rien, passer plutôt par `systeme("cmd")`.
#[cfg(windows)]
pub(crate) fn cmd() -> Command {
    let mut c = Command::new(systeme32("cmd.exe"));
    c.env("NoDefaultCurrentDirectoryInExePath", "1");
    c
}

/// Ce que `lancer_borne` a lu.
pub struct Borne {
    /// Code de retour (`None` : arrêté par la borne, le délai ou un signal).
    pub code: Option<i32>,
    pub sortie: String,
    pub erreurs: String,
    /// Une sortie a passé la borne : le programme a été arrêté là, la suite manque.
    pub tronque: bool,
    /// Le délai est passé : le programme a été arrêté, ce qu'il avait déjà écrit reste.
    pub delai: bool,
}

/// Lit `flux` en fond, `borne` octets au plus ; passé la borne, le dit par `plein` et cesse de lire (le programme
/// bloque ou reçoit SIGPIPE, puis il est arrêté).
fn lire_borne(
    mut flux: impl Read + Send + 'static,
    borne: usize,
    plein: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> mpsc::Receiver<Vec<u8>> {
    let (envoi, reception) = mpsc::channel();
    std::thread::spawn(move || {
        let mut lu = Vec::new();
        let mut tampon = vec![0u8; 16 << 10];
        loop {
            let n = match flux.read(&mut tampon) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let reste = borne - lu.len();
            lu.extend_from_slice(&tampon[..n.min(reste)]);
            if n > reste {
                plein.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }
        let _ = envoi.send(lu);
    });
    reception
}

/// Le programme `pid` a-t-il fini ? Sans le récolter (WNOWAIT) : son numéro reste à lui, et celui de son groupe aussi.
#[cfg(target_os = "linux")]
fn fini_sans_recolter(pid: u32) -> bool {
    let id: libc::id_t = pid;
    // SAFETY : siginfo_t est une structure C sans pointeur, valide remplie de zéros ; waitid l'écrit (taille connue) et
    // ne garde rien. P_PID vise ce seul enfant, WNOHANG ne bloque pas, WNOWAIT laisse l'enfant à récolter par wait.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        libc::waitid(
            libc::P_PID,
            id,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        ) == 0
            && info.si_pid() != 0
    }
}

/// Arrête tout le groupe dont `pid` est le chef (la session créée pour un plugin par `setsid`) : ses descendants, même
/// rattachés à un autre parent, y sont encore. Rien si `pid` n'est pas chef de son groupe (un programme ordinaire).
#[cfg(unix)]
fn tuer_le_groupe(pid: u32) {
    if let Ok(p) = libc::pid_t::try_from(pid) {
        // SAFETY : getpgid lit le groupe d'un processus pas encore récolté ; kill envoie SIGKILL au groupe dont il est
        // le chef, celui que setsid a créé pour lui : aucun autre processus que les siens.
        unsafe {
            if libc::getpgid(p) == p {
                libc::kill(-p, libc::SIGKILL);
            }
        }
    }
}

/// Comme `lancer`, pour un programme qui n'est pas de confiance (un plugin) : chaque sortie gardée en mémoire jusqu'à
/// `borne` octets, puis le programme et tout ce qu'il a lancé arrêtés ; le délai passé, de même. Contrairement à
/// `lancer`, ce qui était déjà écrit reste : un plugin trop bavard ou trop lent montre au moins son début. `None` :
/// il ne démarre pas.
pub fn lancer_borne(commande: &mut Command, secondes: u64, borne: usize) -> Option<Borne> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    commande
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Un programme copié à l'instant (la copie vérifiée d'un plugin) peut être refusé « Text file busy » : un autre fil
    // qui lance un processus au même moment a hérité, le temps de son exec, du fichier encore ouvert en écriture.
    let mut essais = 0;
    let mut enfant = loop {
        match commande.spawn() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && essais < 20 => {
                essais += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            r => break r.ok()?,
        }
    };
    let plein = Arc::new(AtomicBool::new(false));
    let sortie = lire_borne(enfant.stdout.take()?, borne, plein.clone());
    let erreurs = lire_borne(enfant.stderr.take()?, borne, plein.clone());
    let limite = Instant::now() + Duration::from_secs(secondes);
    let mut pause = Duration::from_millis(1);
    let (mut tronque, mut delai) = (false, false);
    let pid = enfant.id();
    let code = loop {
        // Linux : fini, il n'est pas encore récolté ; ce qu'il a laissé derrière lui dans sa session est arrêté avant
        // (un petit-enfant détaché continuerait sinon après « Terminé »), tant que son numéro ne peut pas resservir.
        #[cfg(target_os = "linux")]
        if fini_sans_recolter(pid) {
            tuer_le_groupe(pid);
            break enfant.wait().ok().and_then(|s| s.code());
        }
        match enfant.try_wait() {
            Ok(Some(statut)) => break statut.code(),
            Ok(None) if plein.load(Ordering::Relaxed) => {
                tronque = true;
                #[cfg(unix)]
                tuer_le_groupe(pid);
                arreter(&mut enfant);
                break None;
            }
            Ok(None) if Instant::now() < limite => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(50));
            }
            _ => {
                delai = true;
                #[cfg(unix)]
                tuer_le_groupe(pid);
                arreter(&mut enfant);
                break None;
            }
        }
    };
    #[cfg(not(unix))]
    let _ = pid;
    // Un petit-enfant resté hors de l'arbre peut garder un canal ouvert : on n'attend pas plus que DELAI_LECTURE.
    let texte = |r: mpsc::Receiver<Vec<u8>>| {
        r.recv_timeout(DELAI_LECTURE)
            .map(|o| String::from_utf8_lossy(&o).into_owned())
            .unwrap_or_default()
    };
    let (sortie, erreurs) = (texte(sortie), texte(erreurs));
    Some(Borne {
        code,
        sortie,
        erreurs,
        tronque: tronque || plein.load(Ordering::Relaxed),
        delai,
    })
}

/// Comme `lancer`, l'outil répondant en anglais, avec les nombres et les dates du « C » : pour une sortie que Vanguard
/// analyse et que l'outil traduit (nmcli écrit « oui » pour « yes », lscpu « Nom de modèle » pour « Model name »).
/// En UTF-8, un nom de réseau accentué reste intact ; sans C.UTF-8, le système se replie sur le « C ». LANGUAGE est
/// retirée : selon la bibliothèque C, elle l'emporterait sur C.UTF-8. Une sortie montrée telle quelle à la personne
/// garde sa langue : `lancer`.
#[cfg(target_os = "linux")]
pub fn lancer_en_anglais(commande: &mut Command, secondes: u64) -> Option<Resultat> {
    lancer(commande.env("LC_ALL", "C.UTF-8").env_remove("LANGUAGE"), secondes)
}

/// Quelle part d'une sortie trop longue garder.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Garder {
    /// Le début : la commande est arrêtée à la borne (journalctl --reverse, le plus récent d'abord).
    #[cfg_attr(target_os = "macos", allow(dead_code))] // journalctl n'existe que sous Linux
    Debut,
    /// La fin : tout est lu, seuls les derniers octets restent (log show de macOS, le plus ancien d'abord).
    Fin,
}

/// Ce que `lancer_vers` a écrit.
#[cfg(unix)]
pub struct Ecrit {
    /// Code de retour (`None` : arrêtée par la borne, le délai ou un signal).
    pub code: Option<i32>,
    pub octets: u64,
    /// La sortie dépassait la borne : une partie manque.
    pub tronque: bool,
    /// Le délai est passé : la commande a été arrêtée, ce qui était déjà écrit reste.
    pub delai: bool,
    pub erreurs: String,
}

/// Les morceaux à garder pour n'avoir que les `borne` derniers octets : les plus anciens tombent, et ce qui reste
/// commence au début d'une ligne (une ligne coupée par le milieu se lirait de travers). Rend aussi s'il en est tombé.
#[cfg(any(unix, test))]
pub fn garder_la_fin(morceaux: std::collections::VecDeque<Vec<u8>>, borne: u64) -> (Vec<u8>, bool) {
    let total: usize = morceaux.iter().map(Vec::len).sum();
    let borne = usize::try_from(borne).unwrap_or(usize::MAX);
    let mut tout: Vec<u8> = morceaux.into_iter().flatten().collect();
    if total <= borne {
        return (tout, false);
    }
    let mut debut = total - borne;
    if debut > 0 && tout[debut - 1] != b'\n' {
        debut = tout[debut..]
            .iter()
            .position(|&o| o == b'\n')
            .map_or(total, |p| debut + p + 1);
    }
    tout.drain(..debut);
    (tout, true)
}

/// Comme `lancer`, la sortie écrite dans `fichier` au fil de l'eau, `borne` octets au plus : un journal de plusieurs
/// centaines de Mo ne passe pas tout entier par la mémoire. `Garder::Debut` arrête la commande à la borne ;
/// `Garder::Fin` lit tout et ne garde que la fin (en mémoire, la borne au plus). Le délai passé, la commande est
/// arrêtée et ce qui est déjà lu reste. `None` : la commande ne démarre pas, ou le fichier ne s'écrit pas.
#[cfg(unix)]
pub fn lancer_vers(
    commande: &mut Command,
    secondes: u64,
    fichier: &std::fs::File,
    borne: u64,
    garder: Garder,
) -> Option<Ecrit> {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut enfant = commande
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let mut flux = enfant.stdout.take()?;
    let erreurs = lire_en_fond(enfant.stderr.take()?);
    let mut vers = fichier.try_clone().ok()?;
    let plein = std::sync::Arc::new(AtomicBool::new(false));
    let plein_lu = plein.clone();
    let (envoi, fini) = mpsc::channel();
    std::thread::spawn(move || {
        let mut tampon = vec![0u8; 64 << 10];
        let (mut ecrits, mut tronque, mut ok) = (0u64, false, true);
        let mut fin = std::collections::VecDeque::new();
        let mut en_memoire = 0u64;
        loop {
            let n = match flux.read(&mut tampon) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            match garder {
                Garder::Debut => {
                    let reste = usize::try_from(borne.saturating_sub(ecrits)).unwrap_or(usize::MAX);
                    let n_gardes = n.min(reste);
                    ok &= vers.write_all(&tampon[..n_gardes]).is_ok();
                    ecrits += n_gardes as u64;
                    if n_gardes < n || !ok {
                        tronque = n_gardes < n;
                        plein_lu.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                Garder::Fin => {
                    fin.push_back(tampon[..n].to_vec());
                    en_memoire += n as u64;
                    // Les morceaux entièrement hors de la borne tombent tout de suite : la mémoire reste bornée.
                    while fin
                        .front()
                        .is_some_and(|m: &Vec<u8>| en_memoire - m.len() as u64 >= borne)
                    {
                        en_memoire -= fin.pop_front().map_or(0, |m| m.len() as u64);
                        tronque = true;
                    }
                }
            }
        }
        if garder == Garder::Fin {
            let (derniers, coupe) = garder_la_fin(fin, borne);
            tronque |= coupe;
            ok &= vers.write_all(&derniers).is_ok();
            ecrits = derniers.len() as u64;
        }
        let _ = envoi.send((ecrits, tronque, ok));
    });
    let limite = Instant::now() + Duration::from_secs(secondes);
    let mut pause = Duration::from_millis(1);
    let mut delai = false;
    let code = loop {
        match enfant.try_wait() {
            Ok(Some(statut)) => break statut.code(),
            Ok(None) if plein.load(Ordering::Relaxed) => {
                arreter(&mut enfant);
                break None;
            }
            Ok(None) if Instant::now() < limite => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(50));
            }
            _ => {
                delai = true;
                arreter(&mut enfant);
                break None;
            }
        }
    };
    // Après la fin, la lecture finit vite ; `Garder::Fin` écrit encore ce qu'il a gardé (la borne au plus).
    let (octets, tronque, ok) = fini.recv_timeout(DELAI_LECTURE + Duration::from_secs(30)).ok()?;
    if !ok {
        return None;
    }
    Some(Ecrit {
        code,
        octets,
        tronque,
        delai,
        erreurs: erreurs.recv_timeout(DELAI_LECTURE).unwrap_or_default(),
    })
}

/// Les descendants de `racine` (enfants, petits-enfants…) dans une liste de (processus, parent), sans `racine`
/// elle-même. Une boucle dans la liste (un numéro réutilisé, le processus 0 parent de lui-même) ne fait pas tourner
/// sans fin ; 1 000 au plus.
pub(crate) fn descendants(liste: &[(u32, u32)], racine: u32) -> Vec<u32> {
    let mut vus = vec![racine];
    let mut i = 0;
    while let Some(&pid) = vus.get(i)
        && vus.len() < 1000
    {
        i += 1;
        for &(enfant, parent) in liste {
            if parent == pid && !vus.contains(&enfant) {
                vus.push(enfant);
            }
        }
    }
    vus.split_off(1)
}

/// Les (processus, parent) de Linux, lus dans `/proc/<pid>/stat` : « 4242 (nom) S 4200 … ». Le nom peut contenir des
/// espaces et des parenthèses : le parent se lit après la dernière.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn parent_linux(stat: &str) -> Option<(u32, u32)> {
    let (debut, reste) = stat.rsplit_once(") ")?;
    let pid = debut.split_once(" (")?.0.trim().parse().ok()?;
    let parent = reste.split_whitespace().nth(1)?.parse().ok()?;
    Some((pid, parent))
}

/// Tous les (processus, parent) de l'ordinateur, sans lancer de commande sous Linux et Windows ; pgrep sur macOS.
fn processus_et_parents(racine: u32) -> Vec<(u32, u32)> {
    #[cfg(target_os = "linux")]
    {
        let _ = racine;
        crate::socle::processus::pids()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|pid| parent_linux(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?))
            .collect()
    }
    #[cfg(windows)]
    {
        let _ = racine;
        crate::machine::windows::processus::liste()
            .into_iter()
            .map(|p| (p.pid, p.parent))
            .collect()
    }
    // macOS : pas de /proc ; les enfants demandés au noyau (proc_listchildpids), de proche en proche ; pgrep -P en
    // secours pour un processus dont le noyau ne répond pas, tant que l'oracle de macos.yml ne l'a pas remplacé.
    #[cfg(target_os = "macos")]
    {
        let mut liste = Vec::new();
        let mut a_voir = vec![racine];
        while let Some(pid) = a_voir.pop()
            && liste.len() < 1000
        {
            let enfants = crate::machine::macos::noyau::enfants(pid).unwrap_or_else(|| {
                // Pas par `lancer` : son délai dépassé rappelle `arreter`, qui reviendrait ici.
                Command::new("pgrep")
                    .args(["-P", &pid.to_string()])
                    .output()
                    .map(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .split_whitespace()
                            .filter_map(|p| p.parse::<u32>().ok())
                            .collect()
                    })
                    .unwrap_or_default()
            });
            for enfant in enfants {
                liste.push((enfant, pid));
                a_voir.push(enfant);
            }
        }
        liste
    }
}

/// Arrête le programme et tout ce qu'il a lancé : sinon un sous-processus (winget sous PowerShell, un outil sous un
/// script) continuerait en arrière-plan, avec ses verrous. Les descendants sont d'abord tous repérés, puis tués : tué
/// en premier, le programme laisserait ses enfants rattachés à un autre parent, introuvables. Sous Unix, le programme
/// est suspendu avant : sinon, entre la mort de ses enfants et la sienne, il continue (un script lance la commande
/// suivante dès que la précédente meurt), et sa sortie passe la borne ou le délai : « echo apres » écrit après l'arrêt
/// de « sleep », vu quand l'ordinateur est chargé.
pub fn arreter(enfant: &mut Child) {
    let racine = enfant.id();
    #[cfg(unix)]
    if let Ok(pid) = libc::pid_t::try_from(racine) {
        // SAFETY : simple envoi d'un signal à un numéro de processus ; SIGKILL arrête aussi un processus suspendu.
        unsafe { libc::kill(pid, libc::SIGSTOP) };
    }
    for pid in descendants(&processus_et_parents(racine), racine) {
        #[cfg(windows)]
        crate::machine::windows::processus::terminer(pid);
        #[cfg(unix)]
        if let Ok(pid) = libc::pid_t::try_from(pid) {
            // SAFETY : simple envoi d'un signal à un numéro de processus.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
    let _ = enfant.kill();
    let _ = enfant.wait();
}

/// Apostrophes qui ouvrent et ferment une chaîne '…' de PowerShell : la droite, et aussi les typographiques ‘ ’ ‚ ‛
/// (U+2018 à U+201B), courantes dans un nom de fichier, de compte ou d'appareil.
const APOSTROPHES_PS: [char; 5] = ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'];

/// Le texte à placer entre apostrophes dans un script PowerShell : chaque apostrophe, droite ou typographique,
/// doublée. Ne doubler que « ' » laissait « ’ » fermer la chaîne : la suite d'un nom de fichier téléchargé ou d'un
/// appareil du réseau s'exécutait comme une commande.
pub fn ps_texte(t: &str) -> String {
    let mut s = String::with_capacity(t.len() + 2);
    for c in t.chars() {
        s.push(c);
        if APOSTROPHES_PS.contains(&c) {
            s.push(c);
        }
    }
    s
}

/// Le texte entre apostrophes, pour bash : « '…' » ; une apostrophe du texte ferme, s'échappe et rouvre. La seule
/// façon de mettre un texte venu d'ailleurs (nom d'appareil, de fichier, de certificat…) dans une commande shell : le
/// test `textes_dans_sudo_et_rm_mis_entre_apostrophes` le garde.
pub fn sh_chaine(t: &str) -> String {
    format!("'{}'", t.replace('\'', "'\\''"))
}

/// Le texte entre apostrophes, pour PowerShell : « '…' ».
#[cfg(any(windows, test))]
pub fn ps_chaine(t: &str) -> String {
    format!("'{}'", ps_texte(t))
}

/// Lignes « NOM|… » d'une section de la sortie d'un script, sans leur préfixe ; `None` sans le marqueur « NOM_FIN » :
/// la section n'a pas pu être lue jusqu'au bout.
#[cfg(any(windows, test))]
pub fn section<'a>(sortie: Option<&'a str>, nom: &str) -> Option<Vec<&'a str>> {
    let sortie = sortie?;
    let fin = format!("{nom}_FIN");
    sortie.lines().any(|l| l.trim() == fin).then(|| {
        sortie
            .lines()
            .filter_map(|l| l.trim().strip_prefix(nom)?.strip_prefix('|'))
            .collect()
    })
}

/// Programme et arguments d'une ligne de commande Windows (« "C:\Program Files\x.exe" -a », « x.exe -a »,
/// « C:\Program Files\x.exe -a » sans guillemets). Sur les trois systèmes : `machine::chasse` y lit le programme
/// de chaque ligne de commande en marche.
pub fn decouper_commande(ligne: &str) -> (String, String) {
    let ligne = ligne.trim();
    if let Some(reste) = ligne.strip_prefix('"')
        && let Some((exe, args)) = reste.split_once('"')
    {
        return (exe.to_string(), args.trim().to_string());
    }
    // Minuscules ASCII seulement : la position trouvée vaut dans la ligne d'origine (« İ » change de longueur en
    // minuscules Unicode). « .exe » doit finir un mot : « node.exec\run.exe » n'est pas coupé à « node.exe ».
    let bas = ligne.to_ascii_lowercase();
    let fin = bas
        .match_indices(".exe")
        .map(|(i, _)| i + 4)
        .find(|&f| bas[f..].chars().next().is_none_or(|c| c.is_whitespace() || c == '"'));
    if let Some(f) = fin {
        let (exe, args) = ligne.split_at(f);
        return (exe.to_string(), args.trim().to_string());
    }
    match ligne.split_once(' ') {
        Some((exe, args)) => (exe.to_string(), args.trim().to_string()),
        None => (ligne.to_string(), String::new()),
    }
}

#[cfg(test)]
mod tests_powershell {
    use super::*;

    /// La commande d'un programme : « .exe » qui finit un mot, cherché sans changer la longueur de la ligne.
    #[test]
    fn exe_trouve_a_la_bonne_place() {
        let d = |l: &str| decouper_commande(l);
        assert_eq!(
            d(r"C:\Users\alice\İnstall\app.exe -a"),
            (r"C:\Users\alice\İnstall\app.exe".into(), "-a".into())
        );
        assert_eq!(
            d(r"C:\Tools\node.exec\run.exe /q"),
            (r"C:\Tools\node.exec\run.exe".into(), "/q".into())
        );
        assert_eq!(
            d(r"C:\Program Files\App\APP.EXE"),
            (r"C:\Program Files\App\APP.EXE".into(), String::new())
        );
        assert_eq!(d(r#""C:\A B\x.exe" /s"#), (r"C:\A B\x.exe".into(), "/s".into()));
    }

    /// Un nom piégé : chaque sorte d'apostrophe tente de fermer la chaîne pour lancer une commande.
    const PIEGE: &str = "a'; Write-Output INJECTE; 'b ‘; Write-Output INJECTE; ‘ ’; Write-Output INJECTE; ’ \
                         ‚; Write-Output INJECTE; ‚ ‛; Write-Output INJECTE; ‛ L’outil";

    #[test]
    fn apostrophes_doublees() {
        assert_eq!(ps_texte("L'outil"), "L''outil");
        assert_eq!(ps_texte("L’outil ‘x‚ ‛"), "L’’outil ‘‘x‚‚ ‛‛");
        assert_eq!(ps_chaine("C:\\Users\\Zoé"), "'C:\\Users\\Zoé'");
        // Les guillemets doubles et le « $ » ne comptent pas entre apostrophes.
        assert_eq!(ps_texte("\"$x\" “y”"), "\"$x\" “y”");
    }

    /// La chaîne piégée, passée à un vrai PowerShell, reste du texte. Windows : powershell ; ailleurs, pwsh s'il est
    /// installé (sinon l'essai est sauté : sous Wine, PowerShell n'existe pas).
    #[test]
    fn chaine_piegee_reste_du_texte() {
        let programme = if cfg!(windows) { "powershell" } else { "pwsh" };
        let script = format!(
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $x = {}; Write-Output ('<' + $x + '>')",
            ps_chaine(PIEGE)
        );
        let Some(r) = lancer(
            Command::new(programme).args(["-NoProfile", "-NonInteractive", "-Command", &script]),
            60,
        ) else {
            return crate::essais::saute(&format!("{programme} absent"));
        };
        // Une injection réussie écrirait « INJECTE » sur une ligne à part.
        assert!(!r.sortie.lines().any(|l| l.trim() == "INJECTE"), "{}", r.sortie);
        // Un PowerShell factice (Wine) ne répond rien : rien à comparer.
        if !r.sortie.trim().is_empty() {
            assert_eq!(r.sortie.trim(), format!("<{PIEGE}>"), "{}", r.erreurs);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// L'entrée donnée arrive au programme, puis se ferme : il ne l'attend pas sans fin.
    #[test]
    fn l_entree_arrive_et_se_ferme() {
        let r = lancer_avec_entree(&mut Command::new("cat"), b"table <vanguard> persist\n", 5).unwrap();
        assert_eq!((r.code, r.sortie.as_str()), (Some(0), "table <vanguard> persist\n"));
    }

    #[test]
    fn arbre_des_processus() {
        // 10 lance 11 et 12 ; 11 lance 13 ; 20 n'est pas de la famille ; 0 est son propre parent (Windows).
        let liste = [(11, 10), (12, 10), (13, 11), (20, 1), (0, 0), (10, 1)];
        let mut d = descendants(&liste, 10);
        d.sort_unstable();
        assert_eq!(d, [11, 12, 13]);
        assert_eq!(descendants(&liste, 0), Vec::<u32>::new());
        // Une boucle (numéro réutilisé) ne tourne pas sans fin.
        assert_eq!(descendants(&[(2, 1), (1, 2)], 1), [2]);
        assert_eq!(parent_linux("4242 (Web Content) S 4200 4242 0"), Some((4242, 4200)));
        // Un nom piégé avec « ) » et des espaces : le parent se lit après la dernière parenthèse.
        assert_eq!(parent_linux("77 (a) S 1 (b) R 55 77"), Some((77, 55)));
        assert_eq!(parent_linux("pas une ligne"), None);
    }

    /// Les sorties analysées que leur outil traduit (relevées outil par outil, en français et en anglais) passent
    /// toutes par `lancer_en_anglais` : nmcli écrit « oui » pour « yes » dans la colonne ACTIVE, dpkg -S
    /// traduit ses lignes « diversion by … ». Lu dans les fichiers : l'appel
    /// de l'outil et `lancer_en_anglais` dans la même instruction.
    #[cfg(target_os = "linux")]
    #[test]
    fn sorties_traduites_lues_en_anglais() {
        let dans_la_langue_du_systeme: Vec<String> = [
            (
                "machine/linux/mod.rs",
                include_str!("machine/linux/mod.rs"),
                "Command::new(\"nmcli\")",
            ),
            (
                "machine/linux/mod.rs",
                include_str!("machine/linux/mod.rs"),
                "Command::new(\"dpkg\").args([\"-S\"",
            ),
        ]
        .into_iter()
        .filter(|(_, source, appel)| {
            source.find(appel).is_none_or(|i| {
                let instruction = &source[source[..i].rfind(';').map_or(0, |d| d + 1)..i];
                !instruction.contains("lancer_en_anglais(")
            })
        })
        .map(|(fichier, _, appel)| format!("{fichier} : {appel}"))
        .collect();
        assert!(dans_la_langue_du_systeme.is_empty(), "{dans_la_langue_du_systeme:#?}");
    }

    /// La langue de la personne (ici donnée à la commande : LC_ALL et LANGUAGE en français) arrive à l'outil par
    /// `lancer`, jamais par `lancer_en_anglais`.
    #[cfg(target_os = "linux")]
    #[test]
    fn lancer_en_anglais_remplace_la_langue_de_la_personne() {
        let langue = |r: Option<Resultat>| r.map(|r| r.sortie.trim().to_string()).unwrap_or_default();
        let en_francais = || {
            let mut c = Command::new("sh");
            c.args(["-c", "echo \"$LC_ALL|${LANGUAGE-aucune}\""])
                .env("LC_ALL", "fr_CA.UTF-8")
                .env("LANGUAGE", "fr_CA:fr");
            c
        };
        assert_eq!(langue(lancer(&mut en_francais(), 5)), "fr_CA.UTF-8|fr_CA:fr");
        assert_eq!(langue(lancer_en_anglais(&mut en_francais(), 5)), "C.UTF-8|aucune");
    }

    #[test]
    fn delai_et_sorties() {
        let debut = Instant::now();
        assert!(lancer(Command::new("sleep").arg("5"), 1).is_none());
        assert!(debut.elapsed() < Duration::from_secs(3));
        let r = lancer(Command::new("sh").args(["-c", "echo ok; echo oups >&2; exit 3"]), 5).unwrap();
        assert_eq!(
            (r.code, r.sortie.as_str(), r.erreurs.as_str()),
            (Some(3), "ok\n", "oups\n")
        );
    }

    #[test]
    fn sous_processus_qui_garde_la_sortie() {
        // Le programme se termine mais laisse un processus en arrière-plan sur la sortie : pas de blocage.
        let debut = Instant::now();
        let _ = lancer(Command::new("sh").args(["-c", "sleep 20 & echo fini"]), 5);
        assert!(debut.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn le_delai_arrete_aussi_ce_que_le_programme_a_lance() {
        let fichier = std::env::temp_dir().join(format!("vanguard-test-arbre-{}", std::process::id()));
        let script = format!("sleep 30 & echo $! > '{}'; wait", fichier.display());
        assert!(lancer(Command::new("sh").args(["-c", &script]), 1).is_none());
        let pid = std::fs::read_to_string(&fichier).unwrap().trim().to_string();
        let _ = std::fs::remove_file(&fichier);
        // Arrêté = absent de la liste des processus, ou zombie qui attend d'être ramassé.
        let vivant = || {
            let ps = Command::new("ps").args(["-o", "stat=", "-p", &pid]).output().unwrap();
            let etat = String::from_utf8_lossy(&ps.stdout).trim().to_string();
            !etat.is_empty() && !etat.starts_with('Z')
        };
        let debut = Instant::now();
        while vivant() && debut.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!vivant(), "le sous-processus {pid} tourne encore");
    }
}

/// Le garde de `sh_chaine` : tout texte qui entre dans une commande `sudo` ou `rm` est une constante, un texte passé par
/// `sh_chaine`, ou une exception relue (`RELUES`). Lu dans les fichiers du code, comme un relecteur le ferait.
#[cfg(all(test, unix))]
mod tests_sh_chaine {
    use std::path::Path;

    /// Les arguments relus un par un : (fichier, expression, pourquoi elle ne peut rien injecter).
    const RELUES: &[(&str, &str, &str)] = &[
        (
            "protection/sites_bloques.rs",
            "sha",
            "constante : sha256sum ou shasum -a 256, choisie à la compilation",
        ),
        (
            "protection/sites_bloques.rs",
            "vider",
            "constante : la commande qui vide le cache DNS, choisie à la compilation",
        ),
        (
            "optimiser/linux.rs",
            "suite",
            "la commande `apres` d'un fichier de la liste fermée POSES, écrite dans le code",
        ),
        (
            "machine/linux/durcissement.rs",
            "lignes",
            "réglages sysctl du code et fichier de Vanguard, à root",
        ),
        (
            "machine/linux/maj.rs",
            "k",
            "versions de noyau lues dans dkms status et /lib/modules, à root",
        ),
        (
            "machine/linux/mod.rs",
            "paquets",
            "noms de paquets choisis par le code ou lus dans la base des paquets",
        ),
        (
            "machine/linux/mod.rs",
            "paquet",
            "nom de paquet choisi par le code ou lu dans la base des paquets",
        ),
        (
            "machine/linux/mod.rs",
            "cle",
            "« port/protocole », fait de nombres par le code",
        ),
        (
            "machine/linux/privileges.rs",
            "risques.first().copied().unwrap_or(\"docker\")",
            "noms de groupes du code",
        ),
        (
            "machine/macos/maj.rs",
            "noms.iter() .map(|n| crate::commande::sh_chaine(n)) .collect::<Vec<_>>() .join(\" \")",
            "chaque étiquette passe par sh_chaine",
        ),
        ("machine/macos/mod.rs", "cle", "clés de defaults du code"),
        ("optimiser/linux.rs", "nom", "noms d'unités du code"),
        ("optimiser/linux.rs", "etat_unite(e)", "enable, disable ou mask"),
        (
            "optimiser/linux.rs",
            "apres",
            "commande constante du code (&'static str)",
        ),
        ("optimiser/linux.rs", "cle", "clés de fichiers de configuration du code"),
        (
            "optimiser/linux.rs",
            "v.replace('\\\\', r\"\\\\\") .replace('|', r\"\\|\") .replace('&', r\"\\&\") .replace('\\'', r\"'\\''\")",
            "remplacement de sed, déjà entre apostrophes : protégé pour sed puis pour le shell",
        ),
        ("optimiser/linux.rs", "connexion", "UUID vérifié par uuid_valide"),
        ("optimiser/linux.rs", "oui_non(ignore4)", "yes ou no"),
        ("optimiser/linux.rs", "oui_non(ignore6)", "yes ou no"),
        (
            "optimiser/macos.rs",
            "serveurs",
            "adresses IP relues par IpAddr, ou « empty »",
        ),
        (
            "protection/blocage/pare_feu.rs",
            "lot",
            "lignes de nft du code, chacune passée par sh_chaine ; l'élément est une adresse ou un port analysés",
        ),
        (
            "protection/distance.rs",
            "if application { \"rf\" } else { \"f\" }",
            "deux constantes",
        ),
        (
            "reparer.rs",
            "description",
            "entre_apostrophes, qui passe par sh_chaine sous Unix",
        ),
        (
            "reparer.rs",
            "s",
            "entre_apostrophes, qui passe par sh_chaine sous Unix",
        ),
        (
            "reparer.rs",
            "motif_adresses(&detournees)",
            "adresses IP validées, points protégés pour sed",
        ),
        (
            "sauvegarde.rs",
            "id",
            "chiffres hexadécimaux et tirets, vérifié juste avant",
        ),
        (
            "reseau/wifi_public/linux.rs",
            "unite",
            "unité de la liste fermée etat::UNITES, vérifiée juste avant",
        ),
        (
            "reseau/wifi_public/linux.rs",
            "uuid",
            "UUID vérifié par uuid_valide juste avant (hexadécimal et tirets)",
        ),
        (
            "reseau/wifi_public/linux.rs",
            "paires.join(\" \")",
            "propriétés et valeurs des ensembles fermés etat::PROPRIETES_NM, vérifiées juste avant",
        ),
        (
            "reseau/wifi_public/macos.rs",
            "option",
            "option de la liste fermée etat::OPTIONS_MAC, vérifiée juste avant",
        ),
        (
            "reseau/wifi_public/macos.rs",
            "valeur",
            "« on » ou « off », vérifié juste avant",
        ),
    ];

    pub(super) fn sources(dossier: &Path, base: &Path, sortie: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(dossier).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                sources(&p, base, sortie);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let nom = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                sortie.push((nom, std::fs::read_to_string(&p).unwrap()));
            }
        }
    }

    /// Un littéral de chaîne qui commence à `i` (« "…" », « r"…" », « r#"…"# ») : son texte tel qu'écrit, et la
    /// position qui le suit.
    fn litteral(src: &str, i: usize) -> Option<(&str, usize)> {
        let reste = &src[i..];
        if let Some(apres) = reste.strip_prefix('r') {
            let dieses = apres.len() - apres.trim_start_matches('#').len();
            if !apres[dieses..].starts_with('"') {
                return None;
            }
            let fermeture = format!("\"{}", "#".repeat(dieses));
            let debut = i + 2 + dieses;
            let fin = debut + src[debut..].find(&fermeture)?;
            return Some((&src[debut..fin], fin + fermeture.len()));
        }
        if !reste.starts_with('"') {
            return None;
        }
        let octets = src.as_bytes();
        let mut j = i + 1;
        while octets[j] != b'"' {
            j += if octets[j] == b'\\' { 2 } else { 1 };
        }
        Some((&src[i + 1..j], j + 1))
    }

    /// Les arguments qui suivent le texte d'un format!, jusqu'à sa parenthèse fermante.
    fn arguments(src: &str, mut i: usize) -> Vec<String> {
        let octets = src.as_bytes();
        let (mut profondeur, mut debut, mut args) = (0, i, Vec::new());
        loop {
            let c = octets[i];
            let precede_d_un_mot = i > 0 && (octets[i - 1].is_ascii_alphanumeric() || octets[i - 1] == b'_');
            if (c == b'"' || (c == b'r' && !precede_d_un_mot && matches!(octets[i + 1], b'"' | b'#')))
                && let Some((_, fin)) = litteral(src, i)
            {
                i = fin;
                continue;
            }
            if c == b'\'' {
                // Un caractère (',' ou ')' n'ouvrent ni ne ferment rien) ; sinon une durée de vie.
                let longueur = if octets[i + 1] == b'\\' {
                    2
                } else {
                    src[i + 1..].chars().next().map_or(1, char::len_utf8)
                };
                if octets.get(i + 1 + longueur) == Some(&b'\'') {
                    i += longueur + 2;
                    continue;
                }
            }
            match c {
                b'(' | b'[' | b'{' => profondeur += 1,
                b')' | b']' | b'}' if profondeur == 0 => break,
                b')' | b']' | b'}' => profondeur -= 1,
                b',' if profondeur == 0 => {
                    args.push(src[debut..i].split_whitespace().collect::<Vec<_>>().join(" "));
                    debut = i + 1;
                }
                _ => {}
            }
            i += 1;
        }
        args.push(src[debut..i].split_whitespace().collect::<Vec<_>>().join(" "));
        args.into_iter().filter(|a| !a.is_empty()).collect()
    }

    /// Le texte lance-t-il sudo ou rm (en début de commande, après un séparateur ou un espace) ?
    fn lance_sudo_ou_rm(texte: &str) -> bool {
        ["sudo", "rm"].iter().any(|mot| {
            texte.match_indices(mot).any(|(k, _)| {
                let suivi = texte[k + mot.len()..].starts_with(char::is_whitespace);
                let avant = texte[..k].trim_end();
                let precede = k == 0
                    || texte[..k].ends_with(char::is_whitespace)
                    || avant.is_empty()
                    || avant.ends_with([';', '&', '|', '(']);
                suivi && precede
            })
        })
    }

    fn par_sh_chaine(expr: &str) -> bool {
        ["sh_chaine(", "commande::sh_chaine(", "crate::commande::sh_chaine("]
            .iter()
            .any(|f| expr.starts_with(f))
    }

    /// Une constante, un texte passé par sh_chaine, ou une variable qui en reçoit un (« let nom = sh_chaine(…) »).
    fn sur(expr: &str, avant: &str) -> bool {
        let expr = expr.trim_start_matches('&').trim();
        let constante = expr.starts_with(['"', 'r']) && litteral(expr, 0).is_some()
            || expr.chars().all(|c| c.is_ascii_digit())
            || expr.starts_with(|c: char| c.is_ascii_uppercase())
                && expr
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        let variable = expr.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && avant.rfind(&format!("let {expr} = ")).is_some_and(|k| {
                let valeur = &avant[k + expr.len() + 7..];
                par_sh_chaine(valeur.trim_start())
            });
        constante || par_sh_chaine(expr) || variable
    }

    /// Les arguments d'un format! qui lance sudo ou rm et qui ne sont pas sûrs : (expression, ligne).
    fn douteux(src: &str) -> Vec<(String, usize)> {
        let mut trouves = Vec::new();
        for (k, _) in src.match_indices("format!(") {
            let i = k + "format!(".len();
            let i = i + src[i..].len() - src[i..].trim_start().len();
            let Some((texte, fin)) = litteral(src, i) else { continue };
            if !lance_sudo_ou_rm(texte) {
                continue;
            }
            let args = arguments(src, fin);
            let (nommes, positionnels): (Vec<&String>, Vec<&String>) = args.iter().partition(|a| {
                a.split_once('=').is_some_and(|(nom, reste)| {
                    !reste.starts_with('=') && nom.trim().chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                })
            });
            let mut rang = 0;
            let mut reste = texte;
            while let Some(d) = reste.find('{') {
                if reste[d + 1..].starts_with('{') {
                    reste = &reste[d + 2..];
                    continue;
                }
                let Some(f) = reste[d..].find('}') else { break };
                let nom = reste[d + 1..d + f].split(':').next().unwrap_or("").trim();
                reste = &reste[d + f + 1..];
                let expr = if nom.is_empty() {
                    rang += 1;
                    positionnels.get(rang - 1).map(|s| (*s).clone())
                } else if let Ok(n) = nom.parse::<usize>() {
                    positionnels.get(n).map(|s| (*s).clone())
                } else {
                    let nomme = nommes.iter().find_map(|a| {
                        a.split_once('=')
                            .filter(|(n, _)| n.trim() == nom)
                            .map(|(_, v)| v.trim().to_string())
                    });
                    Some(nomme.unwrap_or_else(|| nom.to_string()))
                };
                let expr = expr.unwrap_or_default();
                if !sur(&expr, &src[..k]) {
                    trouves.push((expr, src[..k].lines().count()));
                }
            }
        }
        trouves
    }

    #[test]
    fn textes_dans_sudo_et_rm_mis_entre_apostrophes() {
        let base = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut fichiers = Vec::new();
        sources(base, base, &mut fichiers);
        let mut nouveaux = Vec::new();
        let mut servies = vec![false; RELUES.len()];
        for (nom, src) in &fichiers {
            // Les tests des modules lancent leurs propres commandes, sur des dossiers jetables.
            let code = src.find("#[cfg(test)]\nmod ").map_or(src.as_str(), |t| &src[..t]);
            for (expr, ligne) in douteux(code) {
                match RELUES.iter().position(|(f, e, _)| f == nom && *e == expr) {
                    Some(i) => servies[i] = true,
                    None => nouveaux.push(format!("{nom}:{ligne} : {expr}")),
                }
            }
        }
        assert!(
            nouveaux.is_empty(),
            "texte non protégé dans une commande sudo ou rm : passe-le par commande::sh_chaine (ou, s'il est sûr \
             par construction, ajoute-le à RELUES avec la raison) :\n{}",
            nouveaux.join("\n")
        );
        let perimees: Vec<_> = RELUES
            .iter()
            .zip(&servies)
            .filter(|(_, s)| !**s)
            .map(|(r, _)| r)
            .collect();
        assert!(perimees.is_empty(), "exceptions qui ne servent plus : {perimees:#?}");
    }

    /// Chemins pris dans une variable et passés tels quels à Get-ChildItem ou Remove-Item, relus : sûrs ici.
    const PS_RELUES: &[(&str, &str, &str)] = &[
        (
            "guide/windows.rs",
            "$env:TEMP",
            "texte du guide, tapé par la personne, jamais lancé par Vanguard",
        ),
        (
            "machine/sante.rs",
            "$_.FullName",
            "le chemin d'un dossier que Get-ChildItem vient de lister",
        ),
    ];

    /// Les variables passées comme chemin à Get-ChildItem ou Remove-Item sans -LiteralPath, avec leur ligne.
    fn ps_douteux(code: &str) -> Vec<(String, usize)> {
        let mut trouves = Vec::new();
        for applet in ["Get-ChildItem ", "Remove-Item "] {
            for (i, _) in code.match_indices(applet) {
                let apres = code[i + applet.len()..].trim_start();
                // Dans le source Rust, le guillemet d'un chemin s'écrit « \" ».
                let apres = apres
                    .strip_prefix("\\\"")
                    .or_else(|| apres.strip_prefix(['"', '\'']))
                    .unwrap_or(apres);
                if let Some(nom) = apres.strip_prefix('$') {
                    let fin = nom
                        .find(|c: char| !(c.is_alphanumeric() || "_:.".contains(c)))
                        .unwrap_or(nom.len());
                    let ligne = code[..i].matches('\n').count() + 1;
                    trouves.push((format!("${}", &nom[..fin]), ligne));
                }
            }
        }
        trouves
    }

    /// Une variable vide passée comme chemin fait lire le dossier courant à Get-ChildItem (« Get-ChildItem '' »), et
    /// Remove-Item -Recurse le viderait ; « $env:SystemRoot\x » vide devient la racine du disque. Vu le 19 octobre : un
    /// dossier Démarrage absent faisait prendre le dossier courant pour des démarrages suspects.
    #[test]
    fn chemins_powershell_jamais_une_variable_nue() {
        let base = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut fichiers = Vec::new();
        sources(base, base, &mut fichiers);
        let mut nouveaux = Vec::new();
        let mut servies = vec![false; PS_RELUES.len()];
        for (nom, src) in &fichiers {
            let code = src.find("#[cfg(test)]\nmod ").map_or(src.as_str(), |t| &src[..t]);
            for (variable, ligne) in ps_douteux(code) {
                match PS_RELUES.iter().position(|(f, v, _)| f == nom && *v == variable) {
                    Some(i) => servies[i] = true,
                    None => nouveaux.push(format!("{nom}:{ligne} : {variable}")),
                }
            }
        }
        assert!(
            nouveaux.is_empty(),
            "chemin PowerShell pris dans une variable, sans -LiteralPath : écris le chemin (ps_chaine) après l'avoir \
             vérifié, ou ajoute-le à PS_RELUES avec la raison :\n{}",
            nouveaux.join("\n")
        );
        let perimees: Vec<_> = PS_RELUES
            .iter()
            .zip(&servies)
            .filter(|(_, s)| !**s)
            .map(|(r, _)| r)
            .collect();
        assert!(perimees.is_empty(), "exceptions qui ne servent plus : {perimees:#?}");
    }

    #[test]
    fn le_garde_powershell_voit_une_variable_nue() {
        assert_eq!(
            ps_douteux("\"Get-ChildItem $env:TEMP -Force\""),
            [("$env:TEMP".to_string(), 1)]
        );
        assert_eq!(
            ps_douteux("x\n\"Remove-Item \\\"$env:SystemRoot\\\\Minidump\\\\*\\\" -Force\""),
            [("$env:SystemRoot".to_string(), 2)]
        );
        assert_eq!(ps_douteux("\"Get-ChildItem -LiteralPath $d -File\""), []);
        assert_eq!(ps_douteux("\"Get-ChildItem 'C:\\\\Windows' -File\""), []);
    }

    /// Le garde lui-même : il voit un nom glissé tel quel, et laisse passer sh_chaine et les constantes.
    #[test]
    fn le_garde_voit_un_nom_glisse_tel_quel() {
        let piege = "fn f(nom: &str) { let c = format!(\"sudo rm -f {nom}\"); }";
        assert_eq!(douteux(piege), [("nom".to_string(), 1)]);
        let positionnel = "let c = format!(\"echo ok; sudo cupsenable {}\", i.nom);";
        assert_eq!(douteux(positionnel), [("i.nom".to_string(), 1)]);
        let protege = "let cite = sh_chaine(nom);\nlet c = format!(\"sudo rm -f {cite} {} {DOSSIER}\", crate::commande::sh_chaine(&x));";
        assert_eq!(douteux(protege), []);
        let sans_sudo = "let c = format!(\"ls {nom}\");";
        assert_eq!(douteux(sans_sudo), []);
        assert!(!lance_sudo_ou_rm("format ce disque") && lance_sudo_ou_rm("a && rm -rf x"));
    }
}

#[cfg(test)]
mod tests_lancer_vers {
    use super::*;

    #[test]
    fn la_fin_gardee_commence_a_une_ligne() {
        let morceaux = |m: &[&str]| m.iter().map(|t| t.as_bytes().to_vec()).collect();
        // Tout tient : rien ne tombe.
        assert_eq!(
            garder_la_fin(morceaux(&["a\nb", "\nc\n"]), 10),
            (b"a\nb\nc\n".to_vec(), false)
        );
        // Dix octets au plus : « un\n » tombe, et « eux\n » aussi, coupée en plein milieu.
        let (gardes, coupe) = garder_la_fin(morceaux(&["un\ndeux\n", "trois\n"]), 10);
        assert!(coupe);
        assert_eq!(gardes, b"trois\n".to_vec());
        // La coupure tombe juste après un saut de ligne : la ligne suivante reste entière.
        assert_eq!(garder_la_fin(morceaux(&["un\n", "deux\n"]), 5).0, b"deux\n".to_vec());
        // Une seule ligne trop longue : rien ne reste plutôt qu'une ligne coupée.
        assert_eq!(garder_la_fin(morceaux(&["abcdefghij"]), 4), (Vec::new(), true));
    }

    #[cfg(unix)]
    /// Nommé par processus : verifier.sh lance deux suites Linux en même temps (avec et sans Internet) sur le même
    /// dossier jetable, et le `sh` de l'une écrivait « apres » dans le fichier que l'autre relisait.
    fn fichier_jetable(nom: &str) -> (std::path::PathBuf, std::fs::File) {
        let dossier = crate::socle::dossier_local();
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join(format!("{}-{nom}", std::process::id()));
        (chemin.clone(), std::fs::File::create(&chemin).unwrap())
    }

    /// Une sortie de 200 000 octets bornée à 1 000 : le début seul, la commande arrêtée ; ou la fin seule, en
    /// commençant par une ligne entière.
    #[cfg(unix)]
    #[test]
    fn sortie_bornee_dans_un_fichier() {
        let (chemin, f) = fichier_jetable("debut.txt");
        let mut c = Command::new("sh");
        c.args(["-c", "i=0; while [ $i -lt 20000 ]; do echo ligne$i; i=$((i+1)); done"]);
        let e = lancer_vers(&mut c, 30, &f, 1000, Garder::Debut).unwrap();
        assert!(e.tronque && !e.delai && e.octets == 1000);
        let texte = std::fs::read_to_string(&chemin).unwrap();
        assert!(texte.starts_with("ligne0\nligne1\n") && texte.len() == 1000);

        let (chemin, f) = fichier_jetable("fin.txt");
        let mut c = Command::new("sh");
        c.args(["-c", "i=0; while [ $i -lt 20000 ]; do echo ligne$i; i=$((i+1)); done"]);
        let e = lancer_vers(&mut c, 30, &f, 1000, Garder::Fin).unwrap();
        assert!(e.tronque && e.code == Some(0));
        let texte = std::fs::read_to_string(&chemin).unwrap();
        assert!(texte.ends_with("ligne19999\n") && texte.starts_with("ligne") && texte.len() <= 1000);

        // Sous la borne : tout, sans troncature ; le délai passé, la commande est arrêtée et le début reste.
        let (chemin, f) = fichier_jetable("court.txt");
        let e = lancer_vers(Command::new("echo").arg("bonjour"), 10, &f, 1000, Garder::Debut).unwrap();
        assert!(!e.tronque && e.code == Some(0));
        assert_eq!(std::fs::read_to_string(&chemin).unwrap(), "bonjour\n");
        let (chemin, f) = fichier_jetable("lent.txt");
        let mut c = Command::new("sh");
        c.args(["-c", "echo avant; sleep 30; echo apres"]);
        let e = lancer_vers(&mut c, 1, &f, 1000, Garder::Debut).unwrap();
        assert!(e.delai && e.code.is_none());
        assert_eq!(std::fs::read_to_string(&chemin).unwrap(), "avant\n");
    }
}

#[cfg(all(test, unix))]
mod tests_lancer_borne {
    use super::*;

    /// Un programme sans fin de sortie (yes) est arrêté à la borne ; un programme trop lent, au délai ; dans les deux
    /// cas, le début de ce qu'il a écrit reste.
    #[test]
    fn sortie_et_delai_bornes() {
        let debut = Instant::now();
        let r = lancer_borne(&mut Command::new("yes"), 30, 4096).unwrap();
        assert!(r.tronque && !r.delai && r.code.is_none());
        assert!(r.sortie.len() <= 4096 && r.sortie.starts_with("y\ny\n"));
        assert!(debut.elapsed() < Duration::from_secs(10));

        let debut = Instant::now();
        let mut c = Command::new("sh");
        c.args(["-c", "echo avant; sleep 30; echo apres"]);
        let r = lancer_borne(&mut c, 1, 4096).unwrap();
        assert!(r.delai && !r.tronque);
        assert_eq!(r.sortie, "avant\n");
        assert!(debut.elapsed() < Duration::from_secs(8));

        let mut c = Command::new("sh");
        c.args(["-c", "echo ok; echo oups >&2; exit 4"]);
        let r = lancer_borne(&mut c, 5, 4096).unwrap();
        assert_eq!(
            (r.code, r.sortie.as_str(), r.erreurs.as_str()),
            (Some(4), "ok\n", "oups\n")
        );
        assert!(lancer_borne(&mut Command::new("/nexiste/pas"), 5, 10).is_none());
    }

    /// Un programme dans sa propre session (comme un plugin) qui laisse un petit-enfant détaché : celui-ci est arrêté
    /// avec lui, il n'écrit plus rien ensuite. Linux seulement : c'est waitid (WNOWAIT) qui laisse arrêter le groupe
    /// avant que son numéro ne resserve, et macOS ne le permet pas (le CHANGELOG le dit ; vu sur le Mac de GitHub).
    #[cfg(target_os = "linux")]
    #[test]
    fn un_petit_enfant_detache_ne_survit_pas() {
        use std::os::unix::process::CommandExt;
        let temoin = std::env::temp_dir().join(format!("vanguard-groupe-{}", std::process::id()));
        let _ = std::fs::remove_file(&temoin);
        let mut c = Command::new("sh");
        c.arg("-c").arg(format!(
            "(sleep 2; touch {}) >/dev/null 2>&1 & echo parti",
            temoin.display()
        ));
        // SAFETY : seul setsid entre fork et exec (sûr dans ce contexte, comme pour un plugin).
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let r = lancer_borne(&mut c, 10, 4096).unwrap();
        assert_eq!((r.code, r.sortie.as_str()), (Some(0), "parti\n"));
        std::thread::sleep(Duration::from_secs(3));
        assert!(!temoin.exists(), "le petit-enfant a survécu");
    }
}

/// Sous Windows, aucun programme lancé par son seul nom : la liste de ceux qui restent, lue dans les sources
/// compilées pour Windows (les `cfg` des modules et des blocs sont suivis, les tests mis à part).
#[cfg(all(test, unix))]
mod tests_noms_nus {
    use std::collections::HashMap;
    use std::path::Path;

    /// Le prédicat d'un `#[cfg(…)]` est-il vrai pour le programme Windows (hors tests) ? Ce qui n'est ni un système
    /// ni `test` (fonction, `debug_assertions`) compte pour vrai : mieux vaut lire un bloc de trop qu'en oublier un.
    fn vrai_sous_windows(p: &str) -> bool {
        let p = p.trim();
        let interieur = |prefixe: &str| p.strip_prefix(prefixe).and_then(|r| r.strip_suffix(')'));
        if let Some(r) = interieur("not(") {
            return !vrai_sous_windows(r);
        }
        for (prefixe, tous) in [("any(", false), ("all(", true)] {
            if let Some(r) = interieur(prefixe) {
                let mut parties = Vec::new();
                let (mut profondeur, mut debut) = (0, 0);
                for (i, c) in r.char_indices() {
                    match c {
                        '(' => profondeur += 1,
                        ')' => profondeur -= 1,
                        ',' if profondeur == 0 => {
                            parties.push(&r[debut..i]);
                            debut = i + 1;
                        }
                        _ => {}
                    }
                }
                parties.push(&r[debut..]);
                let parties = parties.into_iter().filter(|x| !x.trim().is_empty());
                return if tous {
                    parties.into_iter().all(vrai_sous_windows)
                } else {
                    parties.into_iter().any(vrai_sous_windows)
                };
            }
        }
        match p {
            "windows" => true,
            "unix" | "test" => false,
            _ if p.starts_with("target_os") || p.starts_with("target_family") => p.contains("\"windows\""),
            _ => true,
        }
    }

    fn retrait(l: &str) -> usize {
        l.len() - l.trim_start().len()
    }

    /// Les `#[cfg(…)]` posés juste au-dessus de la ligne `n` sont-ils tous vrais sous Windows ?
    fn attributs_vrais(lignes: &[&str], n: usize) -> bool {
        for l in lignes[..n].iter().rev().map(|l| l.trim()) {
            if let Some(p) = l.strip_prefix("#[cfg(").and_then(|r| r.strip_suffix(")]")) {
                if !vrai_sous_windows(p) {
                    return false;
                }
            } else if !(l.starts_with("#[") || l.starts_with("//")) {
                break;
            }
        }
        true
    }

    /// La ligne `n` est-elle compilée sous Windows ? Ses attributs, puis ceux de chaque ligne qui l'englobe (moins
    /// en retrait : fonction, bloc, instruction coupée sur plusieurs lignes), jusqu'au haut du fichier.
    fn ligne_sous_windows(lignes: &[&str], n: usize) -> bool {
        if !attributs_vrais(lignes, n) {
            return false;
        }
        let mut niveau = retrait(lignes[n]);
        for j in (0..n).rev() {
            let l = lignes[j];
            let t = l.trim_start();
            if t.is_empty() || niveau == 0 || retrait(l) >= niveau {
                continue;
            }
            if ["//", "#[", "}", ")", "]"].iter().any(|d| t.starts_with(d)) {
                continue;
            }
            niveau = retrait(l);
            if !attributs_vrais(lignes, j) {
                return false;
            }
        }
        // Le fichier entier sous `#![cfg(…)]`.
        lignes
            .iter()
            .filter_map(|l| l.trim().strip_prefix("#![cfg(").and_then(|r| r.strip_suffix(")]")))
            .all(vrai_sous_windows)
    }

    /// Le fichier `nom` (relatif à src/) est-il compilé sous Windows ? Sa déclaration `mod` chez son parent, puis
    /// celle du parent, jusqu'à main.rs.
    fn fichier_sous_windows(fichiers: &HashMap<&str, &str>, nom: &str) -> bool {
        if nom == "main.rs" {
            return true;
        }
        let chemin = Path::new(nom);
        let (module, dossier) = if chemin.file_stem().is_some_and(|s| s == "mod") {
            let d = chemin.parent().unwrap();
            (d.file_name().unwrap().to_string_lossy(), d.parent().unwrap())
        } else {
            (chemin.file_stem().unwrap().to_string_lossy(), chemin.parent().unwrap())
        };
        let dossier = dossier.to_string_lossy();
        let parents = if dossier.is_empty() {
            vec!["main.rs".to_string()]
        } else {
            vec![format!("{dossier}/mod.rs"), format!("{dossier}.rs")]
        };
        let Some((parent, src)) = parents.iter().find_map(|p| fichiers.get(p.as_str()).map(|s| (p, *s))) else {
            return true;
        };
        let lignes: Vec<&str> = src.lines().collect();
        let declaration = format!("mod {module};");
        let Some(n) = lignes.iter().position(|l| l.trim().ends_with(&declaration)) else {
            return true;
        };
        ligne_sous_windows(&lignes, n) && fichier_sous_windows(fichiers, parent)
    }

    /// Les `Command::new("nom")` compilés sous Windows dont le littéral n'est pas un chemin : (fichier:ligne, texte).
    fn noms_nus(fichiers: &[(String, String)]) -> Vec<String> {
        let index: HashMap<&str, &str> = fichiers.iter().map(|(n, s)| (n.as_str(), s.as_str())).collect();
        let mut trouves = Vec::new();
        for (nom, src) in fichiers {
            if !fichier_sous_windows(&index, nom) {
                continue;
            }
            // Les tests des modules lancent leurs propres commandes, et pas sous Windows.
            let code = src.find("#[cfg(test)]\nmod ").map_or(src.as_str(), |t| &src[..t]);
            let lignes: Vec<&str> = code.lines().collect();
            for (n, l) in lignes.iter().enumerate() {
                for (i, _) in l.match_indices("Command::new(") {
                    let mut apres = l[i + "Command::new(".len()..].trim_start();
                    // rustfmt coupe un appel trop long : le littéral passe alors à la ligne suivante.
                    if apres.is_empty() {
                        apres = lignes.get(n + 1).map_or("", |s| s.trim_start());
                    }
                    let Some(texte) = apres.strip_prefix('"').and_then(|r| r.split('"').next()) else {
                        continue;
                    };
                    if !texte.contains(['\\', '/']) && ligne_sous_windows(&lignes, n) {
                        trouves.push(format!("{nom}:{} : {texte}", n + 1));
                    }
                }
            }
        }
        trouves
    }

    #[test]
    fn aucun_programme_lance_par_son_seul_nom_sous_windows() {
        let base = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut fichiers = Vec::new();
        super::tests_sh_chaine::sources(base, base, &mut fichiers);
        let restes = noms_nus(&fichiers);
        assert!(
            restes.is_empty(),
            "programme lancé par son seul nom sous Windows : passe-le par commande::systeme, systeme32 ou cmd \
             (sinon Windows le cherche d'abord à côté de Vanguard) :\n{}",
            restes.join("\n")
        );
    }

    #[test]
    fn le_lecteur_suit_les_cfg() {
        assert!(vrai_sous_windows("windows") && vrai_sous_windows("any(windows, test)"));
        assert!(!vrai_sous_windows("unix") && !vrai_sous_windows("target_os = \"linux\""));
        assert!(vrai_sous_windows("not(target_os = \"linux\")") && !vrai_sous_windows("all(test, windows)"));
        let src = "fn a() {\n    #[cfg(unix)]\n    let x = lancer(\n        Command::new(\"sh\"),\n    );\n    \
                   #[cfg(windows)]\n    {\n        Command::new(\"netstat\");\n    }\n}\n";
        let fichiers = vec![("main.rs".to_string(), src.to_string())];
        assert_eq!(noms_nus(&fichiers), ["main.rs:8 : netstat"]);
        // Un module déclaré sous cfg(unix) n'est pas lu.
        let fichiers = vec![
            ("main.rs".to_string(), "#[cfg(unix)]\nmod b;\nmod c;\n".to_string()),
            ("b.rs".to_string(), "fn f() { Command::new(\"bash\"); }\n".to_string()),
            (
                "c.rs".to_string(),
                "fn f() { Command::new(\"cmd\"); Command::new(r\"C:\\x.exe\"); }\n".to_string(),
            ),
        ];
        assert_eq!(noms_nus(&fichiers), ["c.rs:1 : cmd"]);
    }

    /// Un appel coupé par rustfmt, le nom seul sur la ligne suivante, est vu aussi (à la ligne de l'appel).
    #[test]
    fn le_lecteur_voit_un_appel_coupe() {
        let src = "fn f() {\n    let sortie = lancer(\n        Command::new(\n            \"wevtutil\",\n        )\n        \
                   .args([\"qe\", \"System\"]),\n    );\n}\n";
        let fichiers = vec![("main.rs".to_string(), src.to_string())];
        assert_eq!(noms_nus(&fichiers), ["main.rs:3 : wevtutil"]);
    }
}

#[cfg(all(test, windows))]
mod tests_systeme32 {
    /// Le chemin donné par Windows, complet, « .exe » ajouté seulement s'il manque ; cmd.exe y est (Wine compris).
    #[test]
    fn programmes_du_systeme_par_leur_chemin() {
        let dossier = super::dossier_systeme();
        assert!(dossier.is_absolute(), "{}", dossier.display());
        assert_eq!(super::systeme32("netstat"), dossier.join("netstat.exe"));
        assert_eq!(super::systeme32("chcp.com"), dossier.join("chcp.com"));
        assert!(super::systeme32("cmd").is_file());
        assert_eq!(
            super::systeme("netstat").get_program(),
            dossier.join("netstat.exe").as_os_str()
        );
    }
}
