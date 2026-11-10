//! Le relais (Linux) : la séparation des droits de la fenêtre. Au démarrage, avant tout fil et toute bibliothèque
//! d'affichage, la fenêtre se dédouble (fork) : l'enfant, le relais, garde les droits du compte et lance `vanguard` ;
//! la fenêtre se met dans son bac à sable (`bac_a_sable`) et ne fait plus que lui demander, par une socket, une
//! commande de la liste fermée, par son numéro. `vanguard` part ainsi du relais et n'hérite pas du bac : il voit tout
//! ce qu'il doit voir (les programmes en cours, le bus système, sudo).
//!
//! Le relais ne fait confiance à rien de ce que dit la fenêtre (c'est elle qu'on protège de ce qu'elle dessine) : une
//! demande est un numéro de la liste fermée, la langue, ou un arrêt ; rien d'autre n'est compris, et une demande
//! hors de ce protocole l'arrête. Il retrouve lui-même le `vanguard` voisin et rejoue sa garde (`lanceur`). Il ne
//! se laisse pas observer (PR_SET_DUMPABLE à 0 : ni ptrace ni /proc/<pid>/mem du même compte), et Landlock empêche
//! de toute façon la fenêtre d'observer ce qui est hors de son bac. Quand la fenêtre se ferme ou meurt, la socket se
//! ferme : le relais arrête ce qui tourne et s'en va. Le protocole, sans rien d'autre, est dans `protocole`.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, mpsc};
use std::time::Duration;

use crate::commandes::Commande;
use crate::lanceur::{Fin, Issue, Message, Programme, Rendre, Reveil, SORTIE_MAX, Tache};
use crate::protocole::{DEMANDE_MAX, Demande, Reponse, coder_fin, coder_ligne, ecrire_trame, lire_reponse, lire_trame};

/// Une réponse du relais : la sortie bornée, son texte d'erreur et l'en-tête.
const REPONSE_MAX: usize = SORTIE_MAX + 64 * 1024;
/// Commandes en même temps au plus (la fenêtre en lance une à la fois ; une qui finit de s'arrêter, en plus).
const TACHES_MAX: usize = 2;
/// Une fenêtre qui ne lit plus ne bloque pas le relais au-delà.
const ECRITURE_DELAI: Duration = Duration::from_secs(10);

static CLIENT: OnceLock<Client> = OnceLock::new();
static ETAT: OnceLock<(String, bool)> = OnceLock::new();

/// Le relais de la fenêtre, s'il a démarré.
pub fn client() -> Option<&'static Client> {
    CLIENT.get()
}

/// La phrase du bac à sable pour la console (et si elle est à souligner), une fois `separer` passé.
pub fn etat() -> Option<&'static (String, bool)> {
    ETAT.get()
}

/// Met le relais à part puis la fenêtre dans son bac à sable. À appeler au tout début, tant que la fenêtre n'a qu'un
/// fil (le dédoublement n'emporte que le fil appelant ; le bac ne s'applique qu'à lui et à ce qu'il crée). Si le
/// relais ne peut pas démarrer, la fenêtre reste libre (et le dit) : restreinte, elle lancerait un `vanguard` qui ne
/// verrait plus tout.
pub fn separer() {
    // Dédoubler un processus qui a déjà plusieurs fils laisserait l'enfant avec des verrous que personne ne rendra.
    let n = crate::bac_a_sable::fils();
    let etat = if n == 1 {
        match UnixStream::pair() {
            Err(e) => absent(&e.to_string()),
            Ok((fenetre, relais)) => match dedoubler() {
                Err(e) => absent(&e.to_string()),
                Ok(0) => {
                    drop(fenetre);
                    devenir_relais(relais)
                }
                Ok(pid) => {
                    drop(relais);
                    let bac = crate::bac_a_sable::restreindre();
                    let _ = CLIENT.set(Client::demarrer(fenetre, Some(pid)));
                    bac.phrase()
                }
            },
        }
    } else {
        absent(&crate::trf!("{} fils déjà là", "{} threads already there", n))
    };
    let _ = ETAT.set(etat);
}

fn absent(e: &str) -> (String, bool) {
    crate::bac_a_sable::Bac::Absent {
        raison: crate::trf!(
            "le relais n'a pas pu démarrer : {}",
            "the relay could not start: {}",
            crate::nettoyage::nom(e, 100)
        ),
        nnp: false,
    }
    .phrase()
}

/// Le relais : ses entrée et sortie au néant (la sortie de la fenêtre est le tuyau que `vanguard` lit jusqu'à
/// « ouverte » : le relais ne doit pas le garder ouvert), invisible au débogage, puis il sert jusqu'à la fermeture.
fn devenir_relais(flux: UnixStream) -> ! {
    systeme::preparer_relais();
    servir(flux, Programme::voisin);
    std::process::exit(0)
}

fn verrou<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Le côté relais : lit les demandes jusqu'à la fermeture (ou une demande hors protocole), lance chaque commande
/// avec la surveillance de `lanceur` et renvoie ses lignes puis sa fin. À la fin, arrête ce qui tourne et l'attend.
fn servir(flux: UnixStream, trouver: impl Fn() -> Result<Programme, String> + Send + Sync + 'static) {
    let Ok(sortie) = flux.try_clone() else {
        return;
    };
    let _ = sortie.set_write_timeout(Some(ECRITURE_DELAI));
    let sortie = Arc::new(Mutex::new(sortie));
    let envoyer = {
        let sortie = Arc::clone(&sortie);
        Arc::new(move |t: &[u8]| {
            let _ = ecrire_trame(&mut *verrou(&sortie), t);
        })
    };
    let trouver = Arc::new(trouver);
    let taches: Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>> = Arc::default();
    let mut fils: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let mut entree = flux;
    while let Ok(Some(t)) = lire_trame(&mut entree, DEMANDE_MAX) {
        let Some(d) = Demande::lire(&t) else {
            break;
        };
        match d {
            Demande::Arreter { id } => {
                if let Some(a) = verrou(&taches).get(&id) {
                    a.store(true, Ordering::Relaxed);
                }
            }
            Demande::Lancer { id, commande, anglais } => {
                let arret = Arc::new(AtomicBool::new(false));
                let refus = {
                    let mut t = verrou(&taches);
                    if t.len() >= TACHES_MAX || t.contains_key(&id) {
                        true
                    } else {
                        t.insert(id, Arc::clone(&arret));
                        false
                    }
                };
                let impossible = |texte: String| Fin {
                    commande,
                    code: None,
                    sortie: Vec::new(),
                    issue: Issue::Impossible(texte),
                    duree: Duration::ZERO,
                };
                if refus {
                    envoyer(&coder_fin(
                        id,
                        &impossible(crate::tr!("trop de commandes en même temps", "too many commands at once").into()),
                    ));
                    continue;
                }
                let rendre: Rendre = {
                    let envoyer = Arc::clone(&envoyer);
                    Arc::new(move |m| {
                        if let Message::Ligne(l) = m {
                            envoyer(&coder_ligne(id, &l));
                        }
                    })
                };
                let (envoyer2, taches2, trouver2) = (Arc::clone(&envoyer), Arc::clone(&taches), Arc::clone(&trouver));
                let lance = std::thread::Builder::new()
                    .name("vanguard-relais".into())
                    .spawn(move || {
                        let fin = match trouver2() {
                            Ok(p) => crate::lanceur::surveiller(&p, commande, anglais, &arret, &rendre),
                            Err(e) => Fin {
                                commande,
                                code: None,
                                sortie: Vec::new(),
                                issue: Issue::Impossible(e),
                                duree: Duration::ZERO,
                            },
                        };
                        envoyer2(&coder_fin(id, &fin));
                        verrou(&taches2).remove(&id);
                    });
                match lance {
                    Ok(f) => fils.push(f),
                    Err(e) => {
                        verrou(&taches).remove(&id);
                        envoyer(&coder_fin(id, &impossible(e.to_string())));
                    }
                }
                fils.retain(|f| !f.is_finished());
            }
        }
    }
    // La fenêtre est partie (ou parle hors protocole) : ce qui tourne est arrêté, puis attendu.
    for a in verrou(&taches).values() {
        a.store(true, Ordering::Relaxed);
    }
    for f in fils {
        let _ = f.join();
    }
}

/// Une tâche de la fenêtre qui attend sa fin du relais.
struct Attente {
    commande: Commande,
    envoi: mpsc::Sender<Message>,
    reveil: Reveil,
}

/// Le côté fenêtre : demande au relais et rend ses réponses aux tâches.
pub struct Client {
    sortie: Mutex<UnixStream>,
    attente: Arc<Mutex<HashMap<u32, Attente>>>,
    /// Le relais est parti : plus rien ne se lance (sans lui, la fenêtre restreinte ne lancerait qu'un `vanguard`
    /// qui ne voit pas tout). Posé sous le verrou d'`attente`.
    mort: Arc<AtomicBool>,
    suivant: AtomicU32,
}

impl Client {
    /// Le lecteur des réponses part en fond (créé après le bac à sable : il y est aussi). `relais` : son numéro, pour
    /// le récolter quand la socket se ferme.
    fn demarrer(flux: UnixStream, relais: Option<i32>) -> Client {
        let attente: Arc<Mutex<HashMap<u32, Attente>>> = Arc::default();
        let mort = Arc::new(AtomicBool::new(false));
        let lecteur = flux.try_clone().and_then(|mut entree| {
            let (attente, mort) = (Arc::clone(&attente), Arc::clone(&mort));
            std::thread::Builder::new()
                .name("vanguard-relais".into())
                .spawn(move || {
                    lire_reponses(&mut entree, &attente);
                    let restes: Vec<Attente> = {
                        let mut a = verrou(&attente);
                        mort.store(true, Ordering::Relaxed);
                        a.drain().map(|(_, x)| x).collect()
                    };
                    for a in restes {
                        rendre_fin(&a, None, Issue::Impossible(relais_parti()), Duration::ZERO, Vec::new());
                    }
                    if let Some(pid) = relais {
                        systeme::recolter(pid);
                    }
                })
        });
        if lecteur.is_err() {
            mort.store(true, Ordering::Relaxed);
        }
        Client {
            sortie: Mutex::new(flux),
            attente,
            mort,
            suivant: AtomicU32::new(1),
        }
    }

    pub fn lancer(&self, commande: Commande, anglais: bool, reveil: &Reveil) -> Tache {
        let (envoi, recu) = mpsc::channel();
        let id = self.suivant.fetch_add(1, Ordering::Relaxed);
        let a = Attente {
            commande,
            envoi,
            reveil: Arc::clone(reveil),
        };
        let refus = {
            let mut attente = verrou(&self.attente);
            if self.mort.load(Ordering::Relaxed) {
                Some(a)
            } else {
                attente.insert(id, a);
                None
            }
        };
        let refus = refus.or_else(|| {
            let d = Demande::Lancer { id, commande, anglais };
            ecrire_trame(&mut *verrou(&self.sortie), &d.coder())
                .err()
                .and_then(|_| verrou(&self.attente).remove(&id))
        });
        if let Some(a) = refus {
            rendre_fin(&a, None, Issue::Impossible(relais_parti()), Duration::ZERO, Vec::new());
        }
        Tache::relayee(commande, id, recu)
    }

    /// Pour les tests : ferme la socket (le relais l'apprend et s'en va, le lecteur aussi).
    #[cfg(test)]
    fn fermer(&self) {
        let _ = verrou(&self.sortie).shutdown(std::net::Shutdown::Both);
    }

    pub fn arreter(&self, id: u32) {
        let _ = ecrire_trame(&mut *verrou(&self.sortie), &Demande::Arreter { id }.coder());
    }
}

fn relais_parti() -> String {
    crate::tr!(
        "le relais de la fenêtre s'est arrêté ; rouvrez la fenêtre",
        "the window's relay stopped; reopen the window"
    )
    .into()
}

fn rendre_fin(a: &Attente, code: Option<i32>, issue: Issue, duree: Duration, sortie: Vec<u8>) {
    let _ = a.envoi.send(Message::Fin(Fin {
        commande: a.commande,
        code,
        sortie,
        issue,
        duree,
    }));
    (a.reveil)();
}

/// Lit les réponses jusqu'à la fermeture du relais (ou une réponse illisible) et les rend à leurs tâches. La
/// commande d'une fin est celle que la fenêtre a demandée, jamais une que le relais dirait.
fn lire_reponses(entree: &mut UnixStream, attente: &Mutex<HashMap<u32, Attente>>) {
    while let Ok(Some(t)) = lire_trame(entree, REPONSE_MAX) {
        match lire_reponse(&t) {
            Some(Reponse::Ligne(id, l)) => {
                if let Some(a) = verrou(attente).get(&id) {
                    let _ = a.envoi.send(Message::Ligne(l));
                    (a.reveil)();
                }
            }
            Some(Reponse::Fin {
                id,
                code,
                issue,
                duree,
                sortie,
            }) => {
                let a = verrou(attente).remove(&id);
                if let Some(a) = a {
                    rendre_fin(&a, code, issue, duree, sortie);
                }
            }
            None => return,
        }
    }
}

mod systeme {
    /// Le dédoublement : 0 dans l'enfant, son numéro dans le parent.
    // raison : FFI de fork (libc), que std ne fait pas sans exec ; appelé quand la fenêtre n'a qu'un fil.
    #[allow(unsafe_code)]
    pub fn dedoubler() -> std::io::Result<i32> {
        // SAFETY: appelé au début de main, avant tout autre fil (`relais::separer`, vérifié par le bac à sable qui
        // suit) : l'enfant reprend un processus entier, sans verrou tenu par un fil disparu, et peut tout faire.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(pid)
        }
    }

    /// Le relais : entrée et sortie au néant, non observable (ni ptrace ni /proc/<pid>/mem), et nommé.
    // raison : FFI de dup2 et prctl (libc), que std ne sait pas faire.
    #[allow(unsafe_code)]
    pub fn preparer_relais() {
        use std::os::fd::AsRawFd;
        if let Ok(rien) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null") {
            // SAFETY: dup2 ne reçoit que des numéros de descripteurs ouverts (`rien`, gardé jusqu'après, et 0, 1) ;
            // il ne touche aucune mémoire du programme.
            unsafe {
                libc::dup2(rien.as_raw_fd(), libc::STDIN_FILENO);
                libc::dup2(rien.as_raw_fd(), libc::STDOUT_FILENO);
            }
        }
        let nom = c"vanguard-relais";
        // SAFETY: prctl ne reçoit que des entiers, et pour PR_SET_NAME un nom terminé par zéro (16 octets au plus,
        // lu pendant l'appel) qui vit jusqu'à la fin du programme.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            libc::prctl(libc::PR_SET_NAME, nom.as_ptr(), 0, 0, 0);
        }
    }

    /// Récolte le relais parti (pas de zombie tant que la fenêtre reste ouverte).
    // raison : FFI de waitpid (libc) sur un numéro que std ne connaît pas (le relais vient de fork).
    #[allow(unsafe_code)]
    pub fn recolter(pid: i32) {
        let mut statut = 0;
        // SAFETY: waitpid écrit un entier, à nous, vivant pendant l'appel ; `pid` est le relais, notre enfant, que
        // rien d'autre ne récolte.
        let _ = unsafe { libc::waitpid(pid, &raw mut statut, 0) };
    }
}

use systeme::dedoubler;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Le relais en fil, et une fenêtre qui lui parle : une commande inconnue de lui (pas de `vanguard` voisin) finit
    /// « impossible », un arrêt d'une tâche inconnue ne fait rien, et une demande hors protocole le ferme : les tâches
    /// en attente l'apprennent, et plus rien ne se lance.
    #[test]
    fn le_relais_se_ferme_sur_une_demande_hors_protocole() {
        let (fenetre, relais) = UnixStream::pair().unwrap();
        let serveur = std::thread::spawn(move || servir(relais, || Err("introuvable".into())));
        let c = Client::demarrer(fenetre.try_clone().unwrap(), None);
        let rien: Reveil = Arc::new(|| {});
        let attendre = attendre_fin;
        let f = attendre(&c.lancer(Commande::Protection, false, &rien));
        assert_eq!(
            (f.commande, f.issue),
            (Commande::Protection, Issue::Impossible("introuvable".into()))
        );
        c.arreter(12345);
        ecrire_trame(&mut &fenetre, &[9, 9, 9]).unwrap();
        serveur.join().unwrap();
        let f = attendre(&c.lancer(Commande::Bilan, false, &rien));
        assert!(matches!(f.issue, Issue::Impossible(_)), "{:?}", f.issue);
        assert!(c.mort.load(Ordering::Relaxed));
    }

    fn attendre_fin(t: &Tache) -> Fin {
        let debut = Instant::now();
        loop {
            if let Some(Message::Fin(f)) = t.recevoir().into_iter().find(|m| matches!(m, Message::Fin(_))) {
                return f;
            }
            assert!(debut.elapsed() < Duration::from_secs(20), "jamais fini");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Le dossier de l'essai du bac à sable, passé au processus d'essai relancé.
    const ESSAI_BAC: &str = "VANGUARD_FENETRE_ESSAI_BAC";

    /// Pour de vrai : le fil d'essai (la fenêtre) entre dans le bac à sable ; le relais, parti avant lui (comme le
    /// relais part avant que la fenêtre se restreigne), lance un faux `vanguard` qui écrit un fichier et lance un
    /// programme. La fenêtre, elle, ne peut ni écrire, ni lancer, ni se connecter. Dans un processus d'essai à part
    /// (ce même programme de tests, relancé sur ce seul test) : le bac ne se retire pas, il ne doit pas suivre les
    /// autres tests.
    #[test]
    fn le_bac_retient_la_fenetre_et_pas_ce_que_le_relais_lance() {
        use std::os::unix::fs::PermissionsExt;
        if let Some(d) = std::env::var_os(ESSAI_BAC) {
            return essai_dans_le_bac(std::path::Path::new(&d));
        }
        let d = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("essais-fenetre")
            .join(format!("bac-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = d.join("vanguard");
        // Le faux `vanguard` : un fichier écrit, un programme lancé, une sortie JSON.
        std::fs::write(
            &f,
            "#!/bin/sh\necho ecrit > \"$(dirname \"$0\")/ecrit\" && /bin/sh -c 'echo \"{}\"'\n",
        )
        .unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        let nom = "relais::tests::le_bac_retient_la_fenetre_et_pas_ce_que_le_relais_lance";
        let sortie = std::process::Command::new(std::env::current_exe().unwrap())
            .args([nom, "--exact", "--nocapture", "--test-threads=1"])
            .env(ESSAI_BAC, &d)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let texte = String::from_utf8_lossy(&sortie.stdout).into_owned() + &String::from_utf8_lossy(&sortie.stderr);
        let _ = std::fs::remove_dir_all(&d);
        if let Some(raison) = texte.lines().find_map(|l| l.strip_prefix("BAC-SAUTÉ ")) {
            return sauter(raison);
        }
        assert!(sortie.status.success() && texte.contains("BAC-OK"), "{texte}");
    }

    /// Un essai qui n'a rien vérifié le dit, et verifier.sh le compte (`VANGUARD_TESTS_SAUTES`, comme `essais::saute`
    /// du programme).
    #[track_caller]
    fn sauter(raison: &str) {
        let ou = std::panic::Location::caller();
        let nom = std::thread::current().name().unwrap_or("?").to_string();
        eprintln!("essai SAUTÉ ({nom}) : {raison}");
        if let Some(fichier) = std::env::var_os("VANGUARD_TESTS_SAUTES")
            && let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(fichier)
        {
            use std::io::Write;
            let _ = writeln!(f, "{nom}\t{raison}\t{}:{}", ou.file(), ou.line());
        }
    }

    fn essai_dans_le_bac(d: &std::path::Path) {
        use std::os::unix::fs::MetadataExt;
        let moi = std::fs::metadata(d.join("vanguard")).unwrap().uid();
        let (fenetre, relais) = UnixStream::pair().unwrap();
        let dossier = d.to_path_buf();
        let serveur = std::thread::spawn(move || servir(relais, move || Programme::dans(&dossier, moi)));
        assert!(crate::bac_a_sable::sans_nouveaux_droits());
        let abi = match crate::bac_a_sable::poser() {
            Ok((abi, _)) => abi,
            Err(e) => {
                println!("BAC-SAUTÉ Landlock absent ({e})");
                return;
            }
        };
        // La fenêtre : ni écrire, ni lancer, ni (Landlock 4 et plus) se connecter.
        let ecrire = std::fs::write(d.join("de-la-fenetre"), b"x");
        assert_eq!(ecrire.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert!(std::process::Command::new("/bin/true").status().is_err());
        if abi >= 4 {
            let tcp = std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], 9).into(), Duration::from_secs(2));
            assert_eq!(tcp.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        }
        // Ce que le relais lance, lui, a tous les droits du compte.
        let c = Client::demarrer(fenetre, None);
        let rien: Reveil = Arc::new(|| {});
        let f = attendre_fin(&c.lancer(Commande::Bilan, false, &rien));
        assert_eq!(
            (f.commande, &f.issue, f.code),
            (Commande::Bilan, &Issue::Terminee, Some(0)),
            "{:?}",
            f.issue
        );
        assert_eq!(f.sortie, b"{}\n");
        assert_eq!(std::fs::read(d.join("ecrit")).unwrap(), b"ecrit\n");
        c.fermer();
        serveur.join().unwrap();
        println!("BAC-OK");
    }
}
