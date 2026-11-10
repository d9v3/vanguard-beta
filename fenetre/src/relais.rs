//! Le relais (Linux) : la séparation des droits de la fenêtre. Au démarrage, avant tout fil et toute bibliothèque
//! d'affichage, la fenêtre se dédouble (fork) : l'enfant, le relais, garde les droits du compte et lance `vanguard` ;
//! la fenêtre se met dans son bac à sable (`bac_a_sable`) et ne fait plus que lui demander, par une socket, une
//! commande de la liste fermée, par son numéro, ou un changement au démarrage, par sa sorte et l'empreinte du
//! programme (16 octets : le relais n'en fait que `demarrage --retirer|--remettre <hex> --json`, et c'est
//! `vanguard` qui la cherche parmi ce qu'il voit, puis demande les droits). `vanguard` part ainsi du relais et n'hérite pas du bac : il voit tout
//! ce qu'il doit voir (les programmes en cours, le bus système, sudo).
//!
//! Le relais ne fait confiance à rien de ce que dit la fenêtre (c'est elle qu'on protège de ce qu'elle dessine) : une
//! demande est un numéro de la liste fermée, un changement de forme fermée, la langue, ou un arrêt ; rien d'autre n'est compris, et une demande
//! hors de ce protocole l'arrête. Il retrouve lui-même le `vanguard` voisin et rejoue sa garde (`lanceur`). Il ne
//! se laisse pas observer (PR_SET_DUMPABLE à 0 : ni ptrace ni /proc/<pid>/mem du même compte), et Landlock empêche
//! de toute façon la fenêtre d'observer ce qui est hors de son bac. Quand la fenêtre se ferme ou meurt, la socket se
//! ferme : le relais arrête les lectures qui tournent, laisse finir un changement commencé, et s'en va. Le protocole,
//! sans rien d'autre, est dans `protocole`.
//!
//! Un changement, côté relais (ce qui tient même si la fenêtre est prise) : il passe seul (refusé tant qu'une
//! commande tourne ; rien d'autre ne se lance pendant lui) ; seulement pour un geste vu dans la dernière liste du
//! démarrage que le relais a lui-même relayée (`demarrage --json`), la même empreinte avec la même sorte (« retirer »
//! un programme que la liste offrait de remettre est refusé), et cette liste ne sert qu'une fois ; « Arrêter »
//! ne le coupe pas, la fermeture de la fenêtre non plus : coupé au milieu, il pourrait laisser un programme retiré sans
//! la note qui le remet. Seul son délai (`Lancement::delai`) l'arrête.

use std::collections::{HashMap, HashSet};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, mpsc};
use std::time::Duration;

use crate::commandes::{Commande, Empreinte, Lancement, Sorte};
use crate::lanceur::{Fin, Issue, Message, Programme, Rendre, Reveil, SORTIE_MAX, Tache};
use crate::protocole::{
    DEMANDE_MAX, Demande, Reponse, coder_fin, coder_lance, coder_ligne, ecrire_trame, lire_reponse, lire_trame,
};

/// Une réponse du relais : la sortie bornée, son texte d'erreur et l'en-tête.
const REPONSE_MAX: usize = SORTIE_MAX + 64 * 1024;
/// Commandes en même temps au plus (la fenêtre en lance une à la fois ; une qui finit de s'arrêter, en plus).
const TACHES_MAX: usize = 2;
/// Une fenêtre qui ne lit plus ne bloque pas le relais au-delà.
const ECRITURE_DELAI: Duration = Duration::from_secs(10);
/// Empreintes retenues au plus d'une liste du démarrage (une machine en a quelques dizaines).
const EMPREINTES_MAX: usize = 4096;

/// Une commande lancée par le relais.
struct EnCours {
    arret: Arc<AtomicBool>,
    /// Un changement : ni « Arrêter » ni la fermeture de la fenêtre ne le coupent.
    changement: bool,
}

/// Ce que le relais retient entre deux demandes.
#[derive(Default)]
struct Etat {
    taches: HashMap<u32, EnCours>,
    /// Les gestes de la dernière liste du démarrage relayée (l'empreinte et la sorte offerte pour elle), vidés quand
    /// un changement part : un changement demande une liste relue après lui.
    vues: HashMap<Empreinte, Sorte>,
}

impl Etat {
    /// Pourquoi ce lancement est refusé, s'il l'est ; sinon il est retenu (et un changement consomme la liste vue).
    fn admettre(&mut self, id: u32, lancement: Lancement, arret: &Arc<AtomicBool>) -> Option<&'static str> {
        let changement = matches!(lancement, Lancement::Changement(_));
        if self.taches.len() >= TACHES_MAX || self.taches.contains_key(&id) {
            return Some(crate::tr!(
                "trop de commandes en même temps",
                "too many commands at once"
            ));
        }
        if self.taches.values().any(|t| t.changement) {
            return Some(crate::tr!(
                "un changement est en cours : rien d'autre ne se lance avant sa fin",
                "a change is running: nothing else starts before it ends"
            ));
        }
        if changement && !self.taches.is_empty() {
            return Some(crate::tr!(
                "un changement à la fois : une commande tourne encore",
                "one change at a time: a command is still running"
            ));
        }
        if let Lancement::Changement(ch) = lancement {
            match self.vues.get(&ch.empreinte) {
                None => {
                    return Some(crate::tr!(
                        "programme absent de la dernière liste du démarrage lue : relisez-la",
                        "program not in the last startup list read: read it again"
                    ));
                }
                Some(&offerte) if offerte != ch.sorte => {
                    return Some(crate::tr!(
                        "la dernière liste du démarrage lue n'offrait pas ce geste pour ce programme : relisez-la",
                        "the last startup list read did not offer this action for this program: read it again"
                    ));
                }
                Some(_) => self.vues.clear(),
            }
        }
        self.taches.insert(
            id,
            EnCours {
                arret: Arc::clone(arret),
                changement,
            },
        );
        None
    }
}

/// Ce que le relais lit d'une liste du démarrage : les gestes de ses constats, rien d'autre (le reste est sauté sans
/// être gardé, et un constat d'une forme inattendue est compté à part par `Liste`, sans faire tomber les autres).
#[derive(serde::Deserialize)]
struct ListeVue {
    #[serde(default)]
    constats: crate::donnees::Liste<ConstatVu>,
}

#[derive(serde::Deserialize)]
struct ConstatVu {
    #[serde(default)]
    geste: Option<GesteVu>,
}

#[derive(serde::Deserialize)]
struct GesteVu {
    sorte: String,
    empreinte: String,
}

/// Les gestes d'une sortie de `demarrage --json` : pour chaque constat, l'empreinte et la sorte lues dans le même
/// objet `geste` (le JSON lu pour de bon, au fil de l'eau comme dans `donnees` : l'ordre des clés n'y fait rien, et
/// un nom de programme, une chaîne, ne fabrique ni clé ni geste). Une empreinte offerte avec deux sortes n'est pas
/// retenue (aucune n'est choisie) ; un geste incomplet non plus ; une sortie qui n'est pas du JSON : rien. Borné à
/// `EMPREINTES_MAX`.
fn gestes_vus(texte: &[u8]) -> HashMap<Empreinte, Sorte> {
    let mut vus = HashMap::new();
    let Ok(liste) = serde_json::from_slice::<ListeVue>(texte) else {
        return vus;
    };
    let mut doubles = HashSet::new();
    for g in liste.constats.elements.into_iter().filter_map(|c| c.geste) {
        if vus.len() >= EMPREINTES_MAX {
            break;
        }
        let (Some(sorte), Some(empreinte)) = (Sorte::lire(&g.sorte), Empreinte::lire(&g.empreinte)) else {
            continue;
        };
        if doubles.contains(&empreinte) {
            continue;
        }
        if vus.insert(empreinte, sorte).is_some_and(|avant| avant != sorte) {
            vus.remove(&empreinte);
            doubles.insert(empreinte);
        }
    }
    vus
}

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
/// avec la surveillance de `lanceur` et renvoie ses lignes puis sa fin. À la fin, arrête les lectures, laisse finir
/// un changement, et attend tout.
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
    let etat: Arc<Mutex<Etat>> = Arc::default();
    let mut fils: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let mut entree = flux;
    while let Ok(Some(t)) = lire_trame(&mut entree, DEMANDE_MAX) {
        let Some(d) = Demande::lire(&t) else {
            break;
        };
        match d {
            Demande::Arreter { id } => {
                // Un changement ne se coupe pas, même demandé : seul son délai l'arrête.
                if let Some(t) = verrou(&etat).taches.get(&id)
                    && !t.changement
                {
                    t.arret.store(true, Ordering::Relaxed);
                }
            }
            Demande::Lancer { id, lancement, anglais } => {
                let arret = Arc::new(AtomicBool::new(false));
                let refus = verrou(&etat).admettre(id, lancement, &arret);
                let impossible = |texte: String| Fin {
                    lancement,
                    code: None,
                    sortie: Vec::new(),
                    issue: Issue::Impossible(texte),
                    duree: Duration::ZERO,
                };
                if let Some(r) = refus {
                    envoyer(&coder_fin(id, &impossible(r.into())));
                    continue;
                }
                let rendre: Rendre = {
                    let envoyer = Arc::clone(&envoyer);
                    Arc::new(move |m| match m {
                        Message::Ligne(l) => envoyer(&coder_ligne(id, &l)),
                        Message::Lance(pid) => envoyer(&coder_lance(id, pid)),
                        // La fin part après `surveiller`, ci-dessous.
                        Message::Fin(_) => {}
                    })
                };
                let (envoyer2, etat2, trouver2) = (Arc::clone(&envoyer), Arc::clone(&etat), Arc::clone(&trouver));
                let lance = std::thread::Builder::new()
                    .name("vanguard-relais".into())
                    .spawn(move || {
                        let fin = match trouver2() {
                            Ok(p) => crate::lanceur::surveiller(&p, lancement, anglais, &arret, &rendre),
                            Err(e) => Fin {
                                lancement,
                                code: None,
                                sortie: Vec::new(),
                                issue: Issue::Impossible(e),
                                duree: Duration::ZERO,
                            },
                        };
                        // Retenue et retirée avant que la fin parte : la fenêtre qui la reçoit peut aussitôt
                        // demander un changement de cette liste.
                        {
                            let mut e = verrou(&etat2);
                            if fin.lancement == Lancement::Commande(Commande::Demarrage) && fin.issue == Issue::Terminee
                            {
                                e.vues = gestes_vus(&fin.sortie);
                            }
                            e.taches.remove(&id);
                        }
                        envoyer2(&coder_fin(id, &fin));
                    });
                match lance {
                    Ok(f) => fils.push(f),
                    Err(e) => {
                        verrou(&etat).taches.remove(&id);
                        envoyer(&coder_fin(id, &impossible(e.to_string())));
                    }
                }
                fils.retain(|f| !f.is_finished());
            }
        }
    }
    // La fenêtre est partie (ou parle hors protocole) : les lectures sont arrêtées ; un changement commencé finit
    // (borné par son délai). Tout est attendu.
    for t in verrou(&etat).taches.values().filter(|t| !t.changement) {
        t.arret.store(true, Ordering::Relaxed);
    }
    for f in fils {
        let _ = f.join();
    }
}

/// Une tâche de la fenêtre qui attend sa fin du relais.
struct Attente {
    lancement: Lancement,
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

    pub fn lancer(&self, lancement: Lancement, anglais: bool, reveil: &Reveil) -> Tache {
        let (envoi, recu) = mpsc::channel();
        let id = self.suivant.fetch_add(1, Ordering::Relaxed);
        let a = Attente {
            lancement,
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
            let d = Demande::Lancer { id, lancement, anglais };
            ecrire_trame(&mut *verrou(&self.sortie), &d.coder())
                .err()
                .and_then(|_| verrou(&self.attente).remove(&id))
        });
        if let Some(a) = refus {
            rendre_fin(&a, None, Issue::Impossible(relais_parti()), Duration::ZERO, Vec::new());
        }
        Tache::relayee(lancement, id, recu)
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
        lancement: a.lancement,
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
            Some(Reponse::Lance(id, pid)) => {
                if let Some(a) = verrou(attente).get(&id) {
                    let _ = a.envoi.send(Message::Lance(pid));
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
    use crate::commandes::{Changement, Commande, Empreinte, Sorte};
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
        let f = attendre(&c.lancer(Commande::Protection.into(), false, &rien));
        assert_eq!(
            (f.lancement, f.issue),
            (Commande::Protection.into(), Issue::Impossible("introuvable".into()))
        );
        c.arreter(12345);
        ecrire_trame(&mut &fenetre, &[9, 9, 9]).unwrap();
        serveur.join().unwrap();
        let f = attendre(&c.lancer(Commande::Bilan.into(), false, &rien));
        assert!(matches!(f.issue, Issue::Impossible(_)), "{:?}", f.issue);
        // L'envoi peut échouer (socket fermée) avant que le lecteur, en fond, ait vu la fin et posé `mort` : on
        // l'attend, borné.
        let debut = Instant::now();
        while !c.mort.load(Ordering::Relaxed) && debut.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(c.mort.load(Ordering::Relaxed));
    }

    /// Un changement bien formé passe le protocole (ici, sans liste du démarrage relayée avant, il est refusé sans
    /// rien lancer) ; un changement à la mauvaise longueur, d'une sorte inconnue ou suivi d'un chemin ferme le relais,
    /// sans rien lancer.
    #[test]
    fn le_relais_ne_comprend_que_le_changement_de_forme_fermee() {
        let ch = Lancement::Changement(Changement {
            sorte: Sorte::Retirer,
            empreinte: Empreinte::depuis_octets([0x5a; 16]),
        });
        let bonne = Demande::Lancer {
            id: 7,
            lancement: ch,
            anglais: false,
        }
        .coder();
        let mut longue = bonne.clone();
        longue.extend(b"/home/alice/.config/autostart/Lecteur.desktop");
        let mut sorte = bonne.clone();
        sorte[5] = 9;
        for fausse in [bonne[..22].to_vec(), longue, sorte] {
            let (fenetre, relais) = UnixStream::pair().unwrap();
            let lances = Arc::new(AtomicU32::new(0));
            let l = Arc::clone(&lances);
            let serveur = std::thread::spawn(move || {
                servir(relais, move || {
                    l.fetch_add(1, Ordering::Relaxed);
                    Err("introuvable".into())
                });
            });
            let c = Client::demarrer(fenetre.try_clone().unwrap(), None);
            let rien: Reveil = Arc::new(|| {});
            let f = attendre_fin(&c.lancer(ch, false, &rien));
            assert_eq!(f.lancement, ch);
            assert!(
                matches!(&f.issue, Issue::Impossible(r) if r.contains("dernière liste")),
                "{:?}",
                f.issue
            );
            ecrire_trame(&mut &fenetre, &fausse).unwrap();
            serveur.join().unwrap();
            assert_eq!(lances.load(Ordering::Relaxed), 0, "{fausse:?}");
            c.fermer();
        }
    }

    /// Les gestes d'une liste : l'empreinte (32 chiffres hexadécimaux minuscules) avec sa sorte, lues dans le même
    /// objet `geste`, dans n'importe quel ordre ; ni geste sans sorte, ni sorte inconnue, ni majuscule, ni longueur
    /// voisine, ni empreinte hors d'un geste, ni geste fabriqué dans une chaîne (un nom de programme) ; une empreinte
    /// offerte avec deux sortes n'est pas retenue.
    #[test]
    fn seuls_les_gestes_de_la_liste_sont_vus() {
        use std::fmt::Write as _;
        let (e1, e2, e3, e4, e5) = (
            "0123456789abcdef0123456789abcdef",
            "a".repeat(32),
            "b".repeat(32),
            "d".repeat(32),
            "e".repeat(32),
        );
        let liste = format!(
            r#"{{"constats": [{{"geste": {{"sorte": "retirer", "empreinte": "{e1}", "nom": "Lecteur"}}}},
            {{"geste": {{"nom": "Agenda", "empreinte":"{e2}", "sorte": "remettre"}}}},
            {{"geste": {{"empreinte": "{e3}"}}}}, {{"geste": {{"sorte": "effacer", "empreinte": "{e3}"}}}},
            {{"nom": "x\", \"geste\": {{\"sorte\": \"retirer\", \"empreinte\": \"{e4}\"}}"}},
            {{"geste": {{"sorte": "retirer", "empreinte": "{e5}"}}}}, {{"geste": {{"sorte": "remettre", "empreinte": "{e5}"}}}},
            {{"geste": {{"sorte": "retirer", "empreinte": "{}"}}}}, {{"geste": {{"sorte": "retirer", "empreinte": "{}"}}}},
            {{"geste": {{"sorte": "retirer", "empreinte": "{e1}0"}}}}, {{"geste": {{"sorte": "retirer", "empreinte": 7}}}},
            {{"empreinte": "{e4}", "sorte": "retirer"}}, "geste"]}}"#,
            "C".repeat(32),
            "c".repeat(31)
        );
        let vus = gestes_vus(liste.as_bytes());
        let attendus: HashMap<Empreinte, Sorte> = [(e1, Sorte::Retirer), (e2.as_str(), Sorte::Remettre)]
            .into_iter()
            .filter_map(|(e, s)| Some((Empreinte::lire(e)?, s)))
            .collect();
        assert_eq!(vus, attendus);
        for rien in [
            &b""[..],
            b"\"empreinte\"",
            b"{\"constats\": 7}",
            b"[1, 2]",
            b"une ligne\n{\"constats\": []}",
        ] {
            assert!(gestes_vus(rien).is_empty());
        }
        // Bornés.
        let mut beaucoup = String::from(r#"{"constats": ["#);
        for i in 0..EMPREINTES_MAX + 10 {
            let _ = write!(
                beaucoup,
                r#"{{"geste": {{"sorte": "retirer", "empreinte": "{i:032x}"}}}},"#
            );
        }
        beaucoup.push_str("{}]}");
        assert_eq!(gestes_vus(beaucoup.as_bytes()).len(), EMPREINTES_MAX);
    }

    /// Le relais refuse un changement dont la sorte n'est pas celle que la liste offrait pour cette empreinte (une
    /// fenêtre prise qui retire un programme que la liste offrait de remettre), sans consommer la liste.
    #[test]
    fn une_sorte_que_la_liste_n_offrait_pas_est_refusee() {
        let e = Empreinte::lire("0123456789abcdef0123456789abcdef").unwrap();
        let mut etat = Etat {
            vues: [(e, Sorte::Remettre)].into(),
            ..Etat::default()
        };
        let arret = Arc::new(AtomicBool::new(false));
        let demande = |sorte| Lancement::Changement(Changement { sorte, empreinte: e });
        assert!(etat.admettre(1, demande(Sorte::Retirer), &arret).is_some());
        assert!(etat.taches.is_empty());
        assert_eq!(etat.vues.get(&e), Some(&Sorte::Remettre));
        assert_eq!(etat.admettre(2, demande(Sorte::Remettre), &arret), None);
        assert!(etat.vues.is_empty());
    }

    /// Un faux `vanguard` : la liste lue dans liste.json ; un changement noté dans « changements », qui attend le
    /// fichier « va » (20 s au plus) puis note « fini » ; toute autre commande attend « va-lecture ».
    const FAUX_VANGUARD: &str = r#"#!/bin/sh
d=$(dirname "$0")
attendre() { i=0; while [ ! -e "$d/$1" ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done; }
case "$1 $2" in
"demarrage --json") cat "$d/liste.json" ;;
"demarrage --retirer"|"demarrage --remettre") echo "$@" >> "$d/changements"; attendre va; echo fini >> "$d/changements"
  echo "{\"geste\": \"${2#--}\", \"issue\": \"fait\", \"raison\": \"\"}" ;;
*) attendre va-lecture; echo '{}' ;;
esac
"#;

    /// Pour de vrai, avec un faux `vanguard` : un changement n'est accepté que pour une empreinte de la dernière
    /// liste relayée, et cette liste ne sert qu'une fois ; il passe seul (refusé pendant une lecture, et rien ne se
    /// lance pendant lui) ; « Arrêter » ne le coupe pas, la fermeture de la fenêtre non plus.
    #[test]
    fn un_changement_vu_passe_seul_et_ne_se_coupe_pas() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("essais-fenetre")
            .join(format!("relais-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let (e1, e2) = ("0123456789abcdef0123456789abcdef", "f".repeat(32));
        std::fs::write(
            d.join("liste.json"),
            format!(
                r#"{{"outil": "PRO-DEM-001", "constats": [{{"categorie": "Démarrage", "objet": "demarrage:Lecteur",
                "geste": {{"sorte": "retirer", "empreinte": "{e1}", "nom": "Lecteur", "commande": "/usr/bin/lecteur"}}}},
                {{"message": "Faux — \"empreinte\": \"{e2}\""}}]}}"#
            ),
        )
        .unwrap();
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX_VANGUARD).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let (fenetre, relais) = UnixStream::pair().unwrap();
        let dossier = d.clone();
        let serveur = std::thread::spawn(move || servir(relais, move || Programme::dans(&dossier, moi)));
        let c = Client::demarrer(fenetre, None);
        let rien: Reveil = Arc::new(|| {});
        let changements = || std::fs::read_to_string(d.join("changements")).unwrap_or_default();
        let changement = |e: &str| {
            Lancement::Changement(Changement {
                sorte: Sorte::Retirer,
                empreinte: Empreinte::lire(e).unwrap(),
            })
        };
        let refuse = |l: Lancement, motif: &str| {
            let f = attendre_fin(&c.lancer(l, false, &rien));
            assert!(
                matches!(&f.issue, Issue::Impossible(r) if r.contains(motif)),
                "{motif} : {:?}",
                f.issue
            );
        };
        let lire_la_liste = || {
            let f = attendre_fin(&c.lancer(Commande::Demarrage.into(), false, &rien));
            assert_eq!((&f.issue, f.code), (&Issue::Terminee, Some(0)), "{:?}", f.issue);
        };
        let commence = || {
            let debut = Instant::now();
            while !changements().ends_with(
                "--json
",
            ) {
                assert!(debut.elapsed() < Duration::from_secs(20), "jamais commencé");
                std::thread::sleep(Duration::from_millis(20));
            }
        };

        // Avant toute liste, puis pour une empreinte absente de la liste (ou seulement citée dans un texte) : refusé.
        refuse(changement(e1), "dernière liste");
        lire_la_liste();
        refuse(changement(&e2), "dernière liste");
        // Une lecture tourne : le changement attend son tour (refusé), la liste reste bonne.
        let lecture = c.lancer(Commande::Protection.into(), false, &rien);
        refuse(changement(e1), "un changement à la fois");
        std::fs::write(d.join("va-lecture"), b"").unwrap();
        assert_eq!(attendre_fin(&lecture).issue, Issue::Terminee);
        assert_eq!(changements(), "");

        // Le changement part ; pendant lui, rien d'autre ; « Arrêter » ne le coupe pas.
        let t = c.lancer(changement(e1), false, &rien);
        let id = c.suivant.load(Ordering::Relaxed) - 1;
        commence();
        refuse(Commande::Protection.into(), "un changement est en cours");
        refuse(changement(e1), "un changement est en cours");
        c.arreter(id);
        std::thread::sleep(Duration::from_millis(500));
        assert!(!t.recevoir().iter().any(|m| matches!(m, Message::Fin(_))));
        std::fs::write(d.join("va"), b"").unwrap();
        let f = attendre_fin(&t);
        assert_eq!((&f.issue, f.code), (&Issue::Terminee, Some(0)), "{:?}", f.issue);
        assert_eq!(changements(), format!("demarrage --retirer {e1} --json\nfini\n"));
        // La liste a servi : relue avant le suivant.
        refuse(changement(e1), "dernière liste");

        // La fenêtre se ferme pendant un changement : il finit quand même.
        std::fs::remove_file(d.join("va")).unwrap();
        lire_la_liste();
        let _t = c.lancer(changement(e1), false, &rien);
        let debut = Instant::now();
        while changements().lines().count() < 3 {
            assert!(debut.elapsed() < Duration::from_secs(20), "jamais commencé");
            std::thread::sleep(Duration::from_millis(20));
        }
        c.fermer();
        std::thread::sleep(Duration::from_millis(500));
        std::fs::write(d.join("va"), b"").unwrap();
        serveur.join().unwrap();
        assert_eq!(
            changements().lines().filter(|l| *l == "fini").count(),
            2,
            "{}",
            changements()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un relais d'essai avec le faux `vanguard` et cette liste, dans un dossier jetable des essais : le dossier,
    /// la fenêtre et le fil du relais.
    fn banc_du_relais(nom: &str, liste: &str) -> (std::path::PathBuf, Client, std::thread::JoinHandle<()>) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("essais-fenetre")
            .join(format!("{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(d.join("liste.json"), liste).unwrap();
        std::fs::write(d.join("va"), b"").unwrap();
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX_VANGUARD).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let (fenetre, relais) = UnixStream::pair().unwrap();
        let dossier = d.clone();
        let serveur = std::thread::spawn(move || servir(relais, move || Programme::dans(&dossier, moi)));
        (d, Client::demarrer(fenetre, None), serveur)
    }

    /// Pour de vrai : la liste n'offre que « retirer » pour le Lecteur ; une fenêtre prise en main demande
    /// « remettre » avec la même empreinte. Le relais, qui a vu la liste, refuse cette sorte et ne lance rien.
    #[test]
    fn le_relais_refuse_la_sorte_que_la_liste_n_offrait_pas() {
        let e1 = "0123456789abcdef0123456789abcdef";
        let (d, c, serveur) = banc_du_relais(
            "relais-sorte",
            &format!(
                r#"{{"outil": "PRO-DEM-001", "constats": [{{"objet": "demarrage:Lecteur",
                "geste": {{"sorte": "retirer", "empreinte": "{e1}", "nom": "Lecteur", "commande": "/usr/bin/lecteur"}}}}]}}"#
            ),
        );
        let rien: Reveil = Arc::new(|| {});
        let f = attendre_fin(&c.lancer(Commande::Demarrage.into(), false, &rien));
        assert_eq!((&f.issue, f.code), (&Issue::Terminee, Some(0)));
        let f = attendre_fin(&c.lancer(
            Lancement::Changement(Changement {
                sorte: Sorte::Remettre,
                empreinte: Empreinte::lire(e1).unwrap(),
            }),
            false,
            &rien,
        ));
        let lances = std::fs::read_to_string(d.join("changements")).unwrap_or_default();
        c.fermer();
        serveur.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
        assert!(
            matches!(&f.issue, Issue::Impossible(r) if r.contains("n'offrait pas")) && lances.is_empty(),
            "{:?} ; lancé : {lances}",
            f.issue
        );
    }

    /// Une limite dite par le modèle de menace, gardée telle quelle : le relais ne met aucune pause entre deux
    /// changements (une fenêtre prise en main peut enchaîner liste et changement). Douze programmes ordinaires
    /// retirés à la suite passent tous ; si un jour une cadence est imposée, cet essai et le texte changent ensemble.
    #[test]
    fn le_relais_n_impose_aucun_intervalle_entre_deux_changements() {
        use std::fmt::Write as _;
        let mut constats = String::new();
        for i in 0..12 {
            let _ = write!(
                constats,
                r#"{}{{"objet": "demarrage:P{i}", "geste": {{"sorte": "retirer", "empreinte": "{i:032x}", "nom": "P{i}", "commande": "/usr/bin/p{i}"}}}}"#,
                if i == 0 { "" } else { "," }
            );
        }
        let (d, c, serveur) = banc_du_relais(
            "relais-rafale",
            &format!(r#"{{"outil": "PRO-DEM-001", "constats": [{constats}]}}"#),
        );
        let rien: Reveil = Arc::new(|| {});
        let mut faits = 0;
        for i in 0..12 {
            let f = attendre_fin(&c.lancer(Commande::Demarrage.into(), false, &rien));
            assert_eq!(f.issue, Issue::Terminee);
            let f = attendre_fin(&c.lancer(
                Lancement::Changement(Changement {
                    sorte: Sorte::Retirer,
                    empreinte: Empreinte::lire(&format!("{i:032x}")).unwrap(),
                }),
                false,
                &rien,
            ));
            if f.issue == Issue::Terminee {
                faits += 1;
            }
        }
        let lances = std::fs::read_to_string(d.join("changements")).unwrap_or_default();
        c.fermer();
        serveur.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(
            lances.lines().filter(|l| l.starts_with("demarrage --retirer")).count(),
            faits
        );
        assert_eq!(faits, 12);
    }

    /// Des noms et des commandes hostiles, écrits par un vrai sérialiseur JSON (comme `vanguard` le fait), essaient
    /// de fabriquer un geste : seul celui de la liste est vu, avec sa sorte.
    #[test]
    fn aucun_nom_ne_fabrique_un_geste_vu() {
        let (vraie, glissee) = ("0123456789abcdef0123456789abcdef", "f".repeat(32));
        let hostiles = [
            format!("\"empreinte\": \"{glissee}\""),
            format!("\\\"empreinte\\\": \\\"{glissee}\\\""),
            format!("\\\\\"empreinte\": \"{glissee}\""),
            format!("x\"}}, {{\"empreinte\":\"{glissee}\""),
            format!("\"empreinte\"\n:\n\"{glissee}\""),
            format!("\u{0}\"empreinte\":\"{glissee}\""),
            format!("\"geste\": {{\"sorte\": \"remettre\", \"empreinte\": \"{glissee}\"}}"),
            "empreinte".to_string(),
            glissee.clone(),
        ];
        let attendus: HashMap<Empreinte, Sorte> = Empreinte::lire(vraie)
            .into_iter()
            .map(|e| (e, Sorte::Retirer))
            .collect();
        for h in &hostiles {
            for joli in [false, true] {
                let v = serde_json::json!({
                    "outil": "PRO-DEM-001",
                    "constats": [
                        {"objet": format!("demarrage:{h}"), "message": h, "categorie": h,
                         "geste": {"sorte": "retirer", "empreinte": vraie, "nom": h, "commande": h}},
                        {"objet": h, "message": [h, "empreinte", glissee]},
                    ],
                });
                let texte = if joli {
                    serde_json::to_string_pretty(&v).unwrap()
                } else {
                    serde_json::to_string(&v).unwrap()
                };
                assert_eq!(gestes_vus(texte.as_bytes()), attendus, "{h:?} : {texte}");
            }
        }
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
    /// La socket d'essai dans /tmp/.X11-unix, si elle a pu y être créée.
    const ESSAI_X11: &str = "VANGUARD_FENETRE_ESSAI_X11";

    /// Pour de vrai : le fil d'essai (la fenêtre) entre dans le bac à sable ; le relais, parti avant lui (comme le
    /// relais part avant que la fenêtre se restreigne), lance un faux `vanguard` qui écrit un fichier et lance un
    /// programme. La fenêtre, elle, ne peut ni écrire, ni lancer, ni se connecter, ni lire le dossier personnel (une
    /// fausse clé SSH dans un HOME jetable), ni joindre X11 sous Wayland (une socket d'essai dans /tmp/.X11-unix,
    /// comme celle de Xwayland). Dans un processus d'essai à part (ce même programme de tests, relancé sur ce seul
    /// test) : le bac ne se retire pas, il ne doit pas suivre les autres tests.
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
        // Sans « .. » : le bac ne suit pas un chemin de curseurs qui en a un (`Milieu::curseurs`).
        let d = std::fs::canonicalize(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = d.join("vanguard");
        // Le faux `vanguard` : un fichier écrit, un programme lancé, une sortie JSON.
        std::fs::write(
            &f,
            "#!/bin/sh\necho ecrit > \"$(dirname \"$0\")/ecrit\" && /bin/sh -c 'echo \"{}\"'\n",
        )
        .unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Un HOME jetable : une fausse clé (valeur inventée), et un thème de curseurs, lui permis.
        let maison = d.join("maison");
        std::fs::create_dir_all(maison.join(".ssh")).unwrap();
        std::fs::write(maison.join(".ssh").join("id_rsa"), "cle-inventee-pour-l-essai\n").unwrap();
        std::fs::create_dir_all(maison.join(".icons").join("essai")).unwrap();
        std::fs::write(
            maison.join(".icons").join("essai").join("index.theme"),
            "[Icon Theme]\n",
        )
        .unwrap();
        // Une socket d'essai où X11 et Xwayland mettent les leurs (le dossier est ouvert à tous, collant).
        let x11 = std::path::Path::new("/tmp/.X11-unix").join(format!("vanguard-essai-{}", std::process::id()));
        let _ = std::fs::remove_file(&x11);
        let ecoute = std::os::unix::net::UnixListener::bind(&x11);
        let nom = "relais::tests::le_bac_retient_la_fenetre_et_pas_ce_que_le_relais_lance";
        let mut essai = std::process::Command::new(std::env::current_exe().unwrap());
        essai
            .args([nom, "--exact", "--nocapture", "--test-threads=1"])
            .env(ESSAI_BAC, &d)
            .env("HOME", &maison)
            .env("WAYLAND_DISPLAY", "vanguard-essai-absent")
            .env("DISPLAY", ":99")
            .stdin(std::process::Stdio::null());
        for v in [
            "WAYLAND_SOCKET",
            "XAUTHORITY",
            "XCURSOR_PATH",
            "XDG_DATA_HOME",
            "XDG_DATA_DIRS",
            "XCOMPOSEFILE",
        ] {
            essai.env_remove(v);
        }
        if ecoute.is_ok() {
            essai.env(ESSAI_X11, &x11);
        }
        let sortie = essai.output().unwrap();
        let texte = String::from_utf8_lossy(&sortie.stdout).into_owned() + &String::from_utf8_lossy(&sortie.stderr);
        drop(ecoute);
        let _ = std::fs::remove_file(&x11);
        let ecrit = std::fs::read(d.join("ecrit"));
        let _ = std::fs::remove_dir_all(&d);
        if let Some(raison) = texte.lines().find_map(|l| l.split_once("BAC-SAUTÉ ").map(|(_, r)| r)) {
            return crate::essais::sauter(raison);
        }
        assert!(sortie.status.success() && texte.contains("BAC-OK"), "{texte}");
        // Ce que le relais a lancé a écrit, lui (relu d'ici : la fenêtre, restreinte, ne lit pas ce dossier).
        assert_eq!(ecrit.unwrap(), b"ecrit\n");
        if let Some(raison) = texte.lines().find_map(|l| l.split_once("X11-SAUTÉ ").map(|(_, r)| r)) {
            crate::essais::sauter(raison);
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
            Ok((abi, _, maison)) => {
                assert!(!maison);
                abi
            }
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
        // Ni le dossier personnel (la fausse clé), ni le dossier de l'essai (sous le vrai dossier personnel) ; le
        // système et les curseurs du compte, oui.
        let maison = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
        let cle = std::fs::read(maison.join(".ssh").join("id_rsa"));
        assert_eq!(cle.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read_dir(&maison).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let faux = std::fs::read(d.join("vanguard"));
        assert_eq!(faux.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert!(std::fs::read(maison.join(".icons").join("essai").join("index.theme")).is_ok());
        assert!(std::fs::read_dir("/usr").is_ok());
        // Sous Wayland (WAYLAND_DISPLAY posé par l'essai), pas d'X11, même avec DISPLAY : Landlock 9 et plus.
        match std::env::var_os(ESSAI_X11) {
            Some(x11) if abi >= 9 => {
                let x = std::os::unix::net::UnixStream::connect(&x11);
                assert_eq!(x.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
            }
            Some(_) => println!("X11-SAUTÉ Landlock {abi} : les sockets nommées restent joignables"),
            None => println!("X11-SAUTÉ /tmp/.X11-unix absent ou fermé"),
        }
        // Ce que le relais lance, lui, a tous les droits du compte.
        let c = Client::demarrer(fenetre, None);
        let rien: Reveil = Arc::new(|| {});
        let f = attendre_fin(&c.lancer(Commande::Bilan.into(), false, &rien));
        assert_eq!(
            (f.lancement, &f.issue, f.code),
            (Commande::Bilan.into(), &Issue::Terminee, Some(0)),
            "{:?}",
            f.issue
        );
        assert_eq!(f.sortie, b"{}\n");
        c.fermer();
        serveur.join().unwrap();
        println!("BAC-OK");
    }
}
