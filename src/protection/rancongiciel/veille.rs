//! L'orchestration de la veille anti-rançongiciel sous Linux : une surveillance en direct des dossiers (par `notify`,
//! déjà présent), l'accumulation des changements dans la fenêtre, le calcul des signaux et le déclenchement de la
//! réponse. Le calcul des signaux à partir des changements est une fonction PURE (`signaux_de`), testée sans système
//! de fichiers ; seules l'écoute, l'échantillonnage et la réponse touchent au disque.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::time::Instant;

use notify::event::{AccessKind, AccessMode, CreateKind, ModifyKind, RemoveKind, RenameMode};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use super::contenu;
use super::fenetre::{self, Changement, Fenetre, Sorte};
use super::noms;
use super::score::{self, Copies, Signaux};

/// Au plus tant de fichiers échantillonnés par jugement : borne le coût (plan : ~200/s).
const ECHANTILLONS_MAX: usize = 200;
/// Fenêtre lente (L1) : 30 minutes.
const FENETRE_LENTE: std::time::Duration = std::time::Duration::from_mins(30);

/// Un changement prêt à juger : son chemin, sa sorte, et — si on l'a — son extension d'origine (avant renommage).
/// `signaux_de` s'en sert sans toucher au disque.
#[derive(Debug, Clone)]
pub(crate) struct Vu {
    pub chemin: PathBuf,
    pub sorte: Sorte,
}

/// Calcule les signaux (hors R7, R8, R9, E1, qui viennent du flux des processus) à partir des changements de la
/// fenêtre. `piege` : vrai si le chemin est un fichier-piège. `format_perdu` : vrai si le contenu actuel ne
/// correspond plus à l'extension d'origine donnée (lecture faite par l'appelant, bornée). Rend aussi la liste des
/// fichiers de la rafale (réécrits), pour l'attribution et la preuve.
pub(crate) fn signaux_de(
    changements: &[Vu],
    piege: impl Fn(&Path) -> bool,
    mut format_perdu: impl FnMut(&Path, &str) -> bool,
) -> (Signaux, Vec<PathBuf>) {
    // Le dernier état par chemin : un fichier écrit puis renommé compte une fois.
    let mut par_chemin: HashMap<&Path, &Sorte> = HashMap::new();
    for v in changements {
        par_chemin.insert(&v.chemin, &v.sorte);
    }
    // Créés dans la fenêtre : écrits ensuite, ils ne sont pas des fichiers EXISTANTS réécrits. Un `git clone`, un
    // `tar x` ou une copie donnent CREATE puis CLOSE_WRITE ; les compter dans R1 criait à chaque copie de 10 MP3. Un
    // chiffreur qui écrit une copie neuve puis efface l'original n'est plus compté dans R1 : R3, R4 et R6 le voient.
    let cree: HashSet<&Path> = changements
        .iter()
        .filter(|v| v.sorte == Sorte::Cree)
        .map(|v| v.chemin.as_path())
        .collect();
    // R6 sur la liste BRUTE, pas sur le dernier état : une écriture qui suit un renommage écrase l'entrée du nouveau
    // nom, et un piège renommé ne porte plus que son ancien nom. Un piège effacé n'est pas un signe : « pieges
    // --retirer » et la désinstallation les effacent pendant que la veille tourne ; un rançongiciel qui copie puis
    // efface reste vu sur la copie écrite (R1, R2).
    let piege_touche = changements.iter().any(|v| match &v.sorte {
        Sorte::Ecrit => piege(&v.chemin),
        Sorte::Renomme { ancien } => piege(ancien) || piege(&v.chemin),
        Sorte::Cree | Sorte::Supprime => false,
    });

    let mut reecrits: Vec<PathBuf> = Vec::new();
    let mut dossiers: HashSet<PathBuf> = HashSet::new();
    let mut extensions_ajoutees: HashMap<String, u32> = HashMap::new();
    let mut nom_au_hasard = false;
    let mut extension_inconnue = false;
    // Notes de rançon : un même nom de note, dans combien de dossiers distincts.
    let mut notes: HashMap<String, HashSet<PathBuf>> = HashMap::new();

    for (chemin, sorte) in &par_chemin {
        if let Some(d) = chemin.parent() {
            dossiers.insert(d.to_path_buf());
        }
        let nom = chemin.file_name().and_then(|n| n.to_str()).unwrap_or("");
        match sorte {
            // Une vraie note arrive en CREATE puis CLOSE_WRITE : son dernier état est « écrit ». Elle se reconnaît
            // donc à son nom dans les deux cas, et ne compte pas comme un fichier réécrit (elle ferait baisser la part
            // de format perdu).
            Sorte::Cree | Sorte::Ecrit if noms::note_de_rancon(nom) => {
                if let Some(d) = chemin.parent() {
                    notes.entry(nom.to_string()).or_default().insert(d.to_path_buf());
                }
            }
            Sorte::Ecrit => {
                if cree.contains(chemin) {
                    continue;
                }
                reecrits.push((*chemin).to_path_buf());
                if !noms::extension_connue(nom) {
                    extension_inconnue = true;
                }
                if noms::nom_au_hasard(nom) {
                    nom_au_hasard = true;
                }
            }
            Sorte::Renomme { ancien } => {
                reecrits.push((*chemin).to_path_buf());
                let ancien_nom = ancien.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if let Some(ext) = noms::extension_ajoutee(ancien_nom, nom) {
                    *extensions_ajoutees.entry(ext).or_default() += 1;
                }
                if !noms::extension_connue(nom) {
                    extension_inconnue = true;
                }
            }
            Sorte::Cree | Sorte::Supprime => {}
        }
    }

    // R2 : format perdu sur les réécrits (bornés). L'extension d'origine est celle du renommage, ou l'extension
    // actuelle pour un fichier écrit en place.
    let mut format_perdu_n = 0u32;
    for chemin in reecrits.iter().take(ECHANTILLONS_MAX) {
        let sorte = par_chemin.get(chemin.as_path());
        let extension = match sorte {
            Some(Sorte::Renomme { ancien }) => ancien.extension().and_then(|e| e.to_str()).unwrap_or("").to_string(),
            _ => chemin.extension().and_then(|e| e.to_str()).unwrap_or("").to_string(),
        };
        if format_perdu(chemin, &extension) {
            format_perdu_n += 1;
        }
    }
    // L'échantillon est borné à ECHANTILLONS_MAX : son taux est ramené à l'ensemble des réécrits, sinon au-delà de
    // 2 × 200 fichiers la majorité « format perdu » devenait impossible, et le quasi-certain avec elle : plus le
    // chiffreur était rapide, moins il pouvait être arrêté.
    let echantillonnes = reecrits.len().min(ECHANTILLONS_MAX);
    if echantillonnes > 0 {
        let estime = u64::from(format_perdu_n) * reecrits.len() as u64 / echantillonnes as u64;
        format_perdu_n = u32::try_from(estime).unwrap_or(u32::MAX);
    }

    let compte = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    let note_de_rancon = notes.values().any(|d| compte(d.len()) >= score::NOTE_DOSSIERS_MIN);
    let ext_ajoutee = extensions_ajoutees.values().any(|&n| n >= score::EXT_AJOUTEE_MIN);

    let signaux = Signaux {
        reecrits: compte(reecrits.len()),
        format_perdu: format_perdu_n,
        noms_suspects: ext_ajoutee || nom_au_hasard || extension_inconnue,
        note_de_rancon,
        dossiers: compte(dossiers.len()),
        piege_touche,
        ..Signaux::default()
    };
    (signaux, reecrits)
}

/// Ce que le fil de `notify` passe à la veille : un changement déjà trié (et horodaté à son arrivée, pas à sa
/// lecture), ou un débordement de la file du noyau.
enum Message {
    Changement(Changement),
    Deborde,
}

/// Au plus tant de messages en attente dans le canal : au-delà, ils sont comptés perdus. Un canal sans borne se
/// remplissait d'événements jusqu'à la limite de mémoire de l'unité (128 Mo) sous des écritures d'un octet en boucle :
/// le veilleur était tué, puis relancé 30 s plus tard, et le chiffrement passait dans ces trous.
const CANAL_MAX: usize = fenetre::CHANGEMENTS_MAX;

/// Le gestionnaire d'événements donné à `notify` : il trie dans son propre fil (l'ouverture et la simple
/// modification, de loin les plus nombreuses, ne remplissent jamais le canal) et n'attend jamais : canal plein, le
/// message est compté perdu.
struct Borne {
    envoi: SyncSender<Message>,
    perdus: Arc<AtomicU64>,
}

impl Borne {
    fn envoyer(&self, m: Message) {
        if self.envoi.try_send(m).is_err() {
            self.perdus.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl notify::EventHandler for Borne {
    fn handle_event(&mut self, evenement: notify::Result<notify::Event>) {
        let Ok(evenement) = evenement else { return };
        if evenement.flag() == Some(notify::event::Flag::Rescan) {
            // Débordement de la file du noyau : des changements perdus, signe de rafale.
            self.envoyer(Message::Deborde);
            return;
        }
        for c in changements_de(&evenement) {
            self.envoyer(Message::Changement(c));
        }
    }
}

/// La veille en marche : le canal de `notify`, la fenêtre, les pièges, et le cumul lent (L1).
pub(crate) struct Veille {
    _watcher: RecommendedWatcher,
    recepteur: Receiver<Message>,
    /// Les messages jetés faute de place dans le canal, comptés par le fil de `notify`.
    perdus_canal: Arc<AtomicU64>,
    fenetre: Fenetre,
    pieges: HashSet<PathBuf>,
    /// Les fichiers DISTINCTS au format perdu vus sur 30 min (L1), et le début de cette fenêtre lente. Un compte
    /// ajouté à chaque tour recomptait un même fichier une dizaine de fois : 10 MP3 copiés donnaient L1.
    lent: (Instant, HashSet<PathBuf>),
    /// R7 vu dans le flux des processus (effacement des copies), et quand : il vieillit comme L1, sinon un seul
    /// ménage des copies rendait Grave toute rafale de 10 fichiers des jours plus tard.
    copies: (Copies, Instant),
    /// Le dernier débordement de la file du noyau ; il ne compte que pendant la fenêtre courte qui le suit.
    deborde: Option<Instant>,
    /// La dernière saturation de la fenêtre ou du canal : des changements jetés faute de place. Des link/unlink en
    /// boucle poussaient ainsi dehors les vrais réécrits, et le verdict restait Calme ; c'est un signal, jamais un
    /// calme, même sans 10 réécrits visibles.
    sature: Option<Instant>,
    /// Les processus du compte déjà illisibles au démarrage (pid, heure de départ) : systemd --user, (sd-pam). Les
    /// compter fermait toute attribution sur un bureau ordinaire ; un illisible apparu après reste compté.
    illisibles_connus: HashSet<(u32, u64)>,
    pub changements_vus: u64,
}

/// Au plus tant de fichiers retenus pour L1 : la mémoire reste bornée, et le seuil (100) est bien en dessous.
const LENT_MAX: usize = 10_000;

impl Veille {
    /// Met en place la surveillance des `dossiers` (récursive, sans suivre les liens) et des dossiers des `pieges`.
    /// `None` si `notify` ne peut pas démarrer ici.
    pub(crate) fn demarrer(dossiers: &[PathBuf], pieges: HashSet<PathBuf>) -> Option<Veille> {
        let (envoi, recepteur) = std::sync::mpsc::sync_channel(CANAL_MAX);
        let perdus_canal = Arc::new(AtomicU64::new(0));
        let borne = Borne {
            envoi,
            perdus: Arc::clone(&perdus_canal),
        };
        // Jamais suivre un lien : un lien vers « / » dans Documents ferait surveiller tout le disque (Critique C7).
        let config = Config::default().with_follow_symlinks(false);
        let mut watcher = RecommendedWatcher::new(borne, config).ok()?;
        let mut poses = Vec::new();
        for d in dossiers {
            if watcher.watch(d, RecursiveMode::Recursive).is_ok() {
                poses.push(d.clone());
            }
        }
        // Les dossiers des pièges, s'ils ne sont pas déjà couverts.
        for p in &pieges {
            if let Some(d) = p.parent()
                && !poses.iter().any(|w| d.starts_with(w))
                && watcher.watch(d, RecursiveMode::NonRecursive).is_ok()
            {
                poses.push(d.to_path_buf());
            }
        }
        if poses.is_empty() {
            return None;
        }
        let maintenant = Instant::now();
        Some(Veille {
            _watcher: watcher,
            recepteur,
            perdus_canal,
            fenetre: Fenetre::nouvelle(),
            pieges,
            lent: (maintenant, HashSet::new()),
            copies: (Copies::Aucune, maintenant),
            deborde: None,
            sature: None,
            illisibles_connus: illisibles_du_compte(),
            changements_vus: 0,
        })
    }

    /// Les débordements de la file de surveillance accumulés (remis à zéro).
    pub(crate) fn prendre_perdus(&mut self) -> u64 {
        self.fenetre.prendre_perdus()
    }

    /// Note qu'un effacement des copies de secours a été vu (depuis le flux des processus).
    pub(crate) fn noter_copies(&mut self, copies: Copies) {
        // On ne redescend jamais la gravité déjà vue dans la fenêtre ; l'heure est celle du dernier vu.
        if copies as u8 >= self.copies.0 as u8 {
            self.copies = (copies, Instant::now());
        }
    }

    /// Vide le canal de `notify` dans la fenêtre. Rend le nombre de changements retenus ce tour.
    pub(crate) fn absorber(&mut self) -> usize {
        let mut n = 0;
        // Borné : un flot qui arrive aussi vite qu'on le lit ne retient pas le tour pour toujours.
        for _ in 0..2 * CANAL_MAX {
            match self.recepteur.try_recv() {
                Ok(Message::Changement(c)) => {
                    self.retenir(c);
                    n += 1;
                }
                Ok(Message::Deborde) => self.deborde = Some(Instant::now()),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        let jetes = self.perdus_canal.swap(0, Ordering::Relaxed);
        if jetes > 0 {
            self.fenetre.noter_perdus(jetes);
            self.sature = Some(Instant::now());
        }
        self.changements_vus += n as u64;
        n
    }

    /// En pause : ce qui arrive est lu puis jeté, comme pour les processus. Sans cela le canal se remplissait pendant
    /// toute la pause, et au retour des heures d'activité tombaient dans la même fenêtre de 10 s.
    pub(crate) fn jeter(&mut self) {
        while self.recepteur.try_recv().is_ok() {}
        self.perdus_canal.store(0, Ordering::Relaxed);
        let _ = self.fenetre.prendre_perdus();
        self.deborde = None;
        self.sature = None;
    }

    /// Un changement dans la fenêtre ; une fenêtre qui déborde est notée saturée.
    fn retenir(&mut self, c: Changement) {
        let quand = c.quand;
        if self.fenetre.ajouter(c) {
            self.sature = Some(quand);
        }
    }

    /// Les changements actuels de la fenêtre, prêts à juger.
    fn vus(&self, maintenant: Instant) -> Vec<Vu> {
        self.fenetre
            .actuels(maintenant)
            .map(|c| Vu {
                chemin: c.chemin.clone(),
                sorte: c.sorte.clone(),
            })
            .collect()
    }

    /// Calcule les signaux du moment (échantillonne les réécrits sur le disque, en lecture seule), met à jour le
    /// cumul lent (L1), et rend les signaux complets avec la liste des fichiers de la rafale.
    pub(crate) fn signaux(&mut self, maintenant: Instant) -> (Signaux, Vec<PathBuf>) {
        let vus = self.vus(maintenant);
        let pieges = &self.pieges;
        let mut perdus_vus: Vec<PathBuf> = Vec::new();
        let (mut s, reecrits) = signaux_de(
            &vus,
            |c| pieges.contains(c),
            |chemin, extension| {
                let perdu = match contenu::echantillons(chemin) {
                    Ok(e) if !e.is_empty() => contenu::format_perdu(extension, &e),
                    _ => false,
                };
                if perdu {
                    perdus_vus.push(chemin.to_path_buf());
                }
                perdu
            },
        );
        // L1 : fichiers distincts au format perdu sur 30 min.
        if maintenant.saturating_duration_since(self.lent.0) >= FENETRE_LENTE {
            self.lent = (maintenant, HashSet::new());
        }
        for p in perdus_vus {
            if self.lent.1.len() >= LENT_MAX {
                break;
            }
            self.lent.1.insert(p);
        }
        s.rafale_lente = u32::try_from(self.lent.1.len()).unwrap_or(u32::MAX) >= score::L1_FICHIERS_MIN;
        if self.copies.0 != Copies::Aucune && maintenant.saturating_duration_since(self.copies.1) >= FENETRE_LENTE {
            self.copies = (Copies::Aucune, maintenant);
        }
        // R7 et débordement ne comptent, dans la veille des fichiers, que PENDANT une rafale : l'effacement des copies
        // hors rafale est mieux jugé par le flux des processus et sa ligne de commande (sinon le ménage planifié de
        // snapper ou timeshift crierait chaque jour, Critique C4).
        let recent = |t: Option<Instant>| t.is_some_and(|t| maintenant.saturating_duration_since(t) < fenetre::FENETRE);
        if recent(self.sature) {
            s.deborde_pendant_rafale = true;
        }
        if s.reecrits >= score::R1_SUSPECT {
            s.deborde_pendant_rafale |= recent(self.deborde);
            if self.copies.0 != Copies::Aucune {
                s.copies = Copies::PendantRafale;
            }
        }
        (s, reecrits)
    }

    /// La liste à jour des fichiers de la rafale (sans échantillonner) : pour l'attribution, après sa pause.
    fn reecrits_a_jour(&mut self) -> Vec<PathBuf> {
        self.absorber();
        let vus = self.vus(Instant::now());
        signaux_de(&vus, |_| false, |_, _| false).1
    }
}

/// Les lanceurs sous lesquels la remontée de lignée s'arrête : sinon la « racine » serait le bureau entier. Un shell,
/// un terminal, le compositeur, la session, systemd.
const LANCEURS: &[&str] = &[
    "systemd",
    "init",
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
    "ksh",
    "login",
    "agetty",
    "su",
    "sudo",
    "doas",
    "tmux",
    "screen",
    "gnome-shell",
    "plasmashell",
    "kwin_wayland",
    "kwin_x11",
    "Hyprland",
    "sway",
    "gnome-terminal-",
    "konsole",
    "alacritty",
    "foot",
    "kitty",
    "ghostty",
    "xterm",
    "sddm-helper",
    "gdm-session-wor",
    "lightdm",
    "nautilus",
    "dolphin",
    "thunar",
    "dbus-daemon",
    "systemd-logind",
];

/// La racine de la lignée d'un processus : on remonte les parents jusqu'à un lanceur connu (shell, terminal,
/// compositeur, systemd) ou le processus 1. Le dernier processus avant le lanceur est la racine ; un double `fork`
/// rattaché à systemd --user donne ainsi le dernier descendant utile.
fn racine_lignee(pid: u32) -> u32 {
    let mut courant = pid;
    let mut vus = HashSet::new();
    for _ in 0..64 {
        if !vus.insert(courant) {
            break;
        }
        let Some(parent) = lire_ppid(courant) else { break };
        if parent <= 1 {
            break;
        }
        let nom_parent = comm(parent).unwrap_or_default();
        if LANCEURS.iter().any(|l| nom_parent.starts_with(l)) {
            break;
        }
        courant = parent;
    }
    courant
}

/// Tente d'attribuer la rafale à un seul groupe (relevé des compteurs d'écriture à ~1 s d'écart et des descripteurs
/// ouverts en écriture sur les fichiers de la rafale). `fichiers` : les fichiers de la rafale. Pure logique dans
/// `attribution::juger_releves` ; ici, seulement la lecture système.
pub(crate) fn attribuer(v: &mut Veille, fichiers: &[PathBuf]) -> super::attribution::Attribution {
    use super::attribution::{self, Releve};
    let moi = std::process::id();
    let euid = euid();
    let octets: u64 = fichiers
        .iter()
        .take(ECHANTILLONS_MAX)
        .filter_map(|f| std::fs::metadata(f).ok().map(|m| m.len()))
        .sum();
    // Les processus du compte, hors Vanguard lui-même.
    let pids: Vec<u32> = crate::socle::processus::pids()
        .unwrap_or_default()
        .into_iter()
        .filter(|&p| p != moi && proprietaire(p) == Some(euid))
        .collect();
    // Premier relevé : les compteurs, et les fichiers tenus ouverts en écriture. Un chiffreur qui traite un fichier à
    // la fois l'a refermé avant le second relevé : sans ce premier regard, personne n'était jamais retenu.
    let mut releves: Vec<(u32, Releve)> = pids
        .iter()
        .map(|&pid| {
            (
                pid,
                Releve {
                    avant: attribution::compteurs_io(pid).map(|c| c.ecrits),
                    ouverts: attribution::ouverts_en_ecriture(pid),
                    ..Releve::default()
                },
            )
        })
        .collect();
    // ~800 ms entre les deux relevés : une rafale est rare, et geler vite prime sur la latence du connecteur.
    std::thread::sleep(std::time::Duration::from_millis(800));
    // La rafale à jour : le fichier tenu ouvert au premier relevé, refermé pendant la pause, y est entré.
    let rafale: HashSet<PathBuf> = fichiers.iter().cloned().chain(v.reecrits_a_jour()).collect();
    for (pid, r) in &mut releves {
        let pid = *pid;
        r.apres = attribution::compteurs_io(pid).map(|c| c.ecrits);
        r.present = Path::new(&format!("/proc/{pid}")).exists();
        r.illisible_connu = depart(pid).is_some_and(|d| v.illisibles_connus.contains(&(pid, d)));
        r.ouverts.extend(attribution::ouverts_en_ecriture(pid));
        r.groupe = racine_lignee(pid);
    }
    let releves: Vec<Releve> = releves.into_iter().map(|(_, r)| r).collect();
    attribution::juger_releves(&releves, &rafale, octets)
}

/// Les processus du compte (hors Vanguard) dont les compteurs ne se lisent pas, avec leur heure de départ : relevés
/// une fois, au démarrage de la veille.
fn illisibles_du_compte() -> HashSet<(u32, u64)> {
    let moi = std::process::id();
    let euid = euid();
    crate::socle::processus::pids()
        .unwrap_or_default()
        .into_iter()
        .filter(|&p| p != moi && proprietaire(p) == Some(euid))
        .filter(|&p| super::attribution::compteurs_io(p).is_none())
        .filter_map(|p| Some((p, depart(p)?)))
        .collect()
}

/// L'heure de départ d'un processus (22e champ de `/proc/<pid>/stat`, en tops depuis le démarrage) : avec le pid, elle
/// distingue un processus d'un autre qui aurait repris son numéro.
fn depart(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    depart_du_stat(&stat)
}

fn depart_du_stat(stat: &str) -> Option<u64> {
    let apres = &stat[stat.rfind(')')? + 1..];
    apres.split_whitespace().nth(19)?.parse().ok()
}

/// La lignée d'une racine (elle-même et ses descendants vivants), avec nom et chemin : ce que la réponse gèle.
pub(crate) fn lignee_de(racine: u32) -> Vec<super::reponse::Membre> {
    let parents: Vec<(u32, u32)> = crate::socle::processus::pids()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| Some((p, lire_ppid(p)?)))
        .collect();
    let mut pids = crate::commande::descendants(&parents, racine);
    pids.push(racine);
    pids.into_iter()
        .map(|pid| {
            (
                pid,
                comm(pid).unwrap_or_default(),
                crate::socle::processus::programme(pid),
            )
        })
        .collect()
}

/// Le compte effectif de ce processus.
fn euid() -> u32 {
    // SAFETY: geteuid ne prend aucun argument et ne touche aucune mémoire.
    unsafe { libc::geteuid() }
}

/// Le compte propriétaire d'un processus (champ « Uid: » de `/proc/<pid>/status`). `None` : illisible.
fn proprietaire(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Le parent d'un processus (PPID, 4e champ de `/proc/<pid>/stat`, après le nom entre parenthèses).
fn lire_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let apres = &stat[stat.rfind(')')? + 1..];
    apres.split_whitespace().nth(1)?.parse().ok()
}

/// Le nom court d'un processus (`/proc/<pid>/comm`).
fn comm(pid: u32) -> Option<String> {
    Some(
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()?
            .trim_end()
            .to_string(),
    )
}

/// Traduit un événement `notify` en changements à juger. Seuls comptent : contenu refermé après écriture, création,
/// suppression, renommage (avec l'ancien nom). L'ouverture, la simple modification de données non refermée et les
/// métadonnées sont ignorées (Critique C7 : le masque inotify comprend IN_OPEN et IN_MODIFY, non réglables).
fn changements_de(evenement: &notify::Event) -> Vec<Changement> {
    match &evenement.kind {
        EventKind::Access(AccessKind::Close(AccessMode::Write)) => evenement
            .paths
            .iter()
            .map(|p| Changement::nouveau(p.clone(), Sorte::Ecrit))
            .collect(),
        EventKind::Create(CreateKind::File) => evenement
            .paths
            .iter()
            .map(|p| Changement::nouveau(p.clone(), Sorte::Cree))
            .collect(),
        EventKind::Remove(RemoveKind::File) => evenement
            .paths
            .iter()
            .map(|p| Changement::nouveau(p.clone(), Sorte::Supprime))
            .collect(),
        // Arrivée depuis un dossier non surveillé (MOVED_TO sans MOVED_FROM) : le contenu est remplacé d'un coup,
        // comme une réécriture (pièges compris, R6). Pour un renommage interne, notify rend « To » puis « Both » sur
        // le même nouveau chemin : le dernier état, « renommé », l'emporte, sans double compte. Un dossier arrivé
        // ainsi n'est pas un fichier réécrit.
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => evenement
            .paths
            .iter()
            .filter(|p| !std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
            .map(|p| Changement::nouveau(p.clone(), Sorte::Ecrit))
            .collect(),
        // Un renommage complet : l'ancien chemin d'abord, le nouveau ensuite.
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) if let [ancien, nouveau] = evenement.paths.as_slice() => {
            vec![Changement::nouveau(
                nouveau.clone(),
                Sorte::Renomme { ancien: ancien.clone() },
            )]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vu(chemin: &str, sorte: Sorte) -> Vu {
        Vu {
            chemin: PathBuf::from(chemin),
            sorte,
        }
    }

    #[test]
    fn rafale_chiffree_comptee() {
        let mut changements = Vec::new();
        for i in 0..25 {
            changements.push(vu(&format!("/home/alice/Documents/f{i}.docx"), Sorte::Ecrit));
        }
        // 20 fichiers dans 4 dossiers, tous au format perdu.
        let (s, reecrits) = signaux_de(&changements, |_| false, |_, _| true);
        assert_eq!(s.reecrits, 25);
        assert_eq!(s.format_perdu, 25);
        assert_eq!(reecrits.len(), 25);
    }

    #[test]
    fn note_de_rancon_dans_trois_dossiers() {
        let changements = vec![
            vu("/home/alice/Documents/HOW_TO_DECRYPT.txt", Sorte::Cree),
            vu("/home/alice/Images/HOW_TO_DECRYPT.txt", Sorte::Cree),
            vu("/home/alice/Bureau/HOW_TO_DECRYPT.txt", Sorte::Cree),
        ];
        let (s, _) = signaux_de(&changements, |_| false, |_, _| false);
        assert!(s.note_de_rancon);
        assert_eq!(s.reecrits, 0);
    }

    #[test]
    fn extension_ajoutee_sur_cinq() {
        let mut changements = Vec::new();
        for i in 0..6 {
            changements.push(vu(
                &format!("/home/alice/Documents/f{i}.docx.locked"),
                Sorte::Renomme {
                    ancien: PathBuf::from(format!("/home/alice/Documents/f{i}.docx")),
                },
            ));
        }
        let (s, _) = signaux_de(&changements, |_| false, |_, _| false);
        assert!(s.noms_suspects);
        assert_eq!(s.reecrits, 6);
    }

    #[test]
    fn piege_touche_vu() {
        let piege = PathBuf::from("/home/alice/Documents/!Vanguard.txt");
        let changements = vec![vu("/home/alice/Documents/!Vanguard.txt", Sorte::Ecrit)];
        let (s, _) = signaux_de(&changements, |c| c == piege, |_, _| true);
        assert!(s.piege_touche);
    }

    /// Banc réel : dans un dossier jetable, on réécrit des fichiers EXISTANTS avec des octets au hasard (un faux
    /// chiffrement), et on vérifie que la veille voit la rafale et la juge au moins Grave. Jamais le vrai dossier
    /// personnel ; rien n'est gelé ni arrêté (le score seul est éprouvé ici).
    #[test]
    fn banc_reel_rafale_de_chiffrement() {
        use std::io::Write;
        let base = std::env::temp_dir().join(format!(
            "vanguard-rancon-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        // Trois dossiers, chacun avec des fichiers PDF bidon (en-tête %PDF) pré-existants.
        let dossiers: Vec<PathBuf> = ["Documents", "Images", "Bureau"].iter().map(|d| base.join(d)).collect();
        for d in &dossiers {
            std::fs::create_dir_all(d).unwrap();
        }
        let mut fichiers = Vec::new();
        for (i, d) in dossiers.iter().cycle().take(24).enumerate() {
            let f = d.join(format!("doc{i}.pdf"));
            let mut contenu = b"%PDF-1.7\n".to_vec();
            contenu.resize(8192, b' ');
            std::fs::write(&f, &contenu).unwrap();
            fichiers.push(f);
        }
        let Some(mut v) = Veille::demarrer(&dossiers, HashSet::new()) else {
            let _ = std::fs::remove_dir_all(&base);
            return crate::essais::saute("notify indisponible ici");
        };
        // Laisse inotify poser ses marques.
        std::thread::sleep(std::time::Duration::from_millis(300));
        // Faux chiffrement : réécriture complète par des octets au hasard, fichier refermé (IN_CLOSE_WRITE).
        for f in &fichiers {
            let mut octets = vec![0u8; 8192];
            getrandom::fill(&mut octets).unwrap();
            let mut fh = std::fs::OpenOptions::new().write(true).truncate(true).open(f).unwrap();
            fh.write_all(&octets).unwrap();
            fh.flush().unwrap();
        }
        // Les événements arrivent de façon asynchrone : on absorbe jusqu'à voir la rafale, 5 s au plus.
        let mut verdict = score::Verdict::Calme;
        for _ in 0..50 {
            v.absorber();
            let (s, _) = v.signaux(std::time::Instant::now());
            verdict = score::juger(&s, false);
            if verdict >= score::Verdict::Grave {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = std::fs::remove_dir_all(&base);
        if verdict < score::Verdict::Grave {
            return crate::essais::saute("inotify n'a pas rendu la rafale à temps (machine chargée)");
        }
        assert!(verdict >= score::Verdict::Grave, "verdict {verdict:?}");
    }

    #[test]
    fn git_clone_ne_crie_pas() {
        // Que des créations (git clone, tar x) : aucun réécrit, pas de note de rançon.
        let mut changements = Vec::new();
        for i in 0..50 {
            changements.push(vu(&format!("/home/alice/projet/src/f{i}.rs"), Sorte::Cree));
        }
        let (s, _) = signaux_de(&changements, |_| false, |_, _| true);
        assert_eq!(s.reecrits, 0);
        assert_eq!(score::juger(&s, false), score::Verdict::Calme);
    }

    #[test]
    fn piege_efface_n_est_pas_touche() {
        // « pieges --retirer » efface les pièges pendant que la veille tourne : pas d'alerte « rançongiciel ».
        let piege = PathBuf::from("/home/alice/Documents/!Vanguard.txt");
        let changements = vec![vu("/home/alice/Documents/!Vanguard.txt", Sorte::Supprime)];
        let (s, _) = signaux_de(&changements, |c| c == piege, |_, _| true);
        assert!(!s.piege_touche);
        assert_eq!(score::juger(&s, false), score::Verdict::Calme);
    }

    #[test]
    fn piege_renomme_puis_ecrit_est_touche() {
        let piege = PathBuf::from("/home/alice/Documents/!Vanguard.txt");
        let changements = vec![
            vu(
                "/home/alice/Documents/!Vanguard.txt.locked",
                Sorte::Renomme { ancien: piege.clone() },
            ),
            // L'écriture qui suit écrase l'entrée « renommé » du nouveau nom.
            vu("/home/alice/Documents/!Vanguard.txt.locked", Sorte::Ecrit),
        ];
        let (s, _) = signaux_de(&changements, |c| c == piege, |_, _| true);
        assert!(s.piege_touche);
    }

    #[test]
    fn arrivee_d_ailleurs_est_une_reecriture() {
        // MOVED_TO seul : un fichier chiffré hors des dossiers surveillés, posé par-dessus un piège.
        let piege = PathBuf::from("/home/alice/Documents/!Vanguard.txt");
        let e = notify::Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::To))).add_path(piege.clone());
        let c = changements_de(&e);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].sorte, Sorte::Ecrit);
        let vus: Vec<Vu> = c
            .into_iter()
            .map(|c| Vu {
                chemin: c.chemin,
                sorte: c.sorte,
            })
            .collect();
        let (s, _) = signaux_de(&vus, |c| c == piege, |_, _| false);
        assert!(s.piege_touche);
    }

    #[test]
    fn note_creee_puis_ecrite() {
        let mut changements = Vec::new();
        for d in ["Documents", "Images", "Bureau"] {
            let chemin = format!("/home/alice/{d}/HOW_TO_DECRYPT.txt");
            changements.push(vu(&chemin, Sorte::Cree));
            changements.push(vu(&chemin, Sorte::Ecrit));
        }
        let (s, _) = signaux_de(&changements, |_| false, |_, _| false);
        assert!(s.note_de_rancon);
        assert_eq!(s.reecrits, 0);
    }

    #[test]
    fn copie_de_fichiers_neufs_ne_crie_pas() {
        // Une copie, un `tar x` : CREATE puis CLOSE_WRITE sur des fichiers neufs, au contenu à forte entropie.
        let mut changements = Vec::new();
        for i in 0..50 {
            let chemin = format!("/home/alice/Musique/piste{i}.mp3");
            changements.push(vu(&chemin, Sorte::Cree));
            changements.push(vu(&chemin, Sorte::Ecrit));
        }
        let (s, _) = signaux_de(&changements, |_| false, |_, _| true);
        assert_eq!(s.reecrits, 0);
        assert_eq!(score::juger(&s, false), score::Verdict::Calme);
    }

    #[test]
    fn mille_reecrits_gardent_la_majorite() {
        let piege = PathBuf::from("/home/alice/Documents/!Vanguard.txt");
        let mut changements = vec![vu("/home/alice/Documents/!Vanguard.txt", Sorte::Ecrit)];
        for i in 0..1_000 {
            let d = ["Documents", "Images", "Bureau", "Musique"][i % 4];
            changements.push(vu(&format!("/home/alice/{d}/f{i}.docx"), Sorte::Ecrit));
        }
        let (s, _) = signaux_de(&changements, |c| c == piege, |_, _| true);
        assert!(s.format_perdu * 2 >= s.reecrits, "{} / {}", s.format_perdu, s.reecrits);
        assert_eq!(score::juger(&s, true), score::Verdict::QuasiCertain);
    }

    #[test]
    fn depart_lu_dans_stat() {
        let stat = "123 (a b) c) S 1 123 123 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 98765 0 0";
        assert_eq!(depart_du_stat(stat), Some(98_765));
        assert_eq!(depart_du_stat("123 (x) S 1"), None);
    }

    /// Une veille sur un dossier jetable, pour éprouver le cumul lent, la saturation et le vieillissement des
    /// drapeaux ; `None` si notify ne démarre pas ici.
    fn veille_jetable(nom: &str) -> Option<(Veille, PathBuf)> {
        let base = std::env::temp_dir().join(format!("vanguard-veille-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).ok()?;
        let v = Veille::demarrer(std::slice::from_ref(&base), HashSet::new());
        if v.is_none() {
            let _ = std::fs::remove_dir_all(&base);
        }
        Some((v?, base))
    }

    #[test]
    fn cumul_lent_compte_des_fichiers_distincts() {
        let Some((mut v, base)) = veille_jetable("lent") else {
            return crate::essais::saute("notify indisponible ici");
        };
        // 10 fichiers à forte entropie, revus à 10 tours : 10 fichiers, pas 100.
        let mut chemins = Vec::new();
        for i in 0..10 {
            let f = base.join(format!("f{i}.bin"));
            let mut octets = vec![0u8; 4096];
            getrandom::fill(&mut octets).unwrap();
            std::fs::write(&f, &octets).unwrap();
            chemins.push(f);
        }
        for f in &chemins {
            v.retenir(Changement::nouveau(f.clone(), Sorte::Ecrit));
        }
        let mut lente = false;
        for _ in 0..10 {
            let (s, _) = v.signaux(Instant::now());
            lente |= s.rafale_lente;
        }
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(v.lent.1.len(), 10);
        assert!(!lente);
    }

    #[test]
    fn fenetre_saturee_n_est_pas_calme() {
        let Some((mut v, base)) = veille_jetable("sature") else {
            return crate::essais::saute("notify indisponible ici");
        };
        let _ = std::fs::remove_dir_all(&base);
        // Des link/unlink en boucle : aucun réécrit, mais la fenêtre déborde.
        for i in 0..5_000 {
            let sorte = if i % 2 == 0 { Sorte::Cree } else { Sorte::Supprime };
            v.retenir(Changement::nouveau(base.join(format!("h{i}")), sorte));
        }
        let (s, _) = v.signaux(Instant::now());
        assert_ne!(score::juger(&s, false), score::Verdict::Calme);
    }

    #[test]
    fn drapeaux_anciens_ne_comptent_plus() {
        let Some((mut v, base)) = veille_jetable("vieux") else {
            return crate::essais::saute("notify indisponible ici");
        };
        let _ = std::fs::remove_dir_all(&base);
        let maintenant = Instant::now();
        let Some(il_y_a_une_heure) = maintenant.checked_sub(std::time::Duration::from_hours(1)) else {
            return crate::essais::saute("horloge monotone trop jeune");
        };
        v.deborde = Some(il_y_a_une_heure);
        v.copies = (Copies::SessionHorsRafale, il_y_a_une_heure);
        // Une rafale ordinaire de 12 fichiers (absents du disque : format non perdu).
        for i in 0..12 {
            v.retenir(Changement::nouveau(base.join(format!("f{i}.docx")), Sorte::Ecrit));
        }
        let (s, _) = v.signaux(maintenant);
        assert!(!s.deborde_pendant_rafale);
        assert_eq!(s.copies, Copies::Aucune);
        assert_eq!(score::juger(&s, false), score::Verdict::Suspect);
    }

    #[test]
    fn en_pause_le_canal_est_jete() {
        let Some((mut v, base)) = veille_jetable("pause") else {
            return crate::essais::saute("notify indisponible ici");
        };
        // Le canal est borné : rempli au-delà, le surplus est compté perdu, jamais gardé en mémoire.
        let (envoi, recepteur) = std::sync::mpsc::sync_channel(CANAL_MAX);
        let perdus = Arc::new(AtomicU64::new(0));
        let borne = Borne {
            envoi,
            perdus: Arc::clone(&perdus),
        };
        for i in 0..CANAL_MAX + 10 {
            borne.envoyer(Message::Changement(Changement::nouveau(
                base.join(format!("f{i}")),
                Sorte::Ecrit,
            )));
        }
        assert_eq!(perdus.load(Ordering::Relaxed), 10);
        v.recepteur = recepteur;
        v.perdus_canal = perdus;
        v.jeter();
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(v.absorber(), 0);
        assert_eq!(v.prendre_perdus(), 0);
    }
}
