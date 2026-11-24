//! La porte de lecture pour les assistants d'IA (`vanguard mcp`, Linux seulement : refusée sous Windows tant qu'elle
//! n'y est pas essayée dans la VM) : un serveur MCP sur l'entrée et la sortie standard, en lecture seule, qu'un
//! assistant lance sous le compte de la personne. Cinq outils fermés lisent ce que Vanguard a déjà écrit (`outils`) ;
//! aucun n'écrit, ne lance d'examen, ne touche au réseau ni ne lit un fichier de la personne. Tout ce qui sort est
//! marqué « non fiable » : le contenu peut citer un attaquant.
//!
//! Le client est tenu pour hostile : messages bornés (64 Kio, finis en 10 s), rythme, durée et nombre de demandes
//! bornés, réponse écrite en 10 s au plus, enveloppe stricte (`rpc`), lecture bornée pendant le cumul (`trame`). La
//! seule écriture est la note de session au journal (`journal::noter_pour_la_porte`), sous l'interrupteur de lecture
//! seule posé pour tout le reste du processus : écrite au premier appel d'outil servi, avant sa réponse (un processus
//! tué ensuite laisse donc sa trace), complétée à la fin si la fin vient ; l'alerte d'un client hostile, avant la
//! réponse qui ferme. Une session sans appel servi ne note rien, sauf l'alerte.

mod outils;
mod rpc;
// Lu par build.rs (le vocabulaire) ; ici, seulement pour ses essais.
#[cfg(test)]
mod sources;
mod trame;
mod vocabulaire;
mod vues;

/// Pour les essais des textes qui atteignent la porte (veilleur, dissimulation) : lus comme la porte les lit.
#[cfg(all(test, target_os = "linux"))]
pub(crate) use vues::texte_externe;

use std::collections::BTreeMap;
use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::modele::journal::NotePorte;
use rpc::{Code, Fin, Outils, Session, Suite};
use trame::Lu;

/// Les bornes d'une session.
#[derive(Clone, Copy)]
pub(crate) struct Bornes {
    /// La taille d'un message, en octets.
    pub(crate) message_max: usize,
    /// Le temps pour finir un message commencé.
    pub(crate) delai_message: Duration,
    /// Le temps sans message avant la fin de la session.
    pub(crate) inactivite: Duration,
    /// La durée d'une session.
    pub(crate) duree_max: Duration,
    /// Les demandes d'une session.
    pub(crate) demandes_max: u32,
    /// Le temps pour qu'une réponse soit prise par le client (`SortieBornee`).
    pub(crate) delai_ecriture: Duration,
}

pub(crate) const BORNES: Bornes = Bornes {
    message_max: 64 * 1024,
    delai_message: Duration::from_secs(10),
    inactivite: Duration::from_mins(15),
    duree_max: Duration::from_hours(8),
    demandes_max: 10_000,
    delai_ecriture: Duration::from_secs(10),
};

/// Le pas de l'attente : un signal d'arrêt est vu en moins de ce temps.
const PAS: Duration = Duration::from_millis(200);

/// Ce qu'une session laisse au journal : des noms fermés et des nombres.
#[derive(Debug)]
pub(crate) struct BilanSession {
    pub(crate) fin: Fin,
    pub(crate) duree: Duration,
    pub(crate) appels: BTreeMap<String, u32>,
    pub(crate) refus: BTreeMap<String, u32>,
    pub(crate) hostile: bool,
}

impl BilanSession {
    fn de(session: &Session, fin: Fin, duree: Duration) -> BilanSession {
        BilanSession {
            fin,
            duree,
            appels: session.appels.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
            refus: session.refus.iter().map(|(k, v)| (k.nom().to_string(), *v)).collect(),
            hostile: session.hostile || fin == Fin::SortieBloquee,
        }
    }
}

/// Qui note la session, et quand : au premier appel servi (`ouvrir`, avant sa réponse), au premier signe hostile
/// (`alerter`, avant la réponse qui ferme), puis à la fin (`fermer`). Chacun n'est appelé qu'une fois.
pub(crate) trait Noteur {
    fn ouvrir(&mut self, ouverture: &BilanSession);
    fn alerter(&mut self);
    fn fermer(&mut self, bilan: &BilanSession);
}

/// Le noteur du vrai programme : le journal du dossier de données, par `journal::noter_pour_la_porte`, qui ne crée,
/// n'adopte ni ne répare rien (dossier ou sceaux absents : rien de noté) et freine les notes à l'heure.
pub(crate) struct NoteurJournal {
    dossier: PathBuf,
    /// La note d'ouverture est écrite : la note de fin la complète. Retenue par le frein, la fin l'est aussi.
    ouverte: bool,
    alertee: bool,
}

impl NoteurJournal {
    pub(crate) fn new(dossier: PathBuf) -> NoteurJournal {
        NoteurJournal {
            dossier,
            ouverte: false,
            alertee: false,
        }
    }

    // Une note qui ne passe pas (verrou tenu, disque, dossier absent) n'arrête rien : la porte sert quand même.
    fn noter(&self, ev: crate::modele::evenement::Evenement) -> Option<NotePorte> {
        crate::modele::journal::noter_pour_la_porte(&self.dossier, ev).ok()
    }
}

fn note_de_session(bilan: &BilanSession) -> crate::modele::evenement::Evenement {
    use crate::modele::evenement::{Evenement, Genre, Source};
    Evenement::nouveau(
        Source::PorteMcp,
        Genre::SessionPorte {
            duree_s: bilan.duree.as_secs(),
            appels: bilan.appels.clone(),
            refus: bilan.refus.clone(),
            fin: bilan.fin.nom().to_string(),
            retenues: 0,
            alertes_retenues: 0,
            retenues_au_moins: false,
        },
    )
    .gravite(crate::risk::Niveau::Info)
}

fn alerte_hostile() -> crate::modele::evenement::Evenement {
    use crate::modele::evenement::{Evenement, Source};
    use crate::modele::journal::PORTE_FAMILLE;
    Evenement::alerte(
        Source::PorteMcp,
        PORTE_FAMILLE,
        crate::tr!(
            "Messages anormaux à la porte des assistants",
            "Abnormal messages at the assistants' door"
        ),
        crate::tr!(
            "Un programme branché à la porte de lecture des assistants d'IA lui a envoyé des messages anormaux, ou n'a pas lu ses réponses.",
            "A program connected to the read-only door for AI assistants sent it abnormal messages, or did not read its replies."
        ),
    )
    .gravite(crate::risk::Niveau::Moyen)
    .cle(Some(PORTE_FAMILLE))
}

impl Noteur for NoteurJournal {
    fn ouvrir(&mut self, ouverture: &BilanSession) {
        self.ouverte = self.noter(note_de_session(ouverture)) == Some(NotePorte::Ecrite);
    }

    fn alerter(&mut self) {
        self.alertee = true;
        let _ = self.noter(alerte_hostile());
    }

    fn fermer(&mut self, bilan: &BilanSession) {
        if bilan.hostile && !self.alertee {
            self.alerter();
        }
        if self.ouverte {
            let _ = self.noter(note_de_session(bilan));
        }
    }
}

/// Ce que le fil de lecture envoie : le premier octet d'un message (le délai part), puis ce qui est lu.
enum Recu {
    Debut,
    Lu(Lu),
}

/// Lit les messages dans un fil à part : l'attente d'une ligne ne bloque pas les délais. Le canal ne tient qu'un
/// message d'avance : un client qui envoie plus vite qu'on ne répond attend, sans que la mémoire grossisse.
fn lire_en_fond<R: Read + Send + 'static>(entree: R, max: usize) -> io::Result<mpsc::Receiver<Recu>> {
    let (envoi, recu) = mpsc::sync_channel(1);
    crate::socle::fil::lancer("porte-mcp-lecture", move || {
        let mut lecteur = BufReader::with_capacity(16 * 1024, entree);
        loop {
            let debut = envoi.clone();
            let lu = trame::lire_ligne(&mut lecteur, max, &mut || {
                let _ = debut.send(Recu::Debut);
            });
            let fini = !matches!(lu, Lu::Ligne(_));
            if envoi.send(Recu::Lu(lu)).is_err() || fini {
                return;
            }
        }
    })?;
    Ok(recu)
}

/// Une sortie dont chaque réponse doit être prise par le client en `delai` : l'écriture se fait dans un fil à part,
/// et un client qui ne lit plus (tuyau plein) ne retient pas la porte au-delà. Bloquée, elle le reste
/// (`ErrorKind::TimedOut`) ; le fil d'écriture, coincé, part avec le processus.
pub(crate) struct SortieBornee {
    envoi: mpsc::SyncSender<Vec<u8>>,
    accuse: mpsc::Receiver<bool>,
    tampon: Vec<u8>,
    delai: Duration,
    bloquee: bool,
}

impl SortieBornee {
    pub(crate) fn new<W: Write + Send + 'static>(mut dehors: W, delai: Duration) -> io::Result<SortieBornee> {
        let (envoi, recu) = mpsc::sync_channel::<Vec<u8>>(1);
        let (accord, accuse) = mpsc::sync_channel::<bool>(1);
        crate::socle::fil::lancer("porte-mcp-ecriture", move || {
            for bloc in recu {
                let ecrit = dehors.write_all(&bloc).and_then(|()| dehors.flush()).is_ok();
                if accord.send(ecrit).is_err() || !ecrit {
                    return;
                }
            }
        })?;
        Ok(SortieBornee {
            envoi,
            accuse,
            tampon: Vec::new(),
            delai,
            bloquee: false,
        })
    }
}

impl Write for SortieBornee {
    fn write(&mut self, octets: &[u8]) -> io::Result<usize> {
        if self.bloquee {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.tampon.extend_from_slice(octets);
        Ok(octets.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.bloquee {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if self.tampon.is_empty() {
            return Ok(());
        }
        // Le fil d'écriture attend, libre, après chaque accusé : un canal plein dit qu'il est encore coincé.
        match self.envoi.try_send(std::mem::take(&mut self.tampon)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                self.bloquee = true;
                return Err(io::ErrorKind::TimedOut.into());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return Err(io::ErrorKind::BrokenPipe.into()),
        }
        match self.accuse.recv_timeout(self.delai) {
            Ok(true) => Ok(()),
            Ok(false) | Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.bloquee = true;
                Err(io::ErrorKind::TimedOut.into())
            }
        }
    }
}

fn ecrire(sortie: &mut impl Write, texte: &str) -> Result<(), Fin> {
    sortie
        .write_all(texte.as_bytes())
        .and_then(|()| sortie.write_all(b"\n"))
        .and_then(|()| sortie.flush())
        .map_err(|e| {
            if e.kind() == io::ErrorKind::TimedOut {
                Fin::SortieBloquee
            } else {
                Fin::SortieFermee
            }
        })
}

/// Ce que la session sert, qui la note, et le drapeau d'arrêt (signal).
pub(crate) struct Branchements<'a> {
    pub(crate) outils: &'a mut dyn Outils,
    pub(crate) noteur: &'a mut dyn Noteur,
    pub(crate) arret: &'a AtomicBool,
}

/// Sert une session jusqu'à sa fin, la note (`Noteur`), et dit comment elle s'est finie.
pub(crate) fn servir<R: Read + Send + 'static>(
    entree: R,
    sortie: &mut impl Write,
    b: &mut Branchements<'_>,
    bornes: Bornes,
) -> BilanSession {
    let depart = Instant::now();
    let mut session = Session::new(env!("CARGO_PKG_VERSION"), bornes.demandes_max);
    let fin = match lire_en_fond(entree, bornes.message_max) {
        Err(_) => Fin::ErreurLecture,
        Ok(recu) => boucle(&recu, sortie, b, bornes, depart, &mut session),
    };
    let bilan = BilanSession::de(&session, fin, depart.elapsed());
    b.noteur.fermer(&bilan);
    bilan
}

fn boucle(
    recu: &mpsc::Receiver<Recu>,
    sortie: &mut impl Write,
    b: &mut Branchements<'_>,
    bornes: Bornes,
    depart: Instant,
    session: &mut Session,
) -> Fin {
    // La fin du message commencé, s'il y en a un, et celle du silence.
    let mut echeance: Option<Instant> = None;
    let mut silence = Instant::now();
    let (mut ouverte, mut alertee) = (false, false);
    loop {
        if b.arret.load(Ordering::SeqCst) {
            return Fin::Signal;
        }
        let maintenant = Instant::now();
        let restant = bornes.duree_max.saturating_sub(depart.elapsed());
        if restant.is_zero() {
            return Fin::Duree;
        }
        let (attente, fin_si_rien) = if let Some(e) = echeance {
            (e.saturating_duration_since(maintenant).min(restant), Fin::Delai)
        } else {
            let calme = bornes
                .inactivite
                .saturating_sub(maintenant.saturating_duration_since(silence));
            if calme < restant {
                (calme, Fin::Inactivite)
            } else {
                (restant, Fin::Duree)
            }
        };
        if attente.is_zero() {
            return fin_si_rien;
        }
        let lu = match recu.recv_timeout(attente.min(PAS)) {
            Ok(Recu::Debut) => {
                echeance = Some(Instant::now().checked_add(bornes.delai_message).unwrap_or(maintenant));
                continue;
            }
            Ok(Recu::Lu(lu)) => lu,
            // Le pas passé, la vraie échéance est revue en tête de boucle.
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Fin::ErreurLecture,
        };
        echeance = None;
        // Une ligne vide n'est pas une activité : le silence continue de courir.
        let (vides, recu_a) = (session.vides, Instant::now());
        let suite = match lu {
            Lu::Ligne(ligne) => {
                let ms = u64::try_from(depart.elapsed().as_millis()).unwrap_or(u64::MAX);
                session.traiter(&ligne, ms, b.outils)
            }
            Lu::TropGrande => session.refuser(&Value::Null, Code::TropGrande),
            Lu::Fin => return Fin::FlotFini,
            Lu::Coupee => return Fin::Coupee,
            Lu::Erreur => return Fin::ErreurLecture,
        };
        if session.vides == vides {
            silence = recu_a;
        }
        // Les notes avant la réponse : un client qui tue la porte en la lisant ne les efface pas.
        if !ouverte && !session.appels.is_empty() {
            ouverte = true;
            b.noteur
                .ouvrir(&BilanSession::de(session, Fin::Ouverte, depart.elapsed()));
            b.outils.apres_sa_note();
        }
        if !alertee && session.hostile {
            alertee = true;
            b.noteur.alerter();
            b.outils.apres_sa_note();
        }
        if let Suite::Repondre { texte, fermer } = suite {
            if let Err(f) = ecrire(sortie, &texte) {
                return f;
            }
            if let Some(f) = fermer {
                return f;
            }
        }
    }
}

/// Les droits du processus sont-ils élevés, d'après `/proc/self/status` ? Oui si un des quatre `Uid` (réel, effectif,
/// gardé, du système de fichiers) est 0 ou s'ils diffèrent (programme setuid), si les quatre `Gid` diffèrent, si une
/// capacité effective est tenue (`CapEff`), ou si un de ces champs manque ou ne se lit pas : non vérifié, refusé.
#[cfg(any(unix, test))]
fn eleve_d_apres(status: &str) -> bool {
    let champ = |nom: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(nom))
            .map(|reste| reste.split_whitespace().collect::<Vec<_>>())
    };
    let pareils = |v: &[&str]| v.len() == 4 && v.iter().all(|x| Some(x) == v.first());
    let (Some(uid), Some(gid), Some(cap)) = (champ("Uid:"), champ("Gid:"), champ("CapEff:")) else {
        return true;
    };
    let capacites = match cap.as_slice() {
        [hexa] => u64::from_str_radix(hexa, 16).ok(),
        _ => None,
    };
    let compte = pareils(&uid) && uid.first().and_then(|u| u.parse::<u32>().ok()).is_some_and(|n| n != 0);
    let groupe = pareils(&gid) && gid.first().is_some_and(|g| g.parse::<u32>().is_ok());
    !(compte && groupe && capacites == Some(0))
}

/// Les droits du processus sont-ils élevés (root, setuid, setgid, capacités) ? Illisible : oui.
#[cfg(unix)]
fn droits_eleves() -> bool {
    crate::socle::euid() == 0 || crate::socle::lire_texte("/proc/self/status").map_or(true, |s| eleve_d_apres(&s))
}

#[cfg(windows)]
fn droits_eleves() -> bool {
    crate::machine::windows::processus::eleve_ou_inconnu()
}

/// Pourquoi la porte refuse de démarrer, s'il y a lieu : sous Windows, tant qu'elle n'y est pas essayée ; avec des
/// droits élevés, elle lirait ce qu'un compte ne voit pas et servirait un client sous ces droits ; sur un terminal,
/// ce n'est pas un assistant qui parle (une aide contre l'erreur, pas une protection : un programme du compte peut
/// toujours lui donner un tuyau).
fn refus_de_demarrer() -> Option<&'static str> {
    use std::io::IsTerminal as _;
    if cfg!(windows) {
        return Some(crate::tr!(
            "vanguard mcp : pas encore offert sous Windows (pas encore essayé sur un vrai Windows).",
            "vanguard mcp: not offered on Windows yet (not yet tried on a real Windows)."
        ));
    }
    if droits_eleves() {
        return Some(crate::tr!(
            "vanguard mcp : refusé en root, en administrateur ou avec des droits élevés ; lancez-le sous votre compte.",
            "vanguard mcp: refused as root, administrator or with raised rights; run it under your own account."
        ));
    }
    #[cfg(target_os = "linux")]
    if plafond_refuse(&crate::socle::processus::plafond_de_fichier()) {
        return Some(crate::tr!(
            "vanguard mcp : refusé sous un plafond de taille de fichier (ulimit -f) ou s'il ne se lit pas ; \
             la note au journal pourrait être coupée au milieu.",
            "vanguard mcp: refused under a file size limit (ulimit -f) or if it cannot be read; \
             the journal note could be cut in the middle."
        ));
    }
    if io::stdin().is_terminal() {
        return Some(crate::tr!(
            "vanguard mcp : c'est la porte de lecture pour les assistants d'IA ; un assistant la lance, pas un terminal.",
            "vanguard mcp: this is the read-only door for AI assistants; an assistant starts it, not a terminal."
        ));
    }
    None
}

/// Un plafond de taille de fichier (RLIMIT_FSIZE) posé par celui qui lance la porte coupe une écriture au milieu :
/// refusé, comme un plafond qui ne se lit pas. Seul « sans plafond » passe.
#[cfg(target_os = "linux")]
fn plafond_refuse(lu: &io::Result<u64>) -> bool {
    !matches!(lu, Ok(u64::MAX))
}

fn dire(texte: &str) -> i32 {
    eprintln!("{texte}");
    2
}

/// `vanguard mcp` : refuse de démarrer s'il le faut (code 2), sert une session sur stdin et stdout, la note au
/// journal, rend 0. La lecture seule est déjà posée par `main`.
pub(crate) fn servir_stdio() -> i32 {
    if let Some(raison) = refus_de_demarrer() {
        return dire(raison);
    }
    // SIGTERM, SIGINT, SIGHUP : la session finit et se note, au lieu d'être tuée au milieu.
    #[cfg(target_os = "linux")]
    let Ok(arret) = crate::socle::canal_stdio::fin_sur_signal() else {
        return dire(crate::tr!(
            "vanguard mcp : les signaux d'arrêt n'ont pas pu être pris.",
            "vanguard mcp: the stop signals could not be taken."
        ));
    };
    #[cfg(target_os = "linux")]
    if crate::socle::canal_stdio::depassement_de_taille_ignore().is_err() {
        return dire(crate::tr!(
            "vanguard mcp : le signal de dépassement de taille n'a pas pu être ignoré.",
            "vanguard mcp: the file size signal could not be ignored."
        ));
    }
    #[cfg(not(target_os = "linux"))]
    let arret = &AtomicBool::new(false);
    crate::parametres::forcer_hors_ligne();
    crate::socle::canal_stdio::hors_des_vidages();
    let Ok(sortie) = crate::socle::canal_stdio::garder_stdout() else {
        return dire(crate::tr!(
            "vanguard mcp : la sortie standard n'a pas pu être réservée.",
            "vanguard mcp: standard output could not be reserved."
        ));
    };
    let Ok(mut sortie) = SortieBornee::new(sortie, BORNES.delai_ecriture) else {
        return dire(crate::tr!(
            "vanguard mcp : le fil d'écriture n'a pas pu partir.",
            "vanguard mcp: the writing thread could not start."
        ));
    };
    let Some(liens) = vues::Liens::tirer() else {
        return dire(crate::tr!(
            "vanguard mcp : le hasard du système n'a pas répondu.",
            "vanguard mcp: the system's randomness did not answer."
        ));
    };
    let mut porte = outils::Porte::new(crate::socle::dossier_local(), liens);
    let mut noteur = NoteurJournal::new(crate::socle::dossier_local());
    let mut b = Branchements {
        outils: &mut porte,
        noteur: &mut noteur,
        arret,
    };
    servir(io::stdin(), &mut sortie, &mut b, BORNES);
    0
}

#[cfg(test)]
mod tests;
