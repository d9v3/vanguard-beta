//! La porte de lecture pour les assistants d'IA (`vanguard mcp`, Linux seulement tant que Windows n'est pas essayé
//! dans la VM) : un serveur MCP sur l'entrée et la sortie standard, en lecture seule, qu'un assistant lance sous le
//! compte de la personne. Cinq outils fermés lisent ce que Vanguard a déjà écrit (`outils`) ; aucun n'écrit, ne lance
//! d'examen, ne touche au réseau ni ne lit un fichier de la personne. Tout ce qui sort est marqué « non fiable » : le
//! contenu peut citer un attaquant.
//!
//! Le client est tenu pour hostile : messages bornés (64 Kio, finis en 10 s), rythme, durée et nombre de demandes
//! bornés, enveloppe stricte (`rpc`), lecture bornée pendant le cumul (`trame`). La seule écriture est la note de fin
//! de session au journal (`journal::noter_pour_la_porte`), sous l'interrupteur de lecture seule posé pour tout le
//! reste du processus.

mod outils;
mod rpc;
mod trame;
mod vues;

use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;

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
}

pub(crate) const BORNES: Bornes = Bornes {
    message_max: 64 * 1024,
    delai_message: Duration::from_secs(10),
    inactivite: Duration::from_mins(15),
    duree_max: Duration::from_hours(8),
    demandes_max: 10_000,
};

/// Ce qu'une session laisse au journal : des noms fermés et des nombres.
#[derive(Debug)]
pub(crate) struct BilanSession {
    pub(crate) fin: Fin,
    pub(crate) duree: Duration,
    pub(crate) appels: BTreeMap<String, u32>,
    pub(crate) refus: BTreeMap<String, u32>,
    pub(crate) hostile: bool,
}

/// Ce que le fil de lecture envoie : le premier octet d'un message (le délai part), puis ce qui est lu.
enum Recu {
    Debut,
    Lu(Lu),
}

/// Lit les messages dans un fil à part : l'attente d'une ligne ne bloque pas les délais. Le canal ne tient qu'un
/// message d'avance : un client qui envoie plus vite qu'on ne répond attend, sans que la mémoire grossisse.
fn lire_en_fond<R: Read + Send + 'static>(entree: R, max: usize) -> std::io::Result<mpsc::Receiver<Recu>> {
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

fn ecrire(sortie: &mut impl Write, texte: &str) -> bool {
    sortie
        .write_all(texte.as_bytes())
        .and_then(|()| sortie.write_all(b"\n"))
        .and_then(|()| sortie.flush())
        .is_ok()
}

/// Sert une session jusqu'à sa fin, et dit comment elle s'est finie.
pub(crate) fn servir<R: Read + Send + 'static>(
    entree: R,
    sortie: &mut impl Write,
    outils: &mut dyn Outils,
    bornes: Bornes,
) -> BilanSession {
    let depart = Instant::now();
    let mut session = Session::new(env!("CARGO_PKG_VERSION"), bornes.demandes_max);
    let fin = match lire_en_fond(entree, bornes.message_max) {
        Err(_) => Fin::ErreurLecture,
        Ok(recu) => boucle(&recu, sortie, outils, bornes, depart, &mut session),
    };
    BilanSession {
        fin,
        duree: depart.elapsed(),
        appels: session.appels.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
        refus: session.refus.iter().map(|(k, v)| (k.nom().to_string(), *v)).collect(),
        hostile: session.hostile,
    }
}

fn boucle(
    recu: &mpsc::Receiver<Recu>,
    sortie: &mut impl Write,
    outils: &mut dyn Outils,
    bornes: Bornes,
    depart: Instant,
    session: &mut Session,
) -> Fin {
    // La fin du message commencé, s'il y en a un.
    let mut echeance: Option<Instant> = None;
    loop {
        let restant = bornes.duree_max.saturating_sub(depart.elapsed());
        if restant.is_zero() {
            return Fin::Duree;
        }
        let (attente, fin_si_rien) = match echeance {
            Some(e) => (e.saturating_duration_since(Instant::now()).min(restant), Fin::Delai),
            None if bornes.inactivite < restant => (bornes.inactivite, Fin::Inactivite),
            None => (restant, Fin::Duree),
        };
        let lu = match recu.recv_timeout(attente) {
            Ok(Recu::Debut) => {
                let maintenant = Instant::now();
                echeance = Some(maintenant.checked_add(bornes.delai_message).unwrap_or(maintenant));
                continue;
            }
            Ok(Recu::Lu(lu)) => lu,
            Err(mpsc::RecvTimeoutError::Timeout) => return fin_si_rien,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Fin::ErreurLecture,
        };
        echeance = None;
        let suite = match lu {
            Lu::Ligne(ligne) => {
                let ms = u64::try_from(depart.elapsed().as_millis()).unwrap_or(u64::MAX);
                session.traiter(&ligne, ms, outils)
            }
            Lu::TropGrande => session.refuser(&Value::Null, Code::TropGrande),
            Lu::Fin => return Fin::FlotFini,
            Lu::Coupee => return Fin::Coupee,
            Lu::Erreur => return Fin::ErreurLecture,
        };
        if let Suite::Repondre { texte, fermer } = suite {
            if !ecrire(sortie, &texte) {
                return Fin::SortieFermee;
            }
            if let Some(f) = fermer {
                return f;
            }
        }
    }
}

/// Pourquoi la porte refuse de démarrer, s'il y a lieu : en root (ou administrateur élevé), elle lirait ce qu'un
/// compte ne voit pas et servirait un client sous ces droits ; sur un terminal, ce n'est pas un assistant qui parle.
fn refus_de_demarrer() -> Option<&'static str> {
    use std::io::IsTerminal as _;
    #[cfg(unix)]
    let eleve = crate::socle::euid() == 0;
    #[cfg(windows)]
    let eleve = crate::machine::windows::processus::eleve_ou_inconnu();
    if eleve {
        return Some(crate::tr!(
            "vanguard mcp : refusé en root ou en administrateur ; lancez-le sous votre compte.",
            "vanguard mcp: refused as root or administrator; run it under your own account."
        ));
    }
    if std::io::stdin().is_terminal() {
        return Some(crate::tr!(
            "vanguard mcp : c'est la porte de lecture pour les assistants d'IA ; un assistant la lance, pas un terminal.",
            "vanguard mcp: this is the read-only door for AI assistants; an assistant starts it, not a terminal."
        ));
    }
    None
}

/// La note de fin de session : un événement d'information, et une alerte si le client a été hostile.
fn noter(bilan: &BilanSession) {
    use crate::modele::evenement::{Evenement, Genre, Source};
    use crate::risk::Niveau;
    let mut evs = vec![
        Evenement::nouveau(
            Source::PorteMcp,
            Genre::SessionPorte {
                duree_s: bilan.duree.as_secs(),
                appels: bilan.appels.clone(),
                refus: bilan.refus.clone(),
                fin: bilan.fin.nom().to_string(),
            },
        )
        .gravite(Niveau::Info),
    ];
    if bilan.hostile {
        evs.push(
            Evenement::alerte(
                Source::PorteMcp,
                "porte-mcp",
                crate::tr!(
                    "Messages anormaux à la porte des assistants",
                    "Abnormal messages at the assistants' door"
                ),
                crate::tr!(
                    "Un programme branché à la porte de lecture des assistants d'IA lui a envoyé des messages anormaux.",
                    "A program connected to the read-only door for AI assistants sent it abnormal messages."
                ),
            )
            .gravite(Niveau::Moyen),
        );
    }
    // Une note qui ne passe pas (verrou tenu, disque) n'arrête rien : la session est déjà finie.
    let _ = crate::modele::journal::noter_pour_la_porte(&crate::socle::dossier_local(), evs);
}

/// `vanguard mcp` : refuse de démarrer s'il le faut (code 2), sert une session sur stdin et stdout, la note au
/// journal, rend 0. La lecture seule est déjà posée par `main`.
pub(crate) fn servir_stdio() -> i32 {
    if let Some(raison) = refus_de_demarrer() {
        eprintln!("{raison}");
        return 2;
    }
    crate::parametres::forcer_hors_ligne();
    crate::socle::canal_stdio::hors_des_vidages();
    let Ok(mut sortie) = crate::socle::canal_stdio::garder_stdout() else {
        eprintln!(
            "{}",
            crate::tr!(
                "vanguard mcp : la sortie standard n'a pas pu être réservée.",
                "vanguard mcp: standard output could not be reserved."
            )
        );
        return 2;
    };
    let Some(liens) = vues::Liens::tirer() else {
        eprintln!(
            "{}",
            crate::tr!(
                "vanguard mcp : le hasard du système n'a pas répondu.",
                "vanguard mcp: the system's randomness did not answer."
            )
        );
        return 2;
    };
    let mut porte = outils::Porte::new(crate::socle::dossier_local(), liens);
    let bilan = servir(std::io::stdin(), &mut sortie, &mut porte, BORNES);
    noter(&bilan);
    0
}

#[cfg(test)]
mod tests;
