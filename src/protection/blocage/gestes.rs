//! Les gestes du blocage : préparés (ce qui sera fait, montré avant l'accord, ou pourquoi rien ne se fera), faits,
//! notés avec de quoi les défaire (changements.rs), puis défaits sur demande. Tout ce qui peut empêcher un geste
//! (garde-fou, droits, pare-feu absent) est vérifié avant d'y toucher : rien n'est fait à moitié.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::gardes;
use super::menaces::{Geste, Menace};
use super::pare_feu::{self, PareFeu};
use crate::changements::{self, Annulation, Blocage, Inverse};
use crate::machine::regles::Os;
use crate::modele::{Echec, Raison};
use crate::protection::preuve;
use crate::ui::{affichable, chemin_affichable};
use crate::{tr, trf};

/// Ce que le geste a besoin de savoir de cet ordinateur, lu une fois par passage.
pub(crate) struct Contexte {
    pub os: Os,
    /// Vanguard, ce qu'il a lancé, ce qui le fait tourner : jamais arrêtés.
    pub intouchables: HashSet<u32>,
    /// Ce que les connexions en cours interdisent de couper ; `None` : illisibles.
    pub sessions: Option<gardes::Sessions>,
    pub pare_feu: Result<PareFeu, Echec>,
    /// Vanguard tourne en administrateur (root, jeton élevé) : rien à demander.
    pub admin: bool,
    /// Quelqu'un peut répondre à une demande de mot de passe ou d'administrateur : pas la surveillance horaire.
    pub interactif: bool,
    /// Le programme de Vanguard, jamais mis en quarantaine.
    pub mon_programme: Option<String>,
}

impl Contexte {
    pub(crate) fn lire(intouchables: HashSet<u32>, interactif: bool) -> Contexte {
        Contexte {
            os: Os::actuel(),
            intouchables,
            sessions: gardes::sessions_a_distance(),
            pare_feu: pare_feu::detecter(),
            admin: administrateur(),
            interactif,
            mon_programme: std::env::current_exe().ok().map(|c| {
                let c = c.to_string_lossy();
                c.strip_suffix(" (deleted)").unwrap_or(&c).to_string()
            }),
        }
    }
}

/// Un geste prêt : ce qui sera fait, montré avant l'accord, et comment le faire.
pub(crate) struct Pret {
    /// Une phrase par étape.
    pub etapes: Vec<String>,
    /// Les commandes, montrées puis lancées par `machine::appliquer_sans_noter`.
    pub commandes: Vec<String>,
    faire: Faire,
}

enum Faire {
    /// Les commandes seules : leur inverse est connu d'avance.
    Commandes {
        annulation: Annulation,
        /// ufw : le port fermé en entrée, retenu seulement si `ufw status` montre le refus avant toute autorisation.
        retenir: Option<u16>,
    },
    /// Arrêter le processus (par les commandes, ou par Windows lui-même pour un processus de ce compte), puis mettre
    /// le fichier en quarantaine.
    Programme {
        arret: Option<Arret>,
        quarantaine: Option<(PathBuf, String)>,
    },
    Demarrage {
        id: String,
    },
    Permissions {
        fichier: PathBuf,
        nouveau: String,
    },
}

struct Arret {
    pid: u32,
    /// Le programme qu'il faisait tourner à la détection : relu juste avant l'arrêt.
    chemin: String,
    /// Sous Windows, un processus de ce compte s'arrête sans fenêtre d'administrateur (TerminateProcess).
    #[cfg_attr(not(windows), allow(dead_code))]
    ici: bool,
}

fn droits_manquants() -> String {
    tr!(
        "droits d'administrateur manquants : rien n'a été fait (ouvrez Vanguard, Bloquer et réagir › Blocage des menaces)",
        "administrator rights missing: nothing was done (open Vanguard, Block and respond › Threat blocking)"
    )
    .to_string()
}

/// Prépare le geste d'une menace : `Err` dit pourquoi il ne se fera pas (garde-fou, droits, pare-feu non
/// disponible) ; la menace reste alors une alerte. `automatique` : le geste se fera sans clic (protection active),
/// et les garde-fous sont alors plus stricts.
pub(crate) fn preparer(m: &Menace, ctx: &Contexte, automatique: bool) -> Result<Pret, Echec> {
    const OU: &str = "blocage/preparer";
    let (pret, droits) = match &m.geste {
        Geste::Programme {
            pid,
            nom,
            chemin,
            fichier,
            detection,
        } => preparer_programme(*pid, nom, (chemin.as_deref(), fichier.as_deref()), detection, ctx)?,
        Geste::Adresse { ip } => {
            if let Some(raison) = gardes::adresse_intouchable(*ip, ctx.sessions.as_ref(), automatique) {
                return Err(Echec::refuse(OU, raison));
            }
            let pf = ctx.pare_feu.clone()?;
            let regle = pare_feu::sortante(pf, *ip);
            let mut etapes = vec![pare_feu::decrire_sortante(pf, *ip)];
            etapes.extend(regle.limite.map(str::to_string));
            let pret = Pret {
                etapes,
                commandes: regle.poser,
                faire: Faire::Commandes {
                    annulation: Annulation::Commandes {
                        commandes: regle.retirer,
                        port: None,
                        inverse: Some(Inverse::Sortante {
                            pare_feu: pf,
                            adresse: ip.to_canonical(),
                        }),
                    },
                    retenir: None,
                },
            };
            (pret, true)
        }
        Geste::Demarrage { id, nom, machine } => {
            let pret = Pret {
                etapes: vec![trf!(
                    "Retirer « {nom} » du démarrage : il reste installé, et se remet exactement par « vanguard blocage annuler »",
                    "Remove “{nom}” from startup: it stays installed, and is put back exactly with “vanguard blocking undo”"
                )],
                commandes: Vec::new(),
                faire: Faire::Demarrage { id: id.clone() },
            };
            (pret, *machine)
        }
        #[cfg(windows)]
        Geste::Pilotes { avant } => {
            let pret = Pret {
                etapes: vec![
                    tr!(
                        "Activer la liste de Microsoft qui bloque les pilotes vulnérables, effective après le prochain redémarrage",
                        "Turn on Microsoft's vulnerable driver blocklist, effective after the next restart"
                    )
                    .to_string(),
                    tr!(
                        "Un vieux pilote vulnérable (outil matériel, ancien anti-triche) ne se chargera plus : c'est le but",
                        "An old vulnerable driver (hardware tool, old anti-cheat) will no longer load: that is the point"
                    )
                    .to_string(),
                ],
                commandes: vec![crate::machine::windows::corrections::id("pilotes-vulnerables-bloques")],
                faire: Faire::Commandes {
                    annulation: Annulation::Commandes {
                        commandes: annuler_pilotes(*avant),
                        port: None,
                        inverse: Some(Inverse::Pilotes { avant: *avant }),
                    },
                    retenir: None,
                },
            };
            (pret, true)
        }
        Geste::ServeurIa { port, nom } => {
            if let Some(raison) = gardes::port_intouchable(*port) {
                return Err(Echec::refuse(OU, raison));
            }
            let pf = ctx.pare_feu.clone()?;
            let Some(regle) = pare_feu::entrante(pf, *port) else {
                return Err(Echec::refuse(
                    OU,
                    trf!(
                        "non disponible ici : faites écouter {nom} sur 127.0.0.1 seulement (Ollama : OLLAMA_HOST=127.0.0.1)",
                        "not available here: make {nom} listen on 127.0.0.1 only (Ollama: OLLAMA_HOST=127.0.0.1)"
                    ),
                ));
            };
            let mut etapes = vec![trf!(
                "Fermer au réseau le port {port} ({nom}) dans {} : il reste joignable depuis cet ordinateur seulement",
                "Close port {port} ({nom}) to the network in {}: it stays reachable from this computer only",
                pf.nom()
            )];
            etapes.extend(regle.limite.map(str::to_string));
            // ufw : le port est retenu, comme pour la correction du bilan, qui le dit alors fermé.
            let retenir = (pf == PareFeu::Ufw).then_some(*port);
            let pret = Pret {
                etapes,
                commandes: regle.poser,
                faire: Faire::Commandes {
                    annulation: Annulation::Commandes {
                        commandes: regle.retirer,
                        port: retenir.map(|p| format!("{p}/tcp")),
                        inverse: Some(Inverse::Entrante {
                            pare_feu: pf,
                            port: *port,
                        }),
                    },
                    retenir,
                },
            };
            (pret, true)
        }
        Geste::Permissions { fichier, outil } => {
            let texte = std::fs::read_to_string(fichier).map_err(|e| Echec::io(OU, &e))?;
            let nouveau = sans_contournement(&texte).ok_or_else(|| {
                Echec::refuse(
                    OU,
                    tr!(
                        "réglage écrit d'une façon que Vanguard ne réécrit pas sans risque : à changer à la main (defaultMode « default »)",
                        "setting written in a way Vanguard does not rewrite safely: change it by hand (defaultMode “default”)"
                    ),
                )
            })?;
            let pret = Pret {
                etapes: vec![
                    trf!(
                        "Remettre les demandes de permission de {outil} : « defaultMode » passe de « bypassPermissions » à « default » dans {}",
                        "Bring {outil}'s permission prompts back: “defaultMode” goes from “bypassPermissions” to “default” in {}",
                        chemin_affichable(fichier)
                    ),
                    tr!(
                        "Le fichier d'avant est copié dans le dossier de Vanguard, et remis tel quel par « vanguard blocage annuler »",
                        "The previous file is copied to Vanguard's folder, and put back as it was with “vanguard blocking undo”"
                    )
                    .to_string(),
                ],
                commandes: Vec::new(),
                faire: Faire::Permissions {
                    fichier: fichier.clone(),
                    nouveau,
                },
            };
            (pret, false)
        }
    };
    if droits && !ctx.admin && !ctx.interactif {
        return Err(Echec::refuse(OU, droits_manquants()));
    }
    Ok(pret)
}

/// Deux chemins de programme sont-ils le même ? Sans tenir compte de la casse sous Windows.
fn meme_chemin(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// `chemin` : le programme du processus à la détection ; `fichier` : ce qui serait mis en quarantaine (jamais un
/// interpréteur, voir `menaces::a_isoler`).
fn preparer_programme(
    pid: Option<u32>,
    nom: &str,
    (chemin, fichier): (Option<&Path>, Option<&Path>),
    detection: &str,
    ctx: &Contexte,
) -> Result<(Pret, bool), Echec> {
    let chemin_texte = chemin.map(|c| c.to_string_lossy().into_owned());
    let mut etapes = Vec::new();
    let mut commandes = Vec::new();
    let mut droits = false;
    // Le processus tourne-t-il toujours, avec le même programme ? Un numéro repris par un autre programme ne s'arrête
    // jamais.
    let arret = match (pid, chemin_du_processus_tel(pid)) {
        (Some(pid), Some(actuel)) => {
            if !chemin_texte.as_deref().is_some_and(|c| meme_chemin(c, &actuel)) {
                return Err(Echec::refuse(
                    "blocage/preparer",
                    trf!(
                        "le PID {pid} désigne maintenant un autre programme : rien n'est arrêté",
                        "PID {pid} now points to another program: nothing is stopped"
                    ),
                ));
            }
            if let Some(raison) = gardes::processus_intouchable(pid, nom, Some(&actuel), &ctx.intouchables, ctx.os) {
                return Err(Echec::refuse("blocage/preparer", raison));
            }
            let ici = arret_sans_droits(pid);
            if !ici {
                droits = !ctx.admin;
                commandes.push(commande_d_arret(pid, &actuel, !ctx.admin));
            } else if cfg!(not(windows)) {
                commandes.push(commande_d_arret(pid, &actuel, false));
            }
            etapes.push(trf!(
                "Arrêter « {nom} » (PID {pid}) tout de suite",
                "Stop “{nom}” (PID {pid}) right away"
            ));
            Some(Arret {
                pid,
                chemin: actuel,
                ici: ici && cfg!(windows),
            })
        }
        _ => None,
    };
    // Un interpréteur ou un shell n'est jamais mis en quarantaine, même si on le désignait ici : seul son script.
    let fichier = fichier.filter(|f| !super::menaces::lance_du_code(&f.to_string_lossy()));
    let quarantaine = match fichier.filter(|c| c.is_file()) {
        Some(c) => {
            let texte = c.to_string_lossy();
            if let Some(raison) = gardes::fichier_intouchable(&texte, ctx.os, ctx.mon_programme.as_deref()) {
                return Err(Echec::refuse("blocage/preparer", raison));
            }
            if !peut_deplacer(c) {
                return Err(Echec::refuse(
                    "blocage/preparer",
                    tr!(
                        "ce compte ne peut pas déplacer ce fichier : relancez Vanguard en administrateur (sudo, ou « Exécuter en tant qu'administrateur ») ; rien n'a été fait",
                        "this account cannot move this file: start Vanguard again as administrator (sudo, or “Run as administrator”); nothing was done"
                    ),
                ));
            }
            etapes.push(trf!(
                "Mettre « {} » en quarantaine : rendu inutilisable, remis exactement par « vanguard blocage annuler »",
                "Quarantine “{}”: made unusable, put back exactly with “vanguard blocking undo”",
                chemin_affichable(c)
            ));
            Some((c.to_path_buf(), detection.to_string()))
        }
        None => None,
    };
    if arret.is_none() && quarantaine.is_none() {
        return Err(Echec::refuse(
            "blocage/preparer",
            tr!(
                "plus rien à bloquer : le processus est fini et son fichier n'est plus là",
                "nothing left to block: the process has ended and its file is gone"
            ),
        ));
    }
    if arret.is_some() && quarantaine.is_none() {
        etapes.push(
            tr!(
                "Rien à mettre en quarantaine (fichier effacé, ou interpréteur, qui ne l'est jamais) : un arrêt ne se défait pas",
                "Nothing to quarantine (file deleted, or an interpreter, which never is): a stop cannot be undone"
            )
            .to_string(),
        );
    }
    Ok((
        Pret {
            etapes,
            commandes,
            faire: Faire::Programme { arret, quarantaine },
        },
        droits,
    ))
}

/// Ce que le shell de l'arrêt lit du processus « $1 », à comparer au programme attendu « $2 ».
#[cfg(not(target_os = "macos"))]
const LIRE_PROGRAMME: &str = r#"e=$(readlink "/proc/$1/exe")"#;
#[cfg(target_os = "macos")]
const LIRE_PROGRAMME: &str = r#"e=$(ps -o comm= -p "$1")"#;

/// La commande qui arrête un processus, l'identité vérifiée DANS la commande, au moment même de l'arrêt : entre le
/// contrôle et l'arrêt, la demande de mot de passe ou de la fenêtre administrateur peut durer, et le numéro passer à
/// un autre programme (un service, csrss). Linux et macOS : kill seulement si le programme du numéro est toujours
/// celui attendu (« (deleted) » compris : effacé depuis) ; Windows : Stop-Process seulement si son chemin l'est.
fn commande_d_arret(pid: u32, attendu: &str, sudo: bool) -> String {
    if cfg!(windows) {
        let attendu = crate::commande::ps_texte(attendu);
        trf!(
            "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p -and $p.Path -eq '{attendu}') {{ Stop-Process -Id {pid} -Force }} else {{ throw 'PID {pid} réaffecté à un autre programme : rien n''est arrêté' }}",
            "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p -and $p.Path -eq '{attendu}') {{ Stop-Process -Id {pid} -Force }} else {{ throw 'PID {pid} reassigned to another program: nothing is stopped' }}"
        )
    } else {
        let attendu = crate::commande::sh_chaine(attendu);
        if sudo {
            format!(
                "sudo sh -c '{LIRE_PROGRAMME}; {{ [ \"$e\" = \"$2\" ] || [ \"$e\" = \"$2 (deleted)\" ]; }} && kill -KILL \"$1\"' sh {pid} {attendu}"
            )
        } else {
            format!(
                "sh -c '{LIRE_PROGRAMME}; {{ [ \"$e\" = \"$2\" ] || [ \"$e\" = \"$2 (deleted)\" ]; }} && kill -KILL \"$1\"' sh {pid} {attendu}"
            )
        }
    }
}

/// Ce compte peut-il arrêter ce processus sans droits de plus ? Sous Linux et macOS : un processus de ce compte ;
/// sous Windows : la poignée d'arrêt accordée.
fn arret_sans_droits(pid: u32) -> bool {
    #[cfg(windows)]
    {
        crate::machine::windows::processus::peut_terminer(pid)
    }
    #[cfg(unix)]
    {
        // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire.
        let moi = unsafe { libc::geteuid() };
        moi == 0 || proprietaire(pid) == Some(moi)
    }
}

#[cfg(target_os = "linux")]
fn proprietaire(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    proprietaire_status(&status)
}

/// Le compte réel d'un processus, d'après la ligne « Uid: réel effectif sauvé fs » de /proc/<pid>/status.
#[cfg(any(target_os = "linux", test))]
fn proprietaire_status(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(target_os = "macos")]
fn proprietaire(pid: u32) -> Option<u32> {
    let r = crate::commande::lancer(
        std::process::Command::new("ps").args(["-o", "uid=", "-p", &pid.to_string()]),
        10,
    )?;
    r.sortie.trim().parse().ok()
}

/// Le programme que fait tourner ce processus en ce moment, `None` s'il est fini (ou illisible).
fn chemin_du_processus_tel(pid: Option<u32>) -> Option<String> {
    chemin_du_processus(pid?)
}

pub(crate) fn chemin_du_processus(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let lien = crate::socle::processus::programme(pid)?;
        let lien = lien.to_string_lossy();
        Some(lien.strip_suffix(" (deleted)").unwrap_or(&lien).to_string())
    }
    #[cfg(windows)]
    {
        crate::machine::windows::processus::chemin(pid)
    }
    #[cfg(target_os = "macos")]
    {
        Some(crate::socle::processus::programme(pid)?.to_string_lossy().into_owned())
    }
}

/// Vanguard tourne-t-il en administrateur ?
pub(super) fn administrateur() -> bool {
    #[cfg(windows)]
    {
        crate::machine::windows::processus::eleve()
    }
    #[cfg(unix)]
    {
        // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire.
        unsafe { libc::geteuid() == 0 }
    }
}

/// Comme `administrateur`, pour un garde-fou qui doit échouer fermé : sous Windows, un jeton illisible compte pour
/// élevé ; sous Unix, un programme setuid aussi (compte effectif différent du compte réel : ses fichiers à lui sont
/// ceux du compte réel).
pub(super) fn administrateur_ou_inconnu() -> bool {
    #[cfg(windows)]
    {
        crate::machine::windows::processus::eleve_ou_inconnu()
    }
    #[cfg(unix)]
    {
        // SAFETY : geteuid et getuid ne prennent aucun argument et ne touchent aucune mémoire.
        unsafe { libc::geteuid() == 0 || libc::geteuid() != libc::getuid() }
    }
}

/// Ce compte peut-il sortir ce fichier de son dossier (la quarantaine le déplace) ? Vérifié avant d'arrêter quoi que
/// ce soit : un processus arrêté dont le fichier resterait en place serait un geste à moitié fait.
fn peut_deplacer(chemin: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let Some(parent) = chemin.parent() else {
            return false;
        };
        let acces = |p: &Path, mode: libc::c_int| {
            std::ffi::CString::new(p.as_os_str().as_bytes())
                // SAFETY : `c` est une chaîne terminée par un zéro, vivante pendant l'appel ; access ne fait que la lire.
                .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), mode) } == 0)
        };
        // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire.
        let moi = unsafe { libc::geteuid() };
        let (Ok(dossier), Ok(fichier)) = (std::fs::metadata(parent), std::fs::symlink_metadata(chemin)) else {
            return false;
        };
        // Dossier « collant » (/tmp) : seul le propriétaire du fichier ou du dossier peut l'en sortir.
        let collant = dossier.mode() & 0o1000 != 0;
        acces(parent, libc::W_OK | libc::X_OK)
            && acces(chemin, libc::R_OK)
            && (!collant || moi == 0 || fichier.uid() == moi || dossier.uid() == moi)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // DELETE : le droit de renommer ou d'effacer, demandé sans rien changer, en partageant tout.
        const SUPPRESSION: u32 = 0x0001_0000;
        const LECTURE: u32 = 0x8000_0000;
        std::fs::OpenOptions::new()
            .access_mode(SUPPRESSION | LECTURE)
            .share_mode(7)
            .open(chemin)
            .is_ok()
    }
}

/// Fait le geste préparé, puis le note avec de quoi l'annuler. `Ok` : ce qui a été fait ; `Err` : ce qui a échoué
/// (noté aussi).
pub(crate) fn faire(m: &Menace, pret: Pret, automatique: bool) -> Result<String, Echec> {
    const OU: &str = "blocage/faire";
    // La preuve d'abord, avant tout geste : ce que l'arrêt et la quarantaine vont effacer. Ce qui ne se lit pas y
    // est dit « impossible », et le geste se fait quand même (défensif d'abord).
    let preuve = preuve::relever(
        releve(&m.geste, &pret.faire),
        &m.cle,
        crate::modele::evenement::Source::Blocage,
    );
    let note = |annulation: Option<Annulation>| Blocage {
        id: changements::nouvel_id(),
        cle: m.cle.clone(),
        quoi: m.quoi.clone(),
        automatique,
        annulation,
        annule: None,
        supprime: false,
        preuve: None,
        evenement: None,
    };
    match pret.faire {
        Faire::Commandes { annulation, retenir } => {
            let (reussi, lancees) = crate::machine::appliquer_sans_noter(&pret.commandes);
            let mut fait = m.quoi.clone();
            if reussi && let Some(port) = retenir {
                // Le bilan dira le port fermé seulement si ufw le refuse vraiment avant toute autorisation.
                if pare_feu::ufw_refuse_en_premier(port) == Some(true) {
                    crate::machine::retenir_port(&format!("{port}/tcp"));
                } else {
                    fait += tr!(
                        " (règle posée, mais pas vue avant les autorisations d'ufw : le port n'est pas compté comme fermé)",
                        " (rule added, but not seen before ufw's allow rules: the port is not counted as closed)"
                    );
                }
            }
            changements::noter_blocage(lancees, reussi, note(Some(annulation)), preuve);
            if reussi {
                Ok(fait)
            } else {
                Err(Echec::echoue(
                    OU,
                    tr!(
                        "la commande a échoué (voir le message ci-dessus) : rien n'est bloqué",
                        "the command failed (see the message above): nothing is blocked"
                    ),
                ))
            }
        }
        Faire::Programme { arret, quarantaine } => {
            let mut lancees = Vec::new();
            if let Some(a) = &arret {
                // Relu juste avant : entre la question et la réponse, le processus a pu finir et son numéro être repris.
                if chemin_du_processus(a.pid).is_some_and(|c| meme_chemin(&c, &a.chemin)) {
                    let arrete = arreter(a, &pret.commandes, &mut lancees);
                    if !arrete {
                        changements::noter_blocage(lancees, false, note(None), preuve);
                        return Err(Echec::echoue(
                            OU,
                            tr!(
                                "l'arrêt du processus a échoué : rien d'autre n'a été fait",
                                "stopping the process failed: nothing else was done"
                            ),
                        ));
                    }
                    attendre_la_fin(a);
                }
            }
            let Some((chemin, detection)) = &quarantaine else {
                changements::noter_blocage(lancees, true, note(None), preuve);
                return Ok(m.quoi.clone());
            };
            // Le seul chemin vers la quarantaine : il note le geste, la preuve et de quoi l'annuler.
            let demande = crate::protection::quarantaine::Demande {
                cle: m.cle.clone(),
                quoi: m.quoi.clone(),
                automatique,
                lancees,
                preuve,
            };
            match crate::protection::quarantaine::isoler(chemin, detection, demande) {
                Ok(_) => Ok(m.quoi.clone()),
                Err(e) => Err(Echec::echoue(
                    OU,
                    trf!(
                        "quarantaine impossible ({e}) : le fichier reste en place",
                        "quarantine not possible ({e}): the file stays in place"
                    ),
                )),
            }
        }
        Faire::Demarrage { id } => match crate::optimiser::retirer_du_demarrage(&id) {
            Some(true) => {
                changements::noter_blocage(
                    vec![trf!("retiré du démarrage : {id}", "removed from startup: {id}")],
                    true,
                    note(Some(Annulation::Demarrage { id })),
                    preuve,
                );
                Ok(m.quoi.clone())
            }
            Some(false) => Err(Echec::echoue(
                OU,
                tr!(
                    "le retrait du démarrage a échoué (voir le message ci-dessus)",
                    "removing it from startup failed (see the message above)"
                ),
            )),
            None => Err(Echec::echoue(
                OU,
                tr!(
                    "il ne se lance déjà plus au démarrage",
                    "it no longer starts at login already"
                ),
            )),
        },
        Faire::Permissions { fichier, nouveau } => {
            let copie = crate::socle::dossier_local()
                .join("blocage")
                .join("copies")
                .join(format!(
                    "{}-{}",
                    changements::nouvel_id(),
                    fichier.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
                ));
            let ecrit = copie
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::copy(&fichier, &copie))
                .and_then(|_| std::fs::write(&fichier, &nouveau));
            let lancees = vec![
                format!("copie : {} → {}", fichier.display(), copie.display()),
                format!("defaultMode : bypassPermissions → default ({})", fichier.display()),
            ];
            let annulation = Annulation::Copie {
                fichier: fichier.to_string_lossy().into_owned(),
                copie: copie.to_string_lossy().into_owned(),
                empreinte: empreinte_texte(nouveau.as_bytes()),
            };
            changements::noter_blocage(lancees, ecrit.is_ok(), note(Some(annulation)), preuve);
            ecrit.map(|()| m.quoi.clone()).map_err(|e| Echec::ecriture(OU, &e))
        }
    }
}

/// Le relevé d'avant le geste : le processus et le fichier d'un programme, les connexions vers une adresse, le
/// fichier réglé tel qu'il était. Rien pour ce qui ne fait disparaître aucune trace (un démarrage retiré se remet
/// exactement, une liste de pilotes, un port fermé).
fn releve<'a>(geste: &'a Geste, faire: &'a Faire) -> preuve::Releve<'a> {
    use preuve::Releve;
    match (geste, faire) {
        // Le numéro relu avant le relevé, comme avant l'arrêt : entre la question et la réponse, le processus a pu
        // finir et son numéro être repris ; la preuve décrirait alors un autre programme.
        (Geste::Programme { pid, fichier, .. }, Faire::Programme { arret, .. }) => {
            let vivant = |a: &Arret| chemin_du_processus(a.pid).is_some_and(|c| meme_chemin(&c, &a.chemin));
            match (arret, pid) {
                (Some(a), _) if vivant(a) => Releve::Programme {
                    pid: Some(a.pid),
                    fichier: fichier.as_deref(),
                },
                // Plus là, ou son programme ne se lit plus : rien ne dit que ce numéro est encore le sien.
                (Some(_), _) | (None, Some(_)) => Releve::ProgrammeParti {
                    fichier: fichier.as_deref(),
                },
                (None, None) => Releve::Programme {
                    pid: None,
                    fichier: fichier.as_deref(),
                },
            }
        }
        (Geste::Programme { pid, fichier, .. }, _) => Releve::Programme {
            pid: *pid,
            fichier: fichier.as_deref(),
        },
        (Geste::Adresse { ip }, _) => Releve::Adresse(*ip),
        (_, Faire::Permissions { fichier, .. }) => Releve::Fichier(fichier),
        _ => Releve::Rien,
    }
}

/// Arrête le processus : par Windows lui-même pour un processus de ce compte, sinon par sa commande.
fn arreter(a: &Arret, commandes: &[String], lancees: &mut Vec<String>) -> bool {
    // Sous Windows, la poignée qui arrête est celle qui a lu le chemin : le numéro ne peut pas changer entre les deux.
    #[cfg(windows)]
    if a.ici {
        lancees.push(format!("TerminateProcess {}", a.pid));
        return crate::machine::windows::processus::terminer_si(a.pid, &a.chemin);
    }
    let _ = a;
    let (reussi, notes) = crate::machine::appliquer_sans_noter(commandes);
    lancees.extend(notes);
    reussi
}

/// Attend que le processus arrêté soit bien fini (5 secondes au plus) : son fichier se libère pour la quarantaine.
fn attendre_la_fin(a: &Arret) {
    for _ in 0..50 {
        if !chemin_du_processus(a.pid).is_some_and(|c| meme_chemin(&c, &a.chemin)) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn empreinte_texte(octets: &[u8]) -> String {
    use sha2::Digest;
    let e: [u8; 32] = sha2::Sha256::digest(octets).into();
    crate::protection::empreintes::hex(&e)
}

/// Défait un blocage noté, exactement, puis le marque annulé.
pub(crate) fn defaire(b: &Blocage) -> Result<String, Echec> {
    const OU: &str = "blocage/defaire";
    let Some(annulation) = &b.annulation else {
        return Err(Echec::new(OU, Raison::Introuvable).detail(tr!("rien à défaire", "nothing to undo")));
    };
    let fait = match annulation {
        Annulation::Commandes {
            commandes,
            port,
            inverse,
        } => {
            let (commandes, port) = commandes_d_annulation(commandes, port.as_deref(), *inverse)
                .ok_or_else(|| Echec::refuse(OU, refus_d_annulation(commandes)))?;
            if crate::machine::appliquer(&commandes) {
                if let Some(p) = port {
                    crate::machine::oublier_port(&p);
                }
                Ok(())
            } else {
                Err(Echec::echoue(
                    OU,
                    tr!(
                        "la commande inverse a échoué (voir le message ci-dessus)",
                        "the reverse command failed (see the message above)"
                    ),
                ))
            }
        }
        Annulation::Quarantaine { nom } => {
            let r = crate::protection::quarantaine::remettre(nom);
            changements::noter(&[vec![format!("quarantaine : remettre {nom}")]], &[r.is_ok()]);
            r
        }
        Annulation::Copie {
            fichier,
            copie,
            empreinte,
        } => {
            let r = remettre_copie(Path::new(fichier), Path::new(copie), empreinte);
            changements::noter(&[vec![format!("copie remise : {copie} → {fichier}")]], &[r.is_ok()]);
            r
        }
        Annulation::Demarrage { id } => match crate::optimiser::remettre_au_demarrage(id) {
            Some(true) => Ok(()),
            Some(false) => Err(Echec::echoue(
                OU,
                tr!(
                    "la remise au démarrage a échoué (voir le message ci-dessus)",
                    "putting it back at startup failed (see the message above)"
                ),
            )),
            None => Err(Echec::new(OU, Raison::Introuvable).detail(tr!(
                "plus de note pour ce programme dans les réglages d'Optimiser",
                "no more note for this program in Optimize's settings"
            ))),
        },
    };
    fait.map(|()| {
        changements::marquer_annule(&b.id);
        b.quoi.clone()
    })
}

/// Les commandes qui défont un blocage, refaites ici depuis ses champs typés, et le port retenu à oublier : jamais
/// les chaînes relues du relevé, que n'importe quel programme du compte peut écrire. Une note d'avant les champs
/// typés n'est rejouée que si elle est exactement ce que Vanguard aurait écrit pour une adresse, un port ou une valeur
/// (`inverse_reconnue`) ; sinon, `None` : refusée (`refus_d_annulation` dit ce qu'elle contient, à faire à la main).
pub(crate) fn commandes_d_annulation(
    commandes: &[String],
    port: Option<&str>,
    inverse: Option<Inverse>,
) -> Option<(Vec<String>, Option<String>)> {
    let inverse = match inverse {
        Some(i) => i,
        None => inverse_reconnue(commandes, port)?,
    };
    match inverse {
        Inverse::Sortante { pare_feu, adresse } => Some((pare_feu::sortante(pare_feu, adresse).retirer, None)),
        Inverse::Entrante { pare_feu, port } => {
            let regle = pare_feu::entrante(pare_feu, port)?;
            let retenu = (pare_feu == PareFeu::Ufw).then(|| format!("{port}/tcp"));
            Some((regle.retirer, retenu))
        }
        #[cfg(any(windows, test))]
        Inverse::Pilotes { avant } => Some((annuler_pilotes(avant), None)),
        // Hors de Windows, rien à remettre : la note ne vient pas d'ici.
        #[cfg(not(any(windows, test)))]
        Inverse::Pilotes { .. } => None,
    }
}

/// Le refus d'une annulation qui ne se refait pas (`commandes_d_annulation`), avec ses commandes montrées.
pub(crate) fn refus_d_annulation(commandes: &[String]) -> String {
    trf!(
        "annulation notée sous une forme que Vanguard ne rejoue pas (elle a pu être écrite par un autre programme) : rien n'est lancé. Si ce blocage est bien le vôtre, défaites-le à la main : {}",
        "undo noted in a form Vanguard does not replay (another program may have written it): nothing is run. If this block really is yours, undo it by hand: {}",
        commandes
            .iter()
            .map(|c| super::commande_montree(c))
            .collect::<Vec<_>>()
            .join(" ; ")
    )
}

/// Une note d'avant les champs typés : les commandes sont-elles exactement celles que Vanguard écrivait pour une
/// adresse, un port ou une valeur d'avant ? Les valeurs essayées sont celles qui se lisent dans les commandes ; tout
/// autre texte (une commande ajoutée, changée d'un caractère) ne colle à rien.
pub(crate) fn inverse_reconnue(commandes: &[String], port: Option<&str>) -> Option<Inverse> {
    const TOUS: [PareFeu; 4] = [PareFeu::Ufw, PareFeu::Nftables, PareFeu::Windows, PareFeu::Pf];
    let morceaux: Vec<&str> = commandes
        .iter()
        .flat_map(|c| c.split(|x: char| !(x.is_ascii_hexdigit() || x == '.' || x == ':')))
        .filter(|m| !m.is_empty())
        .collect();
    for ip in morceaux.iter().filter_map(|m| m.parse::<std::net::IpAddr>().ok()) {
        for pf in TOUS {
            if pare_feu::sortante(pf, ip).retirer == commandes && port.is_none() {
                return Some(Inverse::Sortante {
                    pare_feu: pf,
                    adresse: ip.to_canonical(),
                });
            }
        }
    }
    for p in morceaux.iter().filter_map(|m| m.parse::<u16>().ok()) {
        for pf in TOUS {
            let retenu = (pf == PareFeu::Ufw).then(|| format!("{p}/tcp"));
            if pare_feu::entrante(pf, p).is_some_and(|r| r.retirer == commandes)
                && (port.is_none() || port == retenu.as_deref())
            {
                return Some(Inverse::Entrante { pare_feu: pf, port: p });
            }
        }
    }
    #[cfg(any(windows, test))]
    {
        let valeurs = morceaux.iter().filter_map(|m| m.parse::<u32>().ok()).map(Some);
        for avant in std::iter::once(None).chain(valeurs) {
            if annuler_pilotes(avant) == commandes && port.is_none() {
                return Some(Inverse::Pilotes { avant });
            }
        }
    }
    None
}

/// Remet la copie d'avant, seulement si le fichier est encore celui que Vanguard a écrit : sinon une modification
/// faite depuis serait perdue.
pub(crate) fn remettre_copie(fichier: &Path, copie: &Path, empreinte: &str) -> Result<(), Echec> {
    const OU: &str = "blocage/remettre-copie";
    if !copie_admise(fichier, copie) {
        return Err(Echec::refuse(OU, refus_de_copie(fichier, copie)));
    }
    let actuel = std::fs::read(fichier).map_err(|e| Echec::io(OU, &e))?;
    if empreinte_texte(&actuel) != empreinte {
        return Err(Echec::refuse(
            OU,
            trf!(
                "le fichier a changé depuis le blocage : rien n'est écrasé ; la copie d'avant est ici : {}",
                "the file changed since the block: nothing is overwritten; the previous copy is here: {}",
                copie.display()
            ),
        ));
    }
    let avant = std::fs::read(copie).map_err(|e| Echec::io(OU, &e))?;
    std::fs::write(fichier, avant).map_err(|e| Echec::ecriture(OU, &e))
}

/// La note de copie a la forme que `Faire::Permissions` écrit : la copie, un fichier ordinaire (pas un lien), dans
/// blocage/copies du dossier de Vanguard, nommée « <id>-<nom du fichier> » ; le fichier, un settings.json ou
/// settings.local.json ordinaire d'un dossier .claude. changements.jsonl n'est pas scellé : sans cela, un programme du
/// compte y noterait une « copie » à lui de /etc/passwd ou du fichier hosts, que Vanguard lancé en administrateur
/// (même dossier de données) ou par sudo -E remettrait.
pub(crate) fn copie_admise(fichier: &Path, copie: &Path) -> bool {
    let copies = crate::socle::dossier_local().join("blocage").join("copies");
    let ordinaire = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file());
    let nom = fichier
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| matches!(*n, "settings.json" | "settings.local.json"));
    let dans_claude = fichier
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|d| d == ".claude");
    let nom_de_copie = copie.file_name().and_then(|n| n.to_str());
    copie.parent() == Some(copies.as_path())
        && ordinaire(copie)
        && ordinaire(fichier)
        && dans_claude
        && nom
            .zip(nom_de_copie)
            .is_some_and(|(n, c)| c.ends_with(&format!("-{n}")))
}

/// Le refus d'une note de copie hors de ce que Vanguard écrit, avec le geste à faire à la main si elle est bien à soi.
pub(crate) fn refus_de_copie(fichier: &Path, copie: &Path) -> String {
    trf!(
        "copie notée hors de ce que Vanguard écrit (un autre programme a pu l'écrire) : rien n'est remis ; à faire à la main : {} → {}",
        "copy noted outside what Vanguard writes (another program may have written it): nothing is put back; to do by hand: {} → {}",
        affichable(&copie.to_string_lossy()),
        affichable(&fichier.to_string_lossy())
    )
}

/// La clé que le basculeur « Liste de blocage des pilotes vulnérables » de Sécurité Windows écrit.
#[cfg(any(windows, test))]
const CLE_PILOTES: &str = r"SYSTEM\CurrentControlSet\Control\CI\Config";

/// Ce qui remet la liste de blocage des pilotes comme avant : sa valeur d'avant, ou rien si elle manquait.
#[cfg(any(windows, test))]
pub(crate) fn annuler_pilotes(avant: Option<u32>) -> Vec<String> {
    let cle = format!("HKLM:\\{CLE_PILOTES}");
    vec![match avant {
        Some(v) => format!(
            "Set-ItemProperty -LiteralPath '{cle}' -Name VulnerableDriverBlocklistEnable -Value {v} -Type DWord"
        ),
        None => format!(
            "Remove-ItemProperty -LiteralPath '{cle}' -Name VulnerableDriverBlocklistEnable -ErrorAction SilentlyContinue"
        ),
    }]
}

/// Les chaînes JSON d'un texte (JSONC compris) : (début, fin) de chacune, guillemets compris ; commentaires sautés.
fn chaines(texte: &str) -> Vec<(usize, usize)> {
    let o = texte.as_bytes();
    let mut trouvees = Vec::new();
    let mut i = 0;
    while i < o.len() {
        match o[i] {
            b'"' => {
                let debut = i;
                i += 1;
                while i < o.len() && o[i] != b'"' {
                    i += if o[i] == b'\\' { 2 } else { 1 };
                }
                trouvees.push((debut, (i + 1).min(o.len())));
            }
            b'/' if o.get(i + 1) == Some(&b'/') => {
                while i < o.len() && o[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if o.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < o.len() && !(o[i] == b'*' && o[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    trouvees
}

/// Change chaque « "defaultMode": "bypassPermissions" » en « "defaultMode": "default" », sans toucher au reste du
/// texte (ordre, espaces, commentaires). `None` si rien ne change, ou si le résultat ne se relit pas comme le même
/// JSON à ce seul champ près, ou permet encore tout : rien n'est alors écrit.
pub(crate) fn sans_contournement(texte: &str) -> Option<String> {
    let lire = |t: &str| serde_json::from_str::<String>(t).ok();
    let cs = chaines(texte);
    let mut remplacer = Vec::new();
    for paire in cs.windows(2) {
        let ((cd, cf), (vd, vf)) = (paire[0], paire[1]);
        if lire(texte.get(cd..cf)?).as_deref() == Some("defaultMode")
            && texte.get(cf..vd)?.trim() == ":"
            && lire(texte.get(vd..vf)?).as_deref() == Some("bypassPermissions")
        {
            remplacer.push((vd, vf));
        }
    }
    if remplacer.is_empty() {
        return None;
    }
    let mut nouveau = texte.to_string();
    for (d, f) in remplacer.into_iter().rev() {
        nouveau.replace_range(d..f, "\"default\"");
    }
    let mut attendu = crate::socle::jsonc::lire_json(texte.as_bytes())?;
    remettre_par_defaut(&mut attendu);
    let relu = crate::socle::jsonc::lire_json(nouveau.as_bytes())?;
    (relu == attendu && !crate::machine::agents_ia::tout_permis(&relu)).then_some(nouveau)
}

fn remettre_par_defaut(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(o) => {
            for (cle, valeur) in o.iter_mut() {
                if cle == "defaultMode" && valeur.as_str() == Some("bypassPermissions") {
                    *valeur = serde_json::Value::String("default".into());
                } else {
                    remettre_par_defaut(valeur);
                }
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(remettre_par_defaut),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_permissions_reecrit_sans_rien_d_autre() {
        let avant = r#"{
  // réglages d'alice
  "permissions": {
    "allow": ["Bash(git status)"],
    "defaultMode"  :  "bypassPermissions"
  },
  "model": "exemple",
  "projects": { "/home/alice/projet": { "defaultMode": "bypassPermissions" } },
  "note": "defaultMode: bypassPermissions"
}"#;
        let apres = sans_contournement(avant).unwrap();
        assert_eq!(
            apres,
            avant.replacen("\"bypassPermissions\"\n", "\"default\"\n", 1).replacen(
                "\"defaultMode\": \"bypassPermissions\" }",
                "\"defaultMode\": \"default\" }",
                1
            )
        );
        // Le texte libre et les commentaires restent tels quels.
        assert!(
            apres.contains("\"note\": \"defaultMode: bypassPermissions\"") && apres.contains("// réglages d'alice")
        );
        // Rien à changer : rien n'est écrit.
        assert_eq!(
            sans_contournement("{\"permissions\": {\"defaultMode\": \"acceptEdits\"}}"),
            None
        );
        // Un mode écrit avec une séquence d'échappement se reconnaît aussi.
        assert!(sans_contournement("{\"permissions\": {\"defaultMode\": \"bypass\\u0050ermissions\"}}").is_some());
        // Illisible comme JSON : jamais réécrit.
        assert_eq!(sans_contournement("{\"defaultMode\": \"bypassPermissions\""), None);
    }

    /// La copie d'avant se remet seulement sur le fichier que Vanguard a écrit, jamais sur une modification faite depuis.
    #[test]
    fn copie_remise_seulement_sur_le_fichier_ecrit() {
        let d = std::env::temp_dir().join(format!("vanguard-blocage-copie-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".claude")).unwrap();
        let copies = crate::socle::dossier_local().join("blocage").join("copies");
        std::fs::create_dir_all(&copies).unwrap();
        let (fichier, copie) = (
            d.join(".claude").join("settings.json"),
            copies.join("c0ffee-settings.json"),
        );
        std::fs::write(&copie, "{\"permissions\": {\"defaultMode\": \"bypassPermissions\"}}").unwrap();
        let ecrit = "{\"permissions\": {\"defaultMode\": \"default\"}}";
        std::fs::write(&fichier, ecrit).unwrap();
        let empreinte = empreinte_texte(ecrit.as_bytes());
        // Changé depuis : refusé, rien n'est écrasé.
        std::fs::write(&fichier, "{\"permissions\": {}}").unwrap();
        assert!(remettre_copie(&fichier, &copie, &empreinte).is_err());
        assert_eq!(std::fs::read_to_string(&fichier).unwrap(), "{\"permissions\": {}}");
        // Tel que Vanguard l'a écrit : la copie revient.
        std::fs::write(&fichier, ecrit).unwrap();
        remettre_copie(&fichier, &copie, &empreinte).unwrap();
        assert!(std::fs::read_to_string(&fichier).unwrap().contains("bypassPermissions"));
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_file(&copie);
    }

    /// Une note de copie forgée dans changements.jsonl (non scellé) : une cible hors d'un settings.json de .claude
    /// (/etc/hosts, ici une copie jetable) ou une copie hors de blocage/copies n'est jamais remise, et la cible reste
    /// telle quelle, même avec la bonne empreinte.
    #[test]
    fn copie_forgee_jamais_remise() {
        let d = std::env::temp_dir().join(format!("vanguard-blocage-copie-forgee-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::create_dir_all(d.join(".claude")).unwrap();
        let copies = crate::socle::dossier_local().join("blocage").join("copies");
        std::fs::create_dir_all(&copies).unwrap();
        let hosts = d.join("etc").join("hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\n").unwrap();
        let piege = copies.join("c0ffee-hosts");
        std::fs::write(&piege, "203.0.113.7 banque.example\n").unwrap();
        let empreinte = empreinte_texte(&std::fs::read(&hosts).unwrap());
        // Cible qui n'est pas un settings.json de .claude.
        assert!(!copie_admise(&hosts, &piege));
        let e = remettre_copie(&hosts, &piege, &empreinte).unwrap_err();
        assert_eq!(e.code(), "refuse");
        let e = e.to_string();
        assert!(e.contains("main") || e.contains("hand"), "{e}");
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "127.0.0.1 localhost\n");
        // Bonne cible, copie hors de blocage/copies.
        let settings = d.join(".claude").join("settings.json");
        std::fs::write(&settings, "{}").unwrap();
        let ailleurs = d.join("c0ffee-settings.json");
        std::fs::write(&ailleurs, "{\"permissions\": {\"defaultMode\": \"bypassPermissions\"}}").unwrap();
        let empreinte = empreinte_texte(b"{}");
        assert!(remettre_copie(&settings, &ailleurs, &empreinte).is_err());
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{}");
        // Copie en lien vers un fichier choisi : refusée aussi.
        #[cfg(unix)]
        {
            // Un nom à ce test : copie_remise_seulement_sur_le_fichier_ecrit, en parallèle, écrit c0ffee-settings.json.
            let lien = copies.join("f0f0f0-settings.json");
            let _ = std::fs::remove_file(&lien);
            std::os::unix::fs::symlink(&ailleurs, &lien).unwrap();
            assert!(!copie_admise(&settings, &lien));
            let _ = std::fs::remove_file(&lien);
        }
        let _ = std::fs::remove_file(&piege);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn pilotes_remis_comme_avant() {
        assert_eq!(
            annuler_pilotes(Some(0)),
            [
                "Set-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -Name VulnerableDriverBlocklistEnable -Value 0 -Type DWord"
            ]
        );
        assert!(
            annuler_pilotes(None)[0].starts_with(
                "Remove-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config'"
            )
        );
        #[cfg(windows)]
        assert_eq!(CLE_PILOTES, crate::machine::windows::corrections::PILOTES_VULNERABLES);
    }

    #[test]
    fn arret_d_un_processus() {
        assert_eq!(
            proprietaire_status("Name:\tx\nUid:\t1000\t1000\t1000\t1000\n"),
            Some(1000)
        );
        assert_eq!(proprietaire_status("Name:\tx\n"), None);
        if cfg!(windows) {
            let c = commande_d_arret(4242, r"C:\Users\alice\AppData\Local\Temp\l'outil.exe", true);
            assert!(c.starts_with("$p = Get-Process -Id 4242 -ErrorAction SilentlyContinue; if ($p -and $p.Path -eq 'C:\\Users\\alice\\AppData\\Local\\Temp\\l''outil.exe') { Stop-Process -Id 4242 -Force } else { throw"), "{c}");
        } else {
            let c = commande_d_arret(4242, "/home/alice/.cache/x m'rig", true);
            assert!(c.starts_with("sudo sh -c '"), "{c}");
            assert!(
                c.ends_with(" && kill -KILL \"$1\"' sh 4242 '/home/alice/.cache/x m'\\''rig'"),
                "{c}"
            );
            assert!(!commande_d_arret(4242, "/x", false).starts_with("sudo"));
        }
    }

    /// Défaut de la relecture : le numéro peut passer à un autre programme pendant la demande de mot de passe. La
    /// commande d'arrêt vérifie elle-même le programme du numéro au moment de l'arrêt : avec un autre programme
    /// attendu, rien n'est arrêté (essayé sur ce processus de test, qui survit).
    #[cfg(target_os = "linux")]
    #[test]
    fn arret_refuse_si_le_numero_a_change() {
        let c = commande_d_arret(std::process::id(), "/autre/programme", false);
        let r = std::process::Command::new("bash").arg("-c").arg(&c).status().unwrap();
        assert!(!r.success(), "{c}");
    }

    fn contexte(interactif: bool, admin: bool) -> Contexte {
        Contexte {
            os: Os::Linux,
            intouchables: HashSet::new(),
            sessions: Some(gardes::Sessions {
                sessions: vec!["198.51.100.20".parse().unwrap()],
                autres_comptes: vec!["203.0.113.9".parse().unwrap()],
            }),
            pare_feu: Ok(PareFeu::Ufw),
            admin,
            interactif,
            mon_programme: Some("/home/alice/vanguard".into()),
        }
    }

    fn menace(geste: Geste) -> Menace {
        Menace {
            categorie: super::super::parametres::Categorie::Connexions,
            certaine: true,
            quoi: "x".into(),
            cle: "x".into(),
            geste,
        }
    }

    /// Garde-fous à la préparation : session à distance, droits manquants sans personne pour répondre, pare-feu
    /// absent ; rien ne se prépare, la raison est dite.
    /// Un programme du compte forge dans le relevé un blocage « en place » dont l'annulation est une commande sudo à
    /// lui : elle n'est jamais lancée. L'annulation se refait depuis les champs typés, ou depuis une note d'avant
    /// qui est exactement ce que Vanguard écrivait ; tout le reste est refusé.
    #[test]
    fn annulation_relue_jamais_rejouee_telle_quelle() {
        let forgee = vec!["sudo sh -c 'id > /tmp/vanguard-preuve-root'".to_string()];
        assert_eq!(commandes_d_annulation(&forgee, None, None), None);
        let e = refus_d_annulation(&forgee);
        assert!(e.contains("à la main") || e.contains("by hand"), "{e}");
        // Une vraie commande d'avant, suivie d'une commande ajoutée : refusée aussi.
        let mut ajoutee = pare_feu::sortante(PareFeu::Ufw, "203.0.113.7".parse().unwrap()).retirer;
        ajoutee.push("sudo sh -c 'id'".into());
        assert_eq!(commandes_d_annulation(&ajoutee, None, None), None);
        // Les champs typés l'emportent sur les commandes relues, quelles qu'elles soient.
        let typee = Inverse::Sortante {
            pare_feu: PareFeu::Ufw,
            adresse: "203.0.113.7".parse().unwrap(),
        };
        let (c, port) = commandes_d_annulation(&forgee, Some("22/tcp"), Some(typee)).unwrap();
        assert_eq!(
            (c, port),
            (vec!["sudo ufw delete deny out to '203.0.113.7'".to_string()], None)
        );
        let (c, port) = commandes_d_annulation(
            &[],
            None,
            Some(Inverse::Entrante {
                pare_feu: PareFeu::Ufw,
                port: 11434,
            }),
        )
        .unwrap();
        assert_eq!(
            (c, port.as_deref()),
            (vec!["sudo ufw delete deny '11434/tcp'".to_string()], Some("11434/tcp"))
        );
        // Les notes d'avant, telles que Vanguard les écrivait, se reconnaissent sur chaque pare-feu.
        for pf in [PareFeu::Ufw, PareFeu::Nftables, PareFeu::Windows, PareFeu::Pf] {
            for ip in ["203.0.113.7", "2001:db8::7"] {
                let ip: std::net::IpAddr = ip.parse().unwrap();
                let ancienne = pare_feu::sortante(pf, ip).retirer;
                assert_eq!(
                    inverse_reconnue(&ancienne, None),
                    Some(Inverse::Sortante {
                        pare_feu: pf,
                        adresse: ip
                    }),
                    "{pf:?} {ip}"
                );
            }
            if let Some(r) = pare_feu::entrante(pf, 11434) {
                let port = (pf == PareFeu::Ufw).then_some("11434/tcp");
                assert_eq!(
                    inverse_reconnue(&r.retirer, port),
                    Some(Inverse::Entrante {
                        pare_feu: pf,
                        port: 11434
                    })
                );
            }
        }
        for avant in [None, Some(0), Some(1)] {
            assert_eq!(
                inverse_reconnue(&annuler_pilotes(avant), None),
                Some(Inverse::Pilotes { avant })
            );
        }
        // Les champs typés se relisent tels quels du relevé.
        let a = Annulation::Commandes {
            commandes: Vec::new(),
            port: None,
            inverse: Some(typee),
        };
        let texte = serde_json::to_string(&a).unwrap();
        assert!(
            texte.contains(r#""inverse":{"genre":"sortante","pare_feu":"ufw","adresse":"203.0.113.7"}"#),
            "{texte}"
        );
        assert_eq!(serde_json::from_str::<Annulation>(&texte).unwrap(), a);
    }

    #[test]
    fn gestes_refuses_avant_d_y_toucher() {
        let adresse = |ip: &str| {
            menace(Geste::Adresse {
                ip: ip.parse().unwrap(),
            })
        };
        // Une session SSH en cours avec cette adresse : jamais coupée.
        assert!(preparer(&adresse("198.51.100.20"), &contexte(true, false), false).is_err());
        // Interactif : la règle se prépare, avec son inverse exact.
        let p = preparer(&adresse("203.0.113.7"), &contexte(true, false), false).unwrap();
        assert_eq!(p.commandes[0], "sudo ufw prepend deny out to '203.0.113.7'");
        assert!(matches!(
            &p.faire,
            Faire::Commandes { annulation: Annulation::Commandes { commandes, port: None, inverse: Some(_) }, .. }
                if commandes == &["sudo ufw delete deny out to '203.0.113.7'".to_string()]
        ));
        // Surveillance (personne pour répondre) sans droits : rien.
        let refus = preparer(&adresse("203.0.113.7"), &contexte(false, false), false).err();
        let refus = refus.map(|r| r.to_string());
        assert!(refus.is_some_and(|r| r.contains("droits") || r.contains("rights")));
        // Un autre compte a une connexion avec cette adresse : d'un clic oui, jamais tout seul.
        assert!(preparer(&adresse("203.0.113.9"), &contexte(true, true), false).is_ok());
        assert!(preparer(&adresse("203.0.113.9"), &contexte(true, true), true).is_err());
        // En administrateur, la surveillance peut le faire.
        assert!(preparer(&adresse("203.0.113.7"), &contexte(false, true), false).is_ok());
        // Pas de pare-feu : non disponible.
        let mut sans = contexte(true, true);
        sans.pare_feu = Err(Echec::new("essai", Raison::Absente("nftables".into())));
        assert!(preparer(&adresse("203.0.113.7"), &sans, false).is_err());
        // Jamais fermer SSH en entrée.
        let ssh = menace(Geste::ServeurIa {
            port: 22,
            nom: "x".into(),
        });
        assert!(preparer(&ssh, &contexte(true, true), false).is_err());
        let ollama = preparer(
            &menace(Geste::ServeurIa {
                port: 11434,
                nom: "Ollama".into(),
            }),
            &contexte(true, false),
            false,
        )
        .unwrap();
        assert_eq!(ollama.commandes, ["sudo ufw prepend deny '11434/tcp'"]);
        // Un programme dont le processus est fini et le fichier parti : rien à bloquer.
        let parti = menace(Geste::Programme {
            pid: None,
            nom: "x".into(),
            chemin: Some(PathBuf::from("/home/alice/inexistant-vanguard-test")),
            fichier: Some(PathBuf::from("/home/alice/inexistant-vanguard-test")),
            detection: "x".into(),
        });
        assert!(preparer(&parti, &contexte(true, true), false).is_err());
        // Vanguard lui-même n'est jamais mis en quarantaine.
        let moi = std::env::current_exe().unwrap();
        let mut ctx = contexte(true, true);
        ctx.os = Os::actuel();
        ctx.mon_programme = Some(moi.to_string_lossy().into_owned());
        let vanguard = menace(Geste::Programme {
            pid: None,
            nom: "vanguard".into(),
            chemin: Some(moi.clone()),
            fichier: Some(moi),
            detection: "x".into(),
        });
        assert!(preparer(&vanguard, &ctx, false).is_err());
        // Un interpréteur désigné comme fichier à isoler ne l'est jamais : sans processus en marche, rien à faire.
        let dossier = std::env::temp_dir().join(format!("vanguard-blocage-python-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let python = dossier.join("python3.12");
        std::fs::write(&python, b"x").unwrap();
        let interpreteur = menace(Geste::Programme {
            pid: None,
            nom: "python3".into(),
            chemin: Some(python.clone()),
            fichier: Some(python.clone()),
            detection: "x".into(),
        });
        let mut ctx = contexte(true, true);
        ctx.os = Os::actuel();
        assert!(preparer(&interpreteur, &ctx, false).is_err());
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Le blocage d'un fichier : la preuve (empreinte relevée avant le geste) est notée avec le blocage, par le seul
    /// chemin de la quarantaine, et l'annulation le remet à sa place.
    #[test]
    fn preuve_relevee_avant_la_quarantaine() {
        let d = std::env::temp_dir().join(format!("vanguard-gestes-preuve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let fichier = d.join("facture.pdf.exe");
        std::fs::write(&fichier, b"MZ essai").unwrap();
        let cle = format!("fichier:{}", fichier.display());
        let m = Menace {
            cle: cle.clone(),
            categorie: super::super::parametres::Categorie::Programmes,
            ..menace(Geste::Programme {
                pid: None,
                nom: "facture.pdf.exe".into(),
                chemin: Some(fichier.clone()),
                fichier: Some(fichier.clone()),
                detection: "essai".into(),
            })
        };
        let pret = preparer(&m, &contexte(true, true), true).unwrap();
        faire(&m, pret, true).unwrap();
        assert!(!fichier.exists());
        let (_, reussi, b) = changements::blocages()
            .into_iter()
            .rev()
            .find(|(_, _, b)| b.cle == cle)
            .unwrap();
        assert!(reussi && b.automatique);
        let f = b.preuve.as_ref().and_then(|p| p.fichier.as_ref()).unwrap();
        assert_eq!(f.sha256.as_deref(), Some(empreinte_texte(b"MZ essai").as_str()));
        assert!(matches!(b.annulation, Some(Annulation::Quarantaine { .. })));
        defaire(&b).unwrap();
        assert_eq!(std::fs::read(&fichier).unwrap(), b"MZ essai");
        let _ = std::fs::remove_dir_all(&d);
    }
    /// Le numéro du processus repris par un autre programme entre la question et le geste : la preuve ne décrit pas
    /// ce programme-là, elle le dit ; toujours le même, elle le relève.
    #[test]
    fn preuve_d_un_numero_repris() {
        fn relever(r: preuve::Releve<'_>) -> preuve::Preuve {
            preuve::relever(r, "programme:/tmp/.x/outil", crate::modele::evenement::Source::Blocage)
                .en_preuve()
                .unwrap()
        }
        let moi = std::process::id();
        let geste = Geste::Programme {
            pid: Some(moi),
            nom: "outil".into(),
            chemin: Some("/tmp/.x/outil".into()),
            fichier: None,
            detection: "outil offensif".into(),
        };
        let faire = |chemin: String| Faire::Programme {
            arret: Some(Arret {
                pid: moi,
                chemin,
                ici: false,
            }),
            quarantaine: None,
        };
        let repris = relever(releve(&geste, &faire("/tmp/.x/outil".into())));
        assert!(repris.processus.is_none());
        assert!(repris.impossible.iter().any(|l| l.contains("repris")), "{repris:?}");
        if let Some(actuel) = chemin_du_processus(moi) {
            let meme = relever(releve(&geste, &faire(actuel)));
            assert_eq!(meme.processus.map(|p| p.pid), Some(moi));
        }
    }
}
