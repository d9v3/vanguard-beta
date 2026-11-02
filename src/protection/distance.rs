//! Mon ordinateur est-il contrôlé ? Les logiciels de prise de contrôle à distance (AnyDesk, TeamViewer, RustDesk,
//! Assistance rapide…) installés, lancés au démarrage, en cours d'exécution, ou simplement posés dans Téléchargements.
//! C'est l'outil de l'arnaque au faux technicien : un appel (« votre ordinateur est infecté »), une fenêtre qui fait
//! peur, puis on fait installer le programme ; l'arnaqueur voit l'écran, bouge la souris, vole des mots de passe ou
//! fait payer une réparation inventée. Au bilan (catégorie « Accès à distance ») et en parcours guidé.
//!
//! Vanguard ne coupe jamais une connexion à distance en cours : un programme en cours d'exécution n'est jamais retiré
//! par le bilan, et le parcours redemande un accord exprès, en rappelant que la personne qui aide peut être connectée
//! par ce programme même. Un programme que la personne utilise elle-même se déclare normal (« i » à la correction).

#[cfg(unix)]
use std::path::PathBuf;

use chrono::NaiveDate;

#[cfg(unix)]
use crate::commande::sh_chaine;
#[cfg(target_os = "linux")]
use crate::machine::gestes_unix::ActionUnite;
use crate::machine::{Constat, alerte, impossible, ok};
#[cfg(target_os = "linux")]
use crate::modele::Echec;
use crate::risk::Niveau;
use crate::ui::*;

mod resultat;

const CAT: &str = "Accès à distance";
/// Installé ou téléchargé depuis moins longtemps que ça : le scénario du faux technicien, qui agit tout de suite.
const RECENT_JOURS: i64 = 30;

/// Un logiciel de prise de contrôle à distance.
struct Logiciel {
    /// Nom affiché, en français puis en anglais.
    nom: [&'static str; 2],
    /// Mots, en minuscules, reconnus au début d'un mot dans un nom de programme, de paquet, de service, de fichier ou
    /// de processus (« anydesk » dans « AnyDesk.exe », « com.anydesk.Anydesk », « anydesk.service »).
    motifs: &'static [&'static str],
    /// Fourni avec le système : sa présence est normale, seule son exécution compte.
    integre: bool,
}

impl Logiciel {
    fn nom(&self) -> &'static str {
        if crate::langue::anglais() {
            self.nom[1]
        } else {
            self.nom[0]
        }
    }
}

/// Ceux que les faux techniciens font installer, et les outils d'administration à distance qu'ils détournent.
#[rustfmt::skip] // une ligne par logiciel
const LOGICIELS: &[Logiciel] = &[
    Logiciel { nom: ["AnyDesk", "AnyDesk"], motifs: &["anydesk"], integre: false },
    Logiciel { nom: ["TeamViewer", "TeamViewer"], motifs: &["teamviewer"], integre: false },
    Logiciel { nom: ["RustDesk", "RustDesk"], motifs: &["rustdesk"], integre: false },
    Logiciel { nom: ["Assistance rapide", "Quick Assist"], motifs: &["quickassist", "quick assist", "quick-assist"], integre: true },
    Logiciel { nom: ["Chrome Remote Desktop", "Chrome Remote Desktop"],
        motifs: &["chrome remote desktop", "chrome-remote-desktop", "chromeremotedesktop", "remoting_host", "chromoting"], integre: false },
    Logiciel { nom: ["ScreenConnect (ConnectWise)", "ScreenConnect (ConnectWise)"],
        motifs: &["screenconnect", "connectwise control", "connectwisecontrol"], integre: false },
    Logiciel { nom: ["Splashtop", "Splashtop"], motifs: &["splashtop"], integre: false },
    Logiciel { nom: ["UltraViewer", "UltraViewer"], motifs: &["ultraviewer"], integre: false },
    Logiciel { nom: ["Supremo", "Supremo"], motifs: &["supremo"], integre: false },
    Logiciel { nom: ["LogMeIn / GoTo", "LogMeIn / GoTo"], motifs: &["logmein", "gotoassist", "goto resolve", "gotoresolve", "gotoopener"], integre: false },
    Logiciel { nom: ["Zoho Assist", "Zoho Assist"], motifs: &["zoho assist", "zohoassist"], integre: false },
    Logiciel { nom: ["AnyViewer", "AnyViewer"], motifs: &["anyviewer"], integre: false },
    Logiciel { nom: ["Ammyy Admin", "Ammyy Admin"], motifs: &["ammyy"], integre: false },
    Logiciel { nom: ["DWService", "DWService"], motifs: &["dwagent", "dwservice"], integre: false },
    Logiciel { nom: ["Remote Utilities", "Remote Utilities"], motifs: &["remote utilities", "rutserv", "rfusclient"], integre: false },
    Logiciel { nom: ["NoMachine", "NoMachine"], motifs: &["nomachine", "nxserver"], integre: false },
    Logiciel { nom: ["Serveur VNC", "VNC server"],
        motifs: &["tightvnc", "ultravnc", "realvnc", "vncserver", "x11vnc", "tigervnc-server", "winvnc"], integre: false },
    Logiciel { nom: ["Atera", "Atera"], motifs: &["atera"], integre: false },
    Logiciel { nom: ["NinjaOne", "NinjaOne"], motifs: &["ninjarmm", "ninjaone"], integre: false },
    Logiciel { nom: ["Action1", "Action1"], motifs: &["action1"], integre: false },
    Logiciel { nom: ["MeshCentral", "MeshCentral"], motifs: &["meshagent", "meshcentral"], integre: false },
    Logiciel { nom: ["xrdp", "xrdp"], motifs: &["xrdp"], integre: false },
];

/// Comment un logiciel a été trouvé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trace {
    /// Installé : Programmes et fonctionnalités, gestionnaire de paquets, /Applications.
    Installe,
    /// En cours d'exécution ; `connecte` : avec une connexion réseau ouverte en ce moment.
    EnCours { connecte: bool },
    /// Lancé au démarrage : service, clé Run, autostart, LaunchAgent.
    Demarrage,
    /// Programme ou installateur posé dans Téléchargements, sur le Bureau ou dans un dossier temporaire.
    Fichier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Trouvaille {
    /// Indice dans `LOGICIELS`.
    logiciel: usize,
    trace: Trace,
    /// Où : « Programmes et fonctionnalités : AnyDesk », « paquet anydesk », « service AnyDesk », un chemin…
    ou: String,
    /// Date d'installation ou du fichier, quand elle est connue.
    depuis: Option<NaiveDate>,
    /// Commandes qui le retirent, sans l'arrêter (vides : à faire soi-même).
    retrait: Vec<String>,
    /// Commandes qui l'arrêtent, passées avant le retrait quand la personne l'a accepté une seconde fois.
    arret: Vec<String>,
    /// Son retrait est refusé (`retrait_garde`, la raison dans `ou`) : pas de conseil de le désinstaller autrement,
    /// les réglages du système passeraient par les mêmes scripts.
    refuse: bool,
}

/// Le logiciel dont un mot est reconnu au début d'un mot de `texte` (nom de programme, de paquet, de fichier…).
fn reconnu(texte: &str) -> Option<usize> {
    let bas = texte.to_lowercase();
    LOGICIELS
        .iter()
        .position(|l| l.motifs.iter().any(|m| contient_mot(&bas, m)))
}

/// Un nom (programme, paquet, service, application) d'un logiciel de prise de contrôle à distance : « Logiciels
/// espions » le renvoie ici au lieu de le compter.
pub(crate) fn controle_a_distance(nom: &str) -> bool {
    reconnu(nom).is_some()
}

/// Deux noms (un service, le service PAM d'une session) du même logiciel de prise de contrôle à distance : le fils
/// root s'en sert pour reconnaître une session ouverte par l'outil qu'on lui demande d'arrêter.
// Seul l'arrêt d'une unité désignée (Unix) s'en sert.
#[cfg(unix)]
pub(crate) fn meme_logiciel(a: &str, b: &str) -> bool {
    reconnu(a).is_some_and(|i| reconnu(b) == Some(i))
}

/// `motif` dans `texte`, précédé d'autre chose qu'une lettre ou un chiffre : « atera » dans « AteraAgent », pas dans
/// « lateral » ; « anydesk » dans « com.anydesk.Anydesk » comme dans « AnyDesk.exe ».
pub(crate) fn contient_mot(texte: &str, motif: &str) -> bool {
    let mut debut = 0;
    while let Some(pos) = texte[debut..].find(motif) {
        let i = debut + pos;
        if !texte[..i].chars().next_back().is_some_and(char::is_alphanumeric) {
            return true;
        }
        debut = i + motif.len();
    }
    false
}

fn aujourd_hui() -> NaiveDate {
    chrono::Local::now().date_naive()
}

/// La date d'un fichier (modification ou création), si le système la donne.
#[cfg(unix)]
fn date_de(temps: std::io::Result<std::time::SystemTime>) -> Option<NaiveDate> {
    temps
        .ok()
        .map(|t| chrono::DateTime::<chrono::Local>::from(t).date_naive())
}

/// Les mêmes commandes sans répétition, dans l'ordre.
fn sans_repetition(commandes: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut liste: Vec<String> = Vec::new();
    for c in commandes {
        if !liste.contains(&c) {
            liste.push(c);
        }
    }
    liste
}

/// Les lignes du retrait d'un logiciel, dans l'ordre où elles partent ; `avec_l_arret` : la personne a accepté de
/// l'arrêter (second accord). Sous Linux, l'arrêt d'un service désigné demande à l'administrateur s'il est connecté
/// par lui, et un « oui » (ou rien) le fait échouer : l'assistant ne fait plus rien de la liste après un échec. Ses
/// gestes de retrait du démarrage passent donc en premier, pour être faits quand même ; puis l'arrêt accepté, puis
/// les arrêts qui gardent la désinstallation (`retrait_garde`), le plus souvent les mêmes, gardés une fois. Les
/// commandes, elles, gardent leur ordre (arrêt du processus avant la désinstallation), et ne partent que si tous les
/// gestes ont réussi : un arrêt refusé garde le paquet, qui l'arrêterait sans rien demander. Sans l'arrêt accepté,
/// l'arrêt des services lancés au démarrage garde quand même les commandes : arrêtés au relevé, ils ont pu repartir
/// depuis, et le paquet les arrêterait sans la question ; s'ils ne tournent toujours pas, ce geste ne fait rien.
fn lignes_du_retrait(siens: &[&Trouvaille], avec_l_arret: bool) -> Vec<String> {
    #[cfg(target_os = "linux")]
    let (est_geste, est_arret) = (
        |l: &String| l.starts_with(crate::protection::blocage::ordres::PREFIXE),
        |l: &String| {
            use crate::machine::gestes_unix::{GesteUnix, analyser};
            matches!(analyser(l), Some(GesteUnix::Designee(ActionUnite::Arreter, _)))
        },
    );
    #[cfg(not(target_os = "linux"))]
    let (est_geste, est_arret) = (|_: &String| false, |_: &String| false);
    let (gestes, commandes): (Vec<String>, Vec<String>) = siens
        .iter()
        .flat_map(|t| t.retrait.iter().cloned())
        .partition(est_geste);
    let (gardes, gestes): (Vec<String>, Vec<String>) = gestes.into_iter().partition(est_arret);
    let arret = siens
        .iter()
        .filter(|_| avec_l_arret)
        .flat_map(|t| t.arret.iter().cloned());
    let au_demarrage = siens
        .iter()
        .filter(|t| !avec_l_arret && !commandes.is_empty() && t.trace == Trace::Demarrage)
        .flat_map(|t| t.arret.iter().filter(|l| est_arret(l)).cloned())
        .collect::<Vec<_>>();
    sans_repetition(
        gestes
            .into_iter()
            .chain(arret)
            .chain(au_demarrage)
            .chain(gardes)
            .chain(commandes),
    )
}

/// Où et pourquoi le retrait d'un logiciel est refusé (`retrait_garde`, la raison dans `ou`), joints ; `None` s'il ne
/// l'est pas.
fn raisons_du_refus(siens: &[&Trouvaille]) -> Option<String> {
    let raisons: Vec<&str> = siens.iter().filter(|t| t.refuse).map(|t| t.ou.as_str()).collect();
    (!raisons.is_empty()).then(|| raisons.join(tr!(" ; ", "; ")))
}

/// Retire chaque programme (une liste de commandes chacun) et dit, pour chacun, s'il est retiré. Ailleurs que sous
/// Windows, les gestes d'un programme (arrêt et retrait d'un service système, lot U3) passent avant ses commandes,
/// qui ne suivent que s'ils ont réussi : ne pas désinstaller un programme dont le service tourne encore. `Err(Some)` :
/// une partie seulement est faite ; ce qui a déjà changé, à dire.
fn retirer_les_programmes(correctifs: &[Vec<String>]) -> Vec<Result<(), Option<String>>> {
    #[cfg(windows)]
    return crate::machine::appliquer_chacune(correctifs)
        .into_iter()
        .map(|r| if r { Ok(()) } else { Err(None) })
        .collect();
    #[cfg(not(windows))]
    crate::machine::appliquer_gestes_puis_commandes(correctifs)
        .into_iter()
        .map(issue_du_retrait)
        .collect()
}

/// Ce que dit le retrait d'un programme, selon l'issue de ses gestes et de ses commandes : en partie, ce que les
/// gestes faits ont changé, sinon combien d'étapes sont faites (jamais un simple échec, qui laisserait croire que rien
/// n'a bougé).
#[cfg(not(windows))]
fn issue_du_retrait(issue: crate::machine::IssueMelee) -> Result<(), Option<String>> {
    match issue {
        crate::machine::IssueMelee::Fait => Ok(()),
        crate::machine::IssueMelee::Echec => Err(None),
        crate::machine::IssueMelee::EnPartie { faites, pas_faites } => Err(Some(deja_fait(&faites).map_or_else(
            || {
                let (faites, total) = (faites.len(), faites.len().saturating_add(pas_faites.len()));
                trf!(
                    "{faites} étape(s) sur {total} faite(s)",
                    "{faites} step(s) out of {total} done"
                )
            },
            str::to_string,
        ))),
    }
}

/// Ce que les gestes faits ont déjà changé : le service arrêté, retiré du démarrage, ou les deux ; `None` sans aucun
/// geste sur un service parmi elles.
#[cfg(not(windows))]
fn deja_fait(commandes: &[String]) -> Option<&'static str> {
    use crate::machine::gestes_unix::{ActionUnite, GesteUnix, analyser};
    let mut noms: Vec<String> = Vec::new();
    let (mut arrete, mut retire) = (false, false);
    for g in commandes.iter().filter_map(|c| analyser(c)) {
        if let GesteUnix::Designee(a, nom) = g {
            arrete |= matches!(a, ActionUnite::Arreter | ActionUnite::Desactiver);
            retire |= matches!(a, ActionUnite::DesactiverSansArreter | ActionUnite::Desactiver);
            if !noms.iter().any(|n| n == nom.as_str()) {
                noms.push(nom.as_str().to_string());
            }
        }
    }
    let plusieurs = noms.len() > 1;
    Some(match (arrete, retire, plusieurs) {
        (true, true, false) => tr!(
            "son service est arrêté et ne démarrera plus",
            "its service is stopped and will not start again"
        ),
        (true, true, true) => tr!(
            "ses services sont arrêtés et ne démarreront plus",
            "its services are stopped and will not start again"
        ),
        (true, false, false) => tr!("son service est arrêté", "its service is stopped"),
        (true, false, true) => tr!("ses services sont arrêtés", "its services are stopped"),
        (false, true, false) => tr!("son service ne démarrera plus", "its service will not start again"),
        (false, true, true) => tr!("ses services ne démarreront plus", "its services will not start again"),
        (false, false, _) => return None,
    })
}

/// La même trouvaille relevée deux fois (deux processus d'un même programme, un service et son processus) ne compte
/// qu'une fois.
fn sans_doublons(mut t: Vec<Trouvaille>) -> Vec<Trouvaille> {
    let mut vues: Vec<(usize, Trace, String)> = Vec::new();
    t.retain(|x| {
        let cle = (x.logiciel, x.trace, x.ou.clone());
        if vues.contains(&cle) {
            false
        } else {
            vues.push(cle);
            true
        }
    });
    t
}

/// Ce que le relevé a pu lire, pour chacune des quatre sortes de traces que l'écran annonce : une sorte qui n'a pas
/// pu l'être est dite non vérifiée (`--json`, rapport), jamais comptée comme « rien trouvé ».
// Quatre lectures indépendantes, pas des états d'une même chose.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Lu {
    installes: bool,
    demarrage: bool,
    en_cours: bool,
    fichiers: bool,
}

/// Les trouvailles d'un relevé, et ce qu'il a pu lire.
#[derive(Debug, Default)]
struct Releve {
    trouvailles: Vec<Trouvaille>,
    lu: Lu,
}

/// Un dossier lu, ou absent (rien à y trouver) ; `false` : il existe sans se lire.
#[cfg(unix)]
fn lisible_ou_absent(dossier: &std::path::Path) -> bool {
    match std::fs::read_dir(dossier) {
        Ok(_) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Pour le bilan et le parcours : les trouvailles. Sous Linux, sans les processus, « rien trouvé » ne se conclut pas :
/// `None`, non vérifié ; ce qui a été trouvé reste dit.
fn relever() -> Option<Vec<Trouvaille>> {
    pour_le_bilan(relever_tout())
}

fn pour_le_bilan(r: Option<Releve>) -> Option<Vec<Trouvaille>> {
    let r = r?;
    if cfg!(target_os = "linux") && !r.lu.en_cours && r.trouvailles.is_empty() {
        return None;
    }
    Some(r.trouvailles)
}

// ───────────────────────────── Jugement ─────────────────────────────

/// Les constats du bilan : un par logiciel trouvé, ou un seul « rien trouvé ». Un logiciel fourni avec le système
/// (Assistance rapide) ne compte que s'il est ouvert.
fn juger(trouvailles: &[Trouvaille], aujourd_hui: NaiveDate) -> Vec<Constat> {
    let mut constats = Vec::new();
    for (i, logiciel) in LOGICIELS.iter().enumerate() {
        let siens: Vec<&Trouvaille> = trouvailles.iter().filter(|t| t.logiciel == i).collect();
        if siens.is_empty() {
            continue;
        }
        let en_cours = siens.iter().any(|t| matches!(t.trace, Trace::EnCours { .. }));
        if logiciel.integre && !en_cours {
            continue;
        }
        let nom = logiciel.nom();
        let connecte = siens.iter().any(|t| t.trace == Trace::EnCours { connecte: true });
        let recent = siens.iter().any(|t| {
            matches!(t.trace, Trace::Installe | Trace::Fichier)
                && t.depuis
                    .is_some_and(|d| (0..RECENT_JOURS).contains(&(aujourd_hui - d).num_days()))
        });
        let fichier = siens.iter().any(|t| t.trace == Trace::Fichier);
        let installe = siens.iter().any(|t| t.trace == Trace::Installe);
        let demarrage = siens.iter().any(|t| t.trace == Trace::Demarrage);
        let niveau = if en_cours || recent || fichier {
            Niveau::Eleve
        } else {
            Niveau::Moyen
        };

        // Jamais de date ni de chiffre qui change dans le message : « déclarer normal » le reconnaît d'un jour à l'autre.
        let mut etats: Vec<&str> = Vec::new();
        if connecte {
            etats.push(tr!(
                "en cours d'exécution, avec une connexion ouverte en ce moment",
                "running, with a connection open right now"
            ));
        } else if en_cours {
            etats.push(tr!("en cours d'exécution", "running"));
        }
        if recent {
            etats.push(tr!(
                "installé ou téléchargé depuis moins d'un mois",
                "installed or downloaded less than a month ago"
            ));
        } else if installe {
            etats.push(tr!("installé", "installed"));
        }
        if fichier {
            etats.push(tr!(
                "programme posé dans Téléchargements, sur le Bureau ou dans un dossier temporaire",
                "program sitting in Downloads, on the Desktop or in a temporary folder"
            ));
        }
        if demarrage {
            etats.push(tr!("lancé au démarrage", "started at boot"));
        }
        let etats = etats.join(tr!(" ; ", "; "));
        let message = if logiciel.integre {
            trf!(
                "{nom} (fourni avec Windows) est ouvert en ce moment : la personne à l'autre bout peut voir cet écran et commander cet ordinateur. Ne l'ouvrez que si c'est vous qui avez appelé un soutien technique de confiance ; un faux technicien demande justement de l'ouvrir.",
                "{nom} (built into Windows) is open right now: the person at the other end can see this screen and operate this computer. Open it only if you called trusted technical support yourself; a fake technician asks precisely to open it."
            )
        } else {
            trf!(
                "{nom} est présent : {etats}. C'est un logiciel de prise de contrôle à distance : qui l'a installé peut voir cet écran et commander cet ordinateur ; c'est l'outil des faux techniciens (« votre ordinateur est infecté, laissez-moi réparer »). Si c'est vous qui l'utilisez, déclarez-le normal (« i » à la correction).",
                "{nom} is present: {etats}. It is a remote control tool: whoever installed it can see this screen and operate this computer; it is the tech-support scammers' tool (“your computer is infected, let me fix it”). If you use it yourself, mark it as normal (“i” at the fix step)."
            )
        };
        // L'objet : le logiciel par son nom français, le même quelle que soit la langue de l'interface.
        let constat = alerte(CAT, niveau, message).avec_objet(crate::modele::Objet::de("logiciel", logiciel.nom[0]));
        let retrait = lignes_du_retrait(&siens, false);
        constats.push(if en_cours {
            constat.manuel(
                tr!(
                    "Vanguard ne coupe pas une connexion à distance en cours. Si vous n'avez rien demandé : débranchez Internet (câble, Wi-Fi), puis menu « Arnaques et vie privée » › « Mon ordinateur est-il contrôlé ? » pour le fermer et le retirer",
                    "Vanguard does not cut a remote connection in progress. If you did not ask for anything: unplug the Internet (cable, Wi-Fi), then menu “Scams and privacy” › “Is my computer being controlled?” to close and remove it"
                ),
                &[],
            )
        } else if let Some(raisons) = raisons_du_refus(&siens) {
            // Rien du tout, pas même ses autres commandes : le logiciel à moitié retiré, son service encore en marche.
            // Et les réglages du système passeraient par les mêmes scripts de désinstallation : pas de conseil qui y
            // mène.
            constat.manuel(
                trf!(
                    "Vanguard ne retire pas {nom} : {raisons}. Ne le désinstallez pas non plus depuis les réglages du système, qui arrêteraient ses services sans rien demander",
                    "Vanguard does not remove {nom}: {raisons}. Do not uninstall it from the system settings either, which would stop its services without asking"
                ),
                &[],
            )
        } else if retrait.is_empty() {
            constat.manuel(
                trf!(
                    "Désinstaller {nom} depuis les réglages du système (applications installées)",
                    "Uninstall {nom} from the system settings (installed apps)"
                ),
                &[],
            )
        } else {
            constat.corriger(
                if cfg!(windows) {
                    trf!(
                        "Désinstaller {nom} (sa fenêtre de désinstallation peut s'ouvrir)",
                        "Uninstall {nom} (its uninstall window may open)"
                    )
                } else {
                    trf!("Désinstaller {nom}", "Uninstall {nom}")
                },
                &retrait,
            )
        });
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun logiciel de prise de contrôle à distance (AnyDesk, TeamViewer, RustDesk…) installé, lancé au démarrage, en cours ou téléchargé.",
                "No remote control tool (AnyDesk, TeamViewer, RustDesk…) installed, started at boot, running or downloaded."
            ),
        ));
    }
    constats
}

/// Au bilan.
pub fn constats() -> Vec<Constat> {
    match relever() {
        Some(t) => juger(&t, aujourd_hui()),
        None => vec![impossible(
            CAT,
            tr!("PowerShell indisponible ou bloqué", "PowerShell unavailable or blocked"),
        )],
    }
}

// ───────────────────────────── Relevé : Linux ─────────────────────────────

#[cfg(unix)]
fn sortie_de(cmd: &str, args: &[&str], secondes: u64) -> Option<String> {
    let mut c = std::process::Command::new(cmd);
    c.args(args);
    #[cfg(target_os = "linux")]
    let r = crate::commande::lancer_en_anglais(&mut c, secondes)?;
    #[cfg(not(target_os = "linux"))]
    let r = crate::commande::lancer(&mut c, secondes)?;
    (r.code == Some(0)).then_some(r.sortie)
}

/// Les programmes et installateurs posés à la racine de ces dossiers (Téléchargements, Bureau, temporaires) : le faux
/// technicien fait télécharger la version portable d'AnyDesk, qui ne s'installe nulle part.
/// `false` : un de ces dossiers existe sans se lire (sous macOS, Téléchargements et Bureau sans l'autorisation).
#[cfg(unix)]
fn fichiers_poses(t: &mut Vec<Trouvaille>, dossiers: &[PathBuf]) -> bool {
    let mut lus = true;
    for d in dossiers {
        lus &= lisible_ou_absent(d);
        for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
            let nom = e.file_name().to_string_lossy().into_owned();
            let Some(i) = reconnu(&nom) else {
                continue;
            };
            let Ok(meta) = e.metadata() else {
                continue;
            };
            let application = meta.is_dir() && nom.to_lowercase().ends_with(".app");
            if meta.is_dir() && !application {
                continue;
            }
            let chemin = e.path();
            t.push(Trouvaille {
                logiciel: i,
                trace: Trace::Fichier,
                ou: chemin_affichable(&chemin),
                depuis: date_de(meta.modified()),
                retrait: vec![format!(
                    "rm -{} {}",
                    if application { "rf" } else { "f" },
                    sh_chaine(&chemin.to_string_lossy())
                )],
                arret: Vec::new(),
                refuse: false,
            });
        }
    }
    lus
}

/// Numéros des processus qui ont une connexion TCP établie hors de la machine, d'après `ss` (« pid=1234 » dans la
/// dernière colonne). Une connexion locale (127.0.0.1, ::1) ne compte pas.
#[cfg(any(target_os = "linux", test))]
fn pids_dans_ss(sortie: &str) -> std::collections::BTreeSet<u32> {
    sortie
        .lines()
        .filter(|l| !l.contains(" 127.0.0.1:") && !l.contains(" [::1]:"))
        .flat_map(|l| {
            l.split("pid=")
                .skip(1)
                .filter_map(|m| m.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok())
        })
        .collect()
}

// Même signature que sous Windows, où la lecture peut échouer.
#[allow(clippy::unnecessary_wraps)]
#[cfg(target_os = "linux")]
fn relever_tout() -> Option<Releve> {
    let maison = crate::socle::maison();
    let mut t = Vec::new();
    // Flatpak, Snap et /opt ne s'y ajoutent que là où ils existent : les paquets de la distribution disent seuls si
    // les programmes installés ont été lus.
    // Lues avant les paquets : leur retrait en dépend (`retrait_garde`).
    let en_marche = unites_en_marche();
    let installes = paquets(&mut t, en_marche.as_deref());
    flatpaks(&mut t, &maison);
    snaps(&mut t, en_marche.as_deref());
    dossiers_opt(&mut t);
    // Les deux, toujours : l'un ne se lit pas sans que l'autre soit sauté.
    let en_cours = processus(&mut t) & services_en_marche(&mut t, en_marche.as_deref());
    let demarrage = demarrage_linux(&mut t, &maison);
    let declares = std::fs::read_to_string(maison.join(".config/user-dirs.dirs")).unwrap_or_default();
    let declare = |cle: &str, defaut: &str| {
        crate::protection::pieges::dossier_declare(&declares, cle, &maison).unwrap_or_else(|| maison.join(defaut))
    };
    let fichiers = fichiers_poses(
        &mut t,
        &[
            declare("XDG_DOWNLOAD_DIR", "Downloads"),
            declare("XDG_DESKTOP_DIR", "Desktop"),
            PathBuf::from("/tmp"),
        ],
    );
    Some(Releve {
        trouvailles: sans_doublons(t),
        lu: Lu {
            installes,
            demarrage,
            en_cours,
            fichiers,
        },
    })
}

/// Les unités du système en marche, lues par systemd sur le bus (ListUnits), sans droits : un processus caché par
/// hidepid ne se voit pas dans /proc, son unité si. Sans systemd, aucune ; `None` : systemd est là, mais elles ne se
/// lisent pas.
#[cfg(target_os = "linux")]
fn unites_en_marche() -> Option<Vec<String>> {
    use crate::machine::linux::unites;
    if !std::path::Path::new("/run/systemd/system").is_dir() {
        return Some(Vec::new());
    }
    let lues = unites::bus(false).and_then(|mut b| unites::unites(&mut b)).ok()?;
    Some(
        lues.into_iter()
            .filter(|u| en_marche(&u.activite))
            .map(|u| u.nom)
            .collect(),
    )
}

/// L'état d'activité d'une unité qui tourne, ou s'arrête encore : comme le fils, qui ne demande rien pour une unité
/// arrêtée.
#[cfg(target_os = "linux")]
fn en_marche(activite: &str) -> bool {
    matches!(activite, "active" | "activating" | "reloading" | "deactivating")
}

/// Le logiciel d'une unité en marche, si elle est un service à son nom. Seuls les services comptent : un `.mount` (celui
/// que tout snap monte), un `.scope` ou un `.slice` ne portent pas de session, et l'assistant ne les désigne pas ; les
/// compter bloquerait le retrait pour rien.
#[cfg(target_os = "linux")]
fn service_du_catalogue(nom: &str) -> Option<usize> {
    nom.ends_with(".service").then(|| reconnu(nom)).flatten()
}

/// Le geste d'arrêt d'un service du système en marche, ou la raison de ne pas en proposer (français, anglais). Une
/// instance d'un modèle (« chrome-remote-desktop@<compte>.service ») : l'assistant ne revoit pas les modèles, il la
/// refuserait ; dit tel quel plutôt qu'un geste voué à l'échec.
#[cfg(target_os = "linux")]
fn arret_d_un_service(nom: &str) -> Result<String, (&'static str, &'static str)> {
    if nom.contains('@') {
        return Err((
            "c'est l'instance d'un modèle de service, que Vanguard ne revoit pas",
            "it is an instance of a service template, which Vanguard does not review",
        ));
    }
    action_sur_unite("", false, ActionUnite::Arreter, nom)
}

/// Le retrait d'un paquet ou d'un snap du logiciel `i`, gardé. Ses scripts de désinstallation (prerm de Debian,
/// `snap remove`) arrêtent ses services sans rien demander, et couperaient une session qui passe par eux : chaque
/// unité du système en marche à son nom passe d'abord par le geste d'arrêt de l'assistant, avec sa question
/// « êtes-vous connecté par lui ? », son accord et ses preuves ; un geste en échec, et la commande ne part pas
/// (`machine::appliquer_gestes_puis_commandes`). `Err`, la raison de ne rien proposer : une unité en marche que
/// l'assistant ne désigne pas, ou des unités qui ne se lisent pas. Les unités de la session ne comptent pas : ces
/// scripts n'arrêtent que celles du système.
#[cfg(target_os = "linux")]
fn retrait_garde(i: usize, commande: String, en_marche: Option<&[String]>) -> Result<Vec<String>, Echec> {
    const CONTEXTE: &str = "distance/retrait";
    let Some(en_marche) = en_marche else {
        return Err(Echec::refuse(
            CONTEXTE,
            tr!(
                "les services en marche ne se lisent pas, et sa désinstallation pourrait en arrêter un qui porte une session à distance",
                "the running services cannot be read, and uninstalling it could stop one that carries a remote session"
            ),
        ));
    };
    let mut retrait = Vec::new();
    for nom in en_marche.iter().filter(|n| service_du_catalogue(n) == Some(i)) {
        match arret_d_un_service(nom) {
            Ok(geste) => retrait.push(geste),
            Err((fr, en)) => {
                let vu = affichable(nom);
                return Err(Echec::refuse(
                    CONTEXTE,
                    trf!(
                        "son service {vu} tourne, et Vanguard n'y touche pas ({fr}) ; sa désinstallation l'arrêterait sans rien demander",
                        "its service {vu} is running, and Vanguard leaves it alone ({en}); uninstalling it would stop it without asking"
                    ),
                ));
            }
        }
    }
    retrait.push(commande);
    Ok(retrait)
}

/// Où est un paquet ou un snap, et son retrait gardé (`retrait_garde`) ; refusé, rien n'est proposé, et la raison est
/// dite là où il est montré.
#[cfg(target_os = "linux")]
fn ou_et_retrait(i: usize, ou: String, commande: String, en_marche: Option<&[String]>) -> (String, Vec<String>) {
    match retrait_garde(i, commande, en_marche) {
        Ok(retrait) => (ou, retrait),
        Err(raison) => (
            trf!(
                "{ou} (Vanguard ne le retire pas : {raison})",
                "{ou} (Vanguard does not remove it: {raison})"
            ),
            Vec::new(),
        ),
    }
}

/// Les services du système en marche à son nom (`unites_en_marche`), même lancés autrement qu'au démarrage, et même
/// quand leur processus est caché : leur arrêt est le geste de l'assistant, avec sa question et ses preuves. `false` :
/// systemd est là, mais ils ne se lisent pas.
#[cfg(target_os = "linux")]
fn services_en_marche(t: &mut Vec<Trouvaille>, en_marche: Option<&[String]>) -> bool {
    let Some(en_marche) = en_marche else {
        return false;
    };
    for nom in en_marche {
        let Some(i) = service_du_catalogue(nom) else {
            continue;
        };
        let vu = affichable(nom);
        let (ou, arret) = match arret_d_un_service(nom) {
            Ok(geste) => (trf!("service {vu}", "service {vu}"), vec![geste]),
            Err((fr, en)) => (
                trf!(
                    "service {vu} (Vanguard n'y touche pas : {fr})",
                    "service {vu} (Vanguard leaves it alone: {en})"
                ),
                Vec::new(),
            ),
        };
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::EnCours { connecte: false },
            ou,
            depuis: None,
            retrait: Vec::new(),
            arret,
            refuse: false,
        });
    }
    true
}

/// Date de modification du premier fichier ou dossier de `dossier` dont le nom commence par `prefixe`.
#[cfg(target_os = "linux")]
fn date_dans(dossier: &str, prefixe: &str) -> Option<NaiveDate> {
    std::fs::read_dir(dossier)
        .ok()?
        .flatten()
        .find(|e| {
            let nom = e.file_name().to_string_lossy().into_owned();
            nom == prefixe.trim_end_matches('-')
                || nom
                    .strip_prefix(prefixe)
                    .is_some_and(|reste| reste.starts_with(|c: char| c.is_ascii_digit()))
        })
        .and_then(|e| date_de(e.metadata().and_then(|m| m.modified())))
}

/// Paquets de la distribution dont le nom est celui d'un logiciel de prise de contrôle ; le retrait passe par
/// l'outil de la distribution (Omarchy, rpm-ostree et transactional-update compris : `Paquets::retirer`).
/// `false` : aucun gestionnaire de paquets connu, ou sa liste ne se lit pas.
#[cfg(target_os = "linux")]
fn paquets(t: &mut Vec<Trouvaille>, en_marche: Option<&[String]>) -> bool {
    use crate::machine::linux::Paquets;
    let Some(gestionnaire) = Paquets::detecter() else {
        return false;
    };
    // Les bases de pacman et de dpkg se lisent directement ; leur commande ne sert qu'en secours, quand la base ne
    // se lit pas. rpm garde la sienne : sa base est du SQLite.
    let lue = match gestionnaire {
        Paquets::Pacman => crate::machine::linux::natif::paquets_pacman()
            .map(|l| l.into_iter().map(|(nom, _)| nom).collect::<Vec<_>>()),
        Paquets::Apt => crate::machine::linux::natif::paquets_dpkg_installes().map(|l| {
            let mut noms: Vec<String> = l.into_iter().map(|(nom, _)| nom).collect();
            noms.dedup();
            noms
        }),
        Paquets::Dnf | Paquets::Zypper => None,
    };
    let liste = match (lue, gestionnaire) {
        (Some(noms), _) => Some(noms.join("\n")),
        (None, Paquets::Pacman) => sortie_de("pacman", &["-Qq"], 60),
        (None, Paquets::Apt) => sortie_de("dpkg-query", &["-W", "-f=${binary:Package}\n"], 60),
        (None, Paquets::Dnf | Paquets::Zypper) => sortie_de("rpm", &["-qa", "--qf", "%{NAME}\n"], 60),
    };
    let Some(liste) = liste else {
        return false;
    };
    for p in liste.lines().map(str::trim).filter(|p| !p.is_empty()) {
        let Some(i) = reconnu(p) else {
            continue;
        };
        let depuis = match gestionnaire {
            Paquets::Pacman => date_dans("/var/lib/pacman/local", &format!("{p}-")),
            Paquets::Apt => date_dans(
                "/var/lib/dpkg/info",
                &format!("{}.list", p.split(':').next().unwrap_or(p)),
            ),
            Paquets::Dnf | Paquets::Zypper => sortie_de("rpm", &["-q", "--qf", "%{INSTALLTIME}\n", p], 30)
                .and_then(|s| s.trim().parse::<i64>().ok())
                .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
                .map(|d| d.with_timezone(&chrono::Local).date_naive()),
        };
        let (ou, retrait) = ou_et_retrait(
            i,
            trf!("paquet {p}", "package {p}"),
            gestionnaire.retirer(&sh_chaine(p)),
            en_marche,
        );
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::Installe,
            ou,
            depuis,
            refuse: retrait.is_empty(),
            retrait,
            arret: Vec::new(),
        });
    }
    true
}

#[cfg(target_os = "linux")]
fn flatpaks(t: &mut Vec<Trouvaille>, maison: &std::path::Path) {
    // Lues dans les dossiers de Flatpak ; sa commande en secours, quand d'autres installations sont réglées.
    // Sans le programme flatpak, `applications_flatpak` ne rend rien (voir là).
    let Some(liste) = crate::machine::linux::paquets::applications_flatpak() else {
        return;
    };
    for id in liste.iter().map(String::as_str) {
        let Some(i) = reconnu(id) else {
            continue;
        };
        let depuis = [
            PathBuf::from("/var/lib/flatpak/app").join(id),
            maison.join(".local/share/flatpak/app").join(id),
        ]
        .iter()
        .find_map(|d| date_de(std::fs::metadata(d).and_then(|m| m.modified())));
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::Installe,
            ou: format!("Flatpak {id}"),
            depuis,
            retrait: vec![format!("flatpak uninstall -y --noninteractive {}", sh_chaine(id))],
            arret: Vec::new(),
            refuse: false,
        });
    }
}

#[cfg(target_os = "linux")]
fn snaps(t: &mut Vec<Trouvaille>, en_marche: Option<&[String]>) {
    // Les fichiers de snapd disent les snaps installés ; `snap list` en secours, quand ils ne se lisent pas.
    let natif = crate::machine::linux::natif::snaps;
    let Some(liste) = liste_snaps(crate::machine::linux::natif::present("snap"), natif) else {
        return;
    };
    for nom in liste.iter().map(String::as_str) {
        let Some(i) = reconnu(nom) else {
            continue;
        };
        let (ou, retrait) = ou_et_retrait(
            i,
            format!("Snap {nom}"),
            format!("sudo snap remove {}", sh_chaine(nom)),
            en_marche,
        );
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::Installe,
            ou,
            depuis: None,
            refuse: retrait.is_empty(),
            retrait,
            arret: Vec::new(),
        });
    }
}

/// Les noms des snaps installés. Sans le programme snap, rien : les fichiers restés dans /var/lib/snapd après
/// la désinstallation de snapd ne sont plus des logiciels qui démarrent, et le retrait proposé
/// (`snap remove`) ne pourrait pas se lancer ; `snap list` d'avant ne trouvait rien non plus.
#[cfg(target_os = "linux")]
fn liste_snaps(
    snap_present: bool,
    lire: impl FnOnce() -> Option<Vec<crate::machine::linux::natif::Snap>>,
) -> Option<Vec<String>> {
    if !snap_present {
        return None;
    }
    if let Some(snaps) = lire() {
        return Some(snaps.into_iter().map(|s| s.nom).collect());
    }
    let sortie = sortie_de("snap", &["list"], 60)?;
    Some(
        sortie
            .lines()
            .skip(1)
            .filter_map(|l| Some(l.split_whitespace().next()?.to_string()))
            .collect(),
    )
}

/// Installations à la main dans /opt (archive décompressée), quand aucun paquet ne les fournit.
#[cfg(target_os = "linux")]
fn dossiers_opt(t: &mut Vec<Trouvaille>) {
    for e in std::fs::read_dir("/opt").into_iter().flatten().flatten() {
        let nom = e.file_name().to_string_lossy().into_owned();
        let Some(i) = reconnu(&nom) else {
            continue;
        };
        if t.iter().any(|x| x.logiciel == i && x.trace == Trace::Installe) {
            continue;
        }
        let chemin = e.path();
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::Installe,
            ou: chemin_affichable(&chemin),
            depuis: date_de(e.metadata().and_then(|m| m.modified())),
            retrait: vec![format!("sudo rm -rf {}", sh_chaine(&chemin.to_string_lossy()))],
            arret: Vec::new(),
            refuse: false,
        });
    }
}

/// Processus en cours, d'après /proc : le nom court (comm) et, quand il se lit, le programme lancé. `false` : /proc
/// ne se lit pas (la liste vide d'avant passait pour « rien en cours »).
#[cfg(target_os = "linux")]
fn processus(t: &mut Vec<Trouvaille>) -> bool {
    // Lu dans /proc par le module des connexions sortantes ; ss en secours, quand /proc/net ne se lit pas.
    let connectes = crate::protection::sortantes::processus_connectes()
        .or_else(|| sortie_de("ss", &["-tnpH", "state", "established"], 15).map(|s| pids_dans_ss(&s)))
        .unwrap_or_default();
    let Some(pids) = crate::socle::processus::pids() else {
        return false;
    };
    for pid in pids {
        let comm = crate::socle::processus::nom_court(pid)
            .unwrap_or_default()
            .trim()
            .to_string();
        let exe = crate::socle::processus::programme(pid);
        let nom_exe = exe
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some(i) = reconnu(&comm).or_else(|| reconnu(&nom_exe)) else {
            continue;
        };
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::EnCours {
                connecte: connectes.contains(&pid),
            },
            ou: exe.as_deref().map_or_else(|| affichable(&comm), chemin_affichable),
            depuis: None,
            retrait: Vec::new(),
            arret: vec![format!("pkill -x {} || true", sh_chaine(&comm))],
            refuse: false,
        });
    }
    true
}

/// Arrêter une unité, ou ne plus la lancer au démarrage. Du système : le geste de l'assistant élevé, par le bus
/// système (lot U3), que le fils ne fait qu'après avoir revu l'unité lui-même ; un nom que l'assistant ne désigne pas
/// (une unité de sa table, un nom hors de sa règle) n'a rien de proposé, avec la raison (`Err`, en français et en
/// anglais) : jamais une commande
/// sudo qui passerait à côté de ses contrôles. De la session (`systemctl --user`) : une commande du compte, sans
/// droits.
#[cfg(target_os = "linux")]
fn action_sur_unite(
    prefixe: &str,
    utilisateur: bool,
    action: ActionUnite,
    unite: &str,
) -> Result<String, (&'static str, &'static str)> {
    if utilisateur {
        return Ok(commande_d_unite(prefixe, action, unite));
    }
    crate::machine::gestes_unix::designee_ou_refus(action, unite).map(crate::machine::gestes_unix::GesteUnix::ligne)
}

/// La commande systemctl d'une unité de la session : `stop`, ou `disable` (sans arrêter).
#[cfg(target_os = "linux")]
fn commande_d_unite(prefixe: &str, action: ActionUnite, unite: &str) -> String {
    let mot = if action == ActionUnite::Arreter {
        "stop"
    } else {
        "disable"
    };
    format!("{prefixe} {mot} {}", sh_chaine(unite))
}

/// Lancements automatiques : fichiers .desktop d'autostart (nom ou ligne Exec), services systemd activés (système et
/// session).
/// `false` : un dossier d'autostart existe sans se lire, ou les services activés (système ou session) ne se lisent
/// ni dans leurs dossiers ni par systemctl.
#[cfg(target_os = "linux")]
fn demarrage_linux(t: &mut Vec<Trouvaille>, maison: &std::path::Path) -> bool {
    let mut lus = true;
    for (dossier, sudo) in [
        (maison.join(".config/autostart"), ""),
        (PathBuf::from("/etc/xdg/autostart"), "sudo "),
    ] {
        lus &= lisible_ou_absent(&dossier);
        for e in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
            let chemin = e.path();
            if chemin.extension().is_none_or(|x| x != "desktop") {
                continue;
            }
            let nom = e.file_name().to_string_lossy().into_owned();
            let contenu = std::fs::read_to_string(&chemin).unwrap_or_default();
            let exec = contenu
                .lines()
                .find_map(|l| l.strip_prefix("Exec="))
                .unwrap_or_default();
            let Some(i) = reconnu(&nom).or_else(|| reconnu(exec)) else {
                continue;
            };
            t.push(Trouvaille {
                logiciel: i,
                trace: Trace::Demarrage,
                ou: chemin_affichable(&chemin),
                depuis: None,
                retrait: vec![format!("{sudo}rm -f {}", sh_chaine(&chemin.to_string_lossy()))],
                arret: Vec::new(),
                refuse: false,
            });
        }
    }
    for (args, prefixe, utilisateur) in [
        (
            &["list-unit-files", "--state=enabled", "--no-legend", "--plain"][..],
            "",
            false,
        ),
        (
            &["--user", "list-unit-files", "--state=enabled", "--no-legend", "--plain"][..],
            "systemctl --user",
            true,
        ),
    ] {
        // Les liens d'activation se lisent directement ; systemctl en secours, quand un dossier ne se lit pas.
        let liste: Vec<String> = if let Some(l) = unites_activees(maison, utilisateur) {
            l
        } else {
            let Some(sortie) = sortie_de("systemctl", args, 30) else {
                lus = false;
                continue;
            };
            sortie
                .lines()
                .filter_map(|l| Some(l.split_whitespace().next()?.to_string()))
                .collect()
        };
        for unite in liste.iter().map(String::as_str) {
            let Some(i) = reconnu(unite) else {
                continue;
            };
            // Sans geste admis, rien n'est proposé pour ce service, et la raison est dite là où il est montré.
            let (ou, retrait, arret) = match (
                action_sur_unite(prefixe, utilisateur, ActionUnite::DesactiverSansArreter, unite),
                action_sur_unite(prefixe, utilisateur, ActionUnite::Arreter, unite),
            ) {
                (Ok(retrait), Ok(arret)) => (trf!("service {unite}", "service {unite}"), vec![retrait], vec![arret]),
                (Err((fr, en)), _) | (_, Err((fr, en))) => (
                    trf!(
                        "service {unite} (Vanguard n'y touche pas : {fr})",
                        "service {unite} (Vanguard leaves it alone: {en})"
                    ),
                    Vec::new(),
                    Vec::new(),
                ),
            };
            t.push(Trouvaille {
                logiciel: i,
                trace: Trace::Demarrage,
                ou,
                depuis: None,
                retrait,
                arret,
                refuse: false,
            });
        }
    }
    lus
}

/// Les unités activées, comme `systemctl [--user] list-unit-files --state=enabled`, lues dans les liens que
/// `systemctl enable` pose : /etc/systemd/system pour le système ; ~/.config/systemd/user et /etc/systemd/user
/// (activées pour tous les comptes) pour la session. Ceux de /run ne durent que jusqu'au redémarrage
/// (« enabled-runtime ») : ils ne comptent pas, mais un masque posé là, si. `None` si un dossier existe sans se
/// lire.
#[cfg(target_os = "linux")]
fn unites_activees(maison: &std::path::Path, utilisateur: bool) -> Option<Vec<String>> {
    let chemins = |liste: &[&str]| liste.iter().map(PathBuf::from).collect::<Vec<_>>();
    if utilisateur {
        let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
        let donnees = std::env::var_os("XDG_DATA_HOME").map_or_else(|| maison.join(".local/share"), PathBuf::from);
        let uid = crate::socle::uid();
        let compte = config.join("systemd/user");
        let session = PathBuf::from(format!("/run/user/{uid}/systemd"));
        // Les dossiers où le gestionnaire de la session cherche les unités (sans ceux des générateurs, dont les unités
        // sont « generated », jamais « enabled »).
        let mut recherche = vec![
            config.join("systemd/user.control"),
            session.join("user.control"),
            compte.clone(),
            PathBuf::from("/etc/systemd/user"),
            session.join("user"),
            PathBuf::from("/run/systemd/user"),
            donnees.join("systemd/user"),
        ];
        let partages = std::env::var("XDG_DATA_DIRS").unwrap_or_else(|_| "/usr/local/share:/usr/share".into());
        recherche.extend(
            partages
                .split(':')
                .filter(|d| d.starts_with('/'))
                .map(|d| std::path::Path::new(d).join("systemd/user")),
        );
        recherche.extend(chemins(&["/usr/local/lib/systemd/user", "/usr/lib/systemd/user"]));
        unites_activees_dans(
            &[compte.clone(), PathBuf::from("/etc/systemd/user")],
            &[
                compte,
                PathBuf::from("/etc/systemd/user"),
                session.join("user"),
                PathBuf::from("/run/systemd/user"),
            ],
            &recherche,
        )
    } else {
        unites_activees_dans(
            &[PathBuf::from("/etc/systemd/system")],
            &[
                PathBuf::from("/etc/systemd/system"),
                PathBuf::from("/run/systemd/system"),
            ],
            &chemins(&[
                "/etc/systemd/system.control",
                "/run/systemd/system.control",
                "/etc/systemd/system",
                "/etc/systemd/system.attached",
                "/run/systemd/system",
                "/run/systemd/system.attached",
                "/usr/local/lib/systemd/system",
                "/usr/lib/systemd/system",
                "/lib/systemd/system",
            ]),
        )
    }
}

/// L'unité `nom` existe-t-elle dans un dossier où systemd cherche les unités (son modèle « x@.service » pour une
/// instance) ? Un lien d'activation resté après le retrait de son unité ne démarre rien, et systemctl ne la liste
/// pas : sur Ubuntu 24.04, apport a cessé de fournir apport.service en laissant son lien dans multi-user.target.wants.
#[cfg(target_os = "linux")]
fn unite_existe(nom: &str, recherche: &[PathBuf]) -> bool {
    let modele = nom
        .split_once('@')
        .and_then(|(debut, reste)| Some(format!("{debut}@.{}", reste.rsplit_once('.')?.1)));
    recherche
        .iter()
        .any(|d| d.join(nom).exists() || modele.as_ref().is_some_and(|m| d.join(m).exists()))
}

/// Une unité est activée par un lien à son nom dans un dossier « *.wants », « *.requires » ou « *.upholds », ou
/// par un alias (lien d'un autre nom vers son fichier, « display-manager.service » vers le gestionnaire de
/// connexion). Masquée (lien vers /dev/null dans `masques`), elle ne démarre plus : elle ne compte pas ; absente de
/// tous les dossiers de `recherche` non plus (`unite_existe`).
#[cfg(target_os = "linux")]
fn unites_activees_dans(dossiers: &[PathBuf], masques: &[PathBuf], recherche: &[PathBuf]) -> Option<Vec<String>> {
    let null = std::path::Path::new("/dev/null");
    let mut activees = std::collections::BTreeSet::new();
    for d in dossiers {
        let entrees = match std::fs::read_dir(d) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for e in entrees.flatten() {
            let nom = e.file_name().to_string_lossy().into_owned();
            if [".wants", ".requires", ".upholds"].iter().any(|s| nom.ends_with(s)) {
                for l in std::fs::read_dir(e.path()).into_iter().flatten().flatten() {
                    let lien = l.file_name().to_string_lossy().into_owned();
                    activees.insert(nom_active(&lien, &l.path()));
                }
            } else if let Ok(cible) = std::fs::read_link(e.path())
                && cible != null
                && let Some(vrai) = cible.file_name().map(|n| n.to_string_lossy().into_owned())
                && vrai != nom
                && nom.contains('.')
            {
                activees.insert(vrai);
            }
        }
    }
    activees.retain(|u| {
        !masques
            .iter()
            .any(|m| std::fs::read_link(m.join(u)).is_ok_and(|c| c == null))
            && unite_existe(u, recherche)
    });
    Some(activees.into_iter().collect())
}

/// Le nom sous lequel systemctl range un lien d'activation. Une instance d'un modèle (« modele@instance »
/// suivi du suffixe de l'unité) compte pour le modèle quand elle est son instance par défaut (DefaultInstance= de `[Install]`, comme pour les
/// consoles) ; une autre instance garde son nom : systemctl dit alors le modèle « indirect », mais elle démarre
/// bien, et ne pas la montrer cacherait un lancement automatique.
#[cfg(target_os = "linux")]
fn nom_active(lien: &str, chemin: &std::path::Path) -> String {
    let Some((debut, reste)) = lien.split_once('@') else {
        return lien.to_string();
    };
    let Some((instance, suffixe)) = reste.rsplit_once('.') else {
        return lien.to_string();
    };
    if instance.is_empty() {
        return lien.to_string();
    }
    // Un lien relatif part du dossier qui le contient ; `join` d'un chemin absolu le garde tel quel.
    let fichier = std::fs::read_link(chemin).map_or_else(
        |_| chemin.to_path_buf(),
        |c| chemin.parent().map_or_else(|| c.clone(), |p| p.join(&c)),
    );
    // Le lien peut venir du compte (~/.config/systemd/user) et pointer n'importe où : un fichier d'unité fait
    // quelques Ko, la borne écarte un tube nommé ou /dev/zero, qui bloqueraient ou rempliraient la mémoire.
    let defaut = crate::machine::linux::natif::lire_borne(&fichier, 64 * 1024).and_then(|t| {
        crate::machine::linux::natif::section_ini(&t, "Install")
            .into_iter()
            .find(|(c, _)| *c == "DefaultInstance")
            .map(|(_, v)| v.to_string())
    });
    if defaut.as_deref() == Some(instance) {
        format!("{debut}@.{suffixe}")
    } else {
        lien.to_string()
    }
}

// ───────────────────────────── Relevé : macOS ─────────────────────────────

// Même signature que sous Windows, où la lecture peut échouer.
#[allow(clippy::unnecessary_wraps)]
#[cfg(target_os = "macos")]
fn relever_tout() -> Option<Releve> {
    let maison = crate::socle::maison();
    let mut t = Vec::new();
    let mut lu = Lu {
        installes: true,
        demarrage: true,
        ..Lu::default()
    };
    for (dossier, sudo) in [
        (PathBuf::from("/Applications"), "sudo "),
        (maison.join("Applications"), ""),
    ] {
        lu.installes &= lisible_ou_absent(&dossier);
        for e in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
            let nom = e.file_name().to_string_lossy().into_owned();
            if !nom.to_lowercase().ends_with(".app") {
                continue;
            }
            let Some(i) = reconnu(&nom) else {
                continue;
            };
            let chemin = e.path();
            t.push(Trouvaille {
                logiciel: i,
                trace: Trace::Installe,
                ou: chemin_affichable(&chemin),
                depuis: date_de(e.metadata().and_then(|m| m.created())),
                retrait: vec![format!("{sudo}rm -rf {}", sh_chaine(&chemin.to_string_lossy()))],
                arret: Vec::new(),
                refuse: false,
            });
        }
    }
    for (dossier, domaine, sudo) in [
        (PathBuf::from("/Library/LaunchAgents"), "system", "sudo "),
        (PathBuf::from("/Library/LaunchDaemons"), "system", "sudo "),
        (maison.join("Library/LaunchAgents"), "gui/$(id -u)", ""),
    ] {
        lu.demarrage &= lisible_ou_absent(&dossier);
        for e in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
            let nom = e.file_name().to_string_lossy().into_owned();
            let Some(i) = reconnu(&nom) else {
                continue;
            };
            let chemin = sh_chaine(&e.path().to_string_lossy());
            t.push(Trouvaille {
                logiciel: i,
                trace: Trace::Demarrage,
                ou: chemin_affichable(&e.path()),
                depuis: None,
                retrait: vec![format!("{sudo}rm -f {chemin}")],
                arret: vec![format!("{sudo}launchctl bootout {domaine} {chemin} || true")],
                refuse: false,
            });
        }
    }
    // lsof : « p1234 » puis les connexions « n192.168.1.5:51234->1.2.3.4:443 » du processus.
    let mut connectes = std::collections::BTreeSet::new();
    if let Some(lsof) = sortie_de("lsof", &["-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pn"], 20) {
        let mut pid = None;
        for l in lsof.lines() {
            if let Some(p) = l.strip_prefix('p') {
                pid = p.parse::<u32>().ok();
            } else if l.starts_with('n')
                && l.contains("->")
                && !l.contains("->127.0.0.1:")
                && !l.contains("->[::1]:")
                && let Some(p) = pid
            {
                connectes.insert(p);
            }
        }
    }
    if let Some(ps) = sortie_de("ps", &["-axo", "pid=,comm="], 15) {
        lu.en_cours = true;
        for l in ps.lines() {
            let Some((pid, comm)) = l.trim().split_once(char::is_whitespace) else {
                continue;
            };
            let comm = comm.trim();
            let court = comm.rsplit('/').next().unwrap_or(comm);
            let Some(i) = reconnu(comm) else {
                continue;
            };
            t.push(Trouvaille {
                logiciel: i,
                trace: Trace::EnCours {
                    connecte: pid.parse::<u32>().is_ok_and(|p| connectes.contains(&p)),
                },
                ou: affichable(comm),
                depuis: None,
                retrait: Vec::new(),
                arret: vec![format!("pkill -x {} || true", sh_chaine(court))],
                refuse: false,
            });
        }
    }
    lu.fichiers = fichiers_poses(&mut t, &[maison.join("Downloads"), maison.join("Desktop")]);
    Some(Releve {
        trouvailles: sans_doublons(t),
        lu,
    })
}

// ───────────────────────────── Relevé : Windows ─────────────────────────────

#[cfg(windows)]
fn relever_tout() -> Option<Releve> {
    // Tout est lu par Vanguard lui-même, sans PowerShell (c'était la vérification la plus lente du bilan, plus de 3 s) :
    // programmes installés et clés Run dans le registre, processus et connexions par les fonctions de Windows,
    // fichiers posés par une lecture des dossiers. Le texte garde les sections du script d'avant (INS, PRC, CNX, RUN,
    // FIC, SVC), que `lire_windows` lit.
    let mut sortie = String::new();
    let installes = installes_du_registre(&mut sortie);
    let en_cours = processus_et_connexions(&mut sortie);
    let run = run_du_registre(&mut sortie);
    let fichiers = fichiers_poses_windows(&mut sortie);
    let services = services_du_registre();
    // Clé des services illisible : section vide (voir là).
    let demarrage = run && !services.is_empty();
    sortie.push_str(&services);
    lire_windows(&sortie).map(|t| Releve {
        trouvailles: sans_doublons(t),
        lu: Lu {
            installes,
            demarrage,
            en_cours,
            fichiers,
        },
    })
}

/// Une valeur sur une ligne de section : sans saut de ligne (qui ouvrirait une fausse ligne).
#[cfg(windows)]
fn sur_une_ligne(v: &str) -> String {
    v.replace(['\n', '\r'], " ")
}

/// Programmes et fonctionnalités (64 et 32 bits, et ceux du compte) : « INS|nom|date d'installation|date de la clé|
/// désinstallation|désinstallation silencieuse ». La date de la clé seulement quand l'installateur n'en donne pas.
/// `false` : aucune des clés ne s'ouvre.
#[cfg(windows)]
fn installes_du_registre(sortie: &mut String) -> bool {
    use std::fmt::Write;
    use winreg::RegKey;
    let mut une_lue = false;
    for (racine, chemin) in crate::machine::windows::installes::CLES_UNINSTALL {
        let Ok(liste) = RegKey::predef(racine).open_subkey(chemin) else {
            continue;
        };
        une_lue = true;
        for nom_de_cle in liste.enum_keys().flatten() {
            let Ok(cle) = liste.open_subkey(&nom_de_cle) else {
                continue;
            };
            let texte = |v: &str| sur_une_ligne(&cle.get_value::<String, _>(v).unwrap_or_default());
            let nom = texte("DisplayName");
            if nom.trim().is_empty() {
                continue;
            }
            let installation = texte("InstallDate");
            let date_de_cle = if installation.len() == 8 && installation.bytes().all(|b| b.is_ascii_digit()) {
                String::new()
            } else {
                cle.query_info().map_or_else(
                    |_| String::new(),
                    |i| {
                        let t = i.get_last_write_time_system();
                        format!("{:04}-{:02}-{:02}", t.wYear, t.wMonth, t.wDay)
                    },
                )
            };
            let _ = writeln!(
                sortie,
                "INS|{nom}|{installation}|{date_de_cle}|{}|{}",
                texte("UninstallString"),
                texte("QuietUninstallString")
            );
        }
    }
    sortie.push_str("INS_FIN\n");
    une_lue
}

/// Processus (« PRC|numéro|nom|chemin », le chemin quand Windows le donne et que le logiciel est reconnu) et ceux qui parlent à une autre machine
/// (« CNX|numéro »), lus par les fonctions de Windows. `false` : Windows n'a rendu aucun processus (refus).
#[cfg(windows)]
fn processus_et_connexions(sortie: &mut String) -> bool {
    use crate::machine::windows::processus;
    use std::fmt::Write;
    let liste = processus::liste();
    let lus = !liste.is_empty();
    for p in liste {
        // Le nom (celui du fichier du programme) suffit à reconnaître un logiciel : le chemin, qui coûte une ouverture
        // du processus, seulement pour ceux-là, au lieu des deux ou trois cents d'un Windows.
        let chemin = if reconnu(&p.nom).is_some() {
            processus::chemin(p.pid).map(|c| sur_une_ligne(&c)).unwrap_or_default()
        } else {
            String::new()
        };
        let _ = writeln!(sortie, "PRC|{}|{}|{chemin}", p.pid, sur_une_ligne(&p.nom));
    }
    sortie.push_str("PRC_FIN\n");
    if let Some(connectes) = crate::protection::sortantes::processus_connectes() {
        for pid in connectes {
            let _ = writeln!(sortie, "CNX|{pid}");
        }
        sortie.push_str("CNX_FIN\n");
    }
    lus
}

/// Les clés Run et RunOnce du compte et de la machine : « RUN|clé|nom|commande ». La clé est écrite comme
/// PowerShell l'écrit (« HKCU:\… ») : c'est elle que la commande de retrait reprend. Lues par la lecture commune
/// (`machine::windows::persistance::lignes_run`), qui garde les noms mal formés et lit aussi RunOnce. `false` : une
/// clé n'a pas pu être lue en entier (le démarrage est alors dit non vérifié).
#[cfg(windows)]
fn run_du_registre(sortie: &mut String) -> bool {
    use std::fmt::Write;
    let (valeurs, illisibles) = crate::machine::windows::persistance::lignes_run();
    for v in valeurs {
        let _ = writeln!(
            sortie,
            "RUN|{}|{}|{}",
            v.cle,
            sur_une_ligne(&v.nom),
            sur_une_ligne(&v.valeur)
        );
    }
    sortie.push_str("RUN_FIN\n");
    illisibles.is_empty()
}

/// Les dossiers à lire, parmi ceux que l'environnement et le registre nomment : en chemin absolu seulement (un
/// chemin vide ou relatif lirait le dossier courant).
#[cfg(any(windows, test))]
fn dossiers_nommes(candidats: impl IntoIterator<Item = Option<std::path::PathBuf>>) -> Vec<std::path::PathBuf> {
    candidats.into_iter().flatten().filter(|d| d.is_absolute()).collect()
}

/// Les programmes, installateurs et archives posés dans Téléchargements, sur le Bureau, dans le dossier temporaire et
/// dans les programmes du compte, sous-dossiers compris (un niveau) : « FIC|chemin|date ». `false` : un de ces
/// dossiers existe sans se lire, ou aucun n'a pu être nommé (service, environnement vidé) : rien n'a été lu.
#[cfg(windows)]
fn fichiers_poses_windows(sortie: &mut String) -> bool {
    use std::fmt::Write;
    use std::path::{Path, PathBuf};
    let profil = std::env::var_os("USERPROFILE").map(PathBuf::from);
    // Le Bureau peut être ailleurs (OneDrive) : son vrai chemin est dans le registre.
    let bureau = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
        .and_then(|k| k.get_value::<String, _>("Desktop"))
        .ok()
        .map(PathBuf::from)
        .or_else(|| profil.as_ref().map(|p| p.join("Desktop")));
    let dossiers = dossiers_nommes([
        profil.as_ref().map(|p| p.join("Downloads")),
        bureau,
        std::env::var_os("TEMP").map(PathBuf::from),
        std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Programs")),
    ]);
    let a_garder = |c: &Path| {
        c.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| ["exe", "msi", "zip"].iter().any(|x| e.eq_ignore_ascii_case(x)))
    };
    let mut lus = !dossiers.is_empty();
    for dossier in dossiers {
        if let Err(e) = std::fs::read_dir(&dossier) {
            lus &= e.kind() == std::io::ErrorKind::NotFound;
        }
        let mut a_lire = vec![(dossier, 0)];
        while let Some((d, niveau)) = a_lire.pop() {
            for entree in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let Ok(type_) = entree.file_type() else {
                    continue;
                };
                let chemin = entree.path();
                if type_.is_dir() && niveau == 0 {
                    a_lire.push((chemin, 1));
                } else if type_.is_file() && a_garder(&chemin) {
                    let date = entree
                        .metadata()
                        .and_then(|m| m.modified())
                        .map(|t| {
                            chrono::DateTime::<chrono::Local>::from(t)
                                .format("%Y-%m-%d")
                                .to_string()
                        })
                        .unwrap_or_default();
                    let _ = writeln!(sortie, "FIC|{}|{date}", sur_une_ligne(&chemin.to_string_lossy()));
                }
            }
        }
    }
    sortie.push_str("FIC_FIN\n");
    lus
}

/// Les services, lus dans le registre, au format de la section SVC : « SVC|nom|nom affiché||chemin », puis SVC_FIN.
/// Clé illisible : section vide (sans SVC_FIN), comme quand la requête WMI échouait.
#[cfg(windows)]
fn services_du_registre() -> String {
    use std::fmt::Write;
    let Ok(services) =
        winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey(crate::machine::windows::CLE_SERVICES)
    else {
        return String::new();
    };
    let mut lignes = String::from("\n");
    for nom in services.enum_keys().flatten() {
        let Ok(service) = services.open_subkey(&nom) else {
            continue;
        };
        let texte = |valeur: &str| service.get_value::<String, _>(valeur).unwrap_or_default();
        // Une barre verticale dans une valeur décalerait les champs de la ligne : remplacée.
        let propre = |v: String| v.replace(['|', '\n', '\r'], " ");
        let _ = writeln!(
            lignes,
            "SVC|{}|{}||{}",
            propre(nom.clone()),
            propre(texte("DisplayName")),
            propre(texte("ImagePath"))
        );
    }
    lignes.push_str("SVC_FIN\n");
    lignes
}

/// Le code produit MSI d'une ligne de désinstallation « MsiExec.exe /X{GUID} », pour une désinstallation silencieuse.
#[cfg(any(windows, test))]
fn guid_msi(chaine: &str) -> Option<&str> {
    if !chaine.to_lowercase().contains("msiexec") {
        return None;
    }
    let debut = chaine.find('{')?;
    let fin = chaine[debut..].find('}')? + debut;
    let guid = &chaine[debut..=fin];
    (guid.len() == 38 && guid[1..37].chars().all(|c| c.is_ascii_hexdigit() || c == '-')).then_some(guid)
}

/// La commande PowerShell qui désinstalle : la ligne silencieuse si l'installateur en donne une, msiexec sans
/// question pour un MSI, sinon le désinstalleur lui-même (sa fenêtre s'ouvre dans la session administrateur).
#[cfg(any(windows, test))]
fn retrait_windows(desinstallation: &str, silencieuse: &str) -> Vec<String> {
    use crate::commande::{decouper_commande, ps_chaine};
    let chaine = if silencieuse.trim().is_empty() {
        desinstallation
    } else {
        silencieuse
    };
    if chaine.trim().is_empty() {
        return Vec::new();
    }
    if let Some(guid) = guid_msi(chaine) {
        return vec![format!(
            "Start-Process -Wait -FilePath 'msiexec.exe' -ArgumentList '/x', '{guid}', '/qn', '/norestart'"
        )];
    }
    let (exe, args) = decouper_commande(chaine);
    if args.is_empty() {
        vec![format!("Start-Process -Wait -FilePath {}", ps_chaine(&exe))]
    } else {
        vec![format!(
            "Start-Process -Wait -FilePath {} -ArgumentList {}",
            ps_chaine(&exe),
            ps_chaine(&args)
        )]
    }
}

/// Les sections de la lecture PowerShell. `None` sans la section des programmes installés : rien n'est fiable.
#[cfg(any(windows, test))]
fn lire_windows(sortie: &str) -> Option<Vec<Trouvaille>> {
    use crate::commande::{ps_chaine, section};
    let date = |t: &str, format: &str| NaiveDate::parse_from_str(t.trim(), format).ok();
    let mut t = Vec::new();
    for l in section(Some(sortie), "INS")? {
        let champs: Vec<&str> = l.splitn(5, '|').collect();
        let [nom, installation, cle, desinstallation, silencieuse] = champs[..] else {
            continue;
        };
        let Some(i) = reconnu(nom) else {
            continue;
        };
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::Installe,
            ou: trf!("Programmes et fonctionnalités : {nom}", "Apps & features: {nom}"),
            depuis: date(installation, "%Y%m%d").or_else(|| date(cle, "%Y-%m-%d")),
            retrait: retrait_windows(desinstallation, silencieuse),
            arret: Vec::new(),
            refuse: false,
        });
    }
    let installes: Vec<usize> = t.iter().map(|x| x.logiciel).collect();
    for l in section(Some(sortie), "SVC").unwrap_or_default() {
        let champs: Vec<&str> = l.splitn(4, '|').collect();
        let [nom, affiche, _etat, chemin] = champs[..] else {
            continue;
        };
        let Some(i) = reconnu(nom).or_else(|| reconnu(affiche)).or_else(|| reconnu(chemin)) else {
            continue;
        };
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::Demarrage,
            ou: trf!("service {nom}", "service {nom}"),
            depuis: None,
            // Son désinstalleur retire le service ; sans désinstalleur, le service est retiré lui-même.
            retrait: if installes.contains(&i) {
                Vec::new()
            } else {
                vec![format!("sc.exe delete {}", ps_chaine(nom))]
            },
            arret: vec![format!(
                "Stop-Service -Name {} -Force -ErrorAction SilentlyContinue",
                ps_chaine(nom)
            )],
            refuse: false,
        });
    }
    let connectes: std::collections::BTreeSet<u32> = section(Some(sortie), "CNX")
        .unwrap_or_default()
        .iter()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
    for l in section(Some(sortie), "PRC").unwrap_or_default() {
        let champs: Vec<&str> = l.splitn(3, '|').collect();
        let [pid, nom, chemin] = champs[..] else {
            continue;
        };
        let fichier = chemin.rsplit(['\\', '/']).next().unwrap_or(chemin);
        let Some(i) = reconnu(nom).or_else(|| reconnu(fichier)) else {
            continue;
        };
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::EnCours {
                connecte: pid.trim().parse::<u32>().is_ok_and(|p| connectes.contains(&p)),
            },
            ou: affichable(if chemin.is_empty() { nom } else { chemin }),
            depuis: None,
            retrait: Vec::new(),
            arret: vec![format!(
                "Stop-Process -Name {} -Force -ErrorAction SilentlyContinue",
                ps_chaine(nom)
            )],
            refuse: false,
        });
    }
    for l in section(Some(sortie), "RUN").unwrap_or_default() {
        let champs: Vec<&str> = l.splitn(3, '|').collect();
        let [cle, nom, valeur] = champs[..] else {
            continue;
        };
        let Some(i) = reconnu(nom).or_else(|| reconnu(valeur)) else {
            continue;
        };
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::Demarrage,
            ou: trf!("clé Run : {nom}", "Run key: {nom}"),
            depuis: None,
            retrait: if installes.contains(&i) {
                Vec::new()
            } else {
                vec![format!(
                    "Remove-ItemProperty -Path {} -Name {} -ErrorAction SilentlyContinue",
                    ps_chaine(cle),
                    ps_chaine(nom)
                )]
            },
            arret: Vec::new(),
            refuse: false,
        });
    }
    for l in section(Some(sortie), "FIC").unwrap_or_default() {
        let Some((chemin, modifie)) = l.rsplit_once('|') else {
            continue;
        };
        let fichier = chemin.rsplit(['\\', '/']).next().unwrap_or(chemin);
        let Some(i) = reconnu(fichier) else {
            continue;
        };
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::Fichier,
            ou: affichable(chemin),
            depuis: date(modifie, "%Y-%m-%d"),
            retrait: vec![format!("Remove-Item -LiteralPath {} -Force", ps_chaine(chemin))],
            arret: Vec::new(),
            refuse: false,
        });
    }
    Some(t)
}

// ───────────────────────────── Parcours guidé ─────────────────────────────

fn dire(texte: &str) {
    for ligne in envelopper(texte, LARGEUR - 2) {
        println!("  {ligne}");
    }
}

/// « le 2026-10-03 (il y a 15 jours) ».
fn quand(d: NaiveDate, aujourd_hui: NaiveDate) -> String {
    match (aujourd_hui - d).num_days() {
        0 => tr!("aujourd'hui", "today").to_string(),
        1 => tr!("hier", "yesterday").to_string(),
        n if n > 1 => trf!("le {d} (il y a {n} jours)", "on {d} ({n} days ago)"),
        _ => trf!("le {d}", "on {d}"),
    }
}

fn decrire(t: &Trouvaille, aujourd_hui: NaiveDate) -> String {
    let date = t.depuis.map(|d| quand(d, aujourd_hui));
    match (t.trace, date) {
        (Trace::Installe, Some(q)) => trf!("installé {q} : {}", "installed {q}: {}", t.ou),
        (Trace::Installe, None) => trf!("installé : {}", "installed: {}", t.ou),
        (Trace::EnCours { connecte: true }, _) => trf!(
            "en cours d'exécution, avec une connexion ouverte en ce moment : {}",
            "running, with a connection open right now: {}",
            t.ou
        ),
        (Trace::EnCours { connecte: false }, _) => trf!("en cours d'exécution : {}", "running: {}", t.ou),
        (Trace::Demarrage, _) => trf!("lancé au démarrage : {}", "started at boot: {}", t.ou),
        (Trace::Fichier, Some(q)) => trf!("fichier déposé {q} : {}", "file dropped {q}: {}", t.ou),
        (Trace::Fichier, None) => trf!("fichier déposé : {}", "file dropped: {}", t.ou),
    }
}

/// Menu Antivirus et protection › Mon ordinateur est-il contrôlé ? : explique l'arnaque, cherche, conseille, puis retire
/// après accord ; un programme en cours demande un second accord exprès.
pub fn menu() {
    titre(tr!(
        "Mon ordinateur est-il contrôlé ?",
        "Is my computer being controlled?"
    ));
    dire(tr!(
        "L'arnaque au faux technicien : un appel (« votre ordinateur est infecté »), une fenêtre qui fait peur ou un courriel urgent, puis on vous fait installer un programme de prise de contrôle à distance (AnyDesk, TeamViewer, RustDesk…). La personne voit votre écran, bouge votre souris, et en profite pour voler des mots de passe ou faire payer une réparation inventée. Vanguard cherche ces programmes ici : installés, lancés au démarrage, en cours, ou simplement téléchargés.",
        "The tech-support scam: a call (“your computer is infected”), a scary pop-up or an urgent email, then you are made to install a remote control program (AnyDesk, TeamViewer, RustDesk…). The person sees your screen, moves your mouse, and takes the opportunity to steal passwords or charge for a made-up repair. Vanguard looks for these programs here: installed, started at boot, running, or simply downloaded."
    ));
    println!();
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let releve = relever_tout();
    let aujourd_hui = aujourd_hui();
    crate::modele::resultat::verser(&resultat::resultat(releve.as_ref(), aujourd_hui, debut));
    let Some(trouvailles) = pour_le_bilan(releve) else {
        trp!(
            "  ✖ Impossible de vérifier (PowerShell indisponible ou bloqué).",
            "  ✖ Could not check (PowerShell unavailable or blocked)."
        );
        return;
    };
    let visibles: Vec<&Trouvaille> = trouvailles
        .iter()
        // Un rang hors de la liste (jamais : il vient d'elle) reste visible plutôt que d'être tu.
        .filter(|t| LOGICIELS.get(t.logiciel).is_none_or(|l| !l.integre) || matches!(t.trace, Trace::EnCours { .. }))
        .collect();
    if visibles.is_empty() {
        afficher_aligne(
            &format!("  {VERT}✔{RESET} "),
            tr!(
                "Aucun logiciel de prise de contrôle à distance : ni installé, ni au démarrage, ni en cours, ni téléchargé.",
                "No remote control tool: neither installed, nor at boot, nor running, nor downloaded."
            ),
            4,
            "",
        );
        if cfg!(windows) {
            dire(tr!(
                "Assistance rapide fait partie de Windows : n'acceptez de l'ouvrir que si c'est vous qui avez appelé un soutien technique de confiance.",
                "Quick Assist is part of Windows: agree to open it only if you called trusted technical support yourself."
            ));
        }
        return;
    }
    let presents: Vec<(usize, &Logiciel)> = LOGICIELS
        .iter()
        .enumerate()
        .filter(|&(i, _)| visibles.iter().any(|t| t.logiciel == i))
        .collect();
    for &(i, logiciel) in &presents {
        println!("  {}⚠{RESET} {GRAS}{}{RESET}", couleur(Niveau::Eleve), logiciel.nom());
        for t in visibles.iter().filter(|t| t.logiciel == i) {
            afficher_aligne("      ", &decrire(t, aujourd_hui), 6, "");
        }
    }
    println!();
    dire(tr!(
        "Si vous n'avez pas installé ça vous-même, quelqu'un peut voir cet écran et commander cet ordinateur :",
        "If you did not install this yourself, someone may see this screen and operate this computer:"
    ));
    for conseil in [
        tr!(
            "1. Débranchez le câble réseau ou coupez le Wi-Fi.",
            "1. Unplug the network cable or turn Wi-Fi off."
        ),
        tr!(
            "2. Ne payez rien, ne rappelez pas, ne donnez aucun code.",
            "2. Pay nothing, do not call back, give no code."
        ),
        tr!(
            "3. Changez vos mots de passe importants (courriel, banque) depuis un autre appareil.",
            "3. Change your important passwords (email, bank) from another device."
        ),
        tr!(
            "4. Prévenez votre banque si vous avez payé ou donné un accès.",
            "4. Tell your bank if you paid or gave access."
        ),
        tr!(
            "5. Signalez l'arnaque : au Canada, le Centre antifraude du Canada (1-888-495-8501) ; ailleurs, la police ou l'autorité contre la fraude de votre pays.",
            "5. Report the scam: in Canada, the Canadian Anti-Fraud Centre (1-888-495-8501); elsewhere, the police or your country's anti-fraud authority."
        ),
    ] {
        afficher_aligne("    ", conseil, 7, "");
    }
    println!();
    dire(tr!(
        "Si c'est vous qui l'utilisez (pour aider quelqu'un, ou vous faire aider par une personne de confiance), gardez-le : répondez non.",
        "If you use it yourself (to help someone, or to be helped by someone you trust), keep it: answer no."
    ));
    if !demander(tr!(
        "\n  Retirer ces programmes ? [o/N] : ",
        "\n  Remove these programs? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a été retiré.", "  Nothing was removed.");
        return;
    }
    let mut correctifs: Vec<Vec<String>> = Vec::new();
    let mut noms: Vec<&str> = Vec::new();
    for &(i, logiciel) in &presents {
        let nom = logiciel.nom();
        let siens: Vec<&Trouvaille> = visibles.iter().copied().filter(|t| t.logiciel == i).collect();
        let en_cours = siens.iter().any(|t| matches!(t.trace, Trace::EnCours { .. }));
        if en_cours {
            // Le second accord : la personne qui aide peut être connectée par ce programme même.
            println!();
            dire(&trf!(
                "{nom} est en cours d'exécution : une session à distance est peut-être ouverte. Si vous êtes vous-même connecté à cet ordinateur par {nom}, répondez non.",
                "{nom} is running: a remote session may be open. If you are yourself connected to this computer through {nom}, answer no."
            ));
            if !demander(&trf!(
                "  Fermer {nom} et le retirer quand même ? [o/N] : ",
                "  Close {nom} and remove it anyway? [y/N]: "
            ))
            .oui()
            {
                trp!("  {nom} : gardé.", "  {nom}: kept.");
                continue;
            }
        }
        let commandes = lignes_du_retrait(&siens, en_cours);
        // Son retrait refusé : rien du tout, pas même ses autres commandes (le logiciel à moitié retiré, son service
        // encore en marche). Et les réglages du système le désinstalleraient en arrêtant ce qui tourne sans rien
        // demander : pas de conseil qui y mène.
        if let Some(raisons) = raisons_du_refus(&siens) {
            trp!(
                "  ℹ {nom} : Vanguard ne le retire pas : {raisons}. Les réglages du système l'arrêteraient sans rien demander.",
                "  ℹ {nom}: Vanguard does not remove it: {raisons}. The system settings would stop it without asking."
            );
            continue;
        }
        if commandes.is_empty() && en_cours && cfg!(target_os = "linux") {
            trp!(
                "  ℹ {nom} : Vanguard ne le retire pas tant qu'il tourne (la raison est dite au-dessus) ; les réglages du système l'arrêteraient sans rien demander.",
                "  ℹ {nom}: Vanguard does not remove it while it runs (the reason is given above); the system settings would stop it without asking."
            );
            continue;
        }
        if commandes.is_empty() {
            trp!(
                "  ℹ {nom} : à désinstaller depuis les réglages du système (applications installées).",
                "  ℹ {nom}: uninstall it from the system settings (installed apps)."
            );
            continue;
        }
        correctifs.push(commandes);
        noms.push(nom);
    }
    if correctifs.is_empty() {
        return;
    }
    println!();
    let reussites = retirer_les_programmes(&correctifs);
    for (nom, issue) in noms.iter().zip(reussites) {
        match issue {
            Ok(()) => trp!("  {VERT}✔{RESET} {nom} retiré.", "  {VERT}✔{RESET} {nom} removed."),
            Err(None) => trp!(
                "  ✖ {nom} : le retrait a échoué (voir au-dessus).",
                "  ✖ {nom}: removal failed (see above)."
            ),
            Err(Some(deja)) => trp!(
                "  ✖ {nom} : {deja}, mais la suite du retrait a échoué (voir au-dessus) : le programme n'est pas entièrement retiré.",
                "  ✖ {nom}: {deja}, but the rest of the removal failed (see above): the program is not fully removed."
            ),
        }
    }
    dire(tr!(
        "Ensuite : changez vos mots de passe importants depuis un autre appareil, et refaites un bilan complet (menu principal, 1).",
        "Next: change your important passwords from another device, and run a full check again (main menu, 1)."
    ));
}

/// `vanguard acces-a-distance --json` : le même relevé que le parcours (installés, au démarrage, en cours,
/// téléchargés), jugé en résultat et versé comme lui. Aucune question, rien n'est retiré ni proposé.
pub fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let r = resultat::resultat(relever_tout().as_ref(), aujourd_hui(), debut);
    crate::modele::resultat::verser(&r);
    println!("{}", crate::modele::resultat::json(&r));
}

/// COM-DIS-001 au corpus de détection : `fichier|nom`, posés vides dans un dossier jetable (un Téléchargements
/// fabriqué), relevés et jugés comme au bilan.
#[cfg(all(test, unix))]
pub(crate) fn corpus(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    let dossier = e.jetable("telechargements");
    for c in e.de("fichier") {
        let pose = c.first().map(|nom| std::fs::write(dossier.join(nom), b""));
        assert!(matches!(pose, Some(Ok(()))), "corpus : fichier {c:?} non posé");
    }
    let mut trouvailles = Vec::new();
    assert!(fichiers_poses(&mut trouvailles, &[dossier.to_path_buf()]));
    juger(&trouvailles, aujourd_hui())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sans aucun dossier nommé en chemin absolu (service, environnement vidé), rien n'est lu : la recherche des
    /// fichiers posés ne compte pas vérifiée.
    #[test]
    fn dossiers_des_fichiers_poses() {
        use std::path::PathBuf;
        let aucun = dossiers_nommes([None, Some(PathBuf::new()), Some(PathBuf::from("Downloads"))]);
        assert_eq!(aucun, Vec::<PathBuf>::new());
        let absolu = std::env::temp_dir();
        assert_eq!(dossiers_nommes([None, Some(absolu.clone())]), [absolu]);
    }

    /// Lot U3 : une unité du système devient le geste désigné de l'assistant (jamais une commande sudo) ; un nom
    /// qu'il ne désigne pas n'a rien de proposé, avec sa raison ; une unité de la session reste une commande, citée.
    #[cfg(target_os = "linux")]
    #[test]
    fn unites_du_systeme_par_le_geste() {
        assert_eq!(
            action_sur_unite("", false, ActionUnite::Arreter, "anydesk.service").as_deref(),
            Ok("vanguard:geste unite-designee arreter anydesk.service")
        );
        assert_eq!(
            action_sur_unite("", false, ActionUnite::DesactiverSansArreter, "teamviewerd.service").as_deref(),
            Ok("vanguard:geste unite-designee desactiver-sans-arreter teamviewerd.service")
        );
        // Une unité de la table, ou un nom hors de la règle : aucune commande sudo de repli, la raison seulement.
        for nom in ["ufw.service", "a b;rm.service"] {
            let r = action_sur_unite("", false, ActionUnite::Arreter, nom);
            let (fr, en) = r.expect_err(nom);
            for raison in [fr, en] {
                assert!(!raison.contains("sudo") && !raison.is_empty(), "{raison}");
            }
        }
        assert_eq!(
            action_sur_unite(
                "systemctl --user",
                true,
                ActionUnite::DesactiverSansArreter,
                "rustdesk.service"
            ),
            Ok(format!("systemctl --user disable {}", sh_chaine("rustdesk.service")))
        );
    }

    /// Les gestes faits, la suite en échec : dit ce qui a déjà changé (« son service est arrêté et ne démarrera
    /// plus »), jamais un simple « le retrait a échoué » qui laisserait croire que rien n'a bougé.
    #[cfg(not(windows))]
    #[test]
    fn retrait_a_moitie_dit_ce_qui_est_fait() {
        use crate::machine::IssueMelee;
        use crate::machine::gestes_unix::{ActionUnite, designee};
        let ligne = |a, n: &str| designee(a, n).unwrap().ligne();
        let un = [
            ligne(ActionUnite::Arreter, "anydesk.service"),
            ligne(ActionUnite::DesactiverSansArreter, "anydesk.service"),
            "sudo apt-get remove -y anydesk".to_string(),
        ];
        let en_partie = |n: usize| IssueMelee::EnPartie {
            faites: un[..n].to_vec(),
            pas_faites: un[n..].to_vec(),
        };
        assert_eq!(issue_du_retrait(IssueMelee::Fait), Ok(()));
        assert_eq!(issue_du_retrait(IssueMelee::Echec), Err(None));
        let deja = issue_du_retrait(en_partie(2)).unwrap_err().unwrap();
        assert!(
            deja == "son service est arrêté et ne démarrera plus"
                || deja == "its service is stopped and will not start again",
            "{deja}"
        );
        // Arrêté, mais pas retiré du démarrage : dit tel quel, jamais « le retrait a échoué ».
        let deja = issue_du_retrait(en_partie(1)).unwrap_err().unwrap();
        assert!(
            deja == "son service est arrêté" || deja == "its service is stopped",
            "{deja}"
        );
        // Sans geste fait : combien d'étapes, jamais « ses services sont déjà changés ».
        let commandes = IssueMelee::EnPartie {
            faites: vec!["sudo pkill -x anydesk".to_string()],
            pas_faites: vec!["sudo apt-get remove -y anydesk".to_string()],
        };
        let deja = issue_du_retrait(commandes).unwrap_err().unwrap();
        assert!(
            deja == "1 étape(s) sur 2 faite(s)" || deja == "1 step(s) out of 2 done",
            "{deja}"
        );
        let arret_seul = [ligne(ActionUnite::Arreter, "anydesk.service")];
        let arret = deja_fait(&arret_seul).unwrap();
        assert!(arret.contains("arrêté") || arret.contains("stopped"));
        assert!(!arret.contains("plus") && !arret.contains("again"));
        let deux = [
            ligne(ActionUnite::DesactiverSansArreter, "anydesk.service"),
            ligne(ActionUnite::DesactiverSansArreter, "rustdesk.service"),
        ];
        let deux = deja_fait(&deux).unwrap();
        assert!(deux.starts_with("ses ") || deux.starts_with("its services"));
    }

    fn indice(nom: &str) -> usize {
        LOGICIELS
            .iter()
            .position(|l| l.nom[0] == nom)
            .expect("logiciel du catalogue")
    }

    #[test]
    fn reconnu_au_debut_d_un_mot_seulement() {
        assert_eq!(reconnu("AnyDesk.exe"), Some(indice("AnyDesk")));
        assert_eq!(reconnu("com.rustdesk.RustDesk"), Some(indice("RustDesk")));
        assert_eq!(
            reconnu("MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe"),
            Some(indice("Assistance rapide"))
        );
        assert_eq!(reconnu("Action1 Agent"), Some(indice("Action1")));
        assert_eq!(reconnu("AteraAgent"), Some(indice("Atera")));
        assert_eq!(reconnu("été anydesk"), Some(indice("AnyDesk")));
        // « atera » dans « lateral », « action1 » dans « transaction1 » : pas au début d'un mot.
        assert_eq!(reconnu("lateral thinking"), None);
        assert_eq!(reconnu("transaction1.log"), None);
        assert_eq!(reconnu("Microsoft Edge"), None);
        assert_eq!(reconnu("vanguard"), None);
    }

    /// xrdp se désigne : ses deux unités, son paquet, et la session de logind qu'il ouvre (Service=xrdp-sesman) se
    /// reconnaissent comme lui ; xorgxrdp (le module de Xorg) n'est pas lui.
    #[test]
    fn xrdp_est_au_catalogue() {
        let xrdp = indice("xrdp");
        for nom in ["xrdp", "xrdp.service", "xrdp-sesman.service", "xrdp-sesman"] {
            assert_eq!(reconnu(nom), Some(xrdp), "{nom}");
        }
        assert_eq!(reconnu("xorgxrdp"), None);
        #[cfg(unix)]
        assert!(meme_logiciel("xrdp-sesman", "xrdp.service"));
        // Ses deux unités se désignent ; hors de Linux, il n'y a pas d'unités à désigner.
        #[cfg(target_os = "linux")]
        for unite in ["xrdp.service", "xrdp-sesman.service"] {
            for a in [ActionUnite::Arreter, ActionUnite::DesactiverSansArreter] {
                assert!(
                    crate::machine::gestes_unix::designee_ou_refus(a, unite).is_ok(),
                    "{unite}"
                );
            }
        }
    }

    /// Le retrait d'un paquet dont un service tourne (lu par systemd, même sans être lancé
    /// au démarrage, même caché de /proc) passe d'abord par le geste d'arrêt de l'assistant, avec sa question ; un
    /// service que l'assistant ne désigne pas, ou des services qui ne se lisent pas : rien n'est proposé, et c'est dit.
    #[cfg(target_os = "linux")]
    #[test]
    fn le_retrait_d_un_paquet_passe_par_l_arret_de_ses_services() {
        let s = ToString::to_string;
        let arreter = |u: &str| {
            crate::machine::gestes_unix::designee(ActionUnite::Arreter, u)
                .unwrap()
                .ligne()
        };
        let apt = s("sudo apt-get remove -y xrdp");
        let en_marche = [s("cups.service"), s("xrdp.service"), s("xrdp-sesman.service")];
        let xrdp = indice("xrdp");
        assert_eq!(
            retrait_garde(xrdp, apt.clone(), Some(&en_marche)),
            Ok(vec![
                arreter("xrdp.service"),
                arreter("xrdp-sesman.service"),
                apt.clone()
            ])
        );
        // Rien en marche à son nom, ou pas de systemd : la commande seule.
        assert_eq!(
            retrait_garde(indice("AnyDesk"), s("x"), Some(&en_marche)),
            Ok(vec![s("x")])
        );
        assert_eq!(retrait_garde(xrdp, apt.clone(), Some(&[])), Ok(vec![apt.clone()]));
        assert!(retrait_garde(xrdp, apt.clone(), None).is_err());
        let refuse = [s("xrdp agent.service")];
        let raison = retrait_garde(xrdp, apt.clone(), Some(&refuse)).unwrap_err().to_string();
        assert!(raison.contains("xrdp agent.service"), "{raison}");
        // Une instance d'un modèle : refusée par sa vraie raison, pas par un geste que l'assistant refuserait.
        let instance = [s("xrdp@vnc_1.service")];
        let raison = retrait_garde(xrdp, apt.clone(), Some(&instance))
            .unwrap_err()
            .to_string();
        assert!(raison.contains("modèle") || raison.contains("template"), "{raison}");
        // Un point de montage (celui de tout snap), une tranche : pas des services, ils ne gardent rien.
        let montages = [s("snap-xrdp-12.mount"), s("xrdp.slice"), s("xrdp.scope")];
        assert_eq!(retrait_garde(xrdp, apt.clone(), Some(&montages)), Ok(vec![apt.clone()]));
        let mut t = Vec::new();
        assert!(services_en_marche(&mut t, Some(&montages)));
        assert_eq!(t, []);
        let (ou, retrait) = ou_et_retrait(xrdp, s("paquet xrdp"), apt.clone(), None);
        assert!(retrait.is_empty() && ou.starts_with("paquet xrdp ("), "{ou}");

        // Les services en marche deviennent « en cours », leur arrêt étant le geste de l'assistant.
        let mut t = Vec::new();
        assert!(services_en_marche(&mut t, Some(&en_marche)));
        assert_eq!(t.len(), 2);
        assert!(
            t.iter()
                .all(|x| x.logiciel == xrdp && x.trace == Trace::EnCours { connecte: false })
        );
        assert_eq!(t[0].arret, [arreter("xrdp.service")]);
        let mut t = Vec::new();
        assert!(services_en_marche(&mut t, Some(&refuse)));
        assert!(t[0].arret.is_empty() && t[0].ou.contains("xrdp agent.service"), "{t:?}");
        let mut t = Vec::new();
        assert!(!services_en_marche(&mut t, None));
        assert_eq!(t, []);
    }

    /// L'ordre du retrait : le retrait du démarrage d'abord (fait même si l'arrêt est refusé), puis l'arrêt accepté,
    /// puis les arrêts qui gardent la désinstallation (gardés une fois), puis les commandes, dans leur ordre.
    #[cfg(target_os = "linux")]
    #[test]
    fn le_retrait_du_demarrage_passe_avant_l_arret() {
        use crate::machine::gestes_unix::designee;
        let arreter = designee(ActionUnite::Arreter, "xrdp.service").unwrap().ligne();
        let sesman = designee(ActionUnite::Arreter, "xrdp-sesman.service").unwrap().ligne();
        let retirer = designee(ActionUnite::DesactiverSansArreter, "xrdp.service")
            .unwrap()
            .ligne();
        let apt = "sudo apt-get remove -y xrdp".to_string();
        let mut paquet = trouvaille("xrdp", Trace::Installe, None, &[]);
        paquet.retrait = vec![arreter.clone(), sesman.clone(), apt.clone()];
        paquet.arret = Vec::new();
        let mut demarrage = trouvaille("xrdp", Trace::Demarrage, None, &[]);
        demarrage.retrait = vec![retirer.clone()];
        demarrage.arret = vec![arreter.clone()];
        let mut service = trouvaille("xrdp", Trace::EnCours { connecte: false }, None, &[]);
        service.arret = vec![arreter.clone()];
        let mut processus = trouvaille("xrdp", Trace::EnCours { connecte: true }, None, &[]);
        processus.arret = vec!["pkill -x xrdp || true".to_string()];
        let siens = [&paquet, &demarrage, &service, &processus];
        assert_eq!(
            lignes_du_retrait(&siens, true),
            [
                retirer.clone(),
                arreter.clone(),
                "pkill -x xrdp || true".to_string(),
                sesman.clone(),
                apt.clone()
            ]
        );
        assert_eq!(
            lignes_du_retrait(&siens, false),
            [retirer.clone(), arreter.clone(), sesman.clone(), apt.clone()]
        );
        // Arrêté au relevé, il a pu repartir : son arrêt garde la désinstallation même quand le paquet ne le portait
        // pas, et seulement s'il y a une commande à garder.
        paquet.retrait = vec![apt.clone()];
        let siens = [&paquet, &demarrage];
        assert_eq!(
            lignes_du_retrait(&siens, false),
            [retirer.clone(), arreter.clone(), apt]
        );
        assert_eq!(lignes_du_retrait(&[&demarrage], false), [retirer]);
    }

    fn trouvaille(nom: &str, trace: Trace, depuis: Option<NaiveDate>, retrait: &[&str]) -> Trouvaille {
        Trouvaille {
            logiciel: indice(nom),
            trace,
            ou: format!("ici {nom}"),
            depuis,
            retrait: retrait.iter().map(ToString::to_string).collect(),
            arret: vec!["stop".to_string()],
            refuse: false,
        }
    }

    fn jour(texte: &str) -> NaiveDate {
        NaiveDate::parse_from_str(texte, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn rien_trouve_est_dit_sain_et_un_integre_seulement_installe_ne_compte_pas() {
        let aujourd_hui = jour("2026-10-18");
        let rien = juger(&[], aujourd_hui);
        assert_eq!(rien.len(), 1);
        assert!(rien[0].probleme.is_none() && rien[0].verifie, "{}", rien[0].message);
        let quick = [trouvaille("Assistance rapide", Trace::Installe, None, &[])];
        assert!(juger(&quick, aujourd_hui)[0].probleme.is_none());
        // Ouvert, il compte : quelqu'un est peut-être à l'autre bout.
        let ouvert = [trouvaille(
            "Assistance rapide",
            Trace::EnCours { connecte: true },
            None,
            &[],
        )];
        let c = &juger(&ouvert, aujourd_hui)[0];
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("Assistance rapide"), "{}", c.message);
    }

    #[test]
    fn recent_eleve_et_retire_ancien_moyen_en_cours_jamais_retire_par_le_bilan() {
        let aujourd_hui = jour("2026-10-18");
        let recent = [trouvaille(
            "AnyDesk",
            Trace::Installe,
            Some(jour("2026-10-03")),
            &["sudo pacman -Rns --noconfirm 'anydesk'"],
        )];
        let c = &juger(&recent, aujourd_hui)[0];
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        let k = c.correctif.as_ref().unwrap();
        assert!(k.automatique && k.commandes == ["sudo pacman -Rns --noconfirm 'anydesk'"]);
        assert!(c.message.contains("moins d'un mois"), "{}", c.message);
        // Pas de date dans le message : « déclarer normal » doit le reconnaître demain aussi.
        assert!(!c.message.contains("2026"), "{}", c.message);

        let ancien = [trouvaille(
            "TeamViewer",
            Trace::Installe,
            Some(jour("2024-01-01")),
            &["x"],
        )];
        assert_eq!(juger(&ancien, aujourd_hui)[0].probleme, Some(Niveau::Moyen));

        let en_cours = [
            trouvaille("RustDesk", Trace::Installe, Some(jour("2024-01-01")), &["x"]),
            trouvaille("RustDesk", Trace::EnCours { connecte: false }, None, &[]),
        ];
        let c = &juger(&en_cours, aujourd_hui)[0];
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        let k = c.correctif.as_ref().unwrap();
        assert!(!k.automatique && k.commandes.is_empty(), "{}", k.action);
        assert!(c.message.contains("en cours d'exécution"), "{}", c.message);

        // Son retrait refusé (un service qui tourne sans geste admis) : manuel, et pas de conseil de passer par les
        // réglages du système, qui l'arrêteraient de la même façon.
        let mut refuse = trouvaille("xrdp", Trace::Installe, None, &[]);
        refuse.refuse = true;
        refuse.ou = "paquet xrdp (Vanguard ne le retire pas : son service tourne)".into();
        // Même avec une autre commande (un dossier à effacer) : rien n'est retiré à moitié.
        let autre = trouvaille("xrdp", Trace::Installe, None, &["sudo rm -rf '/opt/xrdp'"]);
        let c = &juger(&[refuse.clone(), autre], aujourd_hui)[0];
        let k = c.correctif.as_ref().unwrap();
        assert!(!k.automatique && k.commandes.is_empty(), "{}", k.action);
        assert!(
            k.action.contains("Ne le désinstallez pas") && k.action.contains("son service tourne"),
            "{}",
            k.action
        );
        refuse.refuse = false;
        let k = juger(&[refuse], aujourd_hui)[0].correctif.clone().unwrap();
        assert!(k.action.contains("applications installées"), "{}", k.action);

        // Un fichier posé dans Téléchargements, même sans date : le scénario du faux technicien.
        let pose = [trouvaille("Supremo", Trace::Fichier, None, &["rm -f 'x'"])];
        assert_eq!(juger(&pose, aujourd_hui)[0].probleme, Some(Niveau::Eleve));

        // Deux logiciels : deux constats, dans l'ordre du catalogue.
        let deux = [
            trouvaille("TeamViewer", Trace::Installe, None, &["b"]),
            trouvaille("AnyDesk", Trace::Demarrage, None, &["a"]),
        ];
        let noms: Vec<String> = juger(&deux, aujourd_hui)
            .iter()
            .map(|c| c.message.split(' ').next().unwrap().to_string())
            .collect();
        assert_eq!(noms, ["AnyDesk", "TeamViewer"]);
    }

    #[test]
    fn lecture_windows_et_commandes_sans_injection() {
        let sortie = "INS|AnyDesk|20261003||\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --remove|\n\
                      INS|TeamViewer|||MsiExec.exe /X{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}|\n\
                      INS|L’outil Supremo||2026-10-10|\"C:\\Users\\alice\\L’outil\\unins000.exe\"|\"C:\\Users\\alice\\L’outil\\unins000.exe\" /SILENT\n\
                      INS|Microsoft Edge|20250101||MsiExec.exe /X{1}|\n\
                      INS_FIN\n\
                      SVC|AnyDesk|AnyDesk Service|Running|\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --service\n\
                      SVC|ScreenConnect Client (abc)|ScreenConnect Client|Running|\"C:\\Program Files (x86)\\ScreenConnect Client (abc)\\ScreenConnect.ClientService.exe\"\n\
                      SVC|Spooler|Print Spooler|Running|C:\\Windows\\System32\\spoolsv.exe\n\
                      SVC_FIN\n\
                      PRC|1234|AnyDesk|C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\n\
                      PRC|777|QuickAssist|\n\
                      PRC|42|explorer|C:\\Windows\\explorer.exe\n\
                      PRC_FIN\n\
                      CNX|1234\n\
                      CNX_FIN\n\
                      RUN|HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|UltraViewer|\"C:\\Users\\alice\\AppData\\Local\\UltraViewer\\UltraViewer.exe\" /tray\n\
                      RUN_FIN\n\
                      FIC|C:\\Users\\alice\\Downloads\\AnyDesk.exe|2026-10-15\n\
                      FIC|C:\\Users\\alice\\Downloads\\rapport.exe|2026-10-15\n\
                      FIC_FIN\n";
        let t = lire_windows(sortie).expect("section des programmes présente");
        let de = |nom: &str, trace: Trace| {
            t.iter()
                .find(|x| x.logiciel == indice(nom) && x.trace == trace)
                .unwrap_or_else(|| panic!("{nom} {trace:?} absent : {t:#?}"))
        };
        let anydesk = de("AnyDesk", Trace::Installe);
        assert_eq!(anydesk.depuis, Some(jour("2026-10-03")));
        assert_eq!(
            anydesk.retrait,
            ["Start-Process -Wait -FilePath 'C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe' -ArgumentList '--remove'"]
        );
        assert_eq!(
            de("TeamViewer", Trace::Installe).retrait,
            [
                "Start-Process -Wait -FilePath 'msiexec.exe' -ArgumentList '/x', '{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}', '/qn', '/norestart'"
            ]
        );
        // La ligne silencieuse d'abord ; les apostrophes typographiques du nom sont doublées, jamais une fin de chaîne.
        let supremo = de("Supremo", Trace::Installe);
        assert_eq!(supremo.depuis, Some(jour("2026-10-10")));
        assert_eq!(
            supremo.retrait,
            ["Start-Process -Wait -FilePath 'C:\\Users\\alice\\L’’outil\\unins000.exe' -ArgumentList '/SILENT'"]
        );
        // Le service d'un programme installé part avec son désinstalleur ; celui sans désinstalleur est retiré lui-même.
        assert_eq!(de("AnyDesk", Trace::Demarrage).retrait, Vec::<String>::new());
        assert_eq!(
            de("ScreenConnect (ConnectWise)", Trace::Demarrage).retrait,
            ["sc.exe delete 'ScreenConnect Client (abc)'"]
        );
        assert_eq!(
            de("AnyDesk", Trace::EnCours { connecte: true }).arret,
            ["Stop-Process -Name 'AnyDesk' -Force -ErrorAction SilentlyContinue"]
        );
        assert!(
            t.iter()
                .any(|x| x.logiciel == indice("Assistance rapide") && x.trace == Trace::EnCours { connecte: false })
        );
        assert_eq!(
            de("UltraViewer", Trace::Demarrage).retrait,
            [
                "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'UltraViewer' -ErrorAction SilentlyContinue"
            ]
        );
        let pose = de("AnyDesk", Trace::Fichier);
        assert_eq!(pose.depuis, Some(jour("2026-10-15")));
        assert_eq!(
            pose.retrait,
            ["Remove-Item -LiteralPath 'C:\\Users\\alice\\Downloads\\AnyDesk.exe' -Force"]
        );
        // Edge, le spouleur, l'explorateur et rapport.exe : rien à voir.
        assert_eq!(t.len(), 9, "{t:#?}");

        // Sans la section des programmes installés (PowerShell tombé avant), rien n'est conclu.
        assert!(lire_windows("PRC|1|x|\nPRC_FIN\n").is_none());
        // Et le jugement : AnyDesk en cours → jamais retiré par le bilan ; Assistance rapide ouvert → signalé.
        let constats = juger(&t, jour("2026-10-18"));
        let anydesk = constats.iter().find(|c| c.message.starts_with("AnyDesk")).unwrap();
        assert_eq!(anydesk.probleme, Some(Niveau::Eleve));
        assert!(!anydesk.correctif.as_ref().unwrap().automatique);
        assert!(anydesk.message.contains("connexion ouverte"), "{}", anydesk.message);
        assert!(constats.iter().any(|c| c.message.starts_with("Assistance rapide")));
    }

    #[test]
    fn guid_msi_reconnu() {
        assert_eq!(
            guid_msi("MsiExec.exe /X{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}"),
            Some("{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}")
        );
        assert_eq!(guid_msi("MsiExec.exe /I{court}"), None);
        assert_eq!(
            guid_msi("\"C:\\x\\u.exe\" {0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}"),
            None
        );
        assert_eq!(retrait_windows("", ""), Vec::<String>::new());
        assert_eq!(
            retrait_windows("C:\\x\\u.exe", ""),
            ["Start-Process -Wait -FilePath 'C:\\x\\u.exe'"]
        );
    }

    #[cfg(target_os = "linux")]
    fn jetable(nom: &str) -> PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-distance-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Un nom d'instance écrit par morceaux : entier, il a la forme d'un courriel, que la vérification de
    /// confidentialité refuserait.
    #[cfg(target_os = "linux")]
    fn instance(modele: &str, nom: &str, suffixe: &str) -> String {
        format!("{modele}@{nom}.{suffixe}")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unites_activees_lues_dans_les_liens() {
        use std::os::unix::fs::symlink;
        let d = jetable("unites");
        let (usr, etc, run) = (d.join("usr"), d.join("etc"), d.join("run"));
        for s in [
            &usr,
            &etc.join("multi-user.target.wants"),
            &etc.join("getty.target.wants"),
            &run,
        ] {
            std::fs::create_dir_all(s).unwrap();
        }
        let modele = instance("console", "", "service");
        std::fs::write(
            usr.join(&modele),
            "[Install]\nDefaultInstance=tty1\nWantedBy=getty.target\n",
        )
        .unwrap();
        for u in ["anydesk.service", "sddm.service", "vieux.service", "cache.service"] {
            std::fs::write(usr.join(u), "[Unit]\n").unwrap();
            symlink(usr.join(u), etc.join("multi-user.target.wants").join(u)).unwrap();
        }
        // Alias : le gestionnaire de connexion compte pour activé.
        symlink(usr.join("sddm.service"), etc.join("display-manager.service")).unwrap();
        // L'instance par défaut range le modèle ; une autre garde son nom.
        symlink(
            usr.join(&modele),
            etc.join("getty.target.wants")
                .join(instance("console", "tty1", "service")),
        )
        .unwrap();
        symlink(
            usr.join(&modele),
            etc.join("getty.target.wants")
                .join(instance("console", "tty5", "service")),
        )
        .unwrap();
        // Masquées dans /etc ou jusqu'au redémarrage : plus lancées.
        symlink("/dev/null", etc.join("vieux.service")).unwrap();
        symlink("/dev/null", run.join("cache.service")).unwrap();
        // Lien d'une unité posée ailleurs (systemctl link) : « linked », pas activée.
        symlink(usr.join("anydesk.service"), etc.join("anydesk.service")).unwrap();
        // Le lien resté après le retrait de son unité (apport.service sur Ubuntu 24.04) : rien ne démarre, systemctl
        // ne la liste pas.
        symlink(
            usr.join("apport.service"),
            etc.join("multi-user.target.wants").join("apport.service"),
        )
        .unwrap();
        let l = unites_activees_dans(
            &[etc.clone(), d.join("absent")],
            &[etc.clone(), run.clone()],
            &[etc.clone(), usr.clone()],
        )
        .unwrap();
        assert_eq!(
            l,
            [
                "anydesk.service".to_string(),
                modele.clone(),
                instance("console", "tty5", "service"),
                "sddm.service".to_string()
            ]
        );
        let _ = std::fs::remove_dir_all(d);
    }

    /// Un lien d'activation posé par le compte vers /dev/zero ou un tube nommé : le nom reste celui du lien,
    /// sans lecture sans fin (mémoire remplie) ni blocage.
    #[cfg(target_os = "linux")]
    #[test]
    fn lien_d_activation_vers_un_fichier_special() {
        use std::os::unix::fs::symlink;
        let d = jetable("special");
        let wants = d.join("default.target.wants");
        std::fs::create_dir_all(&wants).unwrap();
        crate::essais::tube_nomme(&d.join("tube")).unwrap();
        let (zero, fifo) = (instance("x", "y", "service"), instance("x", "z", "service"));
        symlink("/dev/zero", wants.join(&zero)).unwrap();
        symlink(d.join("tube"), wants.join(&fifo)).unwrap();
        let depart = std::time::Instant::now();
        assert_eq!(nom_active(&zero, &wants.join(&zero)), zero);
        assert_eq!(nom_active(&fifo, &wants.join(&fifo)), fifo);
        assert!(depart.elapsed() < std::time::Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(d);
    }

    /// Sans le programme snap, les fichiers restés dans /var/lib/snapd ne donnent aucun snap.
    #[cfg(target_os = "linux")]
    #[test]
    fn sans_snap_aucun_snap() {
        use crate::machine::linux::natif::Snap;
        let restes = || {
            Some(vec![Snap {
                nom: "anydesk".into(),
                courante: None,
                revisions: vec!["12".into()],
            }])
        };
        assert_eq!(liste_snaps(false, restes), None);
        assert_eq!(liste_snaps(true, restes), Some(vec!["anydesk".to_string()]));
    }

    /// Sur cet ordinateur, chaque unité que systemctl dit activée se retrouve dans les liens lus ; en plus, seules
    /// des instances qui ne sont pas celle par défaut de leur modèle (systemctl les dit « indirect »).
    #[cfg(target_os = "linux")]
    #[test]
    fn unites_comme_systemctl() {
        let maison = crate::socle::maison();
        for (args, utilisateur) in [
            (
                &["list-unit-files", "--state=enabled", "--no-legend", "--plain"][..],
                false,
            ),
            (
                &["--user", "list-unit-files", "--state=enabled", "--no-legend", "--plain"][..],
                true,
            ),
        ] {
            let Some(sortie) = sortie_de("systemctl", args, 30) else {
                continue;
            };
            let Some(lues) = unites_activees(&maison, utilisateur) else {
                continue;
            };
            let dites: Vec<&str> = sortie.lines().filter_map(|l| l.split_whitespace().next()).collect();
            for u in &dites {
                assert!(lues.iter().any(|l| l == u), "{u} : {lues:?}");
            }
            for l in &lues {
                let instance = l.split_once('@').is_some_and(|(_, r)| !r.starts_with('.'));
                assert!(instance || dites.contains(&l.as_str()), "{l} : {dites:?}");
            }
        }
    }

    /// Sur cet ordinateur, /proc donne les processus connectés que ss montre, quand il est là. Les connexions
    /// s'ouvrent et se ferment pendant le test : trois essais.
    #[cfg(target_os = "linux")]
    #[test]
    fn connectes_comme_ss() {
        for _ in 0..3 {
            let avant = crate::protection::sortantes::processus_connectes();
            let Some(ss) = sortie_de("ss", &["-tnpH", "state", "established"], 15) else {
                return crate::essais::saute("ss absent");
            };
            let apres = crate::protection::sortantes::processus_connectes();
            let (Some(avant), Some(apres)) = (avant, apres) else {
                return crate::essais::saute("processus connectés illisibles");
            };
            if pids_dans_ss(&ss).iter().all(|p| avant.contains(p) || apres.contains(p)) {
                return;
            }
        }
        panic!("ss montre des processus connectés que /proc ne donne pas");
    }

    #[test]
    fn pids_connectes_dans_ss_sans_les_connexions_locales() {
        let sortie = "0 0 192.168.1.5:51234 1.2.3.4:443 users:((\"anydesk\",pid=1234,fd=12))\n\
                      0 0 127.0.0.1:6000 127.0.0.1:51000 users:((\"x11vnc\",pid=99,fd=3))\n\
                      0 0 [::1]:5900 [::1]:51001 users:((\"vino\",pid=98,fd=3))\n\
                      0 0 10.0.0.2:40000 10.0.0.9:5938 users:((\"TeamViewer\",pid=55,fd=4),(\"TeamViewer\",pid=56,fd=4))\n";
        let pids: Vec<u32> = pids_dans_ss(sortie).into_iter().collect();
        assert_eq!(pids, [55, 56, 1234]);
    }

    #[test]
    fn description_datee_et_doublons_retires() {
        let aujourd_hui = jour("2026-10-18");
        assert_eq!(quand(jour("2026-10-18"), aujourd_hui), "aujourd'hui");
        assert_eq!(quand(jour("2026-10-17"), aujourd_hui), "hier");
        assert_eq!(
            quand(jour("2026-10-03"), aujourd_hui),
            "le 2026-10-03 (il y a 15 jours)"
        );
        assert_eq!(quand(jour("2026-11-03"), aujourd_hui), "le 2026-11-03");
        let t = trouvaille("AnyDesk", Trace::Fichier, Some(jour("2026-10-15")), &[]);
        assert_eq!(
            decrire(&t, aujourd_hui),
            "fichier déposé le 2026-10-15 (il y a 3 jours) : ici AnyDesk"
        );
        let deux = sans_doublons(vec![
            t.clone(),
            t.clone(),
            trouvaille("AnyDesk", Trace::Installe, None, &[]),
        ]);
        assert_eq!(deux.len(), 2);
        assert_eq!(
            sans_repetition(["a".to_string(), "b".to_string(), "a".to_string()]),
            ["a", "b"]
        );
    }

    /// T4 : le logiciel par son nom français, la même clé dans les deux langues.
    #[test]
    fn cles_sans_langue() {
        let t = [
            trouvaille("AnyDesk", Trace::Installe, Some(jour("2026-10-03")), &["x"]),
            trouvaille("Assistance rapide", Trace::EnCours { connecte: true }, None, &[]),
        ];
        let cles = crate::machine::controler_regle("COM-DIS-001", || juger(&t, jour("2026-10-18")));
        assert_eq!(
            cles,
            ["COM-DIS-001|logiciel:AnyDesk", "COM-DIS-001|logiciel:Assistance rapide"]
        );
    }
}
