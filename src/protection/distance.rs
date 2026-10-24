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
use crate::machine::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::*;

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
        let retrait = sans_repetition(siens.iter().flat_map(|t| t.retrait.iter().cloned()));
        constats.push(if en_cours {
            constat.manuel(
                tr!(
                    "Vanguard ne coupe pas une connexion à distance en cours. Si vous n'avez rien demandé : débranchez Internet (câble, Wi-Fi), puis menu « Arnaques et vie privée » › « Mon ordinateur est-il contrôlé ? » pour le fermer et le retirer",
                    "Vanguard does not cut a remote connection in progress. If you did not ask for anything: unplug the Internet (cable, Wi-Fi), then menu “Scams and privacy” › “Is my computer being controlled?” to close and remove it"
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
#[cfg(unix)]
fn fichiers_poses(t: &mut Vec<Trouvaille>, dossiers: &[PathBuf]) {
    for d in dossiers {
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
            });
        }
    }
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

// Même signature que sous Windows, où la lecture PowerShell peut échouer.
#[allow(clippy::unnecessary_wraps)]
#[cfg(target_os = "linux")]
fn relever() -> Option<Vec<Trouvaille>> {
    let maison = crate::socle::maison();
    let mut t = Vec::new();
    paquets(&mut t);
    flatpaks(&mut t, &maison);
    snaps(&mut t);
    dossiers_opt(&mut t);
    let processus_lus = processus(&mut t);
    demarrage_linux(&mut t, &maison);
    let declares = std::fs::read_to_string(maison.join(".config/user-dirs.dirs")).unwrap_or_default();
    let declare = |cle: &str, defaut: &str| {
        crate::protection::pieges::dossier_declare(&declares, cle, &maison).unwrap_or_else(|| maison.join(defaut))
    };
    fichiers_poses(
        &mut t,
        &[
            declare("XDG_DOWNLOAD_DIR", "Downloads"),
            declare("XDG_DESKTOP_DIR", "Desktop"),
            PathBuf::from("/tmp"),
        ],
    );
    // Sans les processus, « rien trouvé » ne se conclut pas : non vérifié ; ce qui a été trouvé reste dit.
    (processus_lus || !t.is_empty()).then(|| sans_doublons(t))
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
#[cfg(target_os = "linux")]
fn paquets(t: &mut Vec<Trouvaille>) {
    use crate::machine::linux::Paquets;
    let Some(gestionnaire) = Paquets::detecter() else {
        return;
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
        return;
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
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::Installe,
            ou: trf!("paquet {p}", "package {p}"),
            depuis,
            retrait: vec![gestionnaire.retirer(&sh_chaine(p))],
            arret: Vec::new(),
        });
    }
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
        });
    }
}

#[cfg(target_os = "linux")]
fn snaps(t: &mut Vec<Trouvaille>) {
    // Les fichiers de snapd disent les snaps installés ; `snap list` en secours, quand ils ne se lisent pas.
    let natif = crate::machine::linux::natif::snaps;
    let Some(liste) = liste_snaps(crate::machine::linux::natif::present("snap"), natif) else {
        return;
    };
    for nom in liste.iter().map(String::as_str) {
        let Some(i) = reconnu(nom) else {
            continue;
        };
        t.push(Trouvaille {
            logiciel: i,
            trace: Trace::Installe,
            ou: format!("Snap {nom}"),
            depuis: None,
            retrait: vec![format!("sudo snap remove {}", sh_chaine(nom))],
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
        });
    }
    true
}

/// Lancements automatiques : fichiers .desktop d'autostart (nom ou ligne Exec), services systemd activés (système et
/// session).
#[cfg(target_os = "linux")]
fn demarrage_linux(t: &mut Vec<Trouvaille>, maison: &std::path::Path) {
    for (dossier, sudo) in [
        (maison.join(".config/autostart"), ""),
        (PathBuf::from("/etc/xdg/autostart"), "sudo "),
    ] {
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
            });
        }
    }
    for (args, prefixe, utilisateur) in [
        (
            &["list-unit-files", "--state=enabled", "--no-legend", "--plain"][..],
            "sudo systemctl",
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
            t.push(Trouvaille {
                logiciel: i,
                trace: Trace::Demarrage,
                ou: trf!("service {unite}", "service {unite}"),
                depuis: None,
                retrait: vec![format!("{prefixe} disable {}", sh_chaine(unite))],
                arret: vec![format!("{prefixe} stop {}", sh_chaine(unite))],
            });
        }
    }
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
        // SAFETY : getuid ne peut pas échouer et ne touche à aucune mémoire du programme.
        let uid = unsafe { libc::getuid() };
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
/// suivi du suffixe de l'unité) compte pour le modèle quand elle est son instance par défaut (DefaultInstance= de [Install], comme pour les
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

// Même signature que sous Windows, où la lecture PowerShell peut échouer.
#[allow(clippy::unnecessary_wraps)]
#[cfg(target_os = "macos")]
fn relever() -> Option<Vec<Trouvaille>> {
    let maison = crate::socle::maison();
    let mut t = Vec::new();
    for (dossier, sudo) in [
        (PathBuf::from("/Applications"), "sudo "),
        (maison.join("Applications"), ""),
    ] {
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
            });
        }
    }
    for (dossier, domaine, sudo) in [
        (PathBuf::from("/Library/LaunchAgents"), "system", "sudo "),
        (PathBuf::from("/Library/LaunchDaemons"), "system", "sudo "),
        (maison.join("Library/LaunchAgents"), "gui/$(id -u)", ""),
    ] {
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
            });
        }
    }
    fichiers_poses(&mut t, &[maison.join("Downloads"), maison.join("Desktop")]);
    Some(sans_doublons(t))
}

// ───────────────────────────── Relevé : Windows ─────────────────────────────

#[cfg(windows)]
fn relever() -> Option<Vec<Trouvaille>> {
    // Tout est lu par Vanguard lui-même, sans PowerShell (c'était la vérification la plus lente du bilan, plus de 3 s) :
    // programmes installés et clés Run dans le registre, processus et connexions par les fonctions de Windows,
    // fichiers posés par une lecture des dossiers. Le texte garde les sections du script d'avant (INS, PRC, CNX, RUN,
    // FIC, SVC), que `lire_windows` lit.
    let mut sortie = String::new();
    installes_du_registre(&mut sortie);
    processus_et_connexions(&mut sortie);
    run_du_registre(&mut sortie);
    fichiers_poses_windows(&mut sortie);
    sortie.push_str(&services_du_registre());
    lire_windows(&sortie).map(sans_doublons)
}

/// Une valeur sur une ligne de section : sans saut de ligne (qui ouvrirait une fausse ligne).
#[cfg(windows)]
fn sur_une_ligne(v: &str) -> String {
    v.replace(['\n', '\r'], " ")
}

/// Programmes et fonctionnalités (64 et 32 bits, et ceux du compte) : « INS|nom|date d'installation|date de la clé|
/// désinstallation|désinstallation silencieuse ». La date de la clé seulement quand l'installateur n'en donne pas.
#[cfg(windows)]
fn installes_du_registre(sortie: &mut String) {
    use std::fmt::Write;
    use winreg::RegKey;
    for (racine, chemin) in crate::machine::windows::installes::CLES_UNINSTALL {
        let Ok(liste) = RegKey::predef(racine).open_subkey(chemin) else {
            continue;
        };
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
}

/// Processus (« PRC|numéro|nom|chemin », le chemin quand Windows le donne et que le logiciel est reconnu) et ceux qui parlent à une autre machine
/// (« CNX|numéro »), lus par les fonctions de Windows.
#[cfg(windows)]
fn processus_et_connexions(sortie: &mut String) {
    use crate::machine::windows::processus;
    use std::fmt::Write;
    for p in processus::liste() {
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
}

/// Les clés Run et RunOnce du compte et de la machine : « RUN|clé|nom|commande ». La clé est écrite comme
/// PowerShell l'écrit (« HKCU:\… ») : c'est elle que la commande de retrait reprend. Lues par la lecture commune
/// (`machine::windows::persistance::lignes_run`), qui garde les noms mal formés et lit aussi RunOnce. Une clé
/// illisible n'a pas encore de place dans ce relevé, qui ne sait pas dire « non vérifié » pour une partie.
#[cfg(windows)]
fn run_du_registre(sortie: &mut String) {
    use std::fmt::Write;
    let (valeurs, _illisibles) = crate::machine::windows::persistance::lignes_run();
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
}

/// Les programmes, installateurs et archives posés dans Téléchargements, sur le Bureau, dans le dossier temporaire et
/// dans les programmes du compte, sous-dossiers compris (un niveau) : « FIC|chemin|date ».
#[cfg(windows)]
fn fichiers_poses_windows(sortie: &mut String) {
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
    let dossiers = [
        profil.as_ref().map(|p| p.join("Downloads")),
        bureau,
        std::env::var_os("TEMP").map(PathBuf::from),
        std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Programs")),
    ];
    let a_garder = |c: &Path| {
        c.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| ["exe", "msi", "zip"].iter().any(|x| e.eq_ignore_ascii_case(x)))
    };
    for dossier in dossiers.into_iter().flatten().filter(|d| d.is_absolute()) {
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
    let Some(trouvailles) = relever() else {
        trp!(
            "  ✖ Impossible de vérifier (PowerShell indisponible ou bloqué).",
            "  ✖ Could not check (PowerShell unavailable or blocked)."
        );
        return;
    };
    let aujourd_hui = aujourd_hui();
    let visibles: Vec<&Trouvaille> = trouvailles
        .iter()
        .filter(|t| !LOGICIELS[t.logiciel].integre || matches!(t.trace, Trace::EnCours { .. }))
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
    let presents: Vec<usize> = (0..LOGICIELS.len())
        .filter(|&i| visibles.iter().any(|t| t.logiciel == i))
        .collect();
    for &i in &presents {
        println!(
            "  {}⚠{RESET} {GRAS}{}{RESET}",
            couleur(Niveau::Eleve),
            LOGICIELS[i].nom()
        );
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
    for &i in &presents {
        let nom = LOGICIELS[i].nom();
        let siens: Vec<&Trouvaille> = visibles.iter().copied().filter(|t| t.logiciel == i).collect();
        let en_cours = siens.iter().any(|t| matches!(t.trace, Trace::EnCours { .. }));
        let mut commandes = Vec::new();
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
            commandes.extend(siens.iter().flat_map(|t| t.arret.iter().cloned()));
        }
        commandes.extend(siens.iter().flat_map(|t| t.retrait.iter().cloned()));
        let commandes = sans_repetition(commandes);
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
    let reussites = crate::machine::appliquer_chacune(&correctifs);
    for (nom, reussi) in noms.iter().zip(reussites) {
        if reussi {
            trp!("  {VERT}✔{RESET} {nom} retiré.", "  {VERT}✔{RESET} {nom} removed.");
        } else {
            trp!(
                "  ✖ {nom} : le retrait a échoué (voir au-dessus).",
                "  ✖ {nom}: removal failed (see above)."
            );
        }
    }
    dire(tr!(
        "Ensuite : changez vos mots de passe importants depuis un autre appareil, et refaites un bilan complet (menu principal, 1).",
        "Next: change your important passwords from another device, and run a full check again (main menu, 1)."
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn trouvaille(nom: &str, trace: Trace, depuis: Option<NaiveDate>, retrait: &[&str]) -> Trouvaille {
        Trouvaille {
            logiciel: indice(nom),
            trace,
            ou: format!("ici {nom}"),
            depuis,
            retrait: retrait.iter().map(ToString::to_string).collect(),
            arret: vec!["stop".to_string()],
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
        let d = std::env::temp_dir().join(format!("vanguard-distance-{nom}-{}", std::process::id()));
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
        let tube = std::ffi::CString::new(d.join("tube").to_str().unwrap()).unwrap();
        // SAFETY : chemin C terminé par un zéro, vivant pendant l'appel ; mkfifo ne touche aucune mémoire du
        // programme.
        assert_eq!(unsafe { libc::mkfifo(tube.as_ptr(), 0o600) }, 0);
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

/// PROVISOIRE (lot H, à remplacer) : `--json` rend un résultat vide, donc « non vérifié ».
pub fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let r = crate::modele::resultat::Resultat::nouveau(
        "PRO-DIS-001",
        debut,
        &[],
        crate::modele::resultat::Couverture::default(),
    );
    println!("{}", crate::modele::resultat::json(&r));
}
