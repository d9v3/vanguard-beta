//! Signes d'un rootkit, en lecture seule : processus cachés à la liste de /proc, programmes qui tournent sans fichier
//! sur le disque (effacé, en mémoire, dossier temporaire), modules du noyau cachés ou hors arbre, carte réseau qui
//! écoute tout le trafic. Chaque signe se juge par une fonction pure ; une petite fonction lit le vrai système (/proc et
//! /sys seulement, sans droits). Rien ne se corrige tout seul : on ne tue pas un processus ni ne retire un module sans
//! enquête, un rootkit qui se sent découvert pouvant tout effacer.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::machine::regles::{Os, regle};

regle!(
    "LNX-PRS-003",
    Os::Linux,
    271,
    ("processus cachés", "hidden processes"),
    &["CIS Controls v8 13.2"],
    || vec![processus_caches()]
);

regle!(
    "LNX-PRS-004",
    Os::Linux,
    272,
    (
        "programmes qui tournent sans fichier",
        "programs running without a file"
    ),
    &["CIS Controls v8 13.2"],
    programmes_sans_fichier
);

regle!(
    "LNX-NOY-006",
    Os::Linux,
    273,
    (
        "modules du noyau cachés ou hors arbre",
        "hidden or out-of-tree kernel modules"
    ),
    &[
        "CIS Controls v8 13.2",
        "ANSSI BP-028 (configuration d'un système GNU/Linux)",
        "kernel.org : tainted-kernels"
    ],
    modules_du_noyau
);

regle!(
    "LNX-RES-002",
    Os::Linux,
    274,
    (
        "carte réseau qui écoute tout le trafic",
        "network card capturing all traffic"
    ),
    &["CIS Controls v8 13.2"],
    || ecoute_du_reseau().into_iter().collect()
);

/// rkhunter et chkrootkit, quand ils sont installés : un deuxième avis, d'un autre auteur, sur les mêmes signes.
fn deuxieme_avis() -> Vec<&'static str> {
    let present = |nom: &str| {
        ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]
            .iter()
            .any(|d| Path::new(d).join(nom).exists())
    };
    let mut outils = Vec::new();
    if present("rkhunter") {
        outils.push("sudo rkhunter --check --skip-keypress");
    }
    if present("chkrootkit") {
        outils.push("sudo chkrootkit");
    }
    outils
}

/// Que faire devant un signe de rootkit : ne rien effacer à la hâte (l'intrus verrait qu'il est découvert), le parcours
/// de Vanguard, puis un deuxième avis. `noyau` : un rootkit dans le noyau ment à tout programme, Vanguard compris ; on
/// ne s'en débarrasse sûrement qu'en réinstallant.
fn enquete(c: Constat, noyau: bool, outils: &[&str]) -> Constat {
    let action = if noyau {
        tr!(
            "Ne rien effacer à la hâte : suivre Dépanner › Après une infection, demander un deuxième avis (rkhunter, chkrootkit), puis sauvegarder ses fichiers et réinstaller le système : un module du noyau qui se cache ne s'enlève pas sûrement",
            "Do not delete anything in a hurry: follow Troubleshoot › After an infection, get a second opinion (rkhunter, chkrootkit), then back up your files and reinstall the system: a kernel module that hides cannot be removed safely"
        )
    } else {
        tr!(
            "Ne rien tuer ni effacer à la hâte : suivre Dépanner › Après une infection, puis demander un deuxième avis (rkhunter, chkrootkit)",
            "Do not kill or delete anything in a hurry: follow Troubleshoot › After an infection, then get a second opinion (rkhunter, chkrootkit)"
        )
    };
    let mut commandes = vec!["vanguard depanner infection"];
    commandes.extend_from_slice(outils);
    c.manuel(action, &commandes)
}

/// Un processus tel qu'il est montré : son nom, choisi par qui l'a lancé, rendu inoffensif.
fn processus_montre(pid: u32, nom: &str) -> String {
    trf!("« {} » (PID {pid})", "“{}” (PID {pid})", crate::ui::affichable(nom))
}

/// Au plus `n` éléments, puis « et k autre(s) ».
fn quelques(liste: &[String], n: usize) -> String {
    let mut texte = liste.iter().take(n).cloned().collect::<Vec<_>>().join(", ");
    if liste.len() > n {
        let reste = liste.len() - n;
        let _ = trw!(texte, " et {reste} autre(s)", " and {reste} more");
    }
    texte
}

// ───────────────────────────── Processus cachés ─────────────────────────────

/// Les PID que montre la lecture du dossier /proc.
pub(crate) fn pids_listes() -> Option<BTreeSet<u32>> {
    Some(
        std::fs::read_dir("/proc")
            .ok()?
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse().ok())
            .collect(),
    )
}

/// Le groupe (Tgid) et le nom d'un processus, d'après /proc/<pid>/status. Un fil d'exécution (thread) répond lui
/// aussi en /proc/<tid> sans être listé : son Tgid est celui du processus qui le porte.
pub(super) fn tgid_et_nom(status: &str) -> Option<(u32, String)> {
    let mut tgid = None;
    let mut nom = None;
    for l in status.lines() {
        if let Some(v) = l.strip_prefix("Name:") {
            nom = Some(v.trim().to_string());
        } else if let Some(v) = l.strip_prefix("Tgid:") {
            tgid = v.trim().parse().ok();
        }
        if tgid.is_some() && nom.is_some() {
            break;
        }
    }
    Some((tgid?, nom.unwrap_or_default()))
}

/// Le lien /proc/self/ns/pid de l'espace de noms des PID de départ (PROC_PID_INIT_INO du noyau). Seul celui-là voit
/// tous les processus de la machine, et seul là le compte du noyau se compare à la liste.
pub(super) fn espace_initial(lien: &str) -> bool {
    lien == "pid:[4026531836]"
}

/// /proc monté avec « hidepid » : sans droits, les processus des autres comptes manquent à la liste ou se lisent
/// mal, ce qui fausserait le compte. La dernière ligne de /proc/self/mounts pour /proc est celle qui vaut.
pub(crate) fn proc_masque(montages: &str) -> bool {
    montages
        .lines()
        .rfind(|l| l.split_whitespace().nth(1) == Some("/proc"))
        .and_then(|l| l.split_whitespace().nth(3))
        .is_some_and(|options| {
            options
                .split(',')
                .filter_map(|o| o.strip_prefix("hidepid="))
                .any(|v| v != "0" && v != "off")
        })
}

/// Fils d'exécution que compte le noyau pour toute la machine : le total du 4e champ de /proc/loadavg
/// (« actifs/total »).
pub(super) fn fils_du_noyau(loadavg: &str) -> Option<u32> {
    loadavg.split_whitespace().nth(3)?.split_once('/')?.1.parse().ok()
}

/// L'écart entre les fils que compte le noyau et ceux que montre /proc, d'après des relevés (compte avant, fils vus,
/// compte après). Un relevé n'est retenu que si le compte n'a pas bougé pendant la lecture ; un programme qui naît et
/// meurt entre-temps fausse encore un relevé, rarement plusieurs de suite. `Some(0)` : un relevé retenu montre tout ;
/// `Some(n)` : trois relevés retenus montrent tous des fils en moins (le plus petit écart) ; `None` : rien à conclure
/// (machine trop occupée).
pub(super) fn ecart_persistant(releves: &[(u32, u32, u32)]) -> Option<u32> {
    let stables: Vec<(u32, u32)> = releves
        .iter()
        .filter(|(avant, _, apres)| avant == apres)
        .map(|(avant, vus, _)| (*avant, *vus))
        .collect();
    if stables.iter().any(|(compte, vus)| vus >= compte) {
        return Some(0);
    }
    (stables.len() >= 3).then(|| stables.iter().map(|(compte, vus)| compte - vus).min().unwrap_or(0))
}

/// Les fils d'exécution que montre /proc : ceux de chaque processus listé. `None` si un processus encore là ne
/// laisse pas lire les siens (le compte ne vaudrait rien).
fn fils_visibles(pids: &BTreeSet<u32>) -> Option<u32> {
    let mut n = 0u32;
    for pid in pids {
        match std::fs::read_dir(format!("/proc/{pid}/task")) {
            Ok(d) => n += u32::try_from(d.count()).unwrap_or(u32::MAX),
            // Parti pendant la lecture : le compte du noyau aura bougé, le relevé sera écarté.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    Some(n)
}

/// L'écart persistant entre le compte du noyau et la liste de /proc ; `None` s'il ne se mesure pas.
fn compter_les_fils() -> Option<u32> {
    let compte = || fils_du_noyau(&std::fs::read_to_string("/proc/loadavg").ok()?);
    let mut releves = Vec::new();
    for _ in 0..6 {
        let avant = compte()?;
        let vus = fils_visibles(&pids_listes()?)?;
        releves.push((avant, vus, compte()?));
        if let Some(e) = ecart_persistant(&releves) {
            return Some(e);
        }
    }
    None
}

/// Les PID de 1 à `borne` qui répondent sans être dans `listes` et qui mènent leur groupe (Tgid égal au PID, pas un
/// simple fil d'exécution), d'après `fiche` (le texte de /proc/<pid>/status). `assez` dit quand le temps est écoulé :
/// rend aussi le dernier PID essayé.
pub(super) fn sonder(
    listes: &BTreeSet<u32>,
    borne: u32,
    mut fiche: impl FnMut(u32) -> Option<String>,
    mut assez: impl FnMut() -> bool,
) -> (Vec<(u32, String)>, u32) {
    let mut trouves = Vec::new();
    for pid in 1..=borne {
        if pid % 512 == 0 && assez() {
            return (trouves, pid - 1);
        }
        if listes.contains(&pid) {
            continue;
        }
        if let Some((tgid, nom)) = fiche(pid).as_deref().and_then(tgid_et_nom)
            && tgid == pid
        {
            trouves.push((pid, nom));
        }
    }
    (trouves, borne)
}

/// Ce que couvre la recherche des processus cachés.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Couverture {
    /// Le compte du noyau, qui vaut pour toute la machine.
    Compte,
    /// Les PID essayés un à un, de 1 à `jusqu_a`, sur `borne` à couvrir.
    Pids { jusqu_a: u32, borne: u32 },
}

pub(super) fn juger_processus_caches(caches: &[(u32, String)], couverture: &Couverture, outils: &[&str]) -> Constat {
    if !caches.is_empty() {
        let liste: Vec<String> = caches.iter().map(|(pid, nom)| processus_montre(*pid, nom)).collect();
        return enquete(
            alerte(
                "Persistance",
                Niveau::Eleve,
                trf!(
                    "Processus caché : {} répond au noyau mais manque à la liste des processus (/proc), deux fois de suite. C'est ainsi qu'un rootkit se cache.",
                    "Hidden process: {} answers the kernel but is missing from the process list (/proc), twice in a row. This is how a rootkit hides.",
                    quelques(&liste, 5)
                ),
            ),
            false,
            outils,
        );
    }
    // Un écart du compte sans PID trouvé n'est pas signalé : des fils d'exécution qui naissent et meurent sans cesse
    // (navigateur, compilation) le font durer plusieurs relevés. La recherche PID par PID tranche ; elle seule accuse.
    match *couverture {
        Couverture::Compte => ok(
            "Persistance",
            tr!(
                "Aucun processus caché : le noyau compte autant de fils d'exécution que la liste des processus en montre.",
                "No hidden process: the kernel counts as many threads as the process list shows."
            ),
        ),
        Couverture::Pids { jusqu_a, borne } if jusqu_a >= borne => ok(
            "Persistance",
            trf!(
                "Aucun processus caché parmi les PID 1 à {borne}.",
                "No hidden process among PIDs 1 to {borne}."
            ),
        ),
        Couverture::Pids { jusqu_a, borne } => ok(
            "Persistance",
            trf!(
                "Aucun processus caché parmi les PID 1 à {jusqu_a} ; les PID {} à {borne} n'ont pas été vérifiés (trop long).",
                "No hidden process among PIDs 1 to {jusqu_a}; PIDs {} to {borne} were not checked (too long).",
                jusqu_a + 1
            ),
        ),
    }
}

/// Processus cachés, à la façon d'unhide : un PID qui répond au noyau mais manque à la lecture du dossier /proc (un
/// rootkit détourne cette lecture). Dans l'espace de noms de départ, le compte du noyau (/proc/loadavg) dit en
/// quelques millisecondes s'il manque quelqu'un ; les PID ne sont essayés un à un que pour trouver lequel, ou quand
/// le compte ne vaut rien (conteneur, /proc masqué, machine trop occupée), dans un temps borné.
pub(super) fn processus_caches() -> Constat {
    let Some(premiere) = pids_listes() else {
        return impossible("Persistance", tr!("/proc illisible", "/proc unreadable"));
    };
    let initial = std::fs::read_link("/proc/self/ns/pid").is_ok_and(|l| espace_initial(&l.to_string_lossy()));
    let masque = std::fs::read_to_string("/proc/self/mounts").is_ok_and(|m| proc_masque(&m));
    let ecart = if initial && !masque { compter_les_fils() } else { None };
    if ecart == Some(0) {
        return juger_processus_caches(&[], &Couverture::Compte, &[]);
    }
    let lire = |chemin: &str| {
        std::fs::read_to_string(chemin)
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
    };
    // PID donnés en tournant : au-delà du dernier donné et du plus grand listé, rien n'existe, sauf après un tour
    // complet (le message dit alors jusqu'où la recherche est allée).
    let plus_grand = premiere.last().copied().unwrap_or(0);
    let borne = (lire("/proc/sys/kernel/ns_last_pid").unwrap_or(0).max(plus_grand) + 256)
        .min(lire("/proc/sys/kernel/pid_max").unwrap_or(u32::MAX));
    let fiche = |pid: u32| std::fs::read_to_string(format!("/proc/{pid}/status")).ok();
    // Pour trouver un écart constaté, plus de temps ; sinon, le bilan doit rester rapide.
    let limite = std::time::Instant::now() + std::time::Duration::from_millis(if ecart.is_some() { 400 } else { 60 });
    let (candidats, jusqu_a) = sonder(&premiere, borne, fiche, || std::time::Instant::now() > limite);
    // Relu : un processus né pendant la recherche répond sans être dans la première liste ; caché, il manque encore
    // à la seconde et garde son nom.
    let seconde = pids_listes().unwrap_or_default();
    let caches: Vec<(u32, String)> = candidats
        .into_iter()
        .filter(|(pid, nom)| {
            !seconde.contains(pid)
                && fiche(*pid)
                    .as_deref()
                    .and_then(tgid_et_nom)
                    .is_some_and(|(tgid, n)| tgid == *pid && n == *nom)
        })
        .collect();
    juger_processus_caches(&caches, &Couverture::Pids { jusqu_a, borne }, &deuxieme_avis())
}

// ───────────────────────────── Programmes sans fichier ─────────────────────────────

/// Pourquoi un programme qui tourne n'a pas (ou plus) de fichier à lui sur le disque.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SansFichier {
    /// Chargé en mémoire seulement (memfd) : rien sur le disque, la marque des logiciels malveillants « sans fichier ».
    Memoire,
    /// Lancé depuis un dossier temporaire puis effacé : un programme déposé qui efface sa trace.
    EffaceTemporaire,
    /// Effacé après son lancement, sans rien à sa place : une désinstallation pendant qu'il tournait, ou une ruse.
    Efface,
    /// Lancé depuis /tmp, /var/tmp ou /dev/shm : un vrai programme s'installe d'abord.
    Temporaire,
    /// Mis à jour pendant qu'il tournait : un nouveau fichier est à sa place, l'ancienne version reste en mémoire.
    AJour,
}

impl SansFichier {
    fn niveau(self) -> Niveau {
        match self {
            SansFichier::Memoire | SansFichier::EffaceTemporaire => Niveau::Eleve,
            SansFichier::Efface | SansFichier::Temporaire => Niveau::Moyen,
            SansFichier::AJour => Niveau::Info,
        }
    }

    fn raison(self) -> &'static str {
        match self {
            SansFichier::Memoire => tr!("en mémoire seulement (memfd)", "in memory only (memfd)"),
            SansFichier::EffaceTemporaire => tr!(
                "effacé d'un dossier temporaire après son lancement",
                "deleted from a temporary folder after it started"
            ),
            SansFichier::Efface => tr!(
                "effacé après son lancement, rien à sa place",
                "deleted after it started, nothing in its place"
            ),
            SansFichier::Temporaire => tr!("lancé depuis un dossier temporaire", "started from a temporary folder"),
            SansFichier::AJour => tr!("mis à jour pendant qu'il tournait", "updated while running"),
        }
    }
}

/// Dossiers temporaires d'où un vrai programme ne tourne pas, sauf ce que des outils y construisent et lancent
/// aussitôt (« go run », « cargo install ») et les AppImage, montées dans /tmp le temps qu'elles tournent.
fn dans_un_temporaire(chemin: &str, montages: &str) -> bool {
    ["/tmp/", "/var/tmp/", "/dev/shm/"]
        .iter()
        .any(|t| chemin.starts_with(t))
        && !["/tmp/go-build", "/tmp/cargo-install"]
            .iter()
            .any(|t| chemin.starts_with(t))
        && !crate::protection::sortantes::appimage(chemin, montages)
}

/// Le jugement du lien /proc/<pid>/exe d'un programme. `remplace` : un fichier existe encore au chemin d'origine (vu
/// depuis la racine du programme) ; `montages` : /proc/self/mounts, pour reconnaître une AppImage. `None` : rien à dire.
pub(crate) fn juger_exe(lien: &str, remplace: bool, montages: &str) -> Option<SansFichier> {
    if let Some(nom) = lien.strip_prefix("/memfd:") {
        // runc et crun se recopient en mémoire un instant en lançant un conteneur (protection contre une faille de
        // runc) ; le reste n'a aucune raison de tourner sans fichier.
        return (!["runc", "crun", "youki"].iter().any(|r| nom.contains(r))).then_some(SansFichier::Memoire);
    }
    let (chemin, efface) = match lien.strip_suffix(" (deleted)") {
        Some(c) => (c, true),
        None => (lien, false),
    };
    let temporaire = dans_un_temporaire(chemin, montages);
    if !efface {
        return temporaire.then_some(SansFichier::Temporaire);
    }
    if temporaire {
        return Some(SansFichier::EffaceTemporaire);
    }
    // Un nouveau fichier à la même place : une mise à jour (paquets, Steam ou Firefox qui se mettent à jour eux-mêmes).
    // Nix, Snap et Flatpak rangent chaque version à part et effacent l'ancienne : même chose, Flatpak du système comme
    // ceux installés pour le compte (~/.local/share/flatpak, qu'une mise à jour faisait passer pour effacés).
    if remplace
        || ["/nix/store/", "/snap/", "/var/lib/flatpak/"]
            .iter()
            .any(|d| chemin.starts_with(d))
        || (chemin.starts_with("/home/") && chemin.contains("/.local/share/flatpak/"))
    {
        return Some(SansFichier::AJour);
    }
    Some(SansFichier::Efface)
}

/// Les constats d'après les programmes repérés (PID, nom, raison) ; `lus` programmes lus, `illisibles` qui ne se
/// lisent pas sans droits root (ceux des autres comptes).
pub(super) fn juger_sans_fichier(
    reperes: &[(u32, String, SansFichier)],
    lus: usize,
    illisibles: usize,
    outils: &[&str],
) -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut signes: Vec<&(u32, String, SansFichier)> = reperes.iter().filter(|r| r.2 != SansFichier::AJour).collect();
    signes.sort_by_key(|r| (r.2, r.0));
    if let Some(niveau) = signes.iter().map(|r| r.2.niveau()).max() {
        let liste: Vec<String> = signes
            .iter()
            .map(|(pid, nom, raison)| format!("{} {}", processus_montre(*pid, nom), raison.raison()))
            .collect();
        constats.push(enquete(
            alerte(
                "Persistance",
                niveau,
                trf!(
                    "Programme qui tourne sans fichier à lui : {}. Un logiciel malveillant fait ainsi pour ne pas laisser de trace ; un programme désinstallé pendant qu'il tournait, ou lancé exprès depuis /tmp, l'explique aussi.",
                    "Program running without a file of its own: {}. Malware does this to leave no trace; a program uninstalled while running, or started on purpose from /tmp, also explains it.",
                    quelques(&liste, 4)
                ),
            ),
            false,
            outils,
        ));
    }
    let mut a_jour: Vec<String> = reperes
        .iter()
        .filter(|r| r.2 == SansFichier::AJour)
        .map(|r| crate::ui::affichable(&r.1))
        .collect();
    a_jour.sort();
    a_jour.dedup();
    if !a_jour.is_empty() {
        constats.push(alerte(
            "Redémarrage",
            Niveau::Info,
            trf!(
                "{} programme(s) mis à jour pendant qu'ils tournaient ({}) : l'ancienne version, et ses failles, restent en mémoire jusqu'à ce qu'ils soient relancés.",
                "{} program(s) updated while running ({}): the old version, and its flaws, stay in memory until they are restarted.",
                a_jour.len(),
                quelques(&a_jour, 5)
            ),
        ));
    }
    if signes.is_empty() {
        constats.push(ok(
            "Persistance",
            if illisibles == 0 {
                tr!(
                    "Chaque programme en marche a son fichier sur le disque, hors des dossiers temporaires.",
                    "Every running program has its file on disk, outside temporary folders."
                )
                .to_string()
            } else {
                trf!(
                    "Les {lus} programmes de votre compte ont leur fichier sur le disque ; les {illisibles} des autres comptes (root, services) ne se lisent qu'avec les droits root : pas vérifiés.",
                    "The {lus} programs of your account have their file on disk; the {illisibles} of other accounts (root, services) can only be read with root rights: not checked."
                )
            },
        ));
    }
    constats
}

/// Programmes qui tournent sans fichier : le lien /proc/<pid>/exe de chacun, lisible sans droits pour ceux du compte
/// seulement. Ce qui est repéré est relu : runc ne passe par la mémoire qu'un instant.
pub(super) fn programmes_sans_fichier() -> Vec<Constat> {
    let Some(pids) = pids_listes() else {
        return vec![impossible("Persistance", tr!("/proc illisible", "/proc unreadable"))];
    };
    let montages = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let moi = std::process::id();
    let lien = |pid: u32| std::fs::read_link(format!("/proc/{pid}/exe"));
    let juger = |pid: u32, l: &str| {
        let chemin = l.strip_suffix(" (deleted)").unwrap_or(l);
        let remplace = Path::new(&format!("/proc/{pid}/root{chemin}")).exists();
        juger_exe(l, remplace, &montages)
    };
    let (mut lus, mut illisibles) = (0, 0);
    let mut reperes = Vec::new();
    for &pid in pids.iter().filter(|p| **p != moi) {
        match lien(pid) {
            Ok(l) => {
                lus += 1;
                let l = l.to_string_lossy().into_owned();
                if let Some(raison) = juger(pid, &l) {
                    reperes.push((pid, l, raison));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => illisibles += 1,
            // Fil du noyau (sans programme) ou processus parti entre-temps.
            Err(_) => {}
        }
    }
    let reperes: Vec<(u32, String, SansFichier)> = reperes
        .into_iter()
        .filter(|(pid, l, _)| lien(*pid).is_ok_and(|encore| encore.to_string_lossy() == *l))
        .map(|(pid, l, raison)| {
            let nom = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            let nom = nom.trim();
            // En mémoire, le nom donné au fichier (memfd) dit souvent mieux qui il est : un nom de processus se change.
            let memfd = l.strip_prefix("/memfd:").map(|m| m.trim_end_matches(" (deleted)"));
            let nom = match memfd {
                Some(m) if !m.is_empty() && m != nom => format!("{nom} — memfd:{m}"),
                _ => nom.to_string(),
            };
            (pid, nom, raison)
        })
        .collect();
    juger_sans_fichier(&reperes, lus, illisibles, &deuxieme_avis())
}

// ───────────────────────────── Modules du noyau ─────────────────────────────

/// Les modules chargés d'après /proc/modules : nom → drapeaux de souillure (« OE », vide sans parenthèses). Ligne
/// « nvidia 54001664 120 nvidia_modeset, Live 0x0000000000000000 (POE) ».
pub(super) fn modules_charges(texte: &str) -> BTreeMap<String, String> {
    texte
        .lines()
        .filter_map(|l| {
            let nom = l.split_whitespace().next()?;
            let drapeaux = l
                .split_whitespace()
                .last()
                .and_then(|d| d.strip_prefix('(')?.strip_suffix(')'))
                .unwrap_or_default();
            Some((nom.to_string(), drapeaux.to_string()))
        })
        .collect()
}

/// Les modules présents dans /sys/module avec un état « live » (`sysfs` : nom, contenu de initstate ; un module
/// compilé dans le noyau n'en a pas) mais absents de /proc/modules : un module qui se retire de la liste pour se cacher.
pub(super) fn modules_caches(sysfs: &[(String, String)], charges: &BTreeMap<String, String>) -> Vec<String> {
    sysfs
        .iter()
        .filter(|(nom, etat)| etat.trim() == "live" && !charges.contains_key(nom))
        .map(|(nom, _)| nom.clone())
        .collect()
}

/// Pilotes hors arbre connus, posés par les paquets ou DKMS (« * » à la fin : tout nom qui commence ainsi). Les
/// signaler chaque fois noierait le reste : un pilote NVIDIA n'a rien d'un rootkit.
const HORS_ARBRE_CONNUS: &[&str] = &[
    "nvidia*",
    "vbox*",
    "zfs",
    "spl",
    "zavl",
    "znvpair",
    "zunicode",
    "zcommon",
    "zlua",
    "zzstd",
    "icp",
    "v4l2loopback",
    "wireguard",
    "acpi_call",
    "evdi",
    "xpadneo",
    "hid_xpadneo",
    "vmmon",
    "vmnet",
    "bbswitch",
    "tp_smapi",
    "ddcci*",
    "razer*",
    "rtl88*",
    "8812au",
    "8821cu",
    "88x2bu",
    "it87",
    "nct6687",
    "zenpower",
    "ryzen_smu",
];

fn hors_arbre_connu(nom: &str) -> bool {
    HORS_ARBRE_CONNUS.iter().any(|k| match k.strip_suffix('*') {
        Some(debut) => nom.starts_with(debut),
        None => nom == *k,
    })
}

/// Modules chargés hors de l'arbre du noyau et non signés (« O » et « E »), ni connus ni posés par DKMS (`dkms` : le
/// module a son dossier dans /var/lib/dkms).
pub(super) fn hors_arbre_inconnus(charges: &BTreeMap<String, String>, dkms: impl Fn(&str) -> bool) -> Vec<String> {
    charges
        .iter()
        .filter(|(nom, d)| d.contains('O') && d.contains('E') && !hors_arbre_connu(nom) && !dkms(nom))
        .map(|(nom, _)| nom.clone())
        .collect()
}

/// Bit 12 de /proc/sys/kernel/tainted : un module hors arbre a été chargé depuis le démarrage (il reste levé après son
/// retrait).
const SOUILLURE_HORS_ARBRE: u64 = 1 << 12;

pub(super) fn juger_modules(
    caches: &[String],
    inconnus: &[String],
    charges: &BTreeMap<String, String>,
    souillure: Option<u64>,
    outils: &[&str],
) -> Vec<Constat> {
    let mut constats = Vec::new();
    let montrer = |noms: &[String]| -> Vec<String> { noms.iter().map(|n| crate::ui::affichable(n)).collect() };
    if !caches.is_empty() {
        constats.push(enquete(
            alerte(
                "Persistance",
                Niveau::Eleve,
                trf!(
                    "Module du noyau caché : {} est chargé (/sys/module) mais manque à la liste des modules (/proc/modules), deux fois de suite. C'est ainsi qu'un rootkit du noyau se cache.",
                    "Hidden kernel module: {} is loaded (/sys/module) but missing from the module list (/proc/modules), twice in a row. This is how a kernel rootkit hides.",
                    quelques(&montrer(caches), 5)
                ),
            ),
            true,
            outils,
        ));
    }
    if !inconnus.is_empty() {
        let premier = inconnus[0].clone();
        // Un nom de module : lettres, chiffres et « _ » ; autre chose ne va pas dans une commande.
        let commande = format!("modinfo {premier}");
        let commandes: Vec<&str> = if premier.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            vec![&commande]
        } else {
            Vec::new()
        };
        constats.push(
            alerte(
                "Pilotes",
                Niveau::Info,
                trf!(
                    "Module(s) du noyau hors arbre et non signé(s) : {}. À reconnaître : un pilote installé à la main, ou un rootkit du noyau, qui se charge de la même façon.",
                    "Out-of-tree, unsigned kernel module(s): {}. Check that you recognize them: a driver installed by hand, or a kernel rootkit, which loads the same way.",
                    quelques(&montrer(inconnus), 5)
                ),
            )
            .manuel(
                tr!("Voir d'où vient le module", "See where the module comes from"),
                &commandes,
            ),
        );
    }
    // Un module hors arbre a été chargé, mais aucun n'est plus dans la liste : retiré depuis, ou caché.
    let hors_arbre_liste = charges.values().any(|d| d.contains('O'));
    if caches.is_empty() && souillure.is_some_and(|s| s & SOUILLURE_HORS_ARBRE != 0) && !hors_arbre_liste {
        constats.push(alerte(
            "Pilotes",
            Niveau::Info,
            tr!(
                "Le noyau a chargé depuis le démarrage un module hors arbre qui n'est plus dans la liste des modules : retiré depuis (un pilote déchargé), ou caché. Le redémarrage efface cette marque.",
                "Since boot, the kernel has loaded an out-of-tree module that is no longer in the module list: removed since (an unloaded driver), or hidden. Restarting clears this mark."
            ),
        ));
    }
    if caches.is_empty() {
        constats.push(ok(
            "Persistance",
            tr!(
                "Aucun module du noyau ne se cache de la liste des modules.",
                "No kernel module hides from the module list."
            ),
        ));
    }
    constats
}

/// Les modules chargeables de /sys/module et l'état de chacun (initstate).
fn modules_sysfs() -> Vec<(String, String)> {
    std::fs::read_dir("/sys/module")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let etat = std::fs::read_to_string(e.path().join("initstate")).ok()?;
            Some((e.file_name().to_string_lossy().into_owned(), etat))
        })
        .collect()
}

/// Modules du noyau : cachés (dans /sys/module, pas dans /proc/modules, relu deux fois pour un module qui se charge
/// ou se retire pendant la lecture), et hors arbre non signés. Tout se lit sans droits.
pub(super) fn modules_du_noyau() -> Vec<Constat> {
    let sysfs = modules_sysfs();
    let Ok(liste) = std::fs::read_to_string("/proc/modules") else {
        // Noyau sans modules chargeables (rien ne peut s'y cacher ainsi), ou liste illisible alors qu'il en a.
        return if sysfs.is_empty() {
            vec![ok(
                "Persistance",
                tr!(
                    "Ce noyau ne charge pas de modules : aucun ne peut s'y cacher.",
                    "This kernel does not load modules: none can hide in it."
                ),
            )]
        } else {
            vec![impossible(
                "Persistance",
                tr!("liste des modules illisible", "module list unreadable"),
            )]
        };
    };
    let charges = modules_charges(&liste);
    let mut caches = modules_caches(&sysfs, &charges);
    if !caches.is_empty() {
        let encore = modules_caches(
            &modules_sysfs(),
            &modules_charges(&std::fs::read_to_string("/proc/modules").unwrap_or_default()),
        );
        caches.retain(|m| encore.contains(m));
    }
    let inconnus = hors_arbre_inconnus(&charges, |nom| Path::new("/var/lib/dkms").join(nom).exists());
    let souillure = std::fs::read_to_string("/proc/sys/kernel/tainted")
        .ok()
        .and_then(|t| t.trim().parse().ok());
    juger_modules(&caches, &inconnus, &charges, souillure, &deuxieme_avis())
}

// ───────────────────────────── Carte réseau qui écoute tout ─────────────────────────────

/// Une interface réseau d'après /sys/class/net.
#[derive(Debug)]
pub(super) struct Carte {
    pub nom: String,
    /// /sys/class/net/<if>/flags (« 0x1103 »), lu en nombre.
    pub drapeaux: u32,
    /// Liée à un vrai périphérique (lien « device ») : pas une interface virtuelle.
    pub materielle: bool,
    /// Port d'un pont ou d'une agrégation (lien « master ») : le pont la met en mode promiscuité, c'est son travail.
    pub esclave: bool,
}

/// IFF_PROMISC : la carte remet au système tout ce qui passe sur le câble ou les ondes, pas seulement ce qui lui est
/// adressé. Le drapeau de /sys se lève aussi pour une capture (tcpdump), que « ip link » ne montre pas.
const IFF_PROMISC: u32 = 0x100;

/// Interfaces virtuelles (conteneurs, machines virtuelles, VPN, ponts) : la promiscuité y est normale.
const VIRTUELLES: &[&str] = &[
    "veth", "docker", "br-", "virbr", "tap", "tun", "vnet", "vmnet", "vboxnet", "lxc", "cni", "flannel", "cali",
    "podman", "wg", "ifb", "dummy",
];

pub(super) fn drapeaux_carte(texte: &str) -> Option<u32> {
    u32::from_str_radix(texte.trim().trim_start_matches("0x"), 16).ok()
}

pub(super) fn juger_ecoute(cartes: &[Carte]) -> Option<Constat> {
    let physiques: Vec<&Carte> = cartes
        .iter()
        .filter(|c| c.materielle && !c.esclave && c.nom != "lo" && !VIRTUELLES.iter().any(|v| c.nom.starts_with(v)))
        .collect();
    if physiques.is_empty() {
        return None;
    }
    let ecoutent: Vec<String> = physiques
        .iter()
        .filter(|c| c.drapeaux & IFF_PROMISC != 0)
        .map(|c| crate::ui::affichable(&c.nom))
        .collect();
    Some(if ecoutent.is_empty() {
        ok(
            "Écoute du réseau",
            tr!(
                "Aucune carte réseau n'écoute le trafic des autres appareils.",
                "No network card is capturing other devices' traffic."
            ),
        )
    } else {
        alerte(
            "Écoute du réseau",
            Niveau::Moyen,
            trf!(
                "La carte réseau {} écoute tout le trafic qui passe, pas seulement le sien (mode promiscuité) : un programme qui espionne le réseau fait ainsi ; Wireshark ou tcpdump lancés exprès, ou une machine virtuelle en accès par pont, aussi.",
                "Network card {} is capturing all passing traffic, not just its own (promiscuous mode): a program spying on the network does this; so do Wireshark or tcpdump started on purpose, or a bridged virtual machine.",
                ecoutent.join(", ")
            ),
        )
        .manuel(
            tr!(
                "Si vous ne capturez rien vous-même, voir quel programme écoute",
                "If you are not capturing anything yourself, see which program is listening"
            ),
            &["sudo ss -0 -p"],
        )
    })
}

pub(super) fn ecoute_du_reseau() -> Option<Constat> {
    let cartes: Vec<Carte> = std::fs::read_dir("/sys/class/net")
        .ok()?
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            Some(Carte {
                nom: e.file_name().to_string_lossy().into_owned(),
                drapeaux: drapeaux_carte(&std::fs::read_to_string(p.join("flags")).ok()?)?,
                materielle: p.join("device").exists(),
                esclave: p.join("master").exists(),
            })
        })
        .collect();
    juger_ecoute(&cartes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Name:\tsshd\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t812\nNgid:\t0\nPid:\t812\nPPid:\t1\n";

    #[test]
    fn fiche_d_un_processus() {
        assert_eq!(tgid_et_nom(STATUS), Some((812, "sshd".into())));
        assert_eq!(tgid_et_nom("Name:\tx\n"), None);
        assert_eq!(fils_du_noyau("0.07 0.43 0.70 2/139 30103\n"), Some(139));
        assert_eq!(fils_du_noyau("rien"), None);
        assert!(espace_initial("pid:[4026531836]") && !espace_initial("pid:[4026532512]"));
    }

    #[test]
    fn proc_masque_par_hidepid() {
        let m = |o: &str| format!("sysfs /sys sysfs rw 0 0\nproc /proc proc {o} 0 0\n");
        assert!(!proc_masque(&m("rw,nosuid,nodev,noexec,relatime")));
        assert!(proc_masque(&m("rw,nosuid,hidepid=invisible")));
        assert!(proc_masque(&m("rw,hidepid=2,gid=27")));
        assert!(!proc_masque(&m("rw,hidepid=0")));
        // Remonté sans hidepid par-dessus : la dernière ligne vaut.
        assert!(!proc_masque(&format!("{}proc /proc proc rw 0 0\n", m("rw,hidepid=2"))));
    }

    #[test]
    fn ecart_entre_le_noyau_et_la_liste() {
        // Un relevé stable qui montre tout suffit.
        assert_eq!(ecart_persistant(&[(139, 139, 139)]), Some(0));
        assert_eq!(ecart_persistant(&[(140, 138, 141), (139, 140, 139)]), Some(0));
        // Compte qui bouge à chaque relevé : rien à conclure.
        assert_eq!(
            ecart_persistant(&[(139, 137, 140), (141, 139, 142), (150, 148, 149)]),
            None
        );
        // Deux relevés stables en défaut ne suffisent pas ; trois, oui.
        assert_eq!(ecart_persistant(&[(139, 138, 139), (139, 138, 139)]), None);
        assert_eq!(
            ecart_persistant(&[(139, 137, 139), (139, 138, 139), (140, 139, 141), (139, 138, 139)]),
            Some(1)
        );
    }

    #[test]
    fn recherche_des_pid_qui_repondent_sans_etre_listes() {
        let listes: BTreeSet<u32> = [1, 2, 300, 812].into();
        let fiches: BTreeMap<u32, String> = [
            (1, "Name:\tsystemd\nTgid:\t1\n".to_string()),
            (812, STATUS.to_string()),
            // Un fil d'exécution de sshd : répond, pas listé, mais pas un processus.
            (813, "Name:\tsshd\nTgid:\t812\nPid:\t813\n".to_string()),
            // Le processus caché.
            (4242, "Name:\tkworker/0:9\nTgid:\t4242\n".to_string()),
        ]
        .into();
        let (trouves, jusqu_a) = sonder(&listes, 5000, |p| fiches.get(&p).cloned(), || false);
        assert_eq!(trouves, vec![(4242, "kworker/0:9".to_string())]);
        assert_eq!(jusqu_a, 5000);
        // Le temps manque : la recherche s'arrête et dit où.
        let (trouves, jusqu_a) = sonder(&listes, 5000, |p| fiches.get(&p).cloned(), || true);
        assert!(trouves.is_empty() && jusqu_a == 511);
    }

    #[test]
    fn processus_caches_juges() {
        let c = juger_processus_caches(&[(4242, "x\x1b[2Ky".into())], &Couverture::Compte, &[]);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(
            c.message.contains("4242") && !c.message.contains('\x1b'),
            "{}",
            c.message
        );
        let k = c.correctif.unwrap();
        assert!(!k.automatique && k.commandes == ["vanguard depanner infection"]);
        // Écart du compte, mais rien de caché trouvé PID par PID : des fils passagers, pas une alerte.
        let c = juger_processus_caches(
            &[],
            &Couverture::Pids {
                jusqu_a: 900,
                borne: 900,
            },
            &[],
        );
        assert!(c.probleme.is_none() && c.verifie, "{}", c.message);
        let c = juger_processus_caches(&[], &Couverture::Compte, &[]);
        assert!(c.probleme.is_none() && c.verifie);
        // Recherche coupée : dit jusqu'où, sans prétendre avoir tout vu.
        let c = juger_processus_caches(
            &[],
            &Couverture::Pids {
                jusqu_a: 70_000,
                borne: 400_000,
            },
            &[],
        );
        assert!(
            c.probleme.is_none() && c.message.contains("70") && c.message.contains("400"),
            "{}",
            c.message
        );
    }

    #[test]
    fn programmes_sans_fichier_juges() {
        let montages =
            "tmpfs /tmp tmpfs rw 0 0\nMonAppli.AppImage /tmp/.mount_MonApp3xYz fuse.MonAppli.AppImage ro 0 0\n";
        let j = |lien: &str, remplace: bool| juger_exe(lien, remplace, montages);
        assert_eq!(j("/usr/bin/bash", true), None);
        assert_eq!(j("/memfd: (deleted)", false), Some(SansFichier::Memoire));
        assert_eq!(j("/memfd:x (deleted)", false), Some(SansFichier::Memoire));
        // runc, un instant, en lançant un conteneur.
        assert_eq!(j("/memfd:runc_cloned:/proc/self/exe (deleted)", false), None);
        assert_eq!(j("/dev/shm/.x", false), Some(SansFichier::Temporaire));
        assert_eq!(j("/tmp/.x (deleted)", false), Some(SansFichier::EffaceTemporaire));
        assert_eq!(j("/tmp/.mount_MonApp3xYz/AppRun", true), None);
        assert_eq!(j("/tmp/go-build1234/b001/exe/main", true), None);
        // Mise à jour pendant qu'il tournait : un nouveau fichier à la même place.
        assert_eq!(j("/usr/lib/firefox/firefox (deleted)", true), Some(SansFichier::AJour));
        assert_eq!(
            j("/home/alice/.local/share/Steam/ubuntu12_32/steam (deleted)", true),
            Some(SansFichier::AJour)
        );
        assert_eq!(
            j("/nix/store/abc-hello/bin/hello (deleted)", false),
            Some(SansFichier::AJour)
        );
        assert_eq!(
            j(
                "/home/alice/.local/share/flatpak/app/org.exemple.App/x86_64/stable/abc/files/bin/app (deleted)",
                false
            ),
            Some(SansFichier::AJour)
        );
        assert_eq!(j("/usr/local/bin/outil (deleted)", false), Some(SansFichier::Efface));

        let reperes = vec![
            (2001, "kdevtmpfsi".to_string(), SansFichier::Memoire),
            (2002, "firefox".to_string(), SansFichier::AJour),
            (2003, "firefox".to_string(), SansFichier::AJour),
        ];
        let c = juger_sans_fichier(&reperes, 40, 0, &[]);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].message.contains("kdevtmpfsi") && c[0].message.contains("2001"));
        assert!(c[1].categorie == "Redémarrage" && c[1].probleme == Some(Niveau::Info));
        assert!(c[1].message.starts_with('1'), "{}", c[1].message);
        // Sans droits : dit que les autres comptes ne sont pas vérifiés.
        let c = juger_sans_fichier(&[], 12, 230, &[]);
        assert_eq!(c.len(), 1);
        assert!(
            c[0].probleme.is_none() && c[0].message.contains("230"),
            "{}",
            c[0].message
        );
    }

    const MODULES: &str = "nvidia_uvm 4911104 0 - Live 0x0000000000000000 (POE)
nvidia 54001664 120 nvidia_uvm, Live 0x0000000000000000 (POE)
btusb 77824 0 - Live 0x0000000000000000
mondriver 16384 0 - Live 0x0000000000000000 (OE)
v4l2loopback 49152 0 - Live 0x0000000000000000 (OE)
";

    #[test]
    fn modules_du_noyau_juges() {
        let charges = modules_charges(MODULES);
        assert_eq!(charges.get("nvidia").map(String::as_str), Some("POE"));
        assert_eq!(charges.get("btusb").map(String::as_str), Some(""));
        let sysfs = vec![
            ("btusb".to_string(), "live\n".to_string()),
            ("nvidia".to_string(), "live\n".to_string()),
            ("diamant".to_string(), "live\n".to_string()),
            // En train de se charger : pas encore dans la liste, rien de caché.
            ("nouveau".to_string(), "coming\n".to_string()),
        ];
        assert_eq!(modules_caches(&sysfs, &charges), vec!["diamant".to_string()]);
        // NVIDIA et v4l2loopback sont connus ; un module posé par DKMS aussi.
        assert_eq!(hors_arbre_inconnus(&charges, |_| false), vec!["mondriver".to_string()]);
        assert_eq!(
            hors_arbre_inconnus(&charges, |n| n == "mondriver"),
            Vec::<String>::new()
        );

        let c = juger_modules(&["diamant".into()], &[], &charges, Some(12288), &["sudo chkrootkit"]);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(
            c[0].correctif
                .as_ref()
                .unwrap()
                .commandes
                .contains(&"sudo chkrootkit".to_string())
        );
        let c = juger_modules(&[], &["mondriver".into()], &charges, Some(12288), &[]);
        assert_eq!(c[0].probleme, Some(Niveau::Info));
        assert_eq!(c[0].correctif.as_ref().unwrap().commandes, ["modinfo mondriver"]);
        assert!(c[1].probleme.is_none());
        // Un pilote NVIDIA seul : rien à dire.
        let nvidia = modules_charges("nvidia 54001664 120 - Live 0x0 (POE)\n");
        let c = juger_modules(&[], &hors_arbre_inconnus(&nvidia, |_| false), &nvidia, Some(12289), &[]);
        assert!(c.len() == 1 && c[0].probleme.is_none());
        // Hors arbre chargé depuis le démarrage, plus dans la liste : retiré, ou caché.
        let sans = modules_charges("btusb 77824 0 - Live 0x0\n");
        let c = juger_modules(&[], &[], &sans, Some(12288), &[]);
        assert_eq!(c[0].probleme, Some(Niveau::Info));
        // Nom piégé : montré inoffensif, jamais dans une commande.
        let c = juger_modules(&[], &["a;rm -rf ~".into()], &charges, Some(0), &[]);
        assert_eq!(c[0].correctif.as_ref().unwrap().commandes, Vec::<String>::new());
    }

    #[test]
    fn carte_en_mode_promiscuite() {
        let carte = |nom: &str, drapeaux: &str, materielle: bool, esclave: bool| Carte {
            nom: nom.into(),
            drapeaux: drapeaux_carte(drapeaux).unwrap(),
            materielle,
            esclave,
        };
        assert_eq!(drapeaux_carte("0x1103\n"), Some(0x1103));
        // Rien de physique : rien à dire.
        assert!(juger_ecoute(&[carte("lo", "0x9", false, false)]).is_none());
        let sain = juger_ecoute(&[carte("enp3s0", "0x1003", true, false), carte("lo", "0x9", false, false)]).unwrap();
        assert!(sain.probleme.is_none());
        // Ports de pont, interfaces virtuelles : écartés.
        let c = juger_ecoute(&[
            carte("enp3s0", "0x1103", true, true),
            carte("veth12ab", "0x1103", false, true),
            carte("wlp2s0", "0x1003", true, false),
        ])
        .unwrap();
        assert!(c.probleme.is_none());
        let c = juger_ecoute(&[carte("wlp2s0", "0x1103", true, false)]).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("wlp2s0") && c.message.contains("Wireshark"));
    }

    /// Le vrai système : la lecture ne plante pas et ne trouve rien de caché ici (conteneur ou machine de test).
    #[test]
    fn lecture_reelle() {
        let c = processus_caches();
        assert!(c.probleme.is_none() || !c.verifie, "{}", c.message);
        for c in modules_du_noyau() {
            assert!(c.probleme != Some(Niveau::Eleve), "{}", c.message);
        }
        let _ = programmes_sans_fichier();
        let _ = ecoute_du_reseau();
    }
}
