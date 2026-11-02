//! L'assistant élevé de Linux et macOS : Vanguard se relance lui-même avec les droits d'administrateur, sous la
//! sous-commande cachée `appliquer-eleve`, pour faire des ordres du blocage (`protection::blocage::ordres`) et des
//! gestes de Linux (`machine::gestes_unix`) sans aucun shell : jamais « sudo sh -c », jamais une commande écrite en
//! texte.
//!
//! L'élévation, dans cet ordre : pkexec (Linux, s'il y a une session graphique : la fenêtre de l'agent polkit ; sans
//! agent, pkexec rend 127 et le suivant est essayé), run0 (Linux, systemd 256 et plus : son propre agent dans le
//! terminal), sudo (dans le terminal ; use_pty, la règle par défaut depuis sudo 1.9.14, passe nos tubes tels quels),
//! sinon c'est dit et rien n'est fait. Le programme lancé est, sous Linux, `/proc/<pid>/exe` de ce Vanguard : ce lien
//! désigne l'image qui tourne, même si le fichier est remplacé entre-temps (sudo et run0 l'exécutent tel quel).
//! pkexec, lui, le résout en chemin réel avant de l'exécuter (realpath dans pkexec.c), et macOS n'a pas de /proc :
//! par chemin, seulement un programme que le compte ne peut pas remplacer (à root, dossiers compris) ; sinon pkexec
//! est sauté (run0 ou sudo prennent la suite), et sous macOS c'est dit.
//!
//! Pendant le dialogue, le parent n'est plus « dumpable » : un autre processus du compte ne peut ni ouvrir ses tubes
//! par `/proc/<pid>/fd` ni s'y attacher, donc ni glisser une autre liste au fils, ni répondre à sa place.
//!
//! Le canal : l'entrée et la sortie standard du fils, deux tubes que seul ce processus tient (pkexec, run0 et sudo
//! les passent tels quels). Le fils dit d'abord qu'il est prêt (il tourne en root), lit la liste jusqu'à « fin »,
//! la relit contre la liste fermée (une ligne étrangère, et rien n'est fait), la montre sur sa sortie d'erreur (le
//! terminal), rejuge chaque ordre avec ses propres yeux (`ordres::juger`), le fait, puis répond une ligne par ordre.
//! Un geste de Linux est fait par le chemin absolu de son outil, dans un environnement vidé
//! (`commande::environnement_propre`) : rien de ce que le compte a posé (PATH, BASH_ENV, LD_PRELOAD) ne le suit.
//! Il n'écrit aucun fichier et ne lit rien du dossier de Vanguard.
//!
//! L'accord. Le parent a montré la liste avant de demander les droits : pour un geste ordinaire, le mot de passe vaut
//! accord. Un geste qui baisse une protection ou supprime quelque chose (`GesteUnix::demande_accord`) est redemandé
//! par le fils lui-même, en root, sur le terminal de la personne (/dev/tty, vidé de ce qui y était tapé d'avance) :
//! seul « oui » le fait ; sans terminal (pkexec lancé hors d'un terminal), il est refusé, jamais fait en silence.
//! Ce que cela arrête, honnêtement : un programme du compte qui écrit des fichiers (un faux `sudo` dans
//! ~/.local/bin, un BASH_ENV, une liste glissée) ne fait faire en root que des gestes de la liste fermée, et pas ceux
//! qui affaiblissent sans que la personne ait dit oui au fils. Ce que cela n'arrête pas : un programme du compte
//! capable d'écrire dans le terminal de la personne ou d'agir à sa place dans sa session (taper pour elle, injecter
//! dans ses processus) peut aussi répondre « oui » ; contre lui, seule une session séparée protège (Windows : le
//! bureau sécurisé de l'UAC). Concrètement, sans aucun droit particulier : `tmux send-keys` ou `screen -X stuff` si
//! Vanguard tourne dedans, la télécommande de kitty, wtype ou ydotool sous Wayland, xdotool sous X11, et TIOCSTI sur
//! un noyau d'avant 6.2 (ou compilé avec CONFIG_LEGACY_TIOCSTI). Vider le terminal (tcflush) ne bat que ce qui a été
//! tapé d'avance : un programme qui lit l'écran (`tmux capture-pane`) tape après la question. L'accord n'est donc
//! pas une barrière contre un programme du compte (limite A2 de D3) : il protège d'un geste fait par erreur.
//!
//! L'accord demande un terminal au fils : pkexec et run0 (en mode tube, avec nos tubes) ne lui en donnent pas, sudo
//! oui (use_pty). Une liste qui contient un tel geste ne passe donc que par sudo, lancé depuis un terminal
//! (`methodes`).

// FFI de libc : prctl (PR_SET_DUMPABLE, le secret de l'assistant élevé hors des vidages).
#![allow(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use crate::machine::gestes_unix::{self, ActionUnite, GesteUnix, Programme};
use crate::modele::Echec;
use crate::protection::blocage::ordres::{self, LIGNE_MAX, LIGNES_MAX, Ordre, Resultat};
use crate::ui::{GRIS, RESET};
use crate::{tr, trf, trp};

/// La première ligne du fils : il tourne en root et attend la liste.
const PRET: &str = "vanguard-eleve pret";
/// La dernière ligne de chaque sens.
const FIN: &str = "fin";
/// Entre deux groupes de la liste : un ordre en échec n'arrête que la suite de son groupe.
const SUITE: &str = "suite";
/// Sortie du fils : la liste reçue n'est pas celle de Vanguard (rien n'a été fait).
const LISTE_REFUSEE: i32 = 8;
/// Sortie du fils : il ne tourne pas en root.
const SANS_DROITS: i32 = 9;

/// Ce que le parent demande au fils : un ordre du blocage, ou un geste de Linux. Les deux grammaires se partagent le
/// canal et ses bornes (`ordres::LIGNE_MAX`, `ordres::LIGNES_MAX`) sans se recouvrir : « vanguard:geste » n'est le
/// verbe d'aucun ordre.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Demande {
    Ordre(Ordre),
    Geste(GesteUnix),
}

impl Demande {
    /// La demande que porte une ligne, relue exactement ; une ligne qui commence comme un geste n'est jamais lue
    /// comme un ordre.
    pub(crate) fn analyser(ligne: &str) -> Option<Demande> {
        if gestes_unix::a_le_prefixe(ligne) {
            gestes_unix::analyser(ligne).map(Demande::Geste)
        } else {
            ordres::analyser(ligne).map(Demande::Ordre)
        }
    }

    pub(crate) fn ligne(&self) -> String {
        match self {
            Demande::Ordre(o) => o.ligne(),
            Demande::Geste(g) => g.ligne(),
        }
    }

    /// Ce que fait la demande, dans la langue de la personne.
    pub(crate) fn texte(&self) -> String {
        match self {
            Demande::Ordre(o) => o.texte(),
            Demande::Geste(g) => texte_du_geste(*g),
        }
    }

    fn permis_ici(&self) -> bool {
        match self {
            Demande::Ordre(o) => o.permis_ici(),
            Demande::Geste(g) => g.permis_ici(),
        }
    }

    /// Le fils demandera-t-il l'accord de la personne sur son terminal (`GesteUnix::demande_accord`) ?
    fn demande_accord(&self) -> bool {
        match self {
            Demande::Ordre(_) => false,
            Demande::Geste(g) => g.demande_accord(),
        }
    }
}

fn texte_du_geste(g: GesteUnix) -> String {
    let (fr, en) = g.phrase();
    if crate::langue::anglais() { en } else { fr }
}

/// Une façon d'obtenir les droits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Methode {
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Pkexec,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Run0,
    Sudo,
}

impl Methode {
    fn nom(self) -> &'static str {
        match self {
            Methode::Pkexec => "pkexec",
            Methode::Run0 => "run0",
            Methode::Sudo => "sudo",
        }
    }
}

/// Un programme du système par son chemin (`commande::outil_systeme`).
fn outil(nom: &str) -> Option<std::path::PathBuf> {
    crate::commande::outil_systeme(nom)
}

/// Un terminal où demander le mot de passe : le terminal de contrôle de ce processus.
fn terminal() -> bool {
    // En lecture seule : l'ouvrir suffit à savoir qu'il y en a un (ENXIO sinon).
    std::fs::File::open("/dev/tty").is_ok()
}

/// Les façons possibles ici, dans l'ordre où les essayer. `accord` : un geste de la liste demande l'accord de la
/// personne sur son terminal (/dev/tty, dans le fils). pkexec et run0 n'en donnent pas au programme élevé (run0 avec
/// nos tubes passe en mode tube, sans terminal de contrôle pour le fils) : seul sudo, lancé depuis un terminal, le
/// permet (avec use_pty, le fils a un terminal relayé) ; sinon aucune, et `sans_methode` dit pourquoi.
fn methodes(graphique: bool, terminal: bool, accord: bool, existe: impl Fn(&str) -> bool) -> Vec<Methode> {
    if accord {
        return if terminal && existe("sudo") {
            vec![Methode::Sudo]
        } else {
            Vec::new()
        };
    }
    let mut m = Vec::new();
    if cfg!(target_os = "linux") {
        if graphique && existe("pkexec") {
            m.push(Methode::Pkexec);
        }
        if terminal && existe("run0") {
            m.push(Methode::Run0);
        }
    }
    if existe("sudo") {
        m.push(Methode::Sudo);
    }
    m
}

/// Le programme et tous ses dossiers appartiennent-ils à root, sans écriture pour le groupe ni les autres ? Alors
/// personne d'autre que root ne peut le remplacer entre l'accord et son lancement par chemin (macOS, ou pkexec qui
/// résout `/proc/<pid>/exe` en chemin réel avant de l'exécuter). Un programme dans un dossier du compte
/// (Téléchargements, la clé) ne l'est pas.
fn chemin_sur(chemin: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mut courant = Some(chemin);
    while let Some(c) = courant {
        let Ok(m) = std::fs::metadata(c) else {
            return false;
        };
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return false;
        }
        courant = c.parent().filter(|p| !p.as_os_str().is_empty());
    }
    true
}

/// L'image qui tourne est-elle à l'abri d'un remplacement par chemin (`chemin_sur`) ?
fn image_sure() -> bool {
    std::env::current_exe().is_ok_and(|c| chemin_sur(&c))
}

/// Le programme à relancer : l'image qui tourne (Linux), ou son chemin (macOS, sans /proc).
fn programme() -> Option<std::ffi::OsString> {
    if cfg!(target_os = "linux") {
        Some(format!("/proc/{}/exe", std::process::id()).into())
    } else {
        std::env::current_exe().ok().map(std::path::PathBuf::into_os_string)
    }
}

/// La ligne de commande de l'élévation, sans la lancer.
fn commande(m: Methode, chemin_outil: &std::path::Path, programme: &std::ffi::OsStr, terminal: bool) -> Command {
    let mut c = Command::new(chemin_outil);
    // L'outil d'élévation lui-même, dans un environnement propre : run0 n'est pas setuid (un LD_PRELOAD de la session
    // s'y chargerait, et c'est lui qui dit à systemd quoi lancer en root), et sudo lit SUDO_PROMPT (le texte de
    // l'invite du mot de passe) ; la langue et le terminal suffisent à l'invite de sudo et à l'agent de run0.
    crate::commande::environnement_propre(&mut c, std::env::vars_os());
    match m {
        // Sans son agent de secours dans le terminal : sans agent graphique, pkexec rend 127, et run0 ou sudo prend
        // la suite.
        Methode::Pkexec => {
            c.arg("--disable-internal-agent");
        }
        // Sans terminal, sudo seulement si le mot de passe n'est pas à demander (déjà donné, ou NOPASSWD).
        Methode::Sudo if !terminal => {
            c.args(["-n", "--"]);
        }
        Methode::Run0 | Methode::Sudo => {
            c.arg("--");
        }
    }
    c.arg(programme);
    c.args([
        "appliquer-eleve",
        "--langue",
        if crate::langue::anglais() { "en" } else { "fr" },
        "--parent",
        &std::process::id().to_string(),
    ]);
    c
}

/// Ce qu'une tentative a donné.
enum Issue {
    Fait(Vec<Vec<Resultat>>),
    /// La personne a refusé, ou le mot de passe n'a pas été donné : rien n'a été fait, sans redemander.
    Refuse,
    /// Cette façon ne marche pas ici (pas d'agent polkit) : la suivante peut l'être.
    Indisponible,
}

/// Le texte envoyé au fils : les demandes, groupe après groupe, séparées par « suite », puis « fin ».
fn envoi(groupes: &[Vec<Demande>]) -> String {
    let mut t = String::new();
    for (i, g) in groupes.iter().enumerate() {
        if i > 0 {
            t += SUITE;
            t.push('\n');
        }
        for o in g {
            t += &o.ligne();
            t.push('\n');
        }
    }
    t + FIN + "\n"
}

/// Les lignes reçues jusqu'à « fin », bornées en nombre et en longueur ; `None` si le flux s'arrête avant.
fn lire_lignes(source: impl Read) -> Option<Vec<String>> {
    let borne = u64::try_from((2 * LIGNES_MAX + 2) * (LIGNE_MAX + 2)).ok()?;
    let mut lecteur = BufReader::new(source.take(borne));
    let mut lignes = Vec::new();
    loop {
        let mut ligne = String::new();
        if lecteur.read_line(&mut ligne).ok()? == 0 {
            return None;
        }
        let ligne = ligne.trim_end_matches(['\r', '\n']).to_string();
        if ligne == FIN {
            return Some(lignes);
        }
        if ligne.len() > LIGNE_MAX || lignes.len() > 2 * LIGNES_MAX {
            return None;
        }
        lignes.push(ligne);
    }
}

/// La liste reçue, relue : des groupes d'ordres et de gestes des listes fermées, permis sur ce système ; `None` dès
/// qu'une ligne n'en est pas un, qu'un groupe est vide, ou qu'il y en a trop.
fn analyser_liste(lignes: &[String]) -> Option<Vec<Vec<Demande>>> {
    let mut groupes = vec![Vec::new()];
    let mut total = 0;
    for l in lignes {
        if l == SUITE {
            groupes.push(Vec::new());
            continue;
        }
        let o = Demande::analyser(l).filter(Demande::permis_ici)?;
        total += 1;
        groupes.last_mut()?.push(o);
    }
    (total > 0 && total <= LIGNES_MAX && groupes.iter().all(|g| !g.is_empty())).then_some(groupes)
}

/// Tout « non fait », avec la même raison.
fn tous_en_echec<D>(groupes: &[Vec<D>], raison: &str) -> Vec<Vec<Resultat>> {
    groupes
        .iter()
        .map(|g| g.iter().map(|_| Resultat::echec(raison)).collect())
        .collect()
}

/// Les réponses du fils, rangées dans les groupes ; `None` si leur nombre n'est pas celui des ordres.
fn ranger<D>(groupes: &[Vec<D>], reponses: &[String]) -> Option<Vec<Vec<Resultat>>> {
    let total: usize = groupes.iter().map(Vec::len).sum();
    if reponses.len() != total {
        return None;
    }
    let mut r = reponses.iter();
    Some(
        groupes
            .iter()
            .map(|g| {
                g.iter()
                    .filter_map(|_| r.next().map(|l| ordres::lire_reponse(&crate::ui::affichable(l))))
                    .collect()
            })
            .collect(),
    )
}

fn essayer(m: Methode, groupes: &[Vec<Demande>]) -> Issue {
    let (Some(chemin), Some(programme)) = (outil(m.nom()), programme()) else {
        return Issue::Indisponible;
    };
    // pkexec exécute le chemin réel du programme, et macOS n'a pas de /proc : par chemin, seulement un programme que
    // le compte ne peut pas remplacer.
    let par_chemin = m == Methode::Pkexec || cfg!(not(target_os = "linux"));
    if par_chemin && !image_sure() {
        return Issue::Indisponible;
    }
    let terminal = terminal();
    trp!(
        "    {GRIS}Droits d'administrateur demandés par {} : Vanguard fera lui-même les gestes montrés, et rien d'autre.{RESET}",
        "    {GRIS}Administrator rights asked through {}: Vanguard itself will do the steps shown, and nothing else.{RESET}",
        m.nom()
    );
    let Ok(mut fils) = commande(m, &chemin, &programme, terminal)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    else {
        return Issue::Indisponible;
    };
    let (Some(mut entree), Some(sortie)) = (fils.stdin.take(), fils.stdout.take()) else {
        crate::commande::arreter(&mut fils);
        return Issue::Indisponible;
    };
    let mut lecteur = BufReader::new(sortie.take(u64::try_from((LIGNES_MAX + 4) * (LIGNE_MAX + 2)).unwrap_or(0)));
    // Pas de délai : la personne tape son mot de passe. Le fils mort sans s'être dit prêt ferme le tube.
    let mut premiere = String::new();
    let pret = lecteur.read_line(&mut premiere).is_ok_and(|n| n > 0) && premiere.trim_end() == PRET;
    if !pret {
        drop(entree);
        let code = fils.wait().ok().and_then(|s| s.code());
        return match (m, code) {
            // pkexec : 126, la personne a fermé la fenêtre ; 127, pas d'agent, ou pas autorisé : on essaie la suite.
            (Methode::Pkexec, Some(127)) => Issue::Indisponible,
            _ => Issue::Refuse,
        };
    }
    let envoye = entree
        .write_all(envoi(groupes).as_bytes())
        .and_then(|()| entree.flush());
    drop(entree);
    let reponses = if envoye.is_ok() {
        lire_lignes(&mut lecteur)
    } else {
        None
    };
    let _ = fils.wait();
    match reponses.and_then(|r| ranger(groupes, &r)) {
        Some(r) => Issue::Fait(r),
        None => Issue::Fait(tous_en_echec(
            groupes,
            tr!(
                "l'assistant administrateur n'a pas répondu jusqu'au bout : compté comme non fait",
                "the administrator helper did not answer to the end: counted as not done"
            ),
        )),
    }
}

/// Fait ces groupes de demandes avec les droits d'administrateur : ici même si Vanguard tourne déjà en root, sinon
/// par l'assistant élevé, une seule demande pour tous. Une réponse par demande, dans l'ordre reçu ; une demande de
/// droits refusée rend tout « non fait », sans redemander.
pub(crate) fn appliquer(groupes: &[Vec<Demande>]) -> Vec<Vec<Resultat>> {
    if crate::socle::euid() == 0 {
        let juge = ordres::Juge::lire(None);
        // Les gestes viennent d'être montrés (`machine::lancer_les_ordres`) : seulement leur issue. L'accord d'un geste
        // qui affaiblit se demande ici aussi sur le terminal : être root ne dit pas que la personne est d'accord.
        return executer_demandes(groupes, &juge, &mut Systeme, &mut |t| {
            if !t.starts_with("> ") {
                let _ = writeln!(std::io::stdout(), "    {GRIS}{t}{RESET}");
            }
        });
    }
    // Les essais ne lancent jamais pkexec, run0 ni sudo pour de vrai.
    if cfg!(test) {
        return tous_en_echec(groupes, "essai : aucune élévation");
    }
    let graphique = std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
    let accord = groupes.iter().flatten().any(Demande::demande_accord);
    let terminal = terminal();
    let possibles = methodes(graphique, terminal, accord, |n| outil(n).is_some());
    // Pendant le dialogue, plus aucun processus du compte ne peut ouvrir nos tubes par /proc/<pid>/fd ni s'attacher
    // à nous (ptrace) pour glisser une autre liste au fils, ou lui répondre à sa place : un processus non
    // « dumpable » n'est plus accessible qu'à root.
    let _garde = Inaccessible::poser();
    if cfg!(not(target_os = "linux")) && !image_sure() {
        let raison = tr!(
            "Vanguard tourne depuis un dossier que ce compte peut modifier : il ne se relance pas en administrateur par son chemin (il pourrait être remplacé entre-temps). Installez-le dans /Applications ou /usr/local/bin, ou lancez-le avec sudo",
            "Vanguard runs from a folder this account can change: it does not relaunch itself as administrator by its path (it could be replaced meanwhile). Install it in /Applications or /usr/local/bin, or start it with sudo"
        );
        trp!("    ✖ {}", "    ✖ {}", raison);
        return tous_en_echec(groupes, raison);
    }
    for m in possibles {
        match essayer(m, groupes) {
            Issue::Fait(r) => return r,
            Issue::Refuse => {
                trp!(
                    "    Droits d'administrateur non obtenus ({}) : rien n'a été modifié.",
                    "    Administrator rights not obtained ({}): nothing was changed.",
                    m.nom()
                );
                return tous_en_echec(
                    groupes,
                    tr!("droits d'administrateur refusés", "administrator rights refused"),
                );
            }
            Issue::Indisponible => {}
        }
    }
    let raison = sans_methode(accord, terminal);
    trp!("    ✖ {}", "    ✖ {}", raison);
    tous_en_echec(groupes, raison)
}

/// Pourquoi aucune façon d'obtenir les droits n'a marché, en nommant celles qui ne pouvaient pas servir.
fn sans_methode(accord: bool, terminal: bool) -> &'static str {
    match (accord, terminal) {
        (true, true) => tr!(
            "un geste demande votre accord dans le terminal, et seul sudo le permet (pkexec et run0 ne donnent pas de terminal au programme administrateur) ; sudo n'est pas installé : rien n'a été fait",
            "a step needs your agreement in the terminal, and only sudo allows it (pkexec and run0 give no terminal to the administrator program); sudo is not installed: nothing was done"
        ),
        (true, false) => tr!(
            "un geste demande votre accord dans un terminal, et Vanguard n'a pas été lancé depuis un terminal (pkexec et run0 n'en donnent pas au programme administrateur, seul sudo dans un terminal le permet) : rien n'a été fait. Lancez Vanguard depuis un terminal",
            "a step needs your agreement in a terminal, and Vanguard was not started from a terminal (pkexec and run0 give none to the administrator program, only sudo in a terminal allows it): nothing was done. Start Vanguard from a terminal"
        ),
        (false, _) => tr!(
            "aucun moyen d'obtenir les droits d'administrateur ici (ni pkexec avec un agent polkit, ni run0, ni sudo) : rien n'a été fait",
            "no way to get administrator rights here (neither pkexec with a polkit agent, nor run0, nor sudo): nothing was done"
        ),
    }
}

/// Rend ce processus inaccessible au compte (PR_SET_DUMPABLE à 0) le temps du dialogue avec le fils, puis le remet.
struct Inaccessible(#[cfg_attr(not(target_os = "linux"), allow(dead_code))] bool);

impl Inaccessible {
    fn poser() -> Inaccessible {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: prctl sans pointeur ; PR_GET_DUMPABLE rend 0 ou 1, PR_SET_DUMPABLE prend 0 ou 1.
            let avant = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) } == 1;
            // SAFETY: voir ci-dessus.
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
            Inaccessible(avant)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Inaccessible(false)
        }
    }
}

impl Drop for Inaccessible {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if self.0 {
            // SAFETY: prctl sans pointeur.
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
        }
    }
}

// ------------------------------------------------------------------ le fils

/// La sous-commande `appliquer-eleve` sous Linux et macOS : rend le code de sortie du processus.
pub(crate) fn executer(langue: Option<&str>, parent: Option<u32>) -> i32 {
    if let Some(l) = langue {
        crate::langue::forcer(l == "en");
    }
    if crate::socle::euid() != 0 {
        let _ = writeln!(
            std::io::stderr(),
            "{}",
            tr!(
                "Ce processus n'a pas les droits d'administrateur : rien n'est fait.",
                "This process has no administrator rights: nothing is done."
            )
        );
        return SANS_DROITS;
    }
    let mut sortie = std::io::stdout().lock();
    if writeln!(sortie, "{PRET}").and_then(|()| sortie.flush()).is_err() {
        return SANS_DROITS;
    }
    let Some(lignes) = lire_lignes(std::io::stdin().lock()) else {
        return LISTE_REFUSEE;
    };
    let Some(groupes) = analyser_liste(&lignes) else {
        let _ = writeln!(
            std::io::stderr(),
            "{}",
            tr!(
                "La liste reçue n'est pas une liste de gestes de Vanguard : rien n'est fait. Un autre programme y a touché : lancez une analyse antivirus.",
                "The list received is not a Vanguard step list: nothing is done. Another program touched it: run an antivirus scan."
            )
        );
        let _ = writeln!(sortie, "{FIN}");
        return LISTE_REFUSEE;
    };
    let _ = writeln!(
        std::io::stderr(),
        "{}",
        tr!(
            "Vanguard (administrateur) va faire :",
            "Vanguard (administrator) will do:"
        )
    );
    for o in groupes.iter().flatten() {
        let _ = writeln!(std::io::stderr(), "  · {}", o.texte());
    }
    let juge = ordres::Juge::lire(parent);
    // Jamais `eprintln!` dans le fils : une sortie d'erreur fermée (fenêtre du terminal fermée) le ferait paniquer,
    // peut-être après l'arrêt d'un service.
    let resultats = executer_demandes(&groupes, &juge, &mut Systeme, &mut |t| {
        let _ = writeln!(std::io::stderr(), "{t}");
    });
    let mut code = 0;
    for r in resultats.iter().flatten() {
        if !r.reussi {
            code = 1;
        }
        if writeln!(sortie, "{}", ordres::ligne_reponse(r)).is_err() {
            return 1;
        }
    }
    let _ = writeln!(sortie, "{FIN}");
    let _ = sortie.flush();
    code
}

/// Pourquoi un geste qui demande l'accord n'est pas fait (pas de terminal, pas de « oui ») : dit tel quel.
#[derive(Debug)]
struct Refus(String);

/// Fait les demandes, groupe par groupe (`ordres::executer_en_groupes`) : un ordre est rejugé puis fait ; un geste
/// est rejugé dans `monde` (`faire_geste`), puis fait.
fn executer_demandes(
    groupes: &[Vec<Demande>],
    juge: &ordres::Juge,
    monde: &mut dyn Monde,
    annoncer: &mut dyn FnMut(&str),
) -> Vec<Vec<Resultat>> {
    ordres::executer_en_groupes(
        groupes,
        Demande::texte,
        |d| match d {
            Demande::Ordre(o) => ordres::juger_et_faire(o, juge),
            Demande::Geste(g) => faire_geste(*g, monde),
        },
        annoncer,
    )
}

/// Ce que le fils lit et fait de l'ordinateur pour un geste : le vrai (`Systeme`), ou un faux monde sous les essais,
/// pour éprouver l'ordre des vérifications sans rien toucher.
trait Monde {
    /// L'accord de la personne pour un geste qui baisse une protection (`accord_au_terminal`).
    fn accord(&mut self, g: GesteUnix) -> Result<(), Refus>;
    /// systemd gère-t-il ce système ?
    fn systemd(&self) -> bool;
    /// Une session à distance entrante est-elle ouverte (SSH ou Bureau à distance reçus, logiciel de prise de contrôle
    /// connecté) ? `None` : les connexions en cours ne se lisent pas.
    fn session_entrante(&self) -> Option<bool>;
    /// Le fichier de l'unité est-il celui de root, dans un dossier du système, fermé aux autres comptes, lien compris
    /// (`fichier_d_unite_sur`) ?
    fn fichier_sur(&self, unite: &str) -> Result<(), Echec>;
    /// L'état du fichier de l'unité (« enabled », « disabled »…) ; `None` : aucun fichier de ce nom.
    fn etat_du_fichier(&mut self, unite: &str) -> Result<Option<String>, Echec>;
    fn unite(&mut self, action: ActionUnite, unite: &str) -> Result<(), Echec>;
    fn reinitialiser_echecs(&mut self) -> Result<(), Echec>;
    fn programme(&mut self, p: &'static Programme) -> Resultat;
}

/// Le vrai ordinateur : le bus système (joint de nouveau pour chaque geste : un job long ne garde pas une prise
/// ouverte d'un geste à l'autre), les connexions en cours, le terminal de la personne.
struct Systeme;

impl Monde for Systeme {
    fn accord(&mut self, g: GesteUnix) -> Result<(), Refus> {
        accord_au_terminal(g)
    }

    fn systemd(&self) -> bool {
        #[cfg(target_os = "linux")]
        return crate::machine::linux::dbus::systeme::systemd_present();
        #[cfg(not(target_os = "linux"))]
        false
    }

    fn session_entrante(&self) -> Option<bool> {
        #[cfg(target_os = "linux")]
        return crate::protection::blocage::session_entrante_ouverte();
        // Ailleurs, aucun geste ne coupe le réseau (`permis_ici`) : jamais lu.
        #[cfg(not(target_os = "linux"))]
        None
    }

    fn fichier_sur(&self, unite: &str) -> Result<(), Echec> {
        let dossiers = DOSSIERS_D_UNITES.map(std::path::Path::new);
        fichier_d_unite_sur(&dossiers, std::path::Path::new("/"), unite, 0)
    }

    fn etat_du_fichier(&mut self, unite: &str) -> Result<Option<String>, Echec> {
        #[cfg(target_os = "linux")]
        {
            use crate::machine::linux::dbus::systeme;
            systeme::bus_pour_agir().and_then(|mut bus| systeme::etat_du_fichier(&mut bus, unite))
        }
        #[cfg(not(target_os = "linux"))]
        Err(refus(format!("{unite} : {}", sans_systemd())))
    }

    fn unite(&mut self, action: ActionUnite, unite: &str) -> Result<(), Echec> {
        #[cfg(target_os = "linux")]
        {
            use crate::machine::linux::dbus::systeme;
            systeme::bus_pour_agir().and_then(|mut bus| systeme::agir_sur_unite(&mut bus, action, unite))
        }
        #[cfg(not(target_os = "linux"))]
        Err(refus(format!("{unite} {} : {}", action.mot(), sans_systemd())))
    }

    fn reinitialiser_echecs(&mut self) -> Result<(), Echec> {
        #[cfg(target_os = "linux")]
        {
            use crate::machine::linux::dbus::systeme;
            systeme::bus_pour_agir().and_then(|mut bus| systeme::reinitialiser_echecs(&mut bus))
        }
        #[cfg(not(target_os = "linux"))]
        Err(Echec::refuse(CONTEXTE, sans_systemd()))
    }

    fn programme(&mut self, p: &'static Programme) -> Resultat {
        lancer_programme(p)
    }
}

/// Le contexte des échecs d'un geste d'unité, pour le journal des erreurs.
const CONTEXTE: &str = "assistant/unite";

/// Un refus de l'assistant, sa phrase déjà dans la langue de l'interface.
fn refus(phrase: String) -> Echec {
    Echec::refuse(CONTEXTE, phrase)
}

/// Pourquoi un geste de systemd n'est pas fait ici.
fn sans_systemd() -> &'static str {
    tr!(
        "cet ordinateur n'utilise pas le gestionnaire de services habituel (systemd) : Vanguard ne sait pas y changer les services, rien n'est fait",
        "this computer does not use the usual service manager (systemd): Vanguard cannot change its services, nothing is done"
    )
}

/// Où le fils cherche le fichier d'une unité désignée par son nom, dans l'ordre de systemd : celui de
/// l'administrateur, puis ceux des logiciels installés à la main, puis ceux des paquets (/lib : distributions où il
/// n'est pas un lien vers /usr/lib).
const DOSSIERS_D_UNITES: [&str; 4] = [
    "/etc/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

/// Le fichier de l'unité `nom` dans le premier de `dossiers` qui l'a : un fichier ordinaire de `proprietaire` (root),
/// que ni son groupe ni les autres ne peuvent modifier. Un lien (`systemctl link`) n'est suivi que vers un tel fichier
/// dont chaque dossier, jusqu'à `racine` (« / ») comprise, est aussi à `proprietaire` et fermé aux autres : sinon un
/// autre compte pourrait changer ce que l'unité lance. Un fichier refusé ne fait pas chercher dans le dossier suivant.
fn fichier_d_unite_sur(
    dossiers: &[&std::path::Path],
    racine: &std::path::Path,
    nom: &str,
    proprietaire: u32,
) -> Result<(), Echec> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let vu = crate::ui::affichable(nom);
    if !gestes_unix::nom_admis(nom) {
        return Err(refus(trf!(
            "nom de service refusé ({vu}) : rien n'est fait",
            "service name refused ({vu}): nothing is done"
        )));
    }
    let douteux = || {
        refus(trf!(
            "le fichier du service {vu} n'est pas un fichier de l'administrateur fermé aux autres comptes (lui, ou un dossier qui le contient, est modifiable par un autre compte) : rien n'est fait",
            "the file of the service {vu} is not an administrator file closed to other accounts (it, or a folder holding it, is writable by another account): nothing is done"
        ))
    };
    let a_lui = |m: &std::fs::Metadata| m.uid() == proprietaire && m.mode() & 0o022 == 0;
    for dossier in dossiers {
        let chemin = dossier.join(nom);
        let vu_du_lien = match std::fs::symlink_metadata(&chemin) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(douteux()),
        };
        let fichier = if vu_du_lien.file_type().is_symlink() {
            let racine = std::fs::canonicalize(racine).map_err(|_| douteux())?;
            let cible = std::fs::canonicalize(&chemin).map_err(|_| douteux())?;
            // La cible a tous ses liens résolus : chacun de ses dossiers est vu tel qu'il est. Un dossier à root et
            // fermé aux autres ne peut pas être remplacé entre ce regard et l'ouverture.
            let dossiers_surs = cible.starts_with(&racine)
                && cible
                    .ancestors()
                    .skip(1)
                    .filter(|d| d.starts_with(&racine))
                    .all(|d| std::fs::metadata(d).is_ok_and(|m| m.is_dir() && a_lui(&m)));
            if vu_du_lien.uid() != proprietaire || !dossiers_surs {
                return Err(douteux());
            }
            cible
        } else {
            chemin
        };
        // Sans suivre de lien (O_NOFOLLOW : un fichier remplacé par un lien depuis le regard est refusé), sans
        // attendre si c'est un tube (O_NONBLOCK).
        let ouvert = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&fichier)
            .map_err(|_| douteux())?;
        let m = ouvert.metadata().map_err(|_| douteux())?;
        return if m.is_file() && a_lui(&m) {
            Ok(())
        } else {
            Err(douteux())
        };
    }
    Err(refus(trf!(
        "aucun fichier du service {vu} dans les dossiers du système : rien n'est fait",
        "no file for the service {vu} in the system folders: nothing is done"
    )))
}

/// Une unité désignée par le parent, revue par le fils avant d'y toucher (P5 du lot U3) : un logiciel de prise de
/// contrôle à distance reconnu, au fichier sûr, activé au démarrage. Le parent l'a trouvée ainsi ; le fils ne le
/// croit pas sur parole.
fn designee_revue(nom: &str, monde: &mut dyn Monde) -> Result<(), Echec> {
    let vu = crate::ui::affichable(nom);
    if !crate::protection::distance::controle_a_distance(nom) {
        return Err(refus(trf!(
            "{vu} n'est pas un logiciel de prise de contrôle à distance connu de Vanguard : rien n'est fait",
            "{vu} is not a remote control tool known to Vanguard: nothing is done"
        )));
    }
    monde.fichier_sur(nom)?;
    match monde.etat_du_fichier(nom)? {
        Some(etat) if etat == "enabled" => Ok(()),
        _ => Err(refus(trf!(
            "{vu} n'est pas lancé au démarrage : rien n'est fait",
            "{vu} is not started at boot: nothing is done"
        ))),
    }
}

/// Aucune session à distance entrante n'est ouverte ; sinon la raison du refus (une ouverte, ou des connexions qui ne
/// se lisent pas).
fn aucune_session_entrante(monde: &dyn Monde) -> Result<(), &'static str> {
    match monde.session_entrante() {
        Some(false) => Ok(()),
        Some(true) => Err(tr!(
            "une session à distance entrante est ouverte sur cet ordinateur, et ce geste pourrait la couper : rien n'est fait. Refaites-le une fois la session fermée",
            "an incoming remote session is open on this computer, and this step could cut it: nothing is done. Do it again once the session is closed"
        )),
        None => Err(tr!(
            "les connexions en cours ne se lisent pas : sans savoir si une session à distance passe par là, rien n'est fait",
            "the current connections cannot be read: without knowing whether a remote session goes through it, nothing is done"
        )),
    }
}

/// Un geste de Linux, rejugé ici avant d'être fait, dans cet ordre : permis sur ce système, jamais refusé
/// (`GesteUnix::refus`), systemd présent s'il en faut, aucune session à distance qu'il couperait, l'unité désignée
/// revue, puis l'accord de la personne s'il en demande un.
fn faire_geste(g: GesteUnix, monde: &mut dyn Monde) -> Resultat {
    if !g.permis_ici() {
        return Resultat::echec(tr!(
            "ce geste n'est pas prévu sur ce système : rien n'est fait",
            "this step is not meant for this system: nothing is done"
        ));
    }
    if let Some((fr, en)) = g.refus() {
        return Resultat::echec(if crate::langue::anglais() { en } else { fr });
    }
    if g.par_systemd() && !monde.systemd() {
        return Resultat::echec(sans_systemd());
    }
    if g.coupe_session()
        && let Err(raison) = aucune_session_entrante(monde)
    {
        return Resultat::echec(raison);
    }
    if let GesteUnix::Designee(_, nom) = g
        && let Err(raison) = designee_revue(nom.as_str(), monde)
    {
        return Resultat::echec(raison);
    }
    if g.demande_accord()
        && let Err(Refus(raison)) = monde.accord(g)
    {
        return Resultat::echec(raison);
    }
    // La question a pu attendre longtemps : une session ouverte entre-temps compte aussi.
    if g.coupe_session()
        && g.demande_accord()
        && let Err(raison) = aucune_session_entrante(monde)
    {
        return Resultat::echec(raison);
    }
    let fait = |r: Result<(), Echec>| r.map_or_else(Resultat::echec, |()| Resultat::ok());
    match g {
        GesteUnix::Programme(p) => monde.programme(p),
        GesteUnix::Unite(a, u) => fait(monde.unite(a, u.nom)),
        GesteUnix::Designee(a, nom) => fait(monde.unite(a, nom.as_str())),
        GesteUnix::ReinitialiserEchecs => fait(monde.reinitialiser_echecs()),
        GesteUnix::SignaturesClamav => signatures_clamav(monde),
    }
}

/// `signatures-clamav` : le service de mise à jour, s'il est installé, verrouille la base pendant qu'il tourne ; il
/// est arrêté le temps de freshclam, puis remis en route, même si freshclam a échoué : jamais laissé arrêté. Ni un
/// signal de fin (terminal fermé, Ctrl+C), ni une panique, ni un arrêt refusé ne sautent la remise en route. Masqué
/// par l'administrateur, il n'est pas touché, et c'est noté.
fn signatures_clamav(monde: &mut dyn Monde) -> Resultat {
    let service = gestes_unix::CLAMAV_FRESHCLAM.nom;
    let etat = match monde.etat_du_fichier(service) {
        Ok(e) => e,
        Err(raison) => return Resultat::echec(raison),
    };
    let masque = etat.as_deref() == Some("masked");
    if etat.is_none() || masque {
        let r = monde.programme(&gestes_unix::FRESHCLAM);
        return if r.reussi && masque {
            Resultat::ok_note(tr!(
                "mise à jour automatique masquée par l'administrateur : laissée telle quelle",
                "automatic update masked by the administrator: left as is"
            ))
        } else {
            r
        };
    }
    // Posés avant l'arrêt, retirés après la remise en route (ordre inverse des `let`) : entre les deux, la fenêtre
    // fermée ne tue plus l'assistant au milieu.
    let _signaux = SignauxIgnores::poser();
    let mut relance = Relance {
        monde,
        service,
        faite: false,
    };
    // Un arrêt en échec n'arrête pas la suite : le service a pu s'arrêter quand même, ou ne tenir aucun verrou ;
    // freshclam le dira s'il bute dessus, et le service est remis en route dans tous les cas.
    let arret = relance.monde.unite(ActionUnite::Arreter, service);
    let r = relance.monde.programme(&gestes_unix::FRESHCLAM);
    let reprise = remettre_en_route(relance.monde, service);
    relance.faite = true;
    match (r.reussi, reprise, arret) {
        (true, Ok(()), _) => Resultat::ok(),
        (false, Ok(()), Ok(())) => r,
        (false, Ok(()), Err(a)) => Resultat::echec(trf!(
            "{} (le service de mise à jour automatique ne s'était pas arrêté : {a})",
            "{} (the automatic update service had not stopped: {a})",
            r.raison
        )),
        (true, Err(raison), _) => Resultat::echec(trf!(
            "signatures à jour, mais leur mise à jour automatique n'a pas repris : {raison}",
            "signatures up to date, but their automatic update did not resume: {raison}"
        )),
        (false, Err(raison), _) => Resultat::echec(trf!(
            "{} ; et la mise à jour automatique n'a pas repris : {raison}",
            "{}; and the automatic update did not resume: {raison}",
            r.raison
        )),
    }
}

/// Remet en route le service de mise à jour : activé et démarré ; si l'activation échoue, au moins démarré. L'erreur
/// rendue est celle de l'activation.
fn remettre_en_route(monde: &mut dyn Monde, service: &str) -> Result<(), Echec> {
    monde
        .unite(ActionUnite::Activer, service)
        .or_else(|e| monde.unite(ActionUnite::Demarrer, service).map_err(|_| e))
}

/// Remet le service en route s'il est quitté avant la fin (`faite` encore faux) : une panique, ou un retour ajouté
/// plus tard au milieu, ne le laissent pas arrêté.
struct Relance<'a> {
    monde: &'a mut dyn Monde,
    service: &'static str,
    faite: bool,
}

impl Drop for Relance<'_> {
    fn drop(&mut self) {
        if !self.faite {
            let _ = remettre_en_route(self.monde, self.service);
        }
    }
}

/// Les signaux qui finiraient l'assistant : la fenêtre du terminal fermée (SIGHUP), Ctrl+C (SIGINT), un arrêt
/// demandé (SIGTERM). freshclam hérite de leur ignorance ; `commande::lancer` le tue à son délai par SIGKILL, qui ne
/// s'ignore pas.
const SIGNAUX_DE_FIN: [libc::c_int; 3] = [libc::SIGHUP, libc::SIGINT, libc::SIGTERM];

/// Ignore `SIGNAUX_DE_FIN` tant qu'elle vit, puis remet chacun comme il était.
struct SignauxIgnores(Vec<(libc::c_int, libc::sigaction)>);

impl SignauxIgnores {
    fn poser() -> SignauxIgnores {
        let mut avant = Vec::new();
        for signal in SIGNAUX_DE_FIN {
            // SAFETY: sigaction est une structure C sans invariant : tout à zéro est valide (masque vide, aucun
            // drapeau).
            let mut ignore: libc::sigaction = unsafe { std::mem::zeroed() };
            ignore.sa_sigaction = libc::SIG_IGN;
            // SAFETY: voir ci-dessus.
            let mut ancien: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: deux pointeurs vers des structures vivantes de la pile, le temps de l'appel ; SIG_IGN ne fait
            // tourner aucun code de Vanguard dans un gestionnaire.
            if unsafe { libc::sigaction(signal, &raw const ignore, &raw mut ancien) } == 0 {
                avant.push((signal, ancien));
            }
        }
        SignauxIgnores(avant)
    }
}

impl Drop for SignauxIgnores {
    fn drop(&mut self) {
        for (signal, ancien) in &self.0 {
            // SAFETY: `ancien` vit le temps de l'appel ; c'est la disposition rendue par le noyau à la pose.
            unsafe { libc::sigaction(*signal, ancien, std::ptr::null_mut()) };
        }
    }
}

/// Les variables que l'outil reçoit de l'assistant : sa langue et son terminal, rien d'autre (ni HOME, ni le bus de
/// la session : il tourne en root, pour le système).
fn langue_ou_terminal(nom: &std::ffi::OsStr) -> bool {
    nom.to_str()
        .is_some_and(|n| n == "LANG" || n == "TERM" || n.strip_prefix("LC_").is_some_and(|r| !r.is_empty()))
}

/// Lance un programme de la table par le chemin absolu de son outil, avec ses arguments figés, dans un environnement
/// vidé ; seul un code de `reussites` dit « fait », et un échec dit pourquoi.
fn lancer_programme(p: &Programme) -> Resultat {
    let Some(chemin) = crate::commande::outil_systeme(p.outil) else {
        return Resultat::echec(trf!(
            "{} n'est pas installé dans les dossiers du système : rien n'est fait",
            "{} is not installed in the system folders: nothing is done",
            p.outil
        ));
    };
    let mut c = Command::new(&chemin);
    c.args(p.arguments);
    crate::commande::environnement_propre(&mut c, std::env::vars_os().filter(|(n, _)| langue_ou_terminal(n)));
    // Un outil long (freshclam : jusqu'à 15 min sur une ligne lente) le dit avant de partir : sans un mot, la personne
    // croirait Vanguard figé et fermerait la fenêtre. Sur la sortie d'erreur : la sortie standard porte les réponses
    // au parent.
    if p.delai >= 60 {
        // Jamais `eprintln!` : une sortie d'erreur fermée (fenêtre du terminal fermée) le ferait paniquer, après
        // l'arrêt d'un service.
        let _ = writeln!(
            std::io::stderr(),
            "{}",
            trf!(
                "    … {} : jusqu'à {} min",
                "    … {}: up to {} min",
                if crate::langue::anglais() { p.en } else { p.fr },
                p.delai.div_ceil(60)
            )
        );
    }
    let Some(r) = crate::commande::lancer(&mut c, p.delai) else {
        return Resultat::echec(trf!(
            "{} n'a pas démarré, ou n'a pas fini en {} minutes : compté comme non fait",
            "{} did not start, or did not finish within {} minutes: counted as not done",
            p.outil,
            p.delai.div_ceil(60)
        ));
    };
    match r.code {
        Some(code) if p.reussites.contains(&code) => Resultat::ok(),
        code => {
            let pourquoi = derniere_ligne(&r.erreurs).or_else(|| derniere_ligne(&r.sortie));
            let code = code.map_or_else(
                || tr!("arrêté par un signal", "stopped by a signal").to_string(),
                |c| trf!("code {c}", "code {c}"),
            );
            Resultat::echec(match pourquoi {
                Some(l) => trf!("{} a échoué ({code}) : {l}", "{} failed ({code}): {l}", p.outil),
                None => trf!("{} a échoué ({code})", "{} failed ({code})", p.outil),
            })
        }
    }
}

/// La dernière ligne non vide d'une sortie, filtrée (`ui::affichable`) et coupée à 200 caractères : la raison d'un
/// échec, telle que l'outil l'a dite.
fn derniere_ligne(texte: &str) -> Option<String> {
    let l = texte.lines().rev().map(str::trim).find(|l| !l.is_empty())?;
    Some(crate::ui::affichable(&l.chars().take(200).collect::<String>()))
}

/// La réponse de la personne à une question d'accord : seuls « o », « oui », « y » et « yes » (majuscules permises)
/// disent oui ; le reste, une ligne vide comprise, dit non. Une seule ligne, bornée, est lue.
fn accord(question: &str, lecteur: &mut impl BufRead, ecrivain: &mut impl Write) -> bool {
    if write!(ecrivain, "{question} ").and_then(|()| ecrivain.flush()).is_err() {
        return false;
    }
    let mut reponse = String::new();
    if (&mut *lecteur).take(64).read_line(&mut reponse).is_err() {
        return false;
    }
    matches!(reponse.trim().to_lowercase().as_str(), "o" | "oui" | "y" | "yes")
}

/// Pourquoi ce geste demande l'accord, dans la langue de l'interface (`GesteUnix::pourquoi_l_accord`).
fn pourquoi_dit(g: GesteUnix) -> &'static str {
    match g.pourquoi_l_accord() {
        Some((fr, en)) => {
            if crate::langue::anglais() {
                en
            } else {
                fr
            }
        }
        None => tr!("ceci change le système", "this changes the system"),
    }
}

/// L'accord d'un geste qui affaiblit, supprime, coupe le réseau ou l'ouvre, demandé sur le terminal de la personne (/dev/tty), jamais sur le
/// canal du parent. Sans terminal, refusé.
fn accord_au_terminal(g: GesteUnix) -> Result<(), Refus> {
    use std::os::fd::AsRawFd;
    let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        return Err(Refus(
            tr!(
            "ce geste demande votre accord, et aucun terminal n'est là pour le donner : rien n'est fait. Lancez Vanguard depuis un terminal pour le faire",
            "this step needs your agreement, and no terminal is there to give it: nothing is done. Start Vanguard from a terminal to do it"
        )
            .to_string(),
        ));
    };
    // Ce qui a été tapé d'avance, ou glissé avant la question, ne répond pas à sa place.
    // SAFETY: tcflush sur un descripteur ouvert que `tty` tient pendant l'appel ; aucun pointeur.
    unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) };
    let question = trf!(
        "Vanguard (administrateur) : {} — {}. D'accord ? Tapez « oui » puis Entrée (autre chose refuse) :",
        "Vanguard (administrator): {} — {}. Agree? Type \"yes\" then Enter (anything else refuses):",
        texte_du_geste(g),
        pourquoi_dit(g)
    );
    let mut ecrivain = &tty;
    let mut lecteur = BufReader::new(&tty);
    if accord(&question, &mut lecteur, &mut ecrivain) {
        Ok(())
    } else {
        Err(Refus(
            tr!(
                "pas fait : vous n'avez pas donné votre accord",
                "not done: you did not give your agreement"
            )
            .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::blocage::pare_feu::PareFeu;

    fn pf() -> PareFeu {
        if cfg!(target_os = "macos") {
            PareFeu::Pf
        } else {
            PareFeu::Nftables
        }
    }

    /// Un programme dans un dossier du compte n'est jamais relancé par son chemin ; un programme du système l'est.
    #[test]
    fn programme_relance_par_chemin_seulement_s_il_est_a_root() {
        use std::os::unix::fs::MetadataExt;
        // Dans un espace de noms utilisateur (unshare -rn), root n'est pas root : /usr/bin y appartient à « nobody ».
        if std::fs::metadata("/usr/bin").map(|m| m.uid()).ok() != Some(0) {
            return crate::essais::saute("/usr/bin n'appartient pas à root ici (espace de noms utilisateur)");
        }
        assert!(chemin_sur(std::path::Path::new("/usr/bin")));
        assert!(!chemin_sur(&crate::essais::temporaire().join("absent-vanguard")));
        let d = crate::essais::temporaire().join(format!("vanguard-chemin-sur-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        if crate::socle::euid() != 0 {
            assert!(!chemin_sur(&d));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le temps du dialogue, ce processus n'est plus accessible au compte ; il l'est de nouveau après. Lancé dans un
    /// processus à part par `inaccessible_le_temps_du_dialogue` : le drapeau vaut pour tout le processus, et les
    /// autres essais, qui tournent en même temps, lisent /proc.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "lancé dans un processus à part par inaccessible_le_temps_du_dialogue"]
    fn inaccessible_dedans() {
        // SAFETY: prctl sans pointeur.
        let avant = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        {
            let _g = Inaccessible::poser();
            // SAFETY: voir ci-dessus.
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, 0);
        }
        // SAFETY: voir ci-dessus.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, avant);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inaccessible_le_temps_du_dialogue() {
        let moi = std::env::current_exe().unwrap();
        let sortie = std::process::Command::new(moi)
            .args([
                "--ignored",
                "--exact",
                "machine::assistant::tests::inaccessible_dedans",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        let texte = String::from_utf8_lossy(&sortie.stdout);
        assert!(sortie.status.success() && texte.contains("1 passed"), "{texte}");
    }

    /// L'accord sur le terminal, pour de vrai : le fils de l'essai tourne dans sa propre session, sous un
    /// pseudo-terminal qui est son terminal de contrôle (/dev/tty), et ce test-ci tape à la place de la personne.
    /// « oui » après la question : accordé. « oui » tapé AVANT la question, puis « non » : refusé (tcflush a vidé
    /// l'avance). Sans terminal de contrôle : refusé, en le disant.
    #[cfg(target_os = "linux")]
    #[test]
    fn accord_au_terminal_sous_pty() {
        for cas in ["oui", "avance", "sans"] {
            let Some(texte) = accord_sous_pty(cas) else {
                return crate::essais::saute("pas de pseudo-terminal ici (/dev/ptmx)");
            };
            assert!(texte.contains("1 passed"), "{cas} : {texte}");
        }
    }

    /// Lance `accord_dedans` dans un processus à part, sous un pseudo-terminal neuf (sauf `sans`), et répond à la
    /// question. La sortie du fils ; `None` si le pseudo-terminal manque.
    #[cfg(target_os = "linux")]
    fn accord_sous_pty(cas: &str) -> Option<String> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::process::CommandExt;
        use std::time::{Duration, Instant};
        // SAFETY: posix_openpt sans pointeur ; le descripteur rendu est confié à un `File` juste après.
        let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        if fd < 0 {
            return None;
        }
        // SAFETY: `fd` vient d'être ouvert, et n'appartient qu'à ce `File`, qui le fermera.
        let mut maitre = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut nom: [libc::c_char; 128] = [0; 128];
        // SAFETY: grantpt et unlockpt sur le maître ouvert ; ptsname_r écrit au plus `nom.len()` octets dans `nom`.
        let pret = unsafe {
            libc::grantpt(fd) == 0 && libc::unlockpt(fd) == 0 && libc::ptsname_r(fd, nom.as_mut_ptr(), nom.len()) == 0
        };
        if !pret {
            return None;
        }
        // SAFETY: ptsname_r a réussi : `nom` est une chaîne finie par un NUL, dans le tableau.
        let esclave = unsafe { std::ffi::CStr::from_ptr(nom.as_ptr()) }.to_owned();
        // L'esclave tenu ouvert ici aussi : ce qui est tapé avant que le fils ne l'ouvre y reste, comme au clavier.
        let _tenu = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(std::ffi::OsStr::from_bytes(esclave.to_bytes()))
            .ok()?;
        if cas == "avance" {
            maitre.write_all(b"oui\n").ok()?;
        }
        let mut c = Command::new(std::env::current_exe().ok()?);
        c.args([
            "--ignored",
            "--exact",
            "machine::assistant::tests::accord_dedans",
            "--test-threads=1",
        ])
        .env("VANGUARD_ESSAI_ACCORD", cas)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let avec_terminal = cas != "sans";
        // SAFETY: entre fork et exec, seulement setsid, open et ioctl (sûrs à ce moment-là), sans allocation ; le
        // chemin de l'esclave est une chaîne C déjà prête.
        unsafe {
            c.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if avec_terminal {
                    let t = libc::open(esclave.as_ptr(), libc::O_RDWR);
                    if t < 0 || libc::ioctl(t, libc::TIOCSCTTY, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let enfant = c.spawn().ok()?;
        if avec_terminal {
            // La question d'abord, comme la personne : répondre avant serait taper d'avance.
            let mut vu = Vec::new();
            let limite = Instant::now() + Duration::from_secs(60);
            while !String::from_utf8_lossy(&vu).contains("Vanguard (admin") && Instant::now() < limite {
                let mut p = libc::pollfd {
                    fd: maitre.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: un seul pollfd, valide le temps de l'appel.
                if unsafe { libc::poll(&raw mut p, 1, 200) } > 0 {
                    let mut tampon = [0u8; 512];
                    match maitre.read(&mut tampon) {
                        Ok(n) if n > 0 => vu.extend_from_slice(&tampon[..n]),
                        _ => break,
                    }
                }
            }
            maitre.write_all(if cas == "oui" { b"oui\n" } else { b"non\n" }).ok()?;
        }
        let sortie = enfant.wait_with_output().ok()?;
        Some(format!(
            "{}{}",
            String::from_utf8_lossy(&sortie.stdout),
            String::from_utf8_lossy(&sortie.stderr)
        ))
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "lancé dans un processus à part, sous un pseudo-terminal, par accord_au_terminal_sous_pty"]
    fn accord_dedans() {
        let Ok(cas) = std::env::var("VANGUARD_ESSAI_ACCORD") else {
            return crate::essais::saute("VANGUARD_ESSAI_ACCORD non donné");
        };
        let r = accord_au_terminal(GesteUnix::Programme(&crate::machine::gestes_unix::FRESHCLAM));
        match cas.as_str() {
            "oui" => assert!(r.is_ok(), "{r:?}"),
            "sans" => assert!(r.is_err_and(|Refus(t)| t.contains("terminal"))),
            _ => assert!(r.is_err(), "« oui » tapé d'avance a répondu à la place de la personne"),
        }
    }

    #[test]
    fn l_ordre_des_methodes() {
        let tout = |_: &str| true;
        if cfg!(target_os = "linux") {
            assert_eq!(
                methodes(true, true, false, tout),
                [Methode::Pkexec, Methode::Run0, Methode::Sudo]
            );
            // Sans session graphique : pas de pkexec ; sans terminal : pas de run0.
            assert_eq!(methodes(false, true, false, tout), [Methode::Run0, Methode::Sudo]);
            assert_eq!(methodes(false, false, false, tout), [Methode::Sudo]);
            assert_eq!(methodes(true, false, false, |n| n == "pkexec"), [Methode::Pkexec]);
        } else {
            assert_eq!(methodes(true, true, false, tout), [Methode::Sudo]);
        }
        assert_eq!(methodes(true, true, false, |_| false), []);
        // Un geste demande l'accord sur le terminal : ni pkexec ni run0 (pas de terminal pour le fils), sudo seulement
        // depuis un terminal ; sinon rien, et le texte nomme ce qui manque.
        assert_eq!(methodes(true, true, true, tout), [Methode::Sudo]);
        assert_eq!(methodes(true, true, true, |n| n != "sudo"), []);
        assert_eq!(methodes(true, false, true, tout), []);
        for terminal in [true, false] {
            let t = sans_methode(true, terminal);
            assert!(t.contains("sudo") && t.contains("pkexec") && t.contains("run0"), "{t}");
        }
        assert!(sans_methode(true, false).contains("terminal"));
        assert!(sans_methode(true, true).contains("installé") || sans_methode(true, true).contains("installed"));
    }

    /// La ligne de commande de l'élévation : l'image qui tourne, la sous-commande et rien d'autre (aucun shell).
    #[test]
    fn la_commande_d_elevation() {
        let c = commande(
            Methode::Pkexec,
            std::path::Path::new("/usr/bin/pkexec"),
            std::ffi::OsStr::new("/proc/4242/exe"),
            true,
        );
        let args: Vec<String> = c.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(c.get_program(), "/usr/bin/pkexec");
        assert_eq!(
            args[..3],
            ["--disable-internal-agent", "/proc/4242/exe", "appliquer-eleve"]
        );
        assert!(args.contains(&"--parent".to_string()));
        let s = commande(
            Methode::Sudo,
            std::path::Path::new("/usr/bin/sudo"),
            std::ffi::OsStr::new("/proc/4242/exe"),
            false,
        );
        let args: Vec<String> = s.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args[..3], ["-n", "--", "/proc/4242/exe"]);
        let r = commande(
            Methode::Run0,
            std::path::Path::new("/usr/bin/run0"),
            std::ffi::OsStr::new("/proc/4242/exe"),
            true,
        );
        assert_eq!(r.get_args().next().unwrap(), "--");
    }

    /// Le dialogue des deux côtés : ce que le parent envoie se relit à l'identique ; une ligne étrangère, une liste
    /// vide, un groupe vide ou un flux sans fin sont refusés en entier.
    #[test]
    fn le_canal_se_relit_et_refuse_l_etranger() {
        let groupes = vec![
            vec![
                Demande::Ordre(Ordre::BloquerSortie {
                    pare_feu: pf(),
                    ip: "203.0.113.7".parse().unwrap(),
                }),
                Demande::Ordre(Ordre::CouperConnexions {
                    ip: "203.0.113.7".parse().unwrap(),
                }),
            ],
            vec![Demande::Ordre(Ordre::ArreterProcessus {
                pid: 4242,
                chemin: "/home/alice/.cache/x".into(),
            })],
        ];
        let t = envoi(&groupes);
        let lignes = lire_lignes(t.as_bytes()).unwrap();
        assert_eq!(analyser_liste(&lignes), Some(groupes.clone()));
        for hostile in [
            "sudo sh -c id\nfin\n".to_string(),
            "fin\n".to_string(),
            format!("{SUITE}\n{}\nfin\n", groupes[1][0].ligne()),
            format!("{}\n{SUITE}\nfin\n", groupes[1][0].ligne()),
            "vanguard:bloquer-sortie windows 203.0.113.7\nfin\n".to_string(),
        ] {
            let l = lire_lignes(hostile.as_bytes()).unwrap();
            assert_eq!(analyser_liste(&l), None, "{hostile:?}");
        }
        assert!(lire_lignes(&b"vanguard:couper-connexions 203.0.113.7\n"[..]).is_none());
        let longue = format!("{}\nfin\n", "a".repeat(LIGNE_MAX + 1));
        assert!(lire_lignes(longue.as_bytes()).is_none());
        let trop = format!("{}fin\n", "x\n".repeat(2 * LIGNES_MAX + 2));
        assert!(lire_lignes(trop.as_bytes()).is_none());
        // Les réponses : autant que d'ordres, sinon tout est compté non fait.
        let r = ranger(
            &groupes,
            &["ok".into(), "ok note=1 coupée".into(), "echec refusé".into()],
        )
        .unwrap();
        assert!(r[0][0].reussi && r[0][1].note.as_deref() == Some("1 coupée") && !r[1][0].reussi);
        assert!(ranger(&groupes, &["ok".into()]).is_none());
    }

    /// Sous les essais, rien n'est jamais élevé pour de vrai : tout est « non fait », dit.
    #[test]
    fn jamais_d_elevation_dans_les_essais() {
        if crate::socle::euid() == 0 {
            return crate::essais::saute("essais lancés en root : l'ordre se ferait ici");
        }
        let r = appliquer(&[vec![Demande::Ordre(Ordre::CouperConnexions {
            ip: "203.0.113.7".parse().unwrap(),
        })]]);
        assert!(!r[0][0].reussi);
    }

    /// Un geste de Linux passe sur le même canal qu'un ordre et se relit tel quel ; une ligne qui commence comme un
    /// geste sans en être un fait refuser toute la liste (jamais lue comme un ordre, jamais confiée à un shell).
    #[test]
    fn les_gestes_passent_par_le_meme_canal() {
        let geste = Demande::Geste(GesteUnix::Programme(&gestes_unix::FRESHCLAM));
        let groupes = vec![vec![geste.clone()]];
        let lignes = lire_lignes(envoi(&groupes).as_bytes()).unwrap();
        assert_eq!(lignes, ["vanguard:geste programme freshclam"]);
        if cfg!(target_os = "linux") {
            assert_eq!(analyser_liste(&lignes), Some(groupes));
        } else {
            // Sous macOS, aucun geste de Linux n'est permis (plan du lot Unix, D8).
            assert_eq!(analyser_liste(&lignes), None);
        }
        assert_eq!(Demande::analyser(&geste.ligne()), Some(geste));
        for hostile in [
            "vanguard:geste programme freshclam --config-file=/home/alice/x\nfin\n",
            "vanguard:geste programme inconnu\nfin\n",
            "vanguard:geste sh -c id\nfin\n",
        ] {
            let l = lire_lignes(hostile.as_bytes()).unwrap();
            assert_eq!(analyser_liste(&l), None, "{hostile:?}");
        }
    }

    /// Seul un oui franc vaut accord ; une ligne vide, autre chose, ou un terminal qui se ferme disent non. La
    /// question est écrite là où la réponse est lue.
    #[test]
    fn l_accord_ne_se_donne_que_par_oui() {
        for (reponse, attendu) in [
            ("oui\n", true),
            ("o\n", true),
            ("YES\n", true),
            ("y\r\n", true),
            ("  Oui  \n", true),
            ("\n", false),
            ("", false),
            ("non\n", false),
            ("ouii\n", false),
            ("oui oui\n", false),
            ("ok\n", false),
        ] {
            let mut ecrit = Vec::new();
            let mut lu = std::io::Cursor::new(reponse.as_bytes());
            assert_eq!(accord("D'accord ?", &mut lu, &mut ecrit), attendu, "{reponse:?}");
            assert!(String::from_utf8(ecrit).unwrap().starts_with("D'accord ?"));
        }
        // Une réponse sans fin n'est lue qu'en partie, et refusée.
        let longue = format!("{}oui\n", "x".repeat(10_000));
        let mut lu = std::io::Cursor::new(longue.as_bytes());
        assert!(!accord("?", &mut lu, &mut Vec::new()));
    }

    /// Un ordinateur inventé pour `faire_geste` : chaque appel est noté dans `journal`, dans l'ordre ; rien ne touche
    /// au vrai système.
    struct FauxMonde {
        journal: Vec<String>,
        refus: Option<&'static str>,
        systemd: bool,
        session: Option<bool>,
        fichier: Result<(), Echec>,
        etat: Result<Option<String>, Echec>,
        /// Les actions (`ActionUnite::mot`) qui échouent.
        echecs: Vec<&'static str>,
        programme_reussi: bool,
        /// Le programme panique au lieu de rendre son issue.
        programme_panique: bool,
    }

    impl FauxMonde {
        fn nouveau() -> Self {
            FauxMonde {
                journal: Vec::new(),
                refus: None,
                systemd: true,
                session: Some(false),
                fichier: Ok(()),
                etat: Ok(Some("enabled".into())),
                echecs: Vec::new(),
                programme_reussi: true,
                programme_panique: false,
            }
        }
    }

    impl Monde for FauxMonde {
        fn accord(&mut self, _: GesteUnix) -> Result<(), Refus> {
            self.journal.push("accord".into());
            self.refus.map_or(Ok(()), |r| Err(Refus(r.into())))
        }
        fn systemd(&self) -> bool {
            self.systemd
        }
        fn session_entrante(&self) -> Option<bool> {
            self.session
        }
        fn fichier_sur(&self, _: &str) -> Result<(), Echec> {
            self.fichier.clone()
        }
        fn etat_du_fichier(&mut self, unite: &str) -> Result<Option<String>, Echec> {
            self.journal.push(format!("etat {unite}"));
            self.etat.clone()
        }
        fn unite(&mut self, action: ActionUnite, unite: &str) -> Result<(), Echec> {
            self.journal.push(format!("{} {unite}", action.mot()));
            if self.echecs.contains(&action.mot()) {
                Err(Echec::echoue("essai", format!("{} en échec", action.mot())))
            } else {
                Ok(())
            }
        }
        fn reinitialiser_echecs(&mut self) -> Result<(), Echec> {
            self.journal.push("reinitialiser".into());
            Ok(())
        }
        fn programme(&mut self, p: &'static Programme) -> Resultat {
            self.journal.push(format!("programme {}", p.id));
            assert!(!self.programme_panique, "panique à l'essai");
            if self.programme_reussi {
                Resultat::ok()
            } else {
                Resultat::echec("programme en échec")
            }
        }
    }

    /// Un geste qui affaiblit n'est jamais fait sans accord : le refus est rendu tel quel, et rien n'est lancé.
    #[test]
    fn un_geste_qui_affaiblit_attend_l_accord() {
        static AFFAIBLIT: Programme = Programme {
            id: "essai-affaiblit",
            outil: "vanguard-outil-absent-essai",
            arguments: &[],
            reussites: &[0],
            delai: 5,
            affaiblit: true,
            supprime: false,
            fr: "essai",
            en: "test",
        };
        let g = GesteUnix::Programme(&AFFAIBLIT);
        if !g.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let mut m = FauxMonde::nouveau();
        m.refus = Some("refusé à l'essai");
        let r = faire_geste(g, &mut m);
        assert_eq!(m.journal, ["accord"]);
        assert!(!r.reussi && r.raison == "refusé à l'essai", "{r:?}");
        let mut m = FauxMonde::nouveau();
        assert!(faire_geste(g, &mut m).reussi);
        assert_eq!(m.journal, ["accord", "programme essai-affaiblit"]);
        // Accordé pour de vrai : il ne reste qu'à trouver l'outil, absent ici, et c'est dit (jamais un faux « ok »).
        let r = lancer_programme(&AFFAIBLIT);
        assert!(!r.reussi && r.raison.contains("vanguard-outil-absent-essai"), "{r:?}");
        // Un geste ordinaire ne demande rien.
        let mut m = FauxMonde::nouveau();
        m.refus = Some("");
        assert!(faire_geste(GesteUnix::Programme(&ESSAI_VRAI), &mut m).reussi);
        assert_eq!(m.journal, ["programme essai-vrai"]);
    }

    /// Les gardes de `faire_geste`, dans leur ordre : un pare-feu jamais coupé, systemd absent dit, une session à
    /// distance jamais coupée (ni quand elle ne se lit pas), l'unité désignée revue, l'accord pour une protection.
    /// Chaque refus arrive avant tout geste sur le système.
    #[test]
    fn les_gardes_d_un_geste_d_unite() {
        if !GesteUnix::ReinitialiserEchecs.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let essai = |g: GesteUnix, regler: &dyn Fn(&mut FauxMonde)| {
            let mut m = FauxMonde::nouveau();
            regler(&mut m);
            let r = faire_geste(g, &mut m);
            (r.reussi, m.journal)
        };
        let rien = |_: &mut FauxMonde| {};
        let vide: Vec<String> = Vec::new();
        // Un pare-feu : jamais arrêté, redémarré ni rechargé (un rechargement peut le laisser vide), même accordé,
        // même avec tout le reste en ordre.
        for a in [
            ActionUnite::Arreter,
            ActionUnite::Desactiver,
            ActionUnite::DesactiverSansArreter,
            ActionUnite::Redemarrer,
            ActionUnite::Recharger,
        ] {
            for u in [&gestes_unix::UFW, &gestes_unix::FIREWALLD] {
                assert_eq!(essai(GesteUnix::Unite(a, u), &rien), (false, vide.clone()), "{a:?}");
            }
        }
        assert_eq!(
            essai(GesteUnix::Unite(ActionUnite::Activer, &gestes_unix::UFW), &rien),
            (true, vec!["activer ufw.service".to_string()])
        );
        // Sans systemd : refusé, dit, rien d'appelé.
        let sans = |m: &mut FauxMonde| m.systemd = false;
        assert_eq!(
            essai(GesteUnix::Unite(ActionUnite::Activer, &gestes_unix::CUPS), &sans),
            (false, vide.clone())
        );
        assert_eq!(essai(GesteUnix::ReinitialiserEchecs, &sans), (false, vide.clone()));
        // Le réseau redémarré : jamais pendant une session à distance, ni sans savoir s'il y en a une.
        let reseau = GesteUnix::Unite(ActionUnite::Redemarrer, &gestes_unix::NETWORKMANAGER);
        assert_eq!(essai(reseau, &|m| m.session = Some(true)), (false, vide.clone()));
        assert_eq!(essai(reseau, &|m| m.session = None), (false, vide.clone()));
        assert_eq!(
            essai(reseau, &rien),
            (true, vec!["redemarrer NetworkManager.service".to_string()])
        );
        // Le réseau seulement rechargé ne coupe rien : la session ne compte pas.
        assert!(
            essai(
                GesteUnix::Unite(ActionUnite::Recharger, &gestes_unix::NETWORKMANAGER),
                &|m| m.session = Some(true)
            )
            .0
        );
        // Une protection : l'accord d'abord ; refusé, rien n'est fait.
        let audit = GesteUnix::Unite(ActionUnite::Desactiver, &gestes_unix::AUDITD);
        assert_eq!(
            essai(audit, &|m| m.refus = Some("non")),
            (false, vec!["accord".to_string()])
        );
        assert_eq!(
            essai(audit, &rien),
            (
                true,
                vec!["accord".to_string(), "desactiver auditd.service".to_string()]
            )
        );
        // Activer une protection ne demande rien.
        assert_eq!(
            essai(GesteUnix::Unite(ActionUnite::Activer, &gestes_unix::AUDITD), &|m| m
                .refus =
                Some("non")),
            (true, vec!["activer auditd.service".to_string()])
        );
        assert_eq!(
            essai(GesteUnix::ReinitialiserEchecs, &rien),
            (true, vec!["reinitialiser".to_string()])
        );
        // Couper le réseau : l'accord, après la session ; ouvrir l'ordinateur au réseau local : l'accord aussi.
        let coupe = GesteUnix::Unite(ActionUnite::Desactiver, &gestes_unix::NETWORKMANAGER);
        assert_eq!(essai(coupe, &|m| m.session = Some(true)), (false, vide.clone()));
        assert_eq!(
            essai(coupe, &|m| m.refus = Some("non")),
            (false, vec!["accord".to_string()])
        );
        assert_eq!(
            essai(
                GesteUnix::Unite(ActionUnite::Activer, &gestes_unix::CUPS_BROWSED),
                &rien
            ),
            (
                true,
                vec!["accord".to_string(), "activer cups-browsed.service".to_string()]
            )
        );
    }

    /// Dans le fils, rien n'écrit par `eprintln!` ni `println!` : la fenêtre du terminal fermée en plein geste les
    /// ferait paniquer, peut-être après l'arrêt d'un service ; `let _ = writeln!` ne panique jamais.
    #[test]
    fn aucune_sortie_qui_panique() {
        let source = include_str!("assistant.rs");
        let code = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        for interdit in ["eprintln!(", "println!(", "eprint!(", "print!("] {
            assert!(!code.contains(interdit), "{interdit}");
        }
    }

    /// Une unité désignée par le parent n'est touchée que revue par le fils : un logiciel de prise de contrôle
    /// reconnu, au fichier sûr, activé au démarrage, puis l'accord de la personne (ce peut être un bureau à distance
    /// voulu, VNC ou NoMachine) ; une session à distance ouverte ne l'empêche pas.
    #[test]
    fn une_unite_designee_est_revue() {
        let arreter = gestes_unix::designee(ActionUnite::Arreter, "anydesk.service").unwrap();
        let retirer = gestes_unix::designee(ActionUnite::DesactiverSansArreter, "anydesk.service").unwrap();
        if !arreter.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let essai = |g: GesteUnix, regler: &dyn Fn(&mut FauxMonde)| {
            let mut m = FauxMonde::nouveau();
            regler(&mut m);
            let r = faire_geste(g, &mut m);
            (r.reussi, m.journal)
        };
        let s = ToString::to_string;
        assert_eq!(
            essai(arreter, &|_| {}),
            (
                true,
                vec![s("etat anydesk.service"), s("accord"), s("arreter anydesk.service")]
            )
        );
        assert_eq!(
            essai(retirer, &|m| m.session = Some(true)),
            (
                true,
                vec![
                    s("etat anydesk.service"),
                    s("accord"),
                    s("desactiver-sans-arreter anydesk.service")
                ]
            )
        );
        // Sans l'accord, rien n'est arrêté.
        assert_eq!(
            essai(arreter, &|m| m.refus = Some("non")),
            (false, vec![s("etat anydesk.service"), s("accord")])
        );
        // Une session ouverte, ou illisible, n'empêche pas d'arrêter le logiciel de prise de contrôle : ses propres
        // connexions sont justement celles du faux technicien.
        for session in [Some(true), None] {
            assert_eq!(
                essai(arreter, &|m| m.session = session),
                (
                    true,
                    vec![s("etat anydesk.service"), s("accord"), s("arreter anydesk.service")]
                ),
                "{session:?}"
            );
        }
        assert_eq!(
            essai(arreter, &|m| m.fichier = Err(Echec::refuse("essai", "lien"))),
            (false, vec![])
        );
        for etat in [None, Some(s("disabled")), Some(s("masked")), Some(s("static"))] {
            let (reussi, journal) = essai(arreter, &|m| m.etat = Ok(etat.clone()));
            assert!(!reussi && journal == [s("etat anydesk.service")], "{etat:?}");
        }
        assert_eq!(
            essai(arreter, &|m| m.etat = Err(Echec::echoue("essai", "bus"))),
            (false, vec![s("etat anydesk.service")])
        );
        // Un service qui n'est pas un logiciel de prise de contrôle : refusé avant de regarder son fichier.
        let autre = gestes_unix::designee(ActionUnite::Arreter, "bluetooth.service").unwrap();
        assert_eq!(essai(autre, &|_| {}), (false, vec![]));
    }

    /// Pose et retrait des signaux ignorés : un essai à la fois.
    static SIGNAUX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// La disposition d'un signal, lue sans la changer.
    fn disposition(signal: libc::c_int) -> libc::sighandler_t {
        // SAFETY: voir `SignauxIgnores::poser`.
        let mut vue: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: lecture seule (aucune nouvelle disposition) dans une structure vivante de la pile.
        assert_eq!(unsafe { libc::sigaction(signal, std::ptr::null(), &raw mut vue) }, 0);
        vue.sa_sigaction
    }

    /// Le temps de `signatures-clamav`, fermer le terminal, Ctrl+C ou un arrêt demandé ne tuent pas l'assistant ;
    /// ensuite, chaque signal redevient ce qu'il était.
    #[test]
    fn les_signaux_de_fin_ignores_le_temps_du_geste() {
        let _seul = SIGNAUX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let avant = SIGNAUX_DE_FIN.map(disposition);
        {
            let _garde = SignauxIgnores::poser();
            for s in SIGNAUX_DE_FIN {
                assert_eq!(disposition(s), libc::SIG_IGN, "{s}");
            }
        }
        assert_eq!(SIGNAUX_DE_FIN.map(disposition), avant);
    }

    /// `signatures-clamav` : le service jamais laissé arrêté (arrêt refusé, activation refusée, panique), masqué
    /// jamais touché, absent sans rien d'autre que freshclam ; la réussite seulement si freshclam et la remise en
    /// route ont réussi.
    #[test]
    fn signatures_clamav_jamais_laisse_arrete() {
        if !GesteUnix::SignaturesClamav.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        // Les signaux du processus sont communs à tous les essais : un seul à la fois les pose.
        let _signaux = SIGNAUX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let essai = |regler: &dyn Fn(&mut FauxMonde)| {
            let mut m = FauxMonde::nouveau();
            regler(&mut m);
            let r = faire_geste(GesteUnix::SignaturesClamav, &mut m);
            (r, m.journal)
        };
        let s = ToString::to_string;
        let etat = s("etat clamav-freshclam.service");
        let arret = s("arreter clamav-freshclam.service");
        let marche = s("activer clamav-freshclam.service");
        let fresh = s("programme freshclam");
        let (r, j) = essai(&|_| {});
        assert!(r.reussi && r.note.is_none(), "{r:?}");
        assert_eq!(j, [etat.clone(), arret.clone(), fresh.clone(), marche.clone()]);
        let (r, j) = essai(&|m| m.etat = Ok(None));
        assert!(r.reussi && r.note.is_none(), "{r:?}");
        assert_eq!(j, [etat.clone(), fresh.clone()]);
        let (r, j) = essai(&|m| m.etat = Ok(Some(s("masked"))));
        assert!(r.reussi && r.note.is_some(), "{r:?}");
        assert_eq!(j, [etat.clone(), fresh.clone()]);
        // L'arrêt refusé : freshclam est lancé quand même, puis le service remis en route.
        let (r, j) = essai(&|m| m.echecs = vec!["arreter"]);
        assert!(r.reussi, "{r:?}");
        assert_eq!(j, [etat.clone(), arret.clone(), fresh.clone(), marche.clone()]);
        let (r, j) = essai(&|m| {
            m.echecs = vec!["arreter"];
            m.programme_reussi = false;
        });
        assert!(!r.reussi && r.raison.contains("arreter en échec"), "{r:?}");
        assert_eq!(j, [etat.clone(), arret.clone(), fresh.clone(), marche.clone()]);
        let (r, j) = essai(&|m| m.programme_reussi = false);
        assert!(!r.reussi && r.raison == "programme en échec", "{r:?}");
        assert_eq!(j, [etat.clone(), arret.clone(), fresh.clone(), marche.clone()]);
        // L'activation refusée : au moins démarré, et c'est une réussite.
        let demarre = s("demarrer clamav-freshclam.service");
        let (r, j) = essai(&|m| m.echecs = vec!["activer"]);
        assert!(r.reussi, "{r:?}");
        assert_eq!(
            j,
            [
                etat.clone(),
                arret.clone(),
                fresh.clone(),
                marche.clone(),
                demarre.clone()
            ]
        );
        // Ni activé ni démarré : dit, avec la raison de l'activation.
        let (r, j) = essai(&|m| m.echecs = vec!["activer", "demarrer"]);
        assert!(!r.reussi && r.raison.contains("activer en échec"), "{r:?}");
        assert_eq!(j, [etat.clone(), arret.clone(), fresh.clone(), marche.clone(), demarre]);
        // Une panique pendant freshclam : le service est quand même remis en route en sortant.
        let mut m = FauxMonde::nouveau();
        m.programme_panique = true;
        let paniquee = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            faire_geste(GesteUnix::SignaturesClamav, &mut m)
        }));
        assert!(paniquee.is_err());
        assert_eq!(m.journal, [etat.clone(), arret, fresh, marche]);
        let (r, j) = essai(&|m| m.etat = Err(Echec::echoue("essai", "bus fermé")));
        assert!(!r.reussi && r.raison == "bus fermé", "{r:?}");
        assert_eq!(j, [etat]);
        // Sans systemd : rien, dit (le parent propose alors freshclam seul).
        let (r, j) = essai(&|m| m.systemd = false);
        assert!(!r.reussi && j.is_empty(), "{r:?}");
    }

    /// Le fichier d'une unité désignée : un fichier ordinaire du compte attendu, que personne d'autre ne peut
    /// modifier ; un autre propriétaire, un fichier modifiable par le groupe : refusés, sans voir plus loin. Un lien
    /// (`systemctl link`) n'est suivi que vers un tel fichier, dans des dossiers fermés aux autres.
    #[test]
    fn le_fichier_d_une_unite_designee() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::essais::Jetable::nouveau("assistant-unite");
        let racine = d.join("racine");
        let premier = racine.join("etc");
        let second = racine.join("usr");
        let ailleurs = racine.join("opt").join("logiciel");
        for dossier in [&premier, &second, &ailleurs] {
            std::fs::create_dir_all(dossier).unwrap();
        }
        let moi = crate::socle::euid();
        let dossiers = [premier.as_path(), second.as_path()];
        let sur = |nom: &str, qui: u32| fichier_d_unite_sur(&dossiers, &racine, nom, qui);
        let poser = |dossier: &std::path::Path, nom: &str, mode: u32| {
            let f = dossier.join(nom);
            std::fs::write(&f, "[Service]\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let mode = |chemin: &std::path::Path, m: u32| {
            std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(m)).unwrap();
        };
        for dossier in [&racine, &premier, &second, &ailleurs, &racine.join("opt")] {
            mode(dossier, 0o755);
        }
        // Absent partout : refusé, dit.
        assert!(sur("anydesk.service", moi).is_err());
        // Dans le second dossier seulement : accepté.
        poser(&second, "anydesk.service", 0o644);
        assert_eq!(sur("anydesk.service", moi), Ok(()));
        // Un autre propriétaire : refusé.
        assert!(sur("anydesk.service", moi.wrapping_add(1)).is_err());
        // Modifiable par le groupe ou par tous : refusé.
        for m in [0o664, 0o646] {
            poser(&second, "rustdesk.service", m);
            assert!(sur("rustdesk.service", moi).is_err(), "{m:o}");
        }
        // Un lien (`systemctl link`) dans le premier dossier, vers un fichier correct : suivi, accepté.
        poser(&ailleurs, "teamviewerd.service", 0o644);
        let lien = premier.join("teamviewerd.service");
        std::os::unix::fs::symlink(ailleurs.join("teamviewerd.service"), &lien).unwrap();
        assert_eq!(sur("teamviewerd.service", moi), Ok(()));
        // Même lien, vers un fichier d'un autre propriétaire : refusé.
        assert!(sur("teamviewerd.service", moi.wrapping_add(1)).is_err());
        // Sa cible modifiable par les autres : refusé, sans aller voir le second dossier.
        poser(&second, "teamviewerd.service", 0o644);
        mode(&ailleurs.join("teamviewerd.service"), 0o646);
        assert!(sur("teamviewerd.service", moi).is_err());
        mode(&ailleurs.join("teamviewerd.service"), 0o644);
        assert_eq!(sur("teamviewerd.service", moi), Ok(()));
        // Un dossier parent de la cible modifiable par les autres : refusé (le fichier pourrait y être remplacé).
        for (dossier, m) in [(&ailleurs, 0o757), (&racine.join("opt"), 0o777), (&racine, 0o775)] {
            mode(dossier, m);
            assert!(sur("teamviewerd.service", moi).is_err(), "{} {m:o}", dossier.display());
            mode(dossier, 0o755);
        }
        // Un lien qui sort de la racine : refusé.
        let dehors = d.join("dehors.service");
        std::fs::write(&dehors, "[Service]\n").unwrap();
        mode(&dehors, 0o644);
        std::os::unix::fs::symlink(&dehors, premier.join("rustdesk.service")).unwrap();
        assert!(sur("rustdesk.service", moi).is_err());
        // Un lien brisé : refusé.
        std::os::unix::fs::symlink(ailleurs.join("absent.service"), premier.join("anydesk.service")).unwrap();
        assert!(sur("anydesk.service", moi).is_err());
        // Un dossier à la place du fichier : refusé.
        std::fs::create_dir(premier.join("x11vnc.service")).unwrap();
        poser(&second, "x11vnc.service", 0o644);
        assert!(sur("x11vnc.service", moi).is_err());
        // Un nom hors de la règle : refusé avant d'ouvrir quoi que ce soit.
        assert!(sur("../etc/anydesk.service", moi).is_err());
        // Les dossiers de systemd, tous : ceux des logiciels installés à la main et /lib compris.
        assert_eq!(
            DOSSIERS_D_UNITES,
            [
                "/etc/systemd/system",
                "/usr/local/lib/systemd/system",
                "/usr/lib/systemd/system",
                "/lib/systemd/system"
            ]
        );
    }

    static FAUX: Programme = Programme {
        id: "essai-faux",
        outil: "false",
        arguments: &[],
        reussites: &[0],
        delai: 10,
        affaiblit: false,
        supprime: false,
        fr: "essai",
        en: "test",
    };

    static ESSAI_VRAI: Programme = Programme {
        id: "essai-vrai",
        outil: "true",
        arguments: &[],
        reussites: &[0],
        delai: 10,
        affaiblit: false,
        supprime: false,
        fr: "essai",
        en: "test",
    };

    /// L'issue d'un programme : son code dit « fait » ou « échec », avec sa raison ; jamais un « ok » pour un code
    /// hors de la table.
    #[test]
    fn un_code_hors_de_la_table_est_un_echec() {
        if crate::commande::outil_systeme("true").is_none() || crate::commande::outil_systeme("false").is_none() {
            return crate::essais::saute("ni true ni false dans les dossiers du système");
        }
        assert!(lancer_programme(&ESSAI_VRAI).reussi);
        let r = lancer_programme(&FAUX);
        assert!(
            !r.reussi && r.raison.contains("false") && r.raison.contains('1'),
            "{r:?}"
        );
    }

    /// L'outil ne reçoit que sa langue et son terminal de l'assistant.
    #[test]
    fn l_outil_ne_recoit_que_langue_et_terminal() {
        for (n, garde) in [
            ("LANG", true),
            ("LC_ALL", true),
            ("TERM", true),
            ("LC_", false),
            ("PATH", false),
            ("HOME", false),
            ("BASH_ENV", false),
            ("LD_PRELOAD", false),
        ] {
            assert_eq!(langue_ou_terminal(std::ffi::OsStr::new(n)), garde, "{n}");
        }
    }
}
