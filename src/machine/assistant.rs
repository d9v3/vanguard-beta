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
//! bureau sécurisé de l'UAC).

// FFI de libc : prctl (PR_SET_DUMPABLE, le secret de l'assistant élevé hors des vidages).
#![allow(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use crate::machine::gestes_unix::{self, GesteUnix, Programme};
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
            Demande::Geste(g) => texte_du_geste(*g).to_string(),
        }
    }

    fn permis_ici(&self) -> bool {
        match self {
            Demande::Ordre(o) => o.permis_ici(),
            Demande::Geste(g) => g.permis_ici(),
        }
    }
}

fn texte_du_geste(g: GesteUnix) -> &'static str {
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

/// Les façons possibles ici, dans l'ordre où les essayer.
fn methodes(graphique: bool, terminal: bool, existe: impl Fn(&str) -> bool) -> Vec<Methode> {
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
        return executer_demandes(groupes, &juge, &mut accord_au_terminal, &mut |t| {
            if !t.starts_with("> ") {
                println!("    {GRIS}{t}{RESET}");
            }
        });
    }
    // Les essais ne lancent jamais pkexec, run0 ni sudo pour de vrai.
    if cfg!(test) {
        return tous_en_echec(groupes, "essai : aucune élévation");
    }
    let graphique = std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
    let possibles = methodes(graphique, terminal(), |n| outil(n).is_some());
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
    let raison = tr!(
        "aucun moyen d'obtenir les droits d'administrateur ici (ni pkexec avec un agent polkit, ni run0, ni sudo) : rien n'a été fait",
        "no way to get administrator rights here (neither pkexec with a polkit agent, nor run0, nor sudo): nothing was done"
    );
    trp!("    ✖ {}", "    ✖ {}", raison);
    tous_en_echec(groupes, raison)
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
        eprintln!(
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
        eprintln!(
            "{}",
            tr!(
                "La liste reçue n'est pas une liste de gestes de Vanguard : rien n'est fait. Un autre programme y a touché : lancez une analyse antivirus.",
                "The list received is not a Vanguard step list: nothing is done. Another program touched it: run an antivirus scan."
            )
        );
        let _ = writeln!(sortie, "{FIN}");
        return LISTE_REFUSEE;
    };
    eprintln!(
        "{}",
        tr!(
            "Vanguard (administrateur) va faire :",
            "Vanguard (administrator) will do:"
        )
    );
    for o in groupes.iter().flatten() {
        eprintln!("  · {}", o.texte());
    }
    let juge = ordres::Juge::lire(parent);
    let resultats = executer_demandes(&groupes, &juge, &mut accord_au_terminal, &mut |t| eprintln!("{t}"));
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
/// est fait après l'accord de la personne s'il en demande un. `accord` rend la raison d'un refus.
fn executer_demandes(
    groupes: &[Vec<Demande>],
    juge: &ordres::Juge,
    accord: &mut dyn FnMut(GesteUnix) -> Result<(), Refus>,
    annoncer: &mut dyn FnMut(&str),
) -> Vec<Vec<Resultat>> {
    ordres::executer_en_groupes(
        groupes,
        Demande::texte,
        |d| match d {
            Demande::Ordre(o) => ordres::juger_et_faire(o, juge),
            Demande::Geste(g) => faire_geste(*g, accord),
        },
        annoncer,
    )
}

/// Un geste de Linux, rejugé ici : permis sur ce système, accordé s'il le faut, puis fait.
fn faire_geste(g: GesteUnix, accord: &mut dyn FnMut(GesteUnix) -> Result<(), Refus>) -> Resultat {
    if !g.permis_ici() {
        return Resultat::echec(tr!(
            "ce geste n'est pas prévu sur ce système : rien n'est fait",
            "this step is not meant for this system: nothing is done"
        ));
    }
    if g.demande_accord()
        && let Err(Refus(raison)) = accord(g)
    {
        return Resultat::echec(raison);
    }
    match g {
        GesteUnix::Programme(p) => lancer_programme(p),
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

/// L'accord d'un geste qui affaiblit ou supprime, demandé sur le terminal de la personne (/dev/tty), jamais sur le
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
        "Vanguard (administrateur) : {} — ceci baisse une protection ou supprime quelque chose. D'accord ? Tapez « oui » puis Entrée (autre chose refuse) :",
        "Vanguard (administrator): {} — this lowers a protection or deletes something. Agree? Type \"yes\" then Enter (anything else refuses):",
        texte_du_geste(g)
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

    #[test]
    fn l_ordre_des_methodes() {
        let tout = |_: &str| true;
        if cfg!(target_os = "linux") {
            assert_eq!(
                methodes(true, true, tout),
                [Methode::Pkexec, Methode::Run0, Methode::Sudo]
            );
            // Sans session graphique : pas de pkexec ; sans terminal : pas de run0.
            assert_eq!(methodes(false, true, tout), [Methode::Run0, Methode::Sudo]);
            assert_eq!(methodes(false, false, tout), [Methode::Sudo]);
            assert_eq!(methodes(true, false, |n| n == "pkexec"), [Methode::Pkexec]);
        } else {
            assert_eq!(methodes(true, true, tout), [Methode::Sudo]);
        }
        assert_eq!(methodes(true, true, |_| false), []);
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
        let mut demandes = 0;
        let r = faire_geste(g, &mut |_| {
            demandes += 1;
            Err(Refus("refusé à l'essai".into()))
        });
        assert_eq!(demandes, 1);
        assert!(!r.reussi && r.raison == "refusé à l'essai", "{r:?}");
        // Accordé : il ne reste qu'à trouver l'outil, absent ici, et c'est dit (jamais un faux « ok »).
        let r = faire_geste(g, &mut |_| Ok(()));
        assert!(!r.reussi && r.raison.contains("vanguard-outil-absent-essai"), "{r:?}");
        // Un geste ordinaire ne demande rien.
        let mut demande = false;
        let _ = faire_geste(GesteUnix::Programme(&ESSAI_VRAI), &mut |_| {
            demande = true;
            Err(Refus(String::new()))
        });
        assert!(!demande);
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
