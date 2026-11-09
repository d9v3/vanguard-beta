//! L'assistant élevé de Linux : Vanguard se relance lui-même avec les droits d'administrateur, sous la
//! sous-commande cachée `appliquer-eleve`, pour faire des ordres du blocage (`protection::blocage::ordres`) et des
//! gestes de Linux (`machine::gestes_unix`) sans aucun shell : jamais « sudo sh -c », jamais une commande écrite en
//! texte.
//!
//! L'élévation, dans cet ordre : pkexec (Linux, s'il y a une session graphique : la fenêtre de l'agent polkit ; sans
//! agent, pkexec rend 127 et le suivant est essayé), run0 (Linux, systemd 256 et plus : son propre agent dans le
//! terminal), sudo (dans le terminal ; use_pty, la règle par défaut depuis sudo 1.9.14, passe nos tubes tels quels),
//! sinon c'est dit et rien n'est fait. Le programme lancé est, sous Linux, `/proc/<pid>/exe` de ce Vanguard : ce lien
//! désigne l'image qui tourne, même si le fichier est remplacé entre-temps (sudo et run0 l'exécutent tel quel).
//! pkexec, lui, le résout en chemin réel avant de l'exécuter (realpath dans pkexec.c) : par chemin, seulement un
//! programme que le compte ne peut pas remplacer (à root, dossiers compris) ; sinon pkexec est sauté (run0 ou sudo
//! prennent la suite). pkexec reçoit donc ce chemin réel lui-même :
//! il vérifie d'abord le chemin reçu avec l'identité de la personne (access() de pkexec 126), et le lien
//! `/proc/<pid>/exe` d'un processus non « dumpable » lui est fermé (É-7 du lot U3).
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
//! Il ne lit rien du dossier de Vanguard, et n'écrit de fichier que pour un geste de défense (`defense_eleve`) : sa
//! note d'« avant » dans /var/lib/vanguard/avant, à root et fermée aux autres, et le fichier que le geste corrige.
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

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]
// FFI de libc : prctl (PR_SET_DUMPABLE, le secret de l'assistant élevé hors des vidages).
#![allow(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use crate::machine::arret_designe::{self, ArretCharge, Chemin, SessionVue};
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
#[allow(clippy::large_enum_variant, reason = "une demande par ligne lue, jamais en masse")]
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

#[allow(
    clippy::large_types_passed_by_value,
    reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
)]
fn texte_du_geste(g: GesteUnix) -> String {
    let (fr, en) = g.phrase();
    if crate::langue::anglais() { en } else { fr }
}

/// Une façon d'obtenir les droits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Methode {
    Pkexec,
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
/// permet (avec use_pty, le fils a un terminal relayé) ; sinon aucune, et `sans_methode` dit pourquoi. `existe` : le
/// programme est là, et utilisable (`avec_polkit`).
fn methodes(graphique: bool, terminal: bool, accord: bool, existe: impl Fn(&str) -> bool) -> Vec<Methode> {
    if accord {
        return if terminal && existe("sudo") {
            vec![Methode::Sudo]
        } else {
            Vec::new()
        };
    }
    let mut m = Vec::new();
    if graphique && existe("pkexec") {
        m.push(Methode::Pkexec);
    }
    if terminal && existe("run0") {
        m.push(Methode::Run0);
    }
    if existe("sudo") {
        m.push(Methode::Sudo);
    }
    m
}

/// `existe`, sauf pour pkexec et run0 quand polkit n'est pas là (`dbus::polkit_present`, B-1 du lot U3) : ils ne sont
/// alors même pas essayés. run0 sortirait en « Access denied » sans rien demander, qu'on ne sait pas distinguer d'un
/// vrai refus, et sudo ne serait jamais essayé ; à l'inverse, compter cette sortie comme « indisponible » ferait
/// reposer la question par sudo à une personne qui vient de refuser.
fn avec_polkit(polkit: bool, existe: impl Fn(&str) -> bool) -> impl Fn(&str) -> bool {
    move |nom| (polkit || ![Methode::Pkexec, Methode::Run0].iter().any(|m| m.nom() == nom)) && existe(nom)
}

/// Le programme et tous ses dossiers appartiennent-ils à root, sans écriture pour le groupe ni les autres ? Alors
/// personne d'autre que root ne peut le remplacer entre l'accord et son lancement par chemin (pkexec, qui résout
/// `/proc/<pid>/exe` en chemin réel avant de l'exécuter). Un programme dans un dossier du compte
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

/// Le programme à relancer : l'image qui tourne, ou son chemin pour pkexec.
///
/// pkexec reçoit le chemin réel (É-7 du lot U3) : pkexec 126 (Debian 13) vérifie le chemin reçu par access(), avec
/// l'identité de la personne, et pendant le dialogue ce processus n'est plus « dumpable » (`Inaccessible`) : son
/// `/proc/<pid>/exe` n'est alors ouvert qu'à root, d'où « Error accessing `/proc/<pid>/exe`: Permission denied ». Rien
/// n'est relâché pour autant : pkexec exécutait déjà ce chemin réel (realpath), et il n'est pris que s'il passe
/// `image_sure` ; rendre ce processus « dumpable » pendant l'élévation rouvrirait ses tubes au compte.
fn programme(m: Methode) -> Option<std::ffi::OsString> {
    if m == Methode::Pkexec {
        std::env::current_exe().ok().map(std::path::PathBuf::into_os_string)
    } else {
        Some(format!("/proc/{}/exe", std::process::id()).into())
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
    let mut total = 0usize;
    for l in lignes {
        if l == SUITE {
            groupes.push(Vec::new());
            continue;
        }
        let o = Demande::analyser(l).filter(Demande::permis_ici)?;
        total = total.saturating_add(1);
        groupes.last_mut()?.push(o);
    }
    // Lot D7c : une baisse (un pare-feu coupé) n'arrive que seule, du choix fait dans les Options de défense. Mêlée à
    // d'autres lignes, elle aurait pu être glissée dans une liste de corrections que la personne accepte d'un bloc :
    // toute la liste est refusée.
    let baisse = groupes.iter().flatten().any(|d| {
        matches!(
            d,
            Demande::Geste(GesteUnix::Defense(gestes_unix::Defense::CouperPareFeu(_), _))
        )
    });
    if baisse && total != 1 {
        return None;
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

/// Début d'une ligne du fils qui porte une erreur de son journal (`journal::relayees`) : aucune réponse
/// (`ordres::ligne_reponse` : « ok… », « echec… ») ne commence ainsi.
const JOURNAL: &str = "journal ";

/// Une erreur gardée par le fils, prête à passer au parent : une seule ligne, sans caractère piégé, coupée pour tenir
/// dans `LIGNE_MAX` (le parent refuserait toute la réponse pour une ligne trop longue).
fn ligne_journal(erreur: &str) -> String {
    let texte = crate::ui::affichable(&erreur.replace("\r\n", "\n").replace(['\r', '\n'], " | "));
    let place = LIGNE_MAX.saturating_sub(JOURNAL.len());
    let mut fin = texte.len().min(place);
    while !texte.is_char_boundary(fin) {
        fin = fin.saturating_sub(1);
    }
    format!("{JOURNAL}{}", &texte[..fin])
}

/// Sépare les erreurs relayées par le fils (au plus `journal::RELAIS_MAX`, le reste est ignoré) de ses réponses.
fn separer_journal(lignes: Vec<String>) -> (Vec<String>, Vec<String>) {
    let mut erreurs = Vec::new();
    let mut reponses = Vec::new();
    for l in lignes {
        match l.strip_prefix(JOURNAL) {
            Some(e) => {
                if erreurs.len() < crate::journal::RELAIS_MAX {
                    erreurs.push(e.to_string());
                }
            }
            None => reponses.push(l),
        }
    }
    (erreurs, reponses)
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
    let (Some(chemin), Some(programme)) = (outil(m.nom()), programme(m)) else {
        return Issue::Indisponible;
    };
    // pkexec exécute le chemin réel du programme : par chemin, seulement un programme que le compte ne peut pas
    // remplacer.
    if m == Methode::Pkexec && !image_sure() {
        return Issue::Indisponible;
    }
    let terminal = terminal();
    trp!(
        "    {GRIS}Droits d'administrateur demandés par {} : Vanguard fera lui-même les gestes montrés, et rien d'autre.{RESET}",
        "    {GRIS}Administrator rights asked through {}: Vanguard itself will do the steps shown, and nothing else.{RESET}",
        m.nom()
    );
    let (lance, mut suivi) = crate::coulisses::Suivie::spawn_et_suivre(
        commande(m, &chemin, &programme, terminal)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    );
    let Ok(mut fils) = lance else {
        return Issue::Indisponible;
    };
    let (Some(mut entree), Some(sortie)) = (fils.stdin.take(), fils.stdout.take()) else {
        crate::commande::arreter(&mut fils);
        return Issue::Indisponible;
    };
    // Les réponses, les erreurs relayées par le fils, « prêt » et « fin ».
    let borne = (LIGNES_MAX + crate::journal::RELAIS_MAX + 4) * (LIGNE_MAX + 2);
    let mut lecteur = BufReader::new(sortie.take(u64::try_from(borne).unwrap_or(0)));
    // Pas de délai : la personne tape son mot de passe. Le fils mort sans s'être dit prêt ferme le tube.
    let mut premiere = String::new();
    let pret = lecteur.read_line(&mut premiere).is_ok_and(|n| n > 0) && premiere.trim_end() == PRET;
    if !pret {
        drop(entree);
        let code = fils.wait().ok().and_then(|s| s.code());
        suivi.fin(crate::coulisses::Issue::Code(code));
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
    suivi.fin(crate::coulisses::Issue::Code(fils.wait().ok().and_then(|s| s.code())));
    let reponses = reponses.map(|r| {
        let (erreurs, reponses) = separer_journal(r);
        // Écrites ici, dans le journal du compte, que « le détail est dans le journal des erreurs » désigne : celui
        // du fils, root, serait sous /root.
        for e in erreurs {
            crate::journal::erreur(crate::compte_rendu::Contexte::CorrectionElevee, &e);
        }
        reponses
    });
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
        return executer_demandes(groupes, &juge, &mut Systeme { demandeur: None }, &mut |t| {
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
    // polkit n'est demandé au bus que s'il peut servir : un geste avec accord passe par sudo seulement.
    #[cfg(target_os = "linux")]
    let polkit = !accord && crate::machine::linux::dbus::polkit_present();
    #[cfg(not(target_os = "linux"))]
    let polkit = false;
    let possibles = methodes(graphique, terminal, accord, avec_polkit(polkit, |n| outil(n).is_some()));
    // Pendant le dialogue, plus aucun processus du compte ne peut ouvrir nos tubes par /proc/<pid>/fd ni s'attacher
    // à nous (ptrace) pour glisser une autre liste au fils, ou lui répondre à sa place : un processus non
    // « dumpable » n'est plus accessible qu'à root.
    let _garde = Inaccessible::poser();
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
            "aucun moyen d'obtenir les droits d'administrateur ici (ni pkexec avec un agent polkit, ni run0, qui demande polkit lui aussi, ni sudo) : rien n'a été fait",
            "no way to get administrator rights here (neither pkexec with a polkit agent, nor run0, which needs polkit too, nor sudo): nothing was done"
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

/// La sous-commande `appliquer-eleve` sous Linux : rend le code de sortie du processus.
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
    // Root, ses erreurs iraient sous /root ; elles partent au parent avec les réponses.
    crate::journal::relayer();
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
    let resultats = executer_demandes(&groupes, &juge, &mut Systeme { demandeur: parent }, &mut |t| {
        let _ = writeln!(std::io::stderr(), "{t}");
    });
    for e in crate::journal::relayees() {
        if writeln!(sortie, "{}", ligne_journal(&e)).is_err() {
            return 1;
        }
    }
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
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
    )]
    fn accord(&mut self, g: GesteUnix) -> Result<(), Refus>;
    /// systemd gère-t-il ce système ?
    fn systemd(&self) -> bool;
    /// Une session à distance entrante est-elle ouverte (SSH ou Bureau à distance reçus, logiciel de prise de contrôle
    /// connecté) ? `None` : les connexions en cours ne se lisent pas.
    fn session_entrante(&self) -> Option<bool>;
    /// Le fichier de l'unité est-il celui de root, dans un dossier du système, fermé aux autres comptes, lien compris,
    /// et de même ses compléments et ce que le gestionnaire a chargé (`fichier_d_unite_sur`) ? `Ok(false)` : l'unité
    /// n'est pas installée (aucun fichier, rien de chargé avec un fichier).
    fn fichier_sur(&self, unite: &str) -> Result<bool, Echec>;
    /// L'unité peut-elle être arrêtée à la main (`systeme::arret_a_la_main`) ? `None` : pas chargée, rien à arrêter.
    fn arret_a_la_main(&mut self, unite: &str) -> Result<Option<bool>, Echec>;
    /// L'état du fichier de l'unité (« enabled », « disabled »…) ; `None` : aucun fichier de ce nom.
    fn etat_du_fichier(&mut self, unite: &str) -> Result<Option<String>, Echec>;
    /// L'état d'activité de l'unité (« active », « inactive »…) ; `None` : aucune unité chargée de ce nom.
    fn etat_d_activite(&mut self, unite: &str) -> Result<Option<String>, Echec>;
    /// systemd a-t-il refusé de lancer l'unité à cause de ses propres conditions, à sa dernière tentative
    /// (`dbus::condition_refusee`) ? Faux par défaut : rien n'en est conclu.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn condition_refusee(&mut self, _unite: &str) -> Result<bool, Echec> {
        Ok(false)
    }
    fn unite(&mut self, action: ActionUnite, unite: &str) -> Result<(), Echec>;
    fn reinitialiser_echecs(&mut self) -> Result<(), Echec>;
    fn programme(&mut self, p: &'static Programme) -> Resultat;
    /// Ce que le gestionnaire a en mémoire de l'unité pour juger son arrêt (`systeme::arret_charge`) ; `None` : pas
    /// chargée.
    fn arret_charge(&mut self, unite: &str) -> Result<Option<ArretCharge>, Echec>;
    /// Les groupes de contrôle de la lignée de Vanguard : ce fils, le Vanguard qui l'a demandé, et leurs ancêtres. Ce
    /// qui ne se lit pas manque (rien n'en est conclu en faveur de l'arrêt).
    fn groupes_de_la_lignee(&self) -> Vec<String>;
    /// Les sessions de logind, avec les groupes de leur meneur et de ses ancêtres ; `None` : la liste ne se lit pas
    /// (l'arrêt est alors refusé : rien n'en est conclu en sa faveur).
    fn sessions(&mut self) -> Option<Vec<SessionVue>>;
    /// Ce qu'un regard voit d'un chemin cité par une commande d'arrêt (`regarder`, `place_sure`).
    fn chemin(&self, chemin: &str) -> Chemin;
    /// « Êtes-vous connecté par lui ? », sur le terminal de la personne : la ligne qu'elle a tapée ; `None` sans
    /// terminal, à la fin de l'entrée, ou sur une erreur de lecture.
    fn connecte(&mut self, nom: &str) -> Option<String>;
    /// Un geste de défense (`defense_eleve::faire`) : il pose lui-même sa question, sur le terminal.
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
    )]
    fn defense(&mut self, d: gestes_unix::Defense, id: gestes_unix::IdNote) -> Resultat;
}

/// Le gestionnaire de services d'un `Monde`, prêté aux gestes de défense.
#[cfg(target_os = "linux")]
struct ServicesDuMonde<'a>(&'a mut dyn Monde);

#[cfg(target_os = "linux")]
impl super::defense_eleve::Services for ServicesDuMonde<'_> {
    fn systemd(&self) -> bool {
        self.0.systemd()
    }
    fn fichier_sur(&self, unite: &str) -> Result<bool, Echec> {
        self.0.fichier_sur(unite)
    }
    fn arret_charge(&mut self, unite: &str) -> Result<Option<ArretCharge>, Echec> {
        self.0.arret_charge(unite)
    }
    fn etat_du_fichier(&mut self, unite: &str) -> Result<Option<String>, Echec> {
        self.0.etat_du_fichier(unite)
    }
    fn etat_d_activite(&mut self, unite: &str) -> Result<Option<String>, Echec> {
        self.0.etat_d_activite(unite)
    }
    fn condition_refusee(&mut self, unite: &str) -> Result<bool, Echec> {
        self.0.condition_refusee(unite)
    }
    fn unite(&mut self, action: ActionUnite, unite: &str) -> Result<(), Echec> {
        self.0.unite(action, unite)
    }
    fn groupes_de_la_lignee(&self) -> Vec<String> {
        self.0.groupes_de_la_lignee()
    }
    fn sessions(&mut self) -> Option<Vec<SessionVue>> {
        self.0.sessions()
    }
    fn chemin(&self, chemin: &str) -> Chemin {
        self.0.chemin(chemin)
    }
}

/// Le vrai ordinateur : le bus système (joint de nouveau pour chaque geste : un job long ne garde pas une prise
/// ouverte d'un geste à l'autre), les connexions en cours, le terminal de la personne. `demandeur` : le Vanguard qui
/// a demandé (`--parent`) ; sous run0, le fils n'en descend pas, et sa lignée compte aussi.
struct Systeme {
    demandeur: Option<u32>,
}

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

    fn fichier_sur(&self, unite: &str) -> Result<bool, Echec> {
        let dossiers = DOSSIERS_D_UNITES.map(std::path::Path::new);
        let racine = std::path::Path::new("/");
        let qui = Proprietaire::root();
        let sur_le_disque = fichier_d_unite_sur(&dossiers, racine, unite, qui)?;
        // Puis ce que le gestionnaire a chargé : son fichier et ses compléments peuvent venir d'ailleurs (un
        // générateur, un complément du genre « service.d » posé dans /run).
        #[cfg(target_os = "linux")]
        {
            use crate::machine::linux::dbus::systeme;
            let charges = systeme::bus_pour_agir().and_then(|mut bus| systeme::fichiers_charges(&mut bus, unite))?;
            match charges {
                // Chargée sans aucun fichier, nulle part : une unité citée par une autre mais introuvable
                // (« not-found »), donc pas installée.
                Some((id, fragment, _)) if !sur_le_disque && fragment.is_empty() && id == unite => return Ok(false),
                // Chargée d'un fichier qu'aucun des dossiers de systemd n'a sous ce nom (l'instance d'un modèle,
                // un alias) : ses compléments n'ont pas été revus sur le disque, refusée.
                Some(_) if !sur_le_disque => return Err(douteux(&crate::ui::affichable(unite))),
                Some((id, fragment, complements)) => {
                    fichiers_charges_surs(&id, &fragment, &complements, racine, unite, qui)?;
                    return Ok(true);
                }
                None => {}
            }
        }
        Ok(sur_le_disque)
    }

    fn arret_a_la_main(&mut self, unite: &str) -> Result<Option<bool>, Echec> {
        #[cfg(target_os = "linux")]
        {
            use crate::machine::linux::dbus::systeme;
            systeme::bus_pour_agir().and_then(|mut bus| systeme::arret_a_la_main(&mut bus, unite))
        }
        #[cfg(not(target_os = "linux"))]
        Err(refus(format!("{unite} : {}", sans_systemd())))
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

    fn etat_d_activite(&mut self, unite: &str) -> Result<Option<String>, Echec> {
        #[cfg(target_os = "linux")]
        {
            use crate::machine::linux::dbus;
            dbus::systeme::bus_pour_agir().and_then(|mut bus| dbus::etat_d_activite(&mut bus, unite))
        }
        #[cfg(not(target_os = "linux"))]
        Err(refus(format!("{unite} : {}", sans_systemd())))
    }

    fn condition_refusee(&mut self, unite: &str) -> Result<bool, Echec> {
        #[cfg(target_os = "linux")]
        {
            use crate::machine::linux::dbus;
            dbus::systeme::bus_pour_agir().and_then(|mut bus| dbus::condition_refusee(&mut bus, unite))
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

    fn arret_charge(&mut self, unite: &str) -> Result<Option<ArretCharge>, Echec> {
        #[cfg(target_os = "linux")]
        {
            use crate::machine::linux::dbus::systeme;
            systeme::bus_pour_agir().and_then(|mut bus| systeme::arret_charge(&mut bus, unite))
        }
        #[cfg(not(target_os = "linux"))]
        Err(refus(format!("{unite} : {}", sans_systemd())))
    }

    fn groupes_de_la_lignee(&self) -> Vec<String> {
        let moi = std::process::id();
        let mut pids = vec![moi];
        pids.extend(ordres::ancetres(moi));
        if let Some(d) = self.demandeur {
            pids.push(d);
            pids.extend(ordres::ancetres(d));
        }
        groupes_des(&pids)
    }

    fn sessions(&mut self) -> Option<Vec<SessionVue>> {
        #[cfg(target_os = "linux")]
        {
            use crate::machine::linux::dbus::systeme;
            let sessions = systeme::bus_pour_agir()
                .ok()
                .and_then(|mut bus| systeme::sessions_logind(&mut bus))?;
            let vues = sessions
                .into_iter()
                .map(|s| {
                    let mut pids = vec![s.meneur];
                    pids.extend(ordres::ancetres(s.meneur));
                    SessionVue {
                        distante: s.distante,
                        service: s.service,
                        groupes_du_meneur: groupes_des(&pids),
                    }
                })
                .collect();
            Some(vues)
        }
        #[cfg(not(target_os = "linux"))]
        None
    }

    fn chemin(&self, chemin: &str) -> Chemin {
        let c = std::path::Path::new(chemin);
        let racine = std::path::Path::new("/");
        let qui = Proprietaire::root();
        match regarder(c, racine, qui, None) {
            Regard::Sur => std::fs::canonicalize(c).map_or(Chemin::Douteux, |reel| Chemin::Sur {
                reel: reel.to_string_lossy().into_owned(),
            }),
            Regard::Absent if place_sure(c, racine, qui) => Chemin::AbsentPlaceSure,
            _ => Chemin::Douteux,
        }
    }

    fn connecte(&mut self, nom: &str) -> Option<String> {
        let vu = crate::ui::affichable(nom);
        let question = trf!(
            "Vanguard (administrateur) : êtes-vous vous-même connecté à cet ordinateur par {vu} en ce moment, depuis un autre appareil ? L'arrêter couperait votre session. Tapez « non » puis Entrée pour l'arrêter (« oui », Entrée seule ou autre chose : il reste en marche) :",
            "Vanguard (administrator): are you yourself connected to this computer through {vu} right now, from another device? Stopping it would cut your session. Type \"no\" then Enter to stop it (\"yes\", Enter alone or anything else: it keeps running):"
        );
        question_au_terminal(&question).ok().flatten()
    }

    fn defense(&mut self, d: gestes_unix::Defense, id: gestes_unix::IdNote) -> Resultat {
        #[cfg(target_os = "linux")]
        {
            let mut acces = super::defense_eleve::Reel {
                demandeur: self.demandeur,
                signees: std::cell::RefCell::default(),
            };
            super::defense_eleve::faire(d, id, &mut acces, &mut ServicesDuMonde(self))
        }
        // Ailleurs, aucun geste de défense n'est permis (`permis_ici`) : jamais appelé.
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (d, id);
            Resultat::echec(tr!(
                "ce geste n'est pas prévu sur ce système : rien n'est fait",
                "this step is not meant for this system: nothing is done"
            ))
        }
    }
}

/// Les groupes de contrôle de ces processus (`/proc/<pid>/cgroup`) ; un processus disparu ou illisible est sauté.
fn groupes_des(pids: &[u32]) -> Vec<String> {
    pids.iter()
        .filter_map(|p| std::fs::read_to_string(format!("/proc/{p}/cgroup")).ok())
        .filter_map(|t| arret_designe::groupe_du_processus(&t))
        .collect()
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

/// Où le fils cherche le fichier d'une unité désignée par son nom, et ses compléments (« nom.d »), dans l'ordre de
/// systemd pour le gestionnaire du système (systemd.unit(5), « System Unit Search Path ») : ceux de `systemctl
/// set-property` et des unités passagères, ceux des générateurs, celui de l'administrateur, ceux du démarrage en
/// cours (/run), ceux des logiciels installés à la main, puis ceux des paquets (/lib : distributions où il n'est pas
/// un lien vers /usr/lib).
const DOSSIERS_D_UNITES: [&str; 13] = [
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
];

/// Ce qu'un regard sur un fichier d'unité en a vu (`regarder`).
#[derive(Debug, PartialEq, Eq)]
enum Regard {
    Absent,
    Sur,
    /// Lui, sa cible, ou un dossier qui contient l'un ou l'autre, modifiable par un autre compte (ou illisible).
    Douteux,
    /// Un lien vers un fichier d'un autre nom.
    AutreNom,
}

/// À qui doivent être les fichiers d'unité et leurs dossiers.
#[derive(Clone, Copy, Debug)]
struct Proprietaire {
    uid: u32,
    /// Un groupe sans autre membre que le propriétaire : un DOSSIER qu'il peut modifier n'ouvre rien à un autre compte.
    /// Fedora Cloud livre `/` en 0775 root:root (É-1 du lot U3), ce qui faisait refuser toute unité. Jamais pour un
    /// fichier, ni pour l'écriture des autres.
    groupe_seul: Option<u32>,
}

impl Proprietaire {
    /// Son seul compte : rien de modifiable par un groupe.
    #[cfg(test)]
    const fn strict(uid: u32) -> Self {
        Proprietaire { uid, groupe_seul: None }
    }

    /// root, et le groupe 0 s'il n'a pas d'autre membre (`groupe_root_seul`).
    fn root() -> Self {
        let lu = |f| std::fs::read_to_string(f).ok();
        // gshadow manque sur certains systèmes : son absence ne donne aucun mot de passe de groupe.
        let gshadow = lu("/etc/gshadow").unwrap_or_default();
        let seul =
            matches!((lu("/etc/group"), lu("/etc/passwd")), (Some(g), Some(p)) if groupe_root_seul(&g, &p, &gshadow));
        Proprietaire {
            uid: 0,
            groupe_seul: seul.then_some(0),
        }
    }

    fn a_le_fichier(self, m: &std::fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;
        m.uid() == self.uid && m.mode() & 0o022 == 0
    }

    fn a_le_dossier(self, m: &std::fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;
        m.uid() == self.uid && m.mode() & 0o002 == 0 && (m.mode() & 0o020 == 0 || Some(m.gid()) == self.groupe_seul)
    }
}

/// Le groupe 0 n'a-t-il aucun autre membre que root ? Ni membre ajouté dans `/etc/group` (sa ligne vide, ou « root »
/// seul), ni compte de personne (uid 1000 et plus) qui l'ait pour groupe principal dans `/etc/passwd`. Les comptes du
/// système au groupe principal 0 que Fedora garde (sync, shutdown, halt, operator) ne font tourner aucun programme de
/// la personne : ils ne comptent pas. Aucun mot de passe de groupe non plus (dans `/etc/group` ou `/etc/gshadow`) :
/// `newgrp root` le donnerait à qui le connaît ; ni administrateur ou membre dans gshadow. Une ligne illisible, ou
/// deux lignes du groupe 0 : non. Les comptes d'un annuaire (LDAP, sssd) ne sont pas vus ici.
fn groupe_root_seul(group: &str, passwd: &str, gshadow: &str) -> bool {
    let lignes_0: Vec<&str> = group
        .lines()
        .filter(|l| l.split(':').nth(2).is_some_and(|g| g.trim() == "0"))
        .collect();
    let [ligne] = lignes_0.as_slice() else {
        return false;
    };
    let champs: Vec<&str> = ligne.split(':').collect();
    let [nom, mot_de_passe, _, membres] = champs.as_slice() else {
        return false;
    };
    let seul_root = |liste: &str| liste.split(',').map(str::trim).all(|m| m.is_empty() || m == "root");
    // Sans mot de passe : vide, verrouillé (« ! », « * »), ou renvoyé à gshadow (« x »).
    let sans_mot_de_passe = |m: &str| m.is_empty() || m.starts_with('!') || m.starts_with('*');
    let ombre_sure = gshadow.lines().filter(|l| l.split(':').next() == Some(*nom)).all(|l| {
        match l.split(':').collect::<Vec<_>>().as_slice() {
            [_, m, admins, membres] => sans_mot_de_passe(m) && seul_root(admins) && seul_root(membres),
            _ => false,
        }
    });
    let membres_surs = seul_root(membres) && (*mot_de_passe == "x" || sans_mot_de_passe(mot_de_passe)) && ombre_sure;
    let aucune_personne = passwd
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .all(|l| {
            let c: Vec<&str> = l.split(':').collect();
            match (c.get(2).map(|u| u.parse::<u32>()), c.get(3).map(|g| g.trim())) {
                (Some(Ok(_)), Some(g)) if g != "0" => true,
                (Some(Ok(uid)), Some(_)) => uid < 1000,
                _ => false,
            }
        });
    membres_surs && aucune_personne
}

/// Un fichier ordinaire de `qui` que ni son groupe ni les autres ne peuvent modifier ; chaque dossier qui le contient
/// jusqu'à `racine` comprise aussi (`Proprietaire::a_le_dossier`), et de même chaque dossier qui contient le lien
/// quand `chemin` en est un (sinon le lien pourrait être remplacé). `nom` : le nom que doit porter le fichier au bout
/// des liens.
fn regarder(chemin: &std::path::Path, racine: &std::path::Path, qui: Proprietaire, nom: Option<&str>) -> Regard {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let vu_du_lien = match std::fs::symlink_metadata(chemin) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Regard::Absent,
        Err(_) => return Regard::Douteux,
    };
    // Lien ou fichier direct, le même regard : un fichier direct dans un dossier qu'un autre compte peut modifier
    // pourrait y être remplacé aussi bien que la cible d'un lien.
    let (Ok(racine), Ok(fichier), Some(Ok(dossier_du_lien))) = (
        std::fs::canonicalize(racine),
        std::fs::canonicalize(chemin),
        chemin.parent().map(std::fs::canonicalize),
    ) else {
        return Regard::Douteux;
    };
    // Les chemins ont tous leurs liens résolus : chacun de leurs dossiers est vu tel qu'il est. Un dossier à root et
    // fermé aux autres ne peut pas être remplacé entre ce regard et l'ouverture.
    let chaine_sure = |depart: &std::path::Path| {
        depart.starts_with(&racine)
            && depart
                .ancestors()
                .filter(|d| d.starts_with(&racine))
                .all(|d| std::fs::metadata(d).is_ok_and(|m| m.is_dir() && qui.a_le_dossier(&m)))
    };
    let lien_a_lui = !vu_du_lien.file_type().is_symlink() || vu_du_lien.uid() == qui.uid;
    if !(fichier.parent().is_some_and(chaine_sure) && chaine_sure(&dossier_du_lien) && lien_a_lui) {
        return Regard::Douteux;
    }
    // Le même nom au bout : un lien vers une autre unité en ferait un alias, et le geste toucherait celle-là, qui n'a
    // pas été revue (`controle_a_distance` juge le nom).
    if let Some(nom) = nom
        && fichier.file_name() != Some(std::ffi::OsStr::new(nom))
    {
        return Regard::AutreNom;
    }
    // Sans suivre de lien (O_NOFOLLOW : un fichier remplacé par un lien depuis le regard est refusé), sans attendre si
    // c'est un tube (O_NONBLOCK).
    let Ok(ouvert) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&fichier)
    else {
        return Regard::Douteux;
    };
    match ouvert.metadata() {
        Ok(m) if m.is_file() && qui.a_le_fichier(&m) => Regard::Sur,
        _ => Regard::Douteux,
    }
}

/// Le dossier le plus profond de `chemin` qui existe (`chemin` compris), et chacun de ceux qui le contiennent jusqu'à
/// `racine` : à `qui` et fermés aux autres (`Proprietaire::a_le_dossier`). Un fichier absent d'un dossier qu'un autre
/// compte peut modifier pourrait y être posé entre la revue et le geste, de même qu'un dossier de compléments vide
/// pourrait recevoir un « .conf » : leur absence ne vaut que si leur place est fermée.
fn place_sure(chemin: &std::path::Path, racine: &std::path::Path, qui: Proprietaire) -> bool {
    let (Ok(racine), Some(existant)) = (
        std::fs::canonicalize(racine),
        chemin.ancestors().find(|d| std::fs::symlink_metadata(d).is_ok()),
    ) else {
        return false;
    };
    // Un lien brisé existe sans se résoudre : douteux.
    let Ok(existant) = std::fs::canonicalize(existant) else {
        return false;
    };
    existant.starts_with(&racine)
        && existant
            .ancestors()
            .filter(|d| d.starts_with(&racine))
            .all(|d| std::fs::metadata(d).is_ok_and(|m| m.is_dir() && qui.a_le_dossier(&m)))
}

/// Les dossiers de compléments (« drop-in ») qui s'appliquent à l'unité `nom` (systemd.unit(5)) : « nom.d », ceux
/// des préfixes à tiret (« a-b-c.service » : « a-b-.service.d », « a-.service.d »), et celui du genre
/// (« service.d »).
fn noms_des_complements(nom: &str) -> Vec<String> {
    let mut noms = vec![format!("{nom}.d")];
    if let Some((base, genre)) = nom.rsplit_once('.') {
        noms.extend(
            base.match_indices('-')
                .rev()
                .filter_map(|(i, _)| base.get(..=i))
                .map(|prefixe| format!("{prefixe}.{genre}.d")),
        );
        noms.push(format!("{genre}.d"));
    }
    noms
}

/// Le fichier de l'unité `nom` dans le premier de `dossiers` qui l'a, et ses compléments dans tous : chacun sûr
/// (`regarder`), sinon un autre compte pourrait changer ce que l'unité lance (ExecStop d'un arrêt, Also= d'un
/// retrait du démarrage). Un lien (`systemctl link`) n'est suivi que vers un tel fichier du même nom. Un fichier
/// refusé ne fait pas chercher dans le dossier suivant. `Ok(false)` : aucun fichier de ce nom, l'unité n'est pas
/// installée (ses compléments, s'il y en a, sont revus quand même : une unité installée plus tard les prendrait).
fn fichier_d_unite_sur(
    dossiers: &[&std::path::Path],
    racine: &std::path::Path,
    nom: &str,
    qui: Proprietaire,
) -> Result<bool, Echec> {
    let vu = crate::ui::affichable(nom);
    if !gestes_unix::nom_admis(nom) {
        return Err(refus(trf!(
            "nom de service refusé ({vu}) : rien n'est fait",
            "service name refused ({vu}): nothing is done"
        )));
    }
    let mut trouve = false;
    for dossier in dossiers {
        let chemin = dossier.join(nom);
        match regarder(&chemin, racine, qui, Some(nom)) {
            Regard::Absent if place_sure(&chemin, racine, qui) => {}
            Regard::Sur => {
                trouve = true;
                break;
            }
            // Absent d'une place qu'un autre compte peut modifier : il pourrait y être posé après la revue.
            Regard::Absent | Regard::Douteux => return Err(douteux(&vu)),
            Regard::AutreNom => return Err(autre_nom(&vu)),
        }
    }
    for dossier in dossiers {
        for complements in noms_des_complements(nom) {
            complements_surs(&dossier.join(complements), racine, qui, &vu)?;
        }
    }
    Ok(trouve)
}

/// Une unité qui n'est pas installée ici (É-4 du lot U3) : dit tel quel, plutôt qu'un échec du gestionnaire.
fn pas_installe(nom: &str) -> String {
    let vu = crate::ui::affichable(nom);
    trf!(
        "ce service n'est pas installé sur cet ordinateur ({vu}) : rien n'est fait",
        "this service is not installed on this computer ({vu}): nothing is done"
    )
}

/// Un dossier de compléments : sa place fermée aux autres comptes, qu'il existe ou non (`place_sure` : vide ou
/// absent, un autre compte pourrait sinon y poser un « .conf » après la revue), et chacun de ses « .conf » sûr
/// (`regarder`).
fn complements_surs(
    dossier: &std::path::Path,
    racine: &std::path::Path,
    qui: Proprietaire,
    vu: &str,
) -> Result<(), Echec> {
    if !place_sure(dossier, racine, qui) {
        return Err(douteux(vu));
    }
    let entrees = match std::fs::read_dir(dossier) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(douteux(vu)),
    };
    for entree in entrees {
        let chemin = entree.map_err(|_| douteux(vu))?.path();
        if chemin.extension().is_none_or(|x| x != "conf") {
            continue;
        }
        match regarder(&chemin, racine, qui, None) {
            Regard::Sur | Regard::Absent => {}
            Regard::Douteux | Regard::AutreNom => return Err(douteux(vu)),
        }
    }
    Ok(())
}

/// Les fichiers d'où le gestionnaire a chargé l'unité (`systeme::fichiers_charges`) : son fichier (`fragment`, vide
/// pour une unité sans fichier) et ses compléments, tous sûrs (`regarder`), et son nom principal le nom désigné (un
/// alias toucherait une autre unité). Ce que le gestionnaire a en mémoire compte, pas seulement ce qui est sur le
/// disque : une unité passagère, un générateur, un complément de /run n'ont pas tous leur place dans
/// `DOSSIERS_D_UNITES`.
#[cfg(any(target_os = "linux", test))]
fn fichiers_charges_surs(
    id: &str,
    fragment: &str,
    complements: &[String],
    racine: &std::path::Path,
    nom: &str,
    qui: Proprietaire,
) -> Result<(), Echec> {
    let vu = crate::ui::affichable(nom);
    if id != nom || fragment.is_empty() {
        return Err(autre_nom(&vu));
    }
    if regarder(std::path::Path::new(fragment), racine, qui, None) != Regard::Sur {
        return Err(douteux(&vu));
    }
    for c in complements {
        if regarder(std::path::Path::new(c), racine, qui, None) != Regard::Sur {
            return Err(douteux(&vu));
        }
    }
    Ok(())
}

/// Le refus d'un fichier d'unité qu'un autre compte pourrait modifier.
fn douteux(vu: &str) -> Echec {
    refus(trf!(
        "le fichier du service {vu} n'est pas un fichier de l'administrateur fermé aux autres comptes (lui, un de ses compléments, ou un dossier qui les contient, est modifiable par un autre compte) : rien n'est fait",
        "the file of the service {vu} is not an administrator file closed to other accounts (it, one of its add-ons, or a folder holding them, is writable by another account): nothing is done"
    ))
}

/// Le refus d'une unité qui en désigne une autre (un lien vers un fichier d'un autre nom, un alias).
fn autre_nom(vu: &str) -> Echec {
    refus(trf!(
        "le fichier du service {vu} est un lien vers un fichier d'un autre nom (un autre service, ou un service masqué) : rien n'est fait",
        "the file of the service {vu} is a link to a file with another name (another service, or a masked service): nothing is done"
    ))
}

/// Une unité désignée par le parent, revue par le fils avant d'y toucher (P5 du lot U3) : un logiciel de prise de
/// contrôle à distance reconnu, au fichier sûr, activé au démarrage. Le parent l'a trouvée ainsi ; le fils ne le
/// croit pas sur parole. Son arrêt, lui, ne demande pas qu'elle soit activée : une unité lancée autrement (préréglage
/// du paquet, « enabled-runtime », à la main) tourne aussi, et la désinstallation de son paquet l'arrêterait ; le
/// parent la fait donc passer par ce même arrêt, ses questions et ses preuves, avant de retirer le paquet.
/// `Ok(false)` : reconnue, mais plus installée (son fichier retiré entre-temps, peut-être encore en marche), ce que
/// l'appelant dit comme pour une unité de la table (`absente`, É-5 du lot U3).
fn designee_revue(a: ActionUnite, nom: &str, monde: &mut dyn Monde) -> Result<bool, Echec> {
    let vu = crate::ui::affichable(nom);
    if !crate::protection::distance::controle_a_distance(nom) {
        return Err(refus(trf!(
            "{vu} n'est pas un logiciel de prise de contrôle à distance connu de Vanguard : rien n'est fait",
            "{vu} is not a remote control tool known to Vanguard: nothing is done"
        )));
    }
    if !monde.fichier_sur(nom)? {
        return Ok(false);
    }
    if a == ActionUnite::Arreter {
        return Ok(true);
    }
    match monde.etat_du_fichier(nom)? {
        Some(etat) if etat == "enabled" => Ok(true),
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

/// L'unité que touche un geste d'unité, de la table ou désignée ; `None` pour les autres gestes (ReinitialiserEchecs ne
/// touche aucune unité en particulier, signatures-clamav revoit la sienne à part).
fn unite_touchee(g: &GesteUnix) -> Option<(ActionUnite, &str)> {
    match g {
        GesteUnix::Unite(a, u) => Some((*a, u.nom)),
        GesteUnix::Designee(a, nom) => Some((*a, nom.as_str())),
        GesteUnix::Programme(_)
        | GesteUnix::ReinitialiserEchecs
        | GesteUnix::SignaturesClamav
        | GesteUnix::Defense(..) => None,
    }
}

/// L'action coupe-t-elle l'unité (arrêt ou retrait du démarrage) ? Pour une unité absente, c'est déjà le cas.
fn coupe(a: ActionUnite) -> bool {
    matches!(
        a,
        ActionUnite::Desactiver | ActionUnite::DesactiverSansArreter | ActionUnite::Arreter
    )
}

/// Le nom d'une unité de la table, tel que la personne le lit (« le service d'impression (CUPS) »).
fn nom_vu(u: &gestes_unix::UniteConnue) -> &'static str {
    if crate::langue::anglais() { u.en } else { u.fr }
}

/// Couper une unité qui n'est pas installée (de la table, ou désignée) : plus lancée au démarrage, c'est fait, tant
/// qu'elle n'est pas réinstallée. Encore en marche (son paquet retiré sans l'arrêter), elle ne s'arrêtera qu'avec
/// l'ordinateur : ce qu'elle lancerait à l'arrêt n'a plus de fichier à revoir, Vanguard ne l'arrête pas ; son arrêt
/// seul est donc un échec, dit.
///
/// Ses liens de démarrage ne sont pas retirés (É-6 du lot U3), et la note le dit : sans fichier, DisableUnitFiles
/// ne suit plus son « Also= » (son socket, son « .path » gardent les leurs) et répond par une erreur même quand il
/// a retiré le lien de l'unité elle-même (essayé sur systemd 262) ; et une réinstallation la relance de toute façon
/// au démarrage sur Fedora (les préréglages du paquet) et sur Debian (deb-systemd-helper se souvient qu'elle était
/// activée). Promettre plus que « tant qu'il n'est pas réinstallé » serait faux.
fn absente(a: ActionUnite, unite: &str, vu: &str, monde: &mut dyn Monde) -> Resultat {
    match monde.etat_d_activite(unite) {
        Ok(Some(e)) if matches!(e.as_str(), "active" | "activating" | "reloading" | "deactivating") => {
            if a == ActionUnite::Arreter {
                Resultat::echec(trf!(
                    "ce service n'est plus installé sur cet ordinateur, mais tourne encore ({vu}) : il s'arrêtera au prochain redémarrage de l'ordinateur ; rien n'est fait",
                    "this service is no longer installed on this computer, but is still running ({vu}): it will stop at the next restart of the computer; nothing is done"
                ))
            } else {
                Resultat::ok_note(trf!(
                    "ce service n'est plus installé sur cet ordinateur ({vu}) : il ne sera plus lancé au démarrage tant qu'il n'est pas réinstallé ; il tourne encore et s'arrêtera au prochain redémarrage de l'ordinateur. Réinstallé, il pourrait de nouveau être lancé au démarrage (ses liens de démarrage restent, ou son paquet les remet) : refaites alors ce geste",
                    "this service is no longer installed on this computer ({vu}): it will no longer start at boot as long as it is not reinstalled; it is still running and will stop at the next restart of the computer. Once reinstalled, it could start at boot again (its boot links remain, or its package puts them back): then do this step again"
                ))
            }
        }
        Ok(_) => Resultat::ok_note(trf!(
            "ce service n'est pas installé sur cet ordinateur ({vu}) : rien à arrêter ni à retirer du démarrage pour l'instant. Installé plus tard, il pourrait être lancé au démarrage (d'anciens liens restés, ou son paquet, l'y mettent) : refaites alors ce geste",
            "this service is not installed on this computer ({vu}): nothing to stop or remove from startup for now. Installed later, it could start at boot (old links left behind, or its package, put it there): then do this step again"
        )),
        Err(raison) => Resultat::echec(raison),
    }
}

/// Le fichier de l'unité revu (`Monde::fichier_sur`) : sûr, ou la raison du refus ; une unité absente est dite « pas
/// installée ».
fn unite_revue(nom: &str, monde: &dyn Monde) -> Result<(), Echec> {
    if monde.fichier_sur(nom)? {
        Ok(())
    } else {
        Err(refus(pas_installe(nom)))
    }
}

/// Le geste tel qu'il sera fait, selon ce que systemd permet d'arrêter (B-3 du lot U3) : une unité qui refuse l'arrêt
/// à la main (RefuseManualStop, auditd sur Fedora et Arch) n'est que retirée du démarrage, avec la note qui le dit ;
/// une unité pas chargée aussi (rien à arrêter, et systemd la chargerait pour refuser). Son arrêt seul est refusé,
/// dit, plutôt qu'un échec du gestionnaire. Une lecture qui échoue laisse le geste tel quel : l'arrêt tenté dira
/// lui-même s'il échoue.
#[allow(
    clippy::large_types_passed_by_value,
    reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
)]
fn selon_l_arret(g: GesteUnix, monde: &mut dyn Monde) -> Result<(Option<GesteUnix>, Option<String>), Echec> {
    let Some((a @ (ActionUnite::Desactiver | ActionUnite::Arreter), nom)) = unite_touchee(&g) else {
        return Ok((Some(g), None));
    };
    // Une lecture en échec ne change rien au geste : seul ce qui est lu compte.
    let permis = monde.arret_a_la_main(nom).ok();
    let vu = crate::ui::affichable(nom);
    match (a, permis) {
        (ActionUnite::Arreter, Some(Some(false))) => Err(refus(trf!(
            "le gestionnaire de services refuse qu'on arrête {vu} à la main (il ne s'arrête qu'avec l'ordinateur) : rien n'est fait",
            "the service manager refuses to stop {vu} by hand (it only stops with the computer): nothing is done"
        ))),
        // Pas chargée, donc pas en marche : rien à arrêter (systemd la chargerait pour l'arrêt, et pourrait le refuser).
        (ActionUnite::Arreter, Some(None)) => Ok((
            None,
            Some(trf!(
                "{vu} n'est pas en marche : rien à arrêter",
                "{vu} is not running: nothing to stop"
            )),
        )),
        (ActionUnite::Desactiver, Some(None | Some(false))) => {
            let sans_arret = match g {
                GesteUnix::Unite(_, u) => GesteUnix::Unite(ActionUnite::DesactiverSansArreter, u),
                GesteUnix::Designee(_, n) => GesteUnix::Designee(ActionUnite::DesactiverSansArreter, n),
                autre => autre,
            };
            let note = (permis == Some(Some(false))).then(|| {
                String::from(tr!(
                    "il ne sera plus lancé au démarrage ; le gestionnaire de services refuse qu'on l'arrête à la main : s'il tourne, il s'arrêtera au prochain redémarrage de l'ordinateur",
                    "it will no longer start at boot; the service manager refuses to stop it by hand: if it is running, it will stop at the next restart of the computer"
                ))
            });
            Ok((Some(sans_arret), note))
        }
        _ => Ok((Some(g), None)),
    }
}

/// Un geste de Linux, rejugé ici avant d'être fait, dans cet ordre : permis sur ce système, jamais refusé
/// (`GesteUnix::refus`), systemd présent s'il en faut, aucune session à distance qu'il couperait, l'unité désignée
/// reconnue, le fichier de l'unité revu (de la table comme désignée : un complément posé par un autre compte ferait
/// lancer ce qu'il veut en root, É-2 du lot U3), l'arrêt permis par systemd, puis l'accord de la personne s'il en
/// demande un, et enfin, juste avant le geste, la session et le fichier revus encore.
#[allow(
    clippy::large_types_passed_by_value,
    reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
)]
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
    // Un geste de défense se rejuge, se montre et se demande lui-même (`defense_eleve`) : jamais l'accord commun.
    if let GesteUnix::Defense(d, id) = g {
        return monde.defense(d, id);
    }
    // Le geste demandé, pas celui qu'il deviendrait : une session ouverte bloque tout ce qui touche au réseau.
    let coupe_session = g.coupe_session();
    if coupe_session && let Err(raison) = aucune_session_entrante(monde) {
        return Resultat::echec(raison);
    }
    if let GesteUnix::Designee(a, nom) = g {
        match designee_revue(a, nom.as_str(), monde) {
            Ok(true) => {}
            // Plus installée, peut-être encore en marche : dit comme pour une unité de la table.
            Ok(false) if coupe(a) => return absente(a, nom.as_str(), &crate::ui::affichable(nom.as_str()), monde),
            Ok(false) => return Resultat::echec(pas_installe(nom.as_str())),
            Err(raison) => return Resultat::echec(raison),
        }
    }
    if let GesteUnix::Unite(a, u) = g {
        match monde.fichier_sur(u.nom) {
            Ok(true) => {}
            // Pas installée : plus lancée au démarrage, c'est déjà fait ; le reste ne peut pas se faire.
            Ok(false) if coupe(a) => return absente(a, u.nom, nom_vu(u), monde),
            Ok(false) => return Resultat::echec(pas_installe(nom_vu(u))),
            Err(raison) => return Resultat::echec(raison),
        }
    }
    let (g, note) = match selon_l_arret(g, monde) {
        Ok((Some(g), note)) => (g, note),
        // Rien à faire : dit, sans question ni geste.
        Ok((None, note)) => return Resultat::ok_note(note.unwrap_or_default()),
        Err(raison) => return Resultat::echec(raison),
    };
    if g.refus().is_some() {
        return Resultat::echec(tr!(
            "ce geste n'est pas permis : rien n'est fait",
            "this step is not allowed: nothing is done"
        ));
    }
    let arret_designe = match g {
        GesteUnix::Designee(ActionUnite::Arreter, nom) => Some(nom),
        _ => None,
    };
    if let Some(nom) = arret_designe
        && let Some(fin) = avant_l_arret_designe(nom.as_str(), monde)
    {
        return fin;
    }
    if g.demande_accord()
        && let Err(Refus(raison)) = monde.accord(g)
    {
        return Resultat::echec(raison);
    }
    // La question a pu attendre longtemps : une session ouverte entre-temps compte aussi.
    if coupe_session
        && g.demande_accord()
        && let Err(raison) = aucune_session_entrante(monde)
    {
        return Resultat::echec(raison);
    }
    // De même, le fichier de l'unité est revu juste avant le geste : il a pu changer pendant la question, ou depuis
    // la première revue.
    if let Some((_, nom)) = unite_touchee(&g)
        && let Err(raison) = unite_revue(nom, monde)
    {
        return Resultat::echec(raison);
    }
    // Ce que l'arrêt lancerait, et les sessions portées par l'outil, revus aussi : une session a pu s'ouvrir par lui
    // pendant les deux questions.
    if let Some(nom) = arret_designe {
        let avec = match arret_designe_revu(nom.as_str(), monde) {
            Ok(avec) => avec,
            Err(raison) => return arret_refuse(&raison),
        };
        // Les unités du même logiciel que l'arrêt entraîne sont dites, et reprises dans la commande qui les relance.
        let vu = crate::ui::affichable(nom.as_str());
        let autres: Vec<String> = avec.iter().map(|e| crate::ui::affichable(e)).collect();
        let entraines = autres.join(", ");
        let tous = std::iter::once(vu.clone()).chain(autres).collect::<Vec<_>>().join(" ");
        return match monde.unite(ActionUnite::Arreter, nom.as_str()) {
            Ok(()) if avec.is_empty() => Resultat::ok_note(trf!(
                "{vu} arrêté par votre choix ; pour le remettre en marche, en administrateur : systemctl start {vu} (et systemctl enable {vu} pour qu'il reparte au démarrage)",
                "{vu} stopped by your choice; to start it again, as administrator: systemctl start {vu} (and systemctl enable {vu} for it to start at boot again)"
            )),
            Ok(()) => Resultat::ok_note(trf!(
                "{vu} arrêté par votre choix, avec {entraines}, qu'il entraîne ; pour les remettre en marche, en administrateur : systemctl start {tous} (et systemctl enable {tous} pour qu'ils repartent au démarrage)",
                "{vu} stopped by your choice, with {entraines}, which it takes along; to start them again, as administrator: systemctl start {tous} (and systemctl enable {tous} for them to start at boot again)"
            )),
            // L'arrêt accepté a échoué : l'unité tourne encore, et le paquet ne doit pas partir non plus.
            Err(raison) => arret_refuse(&raison),
        };
    }
    let fait = |r: Result<(), Echec>| match (r, note) {
        (Ok(()), Some(note)) => Resultat::ok_note(note),
        (Ok(()), None) => Resultat::ok(),
        (Err(raison), _) => Resultat::echec(raison),
    };
    match g {
        GesteUnix::Programme(p) => monde.programme(p),
        GesteUnix::Unite(a, u) => fait(monde.unite(a, u.nom)),
        GesteUnix::Designee(a, nom) => fait(monde.unite(a, nom.as_str())),
        GesteUnix::ReinitialiserEchecs => fait(monde.reinitialiser_echecs()),
        GesteUnix::SignaturesClamav => signatures_clamav(monde),
        // Fait plus haut, par `Monde::defense`.
        GesteUnix::Defense(..) => Resultat::echec(tr!("geste refusé", "step refused")),
    }
}

/// Avant la question d'accord de l'arrêt d'un logiciel de prise en main désigné : `None` pour continuer, sinon la fin
/// du geste. Pas en marche : rien à arrêter, sans question. Puis ce que l'arrêt lancerait et les signes qu'une session
/// passe par lui (`arret_designe_revu`), avant de rien demander : un signe vu refuse même si la personne dirait « non ».
/// Enfin la question « êtes-vous connecté par lui ? » : seul un « non » tapé au terminal mène à l'accord ; « oui »,
/// Entrée seule, l'entrée finie ou aucun terminal le laissent en marche. Un échec, pas une note : le reste de la liste
/// (arrêt des processus, désinstallation) ne doit pas couper la session à sa place.
fn avant_l_arret_designe(nom: &str, monde: &mut dyn Monde) -> Option<Resultat> {
    let vu = crate::ui::affichable(nom);
    match monde.etat_d_activite(nom) {
        Ok(e) if tourne(e.as_deref()) => {}
        Ok(_) => {
            return Some(Resultat::ok_note(trf!(
                "{vu} n'est pas en marche : rien à arrêter",
                "{vu} is not running: nothing to stop"
            )));
        }
        Err(raison) => return Some(Resultat::echec(raison)),
    }
    if let Err(raison) = arret_designe_revu(nom, monde) {
        return Some(arret_refuse(&raison));
    }
    if !arret_designe::dit_non(monde.connecte(nom).as_deref()) {
        return Some(arret_refuse(&trf!(
            "{vu} n'est pas arrêté : vous n'avez pas répondu « non » (êtes-vous connecté par lui ?) ; il reste en marche, une session qui passe par lui n'est pas coupée. S'il est retiré du démarrage, il ne repartira plus au prochain redémarrage",
            "{vu} is not stopped: you did not answer \"no\" (are you connected through it?); it stays running, a session going through it is not cut. If it is removed from startup, it will not start again at the next restart"
        )));
    }
    None
}

/// Une unité en marche, d'après son état d'activité lu sur le bus : en train de partir ou de s'arrêter compris.
fn tourne(etat: Option<&str>) -> bool {
    matches!(etat, Some("active" | "activating" | "reloading" | "deactivating"))
}

/// L'arrêt d'une unité désignée refusé, ou pas voulu : un échec, qui arrête aussi la suite de la liste. Le parent met
/// cet arrêt avant la désinstallation d'un paquet (dont les scripts arrêteraient l'unité sans rien demander) : tant
/// qu'elle tourne, aucun paquet n'est retiré, et c'est dit, sans affirmer qu'il y en a un.
fn arret_refuse(raison: &dyn std::fmt::Display) -> Resultat {
    let raison = raison.to_string();
    let raison = raison.trim_end_matches('.');
    Resultat::echec(trf!(
        "{raison}. Tant qu'il tourne, la suite n'est pas faite non plus, ni la désinstallation d'un paquet qui le porte : elle l'arrêterait sans rien demander",
        "{raison}. As long as it runs, the rest is not done either, nor the removal of a package that carries it: that would stop it without asking"
    ))
}

/// L'arrêt d'un logiciel de prise en main désigné, revu : ce que systemd en dit relu sur le bus, puis, preuves
/// seulement, une session portée par lui (Vanguard lui-même dans son groupe, ou une session de logind qu'il porte),
/// puis ce que l'arrêt lancerait (`arret_designe::juger_arret`). Toute lecture impossible refuse. Les unités du même
/// logiciel que l'arrêt entraîne (`arret_designe::du_meme_logiciel`) passent les mêmes revues, fichier compris ;
/// rendues pour être dites. Les autres refusent.
fn arret_designe_revu(nom: &str, monde: &mut dyn Monde) -> Result<Vec<String>, Echec> {
    let Some(lu) = monde.arret_charge(nom)? else {
        return Err(refus(trf!(
            "{} n'est pas chargé par le gestionnaire de services : rien n'est arrêté",
            "{} is not loaded by the service manager: nothing is stopped",
            crate::ui::affichable(nom)
        )));
    };
    let lignee = monde.groupes_de_la_lignee();
    let Some(sessions) = monde.sessions() else {
        return Err(refus(trf!(
            "{} n'est pas arrêté : les sessions ouvertes sur cet ordinateur ne se lisent pas, et l'une d'elles passe peut-être par lui",
            "{} is not stopped: the sessions open on this computer cannot be read, and one of them may go through it",
            crate::ui::affichable(nom)
        )));
    };
    if let Some(raison) = arret_designe::porte_par_l_outil(nom, &lu.groupe, &lignee, &sessions) {
        return Err(refus(raison));
    }
    let (memes, autres) = arret_designe::du_meme_logiciel(nom, &lu.entrainees);
    let ensemble: Vec<&str> = std::iter::once(nom).chain(memes.iter().map(String::as_str)).collect();
    let mut avec = Vec::new();
    for e in &memes {
        // Pas chargée, ou pas en marche : l'arrêt ne l'arrête pas, et ne lance rien d'elle ; ni son fichier ni ses
        // sessions ne comptent.
        let Some(lu_e) = monde.arret_charge(e)? else {
            continue;
        };
        if !tourne(monde.etat_d_activite(e)?.as_deref()) {
            continue;
        }
        unite_revue(e, monde)?;
        if let Some(raison) = arret_designe::porte_par_l_outil(e, &lu_e.groupe, &lignee, &sessions) {
            return Err(refus(raison));
        }
        let reste: Vec<String> = lu_e
            .entrainees
            .iter()
            .filter(|n| !ensemble.contains(&n.as_str()))
            .cloned()
            .collect();
        arret_designe::juger_arret(
            e,
            &ArretCharge {
                entrainees: reste,
                ..lu_e
            },
            &|c| monde.chemin(c),
        )?;
        avec.push(e.clone());
    }
    arret_designe::juger_arret(
        nom,
        &ArretCharge {
            entrainees: autres,
            ..lu
        },
        &|c| monde.chemin(c),
    )?;
    Ok(avec)
}

/// `signatures-clamav` : le service de mise à jour, s'il est installé, verrouille la base pendant qu'il tourne ; s'il
/// tourne, il est arrêté le temps de freshclam, puis redémarré, même si freshclam a échoué : jamais laissé arrêté. Ni
/// un signal de fin (terminal fermé, Ctrl+C), ni une panique, ni un arrêt refusé ne sautent la remise en route. Son
/// lancement au démarrage n'est jamais changé (rien ne le noterait pour le défaire) : coupé, il le reste, et c'est
/// dit. Masqué par l'administrateur, il n'est pas touché, et c'est noté.
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
    // Le service n'est arrêté que s'il tourne (lui seul tient le verrou de la base), et remis seulement en marche :
    // son lancement au démarrage n'est jamais changé, ce geste ne note rien qui permettrait de le défaire.
    let r = match monde.etat_d_activite(service) {
        // En train de s'arrêter : il tient peut-être encore le verrou. Son arrêt est attendu, et il reste arrêté,
        // comme il allait l'être.
        Ok(Some(a)) if matches!(a.as_str(), "active" | "activating" | "reloading" | "deactivating") => {
            // Arrêté puis relancé en root, il lancerait ce que disent son fichier et ses compléments : revus d'abord,
            // comme pour tout geste d'unité (É-2 du lot U3) ; douteux, il n'est pas touché, et c'est dit.
            match unite_revue(service, monde) {
                Ok(()) => freshclam_service_arrete(monde, a != "deactivating"),
                Err(raison) => freshclam_sans_le_service(monde, &raison),
            }
        }
        Ok(_) => monde.programme(&gestes_unix::FRESHCLAM),
        // Sans savoir s'il tourne : freshclam seul, sans toucher au service ; un échec le dit.
        Err(raison) => {
            let r = monde.programme(&gestes_unix::FRESHCLAM);
            if r.reussi {
                r
            } else {
                Resultat::echec(trf!(
                    "{} (l'état du service de mise à jour automatique ne se lit pas : il tient peut-être la base. {raison})",
                    "{} (the state of the automatic update service cannot be read: it may be holding the database. {raison})",
                    r.raison
                ))
            }
        }
    };
    if r.reussi && matches!(etat.as_deref(), Some("disabled" | "static")) {
        // Coupée avant, coupée après : dit, plutôt que de laisser croire qu'elle tourne. Seulement pour ces deux
        // états : « indirect », « enabled-runtime », « generated », « linked », « alias » la lancent peut-être
        // au démarrage, par un autre chemin. Une note déjà là (le service écarté par la revue, et pourquoi) est
        // gardée devant (B-4 du lot U3) : la remplacer cacherait qu'il n'a pas été touché.
        return Resultat::ok_note(match r.note {
            Some(note) => trf!(
                "{note} ; et leur mise à jour automatique n'est pas lancée au démarrage, Vanguard la laisse ainsi",
                "{note}; and their automatic update is not started at boot, Vanguard leaves it that way"
            ),
            None => String::from(tr!(
                "signatures à jour ; leur mise à jour automatique n'est pas lancée au démarrage, et Vanguard la laisse ainsi",
                "signatures up to date; their automatic update is not started at boot, and Vanguard leaves it that way"
            )),
        });
    }
    r
}

/// freshclam seul, le service de mise à jour laissé tel quel parce que son fichier n'a pas passé la revue (`raison`) :
/// il tient peut-être le verrou de la base, ce qu'un échec dit.
fn freshclam_sans_le_service(monde: &mut dyn Monde, raison: &Echec) -> Resultat {
    let r = monde.programme(&gestes_unix::FRESHCLAM);
    if r.reussi {
        Resultat::ok_note(trf!(
            "signatures à jour ; le service de mise à jour automatique n'a pas été touché : {raison}",
            "signatures up to date; the automatic update service was not touched: {raison}"
        ))
    } else {
        Resultat::echec(trf!(
            "{} (le service de mise à jour automatique, qui tient peut-être la base, n'a pas été arrêté : {raison})",
            "{} (the automatic update service, which may be holding the database, was not stopped: {raison})",
            r.raison
        ))
    }
}

/// freshclam, le service de mise à jour arrêté le temps du téléchargement, puis remis en marche dans tous les cas
/// (`relancer`) ; sans `relancer` (il était en train de s'arrêter), laissé arrêté.
fn freshclam_service_arrete(monde: &mut dyn Monde, relancer: bool) -> Resultat {
    let service = gestes_unix::CLAMAV_FRESHCLAM.nom;
    // Posés avant l'arrêt, retirés après la remise en route (ordre inverse des `let`) : entre les deux, la fenêtre
    // fermée ne tue plus l'assistant au milieu.
    let _signaux = SignauxIgnores::poser();
    let mut relance = Relance {
        monde,
        service,
        faite: !relancer,
    };
    // Un arrêt en échec n'arrête pas la suite : le service a pu s'arrêter quand même, ou ne tenir aucun verrou ;
    // freshclam le dira s'il bute dessus, et le service est remis en route dans tous les cas.
    let arret = relance.monde.unite(ActionUnite::Arreter, service);
    let r = relance.monde.programme(&gestes_unix::FRESHCLAM);
    let reprise = if relancer {
        remettre_en_route(relance.monde, service)
    } else {
        Ok(())
    };
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

/// Remet en marche le service de mise à jour, tel qu'il tournait avant l'arrêt : démarré, jamais activé (son
/// lancement au démarrage reste ce qu'il était). Son fichier est revu juste avant : changé pendant le téléchargement,
/// il ferait lancer en root ce qu'il dit ; il reste alors arrêté, et l'échec le dit.
fn remettre_en_route(monde: &mut dyn Monde, service: &str) -> Result<(), Echec> {
    unite_revue(service, monde)?;
    monde.unite(ActionUnite::Demarrer, service)
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
pub(super) fn langue_ou_terminal(nom: &std::ffi::OsStr) -> bool {
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
pub(super) fn derniere_ligne(texte: &str) -> Option<String> {
    let l = texte.lines().rev().map(str::trim).find(|l| !l.is_empty())?;
    Some(crate::ui::affichable(&l.chars().take(200).collect::<String>()))
}

/// La réponse de la personne à une question d'accord : seuls « o », « oui », « y » et « yes » (majuscules permises)
/// disent oui ; le reste, une ligne vide comprise, dit non. Une seule ligne, bornée, est lue.
#[cfg(test)]
fn accord(question: &str, lecteur: &mut impl BufRead, ecrivain: &mut impl Write) -> bool {
    reponse(question, lecteur, ecrivain).is_some_and(|r| est_oui(&r))
}

/// Seuls « o », « oui », « y » et « yes » (casse et espaces autour ignorés) valent un accord.
pub(super) fn est_oui(reponse: &str) -> bool {
    matches!(reponse.trim().to_lowercase().as_str(), "o" | "oui" | "y" | "yes")
}

/// Pose `question` et lit une seule ligne, bornée à 64 octets ; `None` : la question ne s'écrit pas, la lecture
/// échoue, ou l'entrée est finie sans rien (Ctrl+D, terminal fermé).
fn reponse(question: &str, lecteur: &mut impl BufRead, ecrivain: &mut impl Write) -> Option<String> {
    write!(ecrivain, "{question} ").and_then(|()| ecrivain.flush()).ok()?;
    let mut ligne = String::new();
    match (&mut *lecteur).take(64).read_line(&mut ligne) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(ligne),
    }
}

/// Pose `question` sur le terminal de la personne (/dev/tty), jamais sur le canal du parent, après avoir vidé ce qui
/// a été tapé d'avance : la ligne lue (`reponse`). `Err(())` : aucun terminal.
pub(crate) fn question_au_terminal(question: &str) -> Result<Option<String>, ()> {
    use std::os::fd::AsRawFd;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| ())?;
    // Ce qui a été tapé d'avance, ou glissé avant la question, ne répond pas à sa place.
    // SAFETY: tcflush sur un descripteur ouvert que `tty` tient pendant l'appel ; aucun pointeur.
    unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) };
    let mut ecrivain = &tty;
    let mut lecteur = BufReader::new(&tty);
    Ok(reponse(question, &mut lecteur, &mut ecrivain))
}

/// Pourquoi ce geste demande l'accord, dans la langue de l'interface (`GesteUnix::pourquoi_l_accord`).
#[allow(
    clippy::large_types_passed_by_value,
    reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
)]
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
#[allow(
    clippy::large_types_passed_by_value,
    reason = "un geste lu d'une ligne, copié une fois : quelques centaines d'octets"
)]
fn accord_au_terminal(g: GesteUnix) -> Result<(), Refus> {
    let question = trf!(
        "Vanguard (administrateur) : {} — {}. D'accord ? Tapez « oui » puis Entrée (autre chose refuse) :",
        "Vanguard (administrator): {} — {}. Agree? Type \"yes\" then Enter (anything else refuses):",
        texte_du_geste(g),
        pourquoi_dit(g)
    );
    let Ok(lu) = question_au_terminal(&question) else {
        return Err(Refus(
            tr!(
            "ce geste demande votre accord, et aucun terminal n'est là pour le donner : rien n'est fait. Lancez Vanguard depuis un terminal pour le faire",
            "this step needs your agreement, and no terminal is there to give it: nothing is done. Start Vanguard from a terminal to do it"
        )
            .to_string(),
        ));
    };
    if lu.is_some_and(|r| est_oui(&r)) {
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

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::blocage::pare_feu::PareFeu;

    fn pf() -> PareFeu {
        PareFeu::Nftables
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
        assert_eq!(
            methodes(true, true, false, avec_polkit(true, tout)),
            [Methode::Pkexec, Methode::Run0, Methode::Sudo]
        );
        // Sans session graphique : pas de pkexec ; sans terminal : pas de run0.
        assert_eq!(
            methodes(false, true, false, avec_polkit(true, tout)),
            [Methode::Run0, Methode::Sudo]
        );
        assert_eq!(methodes(false, false, false, avec_polkit(true, tout)), [Methode::Sudo]);
        assert_eq!(
            methodes(true, false, false, avec_polkit(true, |n| n == "pkexec")),
            [Methode::Pkexec]
        );
        // Sans polkit (images cloud de Fedora et d'Arch) : run0 et pkexec présents ne sont pas essayés, sudo l'est
        // (B-1) ; sans sudo non plus, rien, et c'est dit.
        assert_eq!(methodes(true, true, false, avec_polkit(false, tout)), [Methode::Sudo]);
        assert_eq!(methodes(false, true, false, avec_polkit(false, tout)), [Methode::Sudo]);
        assert_eq!(methodes(true, true, false, avec_polkit(false, |n| n != "sudo")), []);
        assert_eq!(methodes(true, true, false, avec_polkit(true, |_| false)), []);
        // Un geste demande l'accord sur le terminal : ni pkexec ni run0 (pas de terminal pour le fils), sudo seulement
        // depuis un terminal ; sinon rien, et le texte nomme ce qui manque. polkit n'y change rien.
        for polkit in [true, false] {
            assert_eq!(methodes(true, true, true, avec_polkit(polkit, tout)), [Methode::Sudo]);
            assert_eq!(methodes(true, true, true, avec_polkit(polkit, |n| n != "sudo")), []);
            assert_eq!(methodes(true, false, true, avec_polkit(polkit, tout)), []);
        }
        for terminal in [true, false] {
            let t = sans_methode(true, terminal);
            assert!(t.contains("sudo") && t.contains("pkexec") && t.contains("run0"), "{t}");
        }
        assert!(sans_methode(true, false).contains("terminal"));
        assert!(sans_methode(true, true).contains("installé") || sans_methode(true, true).contains("installed"));
    }

    /// É-7 du lot U3 : pkexec reçoit le chemin réel de l'image, que pkexec 126 peut vérifier avec l'identité de la
    /// personne pendant que ce processus n'est plus « dumpable » ; run0 et sudo gardent `/proc/<pid>/exe`, qui
    /// désigne l'image qui tourne même remplacée.
    #[test]
    fn pkexec_recoit_le_chemin_reel() {
        let image = std::env::current_exe().map(std::path::PathBuf::into_os_string).ok();
        assert!(image.is_some());
        assert_eq!(programme(Methode::Pkexec), image);
        let par_proc = Some(std::ffi::OsString::from(format!("/proc/{}/exe", std::process::id())));
        assert_eq!(programme(Methode::Run0), par_proc);
        assert_eq!(programme(Methode::Sudo), par_proc);
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
                demande: true,
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
        assert_eq!(analyser_liste(&lignes), Some(groupes));
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

    /// Un geste de défense passe par le même canal ; une ligne de défense forgée (champ en plus, identifiant hors de la
    /// forme, mot inconnu, nom qui commence par « - », saut de ligne glissé) fait refuser toute la liste, même mêlée à
    /// des lignes justes. Accepté, il est confié à `Monde::defense`, sans passer par l'accord commun.
    #[test]
    fn les_gestes_de_defense_forges_sont_refuses() {
        let juste = "vanguard:geste defense verrouiller-compte alice 0123456789abcdef";
        let lignes = vec![juste.to_string()];
        let groupes = analyser_liste(&lignes).unwrap();
        let [Demande::Geste(g)] = groupes[0].as_slice() else {
            panic!("{groupes:?}");
        };
        let mut m = FauxMonde::nouveau();
        assert!(faire_geste(*g, &mut m).reussi);
        assert_eq!(m.journal.len(), 1, "{:?}", m.journal);
        assert!(m.journal[0].starts_with("defense "), "{:?}", m.journal);
        for forge in [
            "vanguard:geste defense verrouiller-compte alice 0123456789abcdef x",
            "vanguard:geste defense verrouiller-compte alice 0123456789ABCDEF",
            "vanguard:geste defense verrouiller-compte alice 0123",
            "vanguard:geste defense verrouiller-compte -alice 0123456789abcdef",
            "vanguard:geste defense verrouiller-compte alice\nroot 0123456789abcdef",
            "vanguard:geste defense supprimer-compte alice 0123456789abcdef",
            "vanguard:geste defense retirer-du-groupe wheel alice 0123456789abcdef",
            "vanguard:geste defense desactiver-service sshd.service 0123456789abcdef",
            "vanguard:geste defense retirer-ligne 00 2f6574632f736861646f77 0123456789abcdef",
            // « Refaire » (D7b) : un autre programme que celui de Vanguard, un dossier d'un compte, un champ en trop.
            "vanguard:geste defense remettre-programme 2f7573722f62696e2f7375646f 0123456789abcdef",
            "vanguard:geste defense remettre-programme 2f686f6d652f616c6963652f76616e6775617264 0123456789abcdef",
            "vanguard:geste defense remettre-programme 2f7573722f6c6f63616c2f62696e2f76616e6775617264 00 0123456789abcdef",
        ] {
            let l = vec![juste.to_string(), forge.to_string()];
            assert_eq!(analyser_liste(&l), None, "{forge:?}");
            let l = lire_lignes(format!("{juste}\n{forge}\nfin\n").as_bytes());
            assert!(l.is_none_or(|l| analyser_liste(&l).is_none()), "{forge:?}");
        }
    }

    /// Lot D7c. Une coupure de pare-feu n'arrive que seule : mêlée à une autre ligne (avant, après, dans un autre
    /// groupe, deux coupures), toute la liste est refusée ; seule, elle passe.
    #[test]
    fn une_coupure_de_pare_feu_n_arrive_que_seule() {
        let coupe = "vanguard:geste defense couper-pare-feu ufw 000000000000fe01";
        let autre = "vanguard:geste defense verrouiller-compte alice 0123456789abcdef";
        let seule = analyser_liste(&[coupe.to_string()]);
        assert!(seule.is_some_and(|g| g.len() == 1 && g[0].len() == 1));
        for meles in [
            vec![coupe, autre],
            vec![autre, coupe],
            vec![coupe, SUITE, autre],
            vec![autre, SUITE, coupe],
            vec![coupe, coupe],
            vec![
                coupe,
                "vanguard:geste defense couper-pare-feu firewalld 000000000000fe02",
            ],
            vec![coupe, "vanguard:geste programme freshclam"],
            vec![coupe, "vanguard:couper-connexions 203.0.113.7"],
        ] {
            let l: Vec<String> = meles.iter().map(|s| (*s).to_string()).collect();
            assert_eq!(analyser_liste(&l), None, "{meles:?}");
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
        fichier: Result<bool, Echec>,
        /// Ce que devient `fichier` une fois l'accord donné (un fichier changé pendant la question).
        fichier_apres_accord: Option<Result<bool, Echec>>,
        /// Combien de fois le fichier a été revu.
        revues: std::cell::Cell<usize>,
        /// À partir de cette revue (la première est 1), le fichier devient douteux : changé entre deux revues.
        douteux_des: Option<usize>,
        /// De vrais dossiers d'unités (dossiers, racine, propriétaire attendu) : `fichier_sur` les lit alors au lieu
        /// de rendre `fichier`.
        disque: Option<(Vec<std::path::PathBuf>, std::path::PathBuf, u32)>,
        /// Ce que rend `arret_a_la_main`.
        arret: Result<Option<bool>, Echec>,
        etat: Result<Option<String>, Echec>,
        actif: Result<Option<String>, Echec>,
        /// Les actions (`ActionUnite::mot`) qui échouent.
        echecs: Vec<&'static str>,
        programme_reussi: bool,
        /// Le programme panique au lieu de rendre son issue.
        programme_panique: bool,
        /// Ce que rend `arret_charge`.
        arret_charge: Result<Option<ArretCharge>, Echec>,
        /// Ce que rend `arret_charge` pour ces unités-là, à la place.
        arret_charge_de: Vec<(&'static str, Option<ArretCharge>)>,
        /// Les unités dont le fichier est douteux ; les autres rendent `fichier`.
        fichiers_douteux: Vec<&'static str>,
        /// Unités arrêtées (« inactive »), quel que soit `actif`.
        arretees: Vec<&'static str>,
        /// Les groupes de la lignée de Vanguard.
        lignee: Vec<String>,
        /// `None` : la liste des sessions ne se lit pas.
        sessions: Option<Vec<SessionVue>>,
        /// Les sessions vues une fois la question « connecté par lui ? » posée (une session ouverte pendant).
        sessions_apres_question: Option<Vec<SessionVue>>,
        /// La réponse à « êtes-vous connecté par lui ? » ; `None` : l'entrée est finie, ou aucun terminal.
        reponse: Option<&'static str>,
        /// Les chemins que `chemin` dit douteux ; les autres sont sûrs, tels quels.
        chemins_douteux: Vec<&'static str>,
    }

    impl FauxMonde {
        fn nouveau() -> Self {
            FauxMonde {
                journal: Vec::new(),
                refus: None,
                systemd: true,
                session: Some(false),
                fichier: Ok(true),
                fichier_apres_accord: None,
                revues: std::cell::Cell::new(0),
                douteux_des: None,
                disque: None,
                arret: Ok(Some(true)),
                etat: Ok(Some("enabled".into())),
                actif: Ok(Some("active".into())),
                echecs: Vec::new(),
                programme_reussi: true,
                programme_panique: false,
                arret_charge: Ok(Some(ArretCharge {
                    lancement: vec![arret_designe::Commande {
                        chemin: "/usr/bin/anydesk".into(),
                        arguments: vec!["/usr/bin/anydesk".into(), "--service".into()],
                    }],
                    groupe: "/system.slice/anydesk.service".into(),
                    ..ArretCharge::default()
                })),
                arret_charge_de: Vec::new(),
                fichiers_douteux: Vec::new(),
                arretees: Vec::new(),
                lignee: vec!["/user.slice/user-1000.slice/session-2.scope".into()],
                sessions: Some(Vec::new()),
                sessions_apres_question: None,
                reponse: Some("non"),
                chemins_douteux: Vec::new(),
            }
        }
    }

    impl Monde for FauxMonde {
        fn accord(&mut self, _: GesteUnix) -> Result<(), Refus> {
            self.journal.push("accord".into());
            if let Some(f) = self.fichier_apres_accord.take() {
                self.fichier = f;
            }
            self.refus.map_or(Ok(()), |r| Err(Refus(r.into())))
        }
        fn systemd(&self) -> bool {
            self.systemd
        }
        fn session_entrante(&self) -> Option<bool> {
            self.session
        }
        fn fichier_sur(&self, unite: &str) -> Result<bool, Echec> {
            let n = self.revues.get() + 1;
            self.revues.set(n);
            if self.douteux_des.is_some_and(|d| n >= d) {
                return Err(Echec::refuse("essai", "fichier changé entre deux revues"));
            }
            if self.fichiers_douteux.contains(&unite) {
                return Err(Echec::refuse("essai", "complément douteux"));
            }
            match &self.disque {
                Some((dossiers, racine, qui)) => {
                    let d: Vec<&std::path::Path> = dossiers.iter().map(std::path::PathBuf::as_path).collect();
                    fichier_d_unite_sur(&d, racine, unite, Proprietaire::strict(*qui))
                }
                None => self.fichier.clone(),
            }
        }
        fn arret_a_la_main(&mut self, _: &str) -> Result<Option<bool>, Echec> {
            self.arret.clone()
        }
        fn etat_du_fichier(&mut self, unite: &str) -> Result<Option<String>, Echec> {
            self.journal.push(format!("etat {unite}"));
            self.etat.clone()
        }
        fn etat_d_activite(&mut self, unite: &str) -> Result<Option<String>, Echec> {
            self.journal.push(format!("actif {unite}"));
            if self.arretees.contains(&unite) {
                return Ok(Some("inactive".into()));
            }
            self.actif.clone()
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
        fn arret_charge(&mut self, unite: &str) -> Result<Option<ArretCharge>, Echec> {
            self.journal.push(format!("arret-lu {unite}"));
            match self.arret_charge_de.iter().find(|(u, _)| *u == unite) {
                Some((_, lu)) => Ok(lu.clone()),
                None => self.arret_charge.clone(),
            }
        }
        fn groupes_de_la_lignee(&self) -> Vec<String> {
            self.lignee.clone()
        }
        fn sessions(&mut self) -> Option<Vec<SessionVue>> {
            self.sessions.clone()
        }
        fn chemin(&self, chemin: &str) -> Chemin {
            if self.chemins_douteux.contains(&chemin) {
                Chemin::Douteux
            } else {
                Chemin::Sur { reel: chemin.into() }
            }
        }
        fn connecte(&mut self, nom: &str) -> Option<String> {
            self.journal.push(format!("question {nom}"));
            if let Some(s) = self.sessions_apres_question.take() {
                self.sessions = Some(s);
            }
            self.reponse.map(String::from)
        }
        fn defense(&mut self, d: gestes_unix::Defense, _: gestes_unix::IdNote) -> Resultat {
            self.journal.push(format!("defense {d:?}"));
            Resultat::ok_note("défense")
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
        // Le réseau rechargé non plus : relire sa configuration peut réappliquer les connexions et faire tomber
        // celle en cours.
        for u in [&gestes_unix::NETWORKMANAGER, &gestes_unix::NETWORKD] {
            let recharger = GesteUnix::Unite(ActionUnite::Recharger, u);
            assert_eq!(essai(recharger, &|m| m.session = Some(true)), (false, vide.clone()));
            assert_eq!(essai(recharger, &|m| m.session = None), (false, vide.clone()));
            assert_eq!(essai(recharger, &rien), (true, vec![format!("recharger {}", u.nom)]));
        }
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
        // L'arrêt : en marche, relu, la question « connecté par lui ? », l'accord, relu encore, puis l'arrêt.
        let arret_complet = || {
            [
                "actif anydesk.service",
                "arret-lu anydesk.service",
                "question anydesk.service",
                "accord",
                "arret-lu anydesk.service",
                "arreter anydesk.service",
            ]
            .map(s)
            .to_vec()
        };
        let jusqu_a_l_accord = || arret_complet()[..4].to_vec();
        assert_eq!(essai(arreter, &|_| {}), (true, arret_complet()));
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
        assert_eq!(essai(arreter, &|m| m.refus = Some("non")), (false, jusqu_a_l_accord()));
        // Une session ouverte, ou illisible, n'empêche pas d'arrêter le logiciel de prise de contrôle : ses propres
        // connexions sont justement celles du faux technicien.
        for session in [Some(true), None] {
            assert_eq!(
                essai(arreter, &|m| m.session = session),
                (true, arret_complet()),
                "{session:?}"
            );
        }
        assert_eq!(
            essai(arreter, &|m| m.fichier = Err(Echec::refuse("essai", "lien"))),
            (false, vec![])
        );
        // Le fichier changé pendant la question (remplacé par un lien, rendu modifiable) : revu après l'accord,
        // refusé, rien n'est arrêté ni retiré.
        for (g, attendu) in [
            (arreter, jusqu_a_l_accord()),
            (retirer, vec![s("etat anydesk.service"), s("accord")]),
        ] {
            assert_eq!(
                essai(g, &|m| m.fichier_apres_accord =
                    Some(Err(Echec::refuse("essai", "remplacé")))),
                (false, attendu),
                "{g:?}"
            );
        }
        // Le retrait du démarrage demande qu'il soit activé ; l'arrêt, non (`l_arret_designe_ne_demande_pas_qu_il_soit_active`).
        for etat in [None, Some(s("disabled")), Some(s("masked")), Some(s("static"))] {
            let (reussi, journal) = essai(retirer, &|m| m.etat = Ok(etat.clone()));
            assert!(!reussi && journal == [s("etat anydesk.service")], "{etat:?}");
        }
        assert_eq!(
            essai(retirer, &|m| m.etat = Err(Echec::echoue("essai", "bus"))),
            (false, vec![s("etat anydesk.service")])
        );
        // Un service qui n'est pas un logiciel de prise de contrôle : refusé avant de regarder son fichier.
        let autre = gestes_unix::designee(ActionUnite::Arreter, "bluetooth.service").unwrap();
        assert_eq!(essai(autre, &|_| {}), (false, vec![]));
    }

    /// La question de l'arrêt : l'entrée finie sans rien (Ctrl+D, terminal fermé) ne répond rien, donc pas « non » ;
    /// une ligne longue est coupée à 64 octets, jamais lue au-delà.
    #[test]
    fn fin_d_entree_ne_dit_pas_non() {
        let lire = |entree: &[u8]| reponse("?", &mut std::io::BufReader::new(entree), &mut Vec::new());
        assert_eq!(lire(b""), None);
        assert!(!arret_designe::dit_non(lire(b"").as_deref()));
        assert!(arret_designe::dit_non(lire(b"non\n").as_deref()));
        assert!(!arret_designe::dit_non(lire(b"\n").as_deref()));
        let longue = format!("{}non\n", " ".repeat(64));
        assert!(!arret_designe::dit_non(lire(longue.as_bytes()).as_deref()));
    }

    /// L'arrêt d'un logiciel de prise en main désigné ne se fait que sur un « non » tapé à « êtes-vous connecté par
    /// lui ? », puis l'accord : « oui », Entrée seule, l'entrée finie, une autre réponse le laissent en marche, sans
    /// même demander l'accord. L'arrêt fait le dit « par votre choix », avec de quoi le remettre.
    #[test]
    fn l_arret_designe_ne_se_fait_que_sur_un_non() {
        let arreter = gestes_unix::designee(ActionUnite::Arreter, "anydesk.service").unwrap();
        if !arreter.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        // Son état au démarrage n'est pas lu : l'arrêt ne demande pas qu'il soit activé.
        let jusqu_a_la_question = [
            "actif anydesk.service",
            "arret-lu anydesk.service",
            "question anydesk.service",
        ];
        for reponse in [
            Some("oui"),
            Some("o"),
            Some("yes"),
            Some(""),
            Some("\n"),
            Some("non merci"),
            Some("nnon"),
            Some("peut-être"),
            None,
        ] {
            let mut m = FauxMonde::nouveau();
            m.reponse = reponse;
            let r = faire_geste(arreter, &mut m);
            assert!(!r.reussi && r.raison.contains("anydesk.service"), "{reponse:?} : {r:?}");
            assert_eq!(m.journal, jusqu_a_la_question, "{reponse:?}");
        }
        for reponse in ["non", "Non", " NO \n", "n"] {
            let mut m = FauxMonde::nouveau();
            m.reponse = Some(reponse);
            let r = faire_geste(arreter, &mut m);
            assert!(r.reussi, "{reponse:?} : {r:?}");
            assert!(m.journal.last().is_some_and(|l| l == "arreter anydesk.service"));
            let note = r.note.unwrap_or_default();
            assert!(note.contains("systemctl start anydesk.service"), "{note}");
            if !crate::langue::anglais() {
                assert!(note.contains("arrêté par votre choix"), "{note}");
            }
        }
        // Le « non » donné, l'accord refusé : rien n'est arrêté.
        let mut m = FauxMonde::nouveau();
        m.refus = Some("pas d'accord");
        assert!(!faire_geste(arreter, &mut m).reussi);
        assert!(!m.journal.iter().any(|l| l == "arreter anydesk.service"));
    }

    /// Les preuves qu'une session passe par l'outil refusent l'arrêt avant toute question, même si la personne
    /// aurait dit « non » ; une session ouverte par lui pendant la question le refuse juste avant le geste. Pas en
    /// marche : rien à arrêter, sans question. Ce que l'arrêt lancerait, douteux ou illisible, refuse aussi avant.
    #[test]
    fn l_arret_designe_revoit_les_preuves_et_ce_qu_il_lancerait() {
        type Reglage<'a> = &'a dyn Fn(&mut FauxMonde);
        let arreter = gestes_unix::designee(ActionUnite::Arreter, "anydesk.service").unwrap();
        if !arreter.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let essai = |regler: &dyn Fn(&mut FauxMonde)| {
            let mut m = FauxMonde::nouveau();
            regler(&mut m);
            let r = faire_geste(arreter, &mut m);
            let questions = m
                .journal
                .iter()
                .filter(|l| l.starts_with("question") || *l == "accord")
                .count();
            let arrete = m.journal.iter().any(|l| l == "arreter anydesk.service");
            (r, questions, arrete)
        };
        let dans_l_outil = "/system.slice/anydesk.service/session".to_string();
        let portee = SessionVue {
            distante: false,
            service: "anydesk".into(),
            groupes_du_meneur: vec![dans_l_outil.clone()],
        };
        let refuses: [(&str, Reglage); 8] = [
            ("lignée", &|m| m.lignee.push(dans_l_outil.clone())),
            ("session", &|m| m.sessions = Some(vec![portee.clone()])),
            ("sessions illisibles", &|m| m.sessions = None),
            ("pas chargé", &|m| m.arret_charge = Ok(None)),
            ("illisible", &|m| m.arret_charge = Err(Echec::echoue("essai", "bus"))),
            ("activité illisible", &|m| m.actif = Err(Echec::echoue("essai", "bus"))),
            ("arrêt douteux", &|m| {
                if let Ok(Some(lu)) = &mut m.arret_charge {
                    lu.arret = vec![arret_designe::Commande {
                        chemin: "/bin/sh".into(),
                        arguments: vec!["sh".into(), "-c".into(), "rm -rf /".into()],
                    }];
                }
            }),
            ("exécutable douteux", &|m| {
                m.chemins_douteux = vec!["/usr/bin/anydesk"];
                if let Ok(Some(lu)) = &mut m.arret_charge {
                    lu.arret = vec![arret_designe::Commande {
                        chemin: "/usr/bin/anydesk".into(),
                        arguments: vec!["/usr/bin/anydesk".into(), "--stop-service".into()],
                    }];
                }
            }),
        ];
        for (cas, regler) in refuses {
            let (r, questions, arrete) = essai(regler);
            assert!(!r.reussi && !arrete && questions == 0, "{cas} : {r:?}");
        }
        // Une session portée par l'outil, ouverte pendant la question : refusé avant l'arrêt.
        let (r, _, arrete) = essai(&|m| m.sessions_apres_question = Some(vec![portee.clone()]));
        assert!(!r.reussi && !arrete, "{r:?}");
        // Pas en marche : dit, sans question ni arrêt.
        for etat in [None, Some("inactive".to_string()), Some("failed".to_string())] {
            let (r, questions, arrete) = essai(&|m| m.actif = Ok(etat.clone()));
            assert!(r.reussi && questions == 0 && !arrete, "{etat:?} : {r:?}");
        }
    }

    /// Un service qui tourne sans être lancé au démarrage (préréglage du paquet, à la
    /// main, processus caché par hidepid) passe par le même arrêt, ses questions et ses preuves, avant le retrait de
    /// son paquet. Son retrait du démarrage, lui, demande toujours qu'il soit activé. Un « oui », rien, ou l'entrée
    /// finie : un échec qui dit que le paquet n'est pas retiré, après un retrait du démarrage fait quand même.
    #[test]
    fn l_arret_designe_ne_demande_pas_qu_il_soit_active() {
        let arreter = gestes_unix::designee(ActionUnite::Arreter, "anydesk.service").unwrap();
        let retirer = gestes_unix::designee(ActionUnite::DesactiverSansArreter, "anydesk.service").unwrap();
        if !arreter.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        for etat in [None, Some("disabled"), Some("static"), Some("indirect")] {
            let mut m = FauxMonde::nouveau();
            m.etat = Ok(etat.map(String::from));
            let r = faire_geste(arreter, &mut m);
            assert!(r.reussi, "{etat:?} : {r:?}");
            assert!(m.journal.iter().any(|l| l == "question anydesk.service"), "{etat:?}");
            assert!(
                m.journal.last().is_some_and(|l| l == "arreter anydesk.service"),
                "{etat:?}"
            );
            let mut m = FauxMonde::nouveau();
            m.etat = Ok(etat.map(String::from));
            assert!(!faire_geste(retirer, &mut m).reussi, "{etat:?}");
            assert!(!m.journal.iter().any(|l| l.starts_with("desactiver")), "{etat:?}");
        }
        for reponse in [Some("oui"), Some(""), None] {
            let mut m = FauxMonde::nouveau();
            m.reponse = reponse;
            assert!(faire_geste(retirer, &mut m).reussi, "{reponse:?}");
            let r = faire_geste(arreter, &mut m);
            assert!(!r.reussi, "{reponse:?}");
            assert!(
                r.raison.contains("d'un paquet qui le porte") && !r.raison.contains(".."),
                "{}",
                r.raison
            );
            assert!(!m.journal.iter().any(|l| l == "arreter anydesk.service"), "{reponse:?}");
            assert!(m.journal.iter().any(|l| l == "desactiver-sans-arreter anydesk.service"));
        }
        // Un arrêt refusé parce qu'une commande ne se relit pas garde aussi le paquet, et le dit.
        let mut m = FauxMonde::nouveau();
        if let Ok(Some(lu)) = &mut m.arret_charge {
            lu.arret = vec![arret_designe::Commande {
                chemin: "/bin/sh".into(),
                arguments: vec!["sh".into(), "-c".into(), "kill $MAINPID".into()],
            }];
        }
        let r = faire_geste(arreter, &mut m);
        assert!(
            !r.reussi && !m.journal.iter().any(|l| l == "question anydesk.service"),
            "{r:?}"
        );
        assert!(
            r.raison.contains("d'un paquet qui le porte") && !r.raison.contains(".."),
            "{}",
            r.raison
        );
        // Accepté, mais refusé par systemd : il tourne encore, et le paquet ne part pas non plus, c'est dit.
        let mut m = FauxMonde::nouveau();
        m.echecs = vec!["arreter"];
        let r = faire_geste(arreter, &mut m);
        assert!(!r.reussi && r.raison.contains("d'un paquet qui le porte"), "{r:?}");
    }

    /// xrdp : l'arrêt de xrdp.service entraîne xrdp-sesman.service (BindsTo=), qui le lui rend. L'unité du même
    /// logiciel passe les mêmes revues (fichier, session portée par elle, ce que son arrêt lancerait) et la note la
    /// nomme ; une autre unité entraînée, ou une unité que l'arrêt lancerait, refusent.
    #[test]
    fn l_arret_designe_revoit_les_unites_du_meme_logiciel() {
        type Reglage<'a> = &'a dyn Fn(&mut FauxMonde);
        let arreter = gestes_unix::designee(ActionUnite::Arreter, "xrdp.service").unwrap();
        if !arreter.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let lu = |nom: &str, programme: &str, entrainees: &[&str]| ArretCharge {
            lancement: vec![arret_designe::Commande {
                chemin: programme.into(),
                arguments: vec![programme.into(), "--nodaemon".into()],
            }],
            groupe: format!("/system.slice/{nom}"),
            entrainees: entrainees.iter().map(ToString::to_string).collect(),
            ..ArretCharge::default()
        };
        let monde = || {
            let mut m = FauxMonde::nouveau();
            m.arret_charge = Ok(Some(lu("xrdp.service", "/usr/sbin/xrdp", &["xrdp-sesman.service"])));
            m.arret_charge_de = vec![(
                "xrdp-sesman.service",
                Some(lu("xrdp-sesman.service", "/usr/sbin/xrdp-sesman", &["xrdp.service"])),
            )];
            m
        };
        let essai = |regler: Reglage| {
            let mut m = monde();
            regler(&mut m);
            let r = faire_geste(arreter, &mut m);
            let question = m.journal.iter().any(|l| l.starts_with("question"));
            let arrete = m.journal.iter().any(|l| l.starts_with("arreter "));
            (r, question, arrete)
        };
        let (r, question, arrete) = essai(&|_| {});
        assert!(r.reussi && question && arrete, "{r:?}");
        let note = r.note.unwrap_or_default();
        assert!(
            note.contains("systemctl start xrdp.service xrdp-sesman.service"),
            "{note}"
        );
        // La session de logind qu'ouvre xrdp : Service=xrdp-sesman, Remote=yes.
        let distante = SessionVue {
            distante: true,
            service: "xrdp-sesman".into(),
            groupes_du_meneur: vec!["/user.slice/user-1000.slice/session-c3.scope".into()],
        };
        let dans_sesman = SessionVue {
            distante: false,
            service: "xrdp-sesman".into(),
            groupes_du_meneur: vec!["/system.slice/xrdp-sesman.service/session".into()],
        };
        let refuses: [(&str, Reglage); 6] = [
            ("session distante", &|m| m.sessions = Some(vec![distante.clone()])),
            ("session dans sesman", &|m| m.sessions = Some(vec![dans_sesman.clone()])),
            ("fichier de sesman douteux", &|m| {
                m.fichiers_douteux = vec!["xrdp-sesman.service"];
            }),
            ("arrêt de sesman douteux", &|m| {
                if let Some((_, Some(lu))) = m.arret_charge_de.first_mut() {
                    lu.arret = vec![arret_designe::Commande {
                        chemin: "/bin/sh".into(),
                        arguments: vec!["sh".into(), "-c".into(), "pkill xrdp".into()],
                    }];
                }
            }),
            ("autre unité entraînée", &|m| {
                if let Ok(Some(lu)) = &mut m.arret_charge {
                    lu.entrainees.push("cups.service".into());
                }
            }),
            ("unité lancée", &|m| {
                if let Some((_, Some(lu))) = m.arret_charge_de.first_mut() {
                    lu.lancees.push("relance.service".into());
                }
            }),
        ];
        for (cas, regler) in refuses {
            let (r, question, arrete) = essai(regler);
            assert!(!r.reussi && !question && !arrete, "{cas} : {r:?}");
        }
        // sesman qui entraîne une autre unité : refusé aussi, sa revue ne s'arrête pas à xrdp.
        let (r, question, _) = essai(&|m| {
            if let Some((_, Some(lu))) = m.arret_charge_de.first_mut() {
                lu.entrainees.push("cups.service".into());
            }
        });
        assert!(!r.reussi && !question && r.raison.contains("cups.service"), "{r:?}");
        // sesman arrêté : l'arrêt ne le touche pas, son fichier douteux ne compte pas, et la note ne le nomme pas.
        let (r, question, arrete) = essai(&|m| {
            m.arretees = vec!["xrdp-sesman.service"];
            m.fichiers_douteux = vec!["xrdp-sesman.service"];
        });
        assert!(r.reussi && question && arrete, "{r:?}");
        assert!(!r.note.unwrap_or_default().contains("xrdp-sesman"));
        // Une session ouverte par xrdp pendant la question : refusé juste avant l'arrêt.
        let (r, _, arrete) = essai(&|m| m.sessions_apres_question = Some(vec![distante.clone()]));
        assert!(!r.reussi && !arrete, "{r:?}");
    }

    /// É-2 du lot U3 : une unité de la table passe par la même revue qu'une unité désignée, avant l'accord et encore
    /// juste avant le geste. Un fichier douteux : rien n'est fait, pas même la question.
    #[test]
    fn les_unites_de_la_table_sont_revues() {
        if !GesteUnix::ReinitialiserEchecs.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let s = ToString::to_string;
        let activer = GesteUnix::Unite(ActionUnite::Activer, &gestes_unix::CUPS);
        let mut m = FauxMonde::nouveau();
        assert!(faire_geste(activer, &mut m).reussi);
        assert_eq!(m.journal, [s("activer cups.service")]);
        assert_eq!(m.revues.get(), 2);
        let mut m = FauxMonde::nouveau();
        m.fichier = Err(Echec::refuse("essai", "complément douteux"));
        let r = faire_geste(activer, &mut m);
        assert!(!r.reussi && r.raison == "complément douteux", "{r:?}");
        assert_eq!(m.journal, Vec::<String>::new());
        // Changé pendant la question : revu après l'accord, rien n'est fait.
        let mut m = FauxMonde::nouveau();
        m.fichier_apres_accord = Some(Err(Echec::refuse("essai", "remplacé")));
        let r = faire_geste(
            GesteUnix::Unite(ActionUnite::Activer, &gestes_unix::CUPS_BROWSED),
            &mut m,
        );
        assert!(!r.reussi && r.raison == "remplacé", "{r:?}");
        assert_eq!(m.journal, [s("accord")]);
        // Changé entre la première revue et le geste, sans question : revu quand même.
        let mut m = FauxMonde::nouveau();
        m.douteux_des = Some(2);
        assert!(!faire_geste(activer, &mut m).reussi);
        assert_eq!(m.journal, Vec::<String>::new());
        // Un geste sans unité : rien à revoir.
        let mut m = FauxMonde::nouveau();
        assert!(faire_geste(GesteUnix::ReinitialiserEchecs, &mut m).reussi);
        assert_eq!(m.revues.get(), 0);
    }

    /// Le cas des essais QEMU : un complément posé par le compte (modifiable par lui) sur cups.service, de vrais
    /// fichiers dans des dossiers jetables. Le geste est refusé, rien n'est activé ; le complément remis en ordre, il
    /// passe.
    #[test]
    fn un_complement_du_compte_sur_une_unite_de_la_table_est_refuse() {
        use std::os::unix::fs::PermissionsExt;
        let activer = GesteUnix::Unite(ActionUnite::Activer, &gestes_unix::CUPS);
        if !activer.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let d = crate::essais::Jetable::nouveau("assistant-table");
        let racine = d.join("racine");
        let dossier = racine.join("usr");
        let complements = dossier.join("cups.service.d");
        std::fs::create_dir_all(&complements).unwrap();
        let mode = |chemin: &std::path::Path, m: u32| {
            std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(m)).unwrap();
        };
        for c in [&racine, &dossier, &complements] {
            mode(c, 0o755);
        }
        let fichier = dossier.join("cups.service");
        let complement = complements.join("50-essai.conf");
        std::fs::write(&fichier, "[Service]\n").unwrap();
        std::fs::write(&complement, "[Service]\nExecStartPre=/home/alice/x\n").unwrap();
        mode(&fichier, 0o644);
        let essai = || {
            let mut m = FauxMonde::nouveau();
            m.disque = Some((vec![dossier.clone()], racine.clone(), crate::socle::euid()));
            let r = faire_geste(activer, &mut m);
            (r, m.journal)
        };
        for m in [0o646, 0o664, 0o666] {
            mode(&complement, m);
            let (r, j) = essai();
            assert!(!r.reussi && j.is_empty(), "{m:o} {r:?} {j:?}");
        }
        // Un lien vers un fichier hors des dossiers du système (le dossier personnel du compte) : refusé aussi.
        let dehors = d.join("dehors.conf");
        std::fs::write(&dehors, "[Service]\n").unwrap();
        mode(&dehors, 0o644);
        std::fs::remove_file(&complement).unwrap();
        std::os::unix::fs::symlink(&dehors, &complement).unwrap();
        let (r, j) = essai();
        assert!(!r.reussi && j.is_empty(), "{r:?}");
        std::fs::remove_file(&complement).unwrap();
        std::fs::write(&complement, "[Service]\n").unwrap();
        mode(&complement, 0o644);
        let (r, j) = essai();
        assert!(r.reussi, "{r:?}");
        assert_eq!(j, ["activer cups.service".to_string()]);
        // Vide mais modifiable par les autres : un « .conf » pourrait y être posé après la revue. Refusé aussi.
        std::fs::remove_file(&complement).unwrap();
        mode(&complements, 0o777);
        let (r, j) = essai();
        assert!(!r.reussi && j.is_empty(), "{r:?}");
        mode(&complements, 0o755);
        assert!(essai().0.reussi);
        // Un dossier de compléments absent, sous un dossier modifiable par les autres : refusé (il pourrait y être
        // créé) ; de même pour un fichier absent du premier dossier, qui y serait posé et passerait devant.
        std::fs::remove_dir(&complements).unwrap();
        mode(&dossier, 0o757);
        assert!(!essai().0.reussi);
        mode(&dossier, 0o755);
        assert!(essai().0.reussi);
        let premier = racine.join("etc");
        std::fs::create_dir(&premier).unwrap();
        mode(&premier, 0o777);
        let mut m = FauxMonde::nouveau();
        m.disque = Some((
            vec![premier.clone(), dossier.clone()],
            racine.clone(),
            crate::socle::euid(),
        ));
        assert!(!faire_geste(activer, &mut m).reussi);
        assert_eq!(m.journal, Vec::<String>::new());
        mode(&premier, 0o755);
        let mut m = FauxMonde::nouveau();
        m.disque = Some((vec![premier, dossier.clone()], racine.clone(), crate::socle::euid()));
        assert!(faire_geste(activer, &mut m).reussi);
    }

    /// É-4 du lot U3 : une unité absente est dite « pas installée ». L'arrêter ou la retirer du démarrage est déjà
    /// fait (réussi, avec la note, sans question) ; la lancer ne peut pas se faire.
    #[test]
    fn une_unite_absente_est_dite_pas_installee() {
        if !GesteUnix::ReinitialiserEchecs.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let absente_qui_tourne = |g: GesteUnix, actif: Option<&str>| {
            let mut m = FauxMonde::nouveau();
            m.fichier = Ok(false);
            m.actif = Ok(actif.map(ToString::to_string));
            let r = faire_geste(g, &mut m);
            (r, m.journal)
        };
        let absente = |g: GesteUnix| absente_qui_tourne(g, None);
        let lu = vec!["actif auditd.service".to_string()];
        for (a, u) in [
            (ActionUnite::Activer, &gestes_unix::FIREWALLD),
            (ActionUnite::Demarrer, &gestes_unix::CUPS),
            (ActionUnite::Redemarrer, &gestes_unix::CUPS),
        ] {
            let (r, j) = absente(GesteUnix::Unite(a, u));
            assert!(!r.reussi && r.raison.contains("install") && j.is_empty(), "{a:?} {r:?}");
        }
        for a in [ActionUnite::Desactiver, ActionUnite::Arreter] {
            let (r, j) = absente(GesteUnix::Unite(a, &gestes_unix::AUDITD));
            assert!(
                r.reussi && r.note.as_deref().is_some_and(|n| n.contains("install")),
                "{a:?} {r:?}"
            );
            assert_eq!(j, lu, "{a:?}");
        }
        // Son paquet retiré sans l'arrêter, elle tourne encore : plus lancée au démarrage, c'est vrai, et dit ; son
        // arrêt, sans fichier à revoir, n'est pas fait, et c'est un échec dit.
        let redemarrage = |t: &str| t.contains("redémarrage") || t.contains("restart");
        let audit = |a| GesteUnix::Unite(a, &gestes_unix::AUDITD);
        let (r, j) = absente_qui_tourne(audit(ActionUnite::Desactiver), Some("active"));
        assert!(r.reussi && r.note.as_deref().is_some_and(redemarrage), "{r:?}");
        assert_eq!(j, lu);
        let (r, j) = absente_qui_tourne(audit(ActionUnite::Arreter), Some("active"));
        assert!(!r.reussi && redemarrage(&r.raison), "{r:?}");
        assert_eq!(j, lu);
        // É-6 : ses liens de démarrage ne sont pas retirés, et la note ne promet rien au-delà d'une réinstallation.
        let reinstalle = |n: &str| n.contains("réinstallé") || n.contains("reinstalled");
        let (r, _) = absente_qui_tourne(audit(ActionUnite::Desactiver), Some("active"));
        assert!(r.note.as_deref().is_some_and(reinstalle), "{r:?}");
        let (r, _) = absente(audit(ActionUnite::Desactiver));
        assert!(
            r.note
                .as_deref()
                .is_some_and(|n| n.contains("plus tard") || n.contains("later")),
            "{r:?}"
        );
    }

    /// É-5 du lot U3 : une unité désignée (un logiciel de prise de contrôle à distance) dont le fichier est retiré
    /// est dite comme une unité de la table : encore en marche, son arrêt est un échec qui le dit (pas « pas
    /// installé »), son retrait du démarrage une note ; à l'arrêt, « pas installé ». Ni question ni geste.
    #[test]
    fn une_unite_designee_retiree_qui_tourne() {
        if !GesteUnix::ReinitialiserEchecs.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let essai = |a: ActionUnite, actif: Option<&str>| {
            let mut m = FauxMonde::nouveau();
            m.fichier = Ok(false);
            m.actif = Ok(actif.map(ToString::to_string));
            let r = faire_geste(gestes_unix::designee(a, "anydesk.service").unwrap(), &mut m);
            (r, m.journal)
        };
        let lu = vec!["actif anydesk.service".to_string()];
        let tourne = |t: &str| t.contains("tourne encore") || t.contains("still running");
        let (r, j) = essai(ActionUnite::Arreter, Some("active"));
        assert!(!r.reussi && tourne(&r.raison), "{r:?}");
        assert_eq!(j, lu);
        // Seuls l'arrêt et le retrait du démarrage sans arrêt se désignent (`GesteUnix::refus`).
        let (r, j) = essai(ActionUnite::DesactiverSansArreter, Some("active"));
        assert!(r.reussi && r.note.as_deref().is_some_and(tourne), "{r:?}");
        assert_eq!(j, lu);
        let (r, j) = essai(ActionUnite::Arreter, None);
        assert!(
            r.reussi && r.note.as_deref().is_some_and(|n| n.contains("install")),
            "{r:?}"
        );
        assert_eq!(j, lu);
        // Un nom qui n'est pas celui d'un logiciel de prise de contrôle reste refusé avant toute lecture.
        let mut m = FauxMonde::nouveau();
        m.fichier = Ok(false);
        let r = faire_geste(
            gestes_unix::designee(ActionUnite::Arreter, "alice.service").unwrap(),
            &mut m,
        );
        assert!(!r.reussi && m.journal.is_empty(), "{r:?}");
    }

    /// B-3 du lot U3 : une unité dont systemd refuse l'arrêt à la main (auditd) n'est que retirée du démarrage, la
    /// note le dit et la question porte sur ce geste-là ; pas chargée, de même sans note ; une lecture en échec ne
    /// change rien. Son arrêt seul est refusé avant toute question.
    #[test]
    fn un_arret_refuse_par_systemd() {
        if !GesteUnix::ReinitialiserEchecs.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let s = ToString::to_string;
        let essai = |g: GesteUnix, arret: Result<Option<bool>, Echec>| {
            let mut m = FauxMonde::nouveau();
            m.arret = arret;
            let r = faire_geste(g, &mut m);
            (r, m.journal)
        };
        let audit = GesteUnix::Unite(ActionUnite::Desactiver, &gestes_unix::AUDITD);
        let (r, j) = essai(audit, Ok(Some(false)));
        assert!(r.reussi, "{r:?}");
        assert!(
            r.note
                .as_deref()
                .is_some_and(|n| n.contains("redémarrage") || n.contains("restart")),
            "{r:?}"
        );
        assert_eq!(j, [s("accord"), s("desactiver-sans-arreter auditd.service")]);
        let (r, j) = essai(audit, Ok(None));
        assert!(r.reussi && r.note.is_none(), "{r:?}");
        assert_eq!(j, [s("accord"), s("desactiver-sans-arreter auditd.service")]);
        let (r, j) = essai(audit, Err(Echec::echoue("essai", "illisible")));
        assert!(r.reussi && r.note.is_none(), "{r:?}");
        assert_eq!(j, [s("accord"), s("desactiver auditd.service")]);
        let (r, j) = essai(audit, Ok(Some(true)));
        assert!(r.reussi && r.note.is_none(), "{r:?}");
        assert_eq!(j, [s("accord"), s("desactiver auditd.service")]);
        // auditd demande l'accord : le refus de systemd arrive avant la question.
        let arreter = GesteUnix::Unite(ActionUnite::Arreter, &gestes_unix::AUDITD);
        let (r, j) = essai(arreter, Ok(Some(false)));
        assert!(!r.reussi && j.is_empty(), "{r:?} {j:?}");
        // Les phrases montrées restent sans jargon.
        assert!(!r.raison.contains("RefuseManualStop"));
        // Pas chargée : pas en marche, rien à arrêter, ni question ni geste.
        let (r, j) = essai(arreter, Ok(None));
        assert!(r.reussi && r.note.is_some() && j.is_empty(), "{r:?} {j:?}");
        let (r, j) = essai(arreter, Ok(Some(true)));
        assert!(r.reussi, "{r:?}");
        assert_eq!(j, [s("accord"), s("arreter auditd.service")]);
    }

    /// `signatures-clamav` et la revue (É-2) : un fichier douteux laisse le service de mise à jour tel quel (freshclam
    /// seul, dit) ; changé pendant le téléchargement, il n'est pas relancé, et c'est dit.
    #[test]
    fn signatures_clamav_et_la_revue() {
        if !GesteUnix::SignaturesClamav.permis_ici() {
            return crate::essais::saute("aucun geste de Linux n'est permis sur ce système");
        }
        let _signaux = SIGNAUX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let s = ToString::to_string;
        let etat = s("etat clamav-freshclam.service");
        let actif = s("actif clamav-freshclam.service");
        let fresh = s("programme freshclam");
        let mut m = FauxMonde::nouveau();
        m.fichier = Err(Echec::refuse("essai", "complément douteux"));
        let r = faire_geste(GesteUnix::SignaturesClamav, &mut m);
        assert!(
            r.reussi && r.note.as_deref().is_some_and(|n| n.contains("complément douteux")),
            "{r:?}"
        );
        assert_eq!(m.journal, [etat.clone(), actif.clone(), fresh.clone()]);
        // B-4 : coupé au démarrage (disabled, static), la raison de la revue reste dans la note, devant.
        for coupee in ["disabled", "static"] {
            let mut m = FauxMonde::nouveau();
            m.fichier = Err(Echec::refuse("essai", "complément douteux"));
            m.etat = Ok(Some(coupee.into()));
            let r = faire_geste(GesteUnix::SignaturesClamav, &mut m);
            let note = r.note.clone().unwrap_or_default();
            assert!(r.reussi && note.contains("complément douteux"), "{coupee} {r:?}");
            assert!(note.contains("démarrage") || note.contains("boot"), "{coupee} {r:?}");
            assert_eq!(m.journal, [etat.clone(), actif.clone(), fresh.clone()], "{coupee}");
        }
        let mut m = FauxMonde::nouveau();
        m.etat = Ok(Some("disabled".into()));
        m.actif = Ok(Some("inactive".into()));
        let r = faire_geste(GesteUnix::SignaturesClamav, &mut m);
        assert!(
            r.reussi
                && r.note
                    .as_deref()
                    .is_some_and(|n| n.starts_with("signatures à jour ;") || n.starts_with("signatures up to date;")),
            "{r:?}"
        );
        let mut m = FauxMonde::nouveau();
        m.fichier = Err(Echec::refuse("essai", "complément douteux"));
        m.programme_reussi = false;
        let r = faire_geste(GesteUnix::SignaturesClamav, &mut m);
        assert!(!r.reussi && r.raison.contains("complément douteux"), "{r:?}");
        let mut m = FauxMonde::nouveau();
        m.douteux_des = Some(2);
        let r = faire_geste(GesteUnix::SignaturesClamav, &mut m);
        assert!(!r.reussi && r.raison.contains("changé entre deux revues"), "{r:?}");
        assert_eq!(m.journal, [etat, actif, s("arreter clamav-freshclam.service"), fresh]);
    }

    /// É-1 du lot U3 : le groupe 0 n'est « seul » que sans autre membre ni compte de personne qui l'ait pour groupe
    /// principal ; une ligne douteuse dit non.
    #[test]
    fn le_groupe_de_root_seul() {
        let groupe_root_seul_essai = |g: &str, p: &str| groupe_root_seul(g, p, "root:!::\n");
        let passwd = "root:x:0:0:root:/root:/bin/bash\nsync:x:5:0:sync:/sbin:/bin/sync\noperator:x:11:0:operator:/root:/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n";
        assert!(groupe_root_seul_essai("root:x:0:\nwheel:x:10:alice\n", passwd));
        assert!(groupe_root_seul_essai("root:x:0:root\n", passwd));
        assert!(!groupe_root_seul_essai("root:x:0:alice\n", passwd));
        assert!(!groupe_root_seul_essai("root:x:0:root,alice\n", passwd));
        assert!(!groupe_root_seul_essai("root:x:0:\nautre:x:0:\n", passwd));
        assert!(!groupe_root_seul_essai("wheel:x:10:\n", passwd));
        assert!(!groupe_root_seul_essai("root:x:0\n", passwd));
        let alice_0 = format!("{passwd}bob:x:1001:0::/home/bob:/bin/bash\n");
        assert!(!groupe_root_seul_essai("root:x:0:\n", &alice_0));
        assert!(!groupe_root_seul_essai(
            "root:x:0:\n",
            "root:x:0:0\nbizarre:x:douze:0\n"
        ));
        // Un mot de passe de groupe (newgrp root), dans group ou gshadow, ou un membre dans gshadow : non.
        assert!(!groupe_root_seul("root:$6$sel$empreinte:0:\n", passwd, ""));
        assert!(!groupe_root_seul("root:x:0:\n", passwd, "root:$6$sel$empreinte::\n"));
        assert!(!groupe_root_seul("root:x:0:\n", passwd, "root:!::alice\n"));
        assert!(!groupe_root_seul("root:x:0:\n", passwd, "root:!:alice:\n"));
        assert!(!groupe_root_seul("root:x:0:\n", passwd, "root:!\n"));
        assert!(groupe_root_seul("root:x:0:\n", passwd, ""));
        assert!(groupe_root_seul(
            "root:x:0:\n",
            passwd,
            "root:*::root\nwheel:!::alice\n"
        ));
    }

    /// É-1 du lot U3 : un dossier modifiable par le seul groupe de son propriétaire (`/` en 0775 root:root de Fedora
    /// Cloud) est accepté ; par les autres, ou par un autre groupe, jamais ; un fichier modifiable par le groupe non
    /// plus.
    #[test]
    fn un_dossier_ouvert_au_seul_groupe_du_proprietaire() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = crate::essais::Jetable::nouveau("assistant-groupe");
        let racine = d.join("racine");
        let dossier = racine.join("usr");
        std::fs::create_dir_all(&dossier).unwrap();
        let mode = |chemin: &std::path::Path, m: u32| {
            std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(m)).unwrap();
        };
        mode(&racine, 0o755);
        mode(&dossier, 0o755);
        let fichier = dossier.join("cups.service");
        std::fs::write(&fichier, "[Service]\n").unwrap();
        mode(&fichier, 0o644);
        let moi = crate::socle::euid();
        let gid = std::fs::metadata(&racine).unwrap().gid();
        let son_groupe = Proprietaire {
            uid: moi,
            groupe_seul: Some(gid),
        };
        let autre_groupe = Proprietaire {
            uid: moi,
            groupe_seul: Some(gid.wrapping_add(1)),
        };
        let sur = |qui| fichier_d_unite_sur(&[dossier.as_path()], &racine, "cups.service", qui);
        assert_eq!(sur(son_groupe), Ok(true));
        mode(&racine, 0o775);
        assert_eq!(sur(son_groupe), Ok(true));
        assert!(sur(Proprietaire::strict(moi)).is_err());
        assert!(sur(autre_groupe).is_err());
        for m in [0o757, 0o777] {
            mode(&racine, m);
            assert!(sur(son_groupe).is_err(), "{m:o}");
        }
        mode(&racine, 0o775);
        mode(&fichier, 0o664);
        assert!(sur(son_groupe).is_err());
    }

    /// É-3 du lot U3 : les erreurs du fils passent au parent sur une ligne chacune, bornée, sans caractère piégé, et
    /// se séparent de ses réponses sans en changer le compte.
    #[test]
    fn les_erreurs_du_fils_passent_au_parent() {
        assert_eq!(ligne_journal("[a] b\nc\r\nd\re"), "journal [a] b | c | d | e");
        let longue = ligne_journal(&"é".repeat(LIGNE_MAX));
        assert!(longue.len() <= LIGNE_MAX && longue.starts_with(JOURNAL));
        assert!(!ligne_journal("x\u{1b}[2Jy").contains('\u{1b}'));
        let mut lignes = vec![ligne_journal("[x] une"), "ok".to_string()];
        lignes.extend((0..2 * crate::journal::RELAIS_MAX).map(|i| ligne_journal(&format!("[x] {i}"))));
        lignes.push("echec raison".to_string());
        let (erreurs, reponses) = separer_journal(lignes);
        assert_eq!(erreurs.len(), crate::journal::RELAIS_MAX);
        assert_eq!(erreurs[0], "[x] une");
        assert_eq!(reponses, ["ok", "echec raison"]);
        // Aucune réponse du fils ne peut passer pour une erreur relayée.
        assert!(!ordres::ligne_reponse(&Resultat::ok()).starts_with(JOURNAL));
        assert!(!ordres::ligne_reponse(&Resultat::echec("journal plein")).starts_with(JOURNAL));
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
        let actif = s("actif clamav-freshclam.service");
        let arret = s("arreter clamav-freshclam.service");
        let marche = s("demarrer clamav-freshclam.service");
        let fresh = s("programme freshclam");
        let tournant = [
            etat.clone(),
            actif.clone(),
            arret.clone(),
            fresh.clone(),
            marche.clone(),
        ];
        let (r, j) = essai(&|_| {});
        assert!(r.reussi && r.note.is_none(), "{r:?}");
        assert_eq!(j, tournant);
        let (r, j) = essai(&|m| m.etat = Ok(None));
        assert!(r.reussi && r.note.is_none(), "{r:?}");
        assert_eq!(j, [etat.clone(), fresh.clone()]);
        let (r, j) = essai(&|m| m.etat = Ok(Some(s("masked"))));
        assert!(r.reussi && r.note.is_some(), "{r:?}");
        assert_eq!(j, [etat.clone(), fresh.clone()]);
        // Jamais activé au démarrage : ce geste ne note rien qui le déferait. Coupé et arrêté, il le reste, et
        // c'est dit ; coupé mais lancé à la main, il est seulement redémarré.
        for arrete in [None, Some("inactive"), Some("failed")] {
            let (r, j) = essai(&|m| {
                m.etat = Ok(Some(s("disabled")));
                m.actif = Ok(arrete.map(s));
            });
            assert!(r.reussi && r.note.is_some(), "{arrete:?} {r:?}");
            assert_eq!(j, [etat.clone(), actif.clone(), fresh.clone()], "{arrete:?}");
        }
        let (r, j) = essai(&|m| m.etat = Ok(Some(s("disabled"))));
        assert!(r.reussi && r.note.is_some(), "{r:?}");
        assert_eq!(j, tournant);
        // Une mise à jour automatique lancée au démarrage par un autre chemin que « enabled » : aucune note qui
        // dirait le contraire.
        for autre in ["indirect", "enabled-runtime", "generated", "linked", "alias"] {
            let (r, j) = essai(&|m| m.etat = Ok(Some(s(autre))));
            assert!(r.reussi && r.note.is_none(), "{autre} {r:?}");
            assert_eq!(j, tournant, "{autre}");
        }
        let (r, _) = essai(&|m| m.etat = Ok(Some(s("static"))));
        assert!(r.reussi && r.note.is_some(), "{r:?}");
        // En train de s'arrêter : arrêté (il tient peut-être encore le verrou), puis laissé arrêté.
        let (r, j) = essai(&|m| m.actif = Ok(Some(s("deactivating"))));
        assert!(r.reussi, "{r:?}");
        assert_eq!(j, [etat.clone(), actif.clone(), arret.clone(), fresh.clone()]);
        // Activé mais arrêté : pas démarré non plus.
        let (r, j) = essai(&|m| m.actif = Ok(Some(s("inactive"))));
        assert!(r.reussi && r.note.is_none(), "{r:?}");
        assert_eq!(j, [etat.clone(), actif.clone(), fresh.clone()]);
        // Son activité illisible : freshclam seul, le service pas touché ; un échec le dit.
        let illisible = |m: &mut FauxMonde| m.actif = Err(Echec::echoue("essai", "activité illisible"));
        let (r, j) = essai(&illisible);
        assert!(r.reussi, "{r:?}");
        assert_eq!(j, [etat.clone(), actif.clone(), fresh.clone()]);
        let (r, _) = essai(&|m| {
            illisible(m);
            m.programme_reussi = false;
        });
        assert!(!r.reussi && r.raison.contains("activité illisible"), "{r:?}");
        // L'arrêt refusé : freshclam est lancé quand même, puis le service remis en route.
        let (r, j) = essai(&|m| m.echecs = vec!["arreter"]);
        assert!(r.reussi, "{r:?}");
        assert_eq!(j, tournant);
        let (r, j) = essai(&|m| {
            m.echecs = vec!["arreter"];
            m.programme_reussi = false;
        });
        assert!(!r.reussi && r.raison.contains("arreter en échec"), "{r:?}");
        assert_eq!(j, tournant);
        let (r, j) = essai(&|m| m.programme_reussi = false);
        assert!(!r.reussi && r.raison == "programme en échec", "{r:?}");
        assert_eq!(j, tournant);
        // Pas redémarré : dit, avec la raison.
        let (r, j) = essai(&|m| m.echecs = vec!["demarrer"]);
        assert!(!r.reussi && r.raison.contains("demarrer en échec"), "{r:?}");
        assert_eq!(j, tournant);
        // Une panique pendant freshclam : le service est quand même remis en route en sortant.
        let mut m = FauxMonde::nouveau();
        m.programme_panique = true;
        let paniquee = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            faire_geste(GesteUnix::SignaturesClamav, &mut m)
        }));
        assert!(paniquee.is_err());
        assert_eq!(m.journal, tournant);
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
        let sur = |nom: &str, qui: u32| fichier_d_unite_sur(&dossiers, &racine, nom, Proprietaire::strict(qui));
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
        // Absent partout : pas installé, dit comme tel (É-4).
        assert_eq!(sur("anydesk.service", moi), Ok(false));
        // Dans le second dossier seulement : accepté.
        poser(&second, "anydesk.service", 0o644);
        assert_eq!(sur("anydesk.service", moi), Ok(true));
        // Fichier direct, mais un dossier qui le contient modifiable par les autres : refusé, comme pour un lien.
        for (dossier, m) in [(&second, 0o757), (&second, 0o775), (&racine, 0o777)] {
            mode(dossier, m);
            assert!(sur("anydesk.service", moi).is_err(), "{} {m:o}", dossier.display());
            mode(dossier, 0o755);
        }
        assert_eq!(sur("anydesk.service", moi), Ok(true));
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
        assert_eq!(sur("teamviewerd.service", moi), Ok(true));
        // Même lien, vers un fichier d'un autre propriétaire : refusé.
        assert!(sur("teamviewerd.service", moi.wrapping_add(1)).is_err());
        // Sa cible modifiable par les autres : refusé, sans aller voir le second dossier.
        poser(&second, "teamviewerd.service", 0o644);
        mode(&ailleurs.join("teamviewerd.service"), 0o646);
        assert!(sur("teamviewerd.service", moi).is_err());
        mode(&ailleurs.join("teamviewerd.service"), 0o644);
        assert_eq!(sur("teamviewerd.service", moi), Ok(true));
        // Un dossier parent de la cible modifiable par les autres : refusé (le fichier pourrait y être remplacé).
        for (dossier, m) in [(&ailleurs, 0o757), (&racine.join("opt"), 0o777), (&racine, 0o775)] {
            mode(dossier, m);
            assert!(sur("teamviewerd.service", moi).is_err(), "{} {m:o}", dossier.display());
            mode(dossier, 0o755);
        }
        // Le dossier du lien lui-même modifiable par les autres : refusé (le lien pourrait y être remplacé par un
        // autre, vers un fichier choisi par ce compte).
        for m in [0o775, 0o757] {
            mode(&premier, m);
            assert!(sur("teamviewerd.service", moi).is_err(), "{m:o}");
            mode(&premier, 0o755);
        }
        assert_eq!(sur("teamviewerd.service", moi), Ok(true));
        // Un lien vers une autre unité (un alias), même correcte : refusé, le geste toucherait celle-là.
        poser(&ailleurs, "autre.service", 0o644);
        std::os::unix::fs::symlink(ailleurs.join("autre.service"), premier.join("dwservice.service")).unwrap();
        assert!(sur("dwservice.service", moi).is_err());
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
        // Les compléments (« drop-in ») comptent comme le fichier : chacun sûr, dans tous les dossiers, sous chacun
        // des noms qui s'appliquent (le nom, ses préfixes à tiret, le genre).
        poser(&second, "a-b-c.service", 0o644);
        assert_eq!(sur("a-b-c.service", moi), Ok(true));
        let propre = second.join("a-b-c.service.d");
        std::fs::create_dir(&propre).unwrap();
        mode(&propre, 0o755);
        poser(&propre, "x.conf", 0o644);
        assert_eq!(sur("a-b-c.service", moi), Ok(true));
        for m in [0o646, 0o664] {
            mode(&propre.join("x.conf"), m);
            assert!(sur("a-b-c.service", moi).is_err(), "{m:o}");
        }
        mode(&propre.join("x.conf"), 0o644);
        mode(&propre, 0o757);
        assert!(sur("a-b-c.service", moi).is_err());
        mode(&propre, 0o755);
        // Un autre fichier que « .conf » n'est pas lu par systemd : sans effet.
        poser(&propre, "lisez-moi.txt", 0o666);
        assert_eq!(sur("a-b-c.service", moi), Ok(true));
        for complements in ["a-.service.d", "a-b-.service.d", "service.d"] {
            let c = premier.join(complements);
            std::fs::create_dir(&c).unwrap();
            mode(&c, 0o755);
            poser(&c, "y.conf", 0o646);
            assert!(sur("a-b-c.service", moi).is_err(), "{complements}");
            mode(&c.join("y.conf"), 0o644);
            assert_eq!(sur("a-b-c.service", moi), Ok(true), "{complements}");
        }
        // Un complément qui est un lien hors de la racine : refusé.
        std::os::unix::fs::symlink(&dehors, propre.join("z.conf")).unwrap();
        assert!(sur("a-b-c.service", moi).is_err());
        assert_eq!(
            noms_des_complements("a-b-c.service"),
            ["a-b-c.service.d", "a-b-.service.d", "a-.service.d", "service.d"]
        );
        assert_eq!(noms_des_complements("sans-genre"), ["sans-genre.d"]);
        // Les dossiers de systemd, tous (systemd.unit(5)) : ceux des logiciels installés à la main, /lib, ceux de
        // /run, des générateurs et des unités passagères compris.
        assert_eq!(DOSSIERS_D_UNITES.len(), 13);
        for dossier in [
            "/etc/systemd/system",
            "/usr/local/lib/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/run/systemd/system",
            "/run/systemd/transient",
            "/run/systemd/generator",
            "/run/systemd/generator.early",
            "/run/systemd/generator.late",
            "/etc/systemd/system.control",
        ] {
            assert!(DOSSIERS_D_UNITES.contains(&dossier), "{dossier}");
        }
    }

    /// Les fichiers d'où le gestionnaire de services a chargé l'unité : son nom principal le nom désigné, un fichier,
    /// et lui comme chacun de ses compléments sûrs ; sinon refusé.
    #[test]
    fn les_fichiers_charges_d_une_unite() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::essais::Jetable::nouveau("assistant-charges");
        let racine = d.join("racine");
        let dossier = racine.join("run");
        std::fs::create_dir_all(&dossier).unwrap();
        let mode = |chemin: &std::path::Path, m: u32| {
            std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(m)).unwrap();
        };
        mode(&racine, 0o755);
        mode(&dossier, 0o755);
        let fragment = dossier.join("anydesk.service");
        let complement = dossier.join("x.conf");
        for f in [&fragment, &complement] {
            std::fs::write(f, "[Service]\n").unwrap();
            mode(f, 0o644);
        }
        let moi = crate::socle::euid();
        let frag = fragment.to_str().unwrap();
        let comp = vec![complement.to_str().unwrap().to_string()];
        let charges = |id: &str, f: &str, c: &[String]| {
            fichiers_charges_surs(id, f, c, &racine, "anydesk.service", Proprietaire::strict(moi))
        };
        assert_eq!(charges("anydesk.service", frag, &comp), Ok(()));
        // Un alias : le nom principal est un autre.
        assert!(charges("autre.service", frag, &comp).is_err());
        // Sans fichier (unité passagère ou générée sans fragment) : rien à revoir, refusé.
        assert!(charges("anydesk.service", "", &comp).is_err());
        // Un complément modifiable par les autres, ou absent : refusé.
        mode(&complement, 0o646);
        assert!(charges("anydesk.service", frag, &comp).is_err());
        mode(&complement, 0o644);
        assert!(
            charges(
                "anydesk.service",
                frag,
                &[dossier.join("absent.conf").to_str().unwrap().to_string()]
            )
            .is_err()
        );
        // Le fichier dans un dossier modifiable par les autres : refusé.
        mode(&dossier, 0o777);
        assert!(charges("anydesk.service", frag, &[]).is_err());
        mode(&dossier, 0o755);
        // Un autre propriétaire : refusé.
        assert!(
            fichiers_charges_surs(
                "anydesk.service",
                frag,
                &comp,
                &racine,
                "anydesk.service",
                Proprietaire::strict(moi.wrapping_add(1))
            )
            .is_err()
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
