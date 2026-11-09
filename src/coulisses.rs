//! Les coulisses : ce que Vanguard lance (programme, arguments abrégés, durée, issue), pour qui veut voir ce qu'il
//! fait. Éteint par défaut (Paramètres › Coulisses). Allumé, chaque commande finie se montre en une ligne grise sous
//! ce qui s'affiche, sur la sortie d'erreur et seulement si c'est un terminal : un `--json` sur la sortie reste propre,
//! et un menu ouvert (mode clavier) n'est pas abîmé. Les 200 dernières restent en mémoire pour « voir », jamais sur le
//! disque ni dans le journal : une commande peut nommer un fichier ou un réseau de la maison. Ce qu'on lance passe par
//! `commande::lancer…` (déjà suivis) ou par `Suivie` ; la garde `appels_directs_suivis` refuse un appel qui
//! l'oublierait.

use std::collections::VecDeque;
use std::process::{Child, Command, ExitStatus, Output};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::ui::{GRIS, RESET};
use crate::{tr, trf};

/// Combien de commandes « voir » montre.
const GARDEES: usize = 200;

/// La place de la commande sur sa ligne : 76 colonnes, moins le retrait, la flèche, la durée et l'issue.
const COLONNES: usize = 56;

static ALLUME: AtomicBool = AtomicBool::new(false);
static TRACES: Mutex<VecDeque<Trace>> = Mutex::new(VecDeque::new());

/// Allumées ou éteintes pour ce processus : au lancement d'après parametres.json, puis à chaque changement du réglage.
pub(crate) fn allumer(oui: bool) {
    ALLUME.store(oui, Ordering::Relaxed);
}

pub(crate) fn allumees() -> bool {
    ALLUME.load(Ordering::Relaxed)
}

/// Comment une commande a fini.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Issue {
    /// Son code de retour ; `None` : arrêtée par un signal.
    Code(Option<i32>),
    /// Arrêtée par Vanguard, son délai passé ou sa sortie trop longue.
    Arretee,
    /// Elle n'a pas démarré.
    PasDemarree,
    /// Lancée sans l'attendre (une fenêtre, un programme ouvert pour la personne).
    Lancee,
}

#[derive(Clone, Debug)]
pub(crate) struct Trace {
    pub(crate) commande: String,
    pub(crate) duree: Duration,
    pub(crate) issue: Issue,
}

impl Trace {
    /// Sa ligne, sans couleur : « ↳ commande … durée ✔ ».
    pub(crate) fn ligne(&self) -> String {
        let (signe, raison) = match &self.issue {
            Issue::Code(Some(0)) => ("✔", String::new()),
            Issue::Code(Some(c)) => ("✖", trf!(" (code {c})", " (code {c})")),
            Issue::Code(None) => (
                "✖",
                tr!(" (arrêtée par un signal)", " (killed by a signal)").to_string(),
            ),
            Issue::Arretee => (
                "✖",
                tr!(" (arrêtée par Vanguard)", " (stopped by Vanguard)").to_string(),
            ),
            Issue::PasDemarree => ("✖", tr!(" (pas démarrée)", " (did not start)").to_string()),
            Issue::Lancee => ("↗", tr!(" (lancée)", " (started)").to_string()),
        };
        let fin = format!("{} {signe}{raison}", duree_lisible(self.duree));
        // Retrait de deux colonnes, « ↳ », et l'espace avant la fin : le tout tient dans `ui::LARGEUR`.
        let place = crate::ui::LARGEUR.saturating_sub(crate::ui::largeur_affichee(&fin).saturating_add(5));
        format!("↳ {} {fin}", crate::ui::couper(&self.commande, place))
    }
}

fn duree_lisible(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        let dixiemes = ms / 100;
        let texte = format!("{}.{} s", dixiemes / 10, dixiemes % 10);
        if crate::langue::anglais() {
            texte
        } else {
            texte.replace('.', ",")
        }
    }
}

/// Un mot qui annonce un secret : la valeur qui suit (ou celle après « = ») n'est pas montrée. Aucune commande de
/// Vanguard n'en passe en argument aujourd'hui ; si une le faisait, il ne s'afficherait pas pour autant.
fn annonce_un_secret(mot: &str) -> bool {
    let m = mot.to_lowercase();
    ["pass", "token", "secret", "api-key", "apikey", "auth"]
        .iter()
        .any(|s| m.contains(s))
}

/// La commande telle qu'elle se montre : le nom du programme (sans son dossier), puis ses arguments, chacun filtré
/// (`ui::affichable` : un nom de fichier piégé ne pilote pas le terminal), sauts de ligne compris.
fn decrire(commande: &Command) -> String {
    let programme = std::path::Path::new(commande.get_program())
        .file_name()
        .unwrap_or_else(|| commande.get_program())
        .to_string_lossy()
        .into_owned();
    let mut mots = vec![programme];
    let mut cacher = false;
    for a in commande.get_args() {
        let a = a.to_string_lossy();
        let mot = if cacher {
            "•••".to_string()
        } else if let Some((cle, _)) = a.split_once('=').filter(|(c, _)| annonce_un_secret(c)) {
            format!("{cle}=•••")
        } else {
            a.replace(['\n', '\r'], " ⏎ ")
        };
        cacher = annonce_un_secret(&a) && !a.contains('=');
        mots.push(mot);
        // Plus loin, rien ne se montrerait : la ligne est coupée à COLONNES.
        if mots.iter().map(String::len).sum::<usize>() > COLONNES.saturating_mul(4) {
            break;
        }
    }
    crate::ui::affichable(&mots.join(" "))
}

/// Une commande suivie, du départ à la fin : notée en sortant (`Drop`), même si l'appelant rend tôt sur une erreur.
pub(crate) struct Suivi {
    commande: Option<String>,
    debut: Instant,
    issue: Issue,
}

impl Suivi {
    /// Rien n'est préparé quand les coulisses sont éteintes : le coût reste celui d'une lecture atomique.
    pub(crate) fn de(commande: &Command) -> Self {
        Suivi {
            commande: allumees().then(|| decrire(commande)),
            debut: Instant::now(),
            issue: Issue::PasDemarree,
        }
    }

    pub(crate) fn fin(&mut self, issue: Issue) {
        self.issue = issue;
    }
}

impl Drop for Suivi {
    fn drop(&mut self) {
        let Some(commande) = self.commande.take() else {
            return;
        };
        let trace = Trace {
            commande,
            duree: self.debut.elapsed(),
            issue: std::mem::replace(&mut self.issue, Issue::PasDemarree),
        };
        montrer(&trace);
        if let Ok(mut t) = TRACES.lock() {
            if t.len() >= GARDEES {
                t.pop_front();
            }
            t.push_back(trace);
        }
    }
}

/// Sur la sortie d'erreur, seulement dans un terminal, et jamais pendant un menu (en mode clavier, un saut de ligne
/// ne revient pas au début et la liste se dessine par-dessus). Le bilan lance ses lectures sur plusieurs fils : une
/// seule écriture par ligne, pour qu'elles ne se mêlent pas.
fn montrer(trace: &Trace) {
    use std::io::{IsTerminal, Write};
    let erreur = std::io::stderr();
    if !erreur.is_terminal() || crossterm::terminal::is_raw_mode_enabled().unwrap_or(true) {
        return;
    }
    let _ = erreur
        .lock()
        .write_all(format!("  {GRIS}{}{RESET}\n", trace.ligne()).as_bytes());
}

/// Les dernières commandes, de la plus ancienne à la plus récente.
pub(crate) fn dernieres() -> Vec<Trace> {
    TRACES.lock().map(|t| t.iter().cloned().collect()).unwrap_or_default()
}

/// `vanguard parametres coulisses voir` : les dernières commandes de ce processus. Un nouveau lancement repart à vide :
/// rien n'est gardé sur le disque.
pub(crate) fn afficher() {
    let traces = dernieres();
    if traces.is_empty() {
        crate::ui::afficher_aligne(
            "  ",
            if allumees() {
                tr!(
                    "Aucune commande encore dans ce lancement de Vanguard : elles se gardent en mémoire seulement, jamais sur le disque.",
                    "No command yet in this run of Vanguard: they are kept in memory only, never on disk."
                )
            } else {
                tr!(
                    "Les coulisses sont éteintes : rien n'est noté. « vanguard parametres coulisses oui » les allume.",
                    "Backstage is off: nothing is noted. “vanguard settings backstage yes” turns it on."
                )
            },
            2,
            GRIS,
        );
    }
    for t in &traces {
        println!("  {GRIS}{}{RESET}", t.ligne());
    }
    #[cfg(windows)]
    crate::ui::afficher_aligne(
        "  ",
        tr!(
            "Ce que fait la fenêtre administrateur n'est pas ici : son journal est gardé dans les fichiers corrections*.log du dossier de Vanguard.",
            "What the administrator window does is not here: its log is kept in the corrections*.log files of Vanguard's folder."
        ),
        2,
        GRIS,
    );
}

/// `output`, `status` et `spawn` suivis, pour un programme lancé hors de `commande::lancer…` (au premier plan, pour la
/// personne, ou dont on lit la sortie au fil de l'eau).
pub(crate) trait Suivie {
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "l'analyse par ClamAV, son seul usage, est sous Linux")
    )]
    fn output_suivi(&mut self) -> std::io::Result<Output>;
    fn status_suivi(&mut self) -> std::io::Result<ExitStatus>;
    /// Lancé sans l'attendre : la trace dit « lancée », et sa durée celle du départ.
    fn spawn_suivi(&mut self) -> std::io::Result<Child>;
    /// Lancé, et suivi jusqu'à ce que l'appelant dise comment il a fini (`Suivi::fin`) : pour un programme dont on
    /// lit la sortie au fil de l'eau, ou qu'on attend à sa façon.
    fn spawn_et_suivre(&mut self) -> (std::io::Result<Child>, Suivi);
}

impl Suivie for Command {
    fn output_suivi(&mut self) -> std::io::Result<Output> {
        let mut suivi = Suivi::de(self);
        // Le seul `output` permis hors de commande.rs : c'est lui qui le suit.
        let r = self.output();
        suivi.fin(r.as_ref().map_or(Issue::PasDemarree, |o| Issue::Code(o.status.code())));
        r
    }

    fn status_suivi(&mut self) -> std::io::Result<ExitStatus> {
        let mut suivi = Suivi::de(self);
        let r = self.status();
        suivi.fin(r.as_ref().map_or(Issue::PasDemarree, |s| Issue::Code(s.code())));
        r
    }

    fn spawn_suivi(&mut self) -> std::io::Result<Child> {
        let mut suivi = Suivi::de(self);
        let r = self.spawn();
        if r.is_ok() {
            suivi.fin(Issue::Lancee);
        }
        r
    }

    fn spawn_et_suivre(&mut self) -> (std::io::Result<Child>, Suivi) {
        let mut suivi = Suivi::de(self);
        let r = self.spawn();
        if r.is_ok() {
            // Jusqu'à ce que l'appelant dise mieux : arrêté sans un mot, il l'a arrêté.
            suivi.fin(Issue::Arretee);
        }
        (r, suivi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ce qui se montre d'une commande : le programme sans son dossier, les arguments filtrés, un secret annoncé
    /// caché, et la ligne tenue dans 76 colonnes avec son retrait.
    #[test]
    fn une_commande_se_montre_courte_et_sans_piege() {
        let mut c = Command::new("/usr/bin/nmcli");
        c.args(["-t", "dev", "wifi", "Salon\x1b[2K\nfaux"]);
        let d = decrire(&c);
        assert!(d.starts_with("nmcli -t dev wifi Salon"), "{d}");
        assert!(!crate::ui::contient_un_piege(&d) && !d.contains('\n'), "{d}");

        let mut c = Command::new("outil");
        c.args(["--password", "a1B2c3", "--token=d4E5f6", "--ok"]);
        let d = decrire(&c);
        assert!(!d.contains("a1B2c3") && !d.contains("d4E5f6"), "{d}");
        assert!(d.contains("--token=•••") && d.ends_with("--ok"), "{d}");

        let longue = Trace {
            commande: decrire(Command::new("powershell").args(["-NoProfile", "-Command", &"x".repeat(5000)])),
            duree: Duration::from_millis(12_345),
            issue: Issue::Code(Some(1)),
        };
        let ligne = format!("  {}", longue.ligne());
        assert!(crate::ui::largeur_affichee(&ligne) <= crate::ui::LARGEUR, "{ligne}");
        assert!(ligne.contains("✖") && ligne.contains("12"), "{ligne}");
    }

    /// Éteintes, rien n'est noté ; allumées, la trace garde l'issue, et la mémoire ne dépasse pas GARDEES.
    #[test]
    fn traces_bornees_et_seulement_allumees() {
        let avant = allumees();
        allumer(false);
        let n = dernieres().len();
        drop(Suivi::de(&Command::new("eteinte")));
        assert_eq!(dernieres().len(), n);

        allumer(true);
        for _ in 0..GARDEES.saturating_add(5) {
            let mut s = Suivi::de(&Command::new("allumee"));
            s.fin(Issue::Code(Some(0)));
        }
        allumer(avant);
        let t = dernieres();
        assert_eq!(t.len(), GARDEES);
        // D'autres tests lancent des commandes en même temps : elles peuvent s'intercaler.
        assert!(
            t.iter()
                .any(|t| t.commande == "allumee" && t.issue == Issue::Code(Some(0)))
        );
    }
}
