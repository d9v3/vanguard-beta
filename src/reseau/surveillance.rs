//! Surveillance automatique : scan du réseau toutes les heures, notification si un appareil inconnu apparaît ; les
//! programmes arrivés dans Téléchargements, à vérifier avant de les ouvrir ; un programme qui parle à un serveur de
//! commande de botnet connu (bloqué seulement si la protection active a été activée : protection/blocage). La
//! protection en temps réel coupée (`protection::temps_reel`), chaque passe s'arrête au début, sans rien regarder ni
//! notifier ; c'est aussi la passe qui constate l'échéance de la coupure et remet la protection.
//! Planificateur natif de chaque système : timer systemd (Linux), Planificateur de tâches (Windows), agent launchd
//! (macOS).

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

use crate::machine::Constat;
use crate::reseau::tableau::{self, Genre};
use crate::reseau::{self, Options, upnp};
use crate::risk::Niveau;
use crate::ui::*;

/// Les noms de ce que la surveillance pose sur chaque système : les unités systemd (Linux), l'agent launchd (macOS),
/// la tâche du Planificateur (Windows). Connus partout : la désinstallation les cherche par leur nom exact.
pub(crate) const NOM: &str = "vanguard-surveillance";
pub(crate) const AGENT_MACOS: &str = "com.vanguard.surveillance";
/// Nom lisible de la tâche dans le Planificateur de tâches Windows.
pub(crate) const TACHE_WINDOWS: &str = "vanguard - surveillance du reseau";

/// La commande réussit-elle ? Avec un délai : le menu demande l'état de la surveillance à chaque affichage, et un
/// bus de session muet (systemctl --user) le figerait.
#[cfg(unix)]
pub(crate) fn reussit(cmd: &str, args: &[&str]) -> bool {
    crate::commande::lancer(Command::new(cmd).args(args), 30).is_some_and(|r| r.code == Some(0))
}

/// La minuterie de l'utilisateur (« nom.timer ») est-elle activée ? Lu dans les liens que pose
/// `systemctl --user enable`, sans le lancer : un bus de session muet ne fige plus le menu. La commande ne
/// sert qu'en secours, quand aucun dossier d'unités de l'utilisateur n'existe.
#[cfg(target_os = "linux")]
pub(crate) fn minuterie_activee(timer: &str) -> bool {
    crate::machine::linux::natif::unite_activee(timer, true)
        .unwrap_or_else(|| reussit("systemctl", &["--user", "is-enabled", timer]))
}

/// Programme à planifier. Lancé depuis la clé USB, on en installe d'abord une copie locale :
/// sinon la surveillance (et l'entretien du mois) s'arrêterait dès que la clé est débranchée. La copie passe par
/// `mise_a_jour::poser_copie` (version revérifiée, essayée, mise en place d'un coup, jamais par-dessus une plus
/// récente). `None` : elle n'a pas pu se faire, et c'est dit ; le chemin de la clé n'est jamais rendu à sa place,
/// une minuterie qui le lancerait s'arrêterait sans bruit une fois la clé débranchée.
pub(crate) fn executable() -> Option<String> {
    // Sous Linux et macOS, le programme peut tourner depuis une copie temporaire (protection de la clé), effacée
    // à la fin.
    #[cfg(unix)]
    let exe = crate::protection::cle::exe_d_origine();
    #[cfg(windows)]
    let exe = std::env::current_exe().ok();
    let Some(exe) = exe else {
        return Some("vanguard".into());
    };
    if !reseau::cle_usb().is_some_and(|cle| sous(&exe, &cle)) {
        return Some(exe.display().to_string());
    }
    match crate::mise_a_jour::poser_copie(&exe) {
        Ok(dest) => {
            trp!(
                "  {GRIS}Copie locale pour la surveillance : {}{RESET}",
                "  {GRIS}Local copy for monitoring: {}{RESET}",
                dest.display()
            );
            Some(dest.display().to_string())
        }
        Err(e) => {
            trp!(
                "  ✖ Copie locale de Vanguard impossible : rien n'est posé.\n    {}\n    {GRIS}Lancé depuis la clé, il s'arrêterait une fois la clé débranchée.{RESET}",
                "  ✖ Local copy of Vanguard not possible: nothing is set up.\n    {}\n    {GRIS}Started from the key, it would stop once the key is unplugged.{RESET}",
                affichable(&e)
            );
            None
        }
    }
}

/// Un chemin sans le préfixe « \\?\ » que `canonicalize` met sous Windows (sauf « \\?\UNC\ », qui n'a pas de forme
/// courte équivalente) : PowerShell et un raccourci veulent la forme courante, et `Path::starts_with` tient
/// « \\?\E:\ » et « E:\ » pour deux débuts différents.
pub(crate) fn sans_verbatim(p: &Path) -> PathBuf {
    p.to_str()
        .and_then(|s| s.strip_prefix(r"\\?\"))
        .filter(|s| !s.starts_with(r"UNC\"))
        .map_or_else(|| p.to_path_buf(), PathBuf::from)
}

/// `p` est-il sous `d` ? Comparés sous leur forme courante, puis canonique : la clé se situe par `canonicalize`
/// (« \\?\E:\ »), le programme par `current_exe` (« E:\… »).
pub(crate) fn sous(p: &Path, d: &Path) -> bool {
    let canon = |x: &Path| {
        x.canonicalize()
            .map_or_else(|_| sans_verbatim(x), |c| sans_verbatim(&c))
    };
    sans_verbatim(p).starts_with(sans_verbatim(d)) || canon(p).starts_with(canon(d))
}

pub(crate) fn notifier(titre: &str, corps: &str) {
    // Délai : sans service de notifications qui réponde, notify-send attendrait sans fin, et la surveillance avec.
    // Par D-Bus (org.freedesktop.Notifications.Notify, urgence critique) ; notify-send seulement sans bus de la
    // session joignable par le client maison.
    #[cfg(target_os = "linux")]
    // Sous les essais, ni le bus ni notify-send : aucune vraie notification ne part d'un test.
    if !cfg!(test) && crate::machine::linux::dbus::actions::notifier(titre, corps).is_err() {
        let _ = crate::commande::lancer(
            // « -- » : un titre ou un corps qui commence par « - » (venu d'une extension) n'est jamais lu comme une
            // option.
            Command::new("notify-send")
                .args(["-a", "Vanguard", "-i", "vanguard", "-u", "critical", "--", titre, corps]),
            10,
        );
    }
    // macOS : notification du Centre de notifications, par AppleScript (texte entre guillemets échappés). osascript
    // fait foi (outil gardé, §4) : UNUserNotificationCenter demande une application signée, ce que n'est pas un
    // programme en ligne de commande. Lancé sans shell.
    #[cfg(target_os = "macos")]
    {
        let e = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let _ = crate::commande::lancer(
            Command::new("osascript").arg("-e").arg(format!(
                "display notification \"{}\" with title \"{}\" sound name \"Basso\"",
                e(corps),
                e(titre)
            )),
            10,
        );
    }
    #[cfg(windows)]
    {
        let e = crate::commande::ps_texte;
        // Identifiant d'application de PowerShell : sans lui, Windows 10/11 n'affiche pas la notification.
        let script = format!(
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; \
             $t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
             $x = $t.GetElementsByTagName('text'); $x.Item(0).AppendChild($t.CreateTextNode('{}')) | Out-Null; $x.Item(1).AppendChild($t.CreateTextNode('{}')) | Out-Null; \
             [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\WindowsPowerShell\\v1.0\\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($t))",
            e(titre),
            e(corps)
        );
        let _ = crate::machine::windows::ps(&script);
    }
}

/// Une alerte de la surveillance : gardée au journal du tableau de bord, puis notifiée. Une notification disparaît
/// en quelques secondes ; celle de la nuit se relit ainsi le matin (« vanguard tableau-de-bord »).
pub(crate) fn alerter(genre: Genre, titre: &str, texte: &str) {
    tableau::noter_alerte(genre, titre, texte);
    notifier(titre, texte);
}

/// Une alerte qui se reconnaît à sa clé (`protection::normales`) : déclarée normale ici, elle n'est ni notée ni
/// notifiée ; sinon, notée avec sa clé (les traces d'incident la relient au blocage), puis notifiée.
pub(crate) fn alerter_cle(genre: Genre, cle: &str, titre: &str, texte: &str) {
    if crate::protection::normales::est_normale(cle) {
        return;
    }
    tableau::noter_alerte_cle(genre, Some(cle), titre, texte);
    notifier(titre, texte);
}

/// Appelé par le planificateur : scan silencieux, puis notification s'il y a du nouveau.
/// Catégories surveillées sur cette machine : ce qui trahit une attaque ou une panne. Les mises à jour
/// disponibles, qui changent tous les jours, n'en font pas partie.
const CATEGORIES_SURVEILLEES: &[&str] = &[
    "Pare-feu",
    "Antivirus",
    "Ports en écoute",
    "Persistance",
    "Certificats",
    "DNS",
    "Santé",
    "Comptes",
    "Sudo",
    "Groupes",
    "Fichiers suspects",
    "Clés SSH",
    "Extensions",
    "Bluetooth",
    "Fin de support",
    "Durcissement",
    // Les alertes des règles EVT- que le bilan rend (WIN-JRN-003), leur règle devant le message.
    "Journaux d'événements",
    // Un fichier d'état réécrit hors de Vanguard : ce qu'un programme du compte ferait pour faire taire son alerte.
    "État de Vanguard",
];

/// Les failles connues changent presque chaque jour, comme les mises à jour : seules les critiques sont notifiées,
/// une faille activement exploitée (catalogue KEV de la CISA) ou critique pour la distribution.
const FAILLES_CRITIQUES: &str = "Failles connues";

/// La génération des textes des alertes suivies, notée dans chaque état (ici et dans l'entretien du mois) : à monter
/// quand un message suivi change de formulation (1 : vouvoiement de la 0.87). Un état écrit sous une autre génération
/// se compare une passe sans la formulation (`sans_formulation`) : la mise à jour ne fait pas passer pour nouveau ce
/// qui était déjà là.
pub(crate) const TEXTES: u32 = 1;

/// État de la machine au dernier passage de la surveillance.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct EtatMachine {
    score: Option<u32>,
    /// `TEXTES` à l'écriture ; 0 dans l'état d'une version d'avant.
    #[serde(default)]
    textes: u32,
    /// Problèmes moyens ou plus graves des catégories surveillées, « catégorie : message ».
    alertes: Vec<String>,
    /// La clé de chaque alerte (`Constat::cle`), dans l'ordre de `alertes` ; `None` pour une règle qui ne pose pas
    /// encore d'objet, vide dans l'état d'une version d'avant les clés (on compare alors le texte). Scellée avec le
    /// reste : une clé écrite d'avance ne tait rien sans se voir.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cles: Vec<Option<String>>,
    /// Le niveau de chaque alerte, dans l'ordre de `alertes` ; vide dans l'état d'une version d'avant. Une alerte qui
    /// s'aggrave sans changer de clé (une extension qui gagne l'accès à tous les sites) se renotifie ainsi.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    niveaux: Vec<Option<Niveau>>,
}

impl EtatMachine {
    /// Les alertes avec leur clé.
    fn alertes_et_cles(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.alertes
            .iter()
            .enumerate()
            .map(|(i, a)| (a.as_str(), self.cles.get(i).and_then(Option::as_deref)))
    }

    /// Le niveau de l'alerte `i`, s'il a été noté.
    fn niveau(&self, i: usize) -> Option<Niveau> {
        self.niveaux.get(i).copied().flatten()
    }

    /// Ajoute une alerte, sa clé et son niveau, en gardant les trois listes alignées.
    fn ajouter(&mut self, alerte: String, cle: Option<String>, niveau: Option<Niveau>) {
        if self.cles.len() < self.alertes.len() {
            self.cles.resize(self.alertes.len(), None);
        }
        if self.niveaux.len() < self.alertes.len() {
            self.niveaux.resize(self.alertes.len(), None);
        }
        self.alertes.push(alerte);
        self.cles.push(cle);
        self.niveaux.push(niveau);
    }

    /// Aucune clé, aucun niveau : l'état garde la forme d'avant.
    fn compacter(&mut self) {
        if self.cles.iter().all(Option::is_none) {
            self.cles.clear();
        }
        if self.niveaux.iter().all(Option::is_none) {
            self.niveaux.clear();
        }
    }
}

/// L'état du passage d'avant, d'après ses sceaux. Changé hors de Vanguard (une alerte écrite d'avance), adopté
/// sans sceau d'avant ou illisible, il ne vaut rien : tout ce qui est là maintenant est nouveau, jamais un silence.
/// Seul un état absent (premier passage) ne fait que mémoriser.
fn etat_d_avant(lu: crate::sceau::Lecture) -> Option<EtatMachine> {
    use crate::sceau::Lecture;
    match lu {
        Lecture::Absent => None,
        Lecture::Intact(o) => Some(serde_json::from_slice(&o).unwrap_or_default()),
        Lecture::Adopte(_) | Lecture::Falsifie(_) | Lecture::Illisible(_) | Lecture::Inconnu => {
            Some(EtatMachine::default())
        }
    }
}

/// Un constat que la surveillance notifie quand il apparaît.
fn machine_surveillee(c: &crate::machine::Constat) -> bool {
    c.probleme.is_some_and(|n| n >= Niveau::Moyen) && CATEGORIES_SURVEILLEES.contains(&c.categorie)
        || c.probleme == Some(Niveau::Critique) && c.categorie == FAILLES_CRITIQUES
}

fn etat_machine(a: &crate::machine::Audit) -> EtatMachine {
    let mut etat = EtatMachine {
        score: a.fiable().then_some(a.score),
        textes: TEXTES,
        ..EtatMachine::default()
    };
    for c in a.constats.iter().filter(|c| machine_surveillee(c)) {
        etat.ajouter(
            format!("{} : {}", c.categorie, c.message),
            c.cle().map(|k| k.to_string()),
            c.probleme,
        );
    }
    etat.compacter();
    etat
}

/// Deux alertes sont-elles la même ? Par leur clé quand les deux en ont une (une autre langue ne renotifie rien),
/// sinon par leur texte sans ses nombres (`cle_alerte`), comme avant les clés ; face à un état d'une autre génération
/// de textes, sans leur formulation, le temps d'une passe.
fn meme_alerte(a: (&str, Option<&str>), b: (&str, Option<&str>), memes_textes: bool) -> bool {
    match (a.1, b.1) {
        (Some(x), Some(y)) => x == y,
        _ if memes_textes => cle_alerte(a.0) == cle_alerte(b.0),
        _ => sans_formulation(a.0) == sans_formulation(b.0),
    }
}

/// Un problème comparé sans ses nombres (« 3 % libres » et « 2 % libres » sont le même problème), sauf les ports :
/// un autre numéro de port est un autre problème.
pub(crate) fn cle_alerte(alerte: &str) -> String {
    if alerte.starts_with("Ports en écoute") {
        return alerte.to_string();
    }
    // Une faille critique : seule sa tête compte, les CVE du catalogue KEV avec leurs chiffres ; le reste du message
    // (paquets corrigés, ports) change chaque jour et la renotifierait.
    if let Some(message) = alerte.strip_prefix(&format!("{FAILLES_CRITIQUES} : ")) {
        let tete = message.split(". ").next().unwrap_or_default();
        return if tete.contains("KEV") {
            format!("{FAILLES_CRITIQUES} : {tete}")
        } else {
            format!("{FAILLES_CRITIQUES} : critique")
        };
    }
    alerte
        .chars()
        .map(|c| if c.is_ascii_digit() { '#' } else { c })
        .collect()
}

/// Notifications à envoyer entre deux passages : (titre, texte).
fn nouveautes_machine(avant: &EtatMachine, apres: &EtatMachine) -> Vec<(String, String)> {
    // Une gravité plus forte renotifie, comme l'apprentissage : la même alerte d'avant ne la tait que si elle était
    // au moins aussi grave. Un niveau non noté (état d'une version d'avant) ne renotifie rien.
    let aggravee = |apres: Option<Niveau>, avant: Option<Niveau>| matches!((apres, avant), (Some(x), Some(y)) if x > y);
    let nouvelles: Vec<&str> = apres
        .alertes_et_cles()
        .enumerate()
        .filter(|(i, a)| {
            !avant.alertes_et_cles().enumerate().any(|(j, b)| {
                meme_alerte(*a, b, avant.textes == TEXTES) && !aggravee(apres.niveau(*i), avant.niveau(j))
            })
        })
        .map(|(_, a)| a.0)
        .collect();
    let mut notes = Vec::new();
    for a in nouvelles.iter().take(3) {
        let (cat, msg) = a.split_once(" : ").unwrap_or(("", a));
        notes.push((
            trf!("Vanguard : {}", "Vanguard: {}", crate::langue::categorie(cat)),
            msg.to_string(),
        ));
    }
    if nouvelles.len() > 3 {
        notes.push((
            tr!("Vanguard : autres problèmes", "Vanguard: other problems").to_string(),
            trf!(
                "{} autre(s) problème(s) nouveau(x) : lancez « vanguard audit ».",
                "{} other new problem(s): run “vanguard audit”.",
                nouvelles.len() - 3
            ),
        ));
    }
    if let (Some(a), Some(b)) = (avant.score, apres.score)
        && b + 10 <= a
    {
        notes.push((
            tr!("Vanguard : note en baisse", "Vanguard: grade dropping").to_string(),
            trf!(
                "La note de cet ordinateur passe de {a} à {b} : lancez « vanguard audit » pour voir pourquoi.",
                "This computer's grade drops from {a} to {b}: run “vanguard audit” to see why."
            ),
        ));
    }
    notes
}

/// Audit silencieux de cette machine, comparé au passage précédent. Le premier passage mémorise seulement. Rend le
/// bilan : l'audit du réseau reprend ses constats réseau sans relancer ces règles.
fn veiller_machine() -> crate::machine::Audit {
    let audit = crate::machine::auditer(false);
    let mut apres = etat_machine(&audit);
    let avant = etat_d_avant(crate::sceau::lire(crate::sceau::MACHINE));
    // Failles pas vérifiées cette fois (hors ligne) : celles d'avant restent, sinon leur retour serait renotifié.
    if let Some(avant) = &avant
        && audit
            .constats
            .iter()
            .any(|c| c.categorie == FAILLES_CRITIQUES && !c.verifie)
    {
        for (i, (a, cle)) in avant.alertes_et_cles().enumerate() {
            if a.starts_with(&format!("{FAILLES_CRITIQUES} : ")) {
                apres.ajouter(a.to_string(), cle.map(str::to_string), avant.niveau(i));
            }
        }
        apres.compacter();
    }
    if let Some(avant) = &avant {
        for (titre, texte) in nouveautes_machine(avant, &apres) {
            alerter(Genre::Machine, &titre, &texte);
        }
    }
    if let Ok(texte) = serde_json::to_string(&apres) {
        let _ = crate::sceau::ecrire(crate::sceau::MACHINE, texte);
    }
    audit
}

/// L'audit du réseau au dernier passage, réduit à ce qui déclenche une alerte quand il change : les redirections de
/// la box (`None` : non lues, rien à comparer) et les constats des règles suivies.
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq)]
struct EtatAudit {
    redirections: Option<Vec<String>>,
    /// `TEXTES` à l'écriture ; 0 dans l'état d'une version d'avant.
    #[serde(default)]
    textes: u32,
    /// « règle|catégorie : message », les nombres neutralisés sauf pour le DNS du bail, dont l'adresse compte.
    constats: Vec<String>,
}

/// L'audit du passage d'avant, d'après ses sceaux. Absent : premier passage, on mémorise seulement. Changé hors de
/// Vanguard (une redirection écrite d'avance), effacé avec les sceaux, adopté ou illisible : un état vide, où toutes
/// les redirections et tous les constats suivis sont nouveaux, jamais un silence.
fn audit_d_avant(lu: crate::sceau::Lecture) -> Option<EtatAudit> {
    use crate::sceau::Lecture;
    let vide = EtatAudit {
        textes: TEXTES,
        redirections: Some(Vec::new()),
        constats: Vec::new(),
    };
    match lu {
        Lecture::Absent => None,
        Lecture::Intact(o) => Some(serde_json::from_slice(&o).unwrap_or(vide)),
        Lecture::Adopte(_) | Lecture::Falsifie(_) | Lecture::Illisible(_) | Lecture::Inconnu => Some(vide),
    }
}

/// La clé d'une redirection, stable d'une passe à l'autre.
fn cle_redirection(r: &upnp::Redirection) -> String {
    format!(
        "{} {} → {}:{}",
        r.protocole.to_uppercase(),
        r.port_public,
        r.appareil,
        r.port_appareil
    )
}

/// Le genre de l'alerte d'une règle de l'audit que la surveillance suit ; `None` : règle non suivie. Les
/// redirections (COM-EXP-001) sont comparées à part, par redirection.
fn genre_de(regle: &str) -> Option<Genre> {
    match regle {
        "COM-EXP-003" => Some(Genre::Machine),
        "COM-DNS-002" | "COM-DNS-004" => Some(Genre::Passerelle),
        r if r.starts_with("COM-WIF-") => Some(Genre::WiFi),
        _ => None,
    }
}

/// Un constat de l'audit que la surveillance suit : vérifié, d'une règle suivie, moyen ou plus grave — sauf le DNS
/// distribué par la box, suivi dès l'information, puisque c'est son changement qui compte.
fn surveille(c: &Constat) -> bool {
    c.verifie
        && genre_de(c.regle).is_some()
        && (c.regle == "COM-DNS-002" || c.probleme.is_some_and(|n| n >= Niveau::Moyen))
}

fn cle_constat(c: &Constat) -> String {
    let texte = format!("{} : {}", c.categorie, c.message);
    let texte = if c.regle == "COM-DNS-002" {
        texte
    } else {
        cle_alerte(&texte)
    };
    format!("{}|{texte}", c.regle)
}

/// Une alerte « catégorie : message » sans sa formulation, pour la comparer à un état d'une autre génération de
/// textes : sa catégorie, et ce qui désigne son objet quelle que soit la phrase (adresses IP et MAC, CVE, ports
/// « 8080/tcp »). Une alerte nouvelle sur un autre objet reste nouvelle ; seul un même objet redit autrement se tait.
pub(crate) fn sans_formulation(alerte: &str) -> String {
    let (categorie, message) = alerte.split_once(" : ").unwrap_or((alerte, ""));
    let objet = |m: &&str| {
        m.parse::<std::net::IpAddr>().is_ok()
            || m.len() == 17 && m.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '-'))
            || m.starts_with("CVE-")
            || m.split_once('/').is_some_and(|(n, p)| {
                !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) && matches!(p, "tcp" | "udp")
            })
    };
    let objets: Vec<&str> = message
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '(' | ')' | '«' | '»'))
        .map(|m| m.trim_end_matches(['.', ':']))
        .filter(objet)
        .collect();
    format!("{categorie}|{}", objets.join(" "))
}

/// Une clé de `cle_constat` (« règle|catégorie : message ») sans sa formulation : la règle et l'objet du message.
fn sans_texte(cle: &str) -> String {
    let (regle, texte) = cle.split_once('|').unwrap_or((cle, ""));
    format!("{regle}|{}", sans_formulation(texte))
}

fn etat_audit(r: &reseau::Rapport, a: &crate::audit::AuditReseau) -> EtatAudit {
    EtatAudit {
        textes: TEXTES,
        redirections: crate::audit::redirections_du_scan(r).map(|l| l.iter().map(cle_redirection).collect()),
        constats: a
            .domaines
            .iter()
            .flat_map(|d| &d.constats)
            .filter(|c| surveille(c))
            .map(cle_constat)
            .collect(),
    }
}

/// Le titre de la notification d'un constat nouveau, selon sa règle.
fn titre_alerte(regle: &str) -> String {
    match regle {
        "COM-DNS-002" => tr!(
            "Vanguard : le DNS distribué par le routeur a changé",
            "Vanguard: the DNS handed out by the router changed"
        ),
        "COM-DNS-004" => tr!("Vanguard : réponses DNS détournées", "Vanguard: DNS answers hijacked"),
        "COM-EXP-003" => tr!(
            "Vanguard : cet ordinateur exposé en IPv6",
            "Vanguard: this computer exposed over IPv6"
        ),
        _ => tr!("Vanguard : Wi-Fi moins protégé", "Vanguard: Wi-Fi less protected"),
    }
    .to_string()
}

/// Les alertes entre deux passages de l'audit : (titre, texte, genre), une par redirection nouvelle de la box et par
/// constat nouveau d'une règle suivie ; rien quand les redirections n'ont pas pu être lues à l'un des deux passages.
fn nouveautes_audit(
    avant: &EtatAudit,
    apres: &EtatAudit,
    redirections: &[upnp::Redirection],
    constats: &[&Constat],
) -> Vec<(String, String, Genre)> {
    let mut alertes = Vec::new();
    if let (Some(av), Some(ap)) = (&avant.redirections, &apres.redirections) {
        for r in redirections.iter().filter(|r| {
            let cle = cle_redirection(r);
            ap.contains(&cle) && !av.contains(&cle)
        }) {
            let description = if r.description.is_empty() {
                String::new()
            } else {
                format!(" « {} »", r.description)
            };
            alertes.push((
                tr!(
                    "Vanguard : le routeur ouvre un port vers Internet",
                    "Vanguard: the router opens a port to the Internet"
                )
                .to_string(),
                trf!(
                    "Nouvelle redirection : port {}/{} d'Internet vers {}:{} ({}){description}. Un appareil l'a demandée au routeur (UPnP) : si ce n'est pas voulu, retirez-la et coupez UPnP dans le routeur.",
                    "New forwarding: Internet port {}/{} to {}:{} ({}){description}. A device asked the router for it (UPnP): if it is not wanted, remove it and turn UPnP off in the router.",
                    r.port_public,
                    r.protocole.to_lowercase(),
                    r.appareil,
                    r.port_appareil,
                    crate::risk::info_port(r.port_appareil).service
                ),
                Genre::Passerelle,
            ));
        }
    }
    let deja = |cle: &str| {
        if avant.textes == TEXTES {
            avant.constats.iter().any(|a| a == cle)
        } else {
            avant.constats.iter().any(|a| sans_texte(a) == sans_texte(cle))
        }
    };
    for c in constats.iter().filter(|c| surveille(c)) {
        let cle = cle_constat(c);
        if apres.constats.contains(&cle) && !deja(&cle) {
            let Some(genre) = genre_de(c.regle) else { continue };
            alertes.push((titre_alerte(c.regle), c.message.clone(), genre));
        }
    }
    alertes
}

/// Les domaines rapides de l'audit du réseau après le scan, comparés au passage précédent : une alerte par
/// changement (redirection nouvelle de la box, DNS du bail changé, Wi-Fi moins protégé, exposition IPv6 nouvelle,
/// divergence DNS), jamais à chaque passe. Le premier passage mémorise seulement.
async fn veiller_audit(r: &reseau::Rapport, machine: Vec<Constat>) {
    let a = crate::audit::auditer(r, Some(machine), false, true).await;
    let apres = etat_audit(r, &a);
    let avant = audit_d_avant(crate::sceau::lire(crate::sceau::AUDIT));
    if let Some(avant) = &avant {
        let redirections = crate::audit::redirections_du_scan(r).unwrap_or_default();
        let constats: Vec<&Constat> = a.domaines.iter().flat_map(|d| &d.constats).collect();
        for (titre, texte, genre) in nouveautes_audit(avant, &apres, &redirections, &constats) {
            alerter(genre, &titre, &texte);
        }
    }
    if let Ok(texte) = serde_json::to_string(&apres) {
        let _ = crate::sceau::ecrire(crate::sceau::AUDIT, texte);
    }
}

/// Box vue au dernier passage : même Wi-Fi et même adresse, mais une autre adresse MAC = alerte.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct Passerelle {
    reseau: String,
    nom: Option<String>,
    ip: std::net::Ipv4Addr,
    mac: String,
}

/// La box du passage d'avant, seulement telle que Vanguard l'a notée : posée ou changée à côté (la MAC d'un
/// usurpateur écrite d'avance), elle ne sert pas de référence, et la comparaison repart de ce passage.
fn passerelle_d_avant(lu: crate::sceau::Lecture) -> Option<Passerelle> {
    match lu {
        crate::sceau::Lecture::Intact(o) => serde_json::from_slice(&o).ok(),
        _ => None,
    }
}

fn passerelle_de(r: &reseau::Rapport) -> Option<Passerelle> {
    let h = r.hotes.iter().find(|h| h.role == Some("passerelle"))?;
    Some(Passerelle {
        reseau: r.reseau.clone(),
        nom: r.nom_reseau.clone(),
        ip: h.ip,
        mac: h.mac.clone()?.to_lowercase(),
    })
}

/// La box a-t-elle changé d'adresse MAC sur le même réseau (même Wi-Fi, même adresse) ? Rend (ancienne, nouvelle).
fn mac_changee(avant: &Passerelle, apres: &Passerelle) -> Option<(String, String)> {
    (avant.reseau == apres.reseau && avant.nom == apres.nom && avant.ip == apres.ip && avant.mac != apres.mac)
        .then(|| (avant.mac.clone(), apres.mac.clone()))
}

/// Contrôles contre l'usurpation de la box : MAC partagée avec un autre appareil, MAC changée depuis le passage
/// précédent. Le changement est retenu seulement s'il n'y a pas d'alerte de partage (on garde l'ancienne référence).
fn veiller_passerelle(r: &reseau::Rapport) {
    if let Some((boite, mac, autre)) = reseau::usurpation_arp(r) {
        alerter(
            Genre::Passerelle,
            tr!("Vanguard : routeur usurpé ?", "Vanguard: router impersonated?"),
            &reseau::message_usurpation(boite, &mac, autre),
        );
        return;
    }
    let Some(apres) = passerelle_de(r) else { return };
    let avant = passerelle_d_avant(crate::sceau::lire(crate::sceau::PASSERELLE));
    if let Some((ancienne, nouvelle)) = avant.as_ref().and_then(|a| mac_changee(a, &apres)) {
        alerter(
            Genre::Passerelle,
            tr!(
                "Vanguard : le routeur a changé d'adresse MAC",
                "Vanguard: the router's MAC address changed"
            ),
            &trf!(
                "Le routeur {} répondait avec {ancienne}, il répond maintenant avec {nouvelle}. Normal si vous venez de changer de routeur ; sinon, quelqu'un se fait peut-être passer pour lui (usurpation ARP).",
                "The router {} answered with {ancienne}, it now answers with {nouvelle}. Normal if you just replaced it; otherwise someone may be impersonating it (ARP spoofing).",
                apres.ip
            ),
        );
    }
    if let Ok(texte) = serde_json::to_string(&apres) {
        let _ = crate::sceau::ecrire(crate::sceau::PASSERELLE, texte);
    }
}

/// Le réseau attendu au plus une minute au début du scan, redemandé toutes les deux secondes : au réveil, systemd lance
/// la passe rattrapée avant que NetworkManager ait rebranché le Wi-Fi et refait le DHCP (quelques secondes), et sans
/// passerelle le scan échouait, ou visait l'interface de Docker ou de libvirt à la place du réseau de la maison.
const ATTENTE_RESEAU: std::time::Duration = std::time::Duration::from_secs(60);
const PAS_RESEAU: std::time::Duration = std::time::Duration::from_secs(2);

/// Attend que `reseau_la` dise le réseau là (une passerelle par défaut), en le redemandant tous les `pas`, `max` au
/// plus ; rend s'il est venu. Asynchrone : l'attente ne bloque pas le fil de tokio.
async fn attendre_reseau(
    mut reseau_la: impl FnMut() -> bool,
    pas: std::time::Duration,
    max: std::time::Duration,
) -> bool {
    let fin = tokio::time::Instant::now() + max;
    loop {
        if reseau_la() {
            return true;
        }
        let reste = fin.saturating_duration_since(tokio::time::Instant::now());
        if reste.is_zero() {
            return false;
        }
        tokio::time::sleep(pas.min(reste)).await;
    }
}

pub async fn surveiller() {
    // Les exemples du guide se renouvellent pendant la passe (au plus une fois par semaine), sans la retarder.
    let exemples = std::thread::spawn(crate::guide::renouveler_exemples);
    passe().await;
    let _ = exemples.join();
    crate::autotest::attendre_hebdomadaire();
}

async fn passe() {
    // Coupée : rien ne se regarde ni ne se notifie, et la dernière passe notée reste la dernière vraie. Échue : la
    // protection est remise, et la passe se fait.
    if crate::protection::temps_reel::a_la_passe() {
        return;
    }
    tableau::noter_passe();
    let machine = veiller_machine();
    // L'autotest de la semaine (au plus une fois tous les 7 jours) reprend le bilan de cette passe, sans le relancer,
    // dans un fil à part : la passe ne l'attend qu'à la fin.
    crate::autotest::hebdomadaire_en_fond(&machine.constats);
    if let Some(fichiers) = crate::protection::integrite::changements_a_signaler() {
        alerter(
            Genre::Fichiers,
            tr!(
                "Vanguard : fichiers critiques modifiés",
                "Vanguard: critical files changed"
            ),
            &fichiers,
        );
    }
    for (titre, texte) in crate::protection::telechargement::nouveaux_a_signaler() {
        alerter(Genre::Telechargement, &titre, &texte);
    }
    for (cle, titre, texte) in crate::protection::sortantes::botnets_a_signaler() {
        alerter_cle(Genre::Botnet, &cle, &titre, &texte);
    }
    for (cle, titre, texte) in crate::protection::sortantes::sites_dangereux_a_signaler() {
        alerter_cle(Genre::Telechargement, &cle, &titre, &texte);
    }
    // Les extensions sans restrictions qui l'ont demandé (dans_la_surveillance) : leurs problèmes graves seulement.
    for (titre, texte) in crate::plugins::a_signaler() {
        notifier(&titre, &texte);
    }
    // La protection active, si elle a été activée : le certain bloqué tout seul, chaque blocage notifié.
    crate::protection::blocage::en_surveillance();
    // La passe est déjà notée (début) et les contrôles de la machine faits : un scan du réseau qui ne peut pas se
    // faire est noté à part, non vérifié, pour que le tableau ne montre pas une passe saine.
    if !attendre_reseau(|| reseau::scan::passerelle().is_some(), PAS_RESEAU, ATTENTE_RESEAU).await {
        tableau::noter_reseau(Some(tr!(
            "pas de réseau : aucune passerelle une minute après le début du scan (Wi-Fi coupé, câble débranché, ou réveil sans réseau)",
            "no network: no gateway a minute after the scan started (Wi-Fi off, cable unplugged, or wake-up without network)"
        )));
        return;
    }
    let r = match reseau::executer(Options {
        silencieux: true,
        ..Options::defaut(None, "courants")
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tableau::noter_reseau(Some(&e));
            return;
        }
    };
    tableau::noter_reseau(None);
    veiller_passerelle(&r);
    veiller_audit(
        &r,
        machine
            .constats
            .into_iter()
            .filter(|c| crate::audit::regle_du_reseau(c.regle))
            .collect(),
    )
    .await;
    // Empoisonneur de noms (Responder…) : la sonde est déjà faite pendant le scan du réseau local, elle ne coûte
    // rien de plus ici. Sans réseau local (VPN seul), le scan n'aurait pas tourné : rien à signaler.
    if let Some(reseau::empoisonnement::Rapport::Teste(empoisonneurs)) = &r.empoisonnement {
        for e in empoisonneurs {
            let titre = r
                .hotes
                .iter()
                .find(|h| h.ip == e.ip)
                .map(reseau::Hote::titre)
                .filter(|t| !t.is_empty());
            alerter(
                Genre::Empoisonneur,
                tr!(
                    "Vanguard : empoisonneur de noms sur le réseau",
                    "Vanguard: name poisoner on the network"
                ),
                &trf!(
                    "{} répond à des noms qui n'existent pas : un outil comme Responder vole les mots de passe Windows. Débranchez-le.",
                    "{} answers names that do not exist: a tool like Responder steals Windows passwords. Unplug it.",
                    titre.map_or_else(|| e.ip.to_string(), |t| format!("{} ({t})", e.ip))
                ),
            );
        }
    }
    for h in r.hotes.iter().filter(|h| h.nouvelle) {
        let qui = if h.titre().is_empty() {
            tr!("appareil inconnu", "unknown device").into()
        } else {
            h.titre()
        };
        // L'appareil se reconnaît à son adresse MAC (son adresse IP change d'un bail à l'autre).
        let cle = format!(
            "appareil|{}",
            h.mac.as_deref().map_or_else(|| h.ip.to_string(), str::to_lowercase)
        );
        alerter_cle(
            Genre::Appareil,
            &cle,
            tr!("Nouvel appareil sur votre réseau", "New device on your network"),
            &format!("{} — {qui} {}", h.ip, h.mac.as_deref().unwrap_or("")),
        );
    }
    for h in r.hotes.iter().filter(|h| !h.nouvelle) {
        for p in h.ports.iter().filter(|p| p.nouveau && p.niveau >= Niveau::Eleve) {
            let cle = format!(
                "port|{}:{}",
                h.mac.as_deref().map_or_else(|| h.ip.to_string(), str::to_lowercase),
                p.port
            );
            alerter_cle(
                Genre::Port,
                &cle,
                &trf!("Port {} nouvellement ouvert", "Port {} newly opened", p.port),
                &format!("{} ({}) : {} — {}", h.ip, h.titre(), p.service, p.conseil),
            );
        }
    }
}

/// Le choix de la personne, noté quand la surveillance est activée (ou vue active) : si la minuterie ou la tâche
/// disparaît ensuite sans qu'elle l'ait coupée, le bilan le dit.
/// Le choix noté de la surveillance, dans le dossier de données : c'est lui qui fait dire au bilan qu'une surveillance
/// voulue a disparu.
pub(crate) const VOULUE: &str = "surveillance-voulue";

fn fichier_voulue() -> std::path::PathBuf {
    crate::socle::dossier_local().join(VOULUE)
}

fn marquer(oui: bool) {
    let fichier = fichier_voulue();
    if oui {
        if let Some(parent) = fichier.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(fichier, b"");
    } else {
        let _ = std::fs::remove_file(fichier);
    }
}

/// La personne allume ou coupe la surveillance par Vanguard : la marque, et l'état scellé des défenses voulues (avec le
/// geste au journal), seul à pouvoir dire ensuite qu'elle a été coupée normalement.
fn noter_voulue(oui: bool) {
    marquer(oui);
    crate::voulues::noter(crate::voulues::Defense::Surveillance, oui);
}

/// Vue en place : la marque refaite, et notée voulue si rien ne l'était (posée par une version d'avant), sans geste
/// au journal.
fn vue_en_place() {
    marquer(true);
    crate::voulues::adopter(crate::voulues::Defense::Surveillance);
}

pub fn active() -> bool {
    let active = installee();
    if active {
        vue_en_place();
    }
    active
}

/// La minuterie, la tâche planifiée (non désactivée) ou l'agent existent-ils ?
fn installee() -> bool {
    #[cfg(target_os = "linux")]
    return minuterie_activee(&format!("{NOM}.timer"));
    #[cfg(windows)]
    return tache_active(TACHE_WINDOWS);
    #[cfg(target_os = "macos")]
    return reussit("launchctl", &["print", &format!("{}/{AGENT_MACOS}", domaine_launchd())]);
}

/// Au bilan : la surveillance voulue a disparu (minuterie ou tâche retirée, ou désactivée), ou elle est là mais le
/// programme qu'elle lance n'existe plus, ou elle a été posée par une version d'avant. Constat et proposition, rien de
/// plus : Vanguard ne s'accroche pas, et une tâche acceptée n'est jamais changée en silence.
///
/// Voulue ou non, c'est l'état scellé des défenses voulues qui le dit (`voulues`) : la marque effacée avec la tâche
/// ne fait plus passer une surveillance coupée par un autre programme pour coupée par la personne.
pub fn constat() -> Option<crate::machine::Constat> {
    use crate::voulues::{Defense, Souvenir, Verdict};
    let marque = fichier_voulue().is_file();
    let souvenir = crate::voulues::souvenir(Defense::Surveillance);
    // Jamais voulue ou arrêtée par Vanguard, sans marque : rien à dire, sans interroger le planificateur (sous
    // Windows, PowerShell en secours peut prendre des secondes).
    if !marque && matches!(souvenir, Souvenir::Jamais | Souvenir::Arretee(_)) {
        return None;
    }
    let installee = installee();
    match crate::voulues::juger(marque, installee, &souvenir) {
        Verdict::PasVoulue(_) => None,
        Verdict::CoupeeHors(depuis) => Some(juger_coupee_hors(&depuis)),
        Verdict::NonVerifiee(doute) => Some(juger_sans_souvenir(doute)),
        Verdict::Voulue if !installee => juger_disparition(true, false),
        Verdict::Voulue => {
            if !marque || souvenir == Souvenir::Jamais {
                vue_en_place();
            }
            juger_planifie(
                Planifie::Surveillance,
                &lire_planifie(Planifie::Surveillance),
                reseau::cle_usb().as_deref(),
                Path::exists,
            )
        }
    }
}

/// Marque et tâche disparues alors que Vanguard a noté la surveillance voulue, sans arrêt noté depuis : coupée par un
/// autre programme, au même niveau qu'une disparition.
fn juger_coupee_hors(depuis: &str) -> crate::machine::Constat {
    crate::machine::alerte(
        "Surveillance",
        Niveau::Eleve,
        trf!(
            "La surveillance horaire que vous aviez activée (le {depuis}) a été coupée sans passer par Vanguard : sa minuterie ou sa tâche planifiée a disparu avec la note de votre choix, et Vanguard n'a noté aucun arrêt. Un logiciel malveillant coupe d'abord ce qui le surveille.",
            "The hourly monitoring you had turned on (on {depuis}) was cut without going through Vanguard: its timer or scheduled task disappeared along with the note of your choice, and Vanguard noted no stop. Malware first cuts what watches it."
        ),
    )
    .manuel(
        tr!(
            "La remettre : « vanguard surveillance on » ; si c'est vous qui l'avez coupée, « vanguard surveillance off » pour que Vanguard le note",
            "Turn it back on: “vanguard monitor on”; if you turned it off yourself, “vanguard monitor off” so Vanguard notes it"
        ),
        &[],
    )
}

/// Ni marque ni tâche, et l'état des défenses voulues ne peut pas être cru : rien ne dit que la personne l'a coupée.
/// Jamais « coupée, comme par défaut ».
fn juger_sans_souvenir(doute: crate::voulues::Doute) -> crate::machine::Constat {
    crate::machine::impossible(
        "Surveillance",
        &trf!(
            "surveillance horaire absente, et l'état des défenses voulues ({}) {} : rien ne dit que c'est vous qui l'avez coupée",
            "hourly monitoring absent, and the state of wanted defenses ({}) {}: nothing tells that you turned it off",
            crate::voulues::FICHIER,
            doute.texte()
        ),
    )
    .manuel(
        tr!(
            "« vanguard surveillance on » la remet ; « vanguard surveillance off » note que vous n'en voulez pas",
            "“vanguard monitor on” turns it back on; “vanguard monitor off” notes that you do not want it"
        ),
        &[],
    )
}

/// `juger_tache`, et le programme lancé comparé à celui que Vanguard a posé (`programmes_poses`) : un autre programme
/// à la même place passe avant ce que la tâche dit d'elle-même (une version d'avant, par exemple). Seulement quand il
/// existe : son absence se dit déjà.
pub(crate) fn juger_planifie(
    quoi: Planifie,
    l: &Lecture,
    cle: Option<&Path>,
    existe: impl Fn(&Path) -> bool,
) -> Option<Constat> {
    let identite = match l {
        Lecture::Lue { programme, .. } if programme.is_absolute() && existe(programme) => {
            crate::programmes_poses::constat(quoi.tache(), programme)
        }
        _ => None,
    };
    identite.or_else(|| juger_tache(quoi, l, cle, existe))
}

fn juger_disparition(voulue: bool, installee: bool) -> Option<crate::machine::Constat> {
    (voulue && !installee).then(|| {
        crate::machine::alerte(
            "Surveillance",
            Niveau::Eleve,
            tr!(
                "La surveillance horaire que vous aviez activée n'existe plus : sa minuterie ou sa tâche planifiée a été retirée ou désactivée. Une mise à jour du système peut l'avoir fait ; un logiciel malveillant aussi, qui coupe d'abord ce qui le surveille.",
                "The hourly monitoring you had turned on no longer exists: its timer or scheduled task was removed or disabled. A system update may have done it; so may malware, which first cuts what watches it."
            ),
        )
        .manuel(
            tr!(
                "La remettre : menu « Réseau et Internet » › Surveillance, ou « vanguard surveillance on » ; si c'est vous qui l'avez coupée, « vanguard surveillance off » pour que Vanguard l'oublie",
                "Turn it back on: menu “Network and Internet” › Monitoring, or “vanguard monitor on”; if you turned it off yourself, “vanguard monitor off” so Vanguard forgets it"
            ),
            &[],
        )
    })
}

/// Ce que Vanguard planifie : la surveillance horaire ou l'entretien du mois.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Planifie {
    Surveillance,
    Entretien,
}

impl Planifie {
    /// (unités systemd, agent launchd, tâche du Planificateur).
    pub(crate) fn noms(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Planifie::Surveillance => (NOM, AGENT_MACOS, TACHE_WINDOWS),
            Planifie::Entretien => (
                crate::entretien::NOM,
                crate::entretien::AGENT_MACOS,
                crate::entretien::TACHE_WINDOWS,
            ),
        }
    }

    /// Son nom dans la liste des programmes posés.
    pub(crate) fn tache(self) -> crate::programmes_poses::Tache {
        match self {
            Planifie::Surveillance => crate::programmes_poses::Tache::Surveillance,
            Planifie::Entretien => crate::programmes_poses::Tache::Entretien,
        }
    }

    /// Son nom dans une phrase : les deux tâches partagent la catégorie « Surveillance », et un « non vérifié » doit
    /// dire laquelle n'a pas pu être lue.
    fn dans_une_phrase(self) -> &'static str {
        match self {
            Planifie::Surveillance => tr!("la surveillance horaire", "the hourly monitoring"),
            Planifie::Entretien => tr!("l'entretien du mois", "the monthly check-up"),
        }
    }
}

/// Ce que le planificateur du système dit d'une tâche de Vanguard : absente, le programme qu'elle lance (et si elle
/// a les réglages d'aujourd'hui), ou illisible. `a_jour` porte sa propre erreur : une minuterie illisible n'empêche
/// pas de juger le programme lu (disparu, sur un lecteur débranché), seule la question « version d'avant » reste
/// alors sans réponse.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lecture {
    Absente,
    Lue {
        programme: PathBuf,
        a_jour: Result<bool, String>,
    },
    Illisible(String),
}

/// Lit la tâche planifiée `quoi` de cet ordinateur : le programme qu'elle lance. Linux : la ligne ExecStart= du
/// service, et, pour la surveillance, sa minuterie relue telle que posée (`minuterie_d_avant`) ; celle de l'entretien
/// n'a jamais changé. macOS : le plist de l'agent, et son RunAtLoad ; Windows : le planificateur lui-même, PowerShell
/// en secours, et son réglage de rattrapage.
pub(crate) fn lire_planifie(quoi: Planifie) -> Lecture {
    let (nom, agent, tache) = quoi.noms();
    #[cfg(target_os = "linux")]
    {
        let _ = (agent, tache);
        lire_unites(&dossier_unites_maison(), nom, quoi == Planifie::Surveillance)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (nom, tache);
        match std::fs::read(plist_agent_nomme(agent)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Lecture::Absente,
            Err(e) => Lecture::Illisible(e.to_string()),
            Ok(o) => lire_plist(&o).map_or_else(
                || Lecture::Illisible(tr!("plist illisible", "unreadable plist").to_string()),
                |(programme, au_lancement)| Lecture::Lue {
                    programme,
                    a_jour: Ok(au_lancement),
                },
            ),
        }
    }
    #[cfg(windows)]
    {
        let _ = (nom, agent);
        match definitions_windows(&[tache]) {
            None => Lecture::Illisible(tr!("planificateur non lu", "task scheduler not read").to_string()),
            Some(lues) => {
                lues.into_iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(tache))
                    .map_or(Lecture::Absente, |(_, d)| Lecture::Lue {
                        programme: PathBuf::from(d.programme.trim().trim_matches('"')),
                        a_jour: Ok(a_jour_windows(&d)),
                    })
            }
        }
    }
}

/// Les unités `nom` posées dans `dossier` : le programme du service, et, si `juger_minuterie`, si la minuterie est
/// d'aujourd'hui. Une minuterie absente ne se dit pas d'avant (sa disparition se juge à part, `juger_disparition`) ;
/// illisible, son âge n'est pas conclu (non vérifié, jamais compté comme à jour), mais le programme lu reste jugé.
#[cfg(any(target_os = "linux", all(unix, test)))]
fn lire_unites(dossier: &Path, nom: &str, juger_minuterie: bool) -> Lecture {
    let lire = |ext: &str| std::fs::read_to_string(dossier.join(format!("{nom}.{ext}")));
    let programme = match lire("service") {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Lecture::Absente,
        Err(e) => return Lecture::Illisible(e.to_string()),
        Ok(t) => match programme_d_une_unite(&t) {
            Some(p) => p,
            None => {
                return Lecture::Illisible(tr!("ligne ExecStart= illisible", "unreadable ExecStart= line").to_string());
            }
        },
    };
    let a_jour = if juger_minuterie {
        match lire("timer") {
            Ok(t) => Ok(!minuterie_d_avant(&t)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e.to_string()),
        }
    } else {
        Ok(true)
    };
    Lecture::Lue { programme, a_jour }
}

/// Une tâche de Windows est-elle d'aujourd'hui ? Jugé sur « dès que possible » seul : les tâches d'avant ne l'ont
/// jamais eu, celles d'aujourd'hui toujours, même quand Windows refuse le déclencheur d'ouverture de session (la tâche
/// est alors posée sans lui, et ce n'est pas une version d'avant : la refaire retomberait sur le même refus).
#[cfg(any(windows, test))]
fn a_jour_windows(d: &Definition) -> bool {
    d.des_que_possible
}

/// Le programme absent est-il sur un lecteur débranché, ou sur la clé branchée à une autre place ? La tâche lance
/// alors le programme de la clé, ce qui n'est ni un dossier effacé ni un logiciel malveillant : la raison est autre.
/// `cle` : la clé VANGUARD branchée ; `existe` : ce qui existe sur cet ordinateur.
fn sur_un_lecteur_absent(programme: &Path, cle: Option<&Path>, existe: &impl Fn(&Path) -> bool) -> bool {
    if let Some(cle) = cle
        && !sous(programme, cle)
    {
        // La clé à une autre lettre (Windows) ou montée ailleurs : le même programme, sous la clé d'aujourd'hui.
        let reste: PathBuf = programme
            .components()
            .skip_while(|c| matches!(c, std::path::Component::Prefix(_) | std::path::Component::RootDir))
            .collect();
        if !reste.as_os_str().is_empty() && existe(&cle.join(&reste)) {
            return true;
        }
        if let Some(etiquette) = cle.file_name() {
            for a in programme.ancestors().skip(1) {
                if a.file_name() == Some(etiquette)
                    && let Ok(r) = programme.strip_prefix(a)
                    && existe(&cle.join(r))
                {
                    return true;
                }
            }
        }
    }
    // Le plus proche dossier qui existe encore : aucun (une lettre de lecteur qui n'existe plus), ou l'endroit où se
    // montent les lecteurs amovibles.
    let Some(present) = programme
        .ancestors()
        .skip(1)
        .find(|a| !a.as_os_str().is_empty() && existe(a))
    else {
        return programme
            .components()
            .next()
            .is_some_and(|c| matches!(c, std::path::Component::Prefix(_)));
    };
    let montage = |a: &Path| {
        ["/media", "/run/media", "/Volumes", "/mnt"]
            .iter()
            .any(|m| a == Path::new(m))
    };
    montage(present) || present.parent().is_some_and(montage)
}

/// Le constat d'une tâche planifiée lue : rien si elle est absente (la disparition se juge à part) ou si tout va bien ;
/// une alerte si le programme qu'elle lance n'existe plus (`existe`) : la tâche est là, mais elle ne tourne plus, ou
/// seulement quand la clé (`cle`) est branchée à la même place ; une information si la surveillance a été posée par
/// une version d'avant ; « non vérifié » si le programme n'a pas pu être lu, ou, programme présent, si la minuterie ne
/// l'a pas été (l'alerte d'un programme disparu passe avant : elle ne dépend pas de la minuterie).
pub(crate) fn juger_tache(
    quoi: Planifie,
    l: &Lecture,
    cle: Option<&Path>,
    existe: impl Fn(&Path) -> bool,
) -> Option<Constat> {
    let tache = quoi.dans_une_phrase();
    let (programme, a_jour) = match l {
        Lecture::Absente => return None,
        Lecture::Illisible(e) => {
            return Some(crate::machine::impossible(
                "Surveillance",
                &trf!(
                    "programme lancé par {tache} non lu : {e}",
                    "program started by {tache} not read: {e}"
                ),
            ));
        }
        Lecture::Lue { programme, a_jour } => (programme, a_jour),
    };
    // Un nom sans chemin (« vanguard », quand le programme n'a pas pu se situer) se cherche dans le PATH au lancement :
    // d'ici, rien ne le confirme, et rien ne le dément.
    if !programme.is_absolute() {
        return Some(crate::machine::impossible(
            "Surveillance",
            &trf!(
                "programme lancé par {tache} sans chemin : {}",
                "program started by {tache} without a path: {}",
                programme.display()
            ),
        ));
    }
    let chemin = chemin_affichable(programme);
    if !existe(programme) && sur_un_lecteur_absent(programme, cle, &existe) {
        let (niveau, remettre) = match quoi {
            Planifie::Surveillance => (
                Niveau::Moyen,
                tr!(
                    "La refaire depuis la clé : « vanguard surveillance on » (Vanguard est recopié sur cet ordinateur et la tâche refaite)",
                    "Redo it from the key: “vanguard monitor on” (Vanguard is copied onto this computer and the task redone)"
                ),
            ),
            Planifie::Entretien => (
                Niveau::Info,
                tr!(
                    "Le refaire depuis la clé : « vanguard entretien on » (Vanguard est recopié sur cet ordinateur)",
                    "Redo it from the key: “vanguard maintenance on” (Vanguard is copied onto this computer)"
                ),
            ),
        };
        return Some(
            crate::machine::alerte(
                "Surveillance",
                niveau,
                trf!(
                    "Le programme que lance {tache} est sur un lecteur débranché ou qui a changé de place ({chemin}) : sans lui, la tâche ne tourne pas. Posée depuis la clé, elle aurait dû lancer une copie sur cet ordinateur.",
                    "The program {tache} starts is on a drive that is unplugged or has moved ({chemin}): without it, it does not run. Set up from the key, the task should have started a copy on this computer."
                ),
            )
            .manuel(remettre, &[]),
        );
    }
    if !existe(programme) {
        return Some(match quoi {
            Planifie::Surveillance => crate::machine::alerte(
                "Surveillance",
                Niveau::Eleve,
                trf!(
                    "La surveillance horaire est planifiée, mais le programme qu'elle lance n'existe plus ({chemin}) : elle ne tourne plus. Un dossier effacé, un antivirus, ou un logiciel malveillant qui coupe d'abord ce qui le surveille, peuvent l'avoir retiré.",
                    "The hourly monitoring is scheduled, but the program it starts no longer exists ({chemin}): it no longer runs. A deleted folder, an antivirus, or malware that first cuts what watches it may have removed it."
                ),
            )
            .manuel(
                tr!(
                    "La remettre : « vanguard surveillance on » (Vanguard est recopié sur cet ordinateur et la tâche refaite) ; si vous n'en voulez plus, « vanguard surveillance off »",
                    "Turn it back on: “vanguard monitor on” (Vanguard is copied onto this computer again and the task redone); if you no longer want it, “vanguard monitor off”"
                ),
                &[],
            ),
            Planifie::Entretien => crate::machine::alerte(
                "Surveillance",
                Niveau::Moyen,
                trf!(
                    "L'entretien du mois est planifié, mais le programme qu'il lance n'existe plus ({chemin}) : il ne tourne plus.",
                    "The monthly check-up is scheduled, but the program it starts no longer exists ({chemin}): it no longer runs."
                ),
            )
            .manuel(
                tr!(
                    "Le remettre : « vanguard entretien on » ; si vous n'en voulez plus, « vanguard entretien off »",
                    "Turn it back on: “vanguard maintenance on”; if you no longer want it, “vanguard maintenance off”"
                ),
                &[],
            ),
        });
    }
    // L'entretien a déjà son rattrapage (-StartWhenAvailable) ; et pas de RunAtLoad pour lui : il notifierait à
    // chaque ouverture de session.
    if quoi == Planifie::Entretien {
        return None;
    }
    match a_jour {
        Ok(true) => return None,
        Ok(false) => {}
        Err(e) => {
            return Some(crate::machine::impossible(
                "Surveillance",
                &trf!(
                    "minuterie de {tache} non lue, rien ne dit si elle vient d'une version d'avant : {e}",
                    "timer of {tache} not read, nothing tells whether it comes from an earlier version: {e}"
                ),
            ));
        }
    }
    let message = if cfg!(target_os = "linux") {
        // La minuterie d'avant passe déjà après un arrêt et à l'ouverture de session (OnBootSec échu) : seule la veille
        // lui manque.
        tr!(
            "La surveillance horaire a été planifiée par une version d'avant : elle ne rattrape pas une heure manquée pendant une veille, la passe suivante attend la fin de l'heure entamée au réveil.",
            "The hourly monitoring was scheduled by an earlier version: it does not catch up an hour missed during sleep; the next run waits for the rest of the hour after wake-up."
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "La surveillance horaire a été planifiée par une version d'avant : elle ne passe pas à l'ouverture de session, la première passe attend une heure.",
            "The hourly monitoring was scheduled by an earlier version: it does not run at sign-in; the first run waits an hour."
        )
    } else {
        tr!(
            "La surveillance horaire a été planifiée par une version d'avant : elle ne rattrape pas une heure manquée (ordinateur éteint ou en veille) et ne passe pas à l'ouverture de session.",
            "The hourly monitoring was scheduled by an earlier version: it does not catch up a missed hour (computer off or asleep) and does not run at sign-in."
        )
    };
    Some(
        crate::machine::alerte("Surveillance", Niveau::Info, message).manuel(
            tr!(
                "La mettre à jour, si vous voulez : « vanguard surveillance on » refait la tâche avec ces réglages ; rien d'autre ne change",
                "Update it if you want: “vanguard monitor on” redoes the task with these settings; nothing else changes"
            ),
            &[],
        ),
    )
}

/// Reprise d'une surveillance active sous l'ancien nom (`passage`) : la minuterie recréée avec ses réglages d'alors
/// (acceptés tels quels), le choix noté.
pub(crate) fn reprendre(exe: &str) -> bool {
    let ok = installer(exe, Reglages::DAvant);
    if ok {
        noter_voulue(true);
        crate::programmes_poses::noter(crate::programmes_poses::Tache::Surveillance, Path::new(exe));
    }
    ok
}

/// Les réglages d'une tâche de surveillance : ceux d'aujourd'hui (une heure manquée rattrapée, une passe à
/// l'ouverture de session), ou ceux d'une version d'avant, pour une tâche déjà acceptée qu'on reprend sans la changer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Reglages {
    Aujourdhui,
    DAvant,
}

pub fn activer(oui: bool) {
    // Une tâche d'une version d'avant que la personne réactive : elle est refaite avec les réglages d'aujourd'hui, et
    // c'est dit.
    let d_avant = oui
        && matches!(
            lire_planifie(Planifie::Surveillance),
            Lecture::Lue { a_jour: Ok(false), .. }
        );
    // Sous Linux, la minuterie qui la remplace est montrée avant d'être posée : c'est elle que la personne accepte en
    // demandant la remise à jour.
    #[cfg(target_os = "linux")]
    if d_avant {
        trp!(
            "  La minuterie d'une version d'avant est refaite ainsi :",
            "  The timer from an earlier version is redone as follows:"
        );
        // Les réglages de la minuterie ne dépendent pas du programme lancé : pas besoin de le situer deux fois.
        let (_, minuterie) = unites_systemd("", Reglages::Aujourdhui);
        for l in minuterie.lines().filter(|l| l.starts_with("On")) {
            println!("    {GRIS}{l}{RESET}");
        }
        trp!(
            "  {GRIS}(toutes les heures pile, rattrapée au réveil, 5 min après l'ouverture){RESET}",
            "  {GRIS}(every hour on the hour, caught up on wake-up, 5 min after sign-in){RESET}"
        );
    }
    let retrait = if oui { Ok(()) } else { desinstaller() };
    let reussi = if oui {
        executable().is_some_and(|exe| {
            let ok = installer(&exe, Reglages::Aujourdhui);
            if ok {
                crate::programmes_poses::noter(crate::programmes_poses::Tache::Surveillance, Path::new(&exe));
            }
            ok
        })
    } else {
        retrait.is_ok()
    };
    if !oui || reussi {
        noter_voulue(oui);
    }
    // Un retrait raté laisse la tâche : son programme reste noté, et jugé.
    if !oui && reussi {
        crate::programmes_poses::oublier(crate::programmes_poses::Tache::Surveillance);
    }
    match (oui, reussi) {
        (true, true) => {
            trp!(
                "  {VERT}✔{RESET} Surveillance activée : scan toutes les heures, notification si un appareil inconnu arrive.",
                "  {VERT}✔{RESET} Monitoring on: scan every hour, notification if an unknown device shows up."
            );
            if d_avant {
                trp!(
                    "  La tâche d'une version d'avant est remplacée par celle d'aujourd'hui.",
                    "  The task from an earlier version is replaced with today's."
                );
            }
            // Coupée, chaque passe s'arrête au début (`passe`) : « toutes les heures » ne vaut qu'à la reprise.
            crate::protection::temps_reel::dire_si_coupee(crate::protection::temps_reel::Ou::Surveillance);
        }
        (true, false) => trp!(
            "  ✖ Impossible d'activer la surveillance.",
            "  ✖ Could not turn monitoring on."
        ),
        (false, true) => trp!("  Surveillance désactivée.", "  Monitoring off."),
        (false, false) => afficher_aligne(
            "  ✖ ",
            &trf!(
                "Surveillance désactivée, mais pas entièrement retirée : {}",
                "Monitoring off, but not fully removed: {}",
                retrait.err().unwrap_or_default()
            ),
            4,
            "",
        ),
    }
}

/// Retire la surveillance sans rien demander (la désinstallation l'a déjà montrée et fait accepter), et l'oublie.
/// `trouves` : ses fichiers, là où la désinstallation les a trouvés. Rend la raison d'un échec, jamais un succès
/// supposé.
pub(crate) fn retirer(trouves: &[PathBuf]) -> Result<(), String> {
    let r = retirer_planifie(Planifie::Surveillance, trouves);
    noter_voulue(false);
    if r.is_ok() {
        crate::programmes_poses::oublier(crate::programmes_poses::Tache::Surveillance);
    }
    r
}

fn desinstaller() -> Result<(), String> {
    retirer_planifie(Planifie::Surveillance, &[])
}

/// Retire la tâche `quoi` : arrêtée (la minuterie et une passe déjà lancée, qui écrirait encore dans le dossier de
/// données qu'une désinstallation efface), ses fichiers retirés là où Vanguard les pose et là où ils ont été trouvés
/// (`trouves`), le planificateur rechargé, puis relus : un fichier encore là est un échec, avec son chemin. Rend la
/// raison d'un échec, jamais un succès supposé.
pub(crate) fn retirer_planifie(quoi: Planifie, trouves: &[PathBuf]) -> Result<(), String> {
    let (nom, agent, tache) = quoi.noms();
    #[cfg(target_os = "linux")]
    {
        let _ = (agent, tache);
        let dossier = dossier_unites_maison();
        let mut fichiers = vec![
            dossier.join(format!("{nom}.timer")),
            dossier.join(format!("{nom}.service")),
        ];
        for f in trouves {
            if !fichiers.contains(f) {
                fichiers.push(f.clone());
            }
        }
        let present = |ext: &str| {
            fichiers
                .iter()
                .any(|f| f.extension().is_some_and(|e| e == ext) && std::fs::symlink_metadata(f).is_ok())
        };
        // Le fichier d'horodatage d'une minuterie Persistent=true (celle d'avant de la surveillance, celle de
        // l'entretien) : à part des unités, car son nom finit aussi par « .timer » et ne dit pas qu'une unité est posée.
        let horodatages = dossier_horodatages_maison();
        // Rien de posé : rien à arrêter ni à recharger, et pas d'échec à dire (un bus de session absent, comme dans
        // une session sans bureau, ferait échouer systemctl pour rien). Un horodatage resté d'un retrait d'avant part
        // quand même.
        if !present("timer") && !present("service") {
            let echecs = retirer_horodatage(horodatages.as_deref(), nom);
            if !echecs.is_empty() {
                return Err(trf!("non retiré : {}", "not removed: {}", echecs.join(", ")));
            }
            return Ok(());
        }
        // Sans son fichier, systemctl dirait « unité inconnue » : une unité absente n'est pas à arrêter.
        let arretee = !present("timer")
            || crate::machine::linux::dbus::actions::utilisateur(
                crate::machine::linux::dbus::actions::Geste::Desactiver { maintenant: true },
                &format!("{nom}.timer"),
            );
        let passe = !present("service")
            || crate::machine::linux::dbus::actions::utilisateur(
                crate::machine::linux::dbus::actions::Geste::Arreter,
                &format!("{nom}.service"),
            );
        let mut echecs = retirer_fichiers(&fichiers);
        let recharge = crate::machine::linux::dbus::actions::utilisateur(
            crate::machine::linux::dbus::actions::Geste::Recharger,
            "",
        );
        echecs.extend(encore_la(&fichiers));
        // Après l'arrêt de la minuterie : en marche, elle le recréerait à sa passe suivante.
        echecs.extend(retirer_horodatage(horodatages.as_deref(), nom));
        if !echecs.is_empty() {
            return Err(trf!("non retiré : {}", "not removed: {}", echecs.join(", ")));
        }
        if !(arretee && passe && recharge) {
            return Err(tr!(
                "fichiers retirés (vérifié), mais systemctl --user n'a pas répondu : la minuterie, ou une passe en cours, peut rester chargée jusqu'à la prochaine ouverture de session, où elle disparaît",
                "files removed (checked), but systemctl --user did not answer: the timer, or a run in progress, may stay loaded until the next sign-in, where it goes away"
            )
            .to_string());
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (nom, tache);
        let mut fichiers = vec![plist_agent_nomme(agent)];
        for f in trouves {
            if !fichiers.contains(f) {
                fichiers.push(f.clone());
            }
        }
        // bootout échoue aussi pour un agent déjà déchargé : son résultat ne dit rien, l'état relu ensuite si.
        for f in &fichiers {
            let _ = reussit("launchctl", &["bootout", &domaine_launchd(), &f.display().to_string()]);
        }
        let mut echecs = retirer_fichiers(&fichiers);
        echecs.extend(encore_la(&fichiers));
        if !echecs.is_empty() {
            return Err(trf!("non retiré : {}", "not removed: {}", echecs.join(", ")));
        }
        if reussit("launchctl", &["print", &format!("{}/{agent}", domaine_launchd())]) {
            return Err(tr!(
                "fichier retiré (vérifié), mais l'agent reste chargé jusqu'à la prochaine ouverture de session",
                "file removed (checked), but the agent stays loaded until the next sign-in"
            )
            .to_string());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = (nom, agent, trouves);
        // Le planificateur dit qu'elle n'existe pas : rien à retirer, et Unregister-ScheduledTask échouerait pour rien.
        // Illisible, on essaie quand même : son échec sera dit.
        if crate::machine::windows::planificateur::etat(&[tache])
            == Some(crate::machine::windows::planificateur::EtatTache::Absente)
        {
            return Ok(());
        }
        let t = crate::commande::ps_texte(tache);
        // Arrêtée d'abord : une passe en cours n'écrit plus dans le dossier de données qu'une désinstallation efface.
        crate::machine::windows::ps(&format!(
            "Stop-ScheduledTask -TaskName '{t}' -ErrorAction SilentlyContinue; \
             Unregister-ScheduledTask -TaskName '{t}' -Confirm:$false"
        ))
        .map(|_| ())
        .ok_or_else(|| {
            trf!(
                "PowerShell n'a pas pu retirer la tâche : « {} » pour réessayer",
                "PowerShell could not remove the task: “{}” to try again",
                match quoi {
                    Planifie::Surveillance => tr!("vanguard surveillance off", "vanguard monitor off"),
                    Planifie::Entretien => tr!("vanguard entretien off", "vanguard maintenance off"),
                }
            )
        })
    }
}

/// Retire ces fichiers ; rend ceux qui n'ont pas pu partir, avec la raison (un fichier déjà absent n'en est pas un).
#[cfg(unix)]
pub(crate) fn retirer_fichiers(fichiers: &[PathBuf]) -> Vec<String> {
    fichiers
        .iter()
        .filter_map(|f| match std::fs::remove_file(f) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Some(format!("{} ({e})", chemin_affichable(f))),
            _ => None,
        })
        .collect()
}

/// Ceux de ces fichiers qui existent encore, relus après le retrait : un retrait se constate, il ne se suppose pas.
#[cfg(unix)]
pub(crate) fn encore_la(fichiers: &[PathBuf]) -> Vec<String> {
    fichiers
        .iter()
        .filter(|f| std::fs::symlink_metadata(f).is_ok())
        .map(|f| trf!("{} (encore là)", "{} (still there)", chemin_affichable(f)))
        .collect()
}

/// Le dossier des unités systemd de l'utilisateur où Vanguard pose la surveillance et l'entretien.
#[cfg(target_os = "linux")]
pub(crate) fn dossier_unites_maison() -> PathBuf {
    crate::socle::maison().join(".config/systemd/user")
}

/// Le dossier où le gestionnaire systemd de l'utilisateur tient les fichiers d'horodatage des minuteries
/// Persistent=true : `$XDG_DATA_HOME/systemd/timers`, sinon `~/.local/share/systemd/timers`. `None` s'il serait
/// relatif (HOME vide, XDG_DATA_HOME relatif) : un retrait viserait alors le dossier courant.
#[cfg(target_os = "linux")]
fn dossier_horodatages(donnees: Option<std::ffi::OsString>, maison: &Path) -> Option<PathBuf> {
    let dossier = donnees
        .filter(|d| !d.is_empty())
        .map_or_else(|| maison.join(".local/share"), PathBuf::from)
        .join("systemd/timers");
    dossier.is_absolute().then_some(dossier)
}

#[cfg(target_os = "linux")]
pub(crate) fn dossier_horodatages_maison() -> Option<PathBuf> {
    dossier_horodatages(std::env::var_os("XDG_DATA_HOME"), &crate::socle::maison())
}

/// Retire le fichier d'horodatage de la minuterie `nom` (« stamp-nom.timer ») : systemd le pose au démarrage d'une
/// minuterie Persistent=true et le touche à chaque passe, mais ne le retire jamais, même quand la minuterie part. Rend
/// ce qui n'est pas parti, relu après le retrait ; un dossier inconnu (`None`) n'a rien à retirer.
#[cfg(target_os = "linux")]
pub(crate) fn retirer_horodatage(dossier: Option<&Path>, nom: &str) -> Vec<String> {
    let Some(dossier) = dossier else {
        return Vec::new();
    };
    let fichier = [dossier.join(format!("stamp-{nom}.timer"))];
    let mut echecs = retirer_fichiers(&fichier);
    echecs.extend(encore_la(&fichier));
    echecs
}

/// Les deux unités systemd : le service, puis la minuterie (`r`).
///
/// D'aujourd'hui : toutes les heures pile (OnCalendar=hourly) et cinq minutes après le démarrage du gestionnaire de
/// l'utilisateur (OnStartupSec=5min). Une heure de l'horloge murale continue d'avancer pendant une veille, et systemd
/// fait au réveil la passe d'une heure échue pendant le sommeil (une seule, même si plusieurs sont passées :
/// systemd.timer(5), OnCalendar=). Ce rattrapage part dès le réveil, souvent avant que le Wi-Fi soit rebranché et
/// l'adresse redemandée : c'est la passe qui attend le réseau (`attendre_reseau`, une minute au plus), pas la
/// minuterie. Après un arrêt ou une fermeture de session, le gestionnaire de l'utilisateur repart à l'ouverture
/// suivante, et OnStartupSec y fait la passe cinq minutes plus tard, le temps que le réseau se monte ; à l'activation,
/// il est déjà échu et passe tout de suite (« already in the past … will immediately elapse »). Pas de Persistent= : il
/// ne ferait que doubler cette passe à l'ouverture (il rattrape au démarrage de la minuterie, comme OnStartupSec), et
/// laisserait un fichier d'horodatage (`retirer_horodatage`). Pas de RandomizedDelaySec= : une seule minuterie de ce
/// genre par ordinateur, rien à étaler ; la précision par défaut (AccuracySec=1min) suffit à la regrouper avec les
/// autres réveils.
///
/// D'avant : cinq minutes après le démarrage (OnBootSec, déjà échu à une ouverture de session plus tardive, donc
/// immédiat), puis une heure après chaque passe (OnUnitActiveSec). Son Persistent= n'agit que sur un OnCalendar= : il
/// ne rattrapait rien, mais systemd lui tient quand même un fichier d'horodatage, retiré quand elle est remplacée
/// (`installer`) ou retirée (`retirer_planifie`). Après une veille, l'horloge de OnUnitActiveSec s'arrête avec
/// l'ordinateur : la passe vient au bout du reste de l'heure entamée, sans rattrapage au réveil. Gardée à l'identique
/// pour une surveillance reprise telle qu'acceptée (`reprendre`), et reconnue à ces réglages (`minuterie_d_avant`).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn unites_systemd(exe: &str, r: Reglages) -> (String, &'static str) {
    // Chemin entre guillemets (un dossier personnel peut contenir une espace), « % » doublé (spécificateurs de
    // systemd).
    let exe = format!("\"{}\"", exe.replace('%', "%%").replace('"', "\\\""));
    let service = trf!(
        "[Unit]\nDescription=Vanguard : surveillance du réseau local\n\n[Service]\nType=oneshot\nExecStart={exe} surveiller\nNice=10\n",
        "[Unit]\nDescription=Vanguard: local network monitoring\n\n[Service]\nType=oneshot\nExecStart={exe} surveiller\nNice=10\n"
    );
    let timer = match r {
        Reglages::Aujourdhui => tr!(
            "[Unit]\nDescription=Vanguard : scan du réseau toutes les heures, rattrapé au réveil\n\n[Timer]\nOnCalendar=hourly\nOnStartupSec=5min\n\n[Install]\nWantedBy=timers.target\n",
            "[Unit]\nDescription=Vanguard: network scan every hour, caught up after sleep\n\n[Timer]\nOnCalendar=hourly\nOnStartupSec=5min\n\n[Install]\nWantedBy=timers.target\n"
        ),
        Reglages::DAvant => tr!(
            "[Unit]\nDescription=Vanguard : scan du réseau toutes les heures\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
            "[Unit]\nDescription=Vanguard: network scan every hour\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
        ),
    };
    (service, timer)
}

/// La minuterie de la surveillance a-t-elle été posée par une version d'avant ? Reconnue à ce qui les distingue : une
/// heure comptée depuis la passe précédente (OnUnitActiveSec=), sans heure de l'horloge (OnCalendar=). Une minuterie
/// d'aujourd'hui, ou retouchée par la personne pour suivre l'horloge, n'en est pas une : rien à lui proposer.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn minuterie_d_avant(texte: &str) -> bool {
    let a = |cle: &str| {
        texte.lines().any(|l| {
            l.trim_start()
                .split_once('=')
                .is_some_and(|(k, v)| k.trim() == cle && !v.trim().is_empty())
        })
    };
    a("OnUnitActiveSec") && !a("OnCalendar")
}

/// Le programme que lance une unité systemd : le premier mot de sa ligne ExecStart=.
pub(crate) fn programme_d_une_unite(texte: &str) -> Option<PathBuf> {
    premier_mot_cite(texte.lines().find_map(|l| l.strip_prefix("ExecStart="))?)
}

/// Le premier mot d'une ligne de commande d'unité systemd ou de fichier .desktop. Entre guillemets, « \" » et « \\ »
/// redeviennent « " » et « \ » ; partout, « %% » redevient « % » : l'inverse de ce qu'écrivent les unités de Vanguard,
/// `sauvegarde::citer_systemd` et le raccourci.
pub(crate) fn premier_mot_cite(valeur: &str) -> Option<PathBuf> {
    let v = valeur.trim_start();
    let brut = if let Some(reste) = v.strip_prefix('"') {
        let mut mot = String::new();
        let mut car = reste.chars();
        loop {
            match car.next()? {
                '"' => break,
                '\\' => match car.next()? {
                    c @ ('"' | '\\') => mot.push(c),
                    c => {
                        mot.push('\\');
                        mot.push(c);
                    }
                },
                c => mot.push(c),
            }
        }
        mot
    } else {
        v.split_whitespace().next()?.to_string()
    };
    let mot = brut.replace("%%", "%");
    (!mot.is_empty()).then(|| PathBuf::from(mot))
}

#[cfg(target_os = "linux")]
fn installer(exe: &str, r: Reglages) -> bool {
    let dossier = dossier_unites_maison();
    let _ = std::fs::create_dir_all(&dossier);
    let (service, timer) = unites_systemd(exe, r);
    let _ = std::fs::write(dossier.join(format!("{NOM}.service")), service);
    let _ = std::fs::write(dossier.join(format!("{NOM}.timer")), timer);
    let minuterie = format!("{NOM}.timer");
    // Redémarrée plutôt que « enable --now » : une minuterie déjà en marche (une réactivation qui remplace celle d'une
    // version d'avant) ne serait pas relancée par start, et rien ici ne vérifie que daemon-reload lui fait prendre ses
    // nouveaux réglages ; redémarrée, elle les prend à coup sûr. Arrêtée, restart la démarre, comme start.
    let posee =
        crate::machine::linux::dbus::actions::utilisateur(crate::machine::linux::dbus::actions::Geste::Recharger, "")
            && crate::machine::linux::dbus::actions::utilisateur(
                crate::machine::linux::dbus::actions::Geste::Activer { maintenant: false },
                &minuterie,
            )
            && crate::machine::linux::dbus::actions::utilisateur(
                crate::machine::linux::dbus::actions::Geste::Redemarrer,
                &minuterie,
            );
    // La minuterie d'avant (Persistent=true) laisse son fichier d'horodatage ; celle d'aujourd'hui n'en a plus
    // l'usage. Retiré après le redémarrage, quand plus rien ne le touche. Un échec reste sans effet sur la
    // surveillance (plus aucune minuterie ne le lit), et la désinstallation le retire de nouveau, relu ensuite.
    if r == Reglages::Aujourdhui {
        let _ = retirer_horodatage(dossier_horodatages_maison().as_deref(), NOM);
    }
    posee
}

#[cfg(target_os = "macos")]
fn plist_agent_nomme(nom: &str) -> std::path::PathBuf {
    crate::socle::maison().join(format!("Library/LaunchAgents/{nom}.plist"))
}

#[cfg(target_os = "macos")]
fn plist_agent() -> std::path::PathBuf {
    plist_agent_nomme(AGENT_MACOS)
}

/// Domaine launchd de la session graphique de l'utilisateur (« gui/501 »).
#[cfg(target_os = "macos")]
pub(crate) fn domaine_launchd() -> String {
    // SAFETY : getuid n'a ni argument ni échec possible.
    let uid = unsafe { libc::getuid() };
    format!("gui/{uid}")
}

/// Agent launchd : relancé toutes les heures (StartInterval), et dès l'ouverture de session (RunAtLoad).
#[cfg(any(target_os = "macos", test))]
fn plist_surveillance(exe: &str, nom: &str, r: Reglages) -> String {
    let exe = exe.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let au_lancement = if r == Reglages::Aujourdhui {
        "\t<key>RunAtLoad</key>\n\t<true/>\n"
    } else {
        ""
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \t<key>Label</key>\n\t<string>{nom}</string>\n\
         \t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>{exe}</string>\n\t\t<string>surveiller</string>\n\t</array>\n\
         \t<key>StartInterval</key>\n\t<integer>3600</integer>\n\
         {au_lancement}\
         \t<key>LowPriorityIO</key>\n\t<true/>\n\
         \t<key>Nice</key>\n\t<integer>10</integer>\n\
         </dict>\n</plist>\n"
    )
}

/// Le programme que lance un agent launchd (le premier de ProgramArguments), et s'il passe à l'ouverture de session.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn lire_plist(octets: &[u8]) -> Option<(PathBuf, bool)> {
    let v = crate::plist::lire(octets)?;
    let programme = v.cle("ProgramArguments")?.tableau()?.first()?.texte()?;
    let au_lancement = v.cle("RunAtLoad") == Some(&crate::plist::Valeur::Booleen(true));
    Some((PathBuf::from(programme), au_lancement))
}

#[cfg(target_os = "macos")]
fn installer(exe: &str, r: Reglages) -> bool {
    let plist = plist_agent();
    let _ = std::fs::create_dir_all(plist.parent().unwrap_or(&plist));
    if std::fs::write(&plist, plist_surveillance(exe, AGENT_MACOS, r)).is_err() {
        return false;
    }
    let chemin = plist.display().to_string();
    // Déjà chargé (réactivation) : on le retire d'abord, sinon bootstrap refuse.
    let _ = reussit("launchctl", &["bootout", &domaine_launchd(), &chemin]);
    reussit("launchctl", &["bootstrap", &domaine_launchd(), &chemin])
}

/// La tâche existe et n'est pas désactivée : une tâche désactivée ne surveille plus rien.
#[cfg(windows)]
fn tache_active(nom: &str) -> bool {
    // Le planificateur d'abord, PowerShell en secours.
    if let Some(e) = crate::machine::windows::planificateur::etat(&[nom]) {
        return e == crate::machine::windows::planificateur::EtatTache::Active;
    }
    crate::machine::windows::ps(&format!(
        "if (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -eq '{}' -and $_.State -ne 'Disabled' }}) {{ 'oui' }}",
        crate::commande::ps_texte(nom)
    ))
    .is_some_and(|s| s.trim() == "oui")
}

/// Une de ces tâches existe-t-elle ? Sans erreur quand aucune n'existe : un échec de PowerShell irait au journal.
#[cfg(windows)]
pub(crate) fn tache_existe(noms: &[&str]) -> bool {
    if let Some(e) = crate::machine::windows::planificateur::etat(noms) {
        return e != crate::machine::windows::planificateur::EtatTache::Absente;
    }
    let liste = noms.iter().map(|n| format!("'{n}'")).collect::<Vec<_>>().join(",");
    crate::machine::windows::ps(&format!(
        "if (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -in @({liste}) }}) {{ 'oui' }}"
    ))
    .is_some_and(|s| s.trim() == "oui")
}

/// Ce que le Planificateur de Windows dit d'une tâche : le programme de sa première action, ses deux réglages de
/// rattrapage (« dès que possible » après une heure manquée, un déclencheur à l'ouverture de session) et si elle est
/// active.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Definition {
    pub programme: String,
    pub des_que_possible: bool,
    pub a_l_ouverture: bool,
    pub active: bool,
}

/// Les tâches nommées `noms` : le planificateur d'abord, PowerShell en secours ; `None` si aucun des deux ne répond.
#[cfg(windows)]
pub(crate) fn definitions_windows(noms: &[&str]) -> Option<Vec<(String, Definition)>> {
    if let Some(lues) = crate::machine::windows::planificateur::definitions(noms) {
        return Some(lues);
    }
    let liste = noms
        .iter()
        .map(|n| format!("'{}'", crate::commande::ps_texte(n)))
        .collect::<Vec<_>>()
        .join(",");
    let sortie = crate::machine::windows::ps(&script_definitions(&liste))?;
    Some(lire_definitions_ps(&sortie))
}

/// Le script de secours : une ligne « nom|programme|StartWhenAvailable|déclencheurs à l'ouverture|état » par tâche.
#[cfg(any(windows, test))]
fn script_definitions(liste: &str) -> String {
    format!(
        "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -in @({liste}) }} | ForEach-Object {{ \
         $o = @($_.Triggers | Where-Object {{ $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' }}).Count; \
         \"$($_.TaskName)|$($_.Actions[0].Execute)|$($_.Settings.StartWhenAvailable)|$o|$($_.State)\" }}"
    )
}

/// Les lignes du script de secours ; une ligne abîmée est sautée, jamais devinée.
#[cfg(any(windows, test))]
pub(crate) fn lire_definitions_ps(sortie: &str) -> Vec<(String, Definition)> {
    sortie
        .lines()
        .filter_map(|l| {
            let champs: Vec<&str> = l.trim().split('|').collect();
            let [nom, programme, des_que_possible, ouverture, etat] = champs[..] else {
                return None;
            };
            let des_que_possible = match des_que_possible {
                "True" => true,
                "False" => false,
                _ => return None,
            };
            let ouverture = ouverture.parse::<u32>().ok()?;
            (!nom.is_empty() && !etat.is_empty()).then(|| {
                (
                    nom.to_string(),
                    Definition {
                        programme: programme.to_string(),
                        des_que_possible,
                        a_l_ouverture: ouverture > 0,
                        active: etat != "Disabled",
                    },
                )
            })
        })
        .collect()
}

/// Le script qui pose la tâche. Aujourd'hui : rattrapée dès que possible après une heure manquée (ordinateur éteint
/// ou en veille), et une passe cinq minutes après l'ouverture de session. Le déclencheur d'ouverture nomme le compte :
/// sans lui, Windows demanderait l'administrateur ; s'il refuse quand même, la tâche est posée sans ce déclencheur, et
/// le script le dit (« sans-ouverture »). Les réglages d'avant restent pour une tâche reprise telle qu'acceptée.
#[cfg(any(windows, test))]
fn script_tache(exe: &str, nom: &str, r: Reglages) -> String {
    let exe = crate::commande::ps_texte(exe);
    let nom = crate::commande::ps_texte(nom);
    match r {
        Reglages::DAvant => trf!(
            "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
             $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
             Register-ScheduledTask -TaskName '{nom}' -Action $a -Trigger $t -Force \
               -Description 'Scan du réseau local toutes les heures par Vanguard, notification si un appareil inconnu apparaît. Pour arrêter : vanguard surveillance off' | Out-Null",
            "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
             $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
             Register-ScheduledTask -TaskName '{nom}' -Action $a -Trigger $t -Force \
               -Description 'Hourly local network scan by Vanguard, with a notification when an unknown device appears. To stop it: vanguard monitor off' | Out-Null"
        ),
        Reglages::Aujourdhui => {
            let description = tr!(
                "Scan du réseau local toutes les heures par Vanguard, notification si un appareil inconnu apparaît, rattrapé au réveil et 5 minutes après l''ouverture de session. Pour arrêter : vanguard surveillance off",
                "Hourly local network scan by Vanguard, with a notification when an unknown device appears, caught up after sleep and 5 minutes after sign-in. To stop it: vanguard monitor off"
            );
            format!(
                "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'surveiller'; \
                 $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1); \
                 $o = New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name); $o.Delay = 'PT5M'; \
                 $s = New-ScheduledTaskSettingsSet -StartWhenAvailable; \
                 try {{ Register-ScheduledTask -TaskName '{nom}' -Action $a -Trigger @($t, $o) -Settings $s -Force -Description '{description}' -ErrorAction Stop | Out-Null }} \
                 catch {{ Register-ScheduledTask -TaskName '{nom}' -Action $a -Trigger $t -Settings $s -Force -Description '{description}' | Out-Null; 'sans-ouverture' }}"
            )
        }
    }
}

#[cfg(windows)]
fn installer(exe: &str, r: Reglages) -> bool {
    let Some(sortie) = crate::machine::windows::ps(&script_tache(exe, TACHE_WINDOWS, r)) else {
        return false;
    };
    if sortie.lines().any(|l| l.trim() == "sans-ouverture") {
        trp!(
            "  Windows a refusé le passage à l'ouverture de session : la surveillance rattrape seulement les heures manquées.",
            "  Windows refused the sign-in run: monitoring only catches up missed hours."
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les alertes des journaux de Windows que rend le bilan (WIN-JRN-003) sont notifiées, et les parcours
    /// « infection » et « compte piraté » les montrent ; une information ne l'est pas.
    #[test]
    fn alertes_des_journaux_surveillees() {
        use crate::journaux_windows::regles::resultat::CAT;
        let mut c = crate::machine::alerte(CAT, Niveau::Critique, "EVT-SRV-001 : service essai");
        c.regle = "WIN-JRN-003";
        assert!(machine_surveillee(&c));
        c.probleme = Some(Niveau::Info);
        assert!(!machine_surveillee(&c));
        assert!(
            crate::depanner::categories_des_parcours()
                .iter()
                .all(|l| l.contains(&CAT))
        );
    }

    /// Sur cet ordinateur, chaque minuterie de l'utilisateur activée ou non selon systemctl l'est aussi
    /// d'après ses liens. Les états à part (static, indirect, generated…) ne se comparent pas : nos
    /// minuteries ont toujours une section [Install].
    #[cfg(target_os = "linux")]
    #[test]
    fn minuteries_comme_systemctl() {
        let Some(r) = crate::commande::lancer_en_anglais(
            Command::new("systemctl").args(["--user", "list-unit-files", "--type=timer", "--no-legend"]),
            10,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("systemctl --user absent");
        };
        for ligne in r.sortie.lines() {
            let mut mots = ligne.split_whitespace();
            let (Some(nom), Some(etat)) = (mots.next(), mots.next()) else {
                continue;
            };
            if matches!(etat, "enabled" | "disabled" | "masked") {
                assert_eq!(minuterie_activee(nom), etat == "enabled", "{ligne}");
            }
        }
    }

    #[test]
    fn agent_launchd() {
        let exe = "/Users/a b/Library/Application Support/vanguard & co/bin/<vanguard>";
        let p = plist_surveillance(exe, "com.vanguard.surveillance", Reglages::Aujourdhui);
        assert!(p.contains(
            "<string>/Users/a b/Library/Application Support/vanguard &amp; co/bin/&lt;vanguard&gt;</string>"
        ));
        assert!(p.contains("<key>StartInterval</key>\n\t<integer>3600</integer>"));
        assert!(p.contains("<string>surveiller</string>"));
        assert!(p.contains("<key>RunAtLoad</key>\n\t<true/>"));
        // Relu tel qu'écrit : le programme d'origine, et le passage à l'ouverture de session.
        assert_eq!(lire_plist(p.as_bytes()), Some((PathBuf::from(exe), true)));
        // Une tâche reprise d'une version d'avant garde ses réglages : sans RunAtLoad, et relue comme telle.
        let avant = plist_surveillance(exe, "com.vanguard.surveillance", Reglages::DAvant);
        assert!(!avant.contains("RunAtLoad"));
        assert_eq!(lire_plist(avant.as_bytes()), Some((PathBuf::from(exe), false)));
    }

    #[test]
    fn script_de_la_tache() {
        let s = script_tache(
            "C:\\Program Files\\L'outil\\vanguard.exe",
            TACHE_WINDOWS,
            Reglages::Aujourdhui,
        );
        for attendu in [
            "-StartWhenAvailable",
            "-AtLogOn -User",
            "PT5M",
            "-Trigger @($t, $o)",
            "-Settings $s",
            "catch {",
            "'sans-ouverture'",
            "-Argument 'surveiller'",
            "-Execute 'C:\\Program Files\\L''outil\\vanguard.exe'",
        ] {
            assert!(s.contains(attendu), "{attendu} absent : {s}");
        }
        // Chaque chaîne entre apostrophes se ferme : leur nombre est pair (les doublées comptent deux).
        assert_eq!(s.matches('\'').count() % 2, 0, "{s}");
        // L'apostrophe typographique ferme aussi une chaîne PowerShell : doublée de même.
        let t = script_tache(
            "C:\\Users\\Zoé\\L’outil\\vanguard.exe",
            TACHE_WINDOWS,
            Reglages::Aujourdhui,
        );
        assert!(t.contains("-Execute 'C:\\Users\\Zoé\\L’’outil\\vanguard.exe'"), "{t}");
        // Une tâche reprise d'une version d'avant : ses réglages d'alors, rien de neuf.
        let avant = script_tache("C:\\vanguard.exe", TACHE_WINDOWS, Reglages::DAvant);
        for absent in ["-StartWhenAvailable", "-AtLogOn", "PT5M", "catch", "-Settings"] {
            assert!(!avant.contains(absent), "{absent} présent : {avant}");
        }
        assert!(avant.contains("-Argument 'surveiller'") && avant.contains(TACHE_WINDOWS));
    }

    #[test]
    fn unites_et_programme_lu() {
        let exe = "/home/a b/100%/van\"guard";
        let (service, timer) = unites_systemd(exe, Reglages::Aujourdhui);
        assert!(
            service.contains("ExecStart=\"/home/a b/100%%/van\\\"guard\" surveiller\n"),
            "{service}"
        );
        assert!(timer.contains("\nOnCalendar=hourly\n") && timer.contains("\nOnStartupSec=5min\n"));
        // Le service ne change pas d'une version à l'autre : seule la minuterie diffère.
        assert_eq!(unites_systemd(exe, Reglages::DAvant).0, service);
        // Aller-retour : le programme relu dans l'unité est celui qu'elle lance.
        assert_eq!(programme_d_une_unite(&service), Some(PathBuf::from(exe)));
        assert_eq!(programme_d_une_unite("[Service]\nType=oneshot\n"), None);
        assert_eq!(
            programme_d_une_unite("ExecStart=/usr/bin/vanguard surveiller\n"),
            Some(PathBuf::from("/usr/bin/vanguard"))
        );
        // L'unité de la sauvegarde : rsync, écrit par citer_systemd.
        let (_, sauvegarde) = crate::sauvegarde::unites(
            Path::new("/usr/bin/rsync"),
            Some(Path::new("/usr/bin/findmnt")),
            Some("1234-ABCD"),
            Path::new("/run/media/alice/Externe"),
            Path::new("/run/media/alice/Externe/Sauvegarde-Vanguard/pc"),
            &[PathBuf::from("/home/alice/Documents")],
            false,
        )
        .unwrap();
        assert_eq!(
            programme_d_une_unite(&sauvegarde),
            Some(PathBuf::from("/usr/bin/rsync"))
        );
    }

    /// La minuterie d'aujourd'hui suit l'horloge (rattrapée au réveil) et passe après l'ouverture de session ; celle
    /// d'avant reste octet pour octet celle des versions d'avant, pour une surveillance reprise telle qu'acceptée.
    #[test]
    fn minuteries_d_aujourdhui_et_d_avant() {
        let (_, aujourdhui) = unites_systemd("/usr/bin/vanguard", Reglages::Aujourdhui);
        for absent in ["OnUnitActiveSec", "OnBootSec", "Persistent", "RandomizedDelaySec"] {
            assert!(!aujourdhui.contains(absent), "{absent} présent : {aujourdhui}");
        }
        assert!(aujourdhui.contains("[Install]\nWantedBy=timers.target\n"));
        let (_, avant) = unites_systemd("/usr/bin/vanguard", Reglages::DAvant);
        let fin =
            "\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n";
        assert!(
            avant == format!("[Unit]\nDescription=Vanguard : scan du réseau toutes les heures{fin}")
                || avant == format!("[Unit]\nDescription=Vanguard: network scan every hour{fin}"),
            "{avant}"
        );
        // Reconnues à leur contenu, dans les deux langues, sans faux positif sur celle d'aujourd'hui.
        assert!(minuterie_d_avant(avant));
        assert!(!minuterie_d_avant(aujourdhui));
        for t in [
            "[Unit]\nDescription=Vanguard : scan du réseau toutes les heures\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n",
            "[Unit]\nDescription=Vanguard: network scan every hour\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n",
            "[Timer]\n  OnUnitActiveSec = 1h\n",
        ] {
            assert!(minuterie_d_avant(t), "{t}");
        }
        // Retouchée pour suivre l'horloge, vide, ou une clé vidée : rien d'une version d'avant à proposer.
        for t in [
            "[Timer]\nOnUnitActiveSec=1h\nOnCalendar=*:30\n",
            "",
            "[Timer]\nOnUnitActiveSec=\nOnCalendar=hourly\n",
            "[Timer]\nOnUnitActiveSec=\n",
        ] {
            assert!(!minuterie_d_avant(t), "{t}");
        }
    }

    /// Les unités relues dans un dossier jetable : le programme du service, et la minuterie d'avant reconnue pour la
    /// surveillance seulement ; absente, elle ne se dit pas d'avant ; illisible, rien n'est conclu. Unix seulement :
    /// sous Windows, le chemin du programme (/home/…) n'est pas absolu, et le bilan dirait « sans chemin ».
    #[cfg(unix)]
    #[test]
    fn unites_relues_d_aujourdhui_ou_d_avant() {
        let d = crate::socle::dossier_local().join("unites-relues");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let exe = "/home/alice/.local/share/vanguard/bin/vanguard";
        assert_eq!(lire_unites(&d, NOM, true), Lecture::Absente);
        let ecrire = |r| {
            let (service, timer) = unites_systemd(exe, r);
            std::fs::write(d.join(format!("{NOM}.service")), service).unwrap();
            std::fs::write(d.join(format!("{NOM}.timer")), timer).unwrap();
        };
        let lue = |a_jour| Lecture::Lue {
            programme: PathBuf::from(exe),
            a_jour: Ok(a_jour),
        };
        ecrire(Reglages::Aujourdhui);
        assert_eq!(lire_unites(&d, NOM, true), lue(true));
        ecrire(Reglages::DAvant);
        assert_eq!(lire_unites(&d, NOM, true), lue(false));
        // L'entretien ne juge pas sa minuterie : elle n'a jamais changé.
        assert_eq!(lire_unites(&d, NOM, false), lue(true));
        // Le bilan qui en sort : une information, et la commande qui la met à jour.
        let c = juger_tache(Planifie::Surveillance, &lire_unites(&d, NOM, true), None, |_| true).expect("constat");
        assert_eq!(c.probleme, Some(Niveau::Info));
        let action = &c.correctif.as_ref().unwrap().action;
        assert!(
            action.contains("surveillance on") || action.contains("monitor on"),
            "{action}"
        );
        // La minuterie retirée : sa disparition se juge à part, pas de « version d'avant » ici.
        std::fs::remove_file(d.join(format!("{NOM}.timer"))).unwrap();
        assert_eq!(lire_unites(&d, NOM, true), lue(true));
        // Un dossier à la place de la minuterie : le programme est lu quand même, seul l'âge de la minuterie reste
        // sans réponse.
        std::fs::create_dir_all(d.join(format!("{NOM}.timer"))).unwrap();
        let illisible = lire_unites(&d, NOM, true);
        assert!(
            matches!(&illisible, Lecture::Lue { programme, a_jour: Err(_) } if programme == Path::new(exe)),
            "{illisible:?}"
        );
        // Programme présent : non vérifié, et le message dit que c'est la minuterie qui n'a pas été lue, pas le
        // programme.
        let c = juger_tache(Planifie::Surveillance, &illisible, None, |_| true).expect("constat");
        assert!(!c.verifie);
        assert!(
            (c.message.contains("minuterie") && !c.message.contains("programme"))
                || (c.message.contains("timer") && !c.message.contains("program")),
            "{}",
            c.message
        );
        // Programme disparu : l'alerte élevée est dite malgré la minuterie illisible.
        let c = juger_tache(Planifie::Surveillance, &illisible, None, |p| p != Path::new(exe)).expect("constat");
        assert!(c.verifie && c.probleme == Some(Niveau::Eleve), "{}", c.message);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn programme_planifie_disparu_ou_d_avant() {
        let programme = PathBuf::from(if cfg!(windows) {
            r"C:\vanguard\vanguard.exe"
        } else {
            "/opt/vanguard/vanguard"
        });
        let lue = |a_jour| Lecture::Lue {
            programme: programme.clone(),
            a_jour: Ok(a_jour),
        };
        // Tout existe, sauf le programme : son dossier est encore là.
        let parti = |p: &Path| p != programme;
        // Le programme parti : la tâche est là, mais ne tourne plus.
        let c = juger_tache(Planifie::Surveillance, &lue(true), None, parti).expect("constat");
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.verifie && !c.correctif.as_ref().unwrap().automatique);
        assert!(
            c.correctif.as_ref().unwrap().action.contains("surveillance on")
                || c.correctif.as_ref().unwrap().action.contains("monitor on")
        );
        // Présent, posé par une version d'avant : une information, et la remise à jour proposée.
        let c = juger_tache(Planifie::Surveillance, &lue(false), None, |_| true).expect("constat");
        assert_eq!(c.probleme, Some(Niveau::Info));
        let action = &c.correctif.as_ref().unwrap().action;
        assert!(
            action.contains("surveillance on") || action.contains("monitor on"),
            "{action}"
        );
        // Illisible : non vérifié, jamais compté comme sain ; et le message dit de quelle tâche il s'agit.
        let c = juger_tache(
            Planifie::Surveillance,
            &Lecture::Illisible("refus".into()),
            None,
            |_| true,
        )
        .expect("constat");
        assert!(!c.verifie);
        let e = juger_tache(Planifie::Entretien, &Lecture::Illisible("refus".into()), None, |_| true).unwrap();
        assert!(
            e.message.contains("entretien") || e.message.contains("check-up"),
            "{}",
            e.message
        );
        assert_ne!(c.message, e.message);
        // Un nom sans chemin : non vérifié non plus, avec le nom de la tâche.
        let relatif = Lecture::Lue {
            programme: PathBuf::from("vanguard"),
            a_jour: Ok(true),
        };
        assert!(
            !juger_tache(Planifie::Surveillance, &relatif, None, |_| true)
                .unwrap()
                .verifie
        );
        let e = juger_tache(Planifie::Entretien, &relatif, None, |_| true).unwrap();
        assert!(
            e.message.contains("entretien") || e.message.contains("check-up"),
            "{}",
            e.message
        );
        // Tout va bien, ou rien de planifié : rien à dire.
        assert!(juger_tache(Planifie::Surveillance, &lue(true), None, |_| true).is_none());
        assert!(juger_tache(Planifie::Surveillance, &Lecture::Absente, None, |_| false).is_none());
        // L'entretien : moyen, et jamais « d'une version d'avant » (il a déjà son rattrapage).
        let c = juger_tache(Planifie::Entretien, &lue(true), None, parti).expect("constat");
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("entretien") || c.message.contains("check-up"));
        assert!(juger_tache(Planifie::Entretien, &lue(false), None, |_| true).is_none());
    }

    #[test]
    fn tache_sans_declencheur_d_ouverture_reste_d_aujourd_hui() {
        // Windows a refusé -AtLogOn : la tâche d'aujourd'hui est posée avec StartWhenAvailable seul.
        let lues = lire_definitions_ps("vanguard - surveillance du reseau|C:\\vanguard.exe|True|0|Ready\n");
        let d = &lues[0].1;
        assert!(d.des_que_possible && !d.a_l_ouverture);
        assert!(a_jour_windows(d));
        let l = Lecture::Lue {
            programme: PathBuf::from(if cfg!(windows) {
                r"C:\vanguard.exe"
            } else {
                "/opt/vanguard/vanguard"
            }),
            a_jour: Ok(a_jour_windows(d)),
        };
        assert!(juger_tache(Planifie::Surveillance, &l, None, |_| true).is_none());
        // Une tâche d'avant n'a jamais eu StartWhenAvailable.
        let avant = lire_definitions_ps("x|C:\\vanguard.exe|False|0|Ready\n");
        assert!(!a_jour_windows(&avant[0].1));
    }

    #[test]
    fn programme_de_la_cle_sur_un_lecteur_absent() {
        // Le préfixe « \\?\ » de canonicalize, retiré pour PowerShell et le raccourci ; UNC gardé tel quel.
        assert_eq!(
            sans_verbatim(Path::new(r"\\?\E:\Windows\vanguard.exe")),
            PathBuf::from(r"E:\Windows\vanguard.exe")
        );
        assert_eq!(
            sans_verbatim(Path::new(r"\\?\UNC\serveur\x")),
            PathBuf::from(r"\\?\UNC\serveur\x")
        );
        #[cfg(windows)]
        {
            // La clé se situe par canonicalize (« \\?\E:\ »), le programme par current_exe (« E:\… ») : le même
            // début.
            assert!(sous(Path::new(r"E:\Windows\vanguard.exe"), Path::new(r"\\?\E:\")));
            assert!(sous(Path::new(r"\\?\E:\Windows\vanguard.exe"), Path::new(r"E:\")));
            assert!(!sous(Path::new(r"C:\Windows\vanguard.exe"), Path::new(r"\\?\E:\")));
            // La clé revenue en F: : le même programme y est ; un lecteur E: qui n'existe plus.
            let e = Path::new(r"E:\Windows\vanguard.exe");
            let f = Path::new(r"F:\");
            assert!(sur_un_lecteur_absent(e, Some(f), &|p: &Path| p == Path::new(r"F:\Windows\vanguard.exe")));
            assert!(sur_un_lecteur_absent(e, None, &|_: &Path| false));
            assert!(!sur_un_lecteur_absent(e, None, &|p: &Path| p == Path::new(r"E:\")));
        }
        #[cfg(unix)]
        {
            // La clé remontée ailleurs, ou débranchée : la raison est le lecteur, pas un logiciel malveillant.
            let p = Path::new("/run/media/alice/VANGUARD/Linux/vanguard");
            let ailleurs = Path::new("/media/alice/VANGUARD");
            let la = |q: &Path| q == Path::new("/media/alice/VANGUARD/Linux/vanguard");
            assert!(sur_un_lecteur_absent(p, Some(ailleurs), &la));
            let monte = |q: &Path| {
                ["/", "/run", "/run/media", "/run/media/alice"]
                    .iter()
                    .any(|m| q == Path::new(m))
            };
            assert!(sur_un_lecteur_absent(p, None, &monte));
            // Un dossier effacé sur le disque de l'ordinateur : l'alerte d'un programme disparu.
            let local = Path::new("/home/alice/.local/share/vanguard/bin/vanguard");
            let maison = |q: &Path| q == Path::new("/") || q == Path::new("/home") || q == Path::new("/home/alice");
            assert!(!sur_un_lecteur_absent(local, None, &maison));
            assert!(!sur_un_lecteur_absent(local, Some(ailleurs), &maison));
            let c = juger_tache(
                Planifie::Surveillance,
                &Lecture::Lue {
                    programme: p.to_path_buf(),
                    a_jour: Ok(true),
                },
                Some(ailleurs),
                la,
            )
            .expect("constat");
            assert_eq!(c.probleme, Some(Niveau::Moyen));
        }
    }

    #[cfg(unix)]
    #[test]
    fn retrait_de_fichiers_constate() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::socle::dossier_local().join("retrait-constate");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let (parti, bloque, absent) = (d.join("a.timer"), d.join("b.service"), d.join("c.timer"));
        std::fs::write(&parti, "x").unwrap();
        std::fs::write(&bloque, "x").unwrap();
        // Un dossier en lecture seule : ses fichiers ne s'effacent pas (sauf pour root, qui passe outre).
        let verrou = d.join("verrou");
        std::fs::create_dir_all(&verrou).unwrap();
        let dedans = verrou.join("d.timer");
        std::fs::write(&dedans, "x").unwrap();
        std::fs::set_permissions(&verrou, std::fs::Permissions::from_mode(0o555)).unwrap();
        let fichiers = [parti.clone(), absent, dedans.clone()];
        let echecs = retirer_fichiers(&fichiers);
        let restes = encore_la(&fichiers);
        let root = est_root();
        assert!(!parti.exists());
        if !root {
            assert_eq!(echecs.len(), 1, "{echecs:?}");
            assert_eq!(restes.len(), 1, "{restes:?}");
            assert!(restes[0].contains("d.timer"));
        }
        assert_eq!(encore_la(&[bloque]).len(), 1);
        std::fs::set_permissions(&verrou, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Au réveil, le réseau revient quelques secondes après la passe : elle l'attend, en le redemandant, puis
    /// s'arrête à la borne s'il ne vient pas. Passerelle simulée, aucune vraie interface ; pas et borne réduits pour
    /// que le test reste court.
    #[tokio::test]
    async fn reseau_attendu_au_plus_la_borne() {
        use std::time::{Duration, Instant};
        let pas = Duration::from_millis(20);
        // Là tout de suite : aucune attente.
        let debut = Instant::now();
        assert!(attendre_reseau(|| true, pas, Duration::from_secs(5)).await);
        assert!(debut.elapsed() < Duration::from_secs(1));
        // Revenu à la troisième demande : attendu, sans aller jusqu'à la borne.
        let mut demandes = 0;
        let debut = Instant::now();
        let venu = attendre_reseau(
            || {
                demandes += 1;
                demandes >= 3
            },
            pas,
            Duration::from_secs(5),
        )
        .await;
        assert!(venu && demandes == 3, "{demandes}");
        assert!(debut.elapsed() >= 2 * pas && debut.elapsed() < Duration::from_secs(4));
        // Jamais revenu : faux à la borne, ni avant ni bien après, et redemandé entre-temps.
        let mut demandes = 0;
        let borne = Duration::from_millis(150);
        let debut = Instant::now();
        let venu = attendre_reseau(
            || {
                demandes += 1;
                false
            },
            pas,
            borne,
        )
        .await;
        let duree = debut.elapsed();
        assert!(!venu);
        assert!(duree >= borne && duree < borne + Duration::from_secs(2), "{duree:?}");
        assert!(demandes >= 3, "{demandes}");
        // Les vraies valeurs : une minute au plus, redemandé toutes les deux secondes.
        assert_eq!(
            (ATTENTE_RESEAU, PAS_RESEAU),
            (Duration::from_secs(60), Duration::from_secs(2))
        );
    }

    /// Le fichier d'horodatage de la minuterie d'avant (Persistent=true) : retiré, puis relu absent ; un fichier qui
    /// ne part pas est dit ; un dossier inconnu ne vise rien, surtout pas le dossier courant.
    #[cfg(target_os = "linux")]
    #[test]
    fn horodatage_de_la_minuterie_retire() {
        let maison = crate::socle::dossier_local().join("horodatage");
        let _ = std::fs::remove_dir_all(&maison);
        let dossier = dossier_horodatages(None, &maison).unwrap();
        assert_eq!(dossier, maison.join(".local/share/systemd/timers"));
        assert_eq!(
            dossier_horodatages(Some(maison.join("donnees").into()), Path::new("/ailleurs")),
            Some(maison.join("donnees/systemd/timers"))
        );
        assert_eq!(dossier_horodatages(Some("".into()), Path::new("")), None);
        assert_eq!(
            dossier_horodatages(Some("relatif".into()), Path::new("/home/alice")),
            None
        );
        assert_eq!(retirer_horodatage(None, NOM), Vec::<String>::new());
        std::fs::create_dir_all(&dossier).unwrap();
        let stamp = dossier.join(format!("stamp-{NOM}.timer"));
        let voisin = dossier.join("stamp-autre.timer");
        std::fs::write(&stamp, "").unwrap();
        std::fs::write(&voisin, "").unwrap();
        assert_eq!(retirer_horodatage(Some(&dossier), NOM), Vec::<String>::new());
        assert!(std::fs::symlink_metadata(&stamp).is_err(), "relu absent");
        // Celui d'une autre minuterie reste ; déjà absent, rien à dire.
        assert!(voisin.exists());
        assert_eq!(retirer_horodatage(Some(&dossier), NOM), Vec::<String>::new());
        // Un dossier à sa place ne part pas : c'est dit, avec son chemin.
        std::fs::create_dir_all(&stamp).unwrap();
        let echecs = retirer_horodatage(Some(&dossier), NOM);
        assert!(
            !echecs.is_empty() && echecs[0].contains(&format!("stamp-{NOM}.timer")),
            "{echecs:?}"
        );
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Root efface même dans un dossier en lecture seule : le cas ne se vérifie alors pas.
    #[cfg(unix)]
    fn est_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|t| {
                t.lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .map(|u| u.split_whitespace().nth(1) == Some("0"))
            })
            .unwrap_or(false)
    }

    #[test]
    fn definitions_lues_par_powershell() {
        let sortie = "vanguard - surveillance du reseau|C:\\Users\\alice\\vanguard.exe|True|1|Ready\n\
                      vanguard - entretien du mois|C:\\vanguard.exe|False|0|Disabled\n\
                      abîmée|sans|champs\n\
                      x|y|Peut-être|1|Ready\n";
        let lues = lire_definitions_ps(sortie);
        assert_eq!(lues.len(), 2, "{lues:?}");
        assert_eq!(
            lues[0],
            (
                "vanguard - surveillance du reseau".to_string(),
                Definition {
                    programme: "C:\\Users\\alice\\vanguard.exe".into(),
                    des_que_possible: true,
                    a_l_ouverture: true,
                    active: true,
                }
            )
        );
        assert!(!lues[1].1.des_que_possible && !lues[1].1.a_l_ouverture && !lues[1].1.active);
        // Le script de secours nomme les tâches et rend ces cinq champs.
        let script = script_definitions("'a','b'");
        assert!(script.contains("-in @('a','b')") && script.contains("MSFT_TaskLogonTrigger"));
        assert!(
            script.contains("$($_.TaskName)|$($_.Actions[0].Execute)|$($_.Settings.StartWhenAvailable)|$o|$($_.State)")
        );
    }

    fn etat(score: u32, alertes: &[&str]) -> EtatMachine {
        EtatMachine {
            score: Some(score),
            textes: TEXTES,
            alertes: alertes.iter().map(ToString::to_string).collect(),
            cles: Vec::new(),
            niveaux: Vec::new(),
        }
    }

    #[test]
    fn box_qui_change_de_mac() {
        let p = |nom: &str, mac: &str| Passerelle {
            reseau: "10.0.0.0/24".into(),
            nom: Some(nom.into()),
            ip: "10.0.0.1".parse().unwrap(),
            mac: mac.into(),
        };
        assert!(mac_changee(&p("Maison", "aa:aa:aa:aa:aa:aa"), &p("Maison", "aa:aa:aa:aa:aa:aa")).is_none());
        assert!(mac_changee(&p("Maison", "aa:aa:aa:aa:aa:aa"), &p("Maison", "bb:bb:bb:bb:bb:bb")).is_some());
        // Autre Wi-Fi (chez un ami) avec la même adresse de box : pas une alerte.
        assert!(mac_changee(&p("Maison", "aa:aa:aa:aa:aa:aa"), &p("Ami", "bb:bb:bb:bb:bb:bb")).is_none());
    }

    /// L'état laissé par la 0.85 (sans clés) se relit et se compare par le texte ; ensuite, avec les clés, passer à
    /// l'anglais ne renotifie rien, et un autre programme sur le même port, si.
    #[test]
    fn etat_de_la_085_puis_comparaison_par_cle() {
        let ancien: EtatMachine =
            serde_json::from_str(include_str!("../../tests/donnees/surveillance-machine-0.85.json")).unwrap();
        assert!(ancien.cles.is_empty() && ancien.alertes.len() == 2);
        let cle = "LNX-RES-001|port:8080/tcp:python3";
        let mut fr = etat(86, &[]);
        fr.ajouter(ancien.alertes[0].clone(), Some(cle.into()), Some(Niveau::Moyen));
        fr.ajouter(ancien.alertes[1].clone(), None, Some(Niveau::Moyen));
        assert_eq!(nouveautes_machine(&ancien, &fr), Vec::new());
        let mut en = etat(86, &[]);
        en.ajouter(
            "Ports en écoute : 8080/tcp (HTTP) open to the network by “python3”. A development web server.".into(),
            Some(cle.into()),
            Some(Niveau::Moyen),
        );
        en.ajouter(ancien.alertes[1].clone(), None, Some(Niveau::Moyen));
        assert_eq!(nouveautes_machine(&fr, &en), Vec::new());
        let mut intrus = etat(86, &[]);
        intrus.ajouter(
            en.alertes[0].clone(),
            Some("LNX-RES-001|port:8080/tcp:intrus".into()),
            Some(Niveau::Moyen),
        );
        assert_eq!(nouveautes_machine(&en, &intrus).len(), 1);
        // Relu tel qu'écrit : les clés suivent leurs alertes.
        let relu: EtatMachine = serde_json::from_str(&serde_json::to_string(&en).unwrap()).unwrap();
        assert_eq!(
            relu.alertes_et_cles().collect::<Vec<_>>(),
            en.alertes_et_cles().collect::<Vec<_>>()
        );
    }

    /// Même clé, plus grave : une note (avant, la clé seule comptait et l'aggravation passait en silence). Même
    /// niveau ou moins grave : rien. Un niveau non noté (état d'avant) ne renotifie rien.
    #[test]
    fn aggravation_renotifiee() {
        let cle = "COM-NAV-001|extension:firefox/exemple@example.com";
        let avec = |niveau: Option<Niveau>, texte: &str| {
            let mut e = etat(86, &[]);
            e.ajouter(format!("Extensions : {texte}"), Some(cle.into()), niveau);
            e
        };
        let moyen = avec(Some(Niveau::Moyen), "Extension d'origine inconnue : Exemple.");
        let eleve = avec(
            Some(Niveau::Eleve),
            "Extension d'origine inconnue : Exemple, avec accès à tous les sites.",
        );
        assert_eq!(nouveautes_machine(&moyen, &eleve).len(), 1);
        assert_eq!(nouveautes_machine(&eleve, &eleve), Vec::new());
        assert_eq!(nouveautes_machine(&eleve, &moyen), Vec::new());
        let sans = avec(None, "Extension d'origine inconnue : Exemple.");
        assert_eq!(nouveautes_machine(&sans, &eleve), Vec::new());
        // Relu tel qu'écrit : les niveaux suivent leurs alertes ; sans niveau, rien n'est écrit.
        let relu: EtatMachine = serde_json::from_str(&serde_json::to_string(&eleve).unwrap()).unwrap();
        assert_eq!(relu.niveau(0), Some(Niveau::Eleve));
        assert!(!serde_json::to_string(&etat(86, &["x"])).unwrap().contains("niveaux"));
    }

    #[test]
    fn faille_critique_notifiee_une_fois() {
        let a = "Failles connues : Activement exploitée (catalogue KEV de la CISA) : php (CVE-2026-109618, au catalogue depuis le 2026-10-21). 3 paquet(s) avec une faille connue : a, b, c.";
        let b = "Failles connues : Activement exploitée (catalogue KEV de la CISA) : php (CVE-2026-109618, au catalogue depuis le 2026-10-21). 1 paquet(s) avec une faille connue : a.";
        let c = "Failles connues : Activement exploitée (catalogue KEV de la CISA) : php (CVE-2026-109619, au catalogue depuis le 2026-10-21). 1 paquet(s) avec une faille connue : a.";
        // Le reste change : même alerte ; une autre CVE exploitée : nouvelle.
        assert_eq!(cle_alerte(a), cle_alerte(b));
        assert_ne!(cle_alerte(b), cle_alerte(c));
        assert_eq!(
            cle_alerte("Failles connues : 2 paquet(s) avec une faille connue : x, y."),
            cle_alerte("Failles connues : Paquet dont un programme écoute sur le réseau : z (port 80). 1 paquet(s).")
        );
    }

    #[test]
    fn failles_notifiees_si_critiques() {
        let faille = |n| crate::machine::alerte("Failles connues", n, "php : faille".to_string());
        assert!(machine_surveillee(&faille(Niveau::Critique)));
        // Corrigées dans les dépôts, chaque jour d'autres : comme les mises à jour, pas notifiées.
        assert!(!machine_surveillee(&faille(Niveau::Eleve)) && !machine_surveillee(&faille(Niveau::Moyen)));
        assert!(machine_surveillee(&crate::machine::alerte(
            "Pare-feu",
            Niveau::Moyen,
            "coupé".to_string()
        )));
    }

    /// Une alerte écrite d'avance dans l'état du passage d'avant, ou cet état effacé : rien n'est cru, l'alerte de
    /// l'état de Vanguard sort quand même.
    #[test]
    fn etat_d_avant_pose_a_cote_ne_tait_rien() {
        use crate::sceau::Lecture;
        let alerte = "État de Vanguard : appris.json a été changé hors de Vanguard.";
        let apres = etat(80, &[alerte]);
        let pose = serde_json::to_vec(&apres).unwrap();
        // Tel que Vanguard l'a écrit : déjà connue, pas renotifiée.
        let avant = etat_d_avant(Lecture::Intact(pose.clone())).unwrap();
        assert_eq!(nouveautes_machine(&avant, &apres), Vec::<(String, String)>::new());
        for lu in [
            Lecture::Falsifie(Some(pose.clone())),
            Lecture::Falsifie(None),
            Lecture::Adopte(pose),
            Lecture::Illisible("refusé".into()),
            // Effacé avec les sceaux : jamais un premier passage.
            Lecture::Inconnu,
        ] {
            let avant = etat_d_avant(lu).unwrap();
            let notes = nouveautes_machine(&avant, &apres);
            assert!(notes.iter().any(|(_, t)| t.contains("appris.json")), "{notes:?}");
        }
        // Premier passage : mémoriser seulement.
        assert!(etat_d_avant(Lecture::Absent).is_none());
    }

    /// Une redirection UPnP écrite d'avance dans l'audit d'avant, ou l'audit effacé avec les sceaux : la nouvelle
    /// redirection est quand même notifiée. Une box posée à côté ne sert pas de référence.
    #[test]
    fn audit_et_passerelle_poses_a_cote_ne_taisent_rien() {
        use crate::sceau::Lecture;
        let r = upnp::Redirection {
            protocole: "TCP".into(),
            port_public: 4444,
            appareil: "192.168.1.20".into(),
            port_appareil: 4444,
            description: String::new(),
            bail: 0,
            hote_distant: String::new(),
            active: true,
        };
        let apres = EtatAudit {
            textes: TEXTES,
            redirections: Some(vec![cle_redirection(&r)]),
            constats: Vec::new(),
        };
        let pose = serde_json::to_vec(&apres).unwrap();
        let avant = audit_d_avant(Lecture::Intact(pose.clone())).unwrap();
        assert_eq!(
            nouveautes_audit(&avant, &apres, std::slice::from_ref(&r), &[]),
            Vec::<(String, String, Genre)>::new()
        );
        for lu in [
            Lecture::Falsifie(Some(pose.clone())),
            Lecture::Falsifie(None),
            Lecture::Adopte(pose),
            Lecture::Illisible("refusé".into()),
            Lecture::Inconnu,
        ] {
            let avant = audit_d_avant(lu).unwrap();
            assert_eq!(nouveautes_audit(&avant, &apres, std::slice::from_ref(&r), &[]).len(), 1);
        }
        assert!(audit_d_avant(Lecture::Absent).is_none());
        let boite = br#"{"reseau":"192.168.1.0/24","nom":"Salon","ip":"192.168.1.1","mac":"00:1a:2b:3c:4d:5e"}"#;
        assert!(passerelle_d_avant(Lecture::Intact(boite.to_vec())).is_some());
        assert!(passerelle_d_avant(Lecture::Falsifie(Some(boite.to_vec()))).is_none());
        assert!(passerelle_d_avant(Lecture::Adopte(boite.to_vec())).is_none());
    }

    #[test]
    fn nouveautes_de_la_machine() {
        let avant = etat(
            90,
            &[
                "Santé : Disque presque plein : / n'a plus que 30 Go libres (4 %).",
                "Ports en écoute : 8080/tcp ouvert.",
            ],
        );
        // Même disque avec d'autres nombres, même port : rien de nouveau.
        let pareil = etat(
            88,
            &[
                "Santé : Disque presque plein : / n'a plus que 25 Go libres (3 %).",
                "Ports en écoute : 8080/tcp ouvert.",
            ],
        );
        assert_eq!(nouveautes_machine(&avant, &pareil), Vec::<(String, String)>::new());
        // Un nouveau port et une note qui chute de 15 points : deux notifications.
        let pire = etat(
            75,
            &[
                "Ports en écoute : 8080/tcp ouvert.",
                "Ports en écoute : 4444/tcp ouvert.",
            ],
        );
        let n = nouveautes_machine(&avant, &pire);
        assert_eq!(n.len(), 2);
        assert!(n[0].1.contains("4444"));
        assert!(n[1].1.contains("90") && n[1].1.contains("75"));
    }
    /// L'audit du réseau entre deux passes : une alerte par redirection nouvelle de la box et par constat nouveau
    /// d'une règle suivie ; un nombre qui change ne compte pas, sauf l'adresse du DNS distribué par la box ; des
    /// redirections non lues ne se comparent pas.
    #[test]
    fn nouveautes_de_l_audit() {
        let redirection = |public: u16, appareil: &str, port: u16| upnp::Redirection {
            protocole: "TCP".into(),
            port_public: public,
            appareil: appareil.into(),
            port_appareil: port,
            description: "Camera".into(),
            bail: 0,
            hote_distant: String::new(),
            active: true,
        };
        let constat = |regle: &'static str, niveau: Niveau, message: &str| {
            let mut c = crate::machine::alerte("Wi-Fi", niveau, message);
            c.regle = regle;
            c
        };
        let redirections = [redirection(3074, "10.0.0.20", 3074), redirection(8080, "10.0.0.30", 80)];
        let tkip = constat(
            "COM-WIF-001",
            Niveau::Moyen,
            "Le Wi-Fi « Salon » accepte encore TKIP (3 bornes).",
        );
        let dns = constat(
            "COM-DNS-002",
            Niveau::Info,
            "Le routeur distribue le DNS 203.0.113.9 à tous vos appareils.",
        );
        let ipv6 = constat(
            "COM-EXP-003",
            Niveau::Eleve,
            "Cet ordinateur a une adresse IPv6 publique sans pare-feu.",
        );
        // Non suivis : une règle hors liste, une information d'une règle suivie, un constat non vérifié.
        let hors = constat("COM-APP-002", Niveau::Critique, "Telnet ouvert.");
        let info = constat("COM-WIF-002", Niveau::Info, "WPS par bouton seulement.");
        let mut non_verifie = constat("COM-WIF-001", Niveau::Moyen, "x");
        non_verifie.verifie = false;
        let constats = [&tkip, &dns, &ipv6, &hors, &info, &non_verifie];
        let avant = EtatAudit {
            textes: TEXTES,
            redirections: Some(vec![cle_redirection(&redirections[0])]),
            constats: vec![
                cle_constat(&constat(
                    "COM-WIF-001",
                    Niveau::Moyen,
                    "Le Wi-Fi « Salon » accepte encore TKIP (2 bornes).",
                )),
                cle_constat(&constat(
                    "COM-DNS-002",
                    Niveau::Info,
                    "Le routeur distribue le DNS 10.0.0.1 à tous vos appareils.",
                )),
            ],
        };
        let apres = EtatAudit {
            textes: TEXTES,
            redirections: Some(redirections.iter().map(cle_redirection).collect()),
            constats: constats
                .iter()
                .filter(|c| surveille(c))
                .map(|c| cle_constat(c))
                .collect(),
        };
        assert_eq!(apres.constats.len(), 3);
        let alertes = nouveautes_audit(&avant, &apres, &redirections, &constats);
        let genres: Vec<Genre> = alertes.iter().map(|a| a.2).collect();
        assert_eq!(genres, [Genre::Passerelle, Genre::Passerelle, Genre::Machine]);
        assert!(
            alertes[0].1.contains("8080/tcp")
                && alertes[0].1.contains("10.0.0.30:80")
                && alertes[0].1.contains("Camera")
        );
        assert!(alertes[1].0.contains("DNS") && alertes[1].1.contains("203.0.113.9"));
        assert!(alertes[2].0.contains("IPv6"));
        // Rien de nouveau : aucune alerte ; redirections non lues à l'un des deux passages : pas comparées.
        assert_eq!(nouveautes_audit(&apres, &apres, &redirections, &constats).len(), 0);
        let non_lues = EtatAudit {
            redirections: None,
            ..EtatAudit::default()
        };
        let seulement = nouveautes_audit(&non_lues, &apres, &redirections, &constats);
        assert!(
            seulement
                .iter()
                .all(|a| a.2 != Genre::Passerelle || a.0.contains("DNS"))
        );
        // L'état se relit tel qu'il a été écrit.
        let relu: EtatAudit = serde_json::from_str(&serde_json::to_string(&apres).unwrap()).unwrap();
        assert_eq!(relu, apres);
    }

    #[test]
    fn surveillance_voulue_mais_disparue() {
        assert!(juger_disparition(false, false).is_none());
        assert!(juger_disparition(true, true).is_none());
        let c = juger_disparition(true, false).expect("constat");
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(!c.correctif.as_ref().unwrap().automatique);
    }

    /// Un état de la 0.86 (textes au tutoiement, « box ») face aux textes d'aujourd'hui : rien de nouveau, sauf un
    /// DNS du bail qui a vraiment changé d'adresse. Ensuite, la comparaison reprend par le texte.
    #[test]
    fn etat_d_autres_textes_compare_sans_les_textes() {
        let constat = |regle: &'static str, niveau: Niveau, message: &str| {
            let mut c = crate::machine::alerte("Wi-Fi", niveau, message);
            c.regle = regle;
            c
        };
        let wps = constat("COM-WIF-004", Niveau::Moyen, "Le WPS de votre routeur est actif.");
        let dns = |ip: &str| {
            constat(
                "COM-DNS-002",
                Niveau::Info,
                &format!("Le routeur distribue le DNS {ip} à tous vos appareils."),
            )
        };
        let avant: EtatAudit = serde_json::from_str(
            r#"{"redirections":[],"constats":["COM-WIF-004|Wi-Fi : Le WPS de ta box est actif.","COM-DNS-002|Wi-Fi : La box distribue le DNS 10.0.0.1 à tous tes appareils."]}"#,
        )
        .unwrap();
        assert_eq!(avant.textes, 0);
        let meme = dns("10.0.0.1");
        let constats = [&wps, &meme];
        let apres = EtatAudit {
            textes: TEXTES,
            redirections: Some(Vec::new()),
            constats: constats.iter().map(|c| cle_constat(c)).collect(),
        };
        assert_eq!(nouveautes_audit(&avant, &apres, &[], &constats), Vec::new());
        let detourne = dns("203.0.113.9");
        let constats = [&wps, &detourne];
        let apres = EtatAudit {
            constats: constats.iter().map(|c| cle_constat(c)).collect(),
            ..apres
        };
        let alertes = nouveautes_audit(&avant, &apres, &[], &constats);
        assert!(
            alertes.len() == 1 && alertes[0].1.contains("203.0.113.9"),
            "{alertes:?}"
        );
        // Même génération : le texte compte de nouveau.
        let autre = constat(
            "COM-WIF-004",
            Niveau::Moyen,
            "Le WPS de votre routeur « Bureau » est actif.",
        );
        let constats = [&autre, &detourne];
        let suivant = EtatAudit {
            constats: constats.iter().map(|c| cle_constat(c)).collect(),
            ..EtatAudit::default()
        };
        assert_eq!(nouveautes_audit(&apres, &suivant, &[], &constats).len(), 1);

        // Côté machine : une alerte sans clé, reformulée, ne renotifie pas face à un état d'avant.
        let mut ancien = etat(80, &["Mots de passe : Ton gestionnaire n'est pas verrouillé."]);
        ancien.textes = 0;
        let nouveau = etat(80, &["Mots de passe : Votre gestionnaire n'est pas verrouillé."]);
        assert_eq!(nouveautes_machine(&ancien, &nouveau), Vec::new());
        assert_eq!(
            nouveautes_machine(&etat(80, &["Mots de passe : Autre."]), &nouveau).len(),
            1
        );
    }
}
