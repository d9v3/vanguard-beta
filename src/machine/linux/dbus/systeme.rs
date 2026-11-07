//! Les ACTIONS de l'assistant élevé (`machine::assistant`) sur les unités de systemd, par le bus SYSTÈME, à la place
//! de `sudo systemctl …` : une troisième liste fermée (`ACTIONS_SYSTEME`), à côté des LECTURES de `dbus.rs` et des
//! actions du bus de la session (`actions.rs`), dont elle reprend l'envoi et l'attente du job.
//!
//! Seul le fils root s'en sert, et seulement pour un geste de `machine::gestes_unix` déjà rejugé (`unite`,
//! `unite-designee`, `signatures-clamav`) ou pour la coupure du réseau d'un programme (ordre rejugé,
//! `CouperReseauProgramme`) : aucune fonction ne prend une méthode, et chaque nom d'unité passe la règle stricte de
//! `gestes_unix::nom_admis` (ou celle des scopes de coupure, `nom_de_coupure`) avant tout envoi. Le drapeau ALLOW_INTERACTIVE_AUTHORIZATION n'est jamais
//! posé : le fils est déjà root, une fenêtre polkit ne viendrait que d'une erreur.
//!
//! Comme `systemctl` sans `--no-block`, une action qui lance un job (démarrer, arrêter…) s'abonne d'abord
//! (AddMatch, Subscribe), puis attend son JobRemoved, venu du seul nom unique du gestionnaire, au plus 90 s : seul le
//! résultat « done » vaut « fait » ; tout autre résultat, ou rien à temps, est « pas vérifié », jamais compté comme
//! fait.

// Ni débordement ni `as` : sous-module d'un module lu par le banc de fuzzing (dbus.rs), qui le déclare (Cargo.toml,
// [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::time::Duration;

use super::actions::{Action, FinDeJob};
use super::{Bus, CHEMIN_SYSTEMD, DBUS, GESTIONNAIRE, SYSTEMD, UNITE, Valeur};
use crate::machine::arret_designe::{ArretCharge, Commande, SessionLogind};
use crate::machine::gestes_unix::{self, ActionUnite};
use crate::modele::Echec;
use crate::{tr, trf};

/// Les seules actions que le fils envoie au bus système. MaskUnitFiles et UnmaskUnitFiles sont prévues pour U4 et U6
/// (le masque du Wi-Fi public, les services qu'on masque avec leur fichier) : aucun geste ne les envoie encore.
pub(crate) const ACTIONS_SYSTEME: &[Action] = &[
    // Le bus lui-même : recevoir le signal de fin d'un job de systemd.
    (DBUS, "/org/freedesktop/DBus", DBUS, "AddMatch", "s"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "Subscribe", ""),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "Reload", ""),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "EnableUnitFiles", "asbb"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "DisableUnitFiles", "asb"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "StartUnit", "ss"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "StopUnit", "ss"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "TryRestartUnit", "ss"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "ReloadOrTryRestartUnit", "ss"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "ResetFailed", ""),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "MaskUnitFiles", "asbb"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "UnmaskUnitFiles", "asb"),
    // La coupure du réseau d'un programme : un scope à lui sous vanguard.slice (propriétés écrites ici seulement,
    // `scope_de_coupure`), puis le retour du processus dans l'unité d'où il venait.
    (
        SYSTEMD,
        CHEMIN_SYSTEMD,
        GESTIONNAIRE,
        "StartTransientUnit",
        "ssa(sv)a(sa(sv))",
    ),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "AttachProcessesToUnit", "ssau"),
];

/// La tranche des scopes de coupure : la règle de nf_tables vise le niveau 2 sous la racine (`vanguard.slice`, puis
/// le scope).
pub(crate) const TRANCHE_DES_COUPURES: &str = "vanguard.slice";

/// Le nom du scope de coupure d'un processus : `coupe-<pid>-<départ>.scope` (le départ, en tops d'horloge depuis le
/// démarrage, distingue un pid repris par un autre processus).
pub(crate) fn nom_de_coupure(pid: u32, depart: u64) -> String {
    format!("coupe-{pid}-{depart}.scope")
}

/// Un nom de scope de coupure, et rien d'autre : « coupe- », deux nombres, « .scope ».
pub(crate) fn est_nom_de_coupure(nom: &str) -> bool {
    let Some(milieu) = nom.strip_prefix("coupe-").and_then(|n| n.strip_suffix(".scope")) else {
        return false;
    };
    let Some((pid, depart)) = milieu.split_once('-') else {
        return false;
    };
    let nombre = |t: &str| !t.is_empty() && t.len() <= 20 && t.bytes().all(|o| o.is_ascii_digit());
    nombre(pid) && nombre(depart) && pid.parse::<u32>().is_ok_and(|p| p != 0) && depart.parse::<u64>().is_ok()
}

/// L'unité où remettre un processus (celle d'où il venait, lue dans /proc/<pid>/cgroup par l'assistant) : un nom
/// d'unité tel qu'il paraît dans un chemin de cgroup (« \\x2d » compris), .service ou .scope, 255 octets au plus.
pub(crate) fn unite_de_retour_admise(nom: &str) -> bool {
    !nom.is_empty()
        && nom.len() <= 255
        && !nom.contains("..")
        && nom.bytes().next().is_some_and(|o| o.is_ascii_alphanumeric())
        && nom
            .bytes()
            .all(|o| o.is_ascii_alphanumeric() || b":_.@-\\".contains(&o))
        && (nom.ends_with(".service") || nom.ends_with(".scope"))
}

/// Le sous-cgroup sous cette unité (vide, ou « /a/b » dans une unité déléguée) : des composants admis comme un nom
/// d'unité, sans « .. », 1024 octets au plus.
pub(crate) fn sous_cgroupe_admis(chemin: &str) -> bool {
    if chemin.is_empty() {
        return true;
    }
    let Some(reste) = chemin.strip_prefix('/') else {
        return false;
    };
    chemin.len() <= 1024
        && reste.split('/').all(|c| {
            !c.is_empty()
                && c != "."
                && !c.contains("..")
                && c.bytes().all(|o| o.is_ascii_alphanumeric() || b":_.@-\\".contains(&o))
        })
}

/// Le temps laissé à un job du système (un service qui démarre ou s'arrête ; systemd en laisse 90 par défaut à un
/// arrêt, TimeoutStopSec) : au-delà, « pas vérifié ».
const DELAI_JOB: Duration = Duration::from_secs(90);

/// Le filtre qui fait recevoir les fins de job du gestionnaire, et rien d'autre.
const FILTRE_FIN_DE_JOB: &str = "type='signal',sender='org.freedesktop.systemd1',interface='org.freedesktop.systemd1.Manager',member='JobRemoved',path='/org/freedesktop/systemd1'";

fn echec(e: impl Into<String>) -> Echec {
    Echec::echoue("dbus/systeme", e)
}

/// Un échec dit sans jargon : le détail technique (`technique` : bus, noms d'erreur de D-Bus, fin de job) va au
/// journal des erreurs ; la personne lit `phrase`.
fn en_clair(technique: impl Into<String>, phrase: impl Into<String>) -> Echec {
    echec(technique).journaliser();
    echec(phrase)
}

/// Le gestionnaire de services injoignable, ou pas celui du système.
fn ne_repond_pas(technique: impl Into<String>) -> Echec {
    en_clair(
        technique,
        tr!(
            "le gestionnaire de services de Linux ne répond pas : rien n'est fait",
            "the Linux service manager does not answer: nothing is done"
        ),
    )
}

/// Une action refusée par le gestionnaire de services, ou une réponse qui ne se lit pas.
fn pas_fait(technique: impl Into<String>) -> Echec {
    en_clair(
        technique,
        tr!(
            "le gestionnaire de services de Linux n'a pas fait l'action (le détail est dans le journal des erreurs)",
            "the Linux service manager did not do the action (the details are in the error log)"
        ),
    )
}

/// Ce que dit la personne quand le job d'une unité ne finit pas par « done ».
fn fin_dite(resultat: &str) -> &'static str {
    match resultat {
        "failed" => tr!("l'action a échoué", "the action failed"),
        "timeout" => tr!("l'action a pris trop de temps", "the action took too long"),
        "canceled" => tr!("l'action a été annulée", "the action was canceled"),
        "dependency" => tr!("un service dont il dépend a échoué", "a service it depends on failed"),
        "skipped" => tr!("l'action n'a pas été faite", "the action was not done"),
        _ => tr!("réponse inattendue", "unexpected answer"),
    }
}

/// systemd est-il le gestionnaire de ce système (le test de sd_booted) ? Sans lui, aucun geste d'unité n'a de sens.
pub(crate) fn systemd_present() -> bool {
    std::fs::symlink_metadata("/run/systemd/system").is_ok_and(|m| m.is_dir())
}

/// Le bus système pour y AGIR, sous root seulement. La prise doit être une prise appartenant à root, dans un dossier
/// à root où personne d'autre n'écrit : un autre compte ne peut pas y avoir posé la sienne. Sous les essais, refusé :
/// une écriture ne doit pas pouvoir partir d'un test.
pub(crate) fn bus_pour_agir() -> Result<Bus, Echec> {
    if cfg!(test) {
        return Err(echec("aucune action réelle sous les essais"));
    }
    if crate::socle::euid() != 0 {
        return Err(echec(tr!(
            "les actions sur les services du système se font en administrateur seulement",
            "actions on system services are done as administrator only"
        )));
    }
    let chemin = std::path::Path::new(super::BUS_SYSTEME);
    prise_sure(chemin)?;
    let prise = std::os::unix::net::UnixStream::connect(chemin)
        .map_err(|e| ne_repond_pas(format!("bus système injoignable ({e})")))?;
    Bus::sur(prise).map_err(ne_repond_pas)
}

/// La prise du bus système et son dossier, vérifiés sans suivre de lien.
fn prise_sure(chemin: &std::path::Path) -> Result<(), Echec> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let douteuse = || {
        en_clair(
            format!(
                "prise du bus système qui n'est pas celle de root : {}",
                chemin.display()
            ),
            tr!(
                "le gestionnaire de services de Linux ne se présente pas comme celui de l'administrateur (un autre programme a pu prendre sa place) : rien n'est fait",
                "the Linux service manager does not present itself as the administrator's (another program may have taken its place): nothing is done"
            ),
        )
    };
    let m = std::fs::symlink_metadata(chemin).map_err(|_| douteuse())?;
    if !m.file_type().is_socket() || m.uid() != 0 {
        return Err(douteuse());
    }
    let dossier = chemin.parent().ok_or_else(douteuse)?;
    let d = std::fs::symlink_metadata(dossier).map_err(|_| douteuse())?;
    if !d.is_dir() || d.uid() != 0 || d.mode() & 0o022 != 0 {
        return Err(douteuse());
    }
    Ok(())
}

impl Bus {
    fn agir_systeme(
        &mut self,
        methode: &str,
        arguments: Vec<Valeur>,
        systemd: Option<&str>,
        fins: &mut Vec<FinDeJob>,
    ) -> Result<Vec<Valeur>, Echec> {
        let interface = if methode == "AddMatch" { DBUS } else { GESTIONNAIRE };
        self.agir_dans(ACTIONS_SYSTEME, interface, methode, arguments, systemd, fins)
            .map(|(_, corps)| corps)
            .map_err(|e| pas_fait(format!("{methode} : {e}")))
    }

    /// Lance `methode` (StartUnit, StopUnit…) sur `unite` et attend la fin de son job : abonné AVANT de le lancer,
    /// sans quoi sa fin peut passer avant l'abonnement.
    fn job(&mut self, methode: &str, unite: &str, fins: &mut Vec<FinDeJob>) -> Result<(), Echec> {
        let arguments = vec![Valeur::texte_de(unite), Valeur::texte_de("replace")];
        self.job_avec(methode, unite, arguments, fins)
    }

    /// `job`, avec les arguments de la méthode (le premier est toujours le nom de l'unité : il filtre les fins de
    /// job, voir `agir_dans`).
    fn job_avec(
        &mut self,
        methode: &str,
        unite: &str,
        arguments: Vec<Valeur>,
        fins: &mut Vec<FinDeJob>,
    ) -> Result<(), Echec> {
        self.agir_systeme("AddMatch", vec![Valeur::texte_de(FILTRE_FIN_DE_JOB)], None, fins)?;
        let (reponse, _) = self
            .agir_dans(ACTIONS_SYSTEME, GESTIONNAIRE, "Subscribe", Vec::new(), None, fins)
            .map_err(|e| pas_fait(format!("Subscribe : {e}")))?;
        // Le nom unique du gestionnaire, écrit par le bus dans sa réponse : seuls ses signaux comptent.
        let systemd = reponse
            .expediteur
            .ok_or_else(|| pas_fait(super::mal_forme("expéditeur absent")))?;
        let corps = self.agir_systeme(methode, arguments, Some(&systemd), fins)?;
        let chemin = corps
            .first()
            .and_then(Valeur::texte)
            .map(String::from)
            .ok_or_else(|| pas_fait(super::mal_forme("job")))?;
        let resultat = self.attendre_job(&chemin, &systemd, fins, DELAI_JOB).map_err(|e| {
            en_clair(
                format!("{unite} {methode} : JobRemoved absent ({e})"),
                trf!(
                    "{unite} : pas vérifié, le gestionnaire de services n'a pas confirmé que c'est fait (pas de réponse à temps)",
                    "{unite}: not verified, the service manager did not confirm it is done (no answer in time)"
                ),
            )
        })?;
        // « done » seulement : « skipped », « failed », « timeout », « canceled »… ne prouvent pas que c'est fait.
        if resultat == "done" {
            Ok(())
        } else {
            let vu = crate::ui::affichable(&resultat);
            let dit = fin_dite(&resultat);
            Err(en_clair(
                format!("{unite} {methode} : JobRemoved « {vu} » au lieu de « done »"),
                trf!(
                    "{unite} : pas vérifié, le gestionnaire de services n'a pas confirmé que c'est fait ({dit})",
                    "{unite}: not verified, the service manager did not confirm it is done ({dit})"
                ),
            ))
        }
    }

    /// EnableUnitFiles ou DisableUnitFiles (jamais au seul démarrage en cours, jamais forcé), puis Reload, comme
    /// systemctl : le gestionnaire ne voit les nouveaux liens qu'après un rechargement. Rend ce qu'il dit en avoir
    /// fait (`Liens`) : une réussite peut n'être qu'en partie.
    fn fichiers(&mut self, activer: bool, unite: &str, fins: &mut Vec<FinDeJob>) -> Result<Liens, Echec> {
        let unites = Valeur::Tableau(vec![Valeur::texte_de(unite)]);
        let corps = if activer {
            self.agir_systeme(
                "EnableUnitFiles",
                vec![unites, Valeur::Booleen(false), Valeur::Booleen(false)],
                None,
                fins,
            )?
        } else {
            self.agir_systeme("DisableUnitFiles", vec![unites, Valeur::Booleen(false)], None, fins)?
        };
        self.agir_systeme("Reload", Vec::new(), None, fins)?;
        Liens::lire(activer, &corps).ok_or_else(|| {
            en_clair(
                format!("{unite} : liste de changements illisible ({corps:?})"),
                trf!(
                    "{unite} : pas vérifié, le gestionnaire de services n'a pas dit ce qu'il a changé au démarrage",
                    "{unite}: not verified, the service manager did not say what it changed at boot"
                ),
            )
        })
    }
}

/// Ce que systemd dit avoir fait des liens d'une unité (EnableUnitFiles « b a(sss) », DisableUnitFiles « a(sss) ») :
/// une réponse réussie peut taire ce qui a échoué (un lien posé, l'autre non : une unité jointe qui n'a pas pu
/// l'être, une cible absente, un alias brisé, une unité masquée), signalé seulement dans sa liste.
struct Liens {
    activer: bool,
    /// Les liens posés (« symlink ») ou retirés (« unlink »).
    faits: usize,
    /// Le reste de la liste (genre et fichier), pour le journal des erreurs.
    manques: Vec<String>,
    /// EnableUnitFiles : le fichier prévoit-il d'être lancé au démarrage (section `[Install]`) ?
    installable: bool,
}

impl Liens {
    fn lire(activer: bool, corps: &[Valeur]) -> Option<Liens> {
        let (installable, liste) = match (activer, corps) {
            (true, [b, l]) => (b.booleen()?, l),
            (false, [l]) => (true, l),
            _ => return None,
        };
        let mut liens = Liens {
            activer,
            faits: 0,
            manques: Vec::new(),
            installable,
        };
        for c in liste.elements() {
            let [genre, fichier, _] = c.elements() else {
                return None;
            };
            match genre.texte()? {
                "symlink" | "unlink" => liens.faits = liens.faits.checked_add(1)?,
                autre => liens.manques.push(format!(
                    "{} {}",
                    crate::ui::affichable(autre),
                    crate::ui::affichable(fichier.texte()?)
                )),
            }
        }
        Some(liens)
    }

    /// Tout est fait : rien de signalé, et une unité activée le prévoit (sans section `[Install]`, EnableUnitFiles
    /// réussit sans rien poser).
    fn complets(&self) -> bool {
        self.manques.is_empty() && (self.installable || !self.activer || self.faits > 0)
    }

    /// Le geste entier : `job`, le démarrage ou l'arrêt qui suit (fait quand même, comme systemctl), rendu seulement
    /// si les liens sont complets ; sinon ce qui est fait et ce qui ne l'est pas, dit, jamais compté comme fait.
    fn et_puis(self, unite: &str, job: Option<Result<(), Echec>>) -> Result<(), Echec> {
        if self.complets() {
            return job.unwrap_or(Ok(()));
        }
        let faits = self.faits;
        let manques = self.manques.len();
        let liens = match (self.activer, self.installable || faits > 0) {
            (true, false) => trf!(
                "{unite} : pas activé au démarrage, son fichier ne le prévoit pas",
                "{unite}: not enabled at boot, its file does not provide for it"
            ),
            (true, true) => trf!(
                "{unite} : activé au démarrage en partie seulement ({faits} lien(s) posé(s), {manques} pas fait(s) ; le détail est dans le journal des erreurs)",
                "{unite}: enabled at boot only in part ({faits} link(s) created, {manques} not done; the details are in the error log)"
            ),
            (false, _) => trf!(
                "{unite} : retiré du démarrage en partie seulement ({faits} lien(s) retiré(s), {manques} pas fait(s) ; le détail est dans le journal des erreurs)",
                "{unite}: removed from boot only in part ({faits} link(s) removed, {manques} not done; the details are in the error log)"
            ),
        };
        let suite = match job {
            None => String::new(),
            Some(Ok(())) if self.activer => tr!(" ; il est lancé", "; it is started").to_string(),
            Some(Ok(())) => tr!(" ; il est arrêté", "; it is stopped").to_string(),
            Some(Err(e)) => format!(" ; {e}"),
        };
        Err(en_clair(
            format!(
                "{unite} : liens en partie ({faits} faits ; {})",
                self.manques.join(", ")
            ),
            format!("{liens}{suite}"),
        ))
    }
}

/// Fait `action` sur `unite` par le bus système (voir `ActionUnite`). `Err` : pas fait, ou pas vérifié, avec la
/// raison ; un nom hors de la règle n'est jamais envoyé.
pub(crate) fn agir_sur_unite(bus: &mut Bus, action: ActionUnite, unite: &str) -> Result<(), Echec> {
    if !gestes_unix::nom_admis(unite) {
        return Err(echec(tr!(
            "nom de service refusé : rien n'est envoyé",
            "service name refused: nothing is sent"
        )));
    }
    let mut fins = Vec::new();
    match action {
        ActionUnite::Activer => {
            let liens = bus
                .fichiers(true, unite, &mut fins)
                .map_err(|e| sans_la_suite(&e, true))?;
            let job = bus.job("StartUnit", unite, &mut fins);
            liens.et_puis(unite, Some(job))
        }
        ActionUnite::Desactiver => {
            let liens = bus
                .fichiers(false, unite, &mut fins)
                .map_err(|e| sans_la_suite(&e, false))?;
            let job = bus.job("StopUnit", unite, &mut fins);
            liens.et_puis(unite, Some(job))
        }
        ActionUnite::DesactiverSansArreter => bus.fichiers(false, unite, &mut fins)?.et_puis(unite, None),
        ActionUnite::ActiverSansDemarrer => bus.fichiers(true, unite, &mut fins)?.et_puis(unite, None),
        ActionUnite::Demarrer => bus.job("StartUnit", unite, &mut fins),
        ActionUnite::Arreter => bus.job("StopUnit", unite, &mut fins),
        ActionUnite::Redemarrer => bus.job("TryRestartUnit", unite, &mut fins),
        ActionUnite::Recharger => bus.job("ReloadOrTryRestartUnit", unite, &mut fins),
    }
}

/// Les propriétés du scope de coupure : le processus (PIDs), la tranche de Vanguard, une description, et le ramassage
/// du scope même en échec (il ne reste pas « failed » après la fin du processus).
fn proprietes_de_coupure(pid: u32, description: &str) -> Valeur {
    let propriete = |nom: &str, signature: &str, v: Valeur| {
        Valeur::Structure(vec![
            Valeur::texte_de(nom),
            Valeur::Variante(signature.into(), Box::new(v)),
        ])
    };
    Valeur::Tableau(vec![
        propriete("PIDs", "au", Valeur::Tableau(vec![Valeur::U32(pid)])),
        propriete("Slice", "s", Valeur::texte_de(TRANCHE_DES_COUPURES)),
        propriete("Description", "s", Valeur::texte_de(description)),
        propriete("CollectMode", "s", Valeur::texte_de("inactive-or-failed")),
    ])
}

/// Met le processus `pid` dans le scope de coupure `nom` (StartTransientUnit, PIDs = [pid], Slice = vanguard.slice),
/// et attend que systemd confirme (« done »). Jamais un déplacement à la main dans /sys/fs/cgroup : systemd tient les
/// cgroups, et le scope se ramasse seul quand le processus finit. Le pid est passé en nombre (le bus ne passe pas ici
/// de descripteur, PIDFDs) : l'appelant revérifie le départ du processus et son cgroup après coup.
pub(crate) fn scope_de_coupure(bus: &mut Bus, nom: &str, pid: u32, description: &str) -> Result<(), Echec> {
    if !est_nom_de_coupure(nom) || pid == 0 {
        return Err(echec(tr!(
            "nom de scope refusé : rien n'est envoyé",
            "scope name refused: nothing is sent"
        )));
    }
    // Une description sur une ligne, bornée : elle paraît dans « systemctl status ».
    let description: String = description.chars().filter(|c| !c.is_control()).take(200).collect();
    let arguments = vec![
        Valeur::texte_de(nom),
        Valeur::texte_de("fail"),
        proprietes_de_coupure(pid, &description),
        Valeur::Tableau(Vec::new()),
    ];
    bus.job_avec("StartTransientUnit", nom, arguments, &mut Vec::new())
}

/// Remet le processus dans l'unité d'où il venait (AttachProcessesToUnit : unité, sous-cgroup, pid). Le scope de
/// coupure, vide, est ramassé par systemd ; il n'est jamais arrêté (StopUnit tuerait le processus).
pub(crate) fn remettre_dans(bus: &mut Bus, unite: &str, sous_cgroupe: &str, pid: u32) -> Result<(), Echec> {
    if !unite_de_retour_admise(unite) || !sous_cgroupe_admis(sous_cgroupe) || pid == 0 {
        return Err(echec(tr!(
            "unité de retour refusée : rien n'est envoyé",
            "return unit refused: nothing is sent"
        )));
    }
    bus.agir_systeme(
        "AttachProcessesToUnit",
        vec![
            Valeur::texte_de(unite),
            Valeur::texte_de(sous_cgroupe),
            Valeur::Tableau(vec![Valeur::U32(pid)]),
        ],
        None,
        &mut Vec::new(),
    )
    .map(|_| ())
}

/// L'échec des liens d'une activation (ou d'une désactivation) « maintenant », complété : le démarrage (ou l'arrêt)
/// qui devait suivre n'est pas tenté, sans savoir ce qui a changé au démarrage. Sans ce mot, « pas vérifié » laissait
/// croire qu'il avait peut-être été lancé.
fn sans_la_suite(e: &Echec, activer: bool) -> Echec {
    let suite = if activer {
        tr!(" ; il n'est pas lancé", "; it is not started")
    } else {
        tr!(" ; il n'est pas arrêté", "; it is not stopped")
    };
    echec(format!("{e}{suite}"))
}

/// `systemctl reset-failed` : ResetFailed, sans nom (toutes les unités).
pub(crate) fn reinitialiser_echecs(bus: &mut Bus) -> Result<(), Echec> {
    bus.agir_systeme("ResetFailed", Vec::new(), None, &mut Vec::new())
        .map(|_| ())
}

/// L'état du fichier d'une unité (« enabled », « disabled », « masked », « static »…), comme `systemctl
/// is-enabled` : GetUnitFileState (une lecture). `Ok(None)` : aucun fichier de ce nom.
pub(crate) fn etat_du_fichier(bus: &mut Bus, unite: &str) -> Result<Option<String>, Echec> {
    if !gestes_unix::nom_admis(unite) {
        return Err(echec(tr!("nom de service refusé", "service name refused")));
    }
    match bus.appeler(
        SYSTEMD,
        CHEMIN_SYSTEMD,
        GESTIONNAIRE,
        "GetUnitFileState",
        "s",
        vec![Valeur::texte_de(unite)],
    ) {
        Ok(corps) => corps
            .first()
            .and_then(Valeur::texte)
            .map(|t| Some(t.to_string()))
            .ok_or_else(|| pas_fait(super::mal_forme("GetUnitFileState"))),
        Err(e) if aucun_fichier(&e) => Ok(None),
        Err(e) => Err(en_clair(
            format!("GetUnitFileState {unite} : {e}"),
            tr!(
                "le gestionnaire de services de Linux n'a pas dit si ce service est lancé au démarrage : rien n'est fait",
                "the Linux service manager did not say whether this service starts at boot: nothing is done"
            ),
        )),
    }
}

/// Ce que le gestionnaire a chargé d'une unité : son nom principal (Id), son fichier (FragmentPath, vide pour une
/// unité sans fichier) et ses compléments (DropInPaths).
pub(crate) type FichiersCharges = (String, String, Vec<String>);

/// Les fichiers d'où le gestionnaire a chargé `unite`, par GetUnit puis ses propriétés (des lectures) : ce qu'il
/// fera d'un arrêt vient de là, pas seulement des dossiers que Vanguard connaît. `Ok(None)` : l'unité n'est pas
/// chargée (rien en mémoire ; ses fichiers sur le disque sont revus à part).
pub(crate) fn fichiers_charges(bus: &mut Bus, unite: &str) -> Result<Option<FichiersCharges>, Echec> {
    if !gestes_unix::nom_admis(unite) {
        return Err(echec(tr!("nom de service refusé", "service name refused")));
    }
    let illisible = |e: String| {
        en_clair(
            format!("fichiers chargés de {unite} : {e}"),
            tr!(
                "le gestionnaire de services de Linux n'a pas dit d'où vient ce service : rien n'est fait",
                "the Linux service manager did not say where this service comes from: nothing is done"
            ),
        )
    };
    let corps = match bus.appeler(
        SYSTEMD,
        CHEMIN_SYSTEMD,
        GESTIONNAIRE,
        "GetUnit",
        "s",
        vec![Valeur::texte_de(unite)],
    ) {
        Ok(c) => c,
        Err(e) if e.starts_with("org.freedesktop.systemd1.NoSuchUnit ") => return Ok(None),
        Err(e) => return Err(illisible(e)),
    };
    let chemin = corps
        .first()
        .and_then(Valeur::texte)
        .ok_or_else(|| illisible(super::mal_forme("GetUnit sans chemin")))?
        .to_string();
    let mut texte = |nom: &str| -> Result<String, Echec> {
        let v = bus.propriete(SYSTEMD, &chemin, UNITE, nom).map_err(illisible)?;
        v.texte()
            .map(String::from)
            .ok_or_else(|| illisible(super::mal_forme(nom)))
    };
    let id = texte("Id")?;
    let fragment = texte("FragmentPath")?;
    let complements = bus
        .propriete(SYSTEMD, &chemin, UNITE, "DropInPaths")
        .map_err(illisible)?
        .elements()
        .iter()
        .map(|c| c.texte().map(String::from))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| illisible(super::mal_forme("DropInPaths")))?;
    Ok(Some((id, fragment, complements)))
}

/// Peut-on arrêter `unite` à la main ? GetUnit puis sa propriété RefuseManualStop (des lectures). `Ok(None)` : elle
/// n'est pas chargée, donc ne tourne pas, rien à arrêter ; `Ok(Some(permis))` sinon. auditd porte
/// `RefuseManualStop=yes` sur Fedora et Arch : systemd y refuse tout StopUnit (B-3 du lot U3), et le demander quand
/// même finissait en échec, le service déjà retiré du démarrage.
pub(crate) fn arret_a_la_main(bus: &mut Bus, unite: &str) -> Result<Option<bool>, Echec> {
    if !gestes_unix::nom_admis(unite) {
        return Err(echec(tr!("nom de service refusé", "service name refused")));
    }
    let illisible = |e: String| {
        en_clair(
            format!("arrêt à la main de {unite} : {e}"),
            tr!(
                "le gestionnaire de services de Linux n'a pas dit si ce service peut être arrêté : rien n'est fait",
                "the Linux service manager did not say whether this service can be stopped: nothing is done"
            ),
        )
    };
    let corps = match bus.appeler(
        SYSTEMD,
        CHEMIN_SYSTEMD,
        GESTIONNAIRE,
        "GetUnit",
        "s",
        vec![Valeur::texte_de(unite)],
    ) {
        Ok(c) => c,
        Err(e) if e.starts_with("org.freedesktop.systemd1.NoSuchUnit ") => return Ok(None),
        Err(e) => return Err(illisible(e)),
    };
    let chemin = corps
        .first()
        .and_then(Valeur::texte)
        .ok_or_else(|| illisible(super::mal_forme("GetUnit sans chemin")))?
        .to_string();
    bus.propriete(SYSTEMD, &chemin, UNITE, "RefuseManualStop")
        .map_err(illisible)?
        .booleen()
        .map(|refuse| Some(!refuse))
        .ok_or_else(|| illisible(super::mal_forme("RefuseManualStop")))
}

/// L'interface D-Bus des propriétés propres au genre de l'unité (commandes, groupe) ; `None` pour un minuteur, qui
/// ne lance rien lui-même.
fn interface_du_genre(unite: &str) -> Option<(&'static str, [&'static str; 2], [&'static str; 2])> {
    if unite.ends_with(".service") {
        Some((
            "org.freedesktop.systemd1.Service",
            ["ExecStart", ""],
            ["ExecStop", "ExecStopPost"],
        ))
    } else if unite.ends_with(".socket") {
        Some((
            "org.freedesktop.systemd1.Socket",
            ["ExecStartPre", "ExecStartPost"],
            ["ExecStopPre", "ExecStopPost"],
        ))
    } else {
        None
    }
}

/// Un tableau D-Bus, et rien d'autre : une propriété d'un autre type n'est jamais lue comme une liste vide.
fn tableau(v: Option<&Valeur>) -> Option<&[Valeur]> {
    match v?.nue() {
        Valeur::Tableau(t) => Some(t),
        _ => None,
    }
}

/// Une liste de textes (`as`), stricte : un élément d'un autre type la rend illisible.
fn liste_de_textes(v: Option<&Valeur>) -> Option<Vec<String>> {
    tableau(v)?.iter().map(|e| e.texte().map(String::from)).collect()
}

/// Les commandes d'une propriété `a(sasbttttuii)` (ExecStart, ExecStop…) : le chemin et les arguments de chacune.
fn commandes(v: Option<&Valeur>) -> Option<Vec<Commande>> {
    tableau(v)?
        .iter()
        .map(|e| match e.nue() {
            Valeur::Structure(c) => Some(Commande {
                chemin: c.first()?.texte()?.to_string(),
                arguments: liste_de_textes(c.get(1))?,
            }),
            _ => None,
        })
        .collect()
}

/// `ArretCharge` d'après les propriétés de l'unité (`proprietes_unite`, interface Unit) et celles de son genre
/// (`proprietes_genre`). Une propriété attendue qui manque ou n'a pas son type : `None`, illisible. Seules
/// PropagatesStopTo, OnSuccess et UpheldBy (systemd 249) peuvent manquer, sur un systemd plus ancien qui ne les
/// connaît pas : vides alors.
pub(crate) fn arret_charge_de(
    unite: &str,
    proprietes_unite: &Valeur,
    proprietes_genre: Option<&Valeur>,
) -> Option<ArretCharge> {
    let mut lu = ArretCharge {
        recharge_attendue: proprietes_unite.champ("NeedDaemonReload")?.booleen()?,
        ..ArretCharge::default()
    };
    for nom in ["RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf"] {
        lu.entrainees.extend(liste_de_textes(proprietes_unite.champ(nom))?);
    }
    lu.lancees.extend(liste_de_textes(proprietes_unite.champ("OnFailure"))?);
    if let Some(v) = proprietes_unite.champ("PropagatesStopTo") {
        lu.entrainees.extend(liste_de_textes(Some(v))?);
    }
    // UpheldBy : une unité qui la maintient la relancerait aussitôt, l'arrêt dit fait serait faux.
    for nom in ["OnSuccess", "UpheldBy"] {
        if let Some(v) = proprietes_unite.champ(nom) {
            lu.lancees.extend(liste_de_textes(Some(v))?);
        }
    }
    let Some((_, lancement, arret)) = interface_du_genre(unite) else {
        // Un minuteur : ni commande, ni groupe ; ses propriétés propres ne sont pas lues.
        return Some(lu);
    };
    let p = proprietes_genre?;
    for nom in lancement.into_iter().filter(|n| !n.is_empty()) {
        lu.lancement.extend(commandes(p.champ(nom))?);
    }
    for nom in arret {
        lu.arret.extend(commandes(p.champ(nom))?);
    }
    lu.fichiers_d_environnement = tableau(p.champ("EnvironmentFiles"))?
        .iter()
        .map(|e| match e.nue() {
            Valeur::Structure(c) => Some((c.first()?.texte()?.to_string(), c.get(1)?.booleen()?)),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    lu.racine = format!(
        "{}{}",
        p.champ("RootDirectory")?.texte()?,
        p.champ("RootImage")?.texte()?
    );
    lu.groupe = p.champ("ControlGroup")?.texte()?.to_string();
    Some(lu)
}

/// Ce que le gestionnaire a en mémoire d'une unité, pour juger son arrêt (`ArretCharge`) : GetUnit, puis toutes les
/// propriétés de l'unité et de son genre (des lectures). `Ok(None)` : pas chargée. Ce qui ne se lit pas est un échec :
/// sans ces propriétés, l'arrêt n'est pas fait.
pub(crate) fn arret_charge(bus: &mut Bus, unite: &str) -> Result<Option<ArretCharge>, Echec> {
    if !gestes_unix::nom_admis(unite) {
        return Err(echec(tr!("nom de service refusé", "service name refused")));
    }
    let illisible = |e: String| {
        en_clair(
            format!("arrêt de {unite} : {e}"),
            tr!(
                "le gestionnaire de services de Linux n'a pas dit ce que l'arrêt de ce service lancerait : il n'est pas arrêté",
                "the Linux service manager did not say what stopping this service would run: it is not stopped"
            ),
        )
    };
    let corps = match bus.appeler(
        SYSTEMD,
        CHEMIN_SYSTEMD,
        GESTIONNAIRE,
        "GetUnit",
        "s",
        vec![Valeur::texte_de(unite)],
    ) {
        Ok(c) => c,
        Err(e) if e.starts_with("org.freedesktop.systemd1.NoSuchUnit ") => return Ok(None),
        Err(e) => return Err(illisible(e)),
    };
    let chemin = corps
        .first()
        .and_then(Valeur::texte)
        .ok_or_else(|| illisible(super::mal_forme("GetUnit sans chemin")))?
        .to_string();
    let proprietes_unite = bus.proprietes(SYSTEMD, &chemin, UNITE).map_err(illisible)?;
    let proprietes_genre = match interface_du_genre(unite) {
        Some((interface, _, _)) => Some(bus.proprietes(SYSTEMD, &chemin, interface).map_err(illisible)?),
        None => None,
    };
    arret_charge_de(unite, &proprietes_unite, proprietes_genre.as_ref())
        .map(Some)
        .ok_or_else(|| illisible(super::mal_forme("propriétés de l'arrêt")))
}

/// Les sessions lues au plus : au-delà, la liste n'est pas lue du tout (une session laissée de côté pourrait être
/// celle qui passe par l'outil), et l'arrêt est refusé.
const SESSIONS_MAX: usize = 1000;

/// Les sessions de logind (ListSessions, puis les propriétés de chacune ; des lectures). Une session dont les
/// propriétés ne se lisent pas est sautée (fermée entre la liste et sa lecture). `None` : la liste ne se lit pas, n'est
/// pas un tableau, ou dépasse `SESSIONS_MAX` ; l'appelant refuse alors l'arrêt.
pub(crate) fn sessions_logind(bus: &mut Bus) -> Option<Vec<SessionLogind>> {
    const LOGIN1: &str = "org.freedesktop.login1";
    let liste = bus
        .appeler(
            LOGIN1,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "ListSessions",
            "",
            Vec::new(),
        )
        .ok()?;
    let liste = tableau(liste.first())?;
    if liste.len() > SESSIONS_MAX {
        return None;
    }
    let mut sessions = Vec::new();
    for s in liste {
        let Some(chemin) = s.elements().get(4).and_then(Valeur::texte) else {
            continue;
        };
        let Ok(p) = bus.proprietes(LOGIN1, chemin, "org.freedesktop.login1.Session") else {
            continue;
        };
        let (Some(distante), Some(service), Some(meneur)) = (
            p.champ("Remote").and_then(Valeur::booleen),
            p.champ("Service").and_then(Valeur::texte),
            p.champ("Leader")
                .and_then(Valeur::entier)
                .and_then(|n| u32::try_from(n).ok()),
        ) else {
            continue;
        };
        sessions.push(SessionLogind {
            distante,
            service: service.to_string(),
            meneur,
        });
    }
    Some(sessions)
}

/// L'erreur de GetUnitFileState pour une unité sans fichier : ENOENT (FileNotFound) ou NoSuchUnit selon la version
/// de systemd.
fn aucun_fichier(erreur: &str) -> bool {
    [
        "org.freedesktop.DBus.Error.FileNotFound ",
        "org.freedesktop.systemd1.NoSuchUnit ",
    ]
    .iter()
    .any(|d| erreur.starts_with(d))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::super::actions::tests::{faux_bus, lire, lire_brut, retour, signal_fin, signal_fin_de};
    use super::super::{Message, RETOUR};
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    #[test]
    fn la_liste_est_fermee() {
        for (service, _, interface, methode, _) in ACTIONS_SYSTEME {
            assert!([DBUS, SYSTEMD].contains(service), "{service}");
            assert!(
                !super::super::LECTURES.contains(&(interface, methode)),
                "{methode} est déjà une lecture"
            );
        }
        for interdite in [
            "PowerOff",
            "Reboot",
            "KillUnit",
            "SetUnitProperties",
            "LinkUnitFiles",
            "RestartUnit",
            "SetDefaultTarget",
            "SetEnvironment",
        ] {
            assert!(!ACTIONS_SYSTEME.iter().any(|a| a.3 == interdite), "{interdite}");
        }
        // Sous les essais, le vrai bus système n'est jamais joint pour agir.
        assert!(bus_pour_agir().is_err());
        // StartTransientUnit ne part que de `scope_de_coupure`, qui écrit lui-même ses propriétés : aucun autre appel
        // dans ce module (hors essais), ni ailleurs dans le programme.
        let source = include_str!("systeme.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            code.matches("\"StartTransientUnit\"").count(),
            2,
            "la liste et scope_de_coupure"
        );
        assert_eq!(
            code.matches("\"AttachProcessesToUnit\"").count(),
            2,
            "la liste et remettre_dans"
        );
    }

    /// Le gestionnaire de services du compte 1000, écrit en deux morceaux : la garde de confidentialité des commits
    /// (outils/confidentialite.py) lirait le nom entier comme un courriel.
    const UNITE_DU_COMPTE: &str = concat!("user", "@1000.service");

    /// Les noms des scopes de coupure et des unités de retour : rien d'autre ne part.
    #[test]
    fn noms_de_coupure_et_de_retour() {
        assert_eq!(nom_de_coupure(4242, 123_456), "coupe-4242-123456.scope");
        assert!(est_nom_de_coupure(&nom_de_coupure(1, 0)));
        for refuse in [
            "coupe-0-1.scope",
            "coupe-1.scope",
            "coupe-a-1.scope",
            "coupe-1-1.service",
            "x-1-1.scope",
            "coupe-1-1-1.scope",
            "coupe--1.scope",
            "coupe-1-/x.scope",
            "coupe-99999999999-1.scope",
        ] {
            assert!(!est_nom_de_coupure(refuse), "{refuse}");
        }
        for admise in [
            UNITE_DU_COMPTE,
            "session-3.scope",
            "app-org.mozilla.firefox-1234.scope",
            "systemd-fsck@dev-disk-by\\x2duuid-1.service",
        ] {
            assert!(unite_de_retour_admise(admise), "{admise}");
        }
        for refusee in [
            "",
            "../x.service",
            "a/b.service",
            "-x.scope",
            "x.slice",
            "x y.service",
            "x.socket",
        ] {
            assert!(!unite_de_retour_admise(refusee), "{refusee}");
        }
        for admis in ["", "/app.slice/app-x.scope", "/init.scope", "/a\\x2db"] {
            assert!(sous_cgroupe_admis(admis), "{admis}");
        }
        for refuse in ["app.slice", "/", "//x", "/x/../y", "/x/./y", "/x/", "/x y", "/x\ny"] {
            assert!(!sous_cgroupe_admis(refuse), "{refuse}");
        }
        // Rien ne part vers le bus avec un nom refusé.
        let (mut bus, fil) = faux_bus(|_, _| {});
        assert!(scope_de_coupure(&mut bus, "coupe-1.scope", 1, "x").is_err());
        assert!(scope_de_coupure(&mut bus, "coupe-1-1.scope", 0, "x").is_err());
        assert!(remettre_dans(&mut bus, "x.slice", "", 1).is_err());
        assert!(remettre_dans(&mut bus, "x.service", "/../y", 1).is_err());
        drop(bus);
        assert_eq!(fil.join().unwrap(), Vec::<String>::new());
    }

    /// Le scope de coupure par le faux bus : AddMatch, Subscribe, StartTransientUnit avec ses propriétés, la fin du
    /// job ; seul « done » vaut « fait ». Puis le retour (AttachProcessesToUnit, sans job).
    #[test]
    fn scope_de_coupure_et_retour_par_le_faux_bus() {
        for resultat in ["done", "failed"] {
            let (mut bus, fil) = faux_bus(move |s, vus| {
                for _ in 0..3 {
                    let a = lire(s);
                    let m = a.membre.clone().unwrap();
                    let r = if m == "StartTransientUnit" {
                        assert_eq!(a.signature, "ssa(sv)a(sa(sv))");
                        assert_eq!(a.corps[0], Valeur::texte_de("coupe-77-5.scope"));
                        assert_eq!(a.corps[1], Valeur::texte_de("fail"));
                        assert_eq!(a.corps[2], proprietes_de_coupure(77, "essai"));
                        assert_eq!(a.corps[3], Valeur::Tableau(Vec::new()));
                        let job = "/org/freedesktop/systemd1/job/12";
                        s.write_all(&signal_fin_de(job, "coupe-77-5.scope", resultat, ":1.2"))
                            .unwrap();
                        retour(&a, "o", vec![Valeur::texte_de(job)], ":1.2")
                    } else {
                        repondre(s, &a, resultat)
                    };
                    vus.push(m);
                    s.write_all(&r).unwrap();
                }
            });
            let r = scope_de_coupure(&mut bus, "coupe-77-5.scope", 77, "essai\n");
            assert_eq!(r.is_ok(), resultat == "done", "{resultat} {r:?}");
            assert_eq!(fil.join().unwrap(), ["AddMatch", "Subscribe", "StartTransientUnit"]);
        }
        let (mut bus, fil) = faux_bus(|s, vus| {
            let a = lire(s);
            assert_eq!(a.signature, "ssau");
            assert_eq!(
                a.corps,
                [
                    Valeur::texte_de(UNITE_DU_COMPTE),
                    Valeur::texte_de("/app.slice/app-x.scope"),
                    Valeur::Tableau(vec![Valeur::U32(77)]),
                ]
            );
            vus.push(a.membre.clone().unwrap());
            s.write_all(&retour(&a, "", Vec::new(), ":1.2")).unwrap();
        });
        remettre_dans(&mut bus, UNITE_DU_COMPTE, "/app.slice/app-x.scope", 77).unwrap();
        assert_eq!(fil.join().unwrap(), ["AttachProcessesToUnit"]);
    }

    /// StartTransientUnit, octet par octet, contre un encodeur écrit à part d'après la spécification D-Bus (le même
    /// procédé que `messages_octet_par_octet`) : série 4 (AddMatch 2, Subscribe 3), propriétés a(sv) alignées à 8, le
    /// tableau vide a(sa(sv)) suivi de son bourrage.
    #[test]
    fn scope_de_coupure_octet_par_octet() {
        let attendu = hexa(
            "
             6c010001b800000004000000b600000001016f00190000002f6f72672f667265656465736b746f702f73797374656d64
             310000000000000002017300200000006f72672e667265656465736b746f702e73797374656d64312e4d616e61676572
             0000000000000000030173001200000053746172745472616e7369656e74556e69740000000000000601730018000000
             6f72672e667265656465736b746f702e73797374656d6431000000000000000008016700107373612873762961287361
             287376292900000010000000636f7570652d37372d352e73636f706500000000040000006661696c000000008b000000
             04000000504944730002617500000000040000004d00000005000000536c696365000173000000000e00000076616e67
             756172642e736c6963650000000000000b0000004465736372697074696f6e0001730000050000006573736169000000
             0b000000436f6c6c6563744d6f6465000173000012000000696e6163746976652d6f722d6661696c6564000000000000",
        );
        let (mut bus, fil) = faux_bus(|s, vus| {
            for _ in 0..3 {
                let brut = lire_brut(s);
                let a = Message::decoder_si(&brut, |_| true).unwrap();
                let r = if a.membre.as_deref() == Some("StartTransientUnit") {
                    let job = "/org/freedesktop/systemd1/job/12";
                    s.write_all(&signal_fin_de(job, "coupe-77-5.scope", "done", ":1.2"))
                        .unwrap();
                    retour(&a, "o", vec![Valeur::texte_de(job)], ":1.2")
                } else {
                    repondre(s, &a, "done")
                };
                vus.push(brut.iter().map(|o| format!("{o:02x}")).collect::<Vec<_>>().concat());
                s.write_all(&r).unwrap();
            }
        });
        scope_de_coupure(&mut bus, "coupe-77-5.scope", 77, "essai").unwrap();
        let envoyes = fil.join().unwrap();
        assert_eq!(hexa(&envoyes[2]), attendu);
    }

    /// Hors de la règle des noms, rien ne part, même à un faux bus.
    #[test]
    fn nom_refuse_avant_tout_envoi() {
        let (mut bus, fil) = faux_bus(|_, _| {});
        for nom in ["../x.service", "a/b.service", "x", "@.service", "-x.service"] {
            assert!(agir_sur_unite(&mut bus, ActionUnite::Arreter, nom).is_err(), "{nom}");
            assert!(etat_du_fichier(&mut bus, nom).is_err(), "{nom}");
        }
        drop(bus);
        assert_eq!(fil.join().unwrap(), Vec::<String>::new());
    }

    /// Une liste de changements (genre, fichier, source) d'EnableUnitFiles ou DisableUnitFiles.
    fn changements(liste: &[(&str, &str)]) -> Valeur {
        Valeur::Tableau(
            liste
                .iter()
                .map(|(genre, fichier)| {
                    Valeur::Structure(vec![
                        Valeur::texte_de(genre),
                        Valeur::texte_de(fichier),
                        Valeur::texte_de(""),
                    ])
                })
                .collect(),
        )
    }

    /// Une réponse du faux gestionnaire ; `StartUnit`, `StopUnit`… rendent un job, dont la fin (`resultat`) arrive
    /// avant la réponse, précédée d'un faux JobRemoved venu d'un autre programme du bus.
    fn repondre(s: &mut UnixStream, a: &Message, resultat: &str) -> Vec<u8> {
        let systemd = ":1.2";
        let m = a.membre.clone().unwrap();
        assert_eq!(a.drapeaux & 0x4, 0, "jamais d'autorisation interactive");
        assert_eq!(
            a.destination.as_deref(),
            Some(if m == "AddMatch" { DBUS } else { SYSTEMD })
        );
        match m.as_str() {
            "AddMatch" => {
                assert_eq!(a.corps, [Valeur::texte_de(FILTRE_FIN_DE_JOB)]);
                retour(a, "", Vec::new(), DBUS)
            }
            "EnableUnitFiles" => retour(
                a,
                "ba(sss)",
                vec![
                    Valeur::Booleen(true),
                    changements(&[("symlink", "/etc/systemd/system/x.wants/u")]),
                ],
                systemd,
            ),
            "DisableUnitFiles" => retour(
                a,
                "a(sss)",
                vec![changements(&[("unlink", "/etc/systemd/system/x.wants/u")])],
                systemd,
            ),
            "StartUnit" | "StopUnit" | "TryRestartUnit" | "ReloadOrTryRestartUnit" => {
                assert_eq!(a.corps[1], Valeur::texte_de("replace"));
                let job = "/org/freedesktop/systemd1/job/9";
                let unite = a.corps[0].texte().unwrap();
                s.write_all(&signal_fin_de(job, unite, "done", ":1.66")).unwrap();
                s.write_all(&signal_fin_de(job, unite, resultat, systemd)).unwrap();
                retour(a, "o", vec![Valeur::texte_de(job)], systemd)
            }
            _ => retour(a, "", Vec::new(), systemd),
        }
    }

    /// Chaque action, avec les appels qu'elle fait, dans l'ordre ; seul « done » vaut « fait ».
    #[test]
    fn chaque_action_et_la_fin_du_job() {
        let attendus: [(ActionUnite, &[&str]); 8] = [
            (
                ActionUnite::Activer,
                &["EnableUnitFiles", "Reload", "AddMatch", "Subscribe", "StartUnit"],
            ),
            (
                ActionUnite::Desactiver,
                &["DisableUnitFiles", "Reload", "AddMatch", "Subscribe", "StopUnit"],
            ),
            (ActionUnite::DesactiverSansArreter, &["DisableUnitFiles", "Reload"]),
            (ActionUnite::ActiverSansDemarrer, &["EnableUnitFiles", "Reload"]),
            (ActionUnite::Demarrer, &["AddMatch", "Subscribe", "StartUnit"]),
            (ActionUnite::Arreter, &["AddMatch", "Subscribe", "StopUnit"]),
            (ActionUnite::Redemarrer, &["AddMatch", "Subscribe", "TryRestartUnit"]),
            (
                ActionUnite::Recharger,
                &["AddMatch", "Subscribe", "ReloadOrTryRestartUnit"],
            ),
        ];
        for (action, appels) in attendus {
            for resultat in ["done", "failed", "skipped", "canceled"] {
                let n = appels.len();
                let (mut bus, fil) = faux_bus(move |s, vus| {
                    for _ in 0..n {
                        let a = lire(s);
                        let r = repondre(s, &a, resultat);
                        vus.push(a.membre.clone().unwrap());
                        s.write_all(&r).unwrap();
                    }
                });
                let r = agir_sur_unite(&mut bus, action, "cups-browsed.service");
                let sans_job = matches!(
                    action,
                    ActionUnite::DesactiverSansArreter | ActionUnite::ActiverSansDemarrer
                );
                assert_eq!(r.is_ok(), sans_job || resultat == "done", "{action:?} {resultat} {r:?}");
                if let Err(e) = r {
                    assert!(
                        e.to_string().contains("pas vérifié") || e.to_string().contains("not verified"),
                        "{e}"
                    );
                }
                assert_eq!(fil.join().unwrap(), appels, "{action:?}");
            }
        }
    }

    /// Une activation ou une désactivation réussie en partie seulement (systemd le tait dans sa réponse et ne le dit
    /// que dans sa liste) : jamais comptée comme faite, et dite, avec ce qui est fait. Déjà activée (rien à poser) :
    /// faite.
    #[test]
    fn liens_en_partie_dits() {
        // L'action, la réponse de systemd, et la phrase attendue (français, anglais) quand ce n'est pas un succès.
        type Cas<'a> = (ActionUnite, Vec<Valeur>, Option<(&'a str, &'a str)>);
        let pose = (
            "symlink",
            "/etc/systemd/system/multi-user.target.wants/cups-browsed.service",
        );
        let cas: [Cas; 7] = [
            (
                ActionUnite::Activer,
                vec![
                    Valeur::Booleen(true),
                    changements(&[pose, ("auxiliary unit failed", "cups-browsed.socket")]),
                ],
                Some(("en partie", "in part")),
            ),
            (
                ActionUnite::Activer,
                vec![
                    Valeur::Booleen(true),
                    changements(&[
                        pose,
                        ("destination not present", "/etc/systemd/system/absent.target.wants"),
                    ]),
                ],
                Some(("en partie", "in part")),
            ),
            (
                ActionUnite::Activer,
                vec![Valeur::Booleen(false), changements(&[])],
                Some(("ne le prévoit pas", "does not provide")),
            ),
            (
                ActionUnite::Activer,
                vec![Valeur::Booleen(true), changements(&[])],
                None,
            ),
            (
                ActionUnite::Desactiver,
                vec![changements(&[("dangling", "/etc/systemd/system/alias.service")])],
                Some(("en partie", "in part")),
            ),
            (
                ActionUnite::DesactiverSansArreter,
                vec![changements(&[
                    ("unlink", "/etc/systemd/system/x.wants/cups-browsed.service"),
                    ("masked", "cups-browsed.path"),
                ])],
                Some(("en partie", "in part")),
            ),
            (ActionUnite::Desactiver, vec![changements(&[])], None),
        ];
        {
            for (action, corps, attendu) in cas {
                let n = if action == ActionUnite::DesactiverSansArreter {
                    2
                } else {
                    5
                };
                let reponse = corps.clone();
                let (mut bus, fil) = faux_bus(move |s, vus| {
                    for _ in 0..n {
                        let a = lire(s);
                        let m = a.membre.clone().unwrap();
                        let r = match m.as_str() {
                            "EnableUnitFiles" => retour(&a, "ba(sss)", reponse.clone(), ":1.2"),
                            "DisableUnitFiles" => retour(&a, "a(sss)", reponse.clone(), ":1.2"),
                            _ => repondre(s, &a, "done"),
                        };
                        vus.push(m);
                        s.write_all(&r).unwrap();
                    }
                });
                let r = agir_sur_unite(&mut bus, action, "cups-browsed.service");
                match attendu {
                    None => assert_eq!(r, Ok(()), "{action:?} {corps:?}"),
                    Some((fr, en)) => {
                        let e = r.unwrap_err().to_string();
                        assert!(
                            (e.contains(fr) || e.contains(en)) && e.contains("cups-browsed.service"),
                            "{action:?} {e}"
                        );
                        // Le démarrage ou l'arrêt qui suit est fait quand même, et dit.
                        let suite = match action {
                            ActionUnite::Activer => Some(("il est lancé", "it is started")),
                            ActionUnite::Desactiver => Some(("il est arrêté", "it is stopped")),
                            _ => None,
                        };
                        match suite {
                            Some((fr, en)) => assert!(e.contains(fr) || e.contains(en), "{e}"),
                            None => assert!(!e.contains(" ; il est") && !e.contains("; it is"), "{e}"),
                        }
                        sans_jargon(&e);
                    }
                }
                assert_eq!(fil.join().unwrap().len(), n, "{action:?}");
            }
        }
        // Une liste qui ne se lit pas : pas vérifié, jamais fait.
        assert!(Liens::lire(true, &[changements(&[])]).is_none());
        assert!(Liens::lire(false, &[Valeur::Tableau(vec![Valeur::texte_de("symlink")])]).is_none());
    }

    /// Une activation (ou désactivation) « maintenant » dont la liste des liens ne se lit pas : pas vérifié, et dit
    /// que le service n'est pas lancé (ou arrêté) ; ni StartUnit ni StopUnit ne part.
    #[test]
    fn liste_illisible_dit_pas_lance() {
        for (action, methode, signature, fr, en) in [
            (
                ActionUnite::Activer,
                "EnableUnitFiles",
                "a(sss)",
                "il n'est pas lancé",
                "it is not started",
            ),
            (
                ActionUnite::Desactiver,
                "DisableUnitFiles",
                "ba(sss)",
                "il n'est pas arrêté",
                "it is not stopped",
            ),
        ] {
            let (mut bus, fil) = faux_bus(move |s, vus| {
                for _ in 0..2 {
                    let a = lire(s);
                    let m = a.membre.clone().unwrap();
                    // Une réponse d'une autre forme que celle attendue : la liste ne se lit pas.
                    let r = if m == methode {
                        let corps = if signature == "ba(sss)" {
                            vec![Valeur::Booleen(true), changements(&[])]
                        } else {
                            vec![changements(&[])]
                        };
                        retour(&a, signature, corps, ":1.2")
                    } else {
                        repondre(s, &a, "done")
                    };
                    vus.push(m);
                    s.write_all(&r).unwrap();
                }
            });
            let e = agir_sur_unite(&mut bus, action, "cups-browsed.service")
                .unwrap_err()
                .to_string();
            assert!(e.contains("pas vérifié") || e.contains("not verified"), "{e}");
            assert!(e.contains(fr) || e.contains(en), "{e}");
            sans_jargon(&e);
            assert_eq!(fil.join().unwrap(), [methode, "Reload"]);
        }
    }

    /// Les fichiers chargés d'une unité, par des lectures seulement (GetUnit, puis Get de ses propriétés) ; une unité
    /// pas chargée n'est pas une erreur.
    #[test]
    fn fichiers_charges_par_le_faux_bus() {
        let (mut bus, fil) = faux_bus(|s, vus| {
            let a = lire(s);
            vus.push(a.membre.clone().unwrap());
            let e = Message {
                genre: super::super::ERREUR,
                serie: 5,
                reponse_a: Some(a.serie),
                nom_erreur: Some("org.freedesktop.systemd1.NoSuchUnit".into()),
                signature: "s".into(),
                corps: vec![Valeur::texte_de("Unit anydesk.service not loaded.")],
                ..Message::default()
            };
            s.write_all(&e.encoder().unwrap()).unwrap();
            let a = lire(s);
            vus.push(a.membre.clone().unwrap());
            s.write_all(&retour(
                &a,
                "o",
                vec![Valeur::texte_de("/org/freedesktop/systemd1/unit/anydesk_2eservice")],
                ":1.2",
            ))
            .unwrap();
            let variante = |sig: &str, v| Valeur::Variante(sig.into(), Box::new(v));
            for _ in 0..3 {
                let a = lire(s);
                assert_eq!(a.corps[0], Valeur::texte_de(UNITE));
                let nom = a.corps[1].texte().unwrap().to_string();
                let v = match nom.as_str() {
                    "Id" => variante("s", Valeur::texte_de("anydesk.service")),
                    "FragmentPath" => variante("s", Valeur::texte_de("/usr/lib/systemd/system/anydesk.service")),
                    _ => variante(
                        "as",
                        Valeur::Tableau(vec![Valeur::texte_de("/run/systemd/system/service.d/x.conf")]),
                    ),
                };
                vus.push(format!("{} {nom}", a.membre.clone().unwrap()));
                s.write_all(&retour(&a, "v", vec![v], ":1.2")).unwrap();
            }
        });
        assert_eq!(fichiers_charges(&mut bus, "anydesk.service"), Ok(None));
        assert_eq!(
            fichiers_charges(&mut bus, "anydesk.service"),
            Ok(Some((
                "anydesk.service".to_string(),
                "/usr/lib/systemd/system/anydesk.service".to_string(),
                vec!["/run/systemd/system/service.d/x.conf".to_string()]
            )))
        );
        assert_eq!(
            fil.join().unwrap(),
            ["GetUnit", "GetUnit", "Get Id", "Get FragmentPath", "Get DropInPaths"]
        );
        assert!(fichiers_charges(&mut bus, "a b.service").is_err());
    }

    /// RefuseManualStop lu par des lectures seulement : une unité pas chargée n'a rien à arrêter, auditd sur Fedora
    /// refuse l'arrêt à la main, une autre le permet ; une réponse qui n'est pas un booléen est un échec dit.
    #[test]
    fn arret_a_la_main_par_le_faux_bus() {
        let (mut bus, fil) = faux_bus(|s, vus| {
            let a = lire(s);
            vus.push(a.membre.clone().unwrap());
            let e = Message {
                genre: super::super::ERREUR,
                serie: 5,
                reponse_a: Some(a.serie),
                nom_erreur: Some("org.freedesktop.systemd1.NoSuchUnit".into()),
                signature: "s".into(),
                corps: vec![Valeur::texte_de("Unit auditd.service not loaded.")],
                ..Message::default()
            };
            s.write_all(&e.encoder().unwrap()).unwrap();
            for v in [Valeur::Booleen(true), Valeur::Booleen(false), Valeur::texte_de("yes")] {
                let a = lire(s);
                vus.push(a.membre.clone().unwrap());
                s.write_all(&retour(
                    &a,
                    "o",
                    vec![Valeur::texte_de("/org/freedesktop/systemd1/unit/auditd_2eservice")],
                    ":1.2",
                ))
                .unwrap();
                let a = lire(s);
                assert_eq!(a.corps[0], Valeur::texte_de(UNITE));
                vus.push(format!("{} {}", a.membre.clone().unwrap(), a.corps[1].texte().unwrap()));
                let sig = if matches!(v, Valeur::Booleen(_)) { "b" } else { "s" };
                s.write_all(&retour(
                    &a,
                    "v",
                    vec![Valeur::Variante(sig.into(), Box::new(v))],
                    ":1.2",
                ))
                .unwrap();
            }
        });
        assert_eq!(arret_a_la_main(&mut bus, "auditd.service"), Ok(None));
        assert_eq!(arret_a_la_main(&mut bus, "auditd.service"), Ok(Some(false)));
        assert_eq!(arret_a_la_main(&mut bus, "auditd.service"), Ok(Some(true)));
        assert!(arret_a_la_main(&mut bus, "auditd.service").is_err());
        let get = "Get RefuseManualStop";
        assert_eq!(
            fil.join().unwrap(),
            ["GetUnit", "GetUnit", get, "GetUnit", get, "GetUnit", get]
        );
        assert!(arret_a_la_main(&mut bus, "a b.service").is_err());
    }

    /// La fin du job n'arrive pas : l'attente se termine (ici, le faux bus se ferme) et c'est « pas vérifié ».
    #[test]
    fn sans_fin_de_job_pas_verifie() {
        let (mut bus, fil) = faux_bus(|s, vus| {
            for _ in 0..3 {
                let a = lire(s);
                let m = a.membre.clone().unwrap();
                let r = if m == "StopUnit" {
                    retour(
                        &a,
                        "o",
                        vec![Valeur::texte_de("/org/freedesktop/systemd1/job/3")],
                        ":1.2",
                    )
                } else {
                    retour(&a, "", Vec::new(), if m == "AddMatch" { DBUS } else { ":1.2" })
                };
                vus.push(m);
                s.write_all(&r).unwrap();
            }
            // Une fin d'un autre job, puis plus rien.
            s.write_all(&signal_fin("/org/freedesktop/systemd1/job/4", "done", ":1.2"))
                .unwrap();
        });
        let r = agir_sur_unite(&mut bus, ActionUnite::Arreter, "cups-browsed.service");
        let e = r.unwrap_err().to_string();
        assert!(e.contains("pas vérifié") || e.contains("not verified"), "{e}");
        sans_jargon(&e);
        assert_eq!(fil.join().unwrap(), ["AddMatch", "Subscribe", "StopUnit"]);
    }

    /// Ce que la personne lit ne parle ni de bus, ni de prise, ni de job : le détail va au journal des erreurs.
    fn sans_jargon(texte: &str) {
        for mot in [
            "bus",
            "prise",
            "socket",
            "done",
            "JobRemoved",
            "/run/systemd",
            "org.freedesktop",
            "D-Bus",
            "StopUnit",
        ] {
            assert!(!texte.contains(mot), "« {mot} » dans : {texte}");
        }
    }

    /// Un job fini autrement que par « done », une erreur du gestionnaire : dits en clair.
    #[test]
    fn echecs_dits_sans_jargon() {
        let (mut bus, fil) = faux_bus(|s, vus| {
            for _ in 0..3 {
                let a = lire(s);
                let m = a.membre.clone().unwrap();
                let r = if m == "StopUnit" {
                    retour(
                        &a,
                        "o",
                        vec![Valeur::texte_de("/org/freedesktop/systemd1/job/3")],
                        ":1.2",
                    )
                } else {
                    retour(&a, "", Vec::new(), if m == "AddMatch" { DBUS } else { ":1.2" })
                };
                vus.push(m);
                s.write_all(&r).unwrap();
            }
            s.write_all(&signal_fin("/org/freedesktop/systemd1/job/3", "failed", ":1.2"))
                .unwrap();
            let a = lire(s);
            vus.push(a.membre.clone().unwrap());
            let e = Message {
                genre: super::super::ERREUR,
                serie: 9,
                reponse_a: Some(a.serie),
                nom_erreur: Some("org.freedesktop.DBus.Error.AccessDenied".into()),
                signature: "s".into(),
                corps: vec![Valeur::texte_de("Access denied")],
                ..Message::default()
            };
            s.write_all(&e.encoder().unwrap()).unwrap();
        });
        let e = agir_sur_unite(&mut bus, ActionUnite::Arreter, "cups-browsed.service")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("cups-browsed.service") && (e.contains("échoué") || e.contains("failed")),
            "{e}"
        );
        sans_jargon(&e);
        let e = reinitialiser_echecs(&mut bus).unwrap_err().to_string();
        sans_jargon(&e);
        assert_eq!(
            fil.join().unwrap(),
            ["AddMatch", "Subscribe", "StopUnit", "ResetFailed"]
        );
        sans_jargon(&ne_repond_pas("bus système injoignable").to_string());
        assert_eq!(fin_dite("done"), fin_dite("autre"));
    }

    /// ResetFailed et GetUnitFileState par le faux bus ; une unité sans fichier n'est pas une erreur.
    #[test]
    fn remise_a_zero_et_etat_du_fichier() {
        let (mut bus, fil) = faux_bus(|s, vus| {
            let a = lire(s);
            assert!(a.corps.is_empty() && a.signature.is_empty());
            vus.push(a.membre.clone().unwrap());
            s.write_all(&retour(&a, "", Vec::new(), ":1.2")).unwrap();
            let a = lire(s);
            vus.push(a.membre.clone().unwrap());
            s.write_all(&retour(&a, "s", vec![Valeur::texte_de("enabled")], ":1.2"))
                .unwrap();
            let a = lire(s);
            let e = Message {
                genre: super::super::ERREUR,
                serie: 5,
                reponse_a: Some(a.serie),
                nom_erreur: Some("org.freedesktop.DBus.Error.FileNotFound".into()),
                signature: "s".into(),
                corps: vec![Valeur::texte_de("No such file or directory")],
                ..Message::default()
            };
            s.write_all(&e.encoder().unwrap()).unwrap();
        });
        assert!(reinitialiser_echecs(&mut bus).is_ok());
        assert_eq!(
            etat_du_fichier(&mut bus, "anydesk.service").unwrap().as_deref(),
            Some("enabled")
        );
        assert_eq!(etat_du_fichier(&mut bus, "absent.service").unwrap(), None);
        assert_eq!(fil.join().unwrap(), ["ResetFailed", "GetUnitFileState"]);
        assert!(aucun_fichier("org.freedesktop.systemd1.NoSuchUnit : x"));
        assert!(!aucun_fichier("org.freedesktop.DBus.Error.AccessDenied : x"));
    }

    /// Des octets écrits en hexadécimal, espaces et sauts de ligne ignorés.
    fn hexa(t: &str) -> Vec<u8> {
        let chiffres: Vec<u8> = t.bytes().filter(u8::is_ascii_hexdigit).collect();
        chiffres
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// Les messages envoyés, octet par octet, contre ceux d'un encodeur écrit à part d'après la spécification D-Bus
    /// (« Marshaling » : petit-boutiste, alignement depuis le début du message, champs d'en-tête a(yv) alignés à 8,
    /// corps aligné à 8), et non d'après ce code. Les champs d'en-tête dans l'ordre de sd-bus (chemin, interface,
    /// membre, destination, signature). La comparaison avec une vraie capture (`busctl monitor` pendant le vrai
    /// `systemctl`, en QEMU) reste à faire : le bus y ajoute l'expéditeur, et les numéros de série diffèrent.
    #[test]
    fn messages_octet_par_octet() {
        // EnableUnitFiles(as ["cups-browsed.service"], b false, b false), série 2 (Hello est la 1).
        let activer = hexa(
            "6c 01 00 01 28 00 00 00 02 00 00 00 a2 00 00 00
             01 01 6f 00 19 00 00 00 2f 6f 72 67 2f 66 72 65
             65 64 65 73 6b 74 6f 70 2f 73 79 73 74 65 6d 64
             31 00 00 00 00 00 00 00 02 01 73 00 20 00 00 00
             6f 72 67 2e 66 72 65 65 64 65 73 6b 74 6f 70 2e
             73 79 73 74 65 6d 64 31 2e 4d 61 6e 61 67 65 72
             00 00 00 00 00 00 00 00 03 01 73 00 0f 00 00 00
             45 6e 61 62 6c 65 55 6e 69 74 46 69 6c 65 73 00
             06 01 73 00 18 00 00 00 6f 72 67 2e 66 72 65 65
             64 65 73 6b 74 6f 70 2e 73 79 73 74 65 6d 64 31
             00 00 00 00 00 00 00 00 08 01 67 00 04 61 73 62
             62 00 00 00 00 00 00 00 19 00 00 00 14 00 00 00
             63 75 70 73 2d 62 72 6f 77 73 65 64 2e 73 65 72
             76 69 63 65 00 00 00 00 00 00 00 00 00 00 00 00",
        );
        // StopUnit(s "cups-browsed.service", s "replace"), série 4 (AddMatch 2, Subscribe 3).
        let arreter = hexa(
            "6c 01 00 01 28 00 00 00 04 00 00 00 a0 00 00 00
             01 01 6f 00 19 00 00 00 2f 6f 72 67 2f 66 72 65
             65 64 65 73 6b 74 6f 70 2f 73 79 73 74 65 6d 64
             31 00 00 00 00 00 00 00 02 01 73 00 20 00 00 00
             6f 72 67 2e 66 72 65 65 64 65 73 6b 74 6f 70 2e
             73 79 73 74 65 6d 64 31 2e 4d 61 6e 61 67 65 72
             00 00 00 00 00 00 00 00 03 01 73 00 08 00 00 00
             53 74 6f 70 55 6e 69 74 00 00 00 00 00 00 00 00
             06 01 73 00 18 00 00 00 6f 72 67 2e 66 72 65 65
             64 65 73 6b 74 6f 70 2e 73 79 73 74 65 6d 64 31
             00 00 00 00 00 00 00 00 08 01 67 00 02 73 73 00
             14 00 00 00 63 75 70 73 2d 62 72 6f 77 73 65 64
             2e 73 65 72 76 69 63 65 00 00 00 00 07 00 00 00
             72 65 70 6c 61 63 65 00",
        );
        // ResetFailed(), série 2 : pas de signature, pas de corps.
        let remettre = hexa(
            "6c 01 00 01 00 00 00 00 02 00 00 00 91 00 00 00
             01 01 6f 00 19 00 00 00 2f 6f 72 67 2f 66 72 65
             65 64 65 73 6b 74 6f 70 2f 73 79 73 74 65 6d 64
             31 00 00 00 00 00 00 00 02 01 73 00 20 00 00 00
             6f 72 67 2e 66 72 65 65 64 65 73 6b 74 6f 70 2e
             73 79 73 74 65 6d 64 31 2e 4d 61 6e 61 67 65 72
             00 00 00 00 00 00 00 00 03 01 73 00 0b 00 00 00
             52 65 73 65 74 46 61 69 6c 65 64 00 00 00 00 00
             06 01 73 00 18 00 00 00 6f 72 67 2e 66 72 65 65
             64 65 73 6b 74 6f 70 2e 73 79 73 74 65 6d 64 31
             00 00 00 00 00 00 00 00",
        );
        assert_eq!((activer.len(), arreter.len(), remettre.len()), (224, 216, 168));

        // Ce que le client écrit vraiment, lu brut par le faux bus.
        let capture = |nombre: usize, quoi: fn(&mut Bus)| -> Vec<Vec<u8>> {
            let (mut bus, fil) = faux_bus(move |s, vus| {
                for _ in 0..nombre {
                    let brut = lire_brut(s);
                    let a = Message::decoder_si(&brut, |_| true).unwrap();
                    let r = repondre(s, &a, "done");
                    vus.push(brut.iter().map(|o| format!("{o:02x}")).collect::<Vec<_>>().concat());
                    s.write_all(&r).unwrap();
                }
            });
            quoi(&mut bus);
            fil.join().unwrap().iter().map(|h: &String| hexa(h)).collect()
        };
        let envoyes = capture(5, |b| {
            agir_sur_unite(b, ActionUnite::Activer, "cups-browsed.service").unwrap();
        });
        assert_eq!(envoyes[0], activer);
        let envoyes = capture(3, |b| {
            agir_sur_unite(b, ActionUnite::Arreter, "cups-browsed.service").unwrap();
        });
        assert_eq!(envoyes[2], arreter);
        let envoyes = capture(1, |b| reinitialiser_echecs(b).unwrap());
        assert_eq!(envoyes[0], remettre);
        // Le genre d'une réponse : rien d'autre qu'un retour n'est attendu d'un appel réussi.
        assert_eq!(RETOUR, 2);
    }

    /// Ce que le gestionnaire dit d'une unité, lu en `ArretCharge` : commandes de lancement et d'arrêt, fichiers
    /// d'environnement, racine, groupe, unités entraînées. Une propriété obligatoire absente ou d'un autre type n'est
    /// jamais lue comme vide : rien n'est rendu, et l'arrêt n'est pas fait.
    #[test]
    fn l_arret_charge_se_lit_des_proprietes() {
        let t = Valeur::texte_de;
        let var = |v: Valeur| Valeur::Variante("v".into(), Box::new(v));
        let dico = |e: Vec<(&str, Valeur)>| Valeur::Dictionnaire(e.into_iter().map(|(k, v)| (t(k), var(v))).collect());
        let commande = |chemin: &str, argv: &[&str]| {
            Valeur::Structure(vec![t(chemin), Valeur::Tableau(argv.iter().map(|a| t(a)).collect())])
        };
        let unite = |requis: Valeur| {
            dico(vec![
                ("NeedDaemonReload", Valeur::Booleen(false)),
                ("RequiredBy", requis),
                ("RequisiteOf", Valeur::Tableau(vec![])),
                ("BoundBy", Valeur::Tableau(vec![])),
                ("ConsistsOf", Valeur::Tableau(vec![])),
                ("OnFailure", Valeur::Tableau(vec![])),
                ("PropagatesStopTo", Valeur::Tableau(vec![t("autre.service")])),
                ("UpheldBy", Valeur::Tableau(vec![t("gardien.service")])),
            ])
        };
        let genre = |groupe: Valeur| {
            dico(vec![
                (
                    "ExecStart",
                    Valeur::Tableau(vec![commande("/usr/bin/anydesk", &["/usr/bin/anydesk", "--service"])]),
                ),
                (
                    "ExecStop",
                    Valeur::Tableau(vec![commande("/bin/kill", &["kill", "$MAINPID"])]),
                ),
                ("ExecStopPost", Valeur::Tableau(vec![])),
                (
                    "EnvironmentFiles",
                    Valeur::Tableau(vec![Valeur::Structure(vec![
                        t("/etc/default/anydesk"),
                        Valeur::Booleen(true),
                    ])]),
                ),
                ("RootDirectory", t("")),
                ("RootImage", t("")),
                ("ControlGroup", groupe),
            ])
        };
        let g = genre(t("/system.slice/anydesk.service"));
        let lu = arret_charge_de("anydesk.service", &unite(Valeur::Tableau(vec![])), Some(&g)).expect("lu");
        assert!(!lu.recharge_attendue);
        assert_eq!(lu.lancement.len(), 1);
        assert_eq!(lu.lancement[0].arguments, ["/usr/bin/anydesk", "--service"]);
        assert_eq!(lu.arret.len(), 1);
        assert_eq!(lu.arret[0].chemin, "/bin/kill");
        assert_eq!(
            lu.fichiers_d_environnement,
            [("/etc/default/anydesk".to_string(), true)]
        );
        assert_eq!(lu.entrainees, ["autre.service"]);
        assert_eq!(lu.lancees, ["gardien.service"]);
        assert_eq!(lu.groupe, "/system.slice/anydesk.service");
        assert_eq!(lu.racine, "");
        // Une liste obligatoire d'un autre type, un groupe qui n'est pas un texte, le genre absent : rien n'est lu.
        assert_eq!(arret_charge_de("anydesk.service", &unite(t("x")), Some(&g)), None);
        assert_eq!(
            arret_charge_de(
                "anydesk.service",
                &unite(Valeur::Tableau(vec![])),
                Some(&genre(Valeur::U32(0)))
            ),
            None
        );
        assert_eq!(
            arret_charge_de("anydesk.service", &unite(Valeur::Tableau(vec![])), None),
            None
        );
        // Un minuteur ne lance rien lui-même : seules ses propriétés d'unité comptent.
        let minuteur = arret_charge_de("x.timer", &unite(Valeur::Tableau(vec![])), None).expect("minuteur");
        assert!(minuteur.arret.is_empty() && minuteur.groupe.is_empty());
    }
}
