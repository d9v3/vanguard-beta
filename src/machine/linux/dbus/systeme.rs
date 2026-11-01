//! Les ACTIONS de l'assistant élevé (`machine::assistant`) sur les unités de systemd, par le bus SYSTÈME, à la place
//! de `sudo systemctl …` : une troisième liste fermée (`ACTIONS_SYSTEME`), à côté des LECTURES de `dbus.rs` et des
//! actions du bus de la session (`actions.rs`), dont elle reprend l'envoi et l'attente du job.
//!
//! Seul le fils root s'en sert, et seulement pour un geste de `machine::gestes_unix` déjà rejugé (`unite`,
//! `unite-designee`, `signatures-clamav`) : aucune fonction ne prend une méthode, et chaque nom d'unité passe la règle
//! stricte de `gestes_unix::nom_admis` avant tout envoi. Le drapeau ALLOW_INTERACTIVE_AUTHORIZATION n'est jamais
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
use super::{Bus, CHEMIN_SYSTEMD, DBUS, GESTIONNAIRE, SYSTEMD, Valeur};
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
];

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
        self.agir_systeme("AddMatch", vec![Valeur::texte_de(FILTRE_FIN_DE_JOB)], None, fins)?;
        let (reponse, _) = self
            .agir_dans(ACTIONS_SYSTEME, GESTIONNAIRE, "Subscribe", Vec::new(), None, fins)
            .map_err(|e| pas_fait(format!("Subscribe : {e}")))?;
        // Le nom unique du gestionnaire, écrit par le bus dans sa réponse : seuls ses signaux comptent.
        let systemd = reponse
            .expediteur
            .ok_or_else(|| pas_fait(super::mal_forme("expéditeur absent")))?;
        let corps = self.agir_systeme(
            methode,
            vec![Valeur::texte_de(unite), Valeur::texte_de("replace")],
            Some(&systemd),
            fins,
        )?;
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
    /// systemctl : le gestionnaire ne voit les nouveaux liens qu'après un rechargement.
    fn fichiers(&mut self, activer: bool, unite: &str, fins: &mut Vec<FinDeJob>) -> Result<(), Echec> {
        let unites = Valeur::Tableau(vec![Valeur::texte_de(unite)]);
        if activer {
            self.agir_systeme(
                "EnableUnitFiles",
                vec![unites, Valeur::Booleen(false), Valeur::Booleen(false)],
                None,
                fins,
            )?;
        } else {
            self.agir_systeme("DisableUnitFiles", vec![unites, Valeur::Booleen(false)], None, fins)?;
        }
        self.agir_systeme("Reload", Vec::new(), None, fins).map(|_| ())
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
            bus.fichiers(true, unite, &mut fins)?;
            bus.job("StartUnit", unite, &mut fins)
        }
        ActionUnite::Desactiver => {
            bus.fichiers(false, unite, &mut fins)?;
            bus.job("StopUnit", unite, &mut fins)
        }
        ActionUnite::DesactiverSansArreter => bus.fichiers(false, unite, &mut fins),
        ActionUnite::Demarrer => bus.job("StartUnit", unite, &mut fins),
        ActionUnite::Arreter => bus.job("StopUnit", unite, &mut fins),
        ActionUnite::Redemarrer => bus.job("TryRestartUnit", unite, &mut fins),
        ActionUnite::Recharger => bus.job("ReloadOrTryRestartUnit", unite, &mut fins),
    }
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
    use super::super::actions::tests::{faux_bus, lire, lire_brut, retour, signal_fin};
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
            "StartTransientUnit",
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
            "EnableUnitFiles" | "DisableUnitFiles" => retour(a, "a(sss)", vec![Valeur::Tableau(Vec::new())], systemd),
            "StartUnit" | "StopUnit" | "TryRestartUnit" | "ReloadOrTryRestartUnit" => {
                assert_eq!(a.corps[1], Valeur::texte_de("replace"));
                let job = "/org/freedesktop/systemd1/job/9";
                s.write_all(&signal_fin(job, "done", ":1.66")).unwrap();
                s.write_all(&signal_fin(job, resultat, systemd)).unwrap();
                retour(a, "o", vec![Valeur::texte_de(job)], systemd)
            }
            _ => retour(a, "", Vec::new(), systemd),
        }
    }

    /// Chaque action, avec les appels qu'elle fait, dans l'ordre ; seul « done » vaut « fait ».
    #[test]
    fn chaque_action_et_la_fin_du_job() {
        let attendus: [(ActionUnite, &[&str]); 7] = [
            (
                ActionUnite::Activer,
                &["EnableUnitFiles", "Reload", "AddMatch", "Subscribe", "StartUnit"],
            ),
            (
                ActionUnite::Desactiver,
                &["DisableUnitFiles", "Reload", "AddMatch", "Subscribe", "StopUnit"],
            ),
            (ActionUnite::DesactiverSansArreter, &["DisableUnitFiles", "Reload"]),
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
                let sans_job = action == ActionUnite::DesactiverSansArreter;
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
}
