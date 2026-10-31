//! Les ACTIONS que Vanguard fait par D-Bus, à part des LECTURES de `dbus.rs` : une seconde liste fermée, par service,
//! chemin, interface, méthode et signature, toutes sur le bus de la SESSION du compte (jamais le bus système) :
//! - le gestionnaire systemd de l'utilisateur, pour les unités de Vanguard seulement (« vanguard-… ») : Reload,
//!   EnableUnitFiles, DisableUnitFiles, StartUnit, StopUnit, RestartUnit, TryRestartUnit, et Subscribe avec AddMatch
//!   pour attendre la fin du job (JobRemoved), comme `systemctl --user` sans `--no-block` ;
//! - une notification (org.freedesktop.Notifications.Notify), à la place de notify-send ;
//! - une écriture dans dconf (ca.desrt.dconf.Writer.Change), à la place de `gsettings set`.
//!
//! Aucune fonction ne prend une méthode, un service ou une signature : chacune fabrique un appel de la liste, et ses
//! arguments sont vérifiés (nom d'unité de Vanguard, textes bornés). Aucune n'autorise d'invite polkit (le drapeau
//! ALLOW_INTERACTIVE_AUTHORIZATION n'est jamais posé ; le gestionnaire de l'utilisateur n'en demande pas).
//!
//! Sous root (sudo), le bus de la session est celui d'un autre compte, ou celui de root : rien n'est envoyé, plutôt
//! que d'écrire au mauvais endroit.

use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::{Bus, CHEMIN_SYSTEMD, DBUS, ERREUR, GESTIONNAIRE, Message, RETOUR, SIGNAL, SYSTEMD, Valeur};
use crate::modele::Echec;
use crate::{tr, trf};

const NOTIFICATIONS: &str = "org.freedesktop.Notifications";
const CHEMIN_NOTIFICATIONS: &str = "/org/freedesktop/Notifications";
const DCONF: &str = "ca.desrt.dconf";
const DCONF_ECRIVAIN: &str = "ca.desrt.dconf.Writer";
const CHEMIN_DCONF: &str = "/ca/desrt/dconf/Writer/user";

/// Une action permise : (service, chemin, interface, méthode, signature des arguments).
type Action = (&'static str, &'static str, &'static str, &'static str, &'static str);

/// Les seules actions que ce client envoie, toutes sur le bus de la session.
pub(super) const ACTIONS: &[Action] = &[
    // Le bus lui-même : recevoir le signal de fin d'un job de systemd.
    (DBUS, "/org/freedesktop/DBus", DBUS, "AddMatch", "s"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "Subscribe", ""),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "Reload", ""),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "EnableUnitFiles", "asbb"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "DisableUnitFiles", "asb"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "StartUnit", "ss"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "StopUnit", "ss"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "RestartUnit", "ss"),
    (SYSTEMD, CHEMIN_SYSTEMD, GESTIONNAIRE, "TryRestartUnit", "ss"),
    (
        NOTIFICATIONS,
        CHEMIN_NOTIFICATIONS,
        NOTIFICATIONS,
        "Notify",
        "susssasa{sv}i",
    ),
    (DCONF, CHEMIN_DCONF, DCONF_ECRIVAIN, "Change", "ay"),
];

/// Le temps laissé à un job de systemd pour finir (un service qui démarre) : au-delà, l'action est dite ratée.
const DELAI_JOB: Duration = Duration::from_secs(60);
/// Un titre ou un corps de notification plus long est coupé (aucune notification de Vanguard n'en approche).
const TEXTE_MAX: usize = 4096;
/// Un changement de dconf plus gros est refusé (une clé de Déjà Dup fait quelques dizaines d'octets).
const CHANGEMENT_MAX: usize = 64 << 10;

/// Une unité de Vanguard pour le gestionnaire de l'utilisateur : « vanguard-… » suivi d'un suffixe d'unité, sans
/// rien d'autre que des lettres, chiffres, « - », « _ », « . », « @ ». Seules celles-là peuvent être activées,
/// démarrées ou arrêtées par ici.
pub(crate) fn unite_de_vanguard(nom: &str) -> bool {
    let Some((base, suffixe)) = nom.rsplit_once('.') else {
        return false;
    };
    nom.len() <= 255
        && ["service", "timer", "path", "socket"].contains(&suffixe)
        && base
            .strip_prefix("vanguard-")
            .is_some_and(|r| !r.is_empty() && r.bytes().all(|o| o.is_ascii_alphanumeric() || b"-_.@".contains(&o)))
}

/// Une adresse de bus de la spécification D-Bus : `%xx` décodé dans la valeur ; `None` pour un `%` mal formé.
fn sans_echappement(valeur: &str) -> Option<Vec<u8>> {
    let mut reste = valeur.as_bytes();
    let mut r = Vec::with_capacity(reste.len());
    while let Some((&premier, suite)) = reste.split_first() {
        if premier == b'%' {
            let (hexa, apres) = suite.split_at_checked(2)?;
            r.push(u8::from_str_radix(std::str::from_utf8(hexa).ok()?, 16).ok()?);
            reste = apres;
        } else {
            r.push(premier);
            reste = suite;
        }
    }
    Some(r)
}

/// Où joindre le bus : une prise du système de fichiers, ou un nom de l'espace abstrait de Linux.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Prise {
    Chemin(std::path::PathBuf),
    Abstraite(Vec<u8>),
}

/// Les prises d'une adresse de bus (« unix:path=…[,guid=…];unix:abstract=… »), dans l'ordre ; les autres transports
/// (tcp, launchd…) sont laissés.
pub(crate) fn prises_de(adresse: &str) -> Vec<Prise> {
    adresse
        .split(';')
        .filter_map(|a| {
            let cles = a.strip_prefix("unix:")?;
            cles.split(',').find_map(|c| {
                let (k, v) = c.split_once('=')?;
                let v = sans_echappement(v)?;
                match k {
                    "path" => {
                        use std::os::unix::ffi::OsStringExt;
                        Some(Prise::Chemin(std::ffi::OsString::from_vec(v).into()))
                    }
                    "abstract" => Some(Prise::Abstraite(v)),
                    _ => None,
                }
            })
        })
        .collect()
}

/// Le compte du programme à l'autre bout de la prise (SO_PEERCRED) : le bus de la session doit tourner sous le
/// nôtre, sinon un autre compte qui aurait pris le nom (prise abstraite d'un bus mort) recevrait nos actions.
fn compte_d_en_face(s: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: 0,
    };
    let mut taille = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).ok()?;
    // SAFETY: getsockopt écrit au plus `taille` octets dans `cred`, une structure à nous vivante pendant l'appel, sur
    // une prise ouverte que `s` garde.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut taille,
        )
    };
    (r == 0).then_some(cred.uid)
}

fn connecter(prise: &Prise, uid: u32) -> Option<UnixStream> {
    let s = connecter_sans_verifier(prise, uid)?;
    (compte_d_en_face(&s) == Some(uid)).then_some(s)
}

fn connecter_sans_verifier(prise: &Prise, uid: u32) -> Option<UnixStream> {
    match prise {
        Prise::Chemin(c) => {
            use std::os::unix::fs::MetadataExt;
            // La prise doit être celle du compte : une autre (posée par quelqu'un d'autre dans un dossier ouvert)
            // recevrait nos actions.
            let m = std::fs::metadata(c).ok()?;
            (m.uid() == uid).then_some(())?;
            UnixStream::connect(c).ok()
        }
        Prise::Abstraite(nom) => {
            use std::os::linux::net::SocketAddrExt;
            let a = std::os::unix::net::SocketAddr::from_abstract_name(nom).ok()?;
            UnixStream::connect_addr(&a).ok()
        }
    }
}

/// Le bus de la session du compte, pour ses lectures (LECTURES) et les actions de ce module. `Err` : pas de bus
/// joignable (hors session, sous sudo, service sans DBUS_SESSION_BUS_ADDRESS ni XDG_RUNTIME_DIR), avec la raison.
pub(crate) fn session() -> Result<Bus, Echec> {
    // SAFETY: geteuid ne prend rien et ne peut pas échouer.
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return Err(echec(tr!(
            "sous root, le bus de la session n'est pas celui du compte",
            "as root, the session bus is not the account's"
        )));
    }
    let mut prises = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .map(|a| prises_de(&a))
        .unwrap_or_default();
    // Le défaut de sd-bus : $XDG_RUNTIME_DIR/bus.
    if prises.is_empty()
        && let Some(d) = std::env::var_os("XDG_RUNTIME_DIR")
    {
        prises.push(Prise::Chemin(std::path::PathBuf::from(d).join("bus")));
    }
    let prise = prises
        .iter()
        .find_map(|p| connecter(p, uid))
        .ok_or_else(|| echec(tr!("bus de la session injoignable", "session bus unreachable")))?;
    Bus::sur(prise).map_err(echec)
}

/// Une erreur dans le canal d'erreur commun ; son texte reste celui du bus quand il vient du bus
/// (« org.freedesktop.systemd1.NoSuchUnit : … »).
fn echec(e: impl Into<String>) -> Echec {
    Echec::echoue("dbus/actions", e)
}

#[cfg(test)]
thread_local! {
    /// Sous les essais, aucune action ne part vers le vrai bus de la session (ni vers systemctl) : seul un essai
    /// `#[ignore]` nommé l'autorise pour son fil.
    static ACTION_REELLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Le bus de la session pour y AGIR. Sous les essais, refusé sauf autorisation explicite du fil : une écriture ne
/// doit pas pouvoir partir d'un test (unité activée, notification, réglage changé).
fn session_pour_agir() -> Result<Bus, Echec> {
    #[cfg(test)]
    if !ACTION_REELLE.with(std::cell::Cell::get) {
        return Err(echec("aucune action réelle sous les essais"));
    }
    session()
}

/// L'action de la liste, s'il y en a une pour (interface, méthode) ; sinon rien ne part.
fn action(interface: &str, methode: &str) -> Result<&'static Action, Echec> {
    ACTIONS
        .iter()
        .find(|a| a.2 == interface && a.3 == methode)
        .ok_or_else(|| {
            echec(trf!(
                "{interface}.{methode} n'est pas une action permise",
                "{interface}.{methode} is not an allowed action"
            ))
        })
}

/// Un signal JobRemoved du gestionnaire : (chemin du job, résultat).
type FinDeJob = (String, String);

impl Bus {
    /// Envoie une action de la liste et attend sa réponse ; les signaux JobRemoved venus de `systemd` (nom unique
    /// du gestionnaire, s'il est connu) en chemin sont gardés dans `fins`.
    fn agir(
        &mut self,
        interface: &str,
        methode: &str,
        arguments: Vec<Valeur>,
        systemd: Option<&str>,
        fins: &mut Vec<FinDeJob>,
    ) -> Result<(Message, Vec<Valeur>), Echec> {
        let &(service, chemin, interface, methode, signature) = action(interface, methode)?;
        let mut appel = Message::appel(service, chemin, interface, methode, signature, arguments);
        self.serie = self.serie.wrapping_add(1).max(1);
        appel.serie = self.serie;
        let octets = appel.encoder().map_err(echec)?;
        self.ecrire(&octets).map_err(echec)?;
        let echeance = super::echeance(super::DELAI);
        loop {
            let r = self.recevoir_avec_signaux(echeance, appel.serie, systemd)?;
            if r.genre == SIGNAL {
                fins.extend(fin_de_job(&r));
                continue;
            }
            if r.reponse_a != Some(appel.serie) {
                continue;
            }
            if r.genre == ERREUR {
                let nom = r.nom_erreur.clone().unwrap_or_default();
                let detail = r.corps.first().and_then(Valeur::texte).unwrap_or_default();
                return Err(echec(crate::ui::affichable(&format!("{nom} : {detail}"))));
            }
            let corps = r.corps.clone();
            return Ok((r, corps));
        }
    }

    /// Le prochain message ; son corps n'est décodé que s'il répond à `attendu`, ou s'il est un JobRemoved du
    /// gestionnaire `systemd` (un autre programme de la session ne peut pas se faire passer pour lui : le bus écrit
    /// lui-même l'expéditeur).
    fn recevoir_avec_signaux(
        &mut self,
        echeance: Instant,
        attendu: u32,
        systemd: Option<&str>,
    ) -> Result<Message, Echec> {
        let reste = echeance.saturating_duration_since(Instant::now());
        if reste.is_zero() {
            return Err(echec(tr!(
                "le bus n'a pas répondu à temps",
                "the bus did not answer in time"
            )));
        }
        let octets = self
            .lire_message(reste)
            .inspect_err(|_| self.condamner())
            .map_err(echec)?;
        Message::decoder_si(&octets, |m| {
            (m.reponse_a == Some(attendu) && matches!(m.genre, RETOUR | ERREUR))
                || (m.genre == SIGNAL
                    && systemd.is_some()
                    && m.expediteur.as_deref() == systemd
                    && m.interface.as_deref() == Some(GESTIONNAIRE)
                    && m.membre.as_deref() == Some("JobRemoved")
                    && m.signature == "uoss")
        })
        .map_err(echec)
    }

    /// Attend la fin du job `job` (JobRemoved), dans `fins` déjà reçus puis dans la prise.
    fn attendre_job(&mut self, job: &str, systemd: &str, fins: &mut Vec<FinDeJob>) -> Result<String, Echec> {
        let echeance = super::echeance(DELAI_JOB);
        loop {
            if let Some(i) = fins.iter().position(|(j, _)| j == job) {
                return Ok(fins.swap_remove(i).1);
            }
            // Aucun appel n'attend de réponse : seul un JobRemoved est décodé.
            let m = self.recevoir_avec_signaux(echeance, 0, Some(systemd))?;
            if m.genre == SIGNAL {
                fins.extend(fin_de_job(&m));
            }
        }
    }
}

/// Le (job, résultat) d'un signal JobRemoved (u id, o job, s unité, s résultat) déjà décodé.
fn fin_de_job(m: &Message) -> Option<FinDeJob> {
    let [_, job, _, resultat] = m.corps.as_slice() else {
        return None;
    };
    Some((job.texte()?.to_string(), resultat.texte()?.to_string()))
}

/// Ce que `systemctl --user` fait, par le gestionnaire de l'utilisateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Geste {
    /// daemon-reload.
    Recharger,
    /// enable, puis daemon-reload ; `--now` : puis start, jusqu'à la fin du job.
    Activer {
        maintenant: bool,
    },
    /// disable, puis daemon-reload ; `--now` : puis stop, jusqu'à la fin du job.
    Desactiver {
        maintenant: bool,
    },
    /// start ; `attendre: false` = `--no-block` (le job est mis en file, rien de plus n'est su).
    Demarrer {
        attendre: bool,
    },
    Arreter,
    Redemarrer,
    /// try-restart : seulement si elle tourne.
    RedemarrerSiActive,
}

/// Le résultat d'un job qui vaut réussite pour systemctl (« done » ; « skipped » pour une condition non remplie).
fn job_reussi(resultat: &str) -> bool {
    matches!(resultat, "done" | "skipped")
}

/// Fait `geste` sur `unite` (une unité de Vanguard ; ignorée pour Recharger) par le bus de la session, rendu comme
/// le code de `systemctl --user` (vrai : réussi). Sans bus de la session (une
/// session sans dbus-broker ni dbus-daemon), `systemctl --user` en secours : il joint le gestionnaire par sa prise
/// privée. Sous root, rien : ni le bus ni systemctl ne viseraient le gestionnaire du compte.
pub(crate) fn utilisateur(geste: Geste, unite: &str) -> bool {
    if geste != Geste::Recharger && !unite_de_vanguard(unite) {
        return false;
    }
    // SAFETY: geteuid ne prend rien et ne peut pas échouer.
    if unsafe { libc::geteuid() } == 0 {
        return false;
    }
    // Sous les essais, ni le vrai bus ni systemctl.
    #[cfg(test)]
    if !ACTION_REELLE.with(std::cell::Cell::get) {
        return false;
    }
    // Un bus de la session sans le gestionnaire de systemd (dbus-run-session, dbus-launch) : systemctl --user le
    // joint par sa prise privée.
    let par_le_bus = session_pour_agir().map(|mut bus| systemd_sur(&mut bus, geste, unite));
    match par_le_bus {
        Ok(Ok(())) => return true,
        Ok(Err(e)) if !super::service_absent(&e.to_string()) => return false,
        _ => {}
    }
    {
        let mut args = vec!["--user"];
        args.extend_from_slice(match geste {
            Geste::Recharger => &["daemon-reload"][..],
            Geste::Activer { maintenant: true } => &["enable", "--now"],
            Geste::Activer { maintenant: false } => &["enable"],
            Geste::Desactiver { maintenant: true } => &["disable", "--now"],
            Geste::Desactiver { maintenant: false } => &["disable"],
            Geste::Demarrer { attendre: true } => &["start"],
            Geste::Demarrer { attendre: false } => &["start", "--no-block"],
            Geste::Arreter => &["stop"],
            Geste::Redemarrer => &["restart"],
            Geste::RedemarrerSiActive => &["try-restart"],
        });
        if geste != Geste::Recharger {
            args.push(unite);
        }
        crate::commande::lancer(std::process::Command::new("systemctl").args(&args), 60)
            .is_some_and(|r| r.code == Some(0))
    }
}

/// `utilisateur` sur un bus déjà ouvert (les essais lui donnent un faux bus).
fn systemd_sur(bus: &mut Bus, geste: Geste, unite: &str) -> Result<(), Echec> {
    let mut fins = Vec::new();
    let unites = || Valeur::Tableau(vec![Valeur::texte_de(unite)]);
    let recharger =
        |bus: &mut Bus, fins: &mut Vec<FinDeJob>| bus.agir(GESTIONNAIRE, "Reload", Vec::new(), None, fins).map(|_| ());
    // Le job à attendre : s'abonner AVANT de le lancer, sans quoi sa fin peut passer avant l'abonnement.
    let job = |bus: &mut Bus, fins: &mut Vec<FinDeJob>, methode: &str| -> Result<(), Echec> {
        bus.agir(
            DBUS,
            "AddMatch",
            vec![Valeur::texte_de(
                "type='signal',sender='org.freedesktop.systemd1',interface='org.freedesktop.systemd1.Manager',member='JobRemoved',path='/org/freedesktop/systemd1'",
            )],
            None,
            fins,
        )?;
        let (reponse, _) = bus.agir(GESTIONNAIRE, "Subscribe", Vec::new(), None, fins)?;
        // Le nom unique du gestionnaire, écrit par le bus dans sa réponse : seuls ses signaux comptent.
        let systemd = reponse
            .expediteur
            .clone()
            .ok_or_else(|| echec(super::mal_forme("expéditeur absent")))?;
        let (_, corps) = bus.agir(
            GESTIONNAIRE,
            methode,
            vec![Valeur::texte_de(unite), Valeur::texte_de("replace")],
            Some(&systemd),
            fins,
        )?;
        let chemin = corps
            .first()
            .and_then(Valeur::texte)
            .map(String::from)
            .ok_or_else(|| echec(super::mal_forme("job")))?;
        let resultat = bus.attendre_job(&chemin, &systemd, fins)?;
        if job_reussi(&resultat) {
            Ok(())
        } else {
            let vu = crate::ui::affichable(&resultat);
            Err(echec(trf!("{unite} : job « {vu} »", "{unite}: job “{vu}”")))
        }
    };
    match geste {
        Geste::Recharger => recharger(bus, &mut fins),
        Geste::Activer { maintenant } => {
            bus.agir(
                GESTIONNAIRE,
                "EnableUnitFiles",
                vec![unites(), Valeur::Booleen(false), Valeur::Booleen(false)],
                None,
                &mut fins,
            )?;
            // Comme systemctl : le gestionnaire ne voit les nouveaux liens qu'après un rechargement.
            recharger(bus, &mut fins)?;
            if maintenant {
                job(bus, &mut fins, "StartUnit")
            } else {
                Ok(())
            }
        }
        Geste::Desactiver { maintenant } => {
            bus.agir(
                GESTIONNAIRE,
                "DisableUnitFiles",
                vec![unites(), Valeur::Booleen(false)],
                None,
                &mut fins,
            )?;
            recharger(bus, &mut fins)?;
            if maintenant {
                job(bus, &mut fins, "StopUnit")
            } else {
                Ok(())
            }
        }
        Geste::Demarrer { attendre: true } => job(bus, &mut fins, "StartUnit"),
        Geste::Demarrer { attendre: false } => bus
            .agir(
                GESTIONNAIRE,
                "StartUnit",
                vec![Valeur::texte_de(unite), Valeur::texte_de("replace")],
                None,
                &mut fins,
            )
            .map(|_| ()),
        Geste::Arreter => job(bus, &mut fins, "StopUnit"),
        Geste::Redemarrer => job(bus, &mut fins, "RestartUnit"),
        Geste::RedemarrerSiActive => job(bus, &mut fins, "TryRestartUnit"),
    }
}

/// Une notification urgente (urgency = 2, critique : elle ne s'efface pas seule), au nom de Vanguard, à la place de
/// `notify-send -a Vanguard -i vanguard -u critical`. Rend son numéro.
pub(crate) fn notifier(titre: &str, corps: &str) -> Result<u32, Echec> {
    let mut bus = session_pour_agir()?;
    notifier_sur(&mut bus, titre, corps)
}

fn coupe(t: &str) -> String {
    t[..t.floor_char_boundary(TEXTE_MAX)].to_string()
}

fn notifier_sur(bus: &mut Bus, titre: &str, corps: &str) -> Result<u32, Echec> {
    let indices = Valeur::Dictionnaire(vec![(
        Valeur::texte_de("urgency"),
        Valeur::Variante("y".into(), Box::new(Valeur::Octet(2))),
    )]);
    let (_, r) = bus.agir(
        NOTIFICATIONS,
        "Notify",
        vec![
            Valeur::texte_de("Vanguard"),
            Valeur::U32(0),
            Valeur::texte_de("vanguard"),
            Valeur::Texte(coupe(titre)),
            Valeur::Texte(coupe(corps)),
            Valeur::Tableau(Vec::new()),
            indices,
            Valeur::I32(-1),
        ],
        None,
        &mut Vec::new(),
    )?;
    r.first()
        .and_then(Valeur::entier)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| echec(super::mal_forme("numéro de notification")))
}

/// Écrit un changement de dconf (les octets d'un GVariant `a{smv}`, voir `dconf::changement`) par l'écrivain de la
/// base de l'utilisateur. Rend l'étiquette du changement.
pub(crate) fn changer_dconf(changement: &[u8]) -> Result<String, Echec> {
    if changement.len() > CHANGEMENT_MAX {
        return Err(echec(super::mal_forme("changement trop gros")));
    }
    let mut bus = session_pour_agir()?;
    changer_dconf_sur(&mut bus, changement)
}

fn changer_dconf_sur(bus: &mut Bus, changement: &[u8]) -> Result<String, Echec> {
    let (_, r) = bus.agir(
        DCONF_ECRIVAIN,
        "Change",
        vec![Valeur::Tableau(changement.iter().map(|o| Valeur::Octet(*o)).collect())],
        None,
        &mut Vec::new(),
    )?;
    r.first()
        .and_then(Valeur::texte)
        .map(String::from)
        .ok_or_else(|| echec(super::mal_forme("étiquette")))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn la_liste_est_fermee() {
        // Rien sur le bus système : chaque action vise la session (systemd de l'utilisateur, notifications, dconf).
        for (service, _, interface, methode, _) in ACTIONS {
            assert!([DBUS, SYSTEMD, NOTIFICATIONS, DCONF].contains(service), "{service}");
            assert!(
                !super::super::LECTURES.contains(&(interface, methode)),
                "{methode} est déjà une lecture"
            );
        }
        assert!(action("org.freedesktop.systemd1.Manager", "PowerOff").is_err());
        assert!(action("org.freedesktop.systemd1.Manager", "StartTransientUnit").is_err());
        assert!(action("org.freedesktop.UDisks2.Filesystem", "Mount").is_err());
    }

    #[test]
    fn seules_les_unites_de_vanguard() {
        for bonne in [
            "vanguard-veilleur.service",
            "vanguard-sauvegarde.timer",
            "vanguard-entretien.timer",
        ] {
            assert!(unite_de_vanguard(bonne), "{bonne}");
        }
        for mauvaise in [
            "ssh.service",
            "vanguard-.service",
            "vanguard-x.target",
            "vanguard-x;reboot.service",
            "vanguard-x .service",
            "../vanguard-x.service",
            "vanguardx.service",
            "",
        ] {
            assert!(!unite_de_vanguard(mauvaise), "{mauvaise}");
        }
        // Refusée avant tout envoi, même sans bus.
        assert!(!utilisateur(Geste::Arreter, "sshd.service"));
        // Sous les essais, rien ne part vers le vrai bus, même pour une unité de Vanguard.
        assert!(!utilisateur(Geste::Recharger, ""));
        assert!(notifier("x", "y").is_err());
    }

    #[test]
    fn adresses_de_la_session() {
        assert_eq!(
            prises_de("unix:path=/run/user/1000/bus,guid=0123"),
            [Prise::Chemin("/run/user/1000/bus".into())]
        );
        assert_eq!(
            prises_de("tcp:host=x;unix:abstract=/tmp/dbus-AbC%2c1,guid=1;unix:path=/a%20b"),
            [
                Prise::Abstraite(b"/tmp/dbus-AbC,1".to_vec()),
                Prise::Chemin("/a b".into())
            ]
        );
        assert!(prises_de("unix:path=/x%zz").is_empty(), "échappement mal formé");
        let vide = prises_de("");
        assert!(vide.is_empty(), "{vide:?}");
    }

    // ── Un faux bus de session : il lit l'authentification, Hello, puis répond selon un scénario ──

    fn lire_ligne(s: &mut UnixStream) {
        let mut l = Vec::new();
        let mut o = [0];
        while !l.ends_with(b"\r\n") {
            s.read_exact(&mut o).unwrap();
            l.push(o[0]);
        }
    }

    fn lire(s: &mut UnixStream) -> Message {
        let mut debut = [0; 16];
        s.read_exact(&mut debut).unwrap();
        let mut octets = debut.to_vec();
        octets.resize(super::super::longueur_totale(&debut).unwrap(), 0);
        s.read_exact(&mut octets[16..]).unwrap();
        Message::decoder_si(&octets, |_| true).unwrap()
    }

    fn retour(a: &Message, signature: &str, corps: Vec<Valeur>, expediteur: &str) -> Vec<u8> {
        Message {
            genre: RETOUR,
            serie: 900 + a.serie,
            reponse_a: Some(a.serie),
            expediteur: Some(expediteur.into()),
            signature: signature.into(),
            corps,
            ..Message::default()
        }
        .encoder()
        .unwrap()
    }

    fn signal_fin(job: &str, resultat: &str, expediteur: &str) -> Vec<u8> {
        Message {
            genre: SIGNAL,
            serie: 77,
            chemin: Some(CHEMIN_SYSTEMD.into()),
            interface: Some(GESTIONNAIRE.into()),
            membre: Some("JobRemoved".into()),
            expediteur: Some(expediteur.into()),
            signature: "uoss".into(),
            corps: vec![
                Valeur::U32(7),
                Valeur::texte_de(job),
                Valeur::texte_de("vanguard-x.service"),
                Valeur::texte_de(resultat),
            ],
            ..Message::default()
        }
        .encoder()
        .unwrap()
    }

    /// Le bus côté client, et le fil du faux bus qui rend les membres appelés, dans l'ordre.
    fn faux_bus(
        scenario: impl FnOnce(&mut UnixStream, &mut Vec<String>) + Send + 'static,
    ) -> (Bus, std::thread::JoinHandle<Vec<String>>) {
        let (client, mut serveur) = UnixStream::pair().unwrap();
        let fil = std::thread::spawn(move || {
            lire_ligne(&mut serveur);
            serveur.write_all(b"OK 0123456789abcdef0123456789abcdef\r\n").unwrap();
            lire_ligne(&mut serveur);
            let hello = lire(&mut serveur);
            serveur
                .write_all(&retour(&hello, "s", vec![Valeur::texte_de(":1.9")], DBUS))
                .unwrap();
            let mut appels = Vec::new();
            scenario(&mut serveur, &mut appels);
            appels
        });
        (Bus::sur(client).unwrap(), fil)
    }

    /// enable --now : EnableUnitFiles, Reload, AddMatch, Subscribe, StartUnit, puis la fin du job, arrivée AVANT la
    /// réponse de StartUnit ; un faux JobRemoved d'un autre programme de la session ne compte pas.
    #[test]
    fn activer_attend_la_fin_du_job() {
        for (resultat, reussi) in [("done", true), ("failed", false)] {
            let (mut bus, fil) = faux_bus(move |s, appels| {
                let systemd = ":1.2";
                for _ in 0..5 {
                    let a = lire(s);
                    let m = a.membre.clone().unwrap();
                    assert_eq!(a.drapeaux & 0x4, 0, "jamais d'autorisation interactive");
                    let r = match m.as_str() {
                        "EnableUnitFiles" => {
                            assert_eq!(
                                a.corps[0],
                                Valeur::Tableau(vec![Valeur::texte_de("vanguard-x.service")])
                            );
                            retour(
                                &a,
                                "ba(sss)",
                                vec![Valeur::Booleen(true), Valeur::Tableau(Vec::new())],
                                systemd,
                            )
                        }
                        "StartUnit" => {
                            s.write_all(&signal_fin("/org/freedesktop/systemd1/job/9", "done", ":1.66"))
                                .unwrap();
                            s.write_all(&signal_fin("/org/freedesktop/systemd1/job/9", resultat, systemd))
                                .unwrap();
                            retour(
                                &a,
                                "o",
                                vec![Valeur::texte_de("/org/freedesktop/systemd1/job/9")],
                                systemd,
                            )
                        }
                        "AddMatch" => retour(&a, "", Vec::new(), DBUS),
                        _ => retour(&a, "", Vec::new(), systemd),
                    };
                    appels.push(m);
                    s.write_all(&r).unwrap();
                }
            });
            let r = systemd_sur(&mut bus, Geste::Activer { maintenant: true }, "vanguard-x.service");
            assert_eq!(r.is_ok(), reussi, "{r:?}");
            assert_eq!(
                fil.join().unwrap(),
                ["EnableUnitFiles", "Reload", "AddMatch", "Subscribe", "StartUnit"]
            );
        }
    }

    /// Une erreur de systemd (unité inconnue) est une erreur, pas une réussite.
    #[test]
    fn erreur_de_systemd() {
        let (mut bus, fil) = faux_bus(|s, appels| {
            let a = lire(s);
            appels.push(a.membre.clone().unwrap());
            let e = Message {
                genre: ERREUR,
                serie: 5,
                reponse_a: Some(a.serie),
                nom_erreur: Some("org.freedesktop.systemd1.NoSuchUnit".into()),
                signature: "s".into(),
                corps: vec![Valeur::texte_de("Unit vanguard-x.service not loaded.")],
                ..Message::default()
            };
            s.write_all(&e.encoder().unwrap()).unwrap();
        });
        let r = systemd_sur(&mut bus, Geste::Demarrer { attendre: false }, "vanguard-x.service");
        assert!(r.unwrap_err().to_string().contains("NoSuchUnit"));
        assert_eq!(fil.join().unwrap(), ["StartUnit"]);
    }

    /// Notify : la signature, l'urgence critique en octet, un texte trop long coupé sans casser un caractère.
    #[test]
    fn notification_par_un_faux_bus() {
        let (mut bus, fil) = faux_bus(|s, appels| {
            let a = lire(s);
            assert_eq!(a.signature, "susssasa{sv}i");
            assert_eq!(a.destination.as_deref(), Some(NOTIFICATIONS));
            let indices = &a.corps[6];
            assert_eq!(indices.champ("urgency"), Some(&Valeur::Octet(2)));
            assert!(a.corps[4].texte().unwrap().len() <= TEXTE_MAX);
            appels.push(a.membre.clone().unwrap());
            s.write_all(&retour(&a, "u", vec![Valeur::U32(12)], ":1.5")).unwrap();
        });
        let long = "é".repeat(TEXTE_MAX);
        assert_eq!(notifier_sur(&mut bus, "Alerte", &long), Ok(12));
        assert_eq!(fil.join().unwrap(), ["Notify"]);
    }

    /// La vraie notification sur le bus de cette session : seulement demandée par son nom (`cargo test --
    /// --ignored notification_reelle`), jamais dans la suite.
    #[test]
    #[ignore = "affiche une vraie notification"]
    fn notification_reelle() {
        ACTION_REELLE.with(|r| r.set(true));
        let n = notifier("Vanguard", "Essai de notification par D-Bus").unwrap();
        assert!(n > 0);
    }
}
