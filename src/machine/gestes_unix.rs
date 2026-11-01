//! La grammaire des gestes de Linux que l'assistant élevé (`machine::assistant`) fait en root, à côté des ordres du
//! blocage (`protection::blocage::ordres`) : une ligne « `vanguard:geste <famille> <champs>` » ne fait que DÉSIGNER
//! un geste d'une liste fermée, et l'enfant root la relit, la rejuge avec ses propres yeux, puis le fait sans shell,
//! par le chemin absolu de l'outil (`commande::outil_systeme`) et dans un environnement vidé
//! (`commande::environnement_propre`). Rien ici ne lance quoi que ce soit : du code pur, sans E/S, compilé partout
//! pour ses tests et lu par le banc de fuzzing (fuzz/fuzz_targets/gestes_unix.rs).
//!
//! Les familles :
//! - `programme <id>` : un programme de la table `PROGRAMMES`, avec ses arguments figés. La ligne ne porte ni chemin,
//!   ni argument, ni texte libre : seulement l'identifiant ;
//! - `unite <action> <nom>` : une action fermée (`ActionUnite`) sur une unité de systemd de la table `UNITES_CONNUES`,
//!   faite par le bus système (`machine::linux::dbus::systeme`), jamais par systemctl ; `unite reinitialiser-echecs`
//!   (reset-failed, sans nom) ;
//! - `unite-designee <action> <nom>` : arrêter, ou ne plus lancer au démarrage, une unité qui n'est pas dans la table
//!   mais que `protection::distance` a trouvée (un logiciel de prise de contrôle à distance) ; le nom suit une règle
//!   stricte (`nom_admis`), et l'enfant relit le fichier de l'unité et le reconnaît lui-même avant d'agir ;
//! - `signatures-clamav` : le geste composé de la mise à jour des signatures (arrêter clamav-freshclam, freshclam,
//!   le réactiver), pour qu'aucun « arrêter clamav-freshclam » isolé n'existe.
//!
//! Les familles des paquets, des fichiers de configuration et du réseau suivront (plan du lot Unix, U2, U4 à U7), sur
//! le même canal et avec les mêmes bornes ; elles reprendront `unite` telle quelle (masquer et démasquer y viendront
//! avec elles).
//!
//! Un geste qui affaiblit la protection ou supprime quelque chose (`demande_accord`) : l'enfant demande alors l'accord
//! de la personne sur son terminal (/dev/tty), et le refuse sans terminal (`assistant`). Un pare-feu n'est jamais
//! coupé : la ligne qui le demanderait ne se relit même pas (`refus`).

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

/// Devant chaque geste : le préfixe des ordres (`ordres::PREFIXE`) suivi de « geste », un verbe qu'aucun ordre ni
/// aucun geste de Windows (`gestes.rs` : `vanguard:programme`, `vanguard:service`…) ne prend.
pub(crate) const PREFIXE: &str = "vanguard:geste ";
/// La plus longue ligne admise sur le canal : celle d'un ordre du blocage, `ordres::LIGNE_MAX` (repris ici pour que le
/// banc de fuzzing lise ce module seul ; l'essai `bornes_du_canal_communes_avec_les_ordres` les garde égales). Le
/// nombre de lignes d'une liste est borné par le canal lui-même (`ordres::LIGNES_MAX`, lu par l'assistant).
pub(crate) const LIGNE_MAX: usize = 8448;
/// La plus longue ligne d'un geste : la famille, l'action et un nom d'unité de `NOM_UNITE_MAX` octets
/// (« vanguard:geste unite-designee desactiver-sans-arreter », espace comprise, + 128 = 182) ; tout ce qui dépasse est refusé avant
/// d'être découpé.
pub(crate) const GESTE_MAX: usize = 192;
const _: () = assert!(GESTE_MAX <= LIGNE_MAX, "un geste tient dans une ligne du canal");

/// Un programme figé : l'outil, cherché par l'enfant dans les dossiers du système, et ses arguments, tous écrits ici.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Programme {
    /// `[a-z0-9-]`, 40 caractères au plus.
    pub id: &'static str,
    /// Le nom de l'outil, sans dossier : l'enfant le cherche par `commande::outil_systeme`, jamais par un PATH.
    pub outil: &'static str,
    pub arguments: &'static [&'static str],
    /// Les codes de sortie qui veulent dire « fait ».
    pub reussites: &'static [i32],
    /// Le délai, en secondes, au-delà duquel l'outil est arrêté et le geste compté en échec.
    pub delai: u64,
    /// Le geste baisse une protection (le remettre comme avant, après un durcissement) : accord sur le terminal.
    pub affaiblit: bool,
    /// Le geste supprime quelque chose : accord sur le terminal.
    pub supprime: bool,
    pub fr: &'static str,
    pub en: &'static str,
}

/// Les signatures de ClamAV : freshclam les télécharge. Seul 0 veut dire « fait » ; tout autre code est une erreur
/// (réseau, miroir, base verrouillée par le service clamav-freshclam), rendue avec sa raison.
pub(crate) static FRESHCLAM: Programme = Programme {
    id: "freshclam",
    outil: "freshclam",
    arguments: &[],
    reussites: &[0],
    delai: 900,
    affaiblit: false,
    supprime: false,
    fr: "Mettre à jour les signatures de virus de ClamAV (freshclam)",
    en: "Update the ClamAV virus signatures (freshclam)",
};

/// La table : un identifiant n'y est qu'une fois (essai `la_table_est_bien_formee`).
pub(crate) static PROGRAMMES: &[&Programme] = &[&FRESHCLAM];

/// Ce que l'enfant fait d'une unité de systemd, par le bus système (comme `systemctl`, sans lui).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionUnite {
    /// `enable --now` : EnableUnitFiles, Reload, puis StartUnit jusqu'à la fin du job.
    Activer,
    /// `disable --now` : DisableUnitFiles, Reload, puis StopUnit jusqu'à la fin du job.
    Desactiver,
    /// `disable` seul : DisableUnitFiles, Reload ; l'unité tourne jusqu'au prochain démarrage.
    DesactiverSansArreter,
    /// `start`.
    Demarrer,
    /// `stop`.
    Arreter,
    /// `try-restart` : seulement si elle tourne déjà (TryRestartUnit).
    Redemarrer,
    /// `reload-or-try-restart` (ReloadOrTryRestartUnit).
    Recharger,
}

impl ActionUnite {
    pub(crate) const TOUTES: [ActionUnite; 7] = [
        ActionUnite::Activer,
        ActionUnite::Desactiver,
        ActionUnite::DesactiverSansArreter,
        ActionUnite::Demarrer,
        ActionUnite::Arreter,
        ActionUnite::Redemarrer,
        ActionUnite::Recharger,
    ];

    /// Le mot de l'action sur la ligne.
    pub(crate) fn mot(self) -> &'static str {
        match self {
            ActionUnite::Activer => "activer",
            ActionUnite::Desactiver => "desactiver",
            ActionUnite::DesactiverSansArreter => "desactiver-sans-arreter",
            ActionUnite::Demarrer => "demarrer",
            ActionUnite::Arreter => "arreter",
            ActionUnite::Redemarrer => "redemarrer",
            ActionUnite::Recharger => "recharger",
        }
    }

    fn depuis_mot(mot: &str) -> Option<Self> {
        Self::TOUTES.into_iter().find(|a| a.mot() == mot)
    }
}

/// Ce que l'enfant protège d'une unité de la table, avant toute action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Garde {
    /// Toute action de la liste est permise.
    Ordinaire,
    /// Un pare-feu : activé ou démarré seulement ; jamais arrêté, désactivé, redémarré ni rechargé (principe « pas
    /// de pare-feu coupé », même un instant : ufw n'a pas de rechargement à lui, ReloadOrTryRestart le redémarrerait).
    PareFeu,
    /// Une protection (audit, antivirus, AppArmor) : la désactiver ou l'arrêter demande l'accord de la personne sur
    /// son terminal.
    Protection,
    /// Le réseau : l'arrêter ou le redémarrer couperait une session à distance entrante ; refusé tant qu'il y en a
    /// une, ou que les connexions ne se lisent pas. Le désactiver demande l'accord : l'ordinateur perdrait le réseau.
    Reseau,
    /// Un service ouvert au réseau local (cups-browsed écoute sur le port UDP 631, jugé « Élevé » au bilan) : l'activer
    /// ou le démarrer demande l'accord de la personne.
    Ouverte,
}

/// Une unité de systemd que Vanguard sait nommer, avec sa garde et ce qu'elle est pour une personne.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UniteConnue {
    /// Le nom complet, suffixe compris (`nom_admis`).
    pub nom: &'static str,
    pub garde: Garde,
    /// Ce qu'elle est, avec son article : « le service d'impression (CUPS) ».
    pub fr: &'static str,
    pub en: &'static str,
}

pub(crate) static UFW: UniteConnue = UniteConnue {
    nom: "ufw.service",
    garde: Garde::PareFeu,
    fr: "le pare-feu ufw",
    en: "the ufw firewall",
};
pub(crate) static FIREWALLD: UniteConnue = UniteConnue {
    nom: "firewalld.service",
    garde: Garde::PareFeu,
    fr: "le pare-feu firewalld",
    en: "the firewalld firewall",
};
pub(crate) static AUDITD: UniteConnue = UniteConnue {
    nom: "auditd.service",
    garde: Garde::Protection,
    fr: "le journal d'audit (auditd)",
    en: "the audit log (auditd)",
};
pub(crate) static APPARMOR: UniteConnue = UniteConnue {
    nom: "apparmor.service",
    garde: Garde::Protection,
    fr: "la protection AppArmor",
    en: "the AppArmor protection",
};
pub(crate) static CLAMAV_FRESHCLAM: UniteConnue = UniteConnue {
    nom: "clamav-freshclam.service",
    garde: Garde::Protection,
    fr: "la mise à jour automatique des signatures de ClamAV (clamav-freshclam)",
    en: "the automatic ClamAV signature updates (clamav-freshclam)",
};
pub(crate) static CLAMAV_DAEMON: UniteConnue = UniteConnue {
    nom: "clamav-daemon.service",
    garde: Garde::Protection,
    fr: "l'antivirus ClamAV en fond (clamav-daemon)",
    en: "the ClamAV background antivirus (clamav-daemon)",
};
pub(crate) static NETWORKMANAGER: UniteConnue = UniteConnue {
    nom: "NetworkManager.service",
    garde: Garde::Reseau,
    fr: "le gestionnaire du réseau (NetworkManager)",
    en: "the network manager (NetworkManager)",
};
pub(crate) static NETWORKD: UniteConnue = UniteConnue {
    nom: "systemd-networkd.service",
    garde: Garde::Reseau,
    fr: "le gestionnaire du réseau (systemd-networkd)",
    en: "the network manager (systemd-networkd)",
};
pub(crate) static CUPS: UniteConnue = UniteConnue {
    nom: "cups.service",
    garde: Garde::Ordinaire,
    fr: "le service d'impression (CUPS)",
    en: "the printing service (CUPS)",
};
pub(crate) static CUPS_BROWSED: UniteConnue = UniteConnue {
    nom: "cups-browsed.service",
    garde: Garde::Ouverte,
    fr: "la recherche d'imprimantes sur le réseau (cups-browsed)",
    en: "the network printer discovery (cups-browsed)",
};
pub(crate) static FSTRIM: UniteConnue = UniteConnue {
    nom: "fstrim.timer",
    garde: Garde::Ordinaire,
    fr: "l'entretien hebdomadaire du SSD (fstrim.timer)",
    en: "the weekly SSD maintenance (fstrim.timer)",
};

/// La table : seules ces unités se nomment par `unite` ; un nom n'y est qu'une fois (essai
/// `la_table_est_bien_formee`). U4 et U6 y ajouteront les leurs (sshd, ollama, smb…).
pub(crate) static UNITES_CONNUES: &[&UniteConnue] = &[
    &UFW,
    &FIREWALLD,
    &AUDITD,
    &APPARMOR,
    &CLAMAV_FRESHCLAM,
    &CLAMAV_DAEMON,
    &NETWORKMANAGER,
    &NETWORKD,
    &CUPS,
    &CUPS_BROWSED,
    &FSTRIM,
];

/// L'unité de la table de ce nom, complet ou sans « .service » (« auditd », « fstrim.timer »).
// Seuls les réglages et le retrait des programmes de contrôle à distance de Linux les demandent.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn unite_connue(nom: &str) -> Option<&'static UniteConnue> {
    UNITES_CONNUES
        .iter()
        .copied()
        .find(|u| u.nom == nom || u.nom.strip_suffix(".service") == Some(nom))
}

/// Le plus long nom d'unité admis (systemd en permet 255 ; aucun service connu n'en approche).
pub(crate) const NOM_UNITE_MAX: usize = 128;
/// Les seuls genres d'unité qu'un geste vise.
const SUFFIXES: [&str; 3] = [".service", ".socket", ".timer"];

/// Un nom d'unité qu'un geste peut porter : 128 octets au plus, lettres ASCII, chiffres, « : _ . @ - » seulement (ni
/// « / », ni « \ », ni espace), sans « .. », un suffixe .service, .socket ou .timer, une base qui commence par une
/// lettre ou un chiffre (jamais une option) et qui n'est pas un gabarit (« x@.service »).
pub(crate) fn nom_admis(nom: &str) -> bool {
    if nom.is_empty() || nom.len() > NOM_UNITE_MAX || nom.contains("..") {
        return false;
    }
    if !nom.bytes().all(|o| o.is_ascii_alphanumeric() || b":_.@-".contains(&o)) {
        return false;
    }
    let Some(base) = SUFFIXES.iter().find_map(|s| nom.strip_suffix(s)) else {
        return false;
    };
    base.bytes().next().is_some_and(|o| o.is_ascii_alphanumeric()) && !base.ends_with('@')
}

/// Le nom d'une unité désignée, recopié (le geste reste `Copy`) : admis (`nom_admis`) et hors de la table, dont les
/// unités ont leur garde et ne se désignent pas autrement.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct NomUnite {
    octets: [u8; NOM_UNITE_MAX],
    longueur: u8,
}

impl NomUnite {
    pub(crate) fn nouveau(nom: &str) -> Option<Self> {
        if !nom_admis(nom) || UNITES_CONNUES.iter().any(|u| u.nom == nom) {
            return None;
        }
        let mut octets = [0; NOM_UNITE_MAX];
        octets.get_mut(..nom.len())?.copy_from_slice(nom.as_bytes());
        Some(NomUnite {
            octets,
            longueur: u8::try_from(nom.len()).ok()?,
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        self.octets
            .get(..usize::from(self.longueur))
            .and_then(|o| std::str::from_utf8(o).ok())
            .unwrap_or_default()
    }
}

impl std::fmt::Debug for NomUnite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NomUnite").field(&self.as_str()).finish()
    }
}

/// Un geste désigné par une ligne, relu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GesteUnix {
    Programme(&'static Programme),
    /// Une action sur une unité de la table.
    Unite(ActionUnite, &'static UniteConnue),
    /// Une unité hors de la table, désignée par son nom : seulement arrêtée, ou plus lancée au démarrage.
    Designee(ActionUnite, NomUnite),
    /// `systemctl reset-failed` : oublie les échecs passés de toutes les unités, sans rien démarrer ni arrêter.
    ReinitialiserEchecs,
    /// Arrêter clamav-freshclam s'il est installé (il verrouille la base), lancer freshclam, puis le réactiver
    /// dans tous les cas.
    SignaturesClamav,
}

impl GesteUnix {
    /// La ligne qui le porte ; `analyser(g.ligne()) == Some(g)` pour tout geste sans `refus`.
    pub(crate) fn ligne(self) -> String {
        match self {
            GesteUnix::Programme(p) => format!("{PREFIXE}programme {}", p.id),
            GesteUnix::Unite(a, u) => format!("{PREFIXE}unite {} {}", a.mot(), u.nom),
            GesteUnix::Designee(a, n) => format!("{PREFIXE}unite-designee {} {}", a.mot(), n.as_str()),
            GesteUnix::ReinitialiserEchecs => format!("{PREFIXE}unite reinitialiser-echecs"),
            GesteUnix::SignaturesClamav => format!("{PREFIXE}signatures-clamav"),
        }
    }

    /// Ce que fait le geste, en une phrase (française et anglaise) : montrée avant l'accord, par le parent, puis par
    /// l'enfant avant de le faire.
    pub(crate) fn phrase(self) -> (String, String) {
        match self {
            GesteUnix::Programme(p) => (p.fr.to_string(), p.en.to_string()),
            GesteUnix::Unite(a, u) => phrase_d_unite(a, u.fr, u.en),
            GesteUnix::Designee(a, n) => phrase_d_unite(
                a,
                &format!("le service {}", n.as_str()),
                &format!("the service {}", n.as_str()),
            ),
            GesteUnix::ReinitialiserEchecs => (
                "Remettre à zéro la liste des services en échec (rien n'est démarré ni arrêté)".to_string(),
                "Clear the list of failed services (nothing is started or stopped)".to_string(),
            ),
            GesteUnix::SignaturesClamav => (
                "Mettre à jour les signatures de virus de ClamAV, puis garder leur mise à jour automatique".to_string(),
                "Update the ClamAV virus signatures, then keep their automatic updates on".to_string(),
            ),
        }
    }

    /// Pourquoi ce geste n'est jamais fait, quoi qu'en dise la ligne : un pare-feu coupé, une unité désignée à qui
    /// l'on ferait autre chose que l'arrêter ou la retirer du démarrage. Une telle ligne ne se relit pas
    /// (`analyser`), et l'enfant le rejuge encore avant d'agir.
    pub(crate) fn refus(self) -> Option<(&'static str, &'static str)> {
        match self {
            GesteUnix::Unite(a, u)
                if u.garde == Garde::PareFeu && !matches!(a, ActionUnite::Activer | ActionUnite::Demarrer) =>
            {
                Some((
                    "Vanguard ne coupe jamais un pare-feu, même un instant : ni arrêt, ni désactivation, ni redémarrage, ni rechargement",
                    "Vanguard never turns a firewall off, even for a moment: no stop, no disabling, no restart, no reload",
                ))
            }
            GesteUnix::Designee(a, _) if !matches!(a, ActionUnite::Arreter | ActionUnite::DesactiverSansArreter) => {
                Some((
                    "un service désigné par son nom ne peut qu'être arrêté, ou ne plus être lancé au démarrage",
                    "a service named by its name can only be stopped, or no longer started at startup",
                ))
            }
            _ => None,
        }
    }

    /// L'enfant demande-t-il l'accord de la personne, sur son terminal, avant de le faire ? Oui pour ce qui
    /// affaiblit : une protection baissée, un service ouvert au réseau mis en marche, le réseau coupé, un programme
    /// qui affaiblit ou supprime (`pourquoi_l_accord` dit lequel).
    pub(crate) fn demande_accord(self) -> bool {
        self.pourquoi_l_accord().is_some()
    }

    /// Pourquoi l'enfant demande l'accord, dit dans la question ; `None` : il ne le demande pas.
    pub(crate) fn pourquoi_l_accord(self) -> Option<(&'static str, &'static str)> {
        let couper = |a| {
            matches!(
                a,
                ActionUnite::Desactiver | ActionUnite::DesactiverSansArreter | ActionUnite::Arreter
            )
        };
        match self {
            GesteUnix::Programme(p) if p.supprime => Some(("ceci supprime quelque chose", "this deletes something")),
            GesteUnix::Programme(p) if p.affaiblit => Some(("ceci baisse une protection", "this lowers a protection")),
            GesteUnix::Unite(a, u) if u.garde == Garde::Protection && couper(a) => {
                Some(("ceci baisse une protection", "this lowers a protection"))
            }
            GesteUnix::Unite(a, u) if u.garde == Garde::Reseau && couper(a) => Some((
                "ceci coupe le réseau de cet ordinateur",
                "this cuts this computer's network",
            )),
            GesteUnix::Unite(ActionUnite::Activer | ActionUnite::Demarrer, u) if u.garde == Garde::Ouverte => Some((
                "ceci ouvre cet ordinateur au réseau local",
                "this opens this computer to the local network",
            )),
            _ => None,
        }
    }

    /// Le geste peut-il couper une session à distance entrante (le réseau arrêté ou redémarré) ? L'enfant le refuse
    /// alors tant qu'une session est ouverte. Arrêter un logiciel de prise de contrôle désigné n'y entre pas : ses
    /// propres connexions ne bloquent jamais son retrait (le faux technicien est justement connecté par lui, et la
    /// personne a déjà choisi de le fermer), et l'arrêter n'affaiblit rien.
    pub(crate) fn coupe_session(self) -> bool {
        match self {
            GesteUnix::Unite(a, u) => {
                u.garde == Garde::Reseau
                    && matches!(
                        a,
                        ActionUnite::Arreter | ActionUnite::Desactiver | ActionUnite::Redemarrer
                    )
            }
            GesteUnix::Designee(..)
            | GesteUnix::Programme(_)
            | GesteUnix::ReinitialiserEchecs
            | GesteUnix::SignaturesClamav => false,
        }
    }

    /// Le geste passe-t-il par systemd (le bus système) ? Sans systemd, l'enfant le refuse en le disant.
    pub(crate) fn par_systemd(self) -> bool {
        !matches!(self, GesteUnix::Programme(_))
    }

    /// Le geste a-t-il un sens sur ce système ? Linux seulement : sous macOS, rien n'est converti avant un essai sur un
    /// vrai Mac (plan du lot Unix, D8). L'absence de systemd n'y entre pas : elle se dit à part (`par_systemd`), sans
    /// faire refuser toute la liste comme une liste étrangère.
    #[allow(
        clippy::unused_self,
        reason = "les familles à venir (paquets) diront chacune où elles valent"
    )]
    pub(crate) fn permis_ici(self) -> bool {
        cfg!(target_os = "linux")
    }
}

/// La phrase d'une action sur une unité que `fr` et `en` décrivent, article compris (aucune préposition devant :
/// « à le » ou « de la » ne s'accorderaient pas).
fn phrase_d_unite(a: ActionUnite, fr: &str, en: &str) -> (String, String) {
    match a {
        ActionUnite::Activer => (
            format!("Activer {fr} (tout de suite et à chaque démarrage)"),
            format!("Turn on {en} (right away and at every startup)"),
        ),
        ActionUnite::Desactiver => (
            format!("Désactiver {fr} (tout de suite et aux prochains démarrages)"),
            format!("Turn off {en} (right away and at the next startups)"),
        ),
        ActionUnite::DesactiverSansArreter => (
            format!("Ne plus lancer {fr} au démarrage (sans l'arrêter maintenant)"),
            format!("Stop starting {en} at startup (without stopping it now)"),
        ),
        ActionUnite::Demarrer => (format!("Démarrer {fr}"), format!("Start {en}")),
        ActionUnite::Arreter => (format!("Arrêter {fr}"), format!("Stop {en}")),
        ActionUnite::Redemarrer => (
            format!("Redémarrer {fr} (seulement si ce service tourne déjà)"),
            format!("Restart {en} (only if it is already running)"),
        ),
        ActionUnite::Recharger => (
            format!("Recharger {fr} (relire sa configuration sans l'arrêter)"),
            format!("Reload {en} (read its configuration again without stopping it)"),
        ),
    }
}

/// Le geste qui remet une unité de la table dans l'état noté par `optimiser` : « enabled », activée et lancée ;
/// « disabled », désactivée et arrêtée. Aucun pour un autre état (« masked » reste une commande montrée, jusqu'à U4),
/// pour une unité hors de la table, ni pour un geste refusé (un pare-feu).
// Seuls les réglages et le retrait des programmes de contrôle à distance de Linux les demandent.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn geste_d_unite(nom: &str, etat: &str) -> Option<GesteUnix> {
    let u = unite_connue(nom)?;
    let a = match etat {
        "enabled" => ActionUnite::Activer,
        "disabled" => ActionUnite::Desactiver,
        _ => return None,
    };
    let g = GesteUnix::Unite(a, u);
    g.refus().is_none().then_some(g)
}

/// Le geste d'une unité désignée par son nom, s'il est admis.
// Seuls les réglages et le retrait des programmes de contrôle à distance de Linux les demandent.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn designee(a: ActionUnite, nom: &str) -> Option<GesteUnix> {
    let g = GesteUnix::Designee(a, NomUnite::nouveau(nom)?);
    g.refus().is_none().then_some(g)
}

/// Un identifiant de la table : minuscules ASCII, chiffres et tirets, 40 caractères au plus.
fn identifiant(t: &str) -> bool {
    !t.is_empty() && t.len() <= 40 && t.bytes().all(|o| matches!(o, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// Le geste que porte une ligne, si et seulement si la ligne est exactement sa forme admise : le préfixe, une famille
/// de la liste, des champs séparés par une seule espace, réécrits à l'identique (une majuscule, une espace de trop, un
/// champ en plus, un octet nul : refusés), et un geste que rien ne refuse (`refus`).
pub(crate) fn analyser(ligne: &str) -> Option<GesteUnix> {
    if ligne.len() > GESTE_MAX {
        return None;
    }
    let reste = ligne.strip_prefix(PREFIXE)?;
    let mots: Vec<&str> = reste.split(' ').collect();
    let geste = match mots.as_slice() {
        ["programme", id] if identifiant(id) => GesteUnix::Programme(PROGRAMMES.iter().copied().find(|p| p.id == *id)?),
        ["unite", "reinitialiser-echecs"] => GesteUnix::ReinitialiserEchecs,
        ["unite", action, nom] => GesteUnix::Unite(
            ActionUnite::depuis_mot(action)?,
            UNITES_CONNUES.iter().copied().find(|u| u.nom == *nom)?,
        ),
        ["unite-designee", action, nom] => {
            GesteUnix::Designee(ActionUnite::depuis_mot(action)?, NomUnite::nouveau(nom)?)
        }
        ["signatures-clamav"] => GesteUnix::SignaturesClamav,
        _ => return None,
    };
    if geste.refus().is_some() {
        return None;
    }
    (geste.ligne() == ligne).then_some(geste)
}

/// La ligne commence-t-elle comme un geste (bien formé ou non) ? Une telle ligne n'est jamais confiée à un shell :
/// refusée si elle ne se relit pas.
pub(crate) fn a_le_prefixe(ligne: &str) -> bool {
    ligne.starts_with(PREFIXE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les bornes reprises d'`ordres` restent les siennes : le canal n'a qu'une limite.
    #[test]
    fn bornes_du_canal_communes_avec_les_ordres() {
        use crate::protection::blocage::ordres;
        assert_eq!(LIGNE_MAX, ordres::LIGNE_MAX);
        assert!(PREFIXE.starts_with(ordres::PREFIXE));
    }

    #[test]
    fn la_table_est_bien_formee() {
        let mut vus = std::collections::HashSet::new();
        for p in PROGRAMMES {
            assert!(identifiant(p.id), "{}", p.id);
            assert!(vus.insert(p.id), "{} en double", p.id);
            // L'outil est un nom, jamais un chemin ni une option.
            assert!(identifiant(p.outil), "{}", p.outil);
            assert!(!p.reussites.is_empty() && p.delai > 0);
            assert!(!p.fr.is_empty() && !p.en.is_empty());
            // Aucun argument ne fait passer un shell, une expansion ou un saut de ligne.
            for a in p.arguments {
                assert!(
                    !a.is_empty() && !a.contains(['\0', '\n', '\r', '$', '`', ';', '|', '&']),
                    "{a}"
                );
            }
            let g = GesteUnix::Programme(p);
            assert!(g.ligne().len() <= GESTE_MAX);
        }
        let mut noms = std::collections::HashSet::new();
        for u in UNITES_CONNUES {
            assert!(nom_admis(u.nom), "{}", u.nom);
            assert!(noms.insert(u.nom), "{} en double", u.nom);
            assert!(!u.fr.is_empty() && !u.en.is_empty());
            // Sans « .service », le nom ne désigne qu'elle.
            assert_eq!(unite_connue(u.nom), Some(*u));
        }
        // Le plus long geste possible tient dans la borne.
        let plus_long = GesteUnix::Designee(
            ActionUnite::DesactiverSansArreter,
            NomUnite::nouveau(&format!("{}.service", "a".repeat(NOM_UNITE_MAX - 8))).unwrap(),
        );
        assert!(plus_long.ligne().len() <= GESTE_MAX);
    }

    /// Propriété : chaque geste de la table se relit tel quel (`analyser(ligne(g)) == g`).
    #[test]
    fn aller_retour_de_chaque_geste() {
        for p in PROGRAMMES {
            let g = GesteUnix::Programme(p);
            assert_eq!(analyser(&g.ligne()), Some(g));
            assert!(a_le_prefixe(&g.ligne()));
        }
        let mut admis = 0;
        for a in ActionUnite::TOUTES {
            for u in UNITES_CONNUES {
                let g = GesteUnix::Unite(a, u);
                // Un geste refusé ne se relit jamais ; tous les autres se relisent tels quels.
                let attendu = g.refus().is_none().then_some(g);
                assert_eq!(analyser(&g.ligne()), attendu, "{}", g.ligne());
                admis += usize::from(attendu.is_some());
            }
            let d = GesteUnix::Designee(a, NomUnite::nouveau("anydesk.service").unwrap());
            assert_eq!(analyser(&d.ligne()), d.refus().is_none().then_some(d), "{}", d.ligne());
        }
        // 7 actions × 11 unités, moins les 5 refusées pour chacun des deux pare-feu (seuls Activer et Demarrer
        // passent).
        assert_eq!(admis, 7 * UNITES_CONNUES.len() - 2 * 5);
        for g in [GesteUnix::ReinitialiserEchecs, GesteUnix::SignaturesClamav] {
            assert_eq!(analyser(&g.ligne()), Some(g));
        }
        assert_eq!(
            GesteUnix::Unite(ActionUnite::Desactiver, &CUPS_BROWSED).ligne(),
            "vanguard:geste unite desactiver cups-browsed.service"
        );
        assert_eq!(
            GesteUnix::ReinitialiserEchecs.ligne(),
            "vanguard:geste unite reinitialiser-echecs"
        );
        assert_eq!(
            designee(ActionUnite::Arreter, "anydesk.service")
                .map(GesteUnix::ligne)
                .as_deref(),
            Some("vanguard:geste unite-designee arreter anydesk.service")
        );
    }

    /// Un pare-feu n'est jamais coupé, même par une ligne bien formée ; une unité désignée ne fait que s'arrêter ou
    /// sortir du démarrage.
    #[test]
    fn pare_feu_jamais_coupe() {
        for pf in [&UFW, &FIREWALLD] {
            for a in ActionUnite::TOUTES {
                let permis = matches!(a, ActionUnite::Activer | ActionUnite::Demarrer);
                assert_eq!(GesteUnix::Unite(a, pf).refus().is_none(), permis, "{a:?} {}", pf.nom);
            }
            assert_eq!(geste_d_unite(pf.nom, "disabled"), None);
        }
        for l in [
            "vanguard:geste unite arreter ufw.service",
            "vanguard:geste unite desactiver ufw.service",
            "vanguard:geste unite desactiver-sans-arreter firewalld.service",
            "vanguard:geste unite redemarrer firewalld.service",
            // Recharger ufw le redémarrerait (pas de rechargement à lui) : coupé un instant.
            "vanguard:geste unite recharger ufw.service",
            "vanguard:geste unite recharger firewalld.service",
            "vanguard:geste unite desactiver firewalld.service",
            // Un pare-feu ne se désigne pas non plus par son nom, ni aucune unité de la table.
            "vanguard:geste unite-designee arreter ufw.service",
            "vanguard:geste unite-designee arreter NetworkManager.service",
            "vanguard:geste unite-designee arreter auditd.service",
            // Une unité désignée ne se démarre, ne s'active ni ne se redémarre.
            "vanguard:geste unite-designee activer anydesk.service",
            "vanguard:geste unite-designee demarrer anydesk.service",
            "vanguard:geste unite-designee desactiver anydesk.service",
            "vanguard:geste unite-designee redemarrer anydesk.service",
        ] {
            assert_eq!(analyser(l), None, "{l}");
        }
    }

    /// Les noms hostiles d'une unité désignée : chemin, remontée, gabarit, sans suffixe, trop long, octet nul,
    /// option, espace, échappement de systemd.
    #[test]
    fn noms_d_unite_hostiles() {
        for bon in [
            "anydesk.service",
            "teamviewerd.service",
            "rustdesk.service",
            // Instances de gabarit, coupées par concat! : le garde-fou de confidentialité les lirait comme des courriels.
            concat!("x11vnc", "@", "1.service"),
            "dwagent.timer",
            "a.socket",
            concat!("chrome-remote-desktop", "@", "alice.service"),
        ] {
            assert!(nom_admis(bon), "{bon}");
            assert!(NomUnite::nouveau(bon).is_some(), "{bon}");
        }
        let trop_long = format!("{}.service", "a".repeat(NOM_UNITE_MAX - 7));
        assert_eq!(trop_long.len(), NOM_UNITE_MAX + 1);
        for mauvais in [
            "",
            "../x.service",
            "..service",
            "a..b.service",
            "a/b.service",
            "/etc/systemd/system/anydesk.service",
            "@.service",
            "@",
            "x@.service",
            ".service",
            "-x.service",
            "anydesk",
            "anydesk.target",
            "anydesk.mount",
            "anydesk.service\0",
            "any\0desk.service",
            "any desk.service",
            "any\\x2ddesk.service",
            "anydesk.service;reboot",
            "anydesk.service\n",
            "anydésk.service",
            trop_long.as_str(),
        ] {
            assert!(
                !nom_admis(mauvais) || NomUnite::nouveau(mauvais).is_none(),
                "{mauvais:?}"
            );
            assert_eq!(designee(ActionUnite::Arreter, mauvais), None, "{mauvais:?}");
            let l = format!("{PREFIXE}unite-designee arreter {mauvais}");
            assert_eq!(analyser(&l), None, "{l:?}");
        }
        // Le plus long admis se relit tel quel.
        let long = format!("{}.service", "a".repeat(NOM_UNITE_MAX - 8));
        let g = designee(ActionUnite::DesactiverSansArreter, &long).unwrap();
        assert_eq!(analyser(&g.ligne()), Some(g));
        if let GesteUnix::Designee(_, n) = g {
            assert_eq!(n.as_str(), long);
        }
    }

    /// Ce que l'enfant rejuge de chaque geste : l'accord pour ce qui affaiblit (une protection baissée, le réseau
    /// coupé, cups-browsed mis en marche), la session à distance pour le réseau seulement.
    #[test]
    fn accord_et_sessions() {
        let accord = |a, u| GesteUnix::Unite(a, u).demande_accord();
        for u in [&AUDITD, &APPARMOR, &CLAMAV_FRESHCLAM, &CLAMAV_DAEMON] {
            assert!(accord(ActionUnite::Desactiver, u));
            assert!(accord(ActionUnite::DesactiverSansArreter, u));
            assert!(accord(ActionUnite::Arreter, u));
            assert!(!accord(ActionUnite::Activer, u));
            assert!(!accord(ActionUnite::Redemarrer, u));
        }
        assert!(!accord(ActionUnite::Desactiver, &CUPS_BROWSED));
        // cups-browsed écoute le réseau local : le mettre en marche demande l'accord, l'arrêter non.
        assert!(accord(ActionUnite::Activer, &CUPS_BROWSED));
        assert!(accord(ActionUnite::Demarrer, &CUPS_BROWSED));
        assert!(!accord(ActionUnite::Arreter, &CUPS_BROWSED));
        assert!(!accord(ActionUnite::Activer, &CUPS));
        // Le réseau coupé demande l'accord ; redémarré ou rechargé, non (la session à distance, elle, est rejugée).
        for u in [&NETWORKMANAGER, &NETWORKD] {
            assert!(accord(ActionUnite::Desactiver, u));
            assert!(accord(ActionUnite::DesactiverSansArreter, u));
            assert!(accord(ActionUnite::Arreter, u));
            assert!(!accord(ActionUnite::Redemarrer, u));
            assert!(!accord(ActionUnite::Recharger, u));
            assert!(!accord(ActionUnite::Activer, u));
        }
        assert!(!GesteUnix::SignaturesClamav.demande_accord());
        assert!(!GesteUnix::ReinitialiserEchecs.demande_accord());
        let coupe = |a, u| GesteUnix::Unite(a, u).coupe_session();
        for u in [&NETWORKMANAGER, &NETWORKD] {
            assert!(coupe(ActionUnite::Redemarrer, u));
            assert!(coupe(ActionUnite::Arreter, u));
            assert!(coupe(ActionUnite::Desactiver, u));
            assert!(!coupe(ActionUnite::Activer, u));
        }
        assert!(!coupe(ActionUnite::Desactiver, &CUPS_BROWSED));
        // Arrêter un logiciel de prise de contrôle n'est jamais bloqué par ses propres connexions, ni le retirer du
        // démarrage ; et ni l'un ni l'autre ne demande l'accord (rien n'est affaibli).
        for a in [ActionUnite::Arreter, ActionUnite::DesactiverSansArreter] {
            let g = designee(a, "anydesk.service").unwrap();
            assert!(!g.coupe_session() && !g.demande_accord(), "{a:?}");
        }
        assert!(!GesteUnix::Programme(&FRESHCLAM).par_systemd());
        assert!(GesteUnix::SignaturesClamav.par_systemd() && GesteUnix::ReinitialiserEchecs.par_systemd());
    }

    /// Les réglages d'`optimiser` (nom court ou complet, état noté) deviennent un geste seulement pour « enabled » et
    /// « disabled » d'une unité de la table.
    #[test]
    fn geste_d_un_reglage() {
        assert_eq!(
            geste_d_unite("cups-browsed", "disabled"),
            Some(GesteUnix::Unite(ActionUnite::Desactiver, &CUPS_BROWSED))
        );
        assert_eq!(
            geste_d_unite("fstrim.timer", "enabled"),
            Some(GesteUnix::Unite(ActionUnite::Activer, &FSTRIM))
        );
        assert_eq!(
            geste_d_unite("auditd", "enabled"),
            Some(GesteUnix::Unite(ActionUnite::Activer, &AUDITD))
        );
        assert_eq!(geste_d_unite("auditd", "masked"), None);
        assert_eq!(geste_d_unite("apport", "disabled"), None);
        assert_eq!(geste_d_unite("cups-browsed", "static"), None);
        // « fstrim » sans suffixe serait fstrim.service, pas le minuteur.
        assert_eq!(unite_connue("fstrim"), None);
    }

    /// Une ligne qui n'a pas exactement la forme d'un geste n'en désigne aucun.
    #[test]
    fn refus_de_l_etranger() {
        for l in [
            "",
            "vanguard:geste",
            "vanguard:geste ",
            "vanguard:geste programme",
            "vanguard:geste programme ",
            "vanguard:geste programme inconnu",
            "vanguard:geste programme FRESHCLAM",
            "vanguard:geste programme freshclam ",
            "vanguard:geste programme  freshclam",
            "vanguard:geste programme freshclam --datadir=/tmp",
            "vanguard:geste programme freshclam\0",
            "vanguard:geste programme freshclam\n",
            "vanguard:geste programme ../freshclam",
            "vanguard:geste programme /usr/bin/freshclam",
            "vanguard:geste famille-inconnue freshclam",
            "vanguard:geste Programme freshclam",
            " vanguard:geste programme freshclam",
            "vanguard:programme freshclam",
            "sudo freshclam",
        ] {
            assert_eq!(analyser(l), None, "{l:?}");
        }
        for l in [
            "vanguard:geste unite",
            "vanguard:geste unite activer",
            "vanguard:geste unite activer cups",
            "vanguard:geste unite activer cups.service ",
            "vanguard:geste unite  activer cups.service",
            "vanguard:geste unite Activer cups.service",
            "vanguard:geste unite activer CUPS.service",
            "vanguard:geste unite activer sshd.service",
            "vanguard:geste unite masquer cups.service",
            "vanguard:geste unite activer cups.service --now",
            "vanguard:geste unite reinitialiser-echecs cups.service",
            "vanguard:geste unite reinitialiser-echecs ",
            "vanguard:geste unite-designee arreter",
            "vanguard:geste unite-designee arreter anydesk.service anydesk.service",
            "vanguard:geste signatures-clamav ",
            "vanguard:geste signatures-clamav freshclam",
            "vanguard:geste Signatures-clamav",
        ] {
            assert_eq!(analyser(l), None, "{l:?}");
        }
        let longue = format!("{PREFIXE}programme {}", "a".repeat(GESTE_MAX));
        assert_eq!(analyser(&longue), None);
        let tres_longue = format!("{PREFIXE}programme freshclam{}", " ".repeat(LIGNE_MAX));
        assert_eq!(analyser(&tres_longue), None);
    }

    /// Un geste de Linux n'est permis que sous Linux (aucun sous macOS, plan D8).
    #[test]
    fn permis_sous_linux_seulement() {
        assert_eq!(GesteUnix::Programme(&FRESHCLAM).permis_ici(), cfg!(target_os = "linux"));
        assert!(!GesteUnix::Programme(&FRESHCLAM).demande_accord());
    }
}
