//! L'arrêt d'un logiciel de prise de contrôle à distance désigné (`vanguard:geste unite-designee arreter …`), jugé
//! par le fils root juste avant de le faire. Du code pur, sans appel système : le fils lit l'ordinateur
//! (`assistant::Monde`), ce module décide, et chaque branche de la décision s'éprouve sous les essais.
//!
//! Les règles (P4 du lot U3) :
//! - ce qui PROUVE qu'une session passe par l'outil refuse l'arrêt, quoi que la personne réponde : la lignée de
//!   Vanguard dans le groupe de contrôle de l'outil, ou une session de logind qu'il mène ou qu'il a ouverte à
//!   distance. Leur absence ne prouve rien (AnyDesk montre l'écran local sans ouvrir de session) : la personne est
//!   alors questionnée, et seule sa réponse « non » (elle n'est pas connectée par lui) mène à l'arrêt ;
//! - aucune commande d'arrêt que le fils ne peut relire et juger n'est lancée : seules passent le programme que
//!   l'unité fait déjà tourner en root (ExecStart), et `kill` de son seul processus principal ($MAINPID). Le reste
//!   (un script, un interprète, une commande générale comme `systemctl` ou `pkill`) est refusé, et c'est dit.

// Ni débordement ni `as` : il juge des propriétés venues du bus et de /proc.
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : du code pur.
#![forbid(unsafe_code)]

use crate::modele::Echec;
use crate::{tr, trf};

/// Le contexte des refus de l'arrêt, pour le journal des erreurs.
const CONTEXTE: &str = "assistant/arret-designe";

/// Un refus de l'arrêt, sa phrase déjà dans la langue de l'interface.
fn refuse(phrase: String) -> Echec {
    Echec::refuse(CONTEXTE, phrase)
}

/// Une commande que le gestionnaire lancerait pour une unité : le programme lancé, et ses arguments (le premier est
/// le nom donné au programme, pas forcément son chemin).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Commande {
    pub(crate) chemin: String,
    pub(crate) arguments: Vec<String>,
}

/// Ce que le gestionnaire a en mémoire d'une unité désignée, et qui dit ce que son arrêt ferait lancer ou toucher.
/// La mémoire du gestionnaire, pas les fichiers : c'est elle que StopUnit suit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ArretCharge {
    /// NeedDaemonReload : ses fichiers ont changé depuis que le gestionnaire les a lus.
    pub(crate) recharge_attendue: bool,
    /// ExecStart (service) ; ExecStartPre et ExecStartPost (socket) : ce qu'elle fait déjà tourner en root.
    pub(crate) lancement: Vec<Commande>,
    /// ExecStop et ExecStopPost (service) ; ExecStopPre et ExecStopPost (socket).
    pub(crate) arret: Vec<Commande>,
    /// EnvironmentFiles : le chemin, et vrai s'il peut manquer (préfixe « - »).
    pub(crate) fichiers_d_environnement: Vec<(String, bool)>,
    /// RootDirectory et RootImage, mis bout à bout : vide sans autre racine.
    pub(crate) racine: String,
    /// RequiredBy, RequisiteOf, BoundBy, ConsistsOf, PropagatesStopTo, OnSuccess, OnFailure : les unités que l'arrêt
    /// arrêterait ou lancerait avec elle.
    pub(crate) entrainees: Vec<String>,
    /// ControlGroup : vide sans groupe (un minuteur).
    pub(crate) groupe: String,
}

/// Une session ouverte, telle que logind la décrit : à distance (Remote), le service PAM qui l'a ouverte (Service :
/// « sshd », « xrdp-sesman »…), et le processus qui la mène (Leader).
// Seul le bus de Linux en donne : ailleurs, les sessions ne se lisent pas et l'arrêt est refusé.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionLogind {
    pub(crate) distante: bool,
    pub(crate) service: String,
    pub(crate) meneur: u32,
}

/// Une session de logind, avec les groupes de contrôle de son meneur et de ses ancêtres : un meneur lancé par l'outil
/// a un ancêtre dans le groupe de l'outil.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionVue {
    pub(crate) distante: bool,
    pub(crate) service: String,
    pub(crate) groupes_du_meneur: Vec<String>,
}

/// Ce qu'un regard (`assistant::regarder`) a vu d'un chemin cité par une commande d'arrêt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Chemin {
    /// Un fichier de root, fermé aux autres comptes, lui et ses dossiers ; `reel` : son chemin, liens résolus.
    Sur { reel: String },
    /// Absent, à une place que seul root peut remplir.
    AbsentPlaceSure,
    /// Modifiable par un autre compte, un dossier, illisible…
    Douteux,
}

/// Les commandes d'arrêt jugées au plus, et leurs arguments : au-delà, refusé plutôt que lu à moitié.
const COMMANDES_MAX: usize = 16;
const ARGUMENTS_MAX: usize = 64;

/// Le groupe de contrôle d'un processus, d'après son `/proc/<pid>/cgroup` : la ligne de la hiérarchie unifiée
/// (« 0::/system.slice/x.service »), ou à défaut celle de systemd en hiérarchie v1 (« 1:name=systemd:/… »).
pub(crate) fn groupe_du_processus(texte: &str) -> Option<String> {
    let unifie = texte.lines().find_map(|l| l.strip_prefix("0::"));
    let v1 = || {
        texte
            .lines()
            .find_map(|l| l.split_once(":name=systemd:").map(|(_, chemin)| chemin))
    };
    unifie
        .or_else(v1)
        .map(str::trim)
        .filter(|c| c.starts_with('/'))
        .map(String::from)
}

/// `chemin` est-il le groupe `groupe` ou un groupe en dessous ? Jamais pour un groupe vide ou la racine, qui
/// contiendrait tout.
pub(crate) fn sous_le_groupe(chemin: &str, groupe: &str) -> bool {
    let groupe = groupe.trim_end_matches('/');
    !groupe.is_empty()
        && chemin
            .strip_prefix(groupe)
            .is_some_and(|reste| reste.is_empty() || reste.starts_with('/'))
}

/// Ce qui prouve qu'une session passe par l'outil `unite`, dont les processus vivent dans `groupe` : la raison du
/// refus, ou `None` quand rien ne le prouve (ce qui ne prouve pas qu'aucune ne passe par lui).
pub(crate) fn porte_par_l_outil(
    unite: &str,
    groupe: &str,
    lignee: &[String],
    sessions: &[SessionVue],
) -> Option<String> {
    let vu = crate::ui::affichable(unite);
    if lignee.iter().any(|g| sous_le_groupe(g, groupe)) {
        return Some(trf!(
            "Vanguard tourne lui-même dans une session ouverte par {vu} : l'arrêter couperait cette session-ci. Il n'est pas arrêté",
            "Vanguard itself runs in a session opened by {vu}: stopping it would cut this very session. It is not stopped"
        ));
    }
    let par_l_outil = sessions.iter().find(|s| {
        s.groupes_du_meneur.iter().any(|g| sous_le_groupe(g, groupe))
            || (s.distante && crate::protection::distance::meme_logiciel(&s.service, unite))
    })?;
    let service = crate::ui::affichable(&par_l_outil.service);
    Some(trf!(
        "une session ouverte par {vu} est en cours sur cet ordinateur (service de connexion « {service} ») : l'arrêter la couperait. Il n'est pas arrêté ; refaites-le une fois cette session fermée",
        "a session opened by {vu} is in progress on this computer (login service \"{service}\"): stopping it would cut it. It is not stopped; do it again once that session is closed"
    ))
}

/// La réponse à « Êtes-vous connecté par lui ? » : seul « non » (« n », « no ») mène à l'arrêt. « oui », une ligne
/// vide, autre chose, la fin de l'entrée ou l'absence de terminal (`None`) le laissent en marche.
pub(crate) fn dit_non(reponse: Option<&str>) -> bool {
    reponse.is_some_and(|r| matches!(r.trim().to_lowercase().as_str(), "n" | "non" | "no"))
}

/// Le nom d'un programme, sans son dossier.
fn base(chemin: &str) -> &str {
    chemin.rsplit('/').next().unwrap_or(chemin)
}

/// Un programme qui lance ce que disent ses arguments (un interprète, un shell, un lanceur), ou qui agit sur tout
/// l'ordinateur d'après eux (`systemctl`, `pkill`) : sa commande d'arrêt ne se juge pas sur son seul nom, même quand
/// l'unité le lance déjà.
fn programme_general(nom: &str) -> bool {
    const NOMS: &[&str] = &[
        "sh",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "mksh",
        "csh",
        "tcsh",
        "fish",
        "ash",
        "busybox",
        "toybox",
        "env",
        "tclsh",
        "wish",
        "expect",
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "sed",
        "java",
        "dotnet",
        "mono",
        "pwsh",
        "xargs",
        "find",
        "nohup",
        "nice",
        "ionice",
        "timeout",
        "chroot",
        "setsid",
        "setpriv",
        "runuser",
        "su",
        "sudo",
        "doas",
        "run0",
        "systemd-run",
        "systemctl",
        "busctl",
        "dbus-send",
        "gdbus",
        "kill",
        "pkill",
        "killall",
        "stdbuf",
        "taskset",
        "chrt",
        "unshare",
        "nsenter",
        "script",
    ];
    // Un numéro de version au bout (python3.12, perl5.38) ne change pas le programme.
    const PREFIXES: &[&str] = &[
        "python", "perl", "ruby", "node", "php", "lua", "ld-linux", "ld.so", "ld-musl", "gdb", "strace", "ltrace",
        "flock",
    ];
    let nom = nom.to_lowercase();
    NOMS.contains(&nom.as_str()) || PREFIXES.iter().any(|p| nom.starts_with(p))
}

/// `$MAINPID`, sous l'une ou l'autre forme : la seule variable qu'une commande d'arrêt peut citer (le gestionnaire
/// la remplace par le processus principal de l'unité, rien d'autre).
fn est_mainpid(argument: &str) -> bool {
    matches!(argument, "$MAINPID" | "${MAINPID}")
}

/// Un signal tel que `kill` le prend : un nom en majuscules (avec ou sans « SIG »), ou un numéro de 1 à 64.
fn signal(texte: &str) -> bool {
    let nom = texte.strip_prefix("SIG").unwrap_or(texte);
    (!nom.is_empty() && nom.len() <= 8 && nom.bytes().all(|o| o.is_ascii_uppercase()))
        || texte.parse::<u8>().is_ok_and(|n| (1..=64).contains(&n))
}

/// `kill` du seul processus principal : « [-SIGNAL | -s SIGNAL | --signal SIGNAL] $MAINPID », rien d'autre. Ni
/// « -1 » seul (tous les processus), ni « -- », ni un autre numéro de processus.
fn kill_du_principal(arguments: &[String]) -> bool {
    let options: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match options.as_slice() {
        [cible] => est_mainpid(cible),
        [option, cible] => option.strip_prefix('-').is_some_and(signal) && est_mainpid(cible),
        ["-s" | "--signal", s, cible] => signal(s) && est_mainpid(cible),
        _ => false,
    }
}

/// Les arguments d'une commande d'arrêt du programme de l'unité : aucune variable sinon `$MAINPID` (ses valeurs
/// viendraient de l'environnement, que le fils ne relit pas), aucun chemin relatif (il dépendrait du dossier de
/// travail), et chaque chemin absolu (aussi après « --option= ») sûr ou absent à une place sûre.
fn arguments_surs(arguments: &[String], regard: &dyn Fn(&str) -> Chemin) -> Result<(), Echec> {
    for a in arguments {
        if a.contains('$') && !est_mainpid(a) {
            return Err(refuse(trf!(
                "sa commande d'arrêt cite une variable ({}), dont la valeur ne se relit pas",
                "its stop command quotes a variable ({}), whose value cannot be read back",
                crate::ui::affichable(a)
            )));
        }
        let valeur = match a.split_once('=') {
            Some((option, valeur)) if option.starts_with('-') => valeur,
            _ => a.as_str(),
        };
        let douteux = if valeur.starts_with('/') {
            regard(valeur) == Chemin::Douteux
        } else {
            valeur.contains('/')
        };
        if douteux {
            return Err(refuse(trf!(
                "sa commande d'arrêt cite un fichier qu'un autre compte que root pourrait changer ({})",
                "its stop command quotes a file that an account other than root could change ({})",
                crate::ui::affichable(valeur)
            )));
        }
    }
    Ok(())
}

/// Une commande d'arrêt, jugée : le programme que l'unité lance déjà (même fichier, même nom donné), aux arguments
/// sûrs ; ou `kill` de son processus principal. Le programme doit être un fichier de root fermé aux autres comptes.
fn commande_jugee(c: &Commande, lancement: &[Commande], regard: &dyn Fn(&str) -> Chemin) -> Result<(), Echec> {
    let vu = crate::ui::affichable(&c.chemin);
    let Chemin::Sur { reel } = (if c.chemin.starts_with('/') {
        regard(&c.chemin)
    } else {
        Chemin::Douteux
    }) else {
        return Err(refuse(trf!(
            "sa commande d'arrêt lance un programme qu'un autre compte que root pourrait changer, ou introuvable ({vu})",
            "its stop command runs a program that an account other than root could change, or that cannot be found ({vu})"
        )));
    };
    let (Some(nom_donne), suite) = (c.arguments.first(), c.arguments.get(1..).unwrap_or_default()) else {
        return Err(refuse(trf!(
            "sa commande d'arrêt est vide ({vu})",
            "its stop command is empty ({vu})"
        )));
    };
    if suite.len() > ARGUMENTS_MAX {
        return Err(refuse(trf!(
            "sa commande d'arrêt est trop longue pour être relue ({vu})",
            "its stop command is too long to be read back ({vu})"
        )));
    }
    if base(&c.chemin) == "kill" && base(&reel) == "kill" && base(nom_donne) == "kill" && kill_du_principal(suite) {
        return Ok(());
    }
    let le_sien = lancement
        .iter()
        .any(|l| l.chemin == c.chemin && l.arguments.first() == Some(nom_donne));
    if !le_sien
        || [base(&c.chemin), base(&reel), base(nom_donne)]
            .into_iter()
            .any(programme_general)
    {
        return Err(refuse(trf!(
            "sa commande d'arrêt ({vu}) n'est ni le programme que ce service fait tourner, ni l'arrêt de son seul processus : Vanguard ne sait pas ce qu'elle ferait",
            "its stop command ({vu}) is neither the program this service runs nor stopping its only process: Vanguard does not know what it would do"
        )));
    }
    arguments_surs(suite, regard)
}

/// L'arrêt de `unite`, d'après ce que le gestionnaire a en mémoire (`lu`) : permis, ou la raison du refus.
/// `regard` voit un chemin comme `assistant::regarder` le verrait.
///
/// Refusé : des fichiers changés depuis leur lecture par le gestionnaire (la revue des fichiers ne dirait plus ce
/// qu'il a en mémoire), une autre racine (les chemins n'y désignent pas les fichiers revus), des unités entraînées
/// (leurs commandes ne sont pas revues), un fichier d'environnement qu'un autre compte pourrait changer, une unité
/// qui tourne sans groupe connu, une commande d'arrêt qui n'est pas jugée sûre (`commande_jugee`).
pub(crate) fn juger_arret(unite: &str, lu: &ArretCharge, regard: &dyn Fn(&str) -> Chemin) -> Result<(), Echec> {
    let vu = crate::ui::affichable(unite);
    let refus = |raison: String| {
        refuse(trf!(
            "{vu} n'est pas arrêté : {raison}. Arrêtez-le vous-même si vous le voulez, ou redémarrez l'ordinateur une fois retiré du démarrage",
            "{vu} is not stopped: {raison}. Stop it yourself if you want, or restart the computer once it is removed from startup"
        ))
    };
    if lu.recharge_attendue {
        return Err(refus(
            tr!(
                "ses fichiers ont changé depuis que le gestionnaire de services les a lus",
                "its files changed since the service manager read them"
            )
            .to_string(),
        ));
    }
    if !lu.racine.is_empty() {
        return Err(refus(
            tr!(
                "il tourne dans une autre racine, où ses commandes ne désignent pas les fichiers revus",
                "it runs in another root, where its commands do not point to the files reviewed"
            )
            .to_string(),
        ));
    }
    if !lu.entrainees.is_empty() {
        let noms: Vec<String> = lu.entrainees.iter().take(3).map(|n| crate::ui::affichable(n)).collect();
        return Err(refus(trf!(
            "son arrêt arrêterait ou lancerait aussi {}, dont les commandes ne sont pas revues",
            "stopping it would also stop or start {}, whose commands are not reviewed",
            noms.join(", ")
        )));
    }
    if (unite.ends_with(".service") || unite.ends_with(".socket")) && lu.groupe.is_empty() {
        return Err(refus(
            tr!(
                "le gestionnaire de services n'a pas dit où vivent ses processus",
                "the service manager did not say where its processes live"
            )
            .to_string(),
        ));
    }
    for (fichier, _) in &lu.fichiers_d_environnement {
        if !fichier.starts_with('/') || regard(fichier) == Chemin::Douteux {
            return Err(refus(trf!(
                "son fichier d'environnement pourrait être changé par un autre compte que root ({})",
                "its environment file could be changed by an account other than root ({})",
                crate::ui::affichable(fichier)
            )));
        }
    }
    if lu.arret.len() > COMMANDES_MAX {
        return Err(refus(
            tr!(
                "il a trop de commandes d'arrêt pour qu'elles soient relues",
                "it has too many stop commands for them to be read back"
            )
            .to_string(),
        ));
    }
    for c in &lu.arret {
        commande_jugee(c, &lu.lancement, regard).map_err(|e| refus(String::from(e)))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(chemin: &str, arguments: &[&str]) -> Commande {
        Commande {
            chemin: chemin.into(),
            arguments: arguments.iter().map(ToString::to_string).collect(),
        }
    }

    /// AnyDesk tel que l'installe son paquet : un programme lancé, aucune commande d'arrêt.
    fn anydesk() -> ArretCharge {
        ArretCharge {
            lancement: vec![cmd("/usr/bin/anydesk", &["/usr/bin/anydesk", "--service"])],
            groupe: "/system.slice/anydesk.service".into(),
            ..ArretCharge::default()
        }
    }

    /// Tout chemin de /usr ou /etc est sûr (son chemin réel : lui-même, sauf /usr/bin/sh-lien, qui mène à bash) ;
    /// /usr/lib/absent manque à une place sûre ; le reste est douteux.
    fn regard(c: &str) -> Chemin {
        match c {
            "/usr/lib/absent" => Chemin::AbsentPlaceSure,
            "/usr/bin/anydesk-lien" => Chemin::Sur {
                reel: "/usr/bin/bash".into(),
            },
            c if c.starts_with("/usr/") || c.starts_with("/etc/") => Chemin::Sur { reel: c.into() },
            _ => Chemin::Douteux,
        }
    }

    #[test]
    fn groupe_lu_dans_proc() {
        assert_eq!(
            groupe_du_processus("0::/user.slice/user-1000.slice/session-3.scope\n").as_deref(),
            Some("/user.slice/user-1000.slice/session-3.scope")
        );
        let hybride = "12:pids:/system.slice/x.service\n1:name=systemd:/system.slice/anydesk.service\n";
        assert_eq!(
            groupe_du_processus(hybride).as_deref(),
            Some("/system.slice/anydesk.service")
        );
        for illisible in ["", "0::\n", "0::relatif\n", "3:cpu:/a\n"] {
            assert_eq!(groupe_du_processus(illisible), None, "{illisible:?}");
        }
    }

    #[test]
    fn sous_le_groupe_seulement() {
        let g = "/system.slice/anydesk.service";
        assert!(sous_le_groupe(g, g));
        assert!(sous_le_groupe("/system.slice/anydesk.service/session", g));
        assert!(sous_le_groupe(g, "/system.slice/anydesk.service/"));
        // Un nom qui commence pareil n'est pas en dessous ; un groupe vide ou la racine ne contient rien.
        assert!(!sous_le_groupe("/system.slice/anydesk.service2", g));
        assert!(!sous_le_groupe(g, ""));
        assert!(!sous_le_groupe(g, "/"));
    }

    /// Seules les preuves refusent : la lignée dans le groupe de l'outil, un meneur de session lancé par lui, une
    /// session à distance ouverte par lui (xrdp). Une session à distance d'un autre service (sshd), ou locale, ne
    /// prouve rien contre lui.
    #[test]
    fn une_session_portee_par_l_outil_se_prouve() {
        let g = "/system.slice/anydesk.service";
        let locale = "/user.slice/user-1000.slice/session-2.scope".to_string();
        let session = |distante: bool, service: &str, groupes: &[&str]| SessionVue {
            distante,
            service: service.into(),
            groupes_du_meneur: groupes.iter().map(ToString::to_string).collect(),
        };
        assert_eq!(
            porte_par_l_outil("anydesk.service", g, std::slice::from_ref(&locale), &[]),
            None
        );
        assert!(porte_par_l_outil("anydesk.service", g, &[locale.clone(), g.to_string()], &[]).is_some());
        let ssh = session(true, "sshd", &["/system.slice/sshd.service"]);
        assert_eq!(
            porte_par_l_outil("anydesk.service", g, &[], std::slice::from_ref(&ssh)),
            None
        );
        assert!(porte_par_l_outil("anydesk.service", g, &[], &[ssh.clone(), session(false, "", &[g])]).is_some());
        // Ouverte à distance par le même logiciel (son service PAM), même menée hors de son groupe.
        let nx = session(true, "nxserver", &["/user.slice/session-9.scope"]);
        assert!(
            porte_par_l_outil(
                "nxserver.service",
                "/system.slice/nxserver.service",
                &[],
                std::slice::from_ref(&nx)
            )
            .is_some()
        );
        // La même, locale : rien de prouvé ; et pas contre un autre logiciel.
        let nx_locale = SessionVue {
            distante: false,
            ..nx.clone()
        };
        assert_eq!(
            porte_par_l_outil("nxserver.service", "/system.slice/nxserver.service", &[], &[nx_locale]),
            None
        );
        assert_eq!(porte_par_l_outil("anydesk.service", g, &[], &[nx]), None);
        // Un minuteur, sans groupe : la lignée n'y est jamais.
        assert_eq!(porte_par_l_outil("x.timer", "", &[locale], &[]), None);
    }

    /// Seul « non » arrête ; tout le reste, la fin de l'entrée et l'absence de terminal comprises, le laisse en marche.
    #[test]
    fn seul_non_mene_a_l_arret() {
        for r in ["non", "n", "NON", " no \n", "No"] {
            assert!(dit_non(Some(r)), "{r:?}");
        }
        for r in [
            "",
            "\n",
            "oui",
            "o",
            "yes",
            "y",
            "nonon",
            "non merci",
            "arrêter",
            "0",
            "nope",
        ] {
            assert!(!dit_non(Some(r)), "{r:?}");
        }
        assert!(!dit_non(None));
    }

    #[test]
    fn un_arret_sans_commande_est_permis() {
        assert_eq!(juger_arret("anydesk.service", &anydesk(), &regard), Ok(()));
        // Un minuteur : ni commande, ni groupe.
        assert_eq!(juger_arret("x.timer", &ArretCharge::default(), &regard), Ok(()));
    }

    /// Le programme du service lui-même, ou `kill` de son seul processus principal : permis.
    #[test]
    fn les_commandes_d_arret_admises() {
        for arret in [
            cmd("/usr/bin/anydesk", &["/usr/bin/anydesk", "--stop-service"]),
            cmd(
                "/usr/bin/anydesk",
                &["/usr/bin/anydesk", "--pid", "$MAINPID", "--log=/usr/lib/absent"],
            ),
            cmd("/usr/bin/kill", &["/usr/bin/kill", "$MAINPID"]),
            cmd("/usr/bin/kill", &["kill", "-TERM", "${MAINPID}"]),
            cmd("/usr/bin/kill", &["kill", "-s", "SIGHUP", "$MAINPID"]),
            cmd("/usr/bin/kill", &["kill", "-9", "$MAINPID"]),
        ] {
            let lu = ArretCharge {
                arret: vec![arret.clone()],
                ..anydesk()
            };
            assert_eq!(juger_arret("anydesk.service", &lu, &regard), Ok(()), "{arret:?}");
        }
    }

    /// Ce qui ne se juge pas est refusé, avec la raison : un script, un interprète (même lancé par l'unité), une
    /// commande générale, une variable, un fichier douteux, `kill` d'autre chose que le processus principal.
    #[test]
    fn les_commandes_d_arret_refusees() {
        let mut lancement = anydesk().lancement;
        lancement.push(cmd("/usr/bin/sh", &["/usr/bin/sh", "-c", "anydesk --service"]));
        lancement.push(cmd("/usr/bin/anydesk-lien", &["anydesk-lien"]));
        lancement.push(cmd("/usr/bin/python3.12", &["python3"]));
        for arret in [
            cmd("/usr/bin/sh", &["/usr/bin/sh", "-c", "pkill sshd"]),
            cmd("/usr/bin/python3.12", &["python3", "/usr/lib/stop.py"]),
            cmd("/usr/bin/anydesk-lien", &["anydesk-lien", "--stop"]),
            cmd("/usr/lib/anydesk/stop.sh", &["/usr/lib/anydesk/stop.sh"]),
            cmd("/usr/bin/systemctl", &["systemctl", "stop", "sshd.service"]),
            cmd("/usr/bin/pkill", &["pkill", "anydesk"]),
            cmd("/usr/bin/kill", &["kill", "-9", "-1"]),
            cmd("/usr/bin/kill", &["kill", "-TERM", "-1", "$MAINPID"]),
            cmd("/usr/bin/kill", &["kill", "--", "$MAINPID"]),
            cmd("/usr/bin/kill", &["kill", "-s", "-1", "$MAINPID"]),
            cmd("/usr/bin/kill", &["kill", "-TERM", "1234"]),
            cmd("/usr/bin/kill", &["sh", "$MAINPID"]),
            cmd("/usr/bin/anydesk", &["/usr/bin/anydesk", "--conf", "$CONF"]),
            cmd("/usr/bin/anydesk", &["/usr/bin/anydesk", "--conf=/home/alice/x"]),
            cmd("/usr/bin/anydesk", &["/usr/bin/anydesk", "conf/x"]),
            cmd("/usr/bin/anydesk", &["busybox", "--stop"]),
            cmd("/usr/bin/anydesk", &[]),
            cmd("/opt/anydesk/anydesk", &["/opt/anydesk/anydesk"]),
            cmd("anydesk", &["anydesk"]),
        ] {
            let lu = ArretCharge {
                lancement: lancement.clone(),
                arret: vec![arret.clone()],
                ..anydesk()
            };
            assert!(juger_arret("anydesk.service", &lu, &regard).is_err(), "{arret:?}");
        }
        let longue = ArretCharge {
            arret: vec![cmd("/usr/bin/kill", &["kill", "$MAINPID"]); COMMANDES_MAX + 1],
            ..anydesk()
        };
        assert!(juger_arret("anydesk.service", &longue, &regard).is_err());
    }

    /// Le reste de ce que l'arrêt toucherait : chaque cas refuse, et le dit.
    #[test]
    fn le_reste_de_l_arret_se_juge() {
        let refuse = |lu: ArretCharge| juger_arret("anydesk.service", &lu, &regard).is_err();
        assert!(refuse(ArretCharge {
            recharge_attendue: true,
            ..anydesk()
        }));
        assert!(refuse(ArretCharge {
            racine: "/srv/racine".into(),
            ..anydesk()
        }));
        assert!(refuse(ArretCharge {
            entrainees: vec!["autre.service".into()],
            ..anydesk()
        }));
        assert!(refuse(ArretCharge {
            groupe: String::new(),
            ..anydesk()
        }));
        for f in ["/home/alice/env", "relatif/env"] {
            assert!(
                refuse(ArretCharge {
                    fichiers_d_environnement: vec![(f.into(), true)],
                    ..anydesk()
                }),
                "{f}"
            );
        }
        for f in ["/etc/default/anydesk", "/usr/lib/absent"] {
            assert!(
                !refuse(ArretCharge {
                    fichiers_d_environnement: vec![(f.into(), false)],
                    ..anydesk()
                }),
                "{f}"
            );
        }
    }
}
