//! Les ordres du blocage : la liste fermée des gestes que Vanguard fait avec les droits d'administrateur, chacun
//! avec des paramètres typés (une adresse, un port, un numéro de processus et son programme, une valeur d'avant).
//! Une ligne « vanguard:<verbe> <paramètres> » les porte du Vanguard qui demande à celui qui agit en administrateur
//! (l'assistant élevé de Linux et macOS, `machine::assistant` ; le processus élevé de Windows,
//! `machine::windows::eleve`), ou à lui-même quand il l'est déjà. Celui qui agit relit chaque ligne (forme exacte,
//! paramètres reparsés, rien d'autre accepté), puis REJUGE chaque geste avec ses propres yeux : les garde-fous du
//! blocage (`gardes`) sont refaits de son côté, sur ce qu'il lit lui-même de l'ordinateur (sessions à distance en
//! cours, processus et programme). La liste montrée avant l'accord dit donc ce qui sera fait, et rien d'autre ne
//! peut l'être : jamais un shell, jamais un texte libre.
//!
//! C'est le changement assumé de la règle « un identifiant sans paramètre » des corrections natives de Windows
//! (`corrections.rs`) : les paramètres sont permis, parce qu'ils sont typés et rejugés.

use std::collections::HashSet;
use std::net::IpAddr;

use super::gardes;
use super::pare_feu::PareFeu;
use crate::machine::regles::Os;
use crate::{tr, trf};

/// Devant chaque verbe (le même que celui des corrections natives de Windows : les verbes ne se recouvrent pas).
pub(crate) const PREFIXE: &str = "vanguard:";
/// Une ligne plus longue ne vient pas de Vanguard : le plus long ordre porte un chemin de 4 096 octets en hexadécimal.
pub(crate) const LIGNE_MAX: usize = 8448;
/// Au-delà, une liste n'est pas celle d'une session de Vanguard.
pub(crate) const LIGNES_MAX: usize = 512;
/// Le plus long chemin de programme qu'un ordre d'arrêt porte.
const CHEMIN_MAX: usize = 4096;

/// Un geste de la liste fermée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Ordre {
    /// La règle sortante vers une adresse.
    BloquerSortie {
        pare_feu: PareFeu,
        ip: IpAddr,
    },
    DebloquerSortie {
        pare_feu: PareFeu,
        ip: IpAddr,
    },
    /// La règle qui ferme un port TCP en entrée (sauf depuis cet ordinateur).
    FermerPort {
        pare_feu: PareFeu,
        port: u16,
    },
    RouvrirPort {
        pare_feu: PareFeu,
        port: u16,
    },
    /// Couper les connexions déjà ouvertes vers une adresse (Linux : sock_diag ; macOS : pfctl -k).
    CouperConnexions {
        ip: IpAddr,
    },
    /// Arrêter ce processus, seulement s'il fait toujours tourner ce programme.
    ArreterProcessus {
        pid: u32,
        chemin: String,
    },
    /// Windows : la liste de blocage des pilotes vulnérables remise à sa valeur d'avant (`None` : valeur absente).
    RemettrePilotes {
        avant: Option<u32>,
    },
}

fn nom_pare_feu(p: PareFeu) -> &'static str {
    match p {
        PareFeu::Ufw => "ufw",
        PareFeu::Nftables => "nftables",
        PareFeu::Windows => "windows",
        PareFeu::Pf => "pf",
    }
}

fn pare_feu_de(t: &str) -> Option<PareFeu> {
    [PareFeu::Ufw, PareFeu::Nftables, PareFeu::Windows, PareFeu::Pf]
        .into_iter()
        .find(|p| nom_pare_feu(*p) == t)
}

fn hex(octets: &[u8]) -> String {
    use std::fmt::Write as _;
    octets.iter().fold(String::with_capacity(octets.len() * 2), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    })
}

fn de_hex(t: &str) -> Option<Vec<u8>> {
    if !t.len().is_multiple_of(2) || !t.bytes().all(|o| matches!(o, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).ok())
        .collect()
}

impl Ordre {
    /// La ligne qui porte cet ordre, sous sa seule forme admise.
    pub(crate) fn ligne(&self) -> String {
        match self {
            Ordre::BloquerSortie { pare_feu, ip } => {
                format!(
                    "{PREFIXE}bloquer-sortie {} {}",
                    nom_pare_feu(*pare_feu),
                    ip.to_canonical()
                )
            }
            Ordre::DebloquerSortie { pare_feu, ip } => {
                format!(
                    "{PREFIXE}debloquer-sortie {} {}",
                    nom_pare_feu(*pare_feu),
                    ip.to_canonical()
                )
            }
            Ordre::FermerPort { pare_feu, port } => format!("{PREFIXE}fermer-port {} {port}", nom_pare_feu(*pare_feu)),
            Ordre::RouvrirPort { pare_feu, port } => {
                format!("{PREFIXE}rouvrir-port {} {port}", nom_pare_feu(*pare_feu))
            }
            Ordre::CouperConnexions { ip } => format!("{PREFIXE}couper-connexions {}", ip.to_canonical()),
            Ordre::ArreterProcessus { pid, chemin } => {
                format!("{PREFIXE}arreter-processus {pid} {}", hex(chemin.as_bytes()))
            }
            Ordre::RemettrePilotes { avant: Some(v) } => format!("{PREFIXE}remettre-pilotes {v}"),
            Ordre::RemettrePilotes { avant: None } => format!("{PREFIXE}remettre-pilotes absent"),
        }
    }

    /// Ce que fait l'ordre, en une phrase, montrée avant l'accord et par celui qui agit.
    pub(crate) fn texte(&self) -> String {
        match self {
            Ordre::BloquerSortie { pare_feu, ip } => super::pare_feu::decrire_sortante(*pare_feu, *ip),
            Ordre::DebloquerSortie { pare_feu, ip } => trf!(
                "Retirer de {} la règle sortante vers {}",
                "Remove from {} the outbound rule to {}",
                pare_feu.nom(),
                ip.to_canonical()
            ),
            Ordre::FermerPort { pare_feu, port } => trf!(
                "Fermer au réseau le port TCP {port} dans {} (il reste joignable depuis cet ordinateur)",
                "Close TCP port {port} to the network in {} (it stays reachable from this computer)",
                pare_feu.nom()
            ),
            Ordre::RouvrirPort { pare_feu, port } => trf!(
                "Retirer de {} la règle qui ferme le port TCP {port}",
                "Remove from {} the rule that closes TCP port {port}",
                pare_feu.nom()
            ),
            Ordre::CouperConnexions { ip } => trf!(
                "Couper les connexions déjà ouvertes vers {}",
                "Cut the connections already open to {}",
                ip.to_canonical()
            ),
            Ordre::ArreterProcessus { pid, chemin } => trf!(
                "Arrêter le processus {pid} ({}), seulement s'il fait toujours tourner ce programme",
                "Stop process {pid} ({}), only if it still runs this program",
                crate::ui::affichable(chemin)
            ),
            Ordre::RemettrePilotes { avant: Some(v) } => trf!(
                "Remettre la liste de blocage des pilotes vulnérables comme avant (VulnerableDriverBlocklistEnable = {v})",
                "Put the vulnerable driver blocklist back as before (VulnerableDriverBlocklistEnable = {v})"
            ),
            Ordre::RemettrePilotes { avant: None } => tr!(
                "Remettre la liste de blocage des pilotes vulnérables comme avant (valeur absente)",
                "Put the vulnerable driver blocklist back as before (value absent)"
            )
            .to_string(),
        }
    }

    /// Cet ordre a-t-il un sens sur ce système ? Celui qui agit refuse tout autre (une note d'un autre système).
    pub(crate) fn permis_ici(&self) -> bool {
        let os = Os::actuel();
        match self {
            Ordre::BloquerSortie { pare_feu, .. } | Ordre::DebloquerSortie { pare_feu, .. } => match os {
                Os::Linux => matches!(pare_feu, PareFeu::Ufw | PareFeu::Nftables),
                Os::Windows => *pare_feu == PareFeu::Windows,
                Os::MacOs => *pare_feu == PareFeu::Pf,
                Os::Tous => false,
            },
            Ordre::FermerPort { pare_feu, .. } | Ordre::RouvrirPort { pare_feu, .. } => match os {
                Os::Linux => matches!(pare_feu, PareFeu::Ufw | PareFeu::Nftables),
                Os::Windows => *pare_feu == PareFeu::Windows,
                Os::MacOs | Os::Tous => false,
            },
            Ordre::CouperConnexions { .. } => os != Os::Windows,
            Ordre::ArreterProcessus { .. } => true,
            Ordre::RemettrePilotes { .. } => os == Os::Windows,
        }
    }
}

/// L'ordre que porte une ligne, si et seulement si la ligne est exactement sa forme admise : le préfixe, un verbe de
/// la liste, des paramètres séparés par une espace, chacun reparsé puis réécrit à l'identique (une adresse IPv4
/// écrite en IPv6, un zéro de tête, une majuscule, une espace de trop : refusés).
pub(crate) fn analyser(ligne: &str) -> Option<Ordre> {
    if ligne.len() > LIGNE_MAX {
        return None;
    }
    let reste = ligne.strip_prefix(PREFIXE)?;
    let mots: Vec<&str> = reste.split(' ').collect();
    let ip = |t: &str| t.parse::<IpAddr>().ok();
    let port = |t: &str| t.parse::<u16>().ok().filter(|p| *p != 0);
    let ordre = match mots.as_slice() {
        ["bloquer-sortie", p, a] => Ordre::BloquerSortie {
            pare_feu: pare_feu_de(p)?,
            ip: ip(a)?,
        },
        ["debloquer-sortie", p, a] => Ordre::DebloquerSortie {
            pare_feu: pare_feu_de(p)?,
            ip: ip(a)?,
        },
        ["fermer-port", p, n] => Ordre::FermerPort {
            pare_feu: pare_feu_de(p)?,
            port: port(n)?,
        },
        ["rouvrir-port", p, n] => Ordre::RouvrirPort {
            pare_feu: pare_feu_de(p)?,
            port: port(n)?,
        },
        ["couper-connexions", a] => Ordre::CouperConnexions { ip: ip(a)? },
        ["arreter-processus", n, c] => {
            let chemin = String::from_utf8(de_hex(c)?).ok()?;
            let absolu = chemin_absolu(&chemin);
            if chemin.is_empty() || chemin.len() > CHEMIN_MAX || !absolu || chemin.contains(['\0', '\n', '\r']) {
                return None;
            }
            Ordre::ArreterProcessus {
                pid: n.parse::<u32>().ok().filter(|p| *p != 0)?,
                chemin,
            }
        }
        ["remettre-pilotes", "absent"] => Ordre::RemettrePilotes { avant: None },
        // Les deux seules valeurs que cette clé a jamais eues avant un blocage de Vanguard.
        ["remettre-pilotes", v @ ("0" | "1")] => Ordre::RemettrePilotes { avant: v.parse().ok() },
        _ => return None,
    };
    (ordre.ligne() == ligne).then_some(ordre)
}

/// Un chemin complet, d'Unix (« / ») ou de Windows (« C:\ », « \\?\ ») : écrit à part de `Path`, pour que la
/// ligne d'un système se relise pareil sur l'autre (les essais, et la note relue).
fn chemin_absolu(c: &str) -> bool {
    let o = c.as_bytes();
    c.starts_with('/')
        || c.starts_with(r"\\?\")
        || (o.len() >= 3 && o[0].is_ascii_alphabetic() && o[1] == b':' && o[2] == b'\\')
}

/// La ligne est-elle un ordre de cette liste (et non une commande ou une correction native) ?
#[cfg(any(unix, test))]
pub(crate) fn est_ordre(ligne: &str) -> bool {
    analyser(ligne).is_some()
}

/// Le texte à montrer pour une ligne : la phrase d'un ordre, la commande elle-même sinon (filtrée).
pub(crate) fn affichable(ligne: &str) -> String {
    analyser(ligne).map_or_else(|| crate::ui::commande_affichable(ligne), |o| o.texte())
}

/// Ce qu'un ordre a donné : réussi ou non, une précision à noter (« 2 connexions coupées », « déjà retirée »), ou la
/// raison de l'échec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Resultat {
    pub reussi: bool,
    pub note: Option<String>,
    pub raison: String,
}

impl Resultat {
    pub(crate) fn ok() -> Self {
        Resultat {
            reussi: true,
            note: None,
            raison: String::new(),
        }
    }
    pub(crate) fn ok_note(note: impl Into<String>) -> Self {
        Resultat {
            reussi: true,
            note: Some(note.into()),
            raison: String::new(),
        }
    }
    pub(crate) fn echec(raison: impl Into<String>) -> Self {
        Resultat {
            reussi: false,
            note: None,
            raison: raison.into(),
        }
    }
}

/// Une réponse sur une ligne : « ok », « ok note=… » ou « echec … » (retours à la ligne ôtés).
#[cfg(any(unix, test))]
pub(crate) fn ligne_reponse(r: &Resultat) -> String {
    let plat = |t: &str| t.replace(['\r', '\n'], " ");
    match (r.reussi, &r.note) {
        (true, Some(n)) => format!("ok note={}", plat(n)),
        (true, None) => "ok".to_string(),
        (false, _) => format!("echec {}", plat(&r.raison)),
    }
}

#[cfg(any(unix, test))]
pub(crate) fn lire_reponse(ligne: &str) -> Resultat {
    if ligne == "ok" {
        return Resultat::ok();
    }
    if let Some(n) = ligne.strip_prefix("ok note=") {
        return Resultat::ok_note(n);
    }
    Resultat::echec(ligne.strip_prefix("echec ").unwrap_or(ligne))
}

/// Ce que celui qui agit lit lui-même de l'ordinateur pour rejuger : les sessions à distance en cours, et les
/// processus jamais arrêtés (lui-même, ce qui l'a lancé, le Vanguard qui demande et ce qui le fait tourner).
pub(crate) struct Juge {
    sessions: Option<gardes::Sessions>,
    intouchables: HashSet<u32>,
    os: Os,
}

impl Juge {
    /// `demandeur` : le numéro du Vanguard qui a demandé (ses ancêtres sont protégés aussi) ; rien n'en dépend d'autre.
    pub(crate) fn lire(demandeur: Option<u32>) -> Juge {
        let mut intouchables: HashSet<u32> = ancetres(std::process::id()).into_iter().collect();
        intouchables.insert(std::process::id());
        if let Some(d) = demandeur {
            intouchables.insert(d);
            intouchables.extend(ancetres(d));
        }
        Juge {
            sessions: gardes::sessions_a_distance(),
            intouchables,
            os: Os::actuel(),
        }
    }

    /// Pour les essais : des sessions et des intouchables donnés.
    #[cfg(test)]
    pub(crate) fn essai(sessions: Option<gardes::Sessions>, intouchables: HashSet<u32>) -> Juge {
        Juge {
            sessions,
            intouchables,
            os: Os::actuel(),
        }
    }
}

/// Les ancêtres d'un processus, du parent à la racine (64 au plus).
fn ancetres(pid: u32) -> Vec<u32> {
    let mut liste = Vec::new();
    let mut courant = pid;
    #[cfg(windows)]
    let parents: std::collections::HashMap<u32, u32> = crate::machine::windows::processus::liste()
        .into_iter()
        .map(|p| (p.pid, p.parent))
        .collect();
    for _ in 0..64 {
        #[cfg(target_os = "linux")]
        let parent = std::fs::read_to_string(format!("/proc/{courant}/stat"))
            .ok()
            .and_then(|s| parent_du_stat(&s));
        #[cfg(target_os = "macos")]
        let parent = super::arret::macos::infos(courant).map(|i| i.pbi_ppid);
        #[cfg(windows)]
        let parent = parents.get(&courant).copied();
        match parent {
            Some(p) if p != 0 && p != courant && !liste.contains(&p) => {
                liste.push(p);
                courant = p;
            }
            _ => break,
        }
    }
    liste
}

/// Le parent dans /proc/<pid>/stat : le 2e champ après la parenthèse fermante du nom (qui peut contenir « ) »).
#[cfg(any(target_os = "linux", test))]
fn parent_du_stat(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()
}

/// Pourquoi celui qui agit refuse cet ordre, ou `None`. Refait ici les garde-fous que la préparation a déjà faits :
/// la liste a pu être écrite par un autre que le Vanguard qui l'a montrée.
pub(crate) fn juger(o: &Ordre, j: &Juge) -> Option<String> {
    if !o.permis_ici() {
        return Some(
            tr!(
                "ordre d'un autre système : refusé",
                "order from another system: refused"
            )
            .to_string(),
        );
    }
    match o {
        Ordre::BloquerSortie { ip, .. } | Ordre::CouperConnexions { ip } => {
            gardes::adresse_intouchable(*ip, j.sessions.as_ref(), false).map(str::to_string)
        }
        Ordre::FermerPort { port, .. } => gardes::port_intouchable(*port).map(str::to_string),
        Ordre::ArreterProcessus { pid, chemin } => {
            let Some(actuel) = super::gestes::chemin_du_processus(*pid) else {
                return Some(trf!(
                    "le processus {pid} est fini ou son programme ne se lit pas : rien n'est arrêté",
                    "process {pid} has ended or its program cannot be read: nothing is stopped"
                ));
            };
            if !super::gestes::meme_chemin(&actuel, chemin) {
                return Some(trf!(
                    "le PID {pid} désigne maintenant un autre programme : rien n'est arrêté",
                    "PID {pid} now points to another program: nothing is stopped"
                ));
            }
            // Le nom du fichier, et sous Linux celui que le processus s'est donné : un nom critique, l'un ou l'autre,
            // et rien n'est arrêté.
            let fichier = std::path::Path::new(&actuel)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            #[cfg(target_os = "linux")]
            let noms = [Some(fichier), crate::socle::processus::nom_court(*pid)];
            #[cfg(not(target_os = "linux"))]
            let noms = [Some(fichier), None];
            noms.iter()
                .flatten()
                .find_map(|nom| gardes::processus_intouchable(*pid, nom, Some(&actuel), &j.intouchables, j.os))
                .map(str::to_string)
        }
        // Défaire n'est permis que pour ce que Vanguard a pu poser : il ne bloque jamais une adresse locale ou un DNS
        // public, ne ferme jamais SSH ni le Bureau à distance. Une note forgée qui viserait la règle d'un autre (ufw ne
        // distingue pas les siennes) pour rouvrir ces portes-là est refusée.
        Ordre::DebloquerSortie { ip, .. } => {
            gardes::adresse_intouchable(*ip, Some(&gardes::Sessions::default()), false).map(|_| pas_de_vanguard())
        }
        Ordre::RouvrirPort { port, .. } => gardes::port_intouchable(*port).map(|_| pas_de_vanguard()),
        // La liste des pilotes n'est remise à sa valeur d'avant que si elle est encore celle que Vanguard a posée (1) :
        // changée depuis, ou absente, rien n'est remis (et jamais coupée sur la foi d'une note seule).
        #[cfg(windows)]
        Ordre::RemettrePilotes { .. } => {
            (crate::machine::windows::corrections::valeur_pilotes() != Some(1)).then(|| {
                tr!(
                    "la liste de blocage des pilotes n'est plus celle que Vanguard a posée : rien n'est remis",
                    "the driver blocklist is no longer the one Vanguard set: nothing is put back"
                )
                .to_string()
            })
        }
        #[cfg(not(windows))]
        Ordre::RemettrePilotes { .. } => None,
    }
}

/// La précision d'une coupure qui n'a pas pu se faire : la règle tient, la connexion déjà ouverte non. Elle ne fait
/// pas échouer le geste (la règle est posée), elle est dite.
pub(crate) fn note_non_coupee() -> &'static str {
    tr!("connexion déjà ouverte non coupée", "connection already open not cut")
}

/// La précision d'un port fermé par ufw : la règle est-elle relue avant toute autorisation (`ufw status`, lu par
/// celui qui agit, en root) ? `None` : l'état d'ufw ne s'est pas lu.
pub(crate) fn note_ufw(en_premier: Option<bool>) -> &'static str {
    match en_premier {
        Some(true) => tr!(
            "refusé par ufw avant toute autorisation",
            "denied by ufw before any allow rule"
        ),
        Some(false) => tr!(
            "pas vu avant les autorisations d'ufw",
            "not seen before ufw's allow rules"
        ),
        None => tr!("état d'ufw illisible", "ufw state unreadable"),
    }
}

fn pas_de_vanguard() -> String {
    tr!(
        "Vanguard ne pose jamais cette règle : ce retrait ne défait pas un de ses blocages, rien n'est fait",
        "Vanguard never adds this rule: this removal does not undo one of its blocks, nothing is done"
    )
    .to_string()
}

/// Fait les ordres, groupe par groupe : dans un groupe, un ordre refusé ou en échec arrête la suite (« non fait ») ;
/// un groupe n'empêche pas le suivant. `annoncer` montre chaque geste au moment de le faire, puis son issue.
#[cfg(any(unix, test))]
pub(crate) fn executer_groupes(
    groupes: &[Vec<Ordre>],
    juge: &Juge,
    annoncer: &mut dyn FnMut(&str),
) -> Vec<Vec<Resultat>> {
    groupes
        .iter()
        .map(|groupe| {
            let mut arret = false;
            groupe
                .iter()
                .map(|o| {
                    annoncer(&format!("> {}", o.texte()));
                    let r = if arret {
                        Resultat::echec(tr!(
                            "non fait : l'étape d'avant a échoué",
                            "not done: the previous step failed"
                        ))
                    } else if let Some(refus) = juger(o, juge) {
                        Resultat::echec(refus)
                    } else {
                        faire(o)
                    };
                    arret |= !r.reussi;
                    annoncer(&match (&r.reussi, &r.note) {
                        (true, Some(n)) => trf!("  OK ({n})", "  OK ({n})"),
                        (true, None) => "  OK".to_string(),
                        (false, _) => trf!("  Échec : {}", "  Failed: {}", r.raison),
                    });
                    r
                })
                .collect()
        })
        .collect()
}

/// Fait un ordre déjà rejugé, avec les droits de ce processus.
pub(crate) fn faire(o: &Ordre) -> Resultat {
    if let Ordre::ArreterProcessus { pid, chemin } = o {
        return match super::arret::arreter(*pid, chemin) {
            Ok(()) => Resultat::ok(),
            Err(e) => Resultat::echec(e.to_string()),
        };
    }
    #[cfg(target_os = "linux")]
    {
        linux::faire(o)
    }
    #[cfg(target_os = "macos")]
    {
        macos::faire(o)
    }
    #[cfg(windows)]
    {
        windows::faire(o)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Ordre, PareFeu, Resultat};
    use crate::machine::linux::nftables::{self, Element, Retrait};
    use crate::{tr, trf};

    /// ufw par son chemin, jamais par le PATH (l'assistant tourne en root).
    fn ufw() -> Option<&'static str> {
        ["/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw", "/bin/ufw"]
            .into_iter()
            .find(|c| std::path::Path::new(c).is_file())
    }

    /// ufw avec ces arguments, sans shell ; son code de retour et son message d'erreur.
    fn lancer_ufw(args: &[String]) -> Resultat {
        let Some(chemin) = ufw() else {
            return Resultat::echec(tr!("ufw introuvable", "ufw not found"));
        };
        let r = crate::commande::lancer(std::process::Command::new(chemin).args(args).env("LC_ALL", "C"), 60);
        match r {
            Some(r) if r.code == Some(0) => Resultat::ok(),
            Some(r) => Resultat::echec(trf!(
                "ufw a refusé (code {}) : {}",
                "ufw refused (code {}): {}",
                r.code.map_or_else(|| "?".to_string(), |c| c.to_string()),
                crate::ui::affichable(r.erreurs.trim().lines().last().unwrap_or(r.sortie.trim()))
            )),
            None => Resultat::echec(tr!(
                "ufw n'a pas répondu dans la minute",
                "ufw did not answer within a minute"
            )),
        }
    }

    fn retrait(r: Result<Retrait, crate::modele::Echec>) -> Resultat {
        match r {
            Ok(Retrait::Retire) => Resultat::ok(),
            Ok(Retrait::SansTable) => Resultat::ok_note(tr!(
                "plus de table de Vanguard (l'ordinateur a redémarré) : rien à retirer",
                "no Vanguard table any more (the computer restarted): nothing to remove"
            )),
            Ok(Retrait::DejaAbsent) => Resultat::ok_note(tr!("déjà retirée", "already removed")),
            Err(e) => Resultat::echec(e.to_string()),
        }
    }

    pub(super) fn faire(o: &Ordre) -> Resultat {
        let posee = |r: Result<(), crate::modele::Echec>| {
            r.map_or_else(|e| Resultat::echec(e.to_string()), |()| Resultat::ok())
        };
        match o {
            Ordre::BloquerSortie {
                pare_feu: PareFeu::Nftables,
                ip,
            } => posee(nftables::poser(Element::Adresse(*ip))),
            Ordre::DebloquerSortie {
                pare_feu: PareFeu::Nftables,
                ip,
            } => retrait(nftables::retirer(Element::Adresse(*ip))),
            Ordre::FermerPort {
                pare_feu: PareFeu::Nftables,
                port,
            } => posee(nftables::poser(Element::Port(*port))),
            Ordre::RouvrirPort {
                pare_feu: PareFeu::Nftables,
                port,
            } => retrait(nftables::retirer(Element::Port(*port))),
            Ordre::BloquerSortie { ip, .. } => lancer_ufw(&ufw_args("prepend", "out", *ip)),
            Ordre::DebloquerSortie { ip, .. } => lancer_ufw(&ufw_args("delete", "out", *ip)),
            // En tête des règles : ajoutée à la fin, une autorisation déjà là pour ce port passerait avant elle.
            Ordre::FermerPort { port, .. } => {
                let r = lancer_ufw(&["prepend".into(), "deny".into(), format!("{port}/tcp")]);
                if !r.reussi {
                    return r;
                }
                // Relu ici, en root : le Vanguard qui demande ne le lirait pas sans redemander le mot de passe.
                let statut = ufw().and_then(|c| {
                    crate::commande::lancer(std::process::Command::new(c).arg("status").env("LC_ALL", "C"), 30)
                });
                let en_premier = statut
                    .filter(|s| s.code == Some(0))
                    .map(|s| crate::protection::blocage::pare_feu::refuse_en_premier(&s.sortie, *port));
                Resultat::ok_note(super::note_ufw(en_premier))
            }
            Ordre::RouvrirPort { port, .. } => lancer_ufw(&["delete".into(), "deny".into(), format!("{port}/tcp")]),
            Ordre::CouperConnexions { ip } => match crate::machine::linux::couper::couper_vers(*ip) {
                Ok(c) if c.coupees > 0 => Resultat::ok_note(trf!(
                    "{} connexion(s) déjà ouverte(s) coupée(s)",
                    "{} connection(s) already open cut",
                    c.coupees
                )),
                Ok(_) => Resultat::ok(),
                Err(e) => Resultat::ok_note(format!("{} : {e}", super::note_non_coupee())),
            },
            Ordre::ArreterProcessus { .. } | Ordre::RemettrePilotes { .. } => {
                Resultat::echec(tr!("ordre d'un autre système", "order from another system"))
            }
        }
    }

    /// « ufw prepend|delete deny out to <adresse> », l'adresse sous sa forme IPv4 quand elle en est une.
    pub(super) fn ufw_args(verbe: &str, sens: &str, ip: std::net::IpAddr) -> Vec<String> {
        vec![
            verbe.into(),
            "deny".into(),
            sens.into(),
            "to".into(),
            ip.to_canonical().to_string(),
        ]
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{Ordre, Resultat};
    use crate::{tr, trf};

    const PFCTL: &str = "/sbin/pfctl";
    const ANCRE: &str = "com.apple/vanguard";

    fn pfctl(args: &[&str], entree: Option<&[u8]>) -> Option<crate::commande::Resultat> {
        let mut c = std::process::Command::new(PFCTL);
        c.args(args).env("LC_ALL", "C");
        match entree {
            Some(e) => crate::commande::lancer_avec_entree(&mut c, e, 60),
            None => crate::commande::lancer(&mut c, 60),
        }
    }

    fn echec_de(r: Option<crate::commande::Resultat>) -> Resultat {
        match r {
            Some(r) => Resultat::echec(trf!(
                "pfctl a refusé (code {}) : {}",
                "pfctl refused (code {}): {}",
                r.code.map_or_else(|| "?".to_string(), |c| c.to_string()),
                crate::ui::affichable(r.erreurs.trim().lines().last().unwrap_or(""))
            )),
            None => Resultat::echec(tr!("pfctl n'a pas répondu", "pfctl did not answer")),
        }
    }

    fn reussi(r: Option<&crate::commande::Resultat>) -> bool {
        r.is_some_and(|r| r.code == Some(0))
    }

    /// pf est-il en marche ? (« Status: Enabled » de pfctl -s info)
    fn en_marche() -> bool {
        pfctl(&["-s", "info"], None).is_some_and(|r| r.code == Some(0) && r.sortie.contains("Status: Enabled"))
    }

    fn bloquer(ip: std::net::IpAddr) -> Resultat {
        let adresse = ip.to_canonical().to_string();
        // Les règles de l'ancre seulement si elles n'y sont pas : les recharger viderait la table.
        let regles = pfctl(&["-a", ANCRE, "-s", "rules"], None);
        if !regles
            .as_ref()
            .is_some_and(|r| r.code == Some(0) && r.sortie.contains("vanguard"))
        {
            let charge = pfctl(
                &["-a", ANCRE, "-f", "-"],
                Some(b"table <vanguard> persist\nblock drop out quick to <vanguard>\n"),
            );
            if !reussi(charge.as_ref()) {
                return echec_de(charge);
            }
        }
        let ajout = pfctl(&["-a", ANCRE, "-t", "vanguard", "-T", "add", &adresse], None);
        if !reussi(ajout.as_ref()) {
            return echec_de(ajout);
        }
        // pf seulement s'il est arrêté, et une seule fois : « pfctl -E » prend une référence à chaque appel, que
        // rien ne rendait. pf déjà en marche n'est pas touché.
        let mut note = None;
        if !en_marche() {
            let marche = pfctl(&["-E"], None);
            if !reussi(marche.as_ref()) {
                return echec_de(marche);
            }
            note = Some(
                tr!(
                    "pf était arrêté : mis en marche (il le reste jusqu'au redémarrage)",
                    "pf was stopped: started (it stays on until restart)"
                )
                .to_string(),
            );
        }
        if !en_marche() {
            return Resultat::echec(tr!(
                "pf ne se dit pas en marche après coup : rien n'est compté comme bloqué",
                "pf does not report itself running afterwards: nothing is counted as blocked"
            ));
        }
        note.map_or_else(Resultat::ok, Resultat::ok_note)
    }

    fn debloquer(ip: std::net::IpAddr) -> Resultat {
        let adresse = ip.to_canonical().to_string();
        let r = pfctl(&["-a", ANCRE, "-t", "vanguard", "-T", "delete", &adresse], None);
        match r {
            Some(r) if r.code == Some(0) => Resultat::ok(),
            // Après un redémarrage, l'ancre n'a plus de table : rien à retirer.
            Some(r) if r.erreurs.contains("Table does not exist") => Resultat::ok_note(tr!(
                "plus de table de Vanguard (l'ordinateur a redémarré) : rien à retirer",
                "no Vanguard table any more (the computer restarted): nothing to remove"
            )),
            r => echec_de(r),
        }
    }

    fn couper(ip: std::net::IpAddr) -> Resultat {
        let ip = ip.to_canonical();
        let tout = if ip.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
        let r = pfctl(&["-k", tout, "-k", &ip.to_string()], None);
        if reussi(r.as_ref()) {
            Resultat::ok()
        } else {
            Resultat::ok_note(format!("{} : {}", super::note_non_coupee(), echec_de(r).raison))
        }
    }

    pub(super) fn faire(o: &Ordre) -> Resultat {
        match o {
            Ordre::BloquerSortie { ip, .. } => bloquer(*ip),
            Ordre::DebloquerSortie { ip, .. } => debloquer(*ip),
            Ordre::CouperConnexions { ip } => couper(*ip),
            _ => Resultat::echec(tr!("ordre d'un autre système", "order from another system")),
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{Ordre, Resultat};
    use crate::tr;

    pub(super) fn faire(o: &Ordre) -> Resultat {
        match o {
            Ordre::BloquerSortie { ip, .. } => crate::machine::windows::pare_feu::bloquer_sortie(*ip),
            Ordre::DebloquerSortie { ip, .. } => crate::machine::windows::pare_feu::debloquer_sortie(*ip),
            Ordre::FermerPort { port, .. } => crate::machine::windows::pare_feu::fermer_port(*port),
            Ordre::RouvrirPort { port, .. } => crate::machine::windows::pare_feu::rouvrir_port(*port),
            Ordre::RemettrePilotes { avant } => crate::machine::windows::corrections::remettre_pilotes(*avant),
            _ => Resultat::echec(tr!("ordre d'un autre système", "order from another system")),
        }
    }
}

/// L'équivalent PowerShell d'un ordre de Windows, pour le chemin par script (Wine, ou une DLL à côté de Vanguard) :
/// les paramètres sont typés, l'adresse et le port s'écrivent tels quels, le chemin passe par `ps_texte`.
#[cfg(any(windows, test))]
pub(crate) fn powershell(o: &Ordre) -> Option<String> {
    use super::pare_feu::ancien;
    match o {
        Ordre::BloquerSortie {
            pare_feu: PareFeu::Windows,
            ip,
        } => ancien::sortante(PareFeu::Windows, *ip).poser.into_iter().next(),
        Ordre::DebloquerSortie {
            pare_feu: PareFeu::Windows,
            ip,
        } => ancien::sortante(PareFeu::Windows, *ip).retirer.into_iter().next(),
        Ordre::FermerPort {
            pare_feu: PareFeu::Windows,
            port,
        } => ancien::entrante(PareFeu::Windows, *port)?.poser.into_iter().next(),
        Ordre::RouvrirPort {
            pare_feu: PareFeu::Windows,
            port,
        } => ancien::entrante(PareFeu::Windows, *port)?.retirer.into_iter().next(),
        Ordre::ArreterProcessus { pid, chemin } => {
            let attendu = crate::commande::ps_texte(chemin);
            Some(trf!(
                "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p -and $p.Path -eq '{attendu}') {{ Stop-Process -Id {pid} -Force }} else {{ throw 'PID {pid} réaffecté à un autre programme : rien n''est arrêté' }}",
                "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p -and $p.Path -eq '{attendu}') {{ Stop-Process -Id {pid} -Force }} else {{ throw 'PID {pid} reassigned to another program: nothing is stopped' }}"
            ))
        }
        Ordre::RemettrePilotes { avant } => super::gestes::annuler_pilotes(*avant).into_iter().next(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tous() -> Vec<Ordre> {
        vec![
            Ordre::BloquerSortie {
                pare_feu: PareFeu::Nftables,
                ip: "203.0.113.7".parse().unwrap(),
            },
            Ordre::DebloquerSortie {
                pare_feu: PareFeu::Ufw,
                ip: "2001:db8::7".parse().unwrap(),
            },
            Ordre::FermerPort {
                pare_feu: PareFeu::Windows,
                port: 11434,
            },
            Ordre::RouvrirPort {
                pare_feu: PareFeu::Nftables,
                port: 7860,
            },
            Ordre::CouperConnexions {
                ip: "198.51.100.4".parse().unwrap(),
            },
            Ordre::ArreterProcessus {
                pid: 4242,
                chemin: "/home/alice/.cache/x m'rig".into(),
            },
            Ordre::ArreterProcessus {
                pid: 7,
                chemin: r"C:\Users\alice\AppData\Local\Temp\l'outil.exe".into(),
            },
            Ordre::RemettrePilotes { avant: None },
            Ordre::RemettrePilotes { avant: Some(0) },
        ]
    }

    #[test]
    fn chaque_ordre_se_relit_tel_quel() {
        for o in tous() {
            let l = o.ligne();
            assert!(l.len() <= LIGNE_MAX);
            assert_eq!(analyser(&l), Some(o.clone()), "{l}");
            assert_ne!(o.texte(), "");
        }
        assert_eq!(
            Ordre::ArreterProcessus {
                pid: 1,
                chemin: "/a b".into()
            }
            .ligne(),
            "vanguard:arreter-processus 1 2f612062"
        );
    }

    /// Tout ce qui n'est pas exactement une ligne d'ordre est refusé : une commande, un shell glissé dans un
    /// paramètre, une adresse écrite autrement, un port nul, un chemin relatif ou à fin de ligne, une valeur d'avant
    /// hors de la liste, une espace de trop.
    #[test]
    fn les_lignes_hostiles_sont_refusees() {
        for hostile in [
            "",
            "vanguard:",
            "sudo ufw prepend deny out to 203.0.113.7",
            "vanguard:bloquer-sortie nftables 203.0.113.7; rm -rf /",
            "vanguard:bloquer-sortie nftables 203.0.113.7 ",
            "vanguard:bloquer-sortie  nftables 203.0.113.7",
            "vanguard:bloquer-sortie nftables 203.0.113.007",
            "vanguard:bloquer-sortie nftables ::ffff:203.0.113.7",
            "vanguard:bloquer-sortie nftables 2001:DB8::7",
            "vanguard:bloquer-sortie nftables 2001:0db8::7",
            "vanguard:bloquer-sortie iptables 203.0.113.7",
            "vanguard:bloquer-sortie NFTABLES 203.0.113.7",
            "vanguard:bloquer-sortie nftables 203.0.113.7\n",
            "vanguard:fermer-port ufw 0",
            "vanguard:fermer-port ufw 011434",
            "vanguard:fermer-port ufw 65536",
            "vanguard:fermer-port ufw 22/tcp",
            "vanguard:couper-connexions 203.0.113.0/24",
            "vanguard:arreter-processus 0 2f78",
            "vanguard:arreter-processus 42 7878",
            "vanguard:arreter-processus 42 2F78",
            "vanguard:arreter-processus 42 2f780a",
            "vanguard:arreter-processus 42 2f7",
            "vanguard:arreter-processus +42 2f78",
            "vanguard:arreter-processus 42",
            "vanguard:remettre-pilotes 2",
            "vanguard:remettre-pilotes",
            "vanguard:wdigest-coupe",
            "Vanguard:bloquer-sortie nftables 203.0.113.7",
        ] {
            assert_eq!(analyser(hostile), None, "{hostile:?}");
        }
        let long = format!("vanguard:arreter-processus 42 2f{}", "61".repeat(CHEMIN_MAX));
        assert_eq!(analyser(&long), None);
    }

    #[test]
    fn reponses_aller_retour() {
        for r in [
            Resultat::ok(),
            Resultat::ok_note("2 connexions coupées"),
            Resultat::echec("ufw a refusé"),
        ] {
            assert_eq!(lire_reponse(&ligne_reponse(&r)), r);
        }
        assert!(!lire_reponse("").reussi);
        assert!(!lire_reponse("okay").reussi);
        assert_eq!(ligne_reponse(&Resultat::echec("a\nb")), "echec a b");
    }

    #[test]
    fn parent_lu_dans_stat() {
        assert_eq!(parent_du_stat("42 (un nom (bizarre) ) S 17 42 42 0"), Some(17));
        assert_eq!(parent_du_stat("42 (x"), None);
    }

    /// Celui qui agit rejuge : jamais une adresse d'une session à distance en cours, ni une adresse du réseau local,
    /// ni le port de SSH, ni un ordre d'un autre système, ni lui-même ni ceux qui le font tourner ; et sans sessions
    /// lisibles, aucune adresse.
    #[test]
    fn le_rejugement_refait_les_garde_fous() {
        let sessions = gardes::Sessions {
            sessions: vec!["198.51.100.20".parse().unwrap()],
            autres_comptes: Vec::new(),
        };
        let juge = Juge::essai(Some(sessions), HashSet::new());
        let pf = match Os::actuel() {
            Os::Windows => PareFeu::Windows,
            Os::MacOs => PareFeu::Pf,
            Os::Linux | Os::Tous => PareFeu::Nftables,
        };
        let bloquer = |ip: &str| Ordre::BloquerSortie {
            pare_feu: pf,
            ip: ip.parse().unwrap(),
        };
        assert!(juger(&bloquer("198.51.100.20"), &juge).is_some(), "session à distance");
        assert!(juger(&bloquer("192.168.1.10"), &juge).is_some(), "réseau local");
        assert!(juger(&bloquer("203.0.113.7"), &juge).is_none());
        let couper = Ordre::CouperConnexions {
            ip: "198.51.100.20".parse().unwrap(),
        };
        if Os::actuel() != Os::Windows {
            assert!(juger(&couper, &juge).is_some());
        }
        let sans = Juge::essai(None, HashSet::new());
        assert!(juger(&bloquer("203.0.113.7"), &sans).is_some(), "sessions illisibles");
        if Os::actuel() != Os::MacOs {
            assert!(juger(&Ordre::FermerPort { pare_feu: pf, port: 22 }, &juge).is_some());
            assert!(
                juger(
                    &Ordre::FermerPort {
                        pare_feu: pf,
                        port: 3389
                    },
                    &juge
                )
                .is_some()
            );
        }
        let autre = if pf == PareFeu::Windows {
            PareFeu::Ufw
        } else {
            PareFeu::Windows
        };
        assert!(
            juger(
                &Ordre::BloquerSortie {
                    pare_feu: autre,
                    ip: "203.0.113.7".parse().unwrap()
                },
                &juge
            )
            .is_some()
        );
        // Ce processus de test : intouchable pour celui qui agit (lui-même).
        let moi = std::process::id();
        if let Some(chemin) = super::super::gestes::chemin_du_processus(moi) {
            let arreter_moi = Ordre::ArreterProcessus {
                pid: moi,
                chemin: chemin.clone(),
            };
            assert!(juger(&arreter_moi, &Juge::lire(None)).is_some());
            // Un autre programme attendu sous ce numéro : refusé aussi.
            let autre = Ordre::ArreterProcessus {
                pid: moi,
                chemin: "/autre/programme".into(),
            };
            assert!(juger(&autre, &juge).is_some());
        }
    }

    /// Dans un groupe, un ordre refusé arrête la suite ; le groupe suivant se fait quand même.
    #[test]
    fn un_refus_arrete_son_groupe_seulement() {
        let juge = Juge::essai(None, HashSet::new());
        let pf = if cfg!(windows) {
            PareFeu::Windows
        } else {
            PareFeu::Nftables
        };
        // Sans sessions lisibles, le blocage est refusé avant d'agir : rien ne touche le pare-feu.
        let groupes = vec![
            vec![
                Ordre::BloquerSortie {
                    pare_feu: pf,
                    ip: "203.0.113.7".parse().unwrap(),
                },
                Ordre::FermerPort { pare_feu: pf, port: 22 },
            ],
            vec![Ordre::FermerPort { pare_feu: pf, port: 22 }],
        ];
        let mut vus = Vec::new();
        let r = executer_groupes(&groupes, &juge, &mut |t| vus.push(t.to_string()));
        assert!(
            !r[0][0].reussi && r[0][0].raison.contains("illisibles"),
            "{:?}",
            r[0][0]
        );
        assert!(r[0][1].raison.contains("étape d'avant"), "{:?}", r[0][1]);
        assert!(
            r[1][0].raison.contains("SSH") || r[1][0].raison.contains("système"),
            "{:?}",
            r[1][0]
        );
        assert!(vus.iter().any(|v| v.starts_with("> ")));
    }

    #[test]
    fn equivalents_powershell() {
        let ps = powershell(&Ordre::BloquerSortie {
            pare_feu: PareFeu::Windows,
            ip: "203.0.113.7".parse().unwrap(),
        })
        .unwrap();
        assert!(ps.contains("-DisplayName 'Vanguard : bloquer vers 203.0.113.7' -Direction Outbound"));
        let ps = powershell(&Ordre::ArreterProcessus {
            pid: 4242,
            chemin: r"C:\Users\alice\l'outil.exe".into(),
        })
        .unwrap();
        assert!(ps.contains(r"$p.Path -eq 'C:\Users\alice\l''outil.exe'"), "{ps}");
        assert!(
            powershell(&Ordre::CouperConnexions {
                ip: "203.0.113.7".parse().unwrap()
            })
            .is_none()
        );
        assert!(
            powershell(&Ordre::RemettrePilotes { avant: None })
                .unwrap()
                .starts_with("Remove-ItemProperty")
        );
    }
}
