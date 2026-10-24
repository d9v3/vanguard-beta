//! Les traces sous Linux : /proc pour les processus (sans rien lancer), ss et ip pour le réseau, systemd, cron et
//! les fichiers de démarrage, les comptes et leurs connexions, le journal de systemd.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::chronologie::Apport;
use super::unix::{cron, journal_vers, journaux_classiques, maison, mo, shell_et_ssh};
use super::{Bi, Empreinte, Feuille, Manque, Partie, Processus, Raison, bi, chronologie};
use crate::commande::Garder;
use crate::machine::linux::dissimulation::{SansFichier, juger_exe, proc_masque};

/// Les comptes d'après /etc/passwd : numéro → nom.
pub(crate) fn comptes_de(passwd: &str) -> HashMap<u32, String> {
    passwd
        .lines()
        .filter_map(|l| {
            let mut c = l.split(':');
            let nom = c.next()?;
            let uid = c.nth(1)?.parse().ok()?;
            Some((uid, nom.to_string()))
        })
        .collect()
}

/// Le parent, le compte (numéro réel) et le nom d'un processus, d'après /proc/<pid>/status.
pub(crate) fn lire_status(status: &str) -> (Option<u32>, Option<u32>, String) {
    let valeur = |cle: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(cle))
            .map(|v| v.trim().to_string())
    };
    let ppid = valeur("PPid:").and_then(|v| v.parse().ok());
    let uid = valeur("Uid:").and_then(|v| v.split_whitespace().next()?.parse().ok());
    (ppid, uid, valeur("Name:").unwrap_or_default())
}

/// L'heure de démarrage d'un processus (secondes depuis 1970) d'après /proc/<pid>/stat : son 22e champ compte les
/// tops d'horloge depuis le démarrage de l'ordinateur (`btime` de /proc/stat). Le nom, entre parenthèses, est choisi
/// par le programme et peut contenir espaces et parenthèses : les champs se comptent après la dernière.
pub(crate) fn debut_du_processus(stat: &str, btime: u64, tops: u64) -> Option<u64> {
    let (_, apres) = stat.rsplit_once(')')?;
    // Après le nom : l'état est le 3e champ, le démarrage le 22e.
    let depart: u64 = apres.split_whitespace().nth(19)?.parse().ok()?;
    Some(btime + depart / tops.max(1))
}

/// Le démarrage de l'ordinateur, d'après /proc/stat.
fn btime() -> Option<u64> {
    std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()
}

/// Ce qui cloche dans le programme d'un processus, dans les deux langues.
fn etat(s: SansFichier) -> &'static str {
    match s {
        SansFichier::Memoire => "en mémoire seulement/in memory only (memfd)",
        SansFichier::EffaceTemporaire => "effacé d'un dossier temporaire/deleted from a temporary folder",
        SansFichier::Efface => "effacé/deleted",
        SansFichier::Temporaire => "dossier temporaire/temporary folder",
        SansFichier::AJour => "remplacé par une mise à jour/replaced by an update",
    }
}

/// Une heure locale lisible, d'après des secondes depuis 1970.
fn heure_locale(secondes: u64) -> String {
    i64::try_from(secondes)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

/// Les processus, lus dans /proc sans rien lancer. Le programme de chacun se lit par /proc/<pid>/exe, même effacé du
/// disque ou chargé en mémoire seulement : c'est ce qu'il faut à un spécialiste, et son empreinte se cherche sur
/// VirusTotal. Ceux des autres comptes ne se lisent qu'en root.
pub(super) fn processus(dossier: &Path) -> Partie {
    let mut manques = Vec::new();
    let Some(pids) = crate::socle::processus::pids() else {
        let mut p = Partie::new(Bi::new("Processus", "Processes"));
        p.manque(Bi::meme("/proc"), Raison::Erreur("illisible / unreadable".into()));
        return p;
    };
    let comptes = comptes_de(&std::fs::read_to_string("/etc/passwd").unwrap_or_default());
    let demarrage = btime().unwrap_or(0);
    // SAFETY : sysconf lit une constante du système, sans toucher à la mémoire du programme.
    let tops = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap_or(100);
    let montages = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let mut empreintes: HashMap<(u64, u64), Empreinte> = HashMap::new();
    let mut illisibles = 0;
    let fin = std::time::Instant::now() + super::DELAI_EMPREINTES;
    let mut liste = Vec::new();
    for pid in pids {
        let racine = PathBuf::from(format!("/proc/{pid}"));
        // Parti entre la liste et la lecture : rien à garder.
        let Ok(status) = std::fs::read_to_string(racine.join("status")) else {
            continue;
        };
        let (ppid, uid, nom) = lire_status(&status);
        let ligne = std::fs::read(racine.join("cmdline"))
            .map(|o| {
                String::from_utf8_lossy(&o)
                    .split('\0')
                    .filter(|a| !a.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let debut = std::fs::read_to_string(racine.join("stat"))
            .ok()
            .and_then(|s| debut_du_processus(&s, demarrage, tops))
            .map(heure_locale)
            .unwrap_or_default();
        let (programme, etat, empreinte) = match std::fs::read_link(racine.join("exe")) {
            Ok(lien) => {
                let lien = lien.to_string_lossy().into_owned();
                let chemin = lien.strip_suffix(" (deleted)").unwrap_or(&lien);
                let remplace = Path::new(&format!("/proc/{pid}/root{chemin}")).exists();
                let etat = juger_exe(&lien, remplace, &montages).map_or("", etat);
                // Le programme lu par /proc/<pid>/exe : le fichier qui tourne, même effacé ; une fois par fichier.
                let empreinte = match std::fs::metadata(racine.join("exe")) {
                    Ok(m) => {
                        use std::os::unix::fs::MetadataExt;
                        empreintes
                            .entry((m.dev(), m.ino()))
                            .or_insert_with(|| {
                                if std::time::Instant::now() > fin {
                                    Empreinte::Delai
                                } else {
                                    super::empreinte(&racine.join("exe"), super::TAILLE_PROGRAMME)
                                }
                            })
                            .clone()
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Empreinte::Droits,
                    Err(_) => Empreinte::Illisible,
                };
                (lien, etat, empreinte)
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                illisibles += 1;
                (String::new(), "", Empreinte::Droits)
            }
            // Fil du noyau : pas de programme.
            Err(_) => (format!("[{nom}]"), "", Empreinte::Aucune),
        };
        liste.push(Processus {
            pid,
            ppid,
            compte: uid
                .map(|u| comptes.get(&u).cloned().unwrap_or_else(|| u.to_string()))
                .unwrap_or_default(),
            debut,
            programme,
            etat,
            ligne: if ligne.is_empty() { format!("[{nom}]") } else { ligne },
            empreinte,
        });
    }
    if illisibles > 0 {
        manques.push(super::Manque {
            quoi: bi!(
                "Programme et empreinte de {illisibles} processus d'autres comptes",
                "Program and fingerprint of {illisibles} processes of other accounts"
            ),
            raison: Raison::Droits,
        });
    }
    if proc_masque(&montages) && !super::privilegie() {
        manques.push(super::Manque {
            quoi: Bi::new(
                "Processus des autres comptes (/proc monté avec hidepid)",
                "Processes of other accounts (/proc mounted with hidepid)",
            ),
            raison: Raison::Droits,
        });
    }
    super::partie_processus(dossier, liste, manques)
}

/// Connexions et ports à l'écoute avec leur programme, voisins (ARP), adresses, routes, DNS et fichier hosts.
pub(super) fn reseau(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Réseau", "Network"));
    let mut f = Feuille::new(&p.titre);
    let ss = f.commande(Command::new("ss").args(["-tunap"]), 15, true);
    f.commande(Command::new("ip").args(["neigh", "show"]), 10, true);
    f.commande(Command::new("ip").args(["address", "show"]), 10, true);
    f.commande(Command::new("ip").args(["route", "show", "table", "all"]), 10, false);
    for chemin in ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"] {
        f.fichier(Path::new(chemin), true);
    }
    f.commande(Command::new("resolvectl").arg("status"), 10, false);
    let connexions = ss.as_ref().map(|s| {
        s.lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with("Netid"))
            .count()
    });
    if ss.is_some() && !super::privilegie() {
        f.manques.push(super::Manque {
            quoi: Bi::new(
                "Programme des connexions des autres comptes",
                "Program of the other accounts' connections",
            ),
            raison: Raison::Droits,
        });
    }
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "02-reseau.txt",
        &f.texte,
        Bi::new(
            "connexions et ports à l'écoute avec leur programme (ss -tunap), voisins du réseau local (table ARP), adresses, routes, DNS configuré et fichier hosts",
            "connections and listening ports with their program (ss -tunap), local network neighbours (ARP table), addresses, routes, configured DNS and hosts file",
        ),
    ) {
        p.compte = Some(match connexions {
            Some(n) => bi!("{n} connexions et ports à l'écoute", "{n} connections and listening ports"),
            None => bi!("{} source(s) lue(s)", "{} source(s) read", f.lues),
        });
    }
    p
}

/// Ce qui se lance tout seul : unités et minuteries de systemd, tâches cron, démarrage de session, bibliothèque
/// préchargée, fichiers du shell, clés SSH autorisées, modules du noyau.
pub(super) fn demarrage(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Ce qui se lance tout seul", "What starts by itself"));
    let mut f = Feuille::new(&p.titre);
    let m = maison();
    f.commande(
        Command::new("systemctl").args(["list-unit-files", "--no-pager", "--full"]),
        20,
        true,
    );
    f.commande(
        Command::new("systemctl").args(["list-units", "--all", "--no-pager", "--full", "--plain"]),
        20,
        false,
    );
    f.commande(
        Command::new("systemctl").args(["list-timers", "--all", "--no-pager"]),
        20,
        false,
    );
    f.commande(
        Command::new("systemctl").args(["--user", "list-unit-files", "--no-pager", "--full"]),
        20,
        false,
    );
    // Les unités posées à la main (hors paquets) : là où une persistance s'installe. Dans leurs dossiers .wants, la
    // date de chaque lien est celle où le service a été activé : la chronologie la reprend.
    for racine in [PathBuf::from("/etc/systemd/system"), m.join(".config/systemd/user")] {
        f.dossier(&racine, 100, false);
        for d in dossiers_wants(&racine) {
            f.dossier(&d, 0, false);
        }
    }
    cron(&mut f);
    f.dossier(&m.join(".config/autostart"), 100, false);
    f.dossier(Path::new("/etc/xdg/autostart"), 100, false);
    for chemin in ["/etc/ld.so.preload", "/etc/rc.local", "/proc/modules"] {
        f.fichier(Path::new(chemin), false);
    }
    shell_et_ssh(&mut f);
    p.manques.append(&mut f.manques);
    p.evenements = chronologie::lancements(&f.dates);
    if p.ecrire(
        dossier,
        "03-demarrage.txt",
        &f.texte,
        Bi::new(
            "ce qui se lance tout seul, tel quel : unités et minuteries de systemd (et services activés, dossiers .wants), tâches cron, démarrage de session (autostart), bibliothèque préchargée (ld.so.preload), fichiers du shell, clés SSH autorisées, modules du noyau chargés",
            "what starts by itself, as is: systemd units and timers (and enabled services, .wants folders), cron jobs, session autostart, preloaded library (ld.so.preload), shell files, authorized SSH keys, loaded kernel modules",
        ),
    ) {
        p.compte = Some(bi!("{} source(s) lue(s)", "{} source(s) read", f.lues));
    }
    p
}

/// Les dossiers « .wants » et « .requires » d'un dossier d'unités : un lien par service activé.
fn dossiers_wants(racine: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let chemin = e.path();
            let extension = chemin.extension().unwrap_or_default();
            (extension == "wants" || extension == "requires") && e.file_type().is_ok_and(|t| t.is_dir())
        })
        .map(|e| e.path())
        .collect();
    v.sort();
    v
}

/// La fin de wtmp et de btmp lue au plus (environ 87 000 enregistrements) : des mois de connexions sur un serveur.
const FIN_WTMP: u64 = 32 << 20;
/// Lignes écrites au plus par relevé de connexions (les plus récentes d'abord), comme `last -n 1000` en écrivait.
const LIGNES_CONNEXIONS: usize = 5000;

/// Les secondes de chaque connexion et démarrage listés par `last -F` (la première date de chaque ligne, en heure
/// locale), pour comparer au relevé de Vanguard.
fn dates_de_last(sortie: &str) -> Vec<i64> {
    const JOURS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    sortie
        .lines()
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            if mots.get(1) == Some(&"begins") {
                return None;
            }
            let i = mots.iter().position(|m| JOURS.contains(m))?;
            let texte = mots.get(i..i + 5)?.join(" ");
            let d = chrono::NaiveDateTime::parse_from_str(&texte, "%a %b %e %H:%M:%S %Y").ok()?;
            chrono::TimeZone::from_local_datetime(&chrono::Local, &d)
                .earliest()
                .map(|d| d.timestamp())
        })
        .collect()
}

/// Les connexions et démarrages de wtmp que `last` aurait dû montrer (ceux d'après sa plus ancienne ligne) et qui n'y
/// sont pas : un `last` remplacé qui cache une session. Comptés par seconde, pour que deux sessions de la même seconde
/// comptent deux fois.
fn absentes_de_last(natifs: &[crate::machine::linux::connexions::Enregistrement], last: &[i64]) -> usize {
    use crate::machine::linux::connexions::{BOOT_TIME, USER_PROCESS};
    let Some(&debut) = last.iter().min() else {
        return 0;
    };
    let mut vus: HashMap<i64, usize> = HashMap::new();
    for t in last {
        *vus.entry(*t).or_default() += 1;
    }
    let mut absentes = 0;
    for e in natifs {
        let montree = match e.genre {
            BOOT_TIME => true,
            USER_PROCESS => !e.compte.is_empty() && !e.ligne.is_empty() && e.ligne != "~",
            _ => false,
        };
        let t = i64::from(e.secondes);
        if !montree || t <= debut {
            continue;
        }
        match vus.get_mut(&t) {
            Some(n) if *n > 0 => *n -= 1,
            _ => absentes += 1,
        }
    }
    absentes
}

/// Les démarrages et les sessions depuis le réseau, d'après les enregistrements de wtmp (comme `lire_last` les tirait
/// du texte de last).
fn evenements_wtmp(natifs: &[crate::machine::linux::connexions::Enregistrement]) -> Vec<chronologie::Evenement> {
    use crate::machine::linux::connexions::{BOOT_TIME, USER_PROCESS};
    natifs
        .iter()
        .filter_map(|e| {
            let quand = i64::from(e.secondes);
            match e.genre {
                BOOT_TIME => Some(chronologie::Evenement::new(
                    quand,
                    chronologie::Source::Compte,
                    chronologie::Genre::DemarrageOrdinateur,
                    e.hote.clone(),
                )),
                USER_PROCESS if chronologie::hote_distant(&e.hote) => Some(chronologie::Evenement::new(
                    quand,
                    chronologie::Source::Compte,
                    chronologie::Genre::SessionReseau,
                    format!("{} ← {} ({})", e.compte, e.hote, e.ligne),
                )),
                _ => None,
            }
        })
        .collect()
}

/// Les mêmes événements d'après wtmpdb (genres à lui : 1 démarrage, 3 session ; dates en microsecondes).
fn evenements_wtmpdb(sessions: &[crate::machine::linux::connexions::Session]) -> Vec<chronologie::Evenement> {
    use crate::machine::linux::connexions::{WTMPDB_BOOT_TIME, WTMPDB_USER_PROCESS};
    sessions
        .iter()
        .filter_map(|s| {
            let quand = s.entree / 1_000_000;
            match s.genre {
                WTMPDB_BOOT_TIME => Some(chronologie::Evenement::new(
                    quand,
                    chronologie::Source::Compte,
                    chronologie::Genre::DemarrageOrdinateur,
                    s.hote.clone(),
                )),
                WTMPDB_USER_PROCESS if chronologie::hote_distant(&s.hote) => Some(chronologie::Evenement::new(
                    quand,
                    chronologie::Source::Compte,
                    chronologie::Genre::SessionReseau,
                    format!("{} ← {} ({})", s.compte, s.hote, s.terminal),
                )),
                _ => None,
            }
        })
        .collect()
}

/// Un fichier d'enregistrements utmp (wtmp, btmp) lu par Vanguard dans la feuille, les plus récents d'abord. Rend ce
/// qui a été lu ; `None` : absent ou illisible, et c'est écrit (un manque si c'est faute de droits et `importante`).
fn releve_utmp(
    f: &mut Feuille,
    chemin: &str,
    titre: &str,
) -> Option<Vec<crate::machine::linux::connexions::Enregistrement>> {
    use crate::machine::linux::connexions as cx;
    f.section(&format!("{chemin} ({titre}, lu par Vanguard / read by Vanguard)"));
    match cx::lire_fin(Path::new(chemin), FIN_WTMP) {
        Ok((octets, coupe)) => {
            let natifs = cx::lire_utmp(&octets);
            let mut texte = String::new();
            for e in natifs.iter().rev().take(LIGNES_CONNEXIONS) {
                texte.push_str(&cx::ligne(e));
                texte.push('\n');
            }
            if natifs.len() > LIGNES_CONNEXIONS {
                texte.push_str(&Raison::Lignes(natifs.len() - LIGNES_CONNEXIONS).note());
                texte.push('\n');
            }
            if coupe {
                texte.push_str(&Raison::Borne(FIN_WTMP).note());
                texte.push('\n');
            }
            f.ajouter(&texte);
            f.lues += 1;
            Some(natifs)
        }
        Err(e) => {
            let raison = if e.kind() == std::io::ErrorKind::PermissionDenied {
                Raison::Droits
            } else if e.kind() == std::io::ErrorKind::NotFound {
                Raison::Introuvable
            } else {
                Raison::Erreur(e.to_string())
            };
            f.ajouter(&raison.note());
            None
        }
    }
}

/// Les sessions de systemd (logind) par le client D-Bus maison : ListSessions, puis les propriétés de chacune.
/// Rend les identifiants lus ; `None` : illisible, la raison écrite dans la feuille.
fn sessions_logind(f: &mut Feuille) -> Option<Vec<String>> {
    use crate::machine::linux::dbus;
    const LOGIN1: &str = "org.freedesktop.login1";
    f.section("logind : ListSessions (lu par Vanguard / read by Vanguard)");
    let r = dbus::Bus::systeme().and_then(|mut bus| {
        let liste = bus.appeler(
            LOGIN1,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "ListSessions",
            "",
            Vec::new(),
        )?;
        let mut lignes = Vec::new();
        let mut ids = Vec::new();
        for s in liste
            .first()
            .map(dbus::Valeur::elements)
            .unwrap_or_default()
            .iter()
            .take(1000)
        {
            let m = s.elements();
            let (Some(id), Some(chemin)) = (
                m.first().and_then(dbus::Valeur::texte),
                m.get(4).and_then(dbus::Valeur::texte),
            ) else {
                continue;
            };
            let p = bus
                .proprietes(LOGIN1, chemin, "org.freedesktop.login1.Session")
                .unwrap_or(dbus::Valeur::Tableau(Vec::new()));
            let t = |c: &str| match p.champ(c) {
                Some(dbus::Valeur::Booleen(b)) => if *b { "oui/yes" } else { "non/no" }.to_string(),
                Some(v) => v
                    .texte()
                    .map(String::from)
                    .or_else(|| v.entier().map(|n| n.to_string()))
                    .unwrap_or_default(),
                None => String::new(),
            };
            let debut = p
                .champ("Timestamp")
                .and_then(dbus::Valeur::entier)
                .and_then(|us| i64::try_from(us / 1_000_000).ok());
            lignes.push(format!(
                "{id}\t{}\tuid {}\t{}\tTTY {}\tremote {} {}\t{}\t{}/{}\t{}\t{}",
                m.get(2).and_then(dbus::Valeur::texte).unwrap_or_default(),
                m.get(1).and_then(dbus::Valeur::entier).unwrap_or_default(),
                m.get(3).and_then(dbus::Valeur::texte).unwrap_or_default(),
                t("TTY"),
                t("Remote"),
                t("RemoteHost"),
                t("Service"),
                t("Type"),
                t("Class"),
                t("State"),
                debut.map(crate::machine::linux::connexions::date).unwrap_or_default()
            ));
            ids.push(id.to_string());
        }
        Ok((lignes, ids))
    });
    match r {
        Ok((lignes, ids)) => {
            f.ajouter(&lignes.join("\n"));
            f.lues += 1;
            Some(ids)
        }
        Err(e) => {
            f.ajouter(&Raison::Erreur(e).note());
            None
        }
    }
}

/// Un écart entre le relevé de Vanguard et l'outil qu'il remplace, pour l'écran.
fn ecart(f: &mut Feuille, outil: &str, ce_qui: Bi) {
    let _ = std::fmt::Write::write_fmt(&mut f.texte, format_args!("{}\n", Raison::Ecart(ce_qui.clone()).note()));
    f.manques.push(Manque {
        quoi: bi!("Comparaison avec « {outil} »", "Comparison with “{outil}”"),
        raison: Raison::Ecart(ce_qui),
    });
}

/// Comptes et groupes, sessions ouvertes, dernières connexions réussies et ratées : lues par Vanguard (utmp, logind,
/// wtmp ou wtmpdb, lastlog2.db et lastlog, btmp en root), la sortie de who, loginctl, last, wtmpdb, lastlog2,
/// lastlog et lastb gardée à côté comme témoin quand l'outil est là. Un écart entre les deux est signalé.
pub(super) fn comptes(dossier: &Path) -> Partie {
    use crate::machine::linux::connexions as cx;
    let mut p = Partie::new(Bi::new("Comptes", "Accounts"));
    let mut f = Feuille::new(&p.titre);
    f.fichier(Path::new("/etc/passwd"), true);
    f.fichier(Path::new("/etc/group"), true);
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();

    // Sessions ouvertes : /run/utmp, puis who en témoin.
    f.section(&format!(
        "{} (sessions ouvertes / open sessions, lu par Vanguard / read by Vanguard)",
        cx::UTMP
    ));
    let ouvertes = match std::fs::read(cx::UTMP) {
        Ok(o) => {
            let v: Vec<_> = cx::lire_utmp(&o)
                .into_iter()
                .filter(|e| e.genre == cx::USER_PROCESS)
                .collect();
            f.ajouter(&v.iter().map(cx::ligne).collect::<Vec<_>>().join("\n"));
            f.lues += 1;
            Some(v.len())
        }
        Err(e) => {
            f.ajouter(&Raison::Erreur(e.to_string()).note());
            None
        }
    };
    let who = f.commande(&mut Command::new("who"), 10, false);
    if let (Some(n), Some(w)) = (ouvertes, &who) {
        let outil = w.lines().filter(|l| !l.trim().is_empty()).count();
        if outil != n {
            ecart(
                &mut f,
                "who",
                bi!(
                    "{n} sessions dans utmp, {outil} pour who",
                    "{n} sessions in utmp, {outil} for who"
                ),
            );
        }
    }

    // Sessions de systemd : logind par D-Bus, puis loginctl en témoin.
    let ids = sessions_logind(&mut f);
    let loginctl = f.commande(
        Command::new("loginctl").args(["list-sessions", "--no-pager", "--no-legend"]),
        10,
        false,
    );
    if let (Some(ids), Some(l)) = (&ids, &loginctl) {
        let outil: Vec<&str> = l.lines().filter_map(|l| l.split_whitespace().next()).collect();
        let cachees = ids.iter().filter(|id| !outil.contains(&id.as_str())).count();
        if cachees > 0 {
            ecart(
                &mut f,
                "loginctl",
                bi!(
                    "{cachees} sessions de logind absentes de loginctl",
                    "{cachees} logind sessions missing from loginctl"
                ),
            );
        }
    }

    // Dernières connexions : wtmp (ou wtmpdb sans lui), puis last et wtmpdb en témoin. Les dates en anglais, quelle
    // que soit la langue de l'ordinateur.
    let wtmp = releve_utmp(&mut f, cx::WTMP, "connexions et démarrages / logins and boots");
    let last = f.commande(
        Command::new("last")
            .args(["-F", "-w", "-n", "1000"])
            .env("LC_ALL", "C.UTF-8"),
        20,
        false,
    );
    if let (Some(n), Some(l)) = (&wtmp, &last) {
        let absentes = absentes_de_last(n, &dates_de_last(l));
        if absentes > 0 {
            ecart(
                &mut f,
                "last",
                bi!(
                    "{absentes} connexions de wtmp absentes de last",
                    "{absentes} wtmp logins missing from last"
                ),
            );
        }
    }
    let wtmpdb = match cx::base(Path::new(cx::WTMPDB)) {
        Err(cx::PasLue::Absente) => None,
        lue => {
            f.section(&format!("{} (wtmpdb, lu par Vanguard / read by Vanguard)", cx::WTMPDB));
            let sessions = lue.ok().as_deref().and_then(cx::wtmpdb);
            match &sessions {
                Some(s) => {
                    let lignes: Vec<String> = s
                        .iter()
                        .rev()
                        .take(LIGNES_CONNEXIONS)
                        .map(|s| {
                            format!(
                                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                                cx::date(s.entree / 1_000_000),
                                s.sortie.map_or_else(|| "-".into(), |t| cx::date(t / 1_000_000)),
                                s.genre,
                                s.compte,
                                s.terminal,
                                s.hote,
                                s.service
                            )
                        })
                        .collect();
                    f.ajouter(&lignes.join("\n"));
                    f.lues += 1;
                }
                None => f.ajouter(
                    &Raison::Erreur("base illisible ou en cours d'écriture / unreadable or being written".into())
                        .note(),
                ),
            }
            sessions
        }
    };
    let wtmpdb_outil = f.commande(Command::new("wtmpdb").arg("last").env("LC_ALL", "C.UTF-8"), 20, false);

    // lastlog2.db et lastlog, puis les outils en témoin.
    match cx::base(Path::new(cx::LASTLOG2)) {
        Err(cx::PasLue::Absente) => {}
        lue => {
            f.section(&format!(
                "{} (lastlog2, lu par Vanguard / read by Vanguard)",
                cx::LASTLOG2
            ));
            match lue.ok().as_deref().and_then(cx::lastlog2) {
                Some(l) => {
                    let lignes: Vec<String> = l
                        .iter()
                        .map(|d| {
                            format!(
                                "{}\t{}\t{}\t{}\t{}",
                                d.compte,
                                cx::date(d.secondes),
                                d.terminal,
                                d.hote,
                                d.service
                            )
                        })
                        .collect();
                    f.ajouter(&lignes.join("\n"));
                    f.lues += 1;
                }
                None => f.ajouter(
                    &Raison::Erreur("base illisible ou en cours d'écriture / unreadable or being written".into())
                        .note(),
                ),
            }
        }
    }
    if Path::new(cx::LASTLOG).exists() {
        f.section(&format!(
            "{} (lastlog, lu par Vanguard / read by Vanguard)",
            cx::LASTLOG
        ));
        let mut lignes = Vec::new();
        for (uid, nom) in comptes_de(&passwd) {
            match cx::lastlog_de(Path::new(cx::LASTLOG), uid) {
                Ok(Some((t, terminal, hote))) => {
                    lignes.push(format!("{nom}\t{}\t{terminal}\t{hote}", cx::date(i64::from(t))));
                }
                Ok(None) => {}
                Err(e) => {
                    lignes.push(Raison::Erreur(e.to_string()).note());
                    break;
                }
            }
        }
        lignes.sort();
        f.ajouter(&lignes.join("\n"));
        f.lues += 1;
    }
    f.commande(&mut Command::new("lastlog2"), 20, false);
    f.commande(&mut Command::new("lastlog"), 20, false);

    // Connexions ratées : btmp, réservé à root.
    if super::privilegie() {
        releve_utmp(&mut f, cx::BTMP, "connexions ratées / failed logins");
        f.commande(Command::new("lastb").args(["-F", "-w", "-n", "1000"]), 20, false);
    } else {
        f.section(&format!("{} / lastb", cx::BTMP));
        f.ajouter(&Raison::Droits.note());
        f.manques.push(super::Manque {
            quoi: Bi::new("Connexions ratées (btmp)", "Failed logins (btmp)"),
            raison: Raison::Droits,
        });
    }
    let n = passwd.lines().filter(|l| l.contains(':')).count();
    p.manques.append(&mut f.manques);
    // Pour la chronologie : démarrages et sessions depuis le réseau, lus par Vanguard (wtmp, sinon wtmpdb) ; la
    // sortie de last ou de wtmpdb seulement quand ni l'un ni l'autre ne s'est lu. Et la date des fichiers des
    // comptes, changée par chaque compte créé ou modifié.
    p.evenements = match (&wtmp, &wtmpdb) {
        (Some(n), _) if !n.is_empty() => evenements_wtmp(n),
        (_, Some(s)) => evenements_wtmpdb(s),
        (Some(n), None) => evenements_wtmp(n),
        (None, None) => {
            let sessions = last
                .filter(|s| !s.trim().is_empty())
                .or(wtmpdb_outil)
                .unwrap_or_default();
            chronologie::lire_last(&sessions, chrono::Local::now().naive_local(), &chrono::Local)
        }
    };
    p.evenements.extend(f.dates.iter().filter_map(|(c, t)| {
        Some(chronologie::Evenement::new(
            chronologie::secondes(*t)?,
            chronologie::Source::Compte,
            chronologie::Genre::FichierDesComptes,
            c.clone(),
        ))
    }));
    if p.ecrire(
        dossier,
        "04-comptes.txt",
        &f.texte,
        Bi::new(
            "comptes et groupes (passwd, group), sessions ouvertes et dernières connexions lues par Vanguard (utmp, logind, wtmp ou wtmpdb, lastlog2, lastlog), avec la sortie de who, loginctl, last, lastlog2 à côté en témoin, et connexions ratées (btmp et lastb, en root)",
            "accounts and groups (passwd, group), open sessions and last logins read by Vanguard (utmp, logind, wtmp or wtmpdb, lastlog2, lastlog), with the output of who, loginctl, last, lastlog2 alongside as a witness, and failed logins (btmp and lastb, as root)",
        ),
    ) {
        p.compte = Some(bi!("{n} comptes", "{n} accounts"));
    }
    p
}

/// Le journal de systemd des 7 derniers jours, du plus récent au plus ancien, 50 Mo au plus ; sans systemd ou sans
/// journal, la fin des fichiers de /var/log.
pub(super) fn journaux(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Journaux", "Logs"));
    let titre = Bi::new("Journal du système, 7 jours", "System log, 7 days");
    let nom = JOURNAL_ECRIT;
    let mut commande = Command::new("journalctl");
    commande
        .args(["--since=-7d", "--reverse", "--no-pager", "-o", "short-iso"])
        .env("LC_ALL", "C.UTF-8");
    let ecrit = journal_vers(dossier, nom, &titre, &mut commande, 120, Garder::Debut, None);
    let vide = match ecrit {
        Err(e) => {
            p.manque(titre.clone(), Raison::Erreur(e.to_string()));
            true
        }
        Ok(None) => {
            p.manque(titre.clone(), Raison::Absente("journalctl".into()));
            true
        }
        Ok(Some(e)) => {
            p.fichiers.push(super::Produit {
                nom: nom.into(),
                contenu: Bi::new(
                    "le journal de systemd (journalctl) des 7 derniers jours, du plus récent au plus ancien, 50 Mo au plus",
                    "the systemd journal (journalctl) of the last 7 days, newest first, 50 MB at most",
                ),
            });
            if e.tronque {
                p.manque(
                    Bi::new("Journal du système, les plus anciens", "System log, the oldest entries"),
                    Raison::Borne(super::BORNE_JOURNAL),
                );
            }
            if e.delai {
                p.manque(titre.clone(), Raison::Delai(120));
            }
            if e.erreurs.contains("not seeing messages from other users")
                || e.erreurs.contains("insufficient permissions")
            {
                p.manque(
                    Bi::new(
                        "Journal : messages du système et des autres comptes",
                        "Log: messages of the system and other accounts",
                    ),
                    Raison::Droits,
                );
            }
            if let Some(code) = e.code.filter(|c| *c != 0) {
                let premiere = e.erreurs.lines().next().unwrap_or_default().to_string();
                p.manque(titre.clone(), Raison::Erreur(format!("code {code} : {premiere}")));
            }
            let rien = e.erreurs.contains("No journal files") || e.octets < 200;
            if !rien {
                let m = mo(e.octets);
                p.compte = Some(Bi::new(format!("{} (7 jours)", m.fr), format!("{} (7 days)", m.en)));
            }
            rien
        }
    };
    if vide {
        let avant = p.fichiers.len();
        let total = journaux_classiques(
            &mut p,
            dossier,
            &[
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/kern.log",
            ],
        );
        if p.fichiers.len() > avant {
            let m = mo(total);
            p.compte = Some(Bi::new(format!("/var/log, {}", m.fr), format!("/var/log, {}", m.en)));
        } else {
            p.manque(Bi::new("Journal du système", "System log"), Raison::Introuvable);
        }
    }
    p
}

/// Les entrées gardées au plus par lecture ciblée du journal (quelques Mo) : de quoi couvrir la semaine même quand un
/// robot essaie des mots de passe par milliers.
const ENTREES_CIBLEES: usize = 20_000;

/// Le journal de systemd écrit par `journaux`.
const JOURNAL_ECRIT: &str = "05-journal.txt";

/// Les lectures ciblées du journal pour la chronologie, chacune bornée à part : une force brute qui remplit celle de
/// SSH ne pousse pas hors de la chronologie le sudo ni le compte créé qui suivent l'intrusion. Les programmes par leur
/// identifiant ; le noyau par son transport plutôt que par -k, qui se limite au démarrage en cours : un module chargé
/// avant le dernier redémarrage compte aussi.
const LECTURES_CIBLEES: [(&str, &str, &[&str]); 3] = [
    ("SSH", "SSH", &["-t", "sshd", "-t", "sshd-session", "-t", "sshd-auth"]),
    (
        "sudo, comptes",
        "sudo, accounts",
        &["-t", "sudo", "-t", "useradd", "-t", "usermod", "-t", "gpasswd"],
    ),
    ("noyau", "kernel", &["_TRANSPORT=kernel"]),
];

/// Une lecture ciblée (`quoi`) qui atteint sa borne : ses plus anciennes entrées de la semaine manquent, et c'est
/// dit.
fn lecture_coupee(quoi: Bi, entrees: usize) -> Option<Manque> {
    (entrees >= ENTREES_CIBLEES).then_some(Manque {
        quoi,
        raison: Raison::Entrees(ENTREES_CIBLEES),
    })
}

/// journalctl sur les 7 derniers jours, en sortie courte datée avec l'année, en anglais.
fn journalctl_7_jours() -> Command {
    let mut c = Command::new("journalctl");
    c.args(["--since=-7d", "--no-pager", "-o", "short-iso"])
        .env("LC_ALL", "C.UTF-8");
    c
}

/// Le journal refuse ce qui n'est pas du compte (ni root, ni groupe systemd-journal ou wheel).
fn journal_reserve(erreurs: &str) -> bool {
    erreurs.contains("not seeing messages from other users") || erreurs.contains("insufficient permissions")
}

/// Les événements du journal pour la chronologie, lus par journalctl filtré (60 s et 20 000 entrées au plus par
/// lecture) : toute la semaine en quelques Mo, là où le journal complet (05-journal.txt, 50 Mo) ne couvre parfois
/// que les dernières minutes d'un ordinateur bavard. Jusqu'où le journal remonte est dit s'il ne couvre pas la
/// semaine. Sans journalctl, la chronologie reprend les journaux écrits, et dit leur limite.
pub(super) fn evenements_des_journaux(dossier: &Path) -> Apport {
    let maintenant = chrono::Local::now().naive_local();
    let debut = chronologie::secondes(std::time::SystemTime::now()).unwrap_or(0) - chronologie::JOURS * 86_400;
    let mut apport = Apport::default();
    let mut lu = false;
    let mut reserve = false;
    for (fr, en, filtres) in LECTURES_CIBLEES {
        let quoi = bi!("Chronologie : journal ciblé ({fr})", "Timeline: targeted log ({en})");
        let mut c = journalctl_7_jours();
        c.arg(format!("--lines={ENTREES_CIBLEES}")).args(filtres);
        let depart = std::time::Instant::now();
        match crate::commande::lancer(&mut c, 60) {
            None if depart.elapsed().as_secs() >= 60 => apport.manques.push(Manque {
                quoi,
                raison: Raison::Delai(60),
            }),
            None => {
                apport.manques.push(Manque {
                    quoi: Bi::new(
                        "Chronologie : journal ciblé (repris dans les journaux écrits)",
                        "Timeline: targeted log (taken from the written logs)",
                    ),
                    raison: Raison::Absente("journalctl".into()),
                });
                break;
            }
            Some(r) if r.code != Some(0) => {
                reserve |= journal_reserve(&r.erreurs);
                let premiere = r.erreurs.lines().next().unwrap_or_default().trim().to_string();
                apport.manques.push(Manque {
                    quoi,
                    raison: Raison::Erreur(premiere),
                });
            }
            Some(r) => {
                lu = true;
                reserve |= journal_reserve(&r.erreurs);
                let mut lecture = super::unix::lire_texte(&r.sortie, maintenant);
                apport.manques.extend(lecture_coupee(quoi, lecture.entrees));
                apport.evenements.append(&mut lecture.evenements);
            }
        }
    }
    if reserve {
        apport.manques.push(Manque {
            quoi: Bi::new(
                "Chronologie : journal, messages du système et des autres comptes",
                "Timeline: log, messages of the system and other accounts",
            ),
            raison: Raison::Droits,
        });
    }
    let mut ecrits = if lu {
        // Jusqu'où le journal remonte : sa plus ancienne entrée de la semaine (« --lines=+1 », systemd 255 et après ;
        // avant, rien n'est affirmé). Un journal tourné tôt sur un ordinateur bavard ne garde qu'un jour ou deux.
        let mut c = journalctl_7_jours();
        c.arg("--lines=+1");
        let plus_ancienne = crate::commande::lancer(&mut c, 30)
            .filter(|r| r.code == Some(0))
            .and_then(|r| {
                r.sortie
                    .lines()
                    .find_map(|l| chronologie::quand_de_ligne(l, maintenant, &chrono::Local))
            });
        if let Some(q) = plus_ancienne.filter(|q| *q > debut + 3600) {
            let depuis = chronologie::date_locale(q, &chrono::Local);
            apport.manques.push(if reserve {
                // Sans droits, la plus ancienne entrée lisible est celle du compte : le système en garde peut-être
                // de bien plus anciennes, que seul root (ou le groupe systemd-journal) peut lire.
                Manque {
                    quoi: bi!(
                        "Chronologie : le journal lisible sans droits ne remonte qu'au {depuis}",
                        "Timeline: the log readable without rights only goes back to {depuis}"
                    ),
                    raison: Raison::Droits,
                }
            } else {
                Manque {
                    quoi: bi!(
                        "Chronologie : le journal du système ne remonte qu'au {depuis}",
                        "Timeline: the system log only goes back to {depuis}"
                    ),
                    raison: Raison::NonGarde,
                }
            });
        }
        // Le journal complet est déjà lu, en mieux ; la fin des fichiers de /var/log, écrite sans journal de
        // systemd, reste à reprendre.
        super::unix::journaux_ecrits(dossier, Some(JOURNAL_ECRIT), false, None)
    } else {
        super::unix::journaux_ecrits(dossier, None, true, reserve.then_some(JOURNAL_ECRIT))
    };
    apport.evenements.append(&mut ecrits.evenements);
    apport.manques.append(&mut ecrits.manques);
    apport
}

/// Les dossiers temporaires du système, où un programme dépose ce qu'il lance.
pub(super) fn endroits_temporaires() -> Vec<PathBuf> {
    ["/tmp", "/var/tmp", "/dev/shm"].iter().map(PathBuf::from).collect()
}

/// Les points de montage de cet ordinateur, que le parcours des fichiers récents ne traverse pas.
pub(super) fn points_de_montage() -> Vec<PathBuf> {
    montages_selon(&std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default())
}

/// Le point de montage est le cinquième champ de chaque ligne de mountinfo, ses espaces écrits en octal.
fn montages_selon(mountinfo: &str) -> Vec<PathBuf> {
    mountinfo
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(|c| PathBuf::from(crate::copier::sans_echappements(c)))
        .collect()
}

/// La place que peuvent prendre les journaux.
pub(super) fn place_des_journaux() -> u64 {
    super::BORNE_JOURNAL
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le vrai journal de cet ordinateur, lu filtré : jamais le journal écrit en plus (il ferait des doublons), et
    /// chaque limite dite ; sans journalctl, le journal écrit est repris et l'absence dite.
    #[test]
    fn journal_cible_de_cette_machine() {
        let dossier = crate::socle::dossier_local().join("journal-cible");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        std::fs::write(
            dossier.join("05-journal.txt"),
            "2026-10-20T14:03:22-04:00 portable sshd[1]: Accepted password for alice from 192.0.2.10 port 1 ssh2\n",
        )
        .unwrap();
        let a = evenements_des_journaux(&dossier);
        let absent = a
            .manques
            .iter()
            .any(|m| m.raison == Raison::Absente("journalctl".into()));
        let invente = a.evenements.iter().any(|e| e.detail.contains("192.0.2.10"));
        assert_eq!(absent, invente, "{:?}", a.manques);
        assert!(a.evenements.iter().all(|e| e.source == chronologie::Source::Journal));
        assert!(journal_reserve(
            "Hint: You are currently not seeing messages from other users and the system."
        ));
        assert!(!journal_reserve(""));
    }

    /// Trois lectures bornées à part : SSH, puis sudo et les comptes, puis le noyau. Une force brute inventée remplit
    /// celle de SSH, qui est dite coupée ; sudo et les comptes gardent la leur.
    #[test]
    fn lectures_ciblees_separees() {
        use std::fmt::Write as _;
        let identifiants = |filtres: &[&str]| -> Vec<String> {
            filtres
                .chunks(2)
                .filter(|c| c[0] == "-t")
                .map(|c| c[1].to_string())
                .collect()
        };
        let [ssh, comptes, noyau] = LECTURES_CIBLEES;
        assert_eq!(identifiants(ssh.2), ["sshd", "sshd-session", "sshd-auth"]);
        assert_eq!(identifiants(comptes.2), ["sudo", "useradd", "usermod", "gpasswd"]);
        assert_eq!(noyau.2, ["_TRANSPORT=kernel"]);
        let mut force_brute = String::new();
        for i in 0..ENTREES_CIBLEES {
            let (minute, seconde) = (i / 60 % 60, i % 60);
            let _ = writeln!(
                force_brute,
                "2026-10-20T14:{minute:02}:{seconde:02}-04:00 portable sshd[{i}]: Failed password for alice from 203.0.113.7 port 22 ssh2"
            );
        }
        let lecture = super::super::unix::lire_texte(&force_brute, chrono::Local::now().naive_local());
        assert_eq!(lecture.entrees, ENTREES_CIBLEES);
        let quoi = Bi::new("Chronologie : journal ciblé (SSH)", "Timeline: targeted log (SSH)");
        assert_eq!(
            lecture_coupee(quoi.clone(), lecture.entrees),
            Some(Manque {
                quoi,
                raison: Raison::Entrees(ENTREES_CIBLEES)
            })
        );
        assert_eq!(lecture_coupee(Bi::meme("sudo"), 3), None);
    }

    /// Une session de wtmp que last ne montre pas (un last remplacé qui la cache) est comptée ; celles d'avant la
    /// plus ancienne ligne de last, et les enregistrements que last ne montre jamais, ne le sont pas.
    #[test]
    fn sessions_cachees_par_last() {
        use crate::machine::linux::connexions::{BOOT_TIME, Enregistrement, USER_PROCESS};
        let e = |genre, compte: &str, ligne: &str, secondes| Enregistrement {
            genre,
            pid: 1,
            ligne: ligne.into(),
            compte: compte.into(),
            hote: String::new(),
            secondes,
            adresse: None,
        };
        let natifs = [
            e(USER_PROCESS, "alice", "pts/0", 100),
            e(BOOT_TIME, "reboot", "~", 200),
            e(USER_PROCESS, "alice", "pts/1", 300),
            e(USER_PROCESS, "alice", "pts/2", 300),
            e(8, "", "pts/0", 350),
            e(USER_PROCESS, "", "pts/3", 360),
            e(USER_PROCESS, "mallory", "pts/4", 400),
        ];
        assert_eq!(absentes_de_last(&natifs, &[150, 200, 300, 300, 400]), 0);
        assert_eq!(
            absentes_de_last(&natifs, &[150, 200, 300, 400]),
            1,
            "deux sessions de la même seconde"
        );
        assert_eq!(absentes_de_last(&natifs, &[150, 200, 300, 300]), 1, "mallory caché");
        assert_eq!(absentes_de_last(&natifs, &[]), 0);
        // Les dates de last -F, en heure locale : jours sur un ou deux chiffres, « wtmp begins » sauté.
        let texte = "alice    pts/0        192.0.2.10       Tue Oct  6 23:09:30 2026 - Tue Oct  6 23:10:00 2026  (00:00)\n\
                     reboot   system boot  6.17.1-arch1-1   Sat Oct 24 02:21:00 2026   still running\n\n\
                     wtmp begins Wed Sep  3 13:47:00 2026\n";
        let d = dates_de_last(texte);
        assert_eq!(d.len(), 2);
        assert_eq!(d[1] - d[0], 17 * 86_400 + 3 * 3600 + 11 * 60 + 30);
        // Les événements de wtmp : démarrage et session depuis le réseau, pas la session locale.
        let mut reseau = e(USER_PROCESS, "alice", "pts/0", 500);
        reseau.hote = "192.0.2.10".into();
        let ev = evenements_wtmp(&[
            e(BOOT_TIME, "reboot", "~", 1),
            reseau,
            e(USER_PROCESS, "alice", "tty1", 2),
        ]);
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[1].detail, "alice ← 192.0.2.10 (pts/0)");
    }

    /// L'oracle des comptes : la partie lue sur cet ordinateur ne voit aucun écart entre le relevé de Vanguard et
    /// who, loginctl et last (un écart dirait un outil remplacé, ou une session ouverte entre les deux lectures).
    #[test]
    fn comptes_de_cette_machine() {
        let dossier = crate::socle::dossier_local().join("traces-comptes");
        std::fs::create_dir_all(&dossier).unwrap();
        let p = comptes(&dossier);
        assert!(p.compte.is_some(), "{:?}", p.manques);
        let ecarts: Vec<_> = p
            .manques
            .iter()
            .filter(|m| matches!(m.raison, Raison::Ecart(_)))
            .collect();
        assert!(ecarts.is_empty(), "{ecarts:?}");
        let texte = std::fs::read_to_string(dossier.join("04-comptes.txt")).unwrap();
        assert!(
            texte.contains("/run/utmp") && texte.contains("$ who"),
            "le relevé et son témoin"
        );
    }

    #[test]
    fn points_de_montage_lus() {
        let mountinfo = "22 1 0:21 / /tmp rw,nosuid shared:5 - tmpfs tmpfs rw\n\
            98 22 0:52 / /tmp/com.freerdp.client.cliprdr.108479 rw - fuse /dev/fuse rw\n\
            99 22 0:53 / /tmp/mon\\040dossier ro - fuse.essai essai ro\n";
        assert_eq!(
            montages_selon(mountinfo),
            [
                PathBuf::from("/tmp"),
                PathBuf::from("/tmp/com.freerdp.client.cliprdr.108479"),
                PathBuf::from("/tmp/mon dossier")
            ]
        );
        assert!(points_de_montage().contains(&PathBuf::from("/")));
    }

    #[test]
    fn comptes_et_status() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/zsh\n# rien\n";
        let c = comptes_de(passwd);
        assert_eq!(c.get(&0).map(String::as_str), Some("root"));
        assert_eq!(c.get(&1000).map(String::as_str), Some("alice"));
        assert_eq!(c.len(), 2);
        let status = "Name:\tmineur\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\nPid:\t4242\nPPid:\t1\n\
                      Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(lire_status(status), (Some(1), Some(1000), "mineur".to_string()));
    }

    #[test]
    fn heure_de_demarrage() {
        // Un nom piégé, avec espaces et parenthèses : les champs se comptent après la dernière.
        let mut champs = vec!["S"; 19];
        champs.push("250000");
        champs.extend(["0"; 20]);
        let stat = format!("4242 (a) b (c) {}", champs.join(" "));
        assert_eq!(debut_du_processus(&stat, 1_000_000, 100), Some(1_002_500));
        assert_eq!(debut_du_processus("4242 (court) S 1", 1_000_000, 100), None);
        // Le vrai /proc de ce processus : un démarrage après celui de l'ordinateur, et pas dans le futur.
        let vrai = std::fs::read_to_string("/proc/self/stat").unwrap();
        let debut = debut_du_processus(&vrai, btime().unwrap(), 100).unwrap();
        assert!(debut >= btime().unwrap());
    }

    /// Les processus de ce compte, lus pour de vrai : celui des tests en fait partie, avec son programme et son
    /// empreinte.
    #[test]
    fn processus_de_cette_machine() {
        let dossier = crate::socle::dossier_local().join("processus");
        std::fs::create_dir_all(&dossier).unwrap();
        let p = processus(&dossier);
        assert!(p.compte.is_some(), "{p:?}");
        let texte = std::fs::read_to_string(dossier.join("01-processus.txt")).unwrap();
        let moi = std::process::id().to_string();
        let ligne = texte
            .lines()
            .find(|l| l.split('\t').next() == Some(moi.as_str()))
            .expect("le processus des tests manque");
        let champs: Vec<&str> = ligne.split('\t').collect();
        // Le programme des tests (debug, avec le client HTTPS) dépasse parfois la borne des empreintes : c'est dit.
        let gros = std::env::current_exe()
            .and_then(std::fs::metadata)
            .is_ok_and(|m| m.len() > super::super::TAILLE_EMPREINTE);
        if gros {
            assert_eq!(champs[4], "(trop gros/too big)", "{ligne}");
        } else {
            assert_eq!(champs[4].len(), 64, "{ligne}");
        }
        assert!(champs[5].starts_with('/'), "{ligne}");
    }
}
