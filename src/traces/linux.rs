//! Les traces sous Linux : /proc pour les processus (sans rien lancer), ss et ip pour le réseau, systemd, cron et
//! les fichiers de démarrage, les comptes et leurs connexions, le journal de systemd.

use std::collections::HashMap;
use std::fmt::Write as _;
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

/// Le parent, le compte (numéro réel) et le nom d'un processus, d'après `/proc/<pid>/status`.
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

/// L'heure de démarrage d'un processus (secondes depuis 1970) d'après `/proc/<pid>/stat` : son 22e champ compte les
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

/// Les processus, lus dans /proc sans rien lancer. Le programme de chacun se lit par `/proc/<pid>/exe`, même effacé du
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

/// Une liste relevée par Vanguard écrite dans la feuille sous son titre ; `None` : le noyau ou le service n'a pas
/// répondu, et c'est écrit.
fn releve(f: &mut Feuille, titre: &str, lignes: Option<Vec<String>>) -> bool {
    f.section(&format!("{titre} (lu par Vanguard / read by Vanguard)"));
    if let Some(l) = lignes {
        f.ajouter(&l.join("\n"));
        f.lues += 1;
        true
    } else {
        f.ajouter(&Raison::Erreur("pas de réponse / no answer".into()).note());
        false
    }
}

/// Connexions et ports à l'écoute avec leur programme, voisins (ARP), adresses, routes, DNS et fichier hosts : lus
/// par Vanguard (netlink, D-Bus) d'abord, la sortie de ss, ip et resolvectl à côté en témoin. Un port à l'écoute vu
/// par le noyau et absent de ss est signalé.
pub(super) fn reseau(dossier: &Path) -> Partie {
    use crate::machine::linux::reseau_natif;
    let mut p = Partie::new(Bi::new("Réseau", "Network"));
    let mut f = Feuille::new(&p.titre);
    let prises = reseau_natif::prises();
    releve(
        &mut f,
        "sock_diag : prises TCP et UDP, tous états / TCP and UDP sockets, all states",
        prises
            .as_ref()
            .map(|v| v.iter().map(reseau_natif::Prise::ligne).collect()),
    );
    let ss = f.commande(Command::new("ss").args(["-tunap"]), 15, prises.is_none());
    if let (Some(natives), Some(ss)) = (&prises, &ss) {
        let outil = reseau_natif::ecoutes_de_ss(ss);
        // Relu après ss : seule une prise à l'écoute avant ET après lui compte (une prise UDP d'un instant, une
        // question DNS, n'est pas cachée).
        let apres: std::collections::HashSet<(bool, u16)> = reseau_natif::prises()
            .unwrap_or_default()
            .iter()
            .filter(|p| p.a_l_ecoute())
            .map(|p| (p.udp, p.port_local))
            .collect();
        let mut caches: Vec<String> = natives
            .iter()
            .filter(|p| {
                p.a_l_ecoute() && apres.contains(&(p.udp, p.port_local)) && !outil.contains(&(p.udp, p.port_local))
            })
            .map(|p| format!("{} {}", if p.udp { "udp" } else { "tcp" }, p.port_local))
            .collect();
        caches.sort();
        caches.dedup();
        if !caches.is_empty() {
            let liste = caches.join(", ");
            ecart(
                &mut f,
                "ss",
                bi!(
                    "ports à l'écoute vus par le noyau, absents de ss : {liste}",
                    "listening ports seen by the kernel, missing from ss: {liste}"
                ),
            );
        }
    }
    releve(&mut f, "RTM_GETNEIGH : voisins / neighbours", reseau_natif::voisins());
    f.commande(Command::new("ip").args(["neigh", "show"]), 10, false);
    releve(&mut f, "RTM_GETADDR : adresses / addresses", reseau_natif::adresses());
    f.commande(Command::new("ip").args(["address", "show"]), 10, false);
    releve(
        &mut f,
        "RTM_GETROUTE : routes, toutes les tables / all tables",
        reseau_natif::routes(),
    );
    f.commande(Command::new("ip").args(["route", "show", "table", "all"]), 10, false);
    for chemin in ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"] {
        f.fichier(Path::new(chemin), true);
    }
    releve(&mut f, "resolve1 : systemd-resolved", reseau_natif::resolved().ok());
    f.commande(Command::new("resolvectl").arg("status"), 10, false);
    let connexions = prises.as_ref().map(Vec::len).or_else(|| {
        ss.as_ref().map(|s| {
            s.lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with("Netid"))
                .count()
        })
    });
    if connexions.is_some() && !super::privilegie() {
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
            "connexions et ports à l'écoute avec leur programme, voisins du réseau local (table ARP), adresses, routes et DNS lus par Vanguard (netlink, D-Bus), avec la sortie de ss, ip et resolvectl à côté en témoin, et le fichier hosts",
            "connections and listening ports with their program, local network neighbours (ARP table), addresses, routes and DNS read by Vanguard (netlink, D-Bus), with the output of ss, ip and resolvectl alongside as a witness, and the hosts file",
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
    // Le relevé de Vanguard (D-Bus) d'abord, la sortie de systemctl ensuite, en témoin.
    let systeme = releve_systemd(&mut f, false);
    let outil = f.commande(
        Command::new("systemctl").args(["list-unit-files", "--no-pager", "--full"]),
        20,
        systeme.is_none(),
    );
    comparer_fichiers_d_unites(
        &mut f,
        systeme.as_deref(),
        outil.as_deref(),
        "systemctl list-unit-files",
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
    let utilisateur = releve_systemd(&mut f, true);
    let outil = f.commande(
        Command::new("systemctl").args(["--user", "list-unit-files", "--no-pager", "--full"]),
        20,
        false,
    );
    comparer_fichiers_d_unites(
        &mut f,
        utilisateur.as_deref(),
        outil.as_deref(),
        "systemctl --user list-unit-files",
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
            "ce qui se lance tout seul : unités et minuteries de systemd lues par Vanguard (D-Bus), avec la sortie de systemctl à côté en témoin (et services activés, dossiers .wants), tâches cron, démarrage de session (autostart), bibliothèque préchargée (ld.so.preload), fichiers du shell, clés SSH autorisées, modules du noyau chargés",
            "what starts by itself: systemd units and timers read by Vanguard (D-Bus), with the output of systemctl alongside as a witness (and enabled services, .wants folders), cron jobs, session autostart, preloaded library (ld.so.preload), shell files, authorized SSH keys, loaded kernel modules",
        ),
    ) {
        p.compte = Some(bi!("{} source(s) lue(s)", "{} source(s) read", f.lues));
    }
    p
}

/// Le gestionnaire systemd du système (ou de l'utilisateur) lu par D-Bus dans la feuille : fichiers d'unités et leur
/// état (ListUnitFiles), unités chargées (ListUnits), minuteries (Timer). Rend les noms des fichiers d'unités lus ;
/// `None` : illisible, et c'est écrit (sous sudo, le gestionnaire de l'utilisateur n'est pas joignable : un manque,
/// pas « aucune unité »).
fn releve_systemd(f: &mut Feuille, utilisateur: bool) -> Option<Vec<String>> {
    use crate::machine::linux::{connexions::date, unites};
    let qui = if utilisateur { "--user" } else { "système / system" };
    f.section(&format!(
        "systemd {qui} : ListUnitFiles, ListUnits, Timer (lu par Vanguard / read by Vanguard)"
    ));
    let lu = unites::bus(utilisateur).and_then(|mut b| {
        let fichiers = unites::fichiers(&mut b)?;
        let chargees = unites::unites(&mut b)?;
        let minuteries = unites::minuteries(&mut b)?;
        Ok((fichiers, chargees, minuteries))
    });
    let (fichiers, chargees, minuteries) = match lu {
        Ok(l) => l,
        Err(e) => {
            f.ajouter(&Raison::Erreur(e.to_string()).note());
            if utilisateur {
                f.manques.push(Manque {
                    quoi: Bi::new("Unités de systemd de l'utilisateur", "User systemd units"),
                    raison: Raison::Erreur(e.to_string()),
                });
            }
            return None;
        }
    };
    let us = |t: u64| {
        if t == 0 {
            "-".to_string()
        } else {
            i64::try_from(t / 1_000_000).map(date).unwrap_or_default()
        }
    };
    let mut texte = String::from("# fichiers / unit files\n");
    for (chemin, etat) in &fichiers {
        let _ = writeln!(texte, "{}\t{etat}\t{chemin}", unites::nom_de(chemin));
    }
    texte.push_str("\n# chargées / loaded\n");
    for u in &chargees {
        let _ = writeln!(
            texte,
            "{}\t{}\t{}\t{}\t{}",
            u.nom, u.chargement, u.activite, u.sous_etat, u.description
        );
    }
    texte.push_str("\n# minuteries / timers (prochain, dernier, unité, lance)\n");
    for m in &minuteries {
        let _ = writeln!(texte, "{}\t{}\t{}\t{}", us(m.prochain), us(m.dernier), m.nom, m.service);
    }
    f.ajouter(&texte);
    f.lues += 1;
    Some(fichiers.iter().map(|(c, _)| unites::nom_de(c).to_string()).collect())
}

/// Les fichiers d'unités vus par D-Bus et absents de la sortie de systemctl : un systemctl remplacé qui cache une
/// unité posée pour durer.
fn comparer_fichiers_d_unites(f: &mut Feuille, natifs: Option<&[String]>, outil: Option<&str>, nom: &str) {
    let (Some(natifs), Some(outil)) = (natifs, outil) else {
        return;
    };
    let vus: std::collections::HashSet<&str> = outil.lines().filter_map(|l| l.split_whitespace().next()).collect();
    // systemctl qui n'a rien listé (refusé, gestionnaire injoignable) : pas un témoin, rien à comparer.
    if !natifs.iter().any(|n| vus.contains(n.as_str())) {
        return;
    }
    let mut caches: Vec<&String> = natifs.iter().filter(|n| !vus.contains(n.as_str())).collect();
    caches.dedup();
    if !caches.is_empty() {
        let n = caches.len();
        ecart(
            f,
            nom,
            bi!(
                "{n} fichiers d'unités vus par D-Bus, absents de systemctl",
                "{n} unit files seen by D-Bus, missing from systemctl"
            ),
        );
    }
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
/// locale), pour comparer au relevé de Vanguard. À l'heure ambiguë du passage à l'heure d'hiver, les deux lectures
/// possibles de la date.
fn dates_de_last(sortie: &str) -> Vec<Vec<i64>> {
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
            let r = chrono::TimeZone::from_local_datetime(&chrono::Local, &d);
            let mut v: Vec<i64> = [r.earliest(), r.latest()]
                .into_iter()
                .flatten()
                .map(|d| d.timestamp())
                .collect();
            v.dedup();
            (!v.is_empty()).then_some(v)
        })
        .collect()
}

/// Les connexions et démarrages de wtmp que `last` aurait dû montrer et qui n'y sont pas : un `last` remplacé qui
/// cache une session. Comparés par position, pas par l'heure (une horloge qui recule ne trompe pas) : les N derniers
/// enregistrements que last montre, N le nombre de ses lignes, ou tous s'il en a montré moins que sa borne. Comptés
/// par seconde, pour que deux sessions de la même seconde comptent deux fois.
fn absentes_de_last(
    natifs: &[crate::machine::linux::connexions::Enregistrement],
    last: &[Vec<i64>],
    borne: usize,
) -> usize {
    use crate::machine::linux::connexions::{BOOT_TIME, USER_PROCESS};
    let montres: Vec<i64> = natifs
        .iter()
        .filter(|e| match e.genre {
            BOOT_TIME => true,
            USER_PROCESS => !e.compte.is_empty() && !e.ligne.is_empty() && e.ligne != "~",
            _ => false,
        })
        .map(|e| i64::from(e.secondes))
        .collect();
    // last s'arrête à sa borne : seuls les plus récents se comparent.
    let n = if last.len() >= borne {
        last.len().min(montres.len())
    } else {
        montres.len()
    };
    let mut vus: HashMap<i64, usize> = HashMap::new();
    for t in last.iter().flatten() {
        *vus.entry(*t).or_default() += 1;
    }
    let mut absentes = 0;
    for t in &montres[montres.len() - n..] {
        match vus.get_mut(t) {
            Some(k) if *k > 0 => *k -= 1,
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
            // Sans date d'entrée : rien à placer dans la chronologie (pas en 1970).
            if quand <= 0 {
                return None;
            }
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

/// Les sessions de logind lues au plus.
const SESSIONS_MAX: usize = 1000;

/// Les sessions de systemd (logind) par le client D-Bus maison : ListSessions, puis les propriétés de chacune.
/// Rend les identifiants lus ; `None` : illisible, la raison écrite dans la feuille.
fn sessions_logind(f: &mut Feuille) -> Option<Vec<String>> {
    use crate::machine::linux::dbus;
    const LOGIN1: &str = "org.freedesktop.login1";
    f.section("logind : ListSessions (lu par Vanguard / read by Vanguard)");
    let mut coupees = 0usize;
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
        let toutes = liste.first().map(dbus::Valeur::elements).unwrap_or_default();
        coupees = toutes.len().saturating_sub(SESSIONS_MAX);
        for s in toutes.iter().take(SESSIONS_MAX) {
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
            // Plus de sessions que la borne : la liste est coupée, et c'est dit (une session qui manque ici n'est pas
            // une session absente).
            if coupees > 0 {
                let raison = Raison::Entrees(SESSIONS_MAX);
                f.ajouter(&raison.note());
                f.manques.push(Manque {
                    quoi: Bi::new("Sessions de logind", "logind sessions"),
                    raison,
                });
            }
            Some(ids)
        }
        Err(e) => {
            f.ajouter(&Raison::Erreur(e).note());
            None
        }
    }
}

/// Pourquoi une base de connexions n'a pas été lue ici, dans les deux langues (l'outil, à côté, la lit).
fn raison_base(e: Option<&crate::machine::linux::connexions::PasLue>) -> String {
    use crate::machine::linux::connexions::PasLue;
    match e {
        Some(PasLue::Journal) => "écriture en attente dans son journal / write pending in its journal".into(),
        Some(PasLue::TropGrosse) => "base trop grosse pour Vanguard / database too big for Vanguard".into(),
        Some(PasLue::Illisible(x)) => format!("illisible / unreadable : {x}"),
        Some(PasLue::Absente) => "absente / missing".into(),
        // Lue, mais pas comprise : abîmée, schéma inattendu, ou plus de lignes que le lecteur n'en lit.
        None => "base abîmée, d'une autre forme ou trop longue / damaged, unexpected or too long database".into(),
    }
}

/// Un écart entre le relevé de Vanguard et l'outil qu'il remplace, pour l'écran.
fn ecart(f: &mut Feuille, outil: &str, ce_qui: Bi) {
    let _ = writeln!(f.texte, "{}", Raison::Ecart(ce_qui.clone()).note());
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
            // who ne montre que les sessions d'un compte dont le processus vit encore : une entrée périmée (terminal
            // tué) n'est pas un écart.
            Some(
                v.iter()
                    .filter(|e| !e.compte.is_empty() && Path::new(&format!("/proc/{}", e.pid)).exists())
                    .count(),
            )
        }
        Err(e) => {
            f.ajouter(&Raison::Erreur(e.to_string()).note());
            None
        }
    };
    let who = f.commande(&mut Command::new("who"), 10, false);
    if let (Some(n), Some(w)) = (ouvertes, &who) {
        let outil = w.lines().filter(|l| !l.trim().is_empty()).count();
        // Seulement des sessions qui manquent à who (un who construit avec logind peut en montrer davantage).
        if outil < n {
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
        let absentes = absentes_de_last(n, &dates_de_last(l), 1000);
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
            let pourquoi = raison_base(lue.as_ref().err());
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
                None => f.ajouter(&Raison::Erreur(pourquoi.clone()).note()),
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
            let pourquoi = raison_base(lue.as_ref().err());
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
                None => f.ajouter(&Raison::Erreur(pourquoi.clone()).note()),
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
    let wtmpdb_absente = !Path::new(cx::WTMPDB).exists();
    p.evenements = match (&wtmp, &wtmpdb) {
        (Some(n), _) if !n.is_empty() => evenements_wtmp(n),
        (_, Some(s)) => evenements_wtmpdb(s),
        // wtmp vide et pas de wtmpdb : vraiment rien.
        (Some(n), None) if wtmpdb_absente => evenements_wtmp(n),
        // Ni wtmp ni wtmpdb lus ici : la sortie des outils, sinon c'est dit.
        _ => {
            let sessions = last
                .filter(|s| !s.trim().is_empty())
                .or(wtmpdb_outil)
                .unwrap_or_default();
            if sessions.trim().is_empty() {
                p.manques.push(Manque {
                    quoi: Bi::new(
                        "Chronologie : démarrages et sessions (wtmp et wtmpdb illisibles)",
                        "Timeline: boots and sessions (wtmp and wtmpdb unreadable)",
                    ),
                    raison: Raison::Introuvable,
                });
            }
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
    // Les fichiers du journal lus par Vanguard d'abord ; journalctl à côté en témoin, ou à leur place s'ils ne se
    // lisent pas ici (droits, xz).
    if let Some(natif) = journal_natif(dossier, &titre) {
        match natif {
            Ok(n) => {
                p.fichiers.push(super::Produit {
                    nom: nom.into(),
                    contenu: Bi::new(
                        "le journal de systemd des 7 derniers jours, lu par Vanguard dans ses fichiers, du plus récent au plus ancien, 50 Mo au plus",
                        "the systemd journal of the last 7 days, read by Vanguard from its files, newest first, 50 MB at most",
                    ),
                });
                if n.coupe {
                    p.manque(
                        Bi::new("Journal du système, les plus anciens", "System log, the oldest entries"),
                        Raison::Borne(super::BORNE_JOURNAL),
                    );
                }
                let m = mo(n.octets);
                p.compte = Some(Bi::new(format!("{} (7 jours)", m.fr), format!("{} (7 days)", m.en)));
                temoin_journalctl(&mut p, dossier, &n.prefixes, n.debut);
                return p;
            }
            Err(e) => p.manque(titre.clone(), Raison::Erreur(e.to_string())),
        }
        return p;
    }
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

/// Le témoin du journal lu par Vanguard : la sortie de journalctl, les plus récentes d'abord, bornée plus court.
const TEMOIN_JOURNAL: u64 = 10 << 20;
/// Le fichier du témoin : hors des « 05-… » que la chronologie relit (il ferait des doublons).
const TEMOIN_ECRIT: &str = "05b-journalctl.txt";
/// Entrées du relevé gardées pour la comparaison avec le témoin (le début, les plus récentes).
const PREFIXES_GARDES: usize = 200_000;

/// Ce que le relevé du journal par Vanguard a écrit.
struct JournalNatif {
    octets: u64,
    coupe: bool,
    /// (heure en secondes, « date hôte `identifiant[pid]` ») des premières entrées écrites, pour le témoin.
    prefixes: Vec<(i64, String)>,
    /// Le début de la lecture (secondes) : ce qui s'est écrit ensuite n'y est pas, et ne se compare pas.
    debut: i64,
}

/// Le début d'une ligne courte du journal, jusqu'au « : » qui suit l'identifiant et le processus, et son heure.
fn prefixe(ligne: &str) -> Option<(i64, String)> {
    let date = ligne.get(..25)?;
    let quand = chrono::DateTime::parse_from_rfc3339(date).ok()?.timestamp();
    let fin = ligne.get(26..)?.find(": ")? + 26;
    Some((quand, ligne[..fin].to_string()))
}

/// Le journal de systemd lu par Vanguard dans ses fichiers (`journal_systemd::tout_le_journal`), écrit dans
/// 05-journal.txt. `None` : il ne se lit pas ici, journalctl le fera ; `Some(Err)` : le fichier ne s'écrit pas.
fn journal_natif(dossier: &Path, titre: &Bi) -> Option<std::io::Result<JournalNatif>> {
    use std::io::Write as _;
    let depuis = u64::try_from(chronologie::secondes(std::time::SystemTime::now())? - chronologie::JOURS * 86_400)
        .ok()?
        .saturating_mul(1_000_000);
    let debut = chronologie::secondes(std::time::SystemTime::now())?;
    let chemin = dossier.join(JOURNAL_ECRIT);
    let mut f = match super::creer_fichier(&chemin) {
        Ok(f) => std::io::BufWriter::new(f),
        Err(e) => return Some(Err(e)),
    };
    let mut entete = super::entete(titre);
    entete.push_str("# lu par Vanguard dans les fichiers du journal / read by Vanguard from the journal files\n");
    let mut octets = 0u64;
    let mut erreur = None;
    let mut prefixes = Vec::new();
    if let Err(e) = f.write_all(entete.as_bytes()) {
        return Some(Err(e));
    }
    let parcours = crate::machine::linux::journal_systemd::tout_le_journal(depuis, |l| {
        let mut ligne = super::texte_sur(l);
        ligne.push('\n');
        if octets + ligne.len() as u64 > super::BORNE_JOURNAL {
            return false;
        }
        if prefixes.len() < PREFIXES_GARDES
            && let Some(p) = prefixe(l)
        {
            prefixes.push(p);
        }
        octets += ligne.len() as u64;
        match f.write_all(ligne.as_bytes()) {
            Ok(()) => true,
            Err(e) => {
                erreur = Some(e);
                false
            }
        }
    });
    if let Some(e) = erreur {
        return Some(Err(e));
    }
    let Some(parcours) = parcours else {
        // Illisible ici : le fichier commencé est retiré, journalctl l'écrira.
        drop(f);
        let _ = std::fs::remove_file(&chemin);
        return None;
    };
    if let Err(e) = f.flush() {
        return Some(Err(e));
    }
    Some(Ok(JournalNatif {
        octets,
        coupe: parcours.coupe,
        prefixes,
        debut,
    }))
}

/// Les entrées présentes d'un côté et pas de l'autre, comptées par leur début (date, hôte, identifiant, processus) :
/// (absentes du témoin, absentes du relevé). La période comparée part du relevé : du plus ancien qu'il a gardé
/// jusqu'à dix secondes avant `fin`, le début de la première lecture (ce qui s'écrit ensuite n'est que dans la
/// seconde). Un témoin coupé à sa borne (`temoin_coupe`) ne couvre que ses plus récentes : la période s'arrête alors à
/// sa plus ancienne. Un témoin vide ne la réduit pas : tout ce que le relevé a manque alors au témoin.
fn ecarts_du_journal(
    natifs: &[(i64, String)],
    temoin: &[(i64, String)],
    fin: i64,
    temoin_coupe: bool,
) -> (usize, usize) {
    fn compter(v: &[(i64, String)], periode: std::ops::Range<i64>) -> HashMap<&str, isize> {
        let mut m: HashMap<&str, isize> = HashMap::new();
        for (q, p) in v {
            if periode.contains(q) {
                *m.entry(p.as_str()).or_default() += 1;
            }
        }
        m
    }
    let Some(debut_n) = natifs.iter().map(|p| p.0).min() else {
        return (0, 0);
    };
    // La plus ancienne seconde peut être coupée : elle ne compte pas.
    let mut debut = debut_n + 1;
    if temoin_coupe && let Some(debut_t) = temoin.iter().map(|p| p.0).min() {
        debut = debut.max(debut_t + 1);
    }
    let fin = fin - 10;
    let (n, t) = (compter(natifs, debut..fin), compter(temoin, debut..fin));
    let manque = |a: &HashMap<&str, isize>, b: &HashMap<&str, isize>| {
        a.iter()
            .map(|(k, v)| (v - b.get(k).copied().unwrap_or(0)).max(0))
            .sum::<isize>()
            .unsigned_abs()
    };
    (manque(&n, &t), manque(&t, &n))
}

/// journalctl à côté du relevé, en témoin (10 Mo, les plus récentes), et l'écart entre les deux : une entrée lue
/// dans les fichiers et absente de journalctl (un journalctl remplacé qui la cache), ou l'inverse.
fn temoin_journalctl(p: &mut Partie, dossier: &Path, natifs: &[(i64, String)], debut_du_releve: i64) {
    let titre = Bi::new(
        "Journal du système, témoin (journalctl)",
        "System log, witness (journalctl)",
    );
    let mut commande = Command::new("journalctl");
    commande
        .args(["--since=-7d", "--reverse", "--no-pager", "-o", "short-iso"])
        .env("LC_ALL", "C.UTF-8");
    match super::unix::journal_vers_borne(
        dossier,
        TEMOIN_ECRIT,
        &titre,
        &mut commande,
        120,
        Garder::Debut,
        None,
        TEMOIN_JOURNAL,
    ) {
        // journalctl absent : pas de témoin, rien à comparer.
        Ok(None) => {}
        Err(e) => p.manque(titre, Raison::Erreur(e.to_string())),
        Ok(Some(ecrit)) => {
            p.fichiers.push(super::Produit {
                nom: TEMOIN_ECRIT.into(),
                contenu: Bi::new(
                    "la sortie de journalctl sur la même semaine (10 Mo, les plus récentes), gardée en témoin du relevé",
                    "the output of journalctl over the same week (10 MB, newest first), kept as a witness of the reading",
                ),
            });
            // Arrêté par le délai ou en échec (ordinateur chargé, journal qui tourne) : le témoin est partiel, la
            // comparaison dirait « caché » à tort. Seule la borne de 10 Mo, connue, se compare.
            if ecrit.delai {
                p.manque(titre, Raison::Delai(120));
                return;
            }
            if ecrit.code != Some(0) && !ecrit.tronque {
                let erreur = ecrit.erreurs.lines().next().unwrap_or_default().trim().to_string();
                p.manque(
                    titre,
                    Raison::Erreur(format!("journalctl : code {:?} {erreur}", ecrit.code)),
                );
                return;
            }
            // Borné (le témoin fait 10 Mo au plus), en simple fichier : rien de posé à sa place ne fige la collecte.
            let texte = crate::socle::lire_texte_ordinaire(&dossier.join(TEMOIN_ECRIT), 32 << 20).unwrap_or_default();
            let temoin: Vec<(i64, String)> = texte.lines().filter_map(prefixe).collect();
            let (cachees, en_plus) = ecarts_du_journal(natifs, &temoin, debut_du_releve, ecrit.tronque);
            if cachees > 0 || en_plus > 0 {
                p.manque(
                    Bi::new("Comparaison avec « journalctl »", "Comparison with “journalctl”"),
                    Raison::Ecart(bi!(
                        "{cachees} entrées des fichiers absentes de journalctl, {en_plus} de journalctl absentes des fichiers",
                        "{cachees} entries from the files missing from journalctl, {en_plus} from journalctl missing from the files"
                    )),
                );
            }
        }
    }
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

/// Une lecture ciblée (filtres de journalctl : « -t X » ou « CHAMP=valeur ») faite dans les fichiers du journal :
/// les `ENTREES_CIBLEES` plus récentes depuis `depuis` (µs), écrites comme `journalctl -o short-iso`. `None` : le
/// journal ne se lit pas ici.
fn journal_cible_natif(filtres: &[&str], depuis: u64) -> Option<String> {
    use crate::machine::linux::journal_systemd::{CHAMPS_COURTS, entrees, ligne_courte};
    let mut champs = Vec::new();
    let mut f = filtres.iter();
    while let Some(x) = f.next() {
        champs.push(if *x == "-t" {
            format!("SYSLOG_IDENTIFIER={}", f.next()?)
        } else {
            (*x).to_string()
        });
    }
    let champs: Vec<&str> = champs.iter().map(String::as_str).collect();
    let toutes = entrees(&champs, depuis, CHAMPS_COURTS)?;
    let debut = toutes.len().saturating_sub(ENTREES_CIBLEES);
    Some(
        toutes[debut..]
            .iter()
            .filter_map(ligne_courte)
            .collect::<Vec<_>>()
            .join("\n"),
    )
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
    let depuis_us = u64::try_from(debut).unwrap_or(0).saturating_mul(1_000_000);
    for (fr, en, filtres) in LECTURES_CIBLEES {
        let quoi = bi!("Chronologie : journal ciblé ({fr})", "Timeline: targeted log ({en})");
        // Les fichiers du journal lus par Vanguard d'abord : « -t X » est le champ SYSLOG_IDENTIFIER=X, un champ
        // exact reste tel quel. journalctl seulement s'ils ne se lisent pas ici.
        if let Some(texte) = journal_cible_natif(filtres, depuis_us) {
            lu = true;
            let mut lecture = super::unix::lire_texte(&texte, maintenant);
            apport.manques.extend(lecture_coupee(quoi, lecture.entrees));
            apport.evenements.append(&mut lecture.evenements);
            continue;
        }
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
        let plus_ancienne = crate::machine::linux::journal_systemd::plus_ancienne()
            .and_then(|us| i64::try_from(us / 1_000_000).ok())
            .or_else(|| {
                crate::commande::lancer(&mut c, 30)
                    .filter(|r| r.code == Some(0))
                    .and_then(|r| {
                        r.sortie
                            .lines()
                            .find_map(|l| chronologie::quand_de_ligne(l, maintenant, &chrono::Local))
                    })
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
    super::BORNE_JOURNAL + TEMOIN_JOURNAL
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
        let l = |v: &[i64]| v.iter().map(|t| vec![*t]).collect::<Vec<_>>();
        assert_eq!(absentes_de_last(&natifs, &l(&[100, 200, 300, 300, 400]), 1000), 0);
        assert_eq!(
            absentes_de_last(&natifs, &l(&[100, 200, 300, 400]), 1000),
            1,
            "deux sessions de la même seconde"
        );
        assert_eq!(
            absentes_de_last(&natifs, &l(&[100, 200, 300, 300]), 1000),
            1,
            "mallory caché"
        );
        // Un last qui ne montre rien : tout manque.
        assert_eq!(absentes_de_last(&natifs, &[], 1000), 5);
        // À sa borne, seuls les plus récents se comparent (ici les 2 derniers).
        assert_eq!(absentes_de_last(&natifs, &l(&[300, 400]), 2), 0);
        // Une horloge qui recule : comparé par position, pas par l'heure.
        let recul = [
            e(USER_PROCESS, "alice", "pts/0", 900),
            e(USER_PROCESS, "alice", "pts/1", 50),
        ];
        assert_eq!(absentes_de_last(&recul, &l(&[900, 50]), 1000), 0);
        assert_eq!(
            absentes_de_last(
                &natifs,
                &[vec![150, 100], vec![200], vec![300], vec![300], vec![400]],
                1000
            ),
            0
        );
        // Les dates de last -F, en heure locale : jours sur un ou deux chiffres, « wtmp begins » sauté.
        let texte = "alice    pts/0        192.0.2.10       Tue Oct  6 23:09:30 2026 - Tue Oct  6 23:10:00 2026  (00:00)\n\
                     reboot   system boot  6.17.1-arch1-1   Sat Oct 24 02:21:00 2026   still running\n\n\
                     wtmp begins Wed Sep  3 13:47:00 2026\n";
        let d = dates_de_last(texte);
        assert_eq!(d.len(), 2);
        assert_eq!(d[1][0] - d[0][0], 17 * 86_400 + 3 * 3600 + 11 * 60 + 30);
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
        let present = |c: &str, a: &str| crate::commande::lancer(Command::new(c).arg(a), 10).is_some();
        if std::fs::read(crate::machine::linux::connexions::UTMP).is_err()
            || !present("who", "--version")
            || !present("last", "-n1")
        {
            return crate::essais::saute("utmp illisible, ou who et last absents");
        }
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

    /// L'oracle du démarrage : les fichiers d'unités du système et de l'utilisateur lus par D-Bus, tous présents dans
    /// la sortie de systemctl, sur cet ordinateur ; le relevé et son témoin sont écrits.
    #[test]
    fn demarrage_de_cette_machine() {
        // Les deux côtés doivent se lire, sinon la comparaison passerait à vide.
        let lu =
            crate::machine::linux::unites::bus(false).and_then(|mut b| crate::machine::linux::unites::fichiers(&mut b));
        if !lu.is_ok_and(|f| !f.is_empty()) || crate::machine::sortie("systemctl", &["--version"]).is_none() {
            return crate::essais::saute("systemd illisible par D-Bus, ou systemctl absent");
        }
        let dossier = crate::socle::dossier_local().join("traces-demarrage");
        std::fs::create_dir_all(&dossier).unwrap();
        let p = demarrage(&dossier);
        let ecarts: Vec<_> = p
            .manques
            .iter()
            .filter(|m| matches!(m.raison, Raison::Ecart(_)))
            .collect();
        assert!(ecarts.is_empty(), "{ecarts:?}");
        let texte = std::fs::read_to_string(dossier.join("03-demarrage.txt")).unwrap();
        assert!(texte.contains("ListUnitFiles") && texte.contains("$ systemctl list-unit-files"));
    }

    /// L'oracle des lectures ciblées : pour chacune, les entrées lues dans les fichiers du journal et celles de
    /// journalctl, comptées par leur début, sur la période que les deux couvrent ; et l'écart compté sur des listes
    /// fabriquées.
    #[test]
    fn lectures_ciblees_comme_journalctl() {
        let maintenant = chronologie::secondes(std::time::SystemTime::now()).unwrap();
        let depuis = u64::try_from(maintenant - chronologie::JOURS * 86_400).unwrap() * 1_000_000;
        let mut comparees = 0;
        for (_, en, filtres) in LECTURES_CIBLEES {
            let Some(natif) = journal_cible_natif(filtres, depuis) else {
                return crate::essais::saute("journal illisible ici");
            };
            let mut c = journalctl_7_jours();
            c.arg(format!("--lines={ENTREES_CIBLEES}")).args(filtres);
            let Some(r) = crate::commande::lancer(&mut c, 60).filter(|r| r.code == Some(0)) else {
                return crate::essais::saute("journalctl absent");
            };
            let n: Vec<(i64, String)> = natif.lines().filter_map(prefixe).collect();
            let t: Vec<(i64, String)> = r.sortie.lines().filter_map(prefixe).collect();
            comparees += n.len();
            assert_eq!(
                ecarts_du_journal(&n, &t, maintenant, t.len() >= ENTREES_CIBLEES),
                (0, 0),
                "{en} : {} lues, {} par journalctl",
                n.len(),
                t.len()
            );
        }
        // Le noyau écrit au moins quelques lignes par semaine : la comparaison n'a pas tourné à vide.
        assert!(comparees > 0, "aucune entrée comparée");
        let p = |q: i64, s: &str| (q, s.to_string());
        let natifs = [p(100, "a"), p(200, "b"), p(200, "b"), p(300, "c")];
        assert_eq!(
            ecarts_du_journal(&natifs, &[p(100, "a"), p(200, "b"), p(300, "c")], 1000, false),
            (1, 0)
        );
        assert_eq!(
            ecarts_du_journal(&natifs, &[p(150, "z"), p(200, "b"), p(200, "b")], 1000, false),
            (1, 1),
            "c caché, z en plus"
        );
        // Un témoin vide : tout manque. Coupé à sa borne : seule sa période compte.
        assert_eq!(ecarts_du_journal(&natifs, &[], 1000, false), (3, 0));
        assert_eq!(
            ecarts_du_journal(&natifs, &[p(200, "b"), p(300, "c")], 1000, true),
            (0, 0)
        );
        // Les dix dernières secondes et la plus ancienne seconde ne comptent pas.
        assert_eq!(
            ecarts_du_journal(&natifs, &[p(100, "a"), p(200, "b"), p(200, "b")], 305, false),
            (0, 0)
        );
        assert_eq!(
            prefixe("2026-10-24T06:36:34-04:00 hote sshd[42]: Accepted"),
            Some((1_792_838_194, "2026-10-24T06:36:34-04:00 hote sshd[42]".to_string()))
        );
        assert_eq!(prefixe("  suite d'un message"), None);
    }

    /// L'oracle du journal complet dans les traces : écrit par Vanguard, avec journalctl en témoin, sans écart.
    #[test]
    fn journal_de_cette_machine() {
        let dossier = crate::socle::dossier_local().join("traces-journal");
        std::fs::create_dir_all(&dossier).unwrap();
        let p = journaux(&dossier);
        if !p.fichiers.iter().any(|f| f.nom == TEMOIN_ECRIT) {
            return crate::essais::saute("journal illisible ici ou journalctl absent");
        }
        let ecarts: Vec<_> = p
            .manques
            .iter()
            .filter(|m| matches!(m.raison, Raison::Ecart(_)))
            .collect();
        assert!(ecarts.is_empty(), "{ecarts:?}");
        let texte = std::fs::read_to_string(dossier.join(JOURNAL_ECRIT)).unwrap();
        assert!(texte.contains("lu par Vanguard"));
    }

    /// L'oracle du réseau : sur cet ordinateur, aucun port à l'écoute vu par le noyau ne manque à ss ; le relevé et
    /// son témoin sont écrits.
    #[test]
    fn reseau_de_cette_machine() {
        if crate::machine::linux::reseau_natif::prises().is_none() || crate::machine::sortie("ss", &["-V"]).is_none() {
            return crate::essais::saute("sock_diag refusé, ou ss absent");
        }
        let dossier = crate::socle::dossier_local().join("traces-reseau");
        std::fs::create_dir_all(&dossier).unwrap();
        let p = reseau(&dossier);
        let ecarts: Vec<_> = p
            .manques
            .iter()
            .filter(|m| matches!(m.raison, Raison::Ecart(_)))
            .collect();
        assert!(ecarts.is_empty(), "{ecarts:?}");
        let texte = std::fs::read_to_string(dossier.join("02-reseau.txt")).unwrap();
        assert!(texte.contains("sock_diag") && texte.contains("RTM_GETROUTE"));
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
