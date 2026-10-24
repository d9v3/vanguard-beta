//! Les traces sous macOS : ps pour les processus, lsof et netstat pour le réseau, launchd (agents et démons), cron,
//! fichiers du shell, comptes (dscl, last), journal unifié (log show) et journal des installations.

use std::collections::HashMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::unix::{cron, journal_vers, journaux_classiques, maison, mo, shell_et_ssh};
use super::{Bi, Empreinte, Feuille, Manque, Partie, Processus, Raison, bi, chronologie, lire_args, lire_ps};
use crate::commande::Garder;

/// Les processus demandés au noyau (libproc, sysctl), écrits dans 01-processus.txt ; la sortie de `ps` recopiée telle
/// quelle à côté (01-processus-ps.txt), avec les numéros que l'un voit et pas l'autre : un ps remplacé qui cache un
/// programme, ou une lecture native qui se trompe, se voit à cet écart. Sans lecture native, ps seul, comme avant.
pub(super) fn processus(dossier: &Path) -> Partie {
    let ps = |format: &str| {
        crate::commande::lancer(Command::new("ps").args(["-axww", "-o", format]).env("LC_ALL", "C"), 20)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
    };
    let brut = ps("pid=,ppid=,user=,lstart=,comm=");
    let Some(natifs) = crate::machine::macos::noyau::processus(true) else {
        let mut p = processus_ps(dossier, brut.as_deref(), &ps);
        p.manque(
            Bi::new(
                "Processus lus au noyau (libproc)",
                "Processes read from the kernel (libproc)",
            ),
            Raison::Erreur("proc_listallpids".into()),
        );
        return p;
    };
    let mut empreintes: HashMap<String, Empreinte> = HashMap::new();
    let fin = std::time::Instant::now() + super::DELAI_EMPREINTES;
    let mut comptes: HashMap<u32, String> = HashMap::new();
    let liste: Vec<Processus> = natifs
        .iter()
        .map(|n| {
            let programme = n.chemin.clone().unwrap_or_else(|| n.comm.clone());
            let empreinte = match &n.chemin {
                Some(c) => empreintes
                    .entry(c.clone())
                    .or_insert_with(|| {
                        if std::time::Instant::now() > fin {
                            Empreinte::Delai
                        } else {
                            super::empreinte(Path::new(c), super::TAILLE_PROGRAMME)
                        }
                    })
                    .clone(),
                None => Empreinte::Aucune,
            };
            Processus {
                pid: n.pid,
                ppid: Some(n.ppid),
                compte: comptes
                    .entry(n.uid)
                    .or_insert_with(|| crate::machine::macos::noyau::compte(n.uid).unwrap_or_else(|| n.uid.to_string()))
                    .clone(),
                debut: n.debut.map(|(s, _)| debut_local(s)).unwrap_or_default(),
                ligne: n.ligne().unwrap_or_default(),
                programme,
                etat: "",
                empreinte,
            }
        })
        .collect();
    let vus_noyau: Vec<u32> = liste.iter().map(|x| x.pid).collect();
    let mut p = super::partie_processus(dossier, liste, Vec::new());
    match brut {
        Some(brut) => {
            let vus_ps: Vec<u32> = lire_ps(&brut).into_iter().map(|(pid, ..)| pid).collect();
            // Par la feuille : les noms des programmes, choisis par eux, y perdent leurs caractères de contrôle.
            let mut f = Feuille::new(&Bi::new("Processus selon ps", "Processes according to ps"));
            f.section("Écart entre le noyau et ps / Difference between the kernel and ps");
            f.ajouter(&ecart_processus(&vus_noyau, &vus_ps));
            f.section("$ ps -axww -o pid=,ppid=,user=,lstart=,comm=");
            f.ajouter(&brut);
            p.ecrire(
                dossier,
                "01-processus-ps.txt",
                &f.texte,
                Bi::new(
                    "la sortie de ps telle quelle, et les processus que ps et le noyau ne voient pas tous les deux (un ps remplacé cache des programmes ; un processus né ou mort entre les deux lectures y paraît aussi)",
                    "ps output as is, and the processes that ps and the kernel do not both see (a replaced ps hides programs; a process born or ended between the two readings also shows up)",
                ),
            );
        }
        None => p.manque(Bi::meme("ps"), Raison::Absente("ps".into())),
    }
    p
}

/// L'heure de démarrage comme `ps -o lstart` l'écrit (heure locale, en anglais) : « Sat Oct 24 10:00:00 2026 ».
fn debut_local(secondes: i64) -> String {
    chrono::DateTime::from_timestamp(secondes, 0)
        .map(|d| {
            d.with_timezone(&chrono::Local)
                .format("%a %b %e %H:%M:%S %Y")
                .to_string()
        })
        .unwrap_or_default()
}

/// Les numéros que seul le noyau voit, puis ceux que seul ps voit, dans une section de texte. Rien d'écrit en trop
/// quand les deux s'accordent.
fn ecart_processus(noyau: &[u32], ps: &[u32]) -> String {
    let seuls = |a: &[u32], b: &[u32]| -> Vec<String> {
        let mut v: Vec<u32> = a.iter().filter(|x| !b.contains(x)).copied().collect();
        v.sort_unstable();
        v.iter().map(u32::to_string).collect()
    };
    let (n, p) = (seuls(noyau, ps), seuls(ps, noyau));
    let mut lignes = Vec::new();
    if n.is_empty() && p.is_empty() {
        lignes.push("aucun / none".to_string());
    }
    if !n.is_empty() {
        lignes.push(format!(
            "vus par le noyau, absents de ps / seen by the kernel, missing from ps : {}",
            n.join(" ")
        ));
    }
    if !p.is_empty() {
        lignes.push(format!(
            "vus par ps, absents du noyau / seen by ps, missing from the kernel : {}",
            p.join(" ")
        ));
    }
    lignes.join("\n")
}

/// Les processus d'après ps seul : le secours quand le noyau ne répond pas.
fn processus_ps(dossier: &Path, liste: Option<&str>, ps: &dyn Fn(&str) -> Option<String>) -> Partie {
    let Some(liste) = liste else {
        let mut p = Partie::new(Bi::new("Processus", "Processes"));
        p.manque(Bi::meme("ps"), Raison::Absente("ps".into()));
        return p;
    };
    let args = ps("pid=,args=").map(|s| lire_args(&s)).unwrap_or_default();
    let mut empreintes: HashMap<String, Empreinte> = HashMap::new();
    let fin = std::time::Instant::now() + super::DELAI_EMPREINTES;
    let liste: Vec<Processus> = lire_ps(liste)
        .into_iter()
        .map(|(pid, ppid, compte, debut, programme)| {
            let empreinte = if programme.starts_with('/') {
                empreintes
                    .entry(programme.clone())
                    .or_insert_with(|| {
                        if std::time::Instant::now() > fin {
                            Empreinte::Delai
                        } else {
                            super::empreinte(Path::new(&programme), super::TAILLE_PROGRAMME)
                        }
                    })
                    .clone()
            } else {
                Empreinte::Aucune
            };
            Processus {
                pid,
                ppid,
                compte,
                debut,
                ligne: args.get(&pid).cloned().unwrap_or_default(),
                programme,
                etat: "",
                empreinte,
            }
        })
        .collect();
    super::partie_processus(dossier, liste, Vec::new())
}

pub(super) fn reseau(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Réseau", "Network"));
    let mut f = Feuille::new(&p.titre);
    let lsof = f.commande(Command::new("lsof").args(["-nP", "-i"]), 30, true);
    f.commande(Command::new("netstat").args(["-an"]), 20, false);
    f.commande(Command::new("arp").args(["-an"]), 15, true);
    f.commande(Command::new("netstat").args(["-rn"]), 15, false);
    f.commande(Command::new("scutil").arg("--dns"), 15, true);
    f.commande(Command::new("scutil").arg("--proxy"), 15, false);
    f.fichier(Path::new("/etc/hosts"), true);
    f.fichier(Path::new("/etc/resolv.conf"), false);
    reseau_natif(&mut f);
    if lsof.is_some() && !super::privilegie() {
        f.manques.push(Manque {
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
            "connexions et ports à l'écoute avec leur programme (lsof -nP -i), toutes les connexions (netstat -an), voisins du réseau local (arp -an), routes, DNS (scutil --dns), proxy et fichier hosts ; puis les mêmes lus par Vanguard au noyau et à configd, à comparer (un écart est un indice)",
            "connections and listening ports with their program (lsof -nP -i), all connections (netstat -an), local network neighbours (arp -an), routes, DNS (scutil --dns), proxy and hosts file; then the same read by Vanguard from the kernel and configd, to compare (a difference is a clue)",
        ),
    ) {
        p.compte = Some(match lsof {
            Some(s) => bi!(
                "{} connexions et ports à l'écoute",
                "{} connections and listening ports",
                s.lines().count().saturating_sub(1)
            ),
            None => bi!("{} source(s) lue(s)", "{} source(s) read", f.lues),
        });
    }
    p
}

/// Ce que Vanguard lit lui-même, à côté de la sortie des outils (qu'un programme malveillant peut remplacer, et que
/// le noyau ne remplace pas) : un écart entre les deux est un indice. Prises (libproc), routes et voisins (sysctl
/// PF_ROUTE), DNS, proxy et services (configd).
fn reseau_natif(f: &mut Feuille) {
    use crate::machine::darwin::nom_etat_tcp;
    use crate::machine::macos::{config_reseau, noyau};
    let illisible = "(illisible / unreadable)";
    f.section("Lu par Vanguard au noyau : prises réseau (libproc) / Read by Vanguard from the kernel: sockets");
    match noyau::prises() {
        Some(l) => {
            let mut t = String::from("PID	PROGRAMME/PROGRAM	PROTO	LOCALE/LOCAL	DISTANTE/REMOTE	ÉTAT/STATE\n");
            for (pid, nom, p) in &l.prises {
                let _ = writeln!(
                    t,
                    "{pid}\t{nom}\t{}\t{}:{}\t{}:{}\t{}",
                    if p.tcp { "tcp" } else { "udp" },
                    p.locale,
                    p.port_local,
                    p.distante,
                    p.port_distant,
                    if p.tcp { nom_etat_tcp(p.etat) } else { "" }
                );
            }
            if l.illisibles > 0 {
                let _ = writeln!(
                    t,
                    "({} prises de forme inattendue, non lues : à comparer à lsof / {} sockets of unexpected shape, not read: compare with lsof)",
                    l.illisibles, l.illisibles
                );
            }
            if l.refuses > 0 {
                let _ = writeln!(
                    t,
                    "({} processus d'autres comptes non lus, réservés à root / {} processes of other accounts not read, root only)",
                    l.refuses, l.refuses
                );
            }
            f.ajouter(&t);
            f.lues += 1;
        }
        None => f.ajouter(illisible),
    }
    f.section(
        "Lu par Vanguard au noyau : routes IPv4 (sysctl NET_RT_DUMP) / Read by Vanguard from the kernel: IPv4 routes",
    );
    match noyau::routes() {
        Some(routes) => {
            let mut t = String::from("DESTINATION	PASSERELLE/GATEWAY	MASQUE/MASK	DRAPEAUX/FLAGS	INDEX\n");
            let montrer =
                |a: Option<&crate::machine::darwin::AdresseRoute>| a.map_or_else(String::new, ToString::to_string);
            for r in &routes {
                let _ = writeln!(
                    t,
                    "{}\t{}\t{}\t0x{:x}\t{}",
                    montrer(r.destination.as_ref()),
                    montrer(r.passerelle.as_ref()),
                    r.masque.map_or_else(String::new, |m| m.to_string()),
                    r.drapeaux,
                    r.index
                );
            }
            f.ajouter(&t);
            f.lues += 1;
        }
        None => f.ajouter(illisible),
    }
    f.section("Lu par Vanguard au noyau : voisins (ARP) / Read by Vanguard from the kernel: neighbours (ARP)");
    match noyau::voisins() {
        Some(v) => {
            let mut t = String::new();
            for x in &v {
                let mac: Vec<String> = x.mac.iter().map(|o| format!("{o:02x}")).collect();
                let _ = writeln!(t, "{}\t{}\tindex {}", x.ip, mac.join(":"), x.index);
            }
            f.ajouter(if t.is_empty() { "(aucun / none)" } else { &t });
            f.lues += 1;
        }
        None => f.ajouter(illisible),
    }
    f.section("Lu par Vanguard à configd : DNS en vigueur / Read by Vanguard from configd: DNS in use");
    match config_reseau::dns_en_vigueur() {
        Some(d) => f.ajouter(&d.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")),
        None => f.ajouter(illisible),
    }
    f.section("Lu par Vanguard à configd : proxy / Read by Vanguard from configd: proxy");
    f.ajouter(&config_reseau::proxy_comme_scutil().unwrap_or_else(|| illisible.to_string()));
    f.section(
        "Lu par Vanguard dans les réglages : services réseau / Read by Vanguard from the settings: network services",
    );
    match config_reseau::services() {
        Some(s) => {
            let mut t = String::new();
            for x in &s {
                let dns: Vec<String> = x.dns.iter().map(ToString::to_string).collect();
                let _ = writeln!(
                    t,
                    "{}\t{}\t{}\t{}\tDNS {}",
                    x.id,
                    x.nom,
                    if x.actif { "actif/enabled" } else { "coupé/disabled" },
                    x.carte.as_deref().unwrap_or("-"),
                    if dns.is_empty() { "-".to_string() } else { dns.join(",") }
                );
            }
            f.ajouter(&t);
        }
        None => f.ajouter(illisible),
    }
    if let Some(p) = config_reseau::principal() {
        f.section("Lu par Vanguard à configd : connexion principale / Read by Vanguard from configd: main connection");
        f.ajouter(&format!(
            "carte/interface : {}\npasserelle/gateway : {}\nservice : {}",
            p.carte.as_deref().unwrap_or("-"),
            p.passerelle.map_or_else(|| "-".to_string(), |g| g.to_string()),
            p.service.as_deref().unwrap_or("-")
        ));
    }
}

/// Les agents et démons de launchd d'un dossier : la liste, puis chaque .plist lu par Vanguard (crate::plist, binaire
/// ou XML) et par plutil -p à côté. Un fichier que le lecteur refuse pour ses bornes (fabriqué pour gêner l'analyse)
/// n'est pas confié à plutil, qui en développerait les références sans limite.
fn plists(f: &mut Feuille, dossier: &Path) {
    f.dossier(dossier, 0, false);
    let mut fichiers: Vec<PathBuf> = std::fs::read_dir(dossier)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|c| c.extension().is_some_and(|e| e == "plist"))
        .collect();
    fichiers.sort();
    for c in fichiers.iter().take(200) {
        f.section(&format!("Lu par Vanguard / Read by Vanguard : {}", c.display()));
        match crate::plist::lire_fichier(c) {
            Ok(crate::plist::Lu::Plist(v)) => f.ajouter(&crate::plist::afficher(&v)),
            Ok(crate::plist::Lu::Hostile | crate::plist::Lu::TropGros) => {
                f.ajouter("(refusé : hors des bornes, fabriqué pour gêner l'analyse / refused: out of bounds, crafted to hinder analysis)");
                continue;
            }
            Ok(crate::plist::Lu::Inconnu) => f.ajouter("(format inconnu / unknown format)"),
            Err(e) => f.ajouter(&format!("({e})")),
        }
        f.commande(Command::new("plutil").arg("-p").arg(c), 10, false);
    }
}

pub(super) fn demarrage(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Ce qui se lance tout seul", "What starts by itself"));
    let mut f = Feuille::new(&p.titre);
    let m = maison();
    // launchctl fait foi (outil gardé, §4) : la liste de ce qui est chargé dans launchd n'a pas d'interface publique.
    f.commande(Command::new("launchctl").arg("list"), 20, true);
    plists(&mut f, &m.join("Library/LaunchAgents"));
    plists(&mut f, Path::new("/Library/LaunchAgents"));
    plists(&mut f, Path::new("/Library/LaunchDaemons"));
    f.dossier(Path::new("/Library/StartupItems"), 0, false);
    // Les éléments d'ouverture et de fond (applications, agents) : leur base ne se lit qu'en root.
    if super::privilegie() {
        f.commande(Command::new("sfltool").arg("dumpbtm"), 30, false);
    } else {
        f.section("$ sfltool dumpbtm");
        f.ajouter(&Raison::Droits.note());
        f.manques.push(Manque {
            quoi: Bi::new(
                "Éléments d'ouverture et de fond (sfltool dumpbtm)",
                "Login and background items (sfltool dumpbtm)",
            ),
            raison: Raison::Droits,
        });
    }
    f.commande(Command::new("profiles").arg("list"), 20, false);
    f.commande(Command::new("kmutil").args(["showloaded", "--list-only"]), 30, false);
    cron(&mut f);
    shell_et_ssh(&mut f);
    p.manques.append(&mut f.manques);
    p.evenements = chronologie::lancements(&f.dates);
    if p.ecrire(
        dossier,
        "03-demarrage.txt",
        &f.texte,
        Bi::new(
            "ce qui se lance tout seul, tel quel : launchctl list, agents et démons de launchd (chaque .plist lu par Vanguard et par plutil -p), éléments d'ouverture (sfltool, en root), profils de configuration, extensions du noyau chargées, tâches cron, fichiers du shell, clés SSH autorisées",
            "what starts by itself, as is: launchctl list, launchd agents and daemons (each .plist read by Vanguard and through plutil -p), login items (sfltool, as root), configuration profiles, loaded kernel extensions, cron jobs, shell files, authorized SSH keys",
        ),
    ) {
        p.compte = Some(bi!("{} source(s) lue(s)", "{} source(s) read", f.lues));
    }
    p
}

pub(super) fn comptes(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Comptes", "Accounts"));
    let mut f = Feuille::new(&p.titre);
    let liste = f.commande(
        Command::new("dscl").args([".", "-list", "/Users", "UniqueID"]),
        15,
        true,
    );
    f.commande(
        Command::new("dscl").args([".", "-read", "/Groups/admin", "GroupMembership"]),
        15,
        true,
    );
    f.commande(&mut Command::new("who"), 10, false);
    comptes_natifs(&mut f);
    // Les dates en anglais, quelle que soit la langue de l'ordinateur : la chronologie les relit.
    let last = f.commande(Command::new("last").args(["-100"]).env("LC_ALL", "C"), 20, true);
    p.manques.append(&mut f.manques);
    p.evenements = chronologie::lire_last(
        &last.unwrap_or_default(),
        chrono::Local::now().naive_local(),
        &chrono::Local,
    );
    if p.ecrire(
        dossier,
        "04-comptes.txt",
        &f.texte,
        Bi::new(
            "comptes (dscl), administrateurs (groupe admin), sessions ouvertes (who), puis comptes et sessions lus par Vanguard à comparer, dernières connexions (last)",
            "accounts (dscl), administrators (admin group), open sessions (who), then accounts and sessions read by Vanguard to compare, last logins (last)",
        ),
    ) {
        p.compte = Some(match liste {
            Some(l) => bi!("{} comptes", "{} accounts", l.lines().count()),
            None => bi!("{} source(s) lue(s)", "{} source(s) read", f.lues),
        });
    }
    p
}

/// Les comptes (getpwent) et les sessions ouvertes (getutxent) lus par Vanguard, à côté de dscl et who.
fn comptes_natifs(f: &mut Feuille) {
    f.section("Lu par Vanguard : comptes (getpwent) / Read by Vanguard: accounts (getpwent)");
    let comptes = crate::machine::macos::noyau::comptes();
    let mut t = String::new();
    for (nom, uid) in &comptes {
        let _ = writeln!(t, "{nom}\t{uid}");
    }
    f.ajouter(if t.is_empty() { "(illisible / unreadable)" } else { &t });
    f.section("Lu par Vanguard : sessions ouvertes (getutxent) / Read by Vanguard: open sessions (getutxent)");
    let mut t = String::new();
    for s in crate::machine::macos::noyau::sessions_ouvertes() {
        let _ = writeln!(t, "{}\t{}\t{}\t{}", s.compte, s.ligne, s.depuis, s.hote);
    }
    f.ajouter(if t.is_empty() { "(aucune / none)" } else { &t });
}

/// Le journal unifié du dernier jour (log show est lent : deux minutes au plus, et seule la fin, la plus récente, est
/// gardée dans la borne), puis la fin du journal des installations.
pub(super) fn journaux(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Journaux", "Logs"));
    let titre = Bi::new("Journal unifié, 1 jour", "Unified log, 1 day");
    let nom = "05-log-show.txt";
    let mut commande = Command::new("log");
    commande.args(["show", "--last", "1d", "--style", "syslog"]);
    let jour = Bi::new("1 jour", "1 day");
    match journal_vers(dossier, nom, &titre, &mut commande, 120, Garder::Fin, Some(&jour)) {
        Err(e) => p.manque(titre.clone(), Raison::Erreur(e.to_string())),
        Ok(None) => p.manque(titre.clone(), Raison::Absente("log".into())),
        Ok(Some(e)) => {
            p.fichiers.push(super::Produit {
                nom: nom.into(),
                contenu: Bi::new(
                    "le journal unifié de macOS (log show) du dernier jour, la fin la plus récente, 50 Mo au plus",
                    "macOS's unified log (log show) of the last day, the most recent end, 50 MB at most",
                ),
            });
            if e.tronque {
                p.manque(
                    Bi::new("Journal unifié, le plus ancien", "Unified log, the oldest part"),
                    Raison::Borne(super::BORNE_JOURNAL),
                );
            }
            if e.delai {
                p.manque(
                    Bi::new("Journal unifié, la suite", "Unified log, the rest"),
                    Raison::Delai(120),
                );
            }
            if let Some(code) = e.code.filter(|c| *c != 0) {
                let premiere = e.erreurs.lines().next().unwrap_or_default().to_string();
                p.manque(titre.clone(), Raison::Erreur(format!("code {code} : {premiere}")));
            }
            let m = mo(e.octets);
            p.compte = Some(Bi::new(format!("{} (1 jour)", m.fr), format!("{} (1 day)", m.en)));
        }
    }
    journaux_classiques(&mut p, dossier, &["/var/log/install.log"]);
    p
}

/// Les événements des journaux pour la chronologie : repris dans le journal unifié et le journal des installations
/// que la collecte vient d'écrire (log show n'a pas de filtre aussi simple que journalctl, et il est lent).
pub(super) fn evenements_des_journaux(dossier: &Path) -> super::chronologie::Apport {
    super::unix::journaux_ecrits(dossier, None, true, None)
}

/// Les dossiers temporaires et le dossier partagé, où un programme dépose ce qu'il lance.
pub(super) fn endroits_temporaires() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::env::var_os("TMPDIR").map(PathBuf::from).into_iter().collect();
    v.extend(
        ["/private/tmp", "/private/var/tmp", "/Users/Shared"]
            .iter()
            .map(PathBuf::from),
    );
    v
}

/// Pas de liste des montages ici : le parcours s'arrête aux dossiers d'un autre appareil que leur racine.
pub(super) fn points_de_montage() -> Vec<PathBuf> {
    Vec::new()
}

/// La place que peuvent prendre les journaux : le journal unifié borné et la fin du journal des installations.
pub(super) fn place_des_journaux() -> u64 {
    super::BORNE_JOURNAL + (10 << 20)
}
