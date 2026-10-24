//! Diagnostic de l'ordinateur, le premier réflexe d'un dépannage : matériel, système, et surtout les problèmes
//! récents (erreurs du journal et programmes plantés sous Linux ; écrans bleus, arrêts brutaux et programmes plantés
//! sous Windows). Lecture seule. Une copie texte est enregistrée pour l'envoyer ou la garder.

use std::fmt::Write;

use crate::risk::Niveau;
use crate::ui::*;

/// Une ligne du diagnostic : libellé, valeur, et un niveau quand la ligne signale un problème.
struct Ligne {
    libelle: String,
    valeur: String,
    niveau: Option<Niveau>,
}

fn ligne(libelle: &str, valeur: impl Into<String>) -> Ligne {
    Ligne {
        libelle: libelle.to_string(),
        valeur: valeur.into(),
        niveau: None,
    }
}

fn alerte(libelle: &str, valeur: impl Into<String>, niveau: Niveau) -> Ligne {
    Ligne {
        libelle: libelle.to_string(),
        valeur: valeur.into(),
        niveau: Some(niveau),
    }
}

type Section = (String, Vec<Ligne>);

fn duree(secondes: u64) -> String {
    let (j, h, m) = (secondes / 86_400, secondes % 86_400 / 3600, secondes % 3600 / 60);
    match j {
        0 => format!("{h} h {m:02}"),
        _ => trf!("{j} j {h} h", "{j} d {h} h"),
    }
}

fn go(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let g = octets as f64 / f64::from(1u32 << 30);
    if g >= 1000.0 {
        trf!("{} To", "{} TB", crate::langue::decimal(g / 1024.0, 1))
    } else {
        trf!("{} Go", "{} GB", crate::langue::decimal(g, 1))
    }
}

/// Sources qui reviennent le plus dans une liste : « NetworkManager (12), kernel (5) ».
fn plus_frequentes(sources: &[String], max: usize) -> String {
    let mut comptes: Vec<(String, usize)> = Vec::new();
    for s in sources {
        match comptes.iter_mut().find(|(n, _)| n == s) {
            Some((_, c)) => *c += 1,
            None => comptes.push((s.clone(), 1)),
        }
    }
    comptes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    comptes
        .iter()
        .take(max)
        .map(|(n, c)| format!("{n} ({c})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// La ligne des programmes plantés en 7 jours, la même sur les trois systèmes.
fn programmes_plantes(plantages: &[String]) -> Ligne {
    if plantages.is_empty() {
        ligne(
            tr!("Programmes plantés", "Crashed programs"),
            tr!("aucun en 7 jours", "none in 7 days"),
        )
    } else {
        alerte(
            tr!("Programmes plantés", "Crashed programs"),
            trf!(
                "{} en 7 jours : {}",
                "{} in 7 days: {}",
                plantages.len(),
                plus_frequentes(plantages, 5)
            ),
            Niveau::Moyen,
        )
    }
}

/// Les trois sections du diagnostic, dans leur ordre.
fn trois_sections(systeme: Vec<Ligne>, materiel: Vec<Ligne>, problemes: Vec<Ligne>) -> Vec<Section> {
    vec![
        (tr!("SYSTÈME", "SYSTEM").into(), systeme),
        (tr!("MATÉRIEL", "HARDWARE").into(), materiel),
        (tr!("PROBLÈMES RÉCENTS", "RECENT PROBLEMS").into(), problemes),
    ]
}

#[cfg(target_os = "linux")]
mod systeme {
    use super::{Ligne, Niveau, Section, alerte, duree, go, ligne, plus_frequentes};
    use crate::ui::affichable;
    use crate::{tr, trf};

    fn lire(chemin: &str) -> Option<String> {
        std::fs::read_to_string(chemin)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    }

    fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
        let r = crate::commande::lancer(std::process::Command::new(cmd).args(args), 20)?;
        (r.code == Some(0)).then_some(r.sortie)
    }

    fn valeur_meminfo(texte: &str, cle: &str) -> Option<u64> {
        texte
            .lines()
            .find(|l| l.starts_with(cle))?
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
            .map(|ko| ko * 1024)
    }

    /// Version du pilote dans /proc/driver/nvidia/version (« … Kernel Module for x86_64  610.57.04  Release … »).
    pub(super) fn version_nvidia(texte: &str) -> Option<String> {
        texte
            .split_whitespace()
            .find(|m| m.contains('.') && m.chars().all(|c| c.is_ascii_digit() || c == '.'))
            .map(str::to_string)
    }

    /// Le journal du système se lit-il ? Sans être root ni dans les groupes adm, systemd-journal ou wheel,
    /// journalctl ne montre que les messages de la session, sans le dire (-q) : « aucune erreur » serait faux.
    fn journal_systeme_lisible() -> bool {
        ["/var/log/journal", "/run/log/journal"].iter().any(|d| {
            std::fs::read_dir(d)
                .into_iter()
                .flatten()
                .flatten()
                .any(|e| std::fs::File::open(e.path().join("system.journal")).is_ok())
        })
    }

    /// Le programme de chaque erreur du démarrage en cours : lu dans les fichiers du journal, journalctl en secours
    /// (format ou droits que la lecture native ne prend pas). `None` : le journal du système ne se lit pas.
    fn sources_des_erreurs() -> Option<Vec<String>> {
        if let Some(entrees) = crate::machine::linux::journal_systemd::erreurs_du_demarrage() {
            return Some(entrees.iter().filter_map(source_entree).collect());
        }
        let j = journal_systeme_lisible()
            .then(|| sortie("journalctl", &["-b", "-p", "err", "-q", "--no-pager", "-o", "short"]))
            .flatten()?;
        Some(j.lines().filter_map(source_journal).collect())
    }

    /// Le nom qu'affiche journalctl pour une entrée : celui que le programme s'est donné (SYSLOG_IDENTIFIER), sinon
    /// celui du processus ; lu prêt à montrer, comme `source_journal`.
    pub(super) fn source_entree(e: &crate::machine::linux::journal_systemd::Entree) -> Option<String> {
        let nom = e.champ("SYSLOG_IDENTIFIER").or_else(|| e.champ("_COMM"))?;
        Some(affichable(nom.trim())).filter(|s| !s.is_empty())
    }

    /// Source d'une ligne du journal (« Oct 17 15:29:32 portable NetworkManager[1334]: … » → « NetworkManager »). Une
    /// ligne en retrait continue l'entrée d'avant (la pile d'un programme planté) : elle n'en est pas une autre. Tout
    /// programme choisit le nom sous lequel il écrit au journal : lu prêt à montrer.
    pub(super) fn source_journal(l: &str) -> Option<String> {
        if l.starts_with(char::is_whitespace) {
            return None;
        }
        let apres_hote = l.splitn(5, ' ').nth(4)?;
        let source = apres_hote.split(':').next()?;
        Some(affichable(source.split('[').next()?.trim())).filter(|s| !s.is_empty())
    }

    /// Le nom d'une carte graphique comme le donnait `lspci -mm` : le fabricant, puis la puce. Les deux viennent de
    /// pci.ids, sinon des numéros : lus prêts à montrer, comme tout ce que ce diagnostic lit du système.
    pub(super) fn nom_de_carte(carte: &crate::fiche::CartePci) -> String {
        affichable(format!("{} {}", carte.fabricant, carte.puce).trim())
    }

    /// « nvme0n1 · 1,8 To · SSD · WD Essai » : le modèle vient du disque lui-même (une clé USB dit ce qu'elle veut),
    /// lu prêt à montrer.
    pub(super) fn ligne_de_disque(d: &crate::machine::linux::natif::Disque) -> String {
        // Une clé USB se déclare souvent « rotative » : le transport dit la vérité.
        let sorte = match (d.bus.as_str(), d.rotatif) {
            ("usb", _) => tr!("clé ou disque USB", "USB stick or drive"),
            (_, true) => tr!("disque dur", "hard drive"),
            _ => "SSD",
        };
        format!(
            "{} · {} · {sorte} · {}",
            affichable(&d.nom),
            go(d.octets),
            affichable(&d.modele)
        )
    }

    /// Programmes plantés d'après `coredumpctl list` : le nom du programme, à la fin du chemin de la colonne EXE. Ce
    /// chemin peut contenir des espaces (« …/common/Hollow Knight/hollow_knight ») : il va du premier mot qui
    /// commence par « / » jusqu'à la colonne SIZE, la dernière quand l'en-tête l'annonce (systemd 248 et plus).
    pub(super) fn programmes_coredumpctl(texte: &str) -> Vec<String> {
        let taille_en_fin = texte
            .lines()
            .find(|l| l.split_whitespace().next() == Some("TIME"))
            .is_some_and(|entete| entete.split_whitespace().any(|c| c == "SIZE"));
        texte
            .lines()
            .filter_map(|l| {
                let exe = l[l.find(" /")? + 1..].trim_end();
                let exe = match exe.rsplit_once(char::is_whitespace) {
                    Some((chemin, _)) if taille_en_fin => chemin.trim_end(),
                    _ => exe,
                };
                Some(affichable(exe.rsplit('/').next().unwrap_or(exe)))
            })
            .collect()
    }

    /// Les plantages d'après `coredumpctl list` : (programme, numéro du processus). Le numéro suit l'heure et
    /// le fuseau (« Tue 2026-10-20 21:11:28 EDT 9543 … »). Sans numéro lisible, le plantage compte quand même.
    pub(super) fn plantages_coredumpctl(texte: &str) -> Vec<(String, Option<u32>)> {
        let noms = programmes_coredumpctl(texte);
        let pids = texte.lines().filter(|l| l.contains(" /")).map(|l| {
            // Après l'heure vient le fuseau, en un mot, puis le numéro.
            let mut mots = l.split_whitespace().skip_while(|m| m.matches(':').count() != 2).skip(2);
            mots.next().and_then(|m| m.parse().ok())
        });
        noms.into_iter().zip(pids).collect()
    }

    /// Où systemd-coredump range les vidages de mémoire des programmes plantés.
    const VIDAGES: &str = "/var/lib/systemd/coredump";

    /// Les vidages gardés sur le disque depuis `depuis` (microsecondes depuis 1970) : (programme, numéro du
    /// processus), du plus ancien au plus récent. Ce n'est qu'une borne basse : le dossier existe toujours (tmpfiles
    /// le crée), même quand coredump.conf dit Storage=journal ou none, et systemd-coredump n'y garde ni un vidage
    /// trop gros (ExternalSizeMax) ni ceux qu'il efface pour la place (MaxUse, KeepFree). Le programme est la fin
    /// du chemin de l'attribut « user.coredump.exe » que `exe` lit, comme la colonne EXE de coredumpctl : le nom
    /// du fichier ne porte que le nom court du fil qui a planté (15 octets, « gnome-keyring-d », « Isolated Web
    /// Co »). `None` si le dossier ne se lit pas ou si un vidage de la semaine n'a pas cet attribut.
    pub(super) fn plantages_coredump(
        dossier: &std::path::Path,
        depuis: u64,
        exe: impl Fn(&std::path::Path) -> Option<Vec<u8>>,
    ) -> Option<Vec<(String, u32)>> {
        let mut plantages: Vec<(u64, std::path::PathBuf, u32)> = std::fs::read_dir(dossier)
            .ok()?
            .flatten()
            .filter_map(|e| {
                let (quand, pid) = vidage(&e.file_name().to_string_lossy())?;
                Some((quand, e.path(), pid))
            })
            .filter(|(quand, ..)| *quand >= depuis)
            .collect();
        // Du plus ancien au plus récent, comme coredumpctl.
        plantages.sort();
        plantages
            .into_iter()
            .map(|(_, chemin, pid)| {
                let chemin_exe = String::from_utf8_lossy(&exe(&chemin)?).into_owned();
                let nom = chemin_exe.rsplit('/').next().unwrap_or_default();
                (!nom.is_empty()).then(|| (affichable(nom), pid))
            })
            .collect()
    }

    /// L'attribut étendu « user.coredump.exe » qu'écrit systemd-coredump sur chaque vidage (avec .comm, .pid…) :
    /// le chemin du programme. Lisible par qui peut lire le fichier.
    pub(super) fn attribut_exe(chemin: &std::path::Path) -> Option<Vec<u8>> {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(chemin.as_os_str().as_bytes()).ok()?;
        let mut tampon = vec![0u8; 4096];
        // SAFETY: c et le nom sont des chaînes C terminées par un octet nul ; le tampon est à nous, de la taille
        // annoncée.
        let n = unsafe {
            libc::getxattr(
                c.as_ptr(),
                c"user.coredump.exe".as_ptr(),
                tampon.as_mut_ptr().cast(),
                tampon.len(),
            )
        };
        tampon.truncate(usize::try_from(n).ok()?);
        Some(tampon)
    }

    /// Le nom d'un vidage : « core.<programme>.<compte>.<démarrage>.<processus>.<µs depuis 1970> », puis la
    /// compression (« .zst », « .xz », « .lz4 ») ou rien. systemd y écrit les points, barres obliques et espaces du
    /// nom en « \x2e », « \x2f », « \x20 ». Ce nom est celui du fil qui a planté, coupé à 15 octets : on n'en
    /// garde que l'heure et le numéro du processus (le programme vient de l'attribut « user.coredump.exe »).
    /// Un fichier en cours d'écriture (« .#core… ») ou étranger n'a pas cette forme et ne compte pas.
    pub(super) fn vidage(nom: &str) -> Option<(u64, u32)> {
        let champs: Vec<&str> = nom.strip_prefix("core.")?.split('.').collect();
        let [programme, compte, demarrage, pid, quand, ..] = champs[..] else {
            return None;
        };
        let chiffres = |t: &str| !t.is_empty() && t.bytes().all(|o| o.is_ascii_digit());
        if !chiffres(compte) || demarrage.len() != 32 || !demarrage.bytes().all(|o| o.is_ascii_hexdigit()) {
            return None;
        }
        if programme.is_empty() {
            return None;
        }
        Some((quand.parse().ok()?, pid.parse().ok()?))
    }

    /// Les plantages de la semaine, des deux sources réunies. Le journal, que coredumpctl lit, voit les
    /// plantages sans vidage gardé ; le dossier garde ceux dont le journal a déjà perdu la trace. Un plantage
    /// des deux côtés (même numéro de processus) ne compte qu'une fois. Sans le journal, le dossier seul ne
    /// prouve que ce qu'il contient : vide, il ne dit pas « aucun » (`None` : non vérifié).
    pub(super) fn plantages_reunis(
        dossier: Option<Vec<(String, u32)>>,
        journal: Option<Vec<(String, Option<u32>)>>,
    ) -> Option<Vec<String>> {
        let dossier = dossier.unwrap_or_default();
        let Some(journal) = journal else {
            return (!dossier.is_empty()).then(|| dossier.into_iter().map(|(nom, _)| nom).collect());
        };
        let vus: std::collections::HashSet<u32> = journal.iter().filter_map(|(_, pid)| *pid).collect();
        let mut tous: Vec<String> = journal.into_iter().map(|(nom, _)| nom).collect();
        tous.extend(
            dossier
                .into_iter()
                .filter(|(_, pid)| !vus.contains(pid))
                .map(|(nom, _)| nom),
        );
        Some(tous)
    }

    /// La liste de coredumpctl, ou `None` s'il est absent ou en échec. Sans aucun plantage, il sort en code 1
    /// sans rien écrire (avec -q) : c'est une réponse, « aucun » ; une vraie erreur écrit sur la sortie d'erreur.
    fn journal_coredumpctl() -> Option<String> {
        let r = crate::commande::lancer(
            std::process::Command::new("coredumpctl").args(["list", "--no-pager", "-q", "--since=-7d"]),
            20,
        )?;
        let vide = r.code == Some(1) && r.sortie.trim().is_empty() && r.erreurs.trim().is_empty();
        (r.code == Some(0) || vide).then_some(r.sortie)
    }

    /// Les programmes plantés en 7 jours ; `None` si rien ne permet de le savoir.
    fn plantages_de_la_semaine() -> Option<Vec<String>> {
        let maintenant = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        let depuis = maintenant.saturating_sub(7 * 86_400 * 1_000_000);
        plantages_reunis(
            plantages_coredump(std::path::Path::new(VIDAGES), depuis, attribut_exe),
            journal_coredumpctl().map(|t| plantages_coredumpctl(&t)),
        )
    }

    /// Les unités en échec, demandées à systemd par le bus système (ce que dit `systemctl --failed`). Un bus qui ne
    /// répond pas laisse la ligne « non vérifié », pas « aucun ».
    fn services_en_echec() -> Ligne {
        use crate::machine::linux::dbus;
        let libelle = tr!("Services en échec", "Failed services");
        match dbus::Bus::systeme().and_then(|mut bus| dbus::unites_en_echec(&mut bus)) {
            Ok(en_echec) if en_echec.is_empty() => ligne(libelle, tr!("aucun", "none")),
            Ok(en_echec) => alerte(
                libelle,
                en_echec.iter().map(|u| affichable(u)).collect::<Vec<_>>().join(", "),
                Niveau::Moyen,
            ),
            Err(e) => ligne(libelle, trf!("non vérifié ({e})", "not verified ({e})")),
        }
    }

    pub fn sections() -> Vec<Section> {
        let mut systeme = Vec::new();
        let os = affichable(&crate::socle::systeme::nom());
        // Une valeur d'une ligne lue dans /proc ou /sys, prête à montrer.
        let valeur = |chemin: &str| lire(chemin).map(|v| affichable(&v));
        systeme.push(ligne(
            tr!("Système", "System"),
            trf!(
                "{os} · noyau {}",
                "{os} · kernel {}",
                valeur("/proc/sys/kernel/osrelease").unwrap_or_default()
            ),
        ));
        systeme.push(ligne(
            tr!("Nom", "Name"),
            valeur("/proc/sys/kernel/hostname").unwrap_or_default(),
        ));
        let modele = [
            valeur("/sys/class/dmi/id/sys_vendor"),
            valeur("/sys/class/dmi/id/board_name"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
        if !modele.is_empty() {
            let bios = valeur("/sys/class/dmi/id/bios_version")
                .map(|b| format!(" · BIOS {b}"))
                .unwrap_or_default();
            systeme.push(ligne(tr!("Modèle", "Model"), format!("{modele}{bios}")));
        }
        if let Some(s) = lire("/proc/uptime").and_then(|t| t.split('.').next().and_then(|s| s.parse::<u64>().ok())) {
            systeme.push(ligne(tr!("Allumé depuis", "Up for"), duree(s)));
        }

        let mut materiel = Vec::new();
        let cpuinfo = lire("/proc/cpuinfo").unwrap_or_default();
        if let Some(cpu) = cpuinfo
            .lines()
            .find_map(|l| l.strip_prefix("model name"))
            .and_then(|l| l.split_once(':'))
        {
            let fils = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
            materiel.push(ligne(
                tr!("Processeur", "Processor"),
                trf!("{} ({fils} fils)", "{} ({fils} threads)", affichable(cpu.1.trim())),
            ));
        }
        let meminfo = lire("/proc/meminfo").unwrap_or_default();
        if let (Some(total), Some(dispo)) = (
            valeur_meminfo(&meminfo, "MemTotal:"),
            valeur_meminfo(&meminfo, "MemAvailable:"),
        ) {
            materiel.push(ligne(
                tr!("Mémoire", "Memory"),
                trf!("{} ({} libres)", "{} ({} free)", go(total), go(dispo)),
            ));
        }
        for nom in crate::fiche::cartes_graphiques().iter().map(nom_de_carte) {
            let pilote = lire("/proc/driver/nvidia/version")
                .filter(|_| nom.contains("NVIDIA"))
                .and_then(|v| version_nvidia(&v))
                .map(|v| trf!(" · pilote NVIDIA {v}", " · NVIDIA driver {v}"))
                .unwrap_or_default();
            materiel.push(ligne(tr!("Carte graphique", "Graphics card"), format!("{nom}{pilote}")));
        }
        for d in crate::machine::linux::natif::disques() {
            if !crate::fiche::disque_entier(&d) || d.nom.starts_with("zram") || d.nom.starts_with("loop") {
                continue;
            }
            materiel.push(ligne(tr!("Disque", "Disk"), ligne_de_disque(&d)));
        }

        let mut problemes: Vec<Ligne> = Vec::new();
        match sources_des_erreurs() {
            Some(sources) => {
                if sources.is_empty() {
                    problemes.push(ligne(
                        tr!("Erreurs du journal", "Journal errors"),
                        tr!("aucune depuis le démarrage", "none since boot"),
                    ));
                } else {
                    let niveau = if sources.len() > 200 {
                        Niveau::Moyen
                    } else {
                        Niveau::Info
                    };
                    problemes.push(alerte(
                        tr!("Erreurs du journal", "Journal errors"),
                        trf!(
                            "{} depuis le démarrage : {}",
                            "{} since boot: {}",
                            sources.len(),
                            plus_frequentes(&sources, 5)
                        ),
                        niveau,
                    ));
                }
            }
            None => problemes.push(ligne(
                tr!("Erreurs du journal", "Journal errors"),
                tr!("journal illisible sans droits", "journal unreadable without rights"),
            )),
        }
        problemes.push(match plantages_de_la_semaine() {
            Some(plantages) => super::programmes_plantes(&plantages),
            None => ligne(
                tr!("Programmes plantés", "Crashed programs"),
                tr!(
                    "non vérifié (journal des plantages illisible)",
                    "not verified (crash journal unreadable)"
                ),
            ),
        });
        problemes.push(services_en_echec());
        super::trois_sections(systeme, materiel, problemes)
    }
}

#[cfg(target_os = "macos")]
mod systeme {
    use super::{Niveau, Section, alerte, duree, go, ligne};
    use crate::ui::affichable;
    use crate::{tr, trf};

    fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
        let r = crate::commande::lancer(std::process::Command::new(cmd).args(args), 30)?;
        (r.code == Some(0)).then(|| r.sortie.trim().to_string())
    }

    /// Valeur d'une ligne « Clé: valeur » (system_profiler, diskutil info), espaces de tête ignorés, prête à montrer
    /// (un disque branché dit son nom lui-même), comme tout ce que ce diagnostic lit du système.
    pub(super) fn valeur(texte: &str, cle: &str) -> Option<String> {
        texte
            .lines()
            .find_map(|l| l.trim().strip_prefix(cle)?.trim().strip_prefix(':'))
            .map(|v| affichable(v.trim()))
            .filter(|v| !v.is_empty())
    }

    /// Rapports de plantage récents (moins de `jours`) : nom du programme avant la date (« Safari-2024-05-01-… »).
    fn rapports(dossiers: &[std::path::PathBuf], extensions: &[&str], jours: u64) -> Vec<String> {
        let limite = std::time::Duration::from_secs(jours * 86_400);
        dossiers
            .iter()
            .filter_map(|d| std::fs::read_dir(d).ok())
            .flatten()
            .flatten()
            .filter(|f| f.path().extension().is_some_and(|e| extensions.iter().any(|x| e == *x)))
            .filter(|f| {
                f.metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|m| m.elapsed().is_ok_and(|e| e < limite))
            })
            .map(|f| {
                let nom = f.file_name().to_string_lossy().into_owned();
                // Le nom s'arrête au premier « -2 » d'une date (« Google Chrome Helper-2024-… »).
                affichable(nom.split_once("-20").map_or(nom.as_str(), |(n, _)| n))
            })
            .collect()
    }

    pub fn sections() -> Vec<Section> {
        let mut systeme = Vec::new();
        // Une valeur d'une ligne, prête à montrer.
        let version_systeme = |cle: &str| crate::machine::macos::version_systeme(cle).map(|v| affichable(&v));
        let version = [version_systeme("ProductName"), version_systeme("ProductVersion")]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        let build = version_systeme("ProductBuildVersion").unwrap_or_default();
        systeme.push(ligne(
            tr!("Système", "System"),
            format!("{version} ({build}) · {}", crate::machine::macos::architecture()),
        ));
        systeme.push(ligne(
            tr!("Nom", "Name"),
            crate::machine::macos::nom_machine("ComputerName")
                .map(|n| affichable(&n))
                .unwrap_or_default(),
        ));
        let materiel_txt = sortie("system_profiler", &["SPHardwareDataType"]).unwrap_or_default();
        let modele = [
            valeur(&materiel_txt, "Model Name"),
            valeur(&materiel_txt, "Model Identifier"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
        if !modele.is_empty() {
            systeme.push(ligne(tr!("Modèle", "Model"), modele));
        }
        let maintenant = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if let Some(s) = crate::machine::macos::demarrage().and_then(|d| maintenant.checked_sub(d)) {
            systeme.push(ligne(tr!("Allumé depuis", "Up for"), duree(s)));
        }

        let mut materiel = Vec::new();
        if let Some(cpu) = crate::machine::macos::sysctl_texte("machdep.cpu.brand_string").map(|c| affichable(&c)) {
            let fils = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
            materiel.push(ligne(
                tr!("Processeur", "Processor"),
                trf!("{cpu} ({fils} cœurs)", "{cpu} ({fils} cores)"),
            ));
        }
        if let Some(total) = crate::machine::macos::sysctl_nombre("hw.memsize") {
            materiel.push(ligne(tr!("Mémoire", "Memory"), go(total)));
        }
        let ecrans = sortie("system_profiler", &["SPDisplaysDataType"]).unwrap_or_default();
        if let Some(puce) = valeur(&ecrans, "Chipset Model") {
            materiel.push(ligne(tr!("Carte graphique", "Graphics card"), puce));
        }
        for disque in sortie("diskutil", &["list", "internal", "physical"])
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.strip_prefix("/dev/")?.split_whitespace().next().map(str::to_string))
        {
            let info = sortie("diskutil", &["info", &disque]).unwrap_or_default();
            let taille = valeur(&info, "Disk Size")
                .map(|t| t.split(" (").next().unwrap_or(&t).to_string())
                .unwrap_or_default();
            let sorte = if valeur(&info, "Solid State").as_deref() == Some("Yes") {
                "SSD"
            } else {
                tr!("disque dur", "hard drive")
            };
            materiel.push(ligne(
                tr!("Disque", "Disk"),
                format!(
                    "{disque} · {taille} · {sorte} · {}",
                    valeur(&info, "Device / Media Name").unwrap_or_default()
                ),
            ));
        }

        let maison = crate::socle::maison();
        let dossiers = [
            maison.join("Library/Logs/DiagnosticReports"),
            std::path::PathBuf::from("/Library/Logs/DiagnosticReports"),
        ];
        let mut problemes = Vec::new();
        let paniques = rapports(&dossiers, &["panic"], 30);
        problemes.push(if paniques.is_empty() {
            ligne(
                tr!("Redémarrages brutaux", "Sudden restarts"),
                tr!("aucun en 30 jours", "none in 30 days"),
            )
        } else {
            alerte(
                tr!("Redémarrages brutaux", "Sudden restarts"),
                trf!(
                    "{} en 30 jours (panique du noyau : matériel, pilote ou extension)",
                    "{} in 30 days (kernel panic: hardware, driver or extension)",
                    paniques.len()
                ),
                Niveau::Moyen,
            )
        });
        let plantages = rapports(&dossiers, &["ips", "crash"], 7);
        problemes.push(super::programmes_plantes(&plantages));
        super::trois_sections(systeme, materiel, problemes)
    }
}

#[cfg(windows)]
mod systeme {
    use serde::Deserialize;

    use super::{Niveau, Section, alerte, duree, go, ligne};
    use crate::ui::affichable;
    use crate::{tr, trf};

    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Etat {
        systeme: String,
        version: String,
        nom: String,
        modele: String,
        bios: String,
        allume_s: u64,
        processeur: String,
        fils: u32,
        memoire: u64,
        memoire_libre: u64,
        cartes: Vec<Carte>,
        disques: Vec<Disque>,
        ecrans_bleus: u32,
        dernier_ecran_bleu: String,
        arrets_brutaux: u32,
        plantages: Vec<String>,
    }

    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Carte {
        nom: String,
        pilote: String,
    }

    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Disque {
        nom: String,
        taille: u64,
        sorte: String,
    }

    /// Ce que lisait le script, sans PowerShell : WMI pour le système et le matériel, les journaux par wevtapi.
    /// `None` sans Win32_OperatingSystem.
    fn lire_directement() -> Option<Etat> {
        use crate::machine::windows::evenements::{date_locale, parcourir};
        use crate::machine::windows::wmi::{self, Ligne};
        const CIMV2: &str = r"root\cimv2";
        let premiere = |classe: &str, champs: &[&str]| -> Option<Ligne> {
            wmi::requete(CIMV2, classe, "", champs).and_then(|l| l.into_iter().next())
        };
        let os = premiere(
            "Win32_OperatingSystem",
            &["Caption", "Version", "LastBootUpTime", "FreePhysicalMemory"],
        )?;
        let cs = premiere(
            "Win32_ComputerSystem",
            &["Manufacturer", "Model", "TotalPhysicalMemory"],
        );
        let cpu = premiere("Win32_Processor", &["Name", "NumberOfLogicalProcessors"]);
        let bios = premiere("Win32_BIOS", &["SMBIOSBIOSVersion"]);
        let texte = |l: Option<&Ligne>, c: &str| l.and_then(|l| l[c].texte()).unwrap_or_default().to_string();
        let nombre = |l: Option<&Ligne>, c: &str| {
            l.and_then(|l| l[c].entier())
                .map_or(0, |n| u64::try_from(n).unwrap_or(0))
        };
        let cartes = wmi::requete(CIMV2, "Win32_VideoController", "", &["Name", "DriverVersion"])
            .unwrap_or_default()
            .iter()
            .map(|c| Carte {
                nom: texte(Some(c), "Name"),
                pilote: texte(Some(c), "DriverVersion"),
            })
            .collect();
        let disques = wmi::requete(
            r"root\Microsoft\Windows\Storage",
            "MSFT_PhysicalDisk",
            "",
            &["FriendlyName", "Size", "MediaType"],
        )
        .unwrap_or_default()
        .iter()
        .map(|d| Disque {
            nom: texte(Some(d), "FriendlyName"),
            taille: nombre(Some(d), "Size"),
            // MediaType écrit comme Get-PhysicalDisk l'écrit.
            sorte: match d["MediaType"].entier() {
                Some(3) => "HDD",
                Some(4) => "SSD",
                Some(5) => "SCM",
                _ => "Unspecified",
            }
            .into(),
        })
        .collect();
        let fin = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let depuis = |jours: u64| format!("TimeCreated[timediff(@SystemTime) <= {}]", jours * 86_400_000);
        // Les événements d'un journal, du plus récent au plus ancien : la date locale et la première valeur.
        let evenements = |journal: &str, filtre: String| {
            parcourir(
                journal,
                &format!("*[System[{filtre}]]"),
                10_000,
                fin,
                |_, date, valeurs| {
                    Some(format!(
                        "{}|{}",
                        date_locale(date).unwrap_or_default(),
                        valeurs.first().map(String::as_str).unwrap_or_default()
                    ))
                },
            )
            .unwrap_or_default()
        };
        let bleus = evenements(
            "System",
            format!(
                "Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and (EventID=1001) and {}",
                depuis(30)
            ),
        );
        let arrets = evenements("System", format!("(EventID=41) and {}", depuis(30)));
        let plantages = evenements("Application", format!("(EventID=1000) and {}", depuis(7)));
        let os = Some(&os);
        Some(Etat {
            systeme: texte(os, "Caption"),
            version: texte(os, "Version"),
            nom: std::env::var("COMPUTERNAME").unwrap_or_default(),
            modele: format!("{} {}", texte(cs.as_ref(), "Manufacturer"), texte(cs.as_ref(), "Model")),
            bios: texte(bios.as_ref(), "SMBIOSBIOSVersion"),
            allume_s: os
                .and_then(|o| o["LastBootUpTime"].texte())
                .and_then(|d| wmi::secondes_depuis(d, chrono::Utc::now()))
                .unwrap_or(0),
            processeur: texte(cpu.as_ref(), "Name").trim().to_string(),
            fils: u32::try_from(nombre(cpu.as_ref(), "NumberOfLogicalProcessors")).unwrap_or(0),
            memoire: nombre(cs.as_ref(), "TotalPhysicalMemory"),
            memoire_libre: nombre(os, "FreePhysicalMemory") * 1024,
            cartes,
            disques,
            ecrans_bleus: u32::try_from(bleus.len()).unwrap_or(u32::MAX),
            dernier_ecran_bleu: bleus.first().and_then(|l| l.get(..10)).unwrap_or_default().to_string(),
            arrets_brutaux: u32::try_from(arrets.len()).unwrap_or(u32::MAX),
            plantages: plantages
                .iter()
                .map(|l| l.split_once('|').map_or("", |(_, p)| p).to_string())
                .collect(),
        })
    }

    /// Une seule lecture, directe (WMI, journaux) ou par PowerShell en secours : matériel, système, puis les
    /// événements des 30 derniers jours (1001 = écran bleu, 41 = arrêt brutal) et les programmes plantés des
    /// 7 derniers jours (événement 1000).
    fn lire() -> Option<Etat> {
        let mut e = match lire_directement() {
            Some(e) => e,
            None => lire_powershell()?,
        };
        // Chaque texte prêt à montrer : un programme planté porte le nom de son choix, un disque branché aussi.
        for t in [
            &mut e.systeme,
            &mut e.version,
            &mut e.nom,
            &mut e.modele,
            &mut e.bios,
            &mut e.processeur,
            &mut e.dernier_ecran_bleu,
        ] {
            *t = affichable(t);
        }
        for c in &mut e.cartes {
            (c.nom, c.pilote) = (affichable(&c.nom), affichable(&c.pilote));
        }
        for d in &mut e.disques {
            d.nom = affichable(&d.nom);
        }
        for p in &mut e.plantages {
            *p = affichable(p);
        }
        Some(e)
    }

    /// Le WMI de Wine connaît le système et le processeur : la lecture directe répond, sans PowerShell.
    #[cfg(test)]
    #[test]
    fn diagnostic_direct() {
        let e = lire_directement().expect("Win32_OperatingSystem répond");
        assert!(!e.systeme.is_empty() && e.fils >= 1, "{} {}", e.systeme, e.fils);
        assert!(e.dernier_ecran_bleu.is_empty() || e.dernier_ecran_bleu.len() == 10);
    }

    fn lire_powershell() -> Option<Etat> {
        let json = crate::machine::windows::ps(
            r#"$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
               $cpu = @(Get-CimInstance Win32_Processor)[0]; $mois = (Get-Date).AddDays(-30); $semaine = (Get-Date).AddDays(-7)
               $bleus = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; StartTime = $mois } -ErrorAction SilentlyContinue)
               [pscustomobject]@{
                 systeme = $os.Caption; version = "$($os.Version)"; nom = $env:COMPUTERNAME
                 modele = "$($cs.Manufacturer) $($cs.Model)"; bios = "$((Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion)"
                 allume_s = [uint64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
                 processeur = "$($cpu.Name)".Trim(); fils = [uint32]$cpu.NumberOfLogicalProcessors
                 memoire = [uint64]$cs.TotalPhysicalMemory; memoire_libre = [uint64]$os.FreePhysicalMemory * 1024
                 cartes = @(Get-CimInstance Win32_VideoController | ForEach-Object { @{ nom = "$($_.Name)"; pilote = "$($_.DriverVersion)" } })
                 disques = @(try { Get-PhysicalDisk | ForEach-Object { @{ nom = "$($_.FriendlyName)"; taille = [uint64]$_.Size; sorte = "$($_.MediaType)" } } } catch { })
                 ecrans_bleus = $bleus.Count
                 dernier_ecran_bleu = if ($bleus.Count) { $bleus[0].TimeCreated.ToString('yyyy-MM-dd') } else { '' }
                 arrets_brutaux = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41; StartTime = $mois } -ErrorAction SilentlyContinue).Count
                 plantages = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000; StartTime = $semaine } -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Properties[0].Value)" })
               } | ConvertTo-Json -Compress -Depth 3"#,
        )?;
        serde_json::from_str(&json).ok()
    }

    pub fn sections() -> Vec<Section> {
        let Some(e) = lire() else {
            return vec![(
                tr!("DIAGNOSTIC", "DIAGNOSTIC").into(),
                vec![ligne(
                    tr!("Lecture", "Reading"),
                    tr!("PowerShell ne répond pas", "PowerShell is not responding"),
                )],
            )];
        };
        let systeme = vec![
            ligne(tr!("Système", "System"), format!("{} · {}", e.systeme, e.version)),
            ligne(tr!("Nom", "Name"), e.nom),
            ligne(tr!("Modèle", "Model"), format!("{} · BIOS {}", e.modele.trim(), e.bios)),
            ligne(tr!("Allumé depuis", "Up for"), duree(e.allume_s)),
        ];
        let mut materiel = vec![
            ligne(
                tr!("Processeur", "Processor"),
                trf!("{} ({} fils)", "{} ({} threads)", e.processeur, e.fils),
            ),
            ligne(
                tr!("Mémoire", "Memory"),
                trf!("{} ({} libres)", "{} ({} free)", go(e.memoire), go(e.memoire_libre)),
            ),
        ];
        materiel.extend(e.cartes.iter().map(|c| {
            ligne(
                tr!("Carte graphique", "Graphics card"),
                trf!("{} · pilote {}", "{} · driver {}", c.nom, c.pilote),
            )
        }));
        materiel.extend(e.disques.iter().map(|d| {
            let sorte = match d.sorte.as_str() {
                "HDD" => tr!("disque dur", "hard drive"),
                "SSD" => "SSD",
                _ => tr!("type inconnu", "unknown type"),
            };
            ligne(tr!("Disque", "Disk"), format!("{} · {} · {sorte}", d.nom, go(d.taille)))
        }));
        let mut problemes = vec![if e.ecrans_bleus == 0 {
            ligne(
                tr!("Écrans bleus", "Blue screens"),
                tr!("aucun en 30 jours", "none in 30 days"),
            )
        } else {
            alerte(
                tr!("Écrans bleus", "Blue screens"),
                trf!(
                    "{} en 30 jours, le dernier le {}",
                    "{} in 30 days, the last one on {}",
                    e.ecrans_bleus,
                    e.dernier_ecran_bleu
                ),
                Niveau::Eleve,
            )
        }];
        problemes.push(if e.arrets_brutaux == 0 {
            ligne(
                tr!("Arrêts brutaux", "Unexpected shutdowns"),
                tr!("aucun en 30 jours", "none in 30 days"),
            )
        } else {
            alerte(
                tr!("Arrêts brutaux", "Unexpected shutdowns"),
                trf!(
                    "{} en 30 jours (coupure, gel ou bouton maintenu)",
                    "{} in 30 days (power cut, freeze or held button)",
                    e.arrets_brutaux
                ),
                Niveau::Moyen,
            )
        });
        problemes.push(super::programmes_plantes(&e.plantages));
        super::trois_sections(systeme, materiel, problemes)
    }
}

/// Texte simple du diagnostic (sans couleur), pour le fichier enregistré.
fn en_texte(sections: &[Section]) -> String {
    let mut t = String::new();
    let date = chrono::Local::now().format("%Y-%m-%d %H:%M");
    let _ = writeln!(
        t,
        "{} — Vanguard {} — {date}\n",
        tr!("Diagnostic de l'ordinateur", "Computer diagnostic"),
        env!("CARGO_PKG_VERSION")
    );
    for (nom, lignes) in sections {
        let _ = writeln!(t, "{nom}");
        for l in lignes {
            let marque = l.niveau.map_or("  ", |_| "! ");
            let _ = writeln!(t, "{marque}{:<22} {}", l.libelle, l.valeur);
        }
        t.push('\n');
    }
    t
}

/// Une ligne du diagnostic à l'écran : marque, libellé sur 22 colonnes, puis la valeur coupée pour tenir dans
/// `LARGEUR`, la suite alignée sous elle. Sans cela, une longue valeur (carte graphique et son pilote, modèle, sources
/// des erreurs) était coupée par le terminal au milieu d'un mot et reprise au bord gauche.
fn a_l_ecran(l: &Ligne) -> Vec<String> {
    // « ● », le libellé et leurs espaces : la valeur commence à la 28e colonne.
    const RETRAIT: usize = 27;
    let (marque, couleur_valeur) = match l.niveau {
        Some(n) => (format!("{}●{RESET}", couleur(n)), couleur(n)),
        None => (format!("{VERT}●{RESET}"), ""),
    };
    let debut = format!("  {marque} {GRAS}{}{RESET} ", ajuster(&l.libelle, 22));
    let mut morceaux = envelopper(&l.valeur, LARGEUR - RETRAIT);
    if morceaux.is_empty() {
        morceaux.push(String::new());
    }
    morceaux
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let avant = if i == 0 { debut.clone() } else { " ".repeat(RETRAIT) };
            format!("{avant}{couleur_valeur}{m}{RESET}")
        })
        .collect()
}

/// « vanguard diagnostic » : affiche le diagnostic et l'enregistre en texte.
pub fn diagnostic() {
    println!();
    cadre(
        &format!(
            "{ACCENT}{}{RESET}",
            tr!("DIAGNOSTIC DE L'ORDINATEUR", "COMPUTER DIAGNOSTIC")
        ),
        &format!("{GRIS}{}{RESET}", tr!("lecture seule", "read only")),
    );
    trp!(
        "  {DISCRET}Lecture du matériel et des journaux…{RESET}",
        "  {DISCRET}Reading hardware and logs…{RESET}"
    );
    let mut sections = systeme::sections();
    // Le dernier autodiagnostic de Vanguard (« vanguard autotest ») : quand, et s'il a trouvé un écart.
    if let Some((_, lignes)) = sections.first_mut() {
        let (valeur, niveau) = crate::autotest::ligne_diagnostic();
        let libelle = tr!("Dernier autotest", "Last self-test");
        lignes.push(match niveau {
            Some(n) => alerte(libelle, valeur, n),
            None => ligne(libelle, valeur),
        });
    }
    for (nom, lignes) in &sections {
        section(nom);
        for t in lignes.iter().flat_map(a_l_ecran) {
            println!("{t}");
        }
    }
    let fichier = crate::reseau::dossier_donnees().join(format!(
        "diagnostic-{}.txt",
        chrono::Local::now().format("%Y-%m-%d-%H%M")
    ));
    let enregistre = std::fs::create_dir_all(fichier.parent().unwrap_or(&fichier)).is_ok()
        && std::fs::write(&fichier, en_texte(&sections)).is_ok();
    if enregistre {
        trp!(
            "\n  {DISCRET}Copie texte : {}{RESET}",
            "\n  {DISCRET}Text copy: {}{RESET}",
            fichier.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mise_en_forme() {
        assert_eq!(duree(3 * 3600 + 5 * 60), "3 h 05");
        assert_eq!(duree(2 * 86_400 + 4 * 3600), "2 j 4 h");
        let sources: Vec<String> = ["dnsmasq", "kernel", "dnsmasq", "firefox"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(plus_frequentes(&sources, 2), "dnsmasq (2), firefox (1)");
        let t = en_texte(&[(
            "SYSTÈME".into(),
            vec![ligne("Nom", "portable"), alerte("Erreurs", "3", Niveau::Moyen)],
        )]);
        assert!(t.contains("  Nom") && t.contains("! Erreurs") && !t.contains('\x1b'));
    }

    /// Une longue valeur (modèle de la carte mère, carte graphique et son pilote, sources des erreurs) tient dans
    /// `LARGEUR` colonnes, la suite alignée sous elle ; une valeur vide garde sa ligne.
    #[test]
    fn lignes_du_diagnostic_dans_la_largeur() {
        let longue = alerte(
            "Erreurs du journal",
            "311 depuis le démarrage : kernel (200), NetworkManager (50), bluetoothd (30), \
             pipewire (20), wireplumber (11)",
            Niveau::Moyen,
        );
        let modele = ligne(
            "Modèle",
            "Exemple Informatique Co., Ltd. · CARTE-MERE X670-E WIFI (EX-0001) · BIOS 1.00",
        );
        for l in [&longue, &modele] {
            let lignes = a_l_ecran(l);
            for t in &lignes {
                assert!(largeur_affichee(t) <= LARGEUR, "{} colonnes : {t}", largeur_affichee(t));
            }
            let mots = |t: &str| t.split_whitespace().map(str::to_string).collect::<Vec<_>>();
            let affiches: Vec<String> = lignes.iter().flat_map(|t| mots(&sans_couleurs(t))).collect();
            assert!(affiches.ends_with(&mots(&l.valeur)), "{lignes:?}");
            assert!(
                lignes.iter().skip(1).all(|t| t.starts_with(&" ".repeat(27))),
                "{lignes:?}"
            );
        }
        assert_eq!(a_l_ecran(&ligne("Nom", "")).len(), 1);
    }

    fn sans_couleurs(t: &str) -> String {
        let mut propre = String::new();
        let mut code = false;
        for c in t.chars() {
            match (code, c) {
                (false, '\x1b') => code = true,
                (true, 'm') => code = false,
                (false, c) => propre.push(c),
                (true, _) => {}
            }
        }
        propre
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lectures_macos() {
        let profil =
            "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Air\n      Model Identifier: Mac14,2\n";
        assert_eq!(systeme::valeur(profil, "Model Name").as_deref(), Some("MacBook Air"));
        assert_eq!(systeme::valeur(profil, "Model Identifier").as_deref(), Some("Mac14,2"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_des_lignes_du_journal() {
        assert_eq!(
            systeme::source_journal("Oct 07 15:29:32 portable NetworkManager[1334]: dhcp4: request timed out")
                .as_deref(),
            Some("NetworkManager")
        );
        assert_eq!(
            systeme::source_journal("Oct 17 14:42:05 portable kernel: kvm_amd: kvm").as_deref(),
            Some("kernel")
        );
        let v = "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  610.57.04  Release Build  (root@builder)";
        assert_eq!(systeme::version_nvidia(v).as_deref(), Some("610.57.04"));
        assert_eq!(go(2_000_398_934_016), "1,8 To");
    }

    /// Ce que le diagnostic montre du journal et du système : n'importe quel programme choisit le nom sous lequel il
    /// écrit au journal, le nom de son fichier, celui de son service ; un appareil, son modèle. Piégés (couleur, OSC 52,
    /// effacement de ligne, bidi), ils arrivent inoffensifs, « � » à la place de chaque caractère piégé.
    #[cfg(target_os = "linux")]
    #[test]
    fn journal_et_systeme_pieges() {
        assert_eq!(
            systeme::source_journal("Oct 17 15:29:32 portable \x1b]52;c;eA==\x07\r\u{202e}x[1334]: boum").as_deref(),
            Some("�]52;c;eA==���x")
        );
        let coredumpctl = "TIME                            PID  UID  GID SIG     COREFILE EXE\n\
                           Sun 2026-09-27 11:30:12 UTC  513823 1000 1000 SIGSEGV missing  /tmp/x\x1b]52;c;eA==\x07\u{202e}\n";
        assert_eq!(systeme::programmes_coredumpctl(coredumpctl), ["x�]52;c;eA==��"]);
        // Lu dans les fichiers du journal : le nom choisi par le programme d'abord, celui du processus sinon.
        let entree = |champs: &[(&str, &str)]| crate::machine::linux::journal_systemd::Entree {
            quand: 0,
            champs: champs
                .iter()
                .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                .collect(),
        };
        let piege = entree(&[("SYSLOG_IDENTIFIER", "\x1b]52;c;eA==\x07x"), ("_COMM", "kworker")]);
        assert_eq!(systeme::source_entree(&piege).as_deref(), Some("�]52;c;eA==�x"));
        assert_eq!(
            systeme::source_entree(&entree(&[("_COMM", "pipewire")])).as_deref(),
            Some("pipewire")
        );
        assert_eq!(systeme::source_entree(&entree(&[("_COMM", "  ")])), None);
        assert_eq!(systeme::source_entree(&entree(&[])), None);
        let carte = crate::fiche::CartePci {
            fabricant: "Faux\x1b[2K".into(),
            puce: "Carte\u{2066}".into(),
            pilote: String::new(),
        };
        assert_eq!(systeme::nom_de_carte(&carte), "Faux�[2K Carte�");
        let cle = crate::machine::linux::natif::Disque {
            nom: "sdb".into(),
            octets: 31_004_295_168,
            rotatif: true,
            amovible: true,
            modele: "Cle\x1b]0;x\x07\u{200b}".into(),
            serie: String::new(),
            bus: "usb".into(),
            genre: "disk".into(),
        };
        assert_eq!(
            systeme::ligne_de_disque(&cle),
            "sdb · 28,9 Go · clé ou disque USB · Cle�]0;x��"
        );
        // Le chemin du programme planté vient d'un attribut que le programme choisit (son nom de fichier).
        let d = std::env::temp_dir().join(format!("vanguard-diagnostic-vidage-piege-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join(format!("core.x.1000.{}.4242.1790000000000000.zst", "0".repeat(32))),
            "",
        )
        .unwrap();
        let piege = |_: &std::path::Path| Some(b"/opt/x\x1b]52;c;eA==\x07".to_vec());
        assert_eq!(
            systeme::plantages_coredump(&d, 0, piege),
            Some(vec![("x�]52;c;eA==�".to_string(), 4242)])
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une entrée de plusieurs lignes (la pile d'un programme planté, écrite par systemd-coredump au niveau « crit »)
    /// se continue en retrait : ce ne sont pas d'autres erreurs, et leur début n'est pas une source.
    #[cfg(target_os = "linux")]
    #[test]
    fn suite_d_une_entree_du_journal() {
        let retrait = " ".repeat(51);
        for suite in [
            format!("{retrait}Stack trace of thread 1949948:"),
            format!("{retrait}#0  0x000071e6e46dc78a save_context (libessai.so.1 + 0x1c78a)"),
            retrait.clone(),
        ] {
            assert_eq!(systeme::source_journal(&suite), None, "« {suite} »");
        }
    }

    /// `coredumpctl list` : le chemin d'un jeu contient souvent des espaces (« …/Hollow Knight/hollow_knight ») ;
    /// systemd 248 et plus ajoutent la colonne SIZE après lui, les versions d'avant non.
    #[cfg(target_os = "linux")]
    #[test]
    fn programmes_plantes_au_chemin_avec_espaces() {
        let entete = "TIME                            PID  UID  GID SIG     COREFILE EXE";
        let lignes = [
            "Sun 2026-09-27 11:30:12 UTC  513823 1000 1000 SIGSEGV missing  /usr/bin/firefox",
            "Sun 2026-09-27 17:18:43 UTC 1528339 1000 1000 SIGSEGV missing  /srv/jeux/Hollow Knight/hollow_knight",
            "Mon 2026-09-28 09:02:11 UTC    4242 1000 1000 SIGABRT present  /opt/Jeu Essai/jeu",
            "Mon 2026-09-28 09:05:00 UTC    4243 1000 1000 SIGSEGV none     n/a",
        ];
        // Comme coredumpctl : la colonne EXE à la largeur du plus long chemin, puis SIZE.
        let taille = ["-", "-", "1.2M", "-"];
        let mut liste = format!("{entete:<120} SIZE\n");
        for (l, t) in lignes.iter().zip(taille) {
            let _ = writeln!(liste, "{l:<120} {t:>4}");
        }
        assert_eq!(
            systeme::programmes_coredumpctl(&liste),
            ["firefox", "hollow_knight", "jeu"]
        );
        let sans_taille = "TIME                            PID   UID   GID SIG COREFILE  EXE\n\
                           Sat 2021-05-01 10:00:00 UTC    1234  1000  1000  11 present   /opt/Mon Jeu/jeu\n";
        assert_eq!(systeme::programmes_coredumpctl(sans_taille), ["jeu"]);
    }

    /// La ligne « Système » de Linux existe dans les deux langues : « noyau » s'affichait aussi en anglais. Les tests
    /// tournent en français : le texte anglais est cherché dans le code de ce fichier.
    #[test]
    fn noyau_dans_les_deux_langues() {
        let source = include_str!("diagnostic.rs");
        let code = &source[..source.find("#[cfg(test)]\nmod tests").unwrap_or(source.len())];
        assert!(
            code.contains("\"{os} · kernel {}\""),
            "ligne « Système » sans texte anglais"
        );
    }

    /// Les noms des vidages de systemd-coredump : l'heure et le numéro du processus ; un fichier en cours
    /// d'écriture ou d'une autre forme ne compte pas.
    #[cfg(target_os = "linux")]
    #[test]
    fn noms_des_vidages() {
        let demarrage = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            systeme::vidage(&format!("core.firefox.1000.{demarrage}.513823.1790000000000000.zst")),
            Some((1_790_000_000_000_000, 513_823))
        );
        assert_eq!(
            systeme::vidage(&format!(
                "core.Jeu\\x20Essai\\x2ebin.1000.{demarrage}.42.1790000000000001"
            )),
            Some((1_790_000_000_000_001, 42)),
            "sans compression"
        );
        for etranger in [
            format!(".#core.firefox.1000.{demarrage}.1.1790000000000000.zst"),
            format!("core.firefox.alice.{demarrage}.1.1790000000000000.zst"),
            "core.firefox.1000.court.1.1790000000000000".to_string(),
            format!("core.firefox.1000.{demarrage}.1"),
            "notes.txt".to_string(),
        ] {
            assert_eq!(systeme::vidage(&etranger), None, "{etranger}");
        }
    }

    /// Le dossier des vidages : ceux de la semaine seulement, du plus ancien au plus récent, nommés par la fin du
    /// chemin de « user.coredump.exe » et non par le nom coupé du fichier. Un dossier absent, ou un vidage sans
    /// cet attribut, ne se lit pas (`None`).
    #[cfg(target_os = "linux")]
    #[test]
    fn vidages_de_la_semaine() {
        let d = std::env::temp_dir().join(format!("vanguard-diagnostic-vidages-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let demarrage = "0123456789abcdef0123456789abcdef";
        let exe = |c: &std::path::Path| -> Option<Vec<u8>> {
            let nom = c.file_name()?.to_string_lossy().into_owned();
            let chemin = match nom.split('.').nth(1)? {
                "gnome-keyring-d" => "/usr/bin/gnome-keyring-daemon",
                "Isolated\\x20Web\\x20Co" => "/usr/lib/firefox/firefox",
                "vieux" => "/usr/bin/vieux",
                _ => return None,
            };
            Some(chemin.as_bytes().to_vec())
        };
        assert_eq!(systeme::plantages_coredump(&d, 0, exe), Some(vec![]));
        for (comm, pid, quand) in [
            ("Isolated Web Co", 3, 300),
            ("vieux", 1, 100),
            ("gnome-keyring-d", 2, 200),
        ] {
            let comm = comm.replace(' ', "\\x20");
            std::fs::write(d.join(format!("core.{comm}.1000.{demarrage}.{pid}.{quand}.zst")), "").unwrap();
        }
        assert_eq!(
            systeme::plantages_coredump(&d, 200, exe),
            Some(vec![
                ("gnome-keyring-daemon".to_string(), 2),
                ("firefox".to_string(), 3)
            ])
        );
        std::fs::write(d.join(format!("core.sans.1000.{demarrage}.4.400.zst")), "").unwrap();
        assert_eq!(
            systeme::plantages_coredump(&d, 200, exe),
            None,
            "un vidage sans attribut"
        );
        assert_eq!(systeme::plantages_coredump(&d.join("absent"), 0, exe), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les numéros des processus de `coredumpctl list`, après l'heure, quel que soit le fuseau.
    #[cfg(target_os = "linux")]
    #[test]
    fn numeros_de_coredumpctl() {
        let liste = "Tue 2026-10-20 21:11:28 EDT    9543 1000 1000 SIGSEGV present  /usr/bin/x  10.8M\n\
                     Tue 2026-10-20 21:12:00 +03     77 1000 1000 SIGABRT missing  /opt/Mon Jeu/jeu  -\n\
                     Tue 2026-10-20 21:13:00 CEST   abc 1000 1000 SIGABRT none     /usr/bin/z  -\n";
        let entete = "TIME PID UID GID SIG COREFILE EXE SIZE\n";
        assert_eq!(
            systeme::plantages_coredumpctl(&format!("{entete}{liste}")),
            [
                ("x".to_string(), Some(9543)),
                ("jeu".to_string(), Some(77)),
                ("z".to_string(), None)
            ]
        );
    }

    /// Les deux sources réunies : un dossier vide face à des plantages du journal (Storage=journal, vidage trop
    /// gros ou effacé) ne dit pas « aucun » ; un plantage des deux côtés compte une fois ; sans journal, un
    /// dossier vide ou illisible n'est pas une preuve (`None`), un dossier plein si.
    #[cfg(target_os = "linux")]
    #[test]
    fn plantages_des_deux_sources() {
        let journal = vec![("jeu".to_string(), Some(7)), ("jeu".to_string(), Some(8))];
        assert_eq!(
            systeme::plantages_reunis(Some(vec![]), Some(journal.clone())),
            Some(vec!["jeu".to_string(), "jeu".to_string()]),
            "Storage=journal : le dossier est vide"
        );
        assert_eq!(
            systeme::plantages_reunis(
                Some(vec![("jeu".to_string(), 8), ("vieux".to_string(), 3)]),
                Some(journal)
            ),
            Some(vec!["jeu".to_string(), "jeu".to_string(), "vieux".to_string()])
        );
        assert_eq!(systeme::plantages_reunis(Some(vec![]), Some(vec![])), Some(vec![]));
        assert_eq!(systeme::plantages_reunis(Some(vec![]), None), None);
        assert_eq!(systeme::plantages_reunis(None, None), None);
        assert_eq!(
            systeme::plantages_reunis(Some(vec![("x".to_string(), 1)]), None),
            Some(vec!["x".to_string()])
        );
    }

    /// Sur cet ordinateur, chaque plantage dont coredumpctl a gardé le vidage (« present ») est aussi dans le
    /// dossier, sous le même nom de programme, quand il est là. L'inverse ne se compare pas : le journal, que
    /// coredumpctl lit, perd ses plus vieilles entrées bien avant que les vidages ne soient effacés. Six jours
    /// plutôt que sept : un vidage à la limite pourrait sortir de la fenêtre entre les deux lectures.
    #[cfg(target_os = "linux")]
    #[test]
    fn vidages_comme_coredumpctl() {
        let Some(r) = crate::commande::lancer(
            std::process::Command::new("coredumpctl").args(["list", "--no-pager", "-q", "--since=-6d"]),
            20,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("coredumpctl absent");
        };
        let maintenant = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let depuis = u64::try_from(maintenant).unwrap() - 7 * 86_400 * 1_000_000;
        let Some(natifs) = systeme::plantages_coredump(
            std::path::Path::new("/var/lib/systemd/coredump"),
            depuis,
            systeme::attribut_exe,
        ) else {
            return crate::essais::saute("plantages de coredump illisibles");
        };
        let journal = systeme::plantages_coredumpctl(&r.sortie);
        for (l, (nom, pid)) in r.sortie.lines().filter(|l| l.contains(" /")).zip(&journal) {
            // « Tue 2026-10-20 21:11:28 EDT 9543 1000 1000 SIGSEGV present /usr/bin/x 10.8M »
            if l.split_whitespace().nth(8) == Some("present") {
                let pid = pid.unwrap_or_else(|| panic!("{l} : numéro illisible"));
                assert!(
                    natifs.contains(&(nom.clone(), pid)),
                    "{l} absent du dossier : {natifs:?}"
                );
            }
        }
    }
}

/// PROVISOIRE (lot H, à remplacer) : `--json` rend un résultat vide, donc « non vérifié ».
pub fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let r = crate::modele::resultat::Resultat::nouveau(
        "PRO-DIA-001",
        debut,
        &[],
        crate::modele::resultat::Couverture::default(),
    );
    println!("{}", crate::modele::resultat::json(&r));
}
