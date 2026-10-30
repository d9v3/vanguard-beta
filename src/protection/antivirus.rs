//! Recherche de malwares avec un moteur reconnu (ClamAV sous Linux, Microsoft Defender sous Windows)
//! et revue des programmes lancés au démarrage, là où un malware cherche à se maintenir.

use std::path::PathBuf;
use std::process::Command;

use crate::risk::Niveau;
use crate::ui::*;

#[cfg(unix)]
fn home() -> PathBuf {
    crate::socle::maison()
}

/// Ce qu'un moteur a conclu sur un fichier.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Examen {
    Sain,
    /// Détections : nom de la menace ou de la famille.
    Trouve(Vec<String>),
    /// Pas pu analyser, avec la raison : jamais compté comme sain.
    Impossible(String),
}

/// Ce que couvre une analyse.
pub enum Portee {
    /// Là où arrivent les menaces : téléchargements, bureau, démarrage automatique, /tmp récent.
    Rapide,
    /// Tout le dossier personnel.
    Complete,
    /// Une clé USB, un disque externe ou un dossier choisi.
    Dossier(PathBuf),
}

pub fn analyser(portee: Portee) {
    titre(match portee {
        Portee::Rapide => tr!("Analyse antivirus rapide", "Quick antivirus scan"),
        Portee::Complete => tr!("Analyse antivirus complète", "Full antivirus scan"),
        Portee::Dossier(_) => tr!(
            "Analyse antivirus d'une clé ou d'un dossier",
            "Antivirus scan of a drive or folder"
        ),
    });
    let portee = match portee {
        Portee::Dossier(d) => {
            let Ok(reel) = d.canonicalize() else {
                trp!("  ✖ Introuvable : {}", "  ✖ Not found: {}", chemin_affichable(&d));
                return;
            };
            Portee::Dossier(reel)
        }
        autre => autre,
    };
    #[cfg(windows)]
    defender(&portee);
    #[cfg(unix)]
    clamav(&portee);
    match &portee {
        // Une clé n'a pas de programmes de démarrage : on regarde plutôt les pièges des vers de clé USB.
        Portee::Dossier(d) => revue_cle(d),
        _ => demarrage(),
    }
}

/// Menu : propose les clés et disques externes branchés, ou un chemin tapé à la main.
pub fn choisir() {
    let volumes = volumes_amovibles();
    titre(tr!("Antivirus : clé USB ou dossier", "Antivirus: USB drive or folder"));
    if volumes.is_empty() {
        trp!(
            "  {GRIS}Aucune clé ni disque externe monté.{RESET}",
            "  {GRIS}No USB drive or external disk mounted.{RESET}"
        );
    }
    for (i, (chemin, description)) in volumes.iter().enumerate() {
        println!(
            "  {TOUCHE}{}{RESET}  {}  {DISCRET}{description}{RESET}",
            i + 1,
            chemin_affichable(chemin)
        );
    }
    let reponse = crate::selection::demander_ou_revenir(tr!(
        "\n  Numéro, ou chemin d'un dossier (Entrée pour revenir) : ",
        "\n  Number, or path of a folder (Enter to go back): "
    ));
    let reponse = reponse.trim();
    if reponse.is_empty() {
        return;
    }
    // Un numéro de la liste (compté depuis 1), sinon un chemin.
    let cible = match reponse
        .parse::<usize>()
        .ok()
        .and_then(|n| volumes.get(n.checked_sub(1)?))
    {
        Some((chemin, _)) => chemin.clone(),
        None => PathBuf::from(reponse.trim_matches(['"', '\''])),
    };
    analyser(Portee::Dossier(cible));
}

/// Clés et disques externes montés : (point de montage, description). Lu dans /proc/self/mountinfo et /sys, comme
/// lsblk le fait lui-même ; lsblk ne sert qu'en secours, quand mountinfo ne se lit pas.
#[cfg(target_os = "linux")]
fn volumes_amovibles() -> Vec<(PathBuf, String)> {
    if let Ok(montages) = std::fs::read_to_string("/proc/self/mountinfo") {
        return volumes_amovibles_sous(std::path::Path::new("/"), &montages);
    }
    crate::commande::lancer(
        Command::new("lsblk").args(["-Pno", "RM,HOTPLUG,LABEL,SIZE,MOUNTPOINT"]),
        10,
    )
    .map(|o| lire_lsblk(&o.sortie))
    .unwrap_or_default()
}

/// Un chemin absolu du système, rattaché à `racine` (les tests passent la leur).
#[cfg(target_os = "linux")]
fn sous(racine: &std::path::Path, chemin: &str) -> PathBuf {
    racine.join(chemin.trim_start_matches('/'))
}

/// Les volumes montés dont le disque est amovible ou branché à chaud. Chaque périphérique compte une fois, à son
/// premier montage entier (racine « / » du système de fichiers, pas un sous-volume Btrfs ni un montage lié) s'il y en
/// a un. Un volume chiffré ou LVM compte quand un des disques dessous est amovible : lsblk ne le disait pas, et une
/// clé chiffrée s'analyse aussi. Description : étiquette et taille, prête à montrer (l'étiquette vient de qui a
/// préparé la clé).
#[cfg(target_os = "linux")]
fn volumes_amovibles_sous(racine: &std::path::Path, mountinfo: &str) -> Vec<(PathBuf, String)> {
    let mut choisis: Vec<(String, PathBuf, bool)> = Vec::new();
    for l in mountinfo.lines() {
        let Some((avant, apres)) = l.split_once(" - ") else {
            continue;
        };
        let champs: Vec<&str> = avant.split(' ').collect();
        let (Some(dedans), Some(point)) = (champs.get(3), champs.get(4)) else {
            continue;
        };
        let Some(source) = apres.split(' ').nth(1).map(crate::copier::sans_echappements) else {
            continue;
        };
        if !source.starts_with("/dev/") {
            continue;
        }
        // /dev/mapper/<nom> et /dev/disk/by-* sont des liens : sysfs connaît le périphérique sous son nom réel.
        let reel = std::fs::canonicalize(sous(racine, &source)).unwrap_or_else(|_| PathBuf::from(&source));
        let Some(nom) = reel.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let entier = *dedans == "/";
        let point = PathBuf::from(crate::copier::sans_echappements(point));
        match choisis.iter_mut().find(|(n, _, _)| *n == nom) {
            Some(c) if entier && !c.2 => *c = (nom, point, true),
            Some(_) => {}
            None => choisis.push((nom, point, entier)),
        }
    }
    choisis
        .into_iter()
        .filter(|(nom, _, _)| bloc_amovible(racine, &sous(racine, "/sys/class/block").join(nom), 0))
        .map(|(nom, point, _)| {
            let octets = std::fs::read_to_string(sous(racine, "/sys/class/block").join(&nom).join("size"))
                .ok()
                .and_then(|t| t.trim().parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_mul(512);
            let taille = taille_lsblk(octets);
            let description = match etiquette(racine, &nom) {
                Some(e) if !e.is_empty() => format!("{e} · {taille}"),
                _ => taille,
            };
            (point, affichable(&description))
        })
        .collect()
}

/// Un périphérique bloc (`/sys/class/block/<nom>`) est-il sur un disque amovible ? Une partition regarde son disque
/// (le dossier parent dans sysfs), un volume device-mapper les périphériques dessous (« slaves »).
#[cfg(target_os = "linux")]
fn bloc_amovible(racine: &std::path::Path, bloc: &std::path::Path, profondeur: u8) -> bool {
    // Une boucle de liens ne doit pas faire tourner sans fin : aucune pile réelle n'a seize étages.
    if profondeur > 16 {
        return false;
    }
    let Ok(reel) = std::fs::canonicalize(bloc) else {
        return false;
    };
    let disque = if reel.join("partition").exists() {
        match reel.parent() {
            Some(p) => p.to_path_buf(),
            None => return false,
        }
    } else {
        reel
    };
    let esclaves: Vec<PathBuf> = std::fs::read_dir(disque.join("slaves"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    if !esclaves.is_empty() {
        return esclaves.iter().any(|e| bloc_amovible(racine, e, profondeur + 1));
    }
    std::fs::read_to_string(disque.join("removable")).is_ok_and(|r| r.trim() == "1")
        || branche_a_chaud(racine, &disque.join("device"))
}

/// Branché à chaud, comme le dit lsblk (HOTPLUG) : en remontant le chemin de l'appareil dans /sys/devices, le premier
/// attribut « removable » rencontré dit « removable » (un port USB, un lecteur de cartes) ; « fixed » arrête.
#[cfg(target_os = "linux")]
fn branche_a_chaud(racine: &std::path::Path, appareil: &std::path::Path) -> bool {
    let Ok(chemin) = std::fs::canonicalize(appareil) else {
        return false;
    };
    let devices = sous(racine, "/sys/devices");
    for d in chemin
        .ancestors()
        .take_while(|d| d.starts_with(&devices) && *d != devices)
    {
        match std::fs::read_to_string(d.join("removable")).as_deref().map(str::trim) {
            Ok("removable") => return true,
            Ok("fixed") => return false,
            _ => {}
        }
    }
    false
}

/// L'étiquette du système de fichiers, d'après les liens de /dev/disk/by-label (posés par udev, lisibles par tous).
/// udev y écrit en « \xHH » les octets qui ne vont pas dans un nom de fichier (l'espace : « MA\x20CLE »).
#[cfg(target_os = "linux")]
fn etiquette(racine: &std::path::Path, nom: &str) -> Option<String> {
    std::fs::read_dir(sous(racine, "/dev/disk/by-label"))
        .ok()?
        .flatten()
        .find(|e| {
            std::fs::read_link(e.path())
                .ok()
                .and_then(|c| c.file_name().map(|n| n == std::ffi::OsStr::new(nom)))
                .unwrap_or(false)
        })
        .map(|e| sans_hex(&e.file_name().to_string_lossy()))
}

/// « MA\x20CLE » → « MA CLE » : les octets écrits en hexadécimal, puis le texte relu en UTF-8.
#[cfg(any(target_os = "linux", test))]
fn sans_hex(t: &str) -> String {
    let o = t.as_bytes();
    let mut sortie = Vec::with_capacity(o.len());
    let mut i = 0;
    while let Some(&c) = o.get(i) {
        if c == b'\\'
            && o.get(i + 1) == Some(&b'x')
            && let Some(h) = t.get(i + 2..i + 4).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            sortie.push(h);
            i += 4;
        } else {
            sortie.push(c);
            i += 1;
        }
    }
    String::from_utf8_lossy(&sortie).into_owned()
}

/// Une taille écrite comme lsblk l'écrit : en puissances de 1024, une lettre (« 512B », « 47G », « 28,9G »), un
/// chiffre après la virgule quand il n'est pas nul, arrondi comme util-linux le fait. macOS l'écrit de même.
#[cfg(any(unix, test))]
fn taille_lsblk(octets: u64) -> String {
    const LETTRES: [&str; 6] = ["K", "M", "G", "T", "P", "E"];
    if octets < 1024 {
        return format!("{octets}B");
    }
    // La plus grande unité (de 2^10 à 2^60) que la taille atteint ; K au moins, puisque `octets` ≥ 1024.
    let Some((exposant, lettre)) = (10..)
        .step_by(10)
        .zip(LETTRES)
        .take_while(|&(e, _)| e == 10 || octets >> e > 0)
        .last()
    else {
        return format!("{octets}B");
    };
    let mut entier = octets >> exposant;
    // Le reste en millièmes de l'unité (tronqués), puis arrondi au dixième.
    let reste = u128::from(octets & ((1u64 << exposant) - 1));
    let milliemes = u64::try_from((reste * 1000) >> exposant).unwrap_or(0);
    let mut dixiemes = (milliemes + 50) / 100;
    if dixiemes == 10 {
        entier += 1;
        dixiemes = 0;
    }
    if dixiemes == 0 {
        format!("{entier}{lettre}")
    } else {
        let virgule = if crate::langue::anglais() { '.' } else { ',' };
        format!("{entier}{virgule}{dixiemes}{lettre}")
    }
}

/// Clés et disques externes montés sous macOS : tout ce qui est dans /Volumes, sauf le disque du système (un
/// lien vers « / »). Description : nom et taille (`tailles_des_volumes`), prête à montrer (l'étiquette vient de qui a préparé la clé).
#[cfg(target_os = "macos")]
fn volumes_amovibles() -> Vec<(PathBuf, String)> {
    let racine = std::fs::canonicalize("/").unwrap_or_default();
    let tailles = tailles_des_volumes();
    std::fs::read_dir("/Volumes")
        .into_iter()
        .flatten()
        .flatten()
        .map(|d| d.path())
        .filter(|p| std::fs::canonicalize(p).is_ok_and(|r| r != racine))
        .map(|p| {
            let taille = tailles.get(&p).map(|&o| taille_lsblk(o)).unwrap_or_default();
            let nom = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (p, affichable(&format!("{nom} · {taille}")))
        })
        .collect()
}

/// La taille de chaque système de fichiers monté (point de montage → octets), lue par getfsstat avec MNT_NOWAIT :
/// les valeurs que le noyau garde, sans interroger chaque volume, si bien qu'un volume réseau qui ne répond plus ne
/// fait rien attendre (df, lancé avant, pouvait y rester bloqué jusqu'à son délai).
#[cfg(target_os = "macos")]
fn tailles_des_volumes() -> std::collections::HashMap<PathBuf, u64> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: sans tampon, getfsstat rend seulement le nombre de systèmes de fichiers montés.
    let n = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    let Ok(n) = usize::try_from(n) else {
        return std::collections::HashMap::new();
    };
    // Quelques places de plus : un volume monté entre les deux appels n'est pas perdu.
    // SAFETY: statfs n'est fait que d'entiers et de tableaux d'octets, pour qui zéro est une valeur permise.
    let mut tampon: Vec<libc::statfs> = vec![unsafe { std::mem::zeroed() }; n + 8];
    let Ok(taille) = libc::c_int::try_from(tampon.len() * std::mem::size_of::<libc::statfs>()) else {
        return std::collections::HashMap::new();
    };
    // SAFETY: le tampon fait `taille` octets, à nous ; getfsstat y écrit au plus autant de structures et rend leur
    // nombre.
    let lus = unsafe { libc::getfsstat(tampon.as_mut_ptr(), taille, libc::MNT_NOWAIT) };
    let lus = usize::try_from(lus).unwrap_or(0).min(tampon.len());
    tampon
        .iter()
        .take(lus)
        .map(|f| {
            // f_mntonname : un nom C terminé par un zéro dans un tableau de 1024 octets.
            let octets: Vec<u8> = f
                .f_mntonname
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c.cast_unsigned())
                .collect();
            let point = PathBuf::from(std::ffi::OsStr::from_bytes(&octets));
            (point, f.f_blocks.saturating_mul(u64::from(f.f_bsize)))
        })
        .collect()
}

/// Lignes de `lsblk -P` : RM="1" HOTPLUG="1" LABEL="CLE" SIZE="28,9G" MOUNTPOINT="/run/media/alice/CLE". La
/// description est prête à montrer (l'étiquette vient de qui a préparé la clé) ; le point de montage reste tel quel,
/// pour l'analyse.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lire_lsblk(texte: &str) -> Vec<(PathBuf, String)> {
    texte
        .lines()
        .filter_map(|l| {
            let champ = |nom: &str| {
                let debut = l.find(&format!("{nom}=\""))? + nom.len() + 2;
                let fin = l[debut..].find('"')? + debut;
                // lsblk échappe les espaces et caractères spéciaux en \xHH.
                Some(l[debut..fin].replace("\\x20", " "))
            };
            let amovible = champ("RM").as_deref() == Some("1") || champ("HOTPLUG").as_deref() == Some("1");
            let point = champ("MOUNTPOINT").filter(|m| m.starts_with('/'))?;
            amovible.then(|| {
                let nom = champ("LABEL").filter(|n| !n.is_empty());
                let taille = champ("SIZE").unwrap_or_default();
                (
                    PathBuf::from(point),
                    affichable(&nom.map_or(taille.clone(), |n| format!("{n} · {taille}"))),
                )
            })
        })
        .collect()
}

#[cfg(windows)]
fn volumes_amovibles() -> Vec<(PathBuf, String)> {
    let lecteurs = crate::machine::windows::lecteurs::lecteurs();
    if !lecteurs.is_empty() {
        #[allow(clippy::cast_precision_loss)] // une taille en Go, montrée avec une décimale
        return lecteurs
            .into_iter()
            .filter(|l| l.amovible)
            .map(|l| {
                let taille = crate::langue::decimal(l.total as f64 / f64::from(1u32 << 30), 1);
                (l.racine, affichable(&format!("{} · {taille} Go", l.etiquette)))
            })
            .collect();
    }
    crate::machine::windows::ps(
        "Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } | ForEach-Object { \
         \"$($_.DriveLetter)|$($_.FileSystemLabel)|$([math]::Round($_.Size / 1GB, 1))\" }",
    )
    .unwrap_or_default()
    .lines()
    .filter_map(|l| {
        let mut c = l.trim().splitn(3, '|');
        let lettre = c.next().filter(|x| !x.is_empty())?;
        let nom = c.next().unwrap_or("");
        let taille = c.next().unwrap_or("");
        Some((
            PathBuf::from(format!("{lettre}:\\")),
            affichable(&format!("{nom} · {taille} Go")),
        ))
    })
    .collect()
}

/// Pièges classiques des vers de clé USB, à la racine : raccourci qui imite un dossier (le vrai est caché),
/// lanceur automatique, scripts. `entrees` = (nom, est un dossier).
fn signes_de_ver(entrees: &[(String, bool)]) -> Vec<(Niveau, String)> {
    // La clé de Vanguard a son autorun.inf et son lanceur : rien de suspect.
    if entrees
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(crate::reseau::TEMOIN_CLE))
    {
        return Vec::new();
    }
    let mut signes = Vec::new();
    let dossiers: Vec<String> = entrees
        .iter()
        .filter(|(_, d)| *d)
        .map(|(n, _)| n.to_lowercase())
        .collect();
    for (nom, dossier) in entrees.iter().filter(|(_, d)| !*d) {
        let bas = nom.to_lowercase();
        let (souche, extension) = bas.rsplit_once('.').unwrap_or((&bas, ""));
        if bas == "autorun.inf" {
            signes.push((Niveau::Moyen, trf!(
                "autorun.inf : Windows ne le lance plus tout seul, mais des vers s'en servent encore. À supprimer si vous ne l'avez pas mis.",
                "autorun.inf: Windows no longer runs it by itself, but worms still use it. Delete it if you did not put it there."
            )));
        } else if extension == "lnk" && (dossiers.iter().any(|d| d == souche) || entrees.len() <= 3) && !dossier {
            signes.push((Niveau::Eleve, trf!(
                "« {nom} » : un raccourci qui se fait passer pour un dossier, technique classique d'un ver de clé USB (le vrai dossier est caché, le raccourci lance le ver). N'ouvrez pas ce raccourci.",
                "“{nom}”: a shortcut posing as a folder, a classic USB worm trick (the real folder is hidden, the shortcut runs the worm). Do not open this shortcut."
            )));
        } else if ["vbs", "vbe", "js", "jse", "wsf", "wsh", "scr", "pif", "hta"].contains(&extension) {
            signes.push((Niveau::Eleve, trf!(
                "« {nom} » : script ou programme rarement légitime sur une clé. Ne le lancez pas sans savoir d'où il vient.",
                "“{nom}”: a script or program rarely legitimate on a drive. Do not run it without knowing where it comes from."
            )));
        }
    }
    signes
}

fn revue_cle(racine: &std::path::Path) {
    if !racine.is_dir() {
        return;
    }
    titre(tr!("Pièges de clé USB", "USB drive traps"));
    // Les noms, choisis par qui a rempli la clé, sont seulement montrés : lus prêts à montrer.
    let entrees: Vec<(String, bool)> = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| (affichable(&e.file_name().to_string_lossy()), e.path().is_dir()))
        .collect();
    let signes = signes_de_ver(&entrees);
    if signes.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Aucun raccourci piégé, lanceur automatique ni script suspect à la racine.",
            "  {VERT}✔{RESET} No trapped shortcut, autorun or suspicious script at the root."
        );
    }
    for (n, s) in signes {
        println!("  {}●{RESET} {s}", couleur(n));
    }
}

// ───────────────────────────── Windows : Microsoft Defender ─────────────────────────────

#[cfg(windows)]
fn defender(portee: &Portee) {
    use crate::machine::windows::{powershell_admin, ps};
    let mpcmd =
        PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_default()).join(r"Windows Defender\MpCmdRun.exe");
    trp!(
        "  {GRIS}Moteur : Microsoft Defender. Cela peut prendre de quelques minutes à une heure (analyse complète)…{RESET}",
        "  {GRIS}Engine: Microsoft Defender. This can take from a few minutes to an hour (full scan)…{RESET}"
    );
    let mut commande = Command::new(&mpcmd);
    match portee {
        Portee::Rapide => commande.args(["-Scan", "-ScanType", "1"]),
        Portee::Complete => commande.args(["-Scan", "-ScanType", "2"]),
        // Analyse personnalisée d'un dossier ou d'une clé.
        Portee::Dossier(d) => commande.args(["-Scan", "-ScanType", "3", "-File"]).arg(d),
    };
    let statut = commande.status();
    match statut.map(|s| s.code()) {
        Ok(Some(0)) => trp!(
            "  {VERT}✔ Aucun malware trouvé.{RESET}",
            "  {VERT}✔ No malware found.{RESET}"
        ),
        Ok(Some(2)) => {
            // WMI d'abord (la classe que lit Get-MpThreat), PowerShell en secours.
            let menaces = crate::machine::windows::wmi::requete(
                r"root\Microsoft\Windows\Defender",
                "MSFT_MpThreat",
                "",
                &["ThreatName", "Resources"],
            )
            .map(|l| {
                l.iter()
                    .map(|m| {
                        let fichiers: Vec<&str> = m["Resources"].liste().iter().filter_map(|r| r.texte()).collect();
                        format!(
                            "{}|{}",
                            m["ThreatName"].texte().unwrap_or_default(),
                            fichiers.join(", ")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .or_else(|| ps("Get-MpThreat | ForEach-Object { \"$($_.ThreatName)|$($_.Resources -join ', ')\" }"))
            .unwrap_or_default();
            for l in menaces.lines() {
                let (nom, fichiers) = l.split_once('|').unwrap_or((l, ""));
                let (nom, fichiers) = (affichable(nom), affichable(fichiers));
                println!("  {}✖ {nom}{RESET}  {fichiers}", couleur(Niveau::Critique));
            }
            trp!(
                "  Defender a normalement déjà mis ces fichiers en quarantaine.",
                "  Defender has normally already quarantined these files."
            );
            if demander(tr!(
                "  Supprimer définitivement les menaces détectées ? [o/N] : ",
                "  Permanently delete the detected threats? [y/N]: "
            ))
            .oui()
                && powershell_admin(&["Remove-MpThreat".to_string()])
            {
                trp!(
                    "  {VERT}✔ Menaces supprimées.{RESET}",
                    "  {VERT}✔ Threats deleted.{RESET}"
                );
            }
        }
        _ => trp!(
            "  Defender n'a pas pu lancer l'analyse (antivirus tiers actif ?).",
            "  Defender could not start the scan (third-party antivirus active?)."
        ),
    }
}

/// Un seul fichier, pour « Vérifier un fichier téléchargé » : le résultat de Defender, qui met lui-même en
/// quarantaine ce qu'il reconnaît.
#[cfg(windows)]
pub(crate) fn examiner(fichier: &std::path::Path) -> Examen {
    let mpcmd =
        PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_default()).join(r"Windows Defender\MpCmdRun.exe");
    let Some(r) = crate::commande::lancer(
        Command::new(&mpcmd)
            .args(["-Scan", "-ScanType", "3", "-File"])
            .arg(fichier),
        900,
    ) else {
        return Examen::Impossible(tr!("Defender n'a pas pu aller au bout", "Defender could not finish").into());
    };
    lire_mpcmdrun(r.code, &r.sortie, std::fs::symlink_metadata(fichier).is_ok())
}

/// Le code 2 de MpCmdRun ne veut pas toujours dire « menace » : un fichier exclu de Defender (« was skipped ») le
/// rend aussi, sans rien analyser. Seul ce cas-là, reconnu à sa phrase et au fichier resté en place, devient
/// « impossible » ; toute autre réponse 2 reste une menace (fausse alerte plutôt que silence), avec la dernière
/// ligne de MpCmdRun quand il ne nomme rien.
#[cfg(any(windows, test))]
fn lire_mpcmdrun(code: Option<i32>, sortie: &str, encore_la: bool) -> Examen {
    match code {
        Some(0) => Examen::Sain,
        Some(2) => {
            let noms = menaces_mpcmdrun(sortie);
            if !noms.is_empty() {
                Examen::Trouve(noms)
            } else if encore_la && saute_par_mpcmdrun(sortie) {
                Examen::Impossible(raison_sautee().into())
            } else {
                let generique = tr!("menace reconnue par Defender", "threat recognized by Defender");
                Examen::Trouve(vec![match sortie.lines().map(str::trim).rfind(|l| !l.is_empty()) {
                    // Le chemin du fichier y est, aussi long que Windows le permet : la ligne est coupée.
                    Some(l) => {
                        let l = couper(&affichable(l), 160);
                        trf!("{generique} (MpCmdRun : « {l} »)", "{generique} (MpCmdRun: \"{l}\")")
                    }
                    None => generique.to_string(),
                }])
            }
        }
        _ => Examen::Impossible(
            tr!(
                "Defender n'a pas pu analyser (antivirus tiers actif ?)",
                "Defender could not scan (third-party antivirus active?)"
            )
            .into(),
        ),
    }
}

/// MpCmdRun a sauté le fichier : une ligne entière « Scanning <chemin> was skipped. », et aucune « found N threats ».
/// Le chemin, lui, est choisi par qui a nommé le fichier (« facture was skipped.exe ») : la phrase n'est reconnue qu'en
/// fin de ligne, où Windows ne laisse pas finir un nom de fichier (ni point final ni retour à la ligne).
#[cfg(any(windows, test))]
fn saute_par_mpcmdrun(sortie: &str) -> bool {
    let lignes = || sortie.lines().map(str::trim);
    lignes().any(|l| l.starts_with("Scanning ") && l.ends_with(" was skipped."))
        && !lignes().any(|l| l.starts_with("Scanning ") && l.ends_with(" threats."))
}

/// La raison d'un fichier sauté par Defender : propre à ce fichier, jamais l'antivirus absent (`pieces::moteurs` ne
/// la reporte pas sur les pièces suivantes). Une exclusion qu'on n'a pas posée est elle-même un signe.
pub(crate) fn raison_sautee() -> &'static str {
    tr!(
        "Defender a sauté ce fichier : exclu de l'analyse, ce qui est suspect si personne ne l'a voulu",
        "Defender skipped this file: excluded from scanning, which is suspicious if nobody meant it"
    )
}

/// Noms des menaces dans la sortie de MpCmdRun : « Threat                  : Virus:DOS/EICAR_Test_File », prêts à
/// montrer.
#[cfg(any(windows, test))]
fn menaces_mpcmdrun(sortie: &str) -> Vec<String> {
    sortie
        .lines()
        .filter_map(|l| {
            let (cle, valeur) = l.split_once(':')?;
            (cle.trim() == "Threat").then(|| affichable(valeur.trim()))
        })
        .filter(|v| !v.is_empty())
        .collect()
}

/// Un seul fichier, pour « Vérifier un fichier téléchargé » : le résultat de ClamAV, sans rien déplacer.
#[cfg(unix)]
pub(crate) fn examiner(fichier: &std::path::Path) -> Examen {
    if !preparer() {
        return Examen::Impossible(
            tr!(
                "ClamAV absent (installation refusée ou impossible)",
                "ClamAV missing (installation declined or failed)"
            )
            .into(),
        );
    }
    // Au-delà de 200 Mo, ClamAV saute le fichier sans le lire (--max-filesize) : rien ne serait conclu.
    if std::fs::metadata(fichier).is_ok_and(|m| m.len() > 200 * 1024 * 1024) {
        return Examen::Impossible(
            tr!(
                "fichier de plus de 200 Mo, que ClamAV ne lit pas",
                "file over 200 MB, which ClamAV does not read"
            )
            .into(),
        );
    }
    let Some(r) = crate::commande::lancer(
        Command::new(outil_clamav("clamscan"))
            .args(["-i", "--max-filesize=200M", "--max-scansize=400M"])
            .args(option_base())
            .arg(fichier),
        900,
    ) else {
        return Examen::Impossible(tr!("ClamAV n'a pas pu aller au bout", "ClamAV could not finish").into());
    };
    match lire_resultat(r.code, &r.sortie) {
        Some(b) if b.analyses == 0 => {
            Examen::Impossible(tr!("fichier illisible pour ClamAV", "file unreadable for ClamAV").into())
        }
        Some(b) if b.infectes.is_empty() => Examen::Sain,
        Some(b) => Examen::Trouve(b.infectes.into_iter().map(|(_, menace)| menace).collect()),
        None => Examen::Impossible(tr!("l'analyse de ClamAV a échoué", "the ClamAV scan failed").into()),
    }
}

// ───────────────────────────── Linux : ClamAV ─────────────────────────────

/// Les configurations de freshclam : Debian et Arch, Fedora, Homebrew (Apple Silicon, puis Intel).
#[cfg(unix)]
const CONFS_FRESHCLAM: [&str; 4] = [
    "/etc/clamav/freshclam.conf",
    "/etc/freshclam.conf",
    "/opt/homebrew/etc/clamav/freshclam.conf",
    "/usr/local/etc/clamav/freshclam.conf",
];

#[cfg(unix)]
fn base_presente() -> bool {
    dossier_de_base().is_some()
}

/// `--database=<dossier>` pour clamscan : il ne lit pas freshclam.conf, et une base rangée ailleurs que dans son
/// dossier compilé (`DatabaseDirectory`) le faisait échouer, faute de signatures.
#[cfg(unix)]
fn option_base() -> Option<String> {
    dossier_de_base().map(|d| format!("--database={}", d.display()))
}

/// Le dossier qui contient les signatures de ClamAV.
#[cfg(unix)]
fn dossier_de_base() -> Option<PathBuf> {
    // Homebrew : /opt/homebrew (Apple Silicon) ou /usr/local (Intel).
    dossier_de_base_parmi(
        &CONFS_FRESHCLAM,
        &[
            "/var/lib/clamav",
            "/opt/homebrew/var/lib/clamav",
            "/usr/local/var/lib/clamav",
        ],
    )
}

#[cfg(unix)]
fn dossier_de_base_parmi(confs: &[&str], fixes: &[&str]) -> Option<PathBuf> {
    // Le dossier choisi dans freshclam.conf d'abord : une base ailleurs faisait reproposer le téléchargement.
    confs
        .iter()
        .filter_map(|c| crate::socle::lire_texte_ordinaire(std::path::Path::new(c), 1 << 16).ok())
        .filter_map(|t| dossier_de_la_base(&t))
        .chain(fixes.iter().map(PathBuf::from))
        .find(|d| base_dans(d))
}

/// Le `DatabaseDirectory` d'une configuration de freshclam, s'il y en a un (la dernière ligne l'emporte).
#[cfg(unix)]
fn dossier_de_la_base(conf: &str) -> Option<PathBuf> {
    conf.lines()
        .rev()
        .find_map(|l| {
            let mut mots = l.split_whitespace();
            (mots.next()? == "DatabaseDirectory").then(|| mots.next()).flatten()
        })
        .map(|d| PathBuf::from(d.trim_matches('"')))
}

/// `dossier` contient-il des signatures (.cvd, .cld) ?
#[cfg(unix)]
fn base_dans(dossier: &std::path::Path) -> bool {
    std::fs::read_dir(dossier).is_ok_and(|d| {
        d.flatten().any(|f| {
            std::path::Path::new(&f.file_name())
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("cvd") || e.eq_ignore_ascii_case("cld"))
        })
    })
}

/// freshclam sous macOS : ClamAV de Homebrew y écrit « ERROR: NULL X509 store » à chaque téléchargement, alors que
/// les signatures arrivent et sont vérifiées (cause inconnue même des auteurs : Cisco-Talos/clamav#1421). Le
/// message, alarmant et sans conséquence, est retiré ; le code de retour de freshclam est gardé.
#[cfg(target_os = "macos")]
pub(crate) fn commande_freshclam(freshclam: &str) -> String {
    format!(
        "set -o pipefail; {} 2>&1 | {{ grep -v 'NULL X509 store' || true; }}",
        crate::commande::sh_chaine(freshclam)
    )
}

/// Chemin d'un outil de ClamAV. Sous macOS, Homebrew n'est pas toujours dans le PATH du Terminal.
#[cfg(unix)]
fn outil_clamav(nom: &str) -> String {
    #[cfg(target_os = "macos")]
    if let Some(brew) = crate::machine::macos::homebrew() {
        let chemin = std::path::Path::new(brew).with_file_name(nom);
        if chemin.is_file() {
            return chemin.display().to_string();
        }
    }
    nom.to_string()
}

/// Installe ClamAV et télécharge les signatures si besoin. Retourne `false` si l'utilisateur refuse. Chaque commande
/// est montrée avant la question qui l'accepte (comme `outil::proposer`) : on dit oui à ce qu'on a vu.
#[cfg(unix)]
fn preparer() -> bool {
    // Linux : le PATH parcouru sur le disque, sans lancer de shell.
    #[cfg(target_os = "linux")]
    let present = crate::machine::linux::natif::present(&outil_clamav("clamscan"));
    // macOS aussi : le PATH parcouru sur le disque, sans bash (le chemin y était collé entre apostrophes).
    #[cfg(target_os = "macos")]
    let present = crate::machine::unix::present(&outil_clamav("clamscan"));
    if !present {
        trp!(
            "  ClamAV (antivirus open source) n'est pas installé.",
            "  ClamAV (open source antivirus) is not installed."
        );
        let Some(installation) = commande_d_installation() else {
            return false;
        };
        println!("  {GRIS}{installation}{RESET}");
        // Sans réponse (`vanguard verifier-fichier f < /dev/null`, un script) : « non », et le fichier a son verdict.
        if !demander_ou_defaut(tr!("  L'installer maintenant ? [o/N] : ", "  Install it now? [y/N]: ")).oui() {
            return false;
        }
        // Par le lanceur des corrections : l'installation est notée dans « Ce que Vanguard a changé ».
        if !crate::machine::appliquer(&[installation]) {
            trp!("  Installation impossible.", "  Installation failed.");
            return false;
        }
    }
    if !base_presente() {
        trp!(
            "  Les signatures de virus de ClamAV manquent (~300 Mo, une seule fois).",
            "  ClamAV's virus signatures are missing (~300 MB, only once)."
        );
        let (telechargement, service) = commandes_des_signatures();
        for c in std::iter::once(&telechargement).chain(&service) {
            println!("  {GRIS}{c}{RESET}");
        }
        // Le téléchargement passe par sudo et active leur mise à jour automatique : pas sans accord.
        if !demander_ou_defaut(tr!(
            "  Les télécharger maintenant ? [o/N] : ",
            "  Download them now? [y/N]: "
        ))
        .oui()
        {
            return false;
        }
        trp!(
            "  Téléchargement des signatures de virus…",
            "  Downloading the virus signatures…"
        );
        // Le téléchargement ne change rien à noter sous Linux ; le service activé pour de bon, si. Sous macOS, la
        // configuration posée est notée, comme toute correction.
        #[cfg(target_os = "linux")]
        let ok = crate::machine::appliquer_sans_noter(&[telechargement]).0
            && service.is_none_or(|s| crate::machine::appliquer(&[s]));
        #[cfg(target_os = "macos")]
        let ok = crate::machine::appliquer(&[telechargement]);
        if !ok {
            return false;
        }
    }
    true
}

/// La commande qui installe ClamAV, ou `None` (et pourquoi, à l'écran) faute d'outil pour l'installer.
#[cfg(target_os = "linux")]
fn commande_d_installation() -> Option<String> {
    // Fedora sépare le moteur et l'outil de mise à jour des signatures.
    match crate::machine::linux::Paquets::detecter() {
        Some(g @ crate::machine::linux::Paquets::Dnf) => Some(g.installer("clamav clamav-update")),
        Some(g) => Some(g.installer("clamav")),
        None => {
            trp!(
                "  Gestionnaire de paquets non reconnu : installez ClamAV avec l'outil de votre distribution.",
                "  Package manager not recognized: install ClamAV with your distribution's tool."
            );
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn commande_d_installation() -> Option<String> {
    let Some(brew) = crate::machine::macos::homebrew() else {
        trp!(
            "  Homebrew est nécessaire pour installer ClamAV : https://brew.sh",
            "  Homebrew is needed to install ClamAV: https://brew.sh"
        );
        return None;
    };
    Some(format!("{brew} install clamav"))
}

/// Les commandes du premier téléchargement des signatures, puis celle qui active leur mise à jour (Linux seulement).
#[cfg(target_os = "linux")]
fn commandes_des_signatures() -> (String, Option<String>) {
    // Sur Debian/Ubuntu/Mint, le service tourne déjà et verrouille la base : on l'arrête le temps du premier téléchargement.
    (
        "sudo systemctl stop clamav-freshclam.service 2>/dev/null; sudo freshclam".to_string(),
        Some("sudo systemctl enable --now clamav-freshclam.service".to_string()),
    )
}

/// Homebrew livre seulement un modèle de configuration (« Example » à retirer) ; pas besoin de sudo.
#[cfg(target_os = "macos")]
fn commandes_des_signatures() -> (String, Option<String>) {
    let freshclam = outil_clamav("freshclam");
    let prefixe = std::path::Path::new(&freshclam)
        .parent()
        .and_then(std::path::Path::parent)
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    (
        format!(
            "C='{prefixe}/etc/clamav/freshclam.conf'; [ -f \"$C\" ] || sed '/^Example/d' \"$C.sample\" > \"$C\"; {}",
            commande_freshclam(&freshclam)
        ),
        None,
    )
}

/// Les endroits à risque du dossier personnel sous Linux et macOS : là où arrivent les menaces (téléchargements,
/// bureau, démarrage automatique, programmes de l'utilisateur). L'analyse rapide de l'antivirus et celle de YARA.
#[cfg(unix)]
pub(crate) const ENDROITS_A_RISQUE: [&str; 7] = [
    "Downloads",
    "Téléchargements",
    "Desktop",
    "Bureau",
    ".local/bin",
    ".config/autostart",
    "Library/LaunchAgents",
];

#[cfg(unix)]
fn clamav(portee: &Portee) {
    if !preparer() {
        trp!("  Analyse annulée.", "  Scan cancelled.");
        return;
    }
    let h = home();
    // Analyse rapide : là où arrivent les menaces (téléchargements, bureau, démarrage automatique, programmes de
    // l'utilisateur). Documents passe par l'analyse complète : des milliers de fichiers, rarement une porte d'entrée.
    let cibles: Vec<PathBuf> = match portee {
        Portee::Dossier(d) => vec![d.clone()],
        Portee::Complete => vec![h.clone()],
        Portee::Rapide => ENDROITS_A_RISQUE
            .iter()
            .map(|d| h.join(d))
            .filter(|p| p.exists())
            .collect(),
    };
    let cibles = sans_doublons(cibles);
    // /tmp : seulement les fichiers récents (7 jours), où atterrit un téléchargement en cours ou un script lancé ;
    // le reste peut peser des gigaoctets (caches de compilation, préfixes Wine) sans rien apprendre.
    let liste_tmp = if matches!(portee, Portee::Rapide) {
        let fichiers = fichiers_recents(std::path::Path::new("/tmp"), 7, 5000);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let chemin = std::env::temp_dir().join(format!("vanguard-clamav-{}-{nanos}.txt", std::process::id()));
        let texte = fichiers
            .iter()
            .map(|f| f.display().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        // Création exclusive : jamais un fichier ou un lien posé d'avance par un autre compte dans /tmp.
        let ecrit = !fichiers.is_empty()
            && std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&chemin)
                .and_then(|mut f| std::io::Write::write_all(&mut f, texte.as_bytes()))
                .is_ok();
        ecrit.then_some((chemin, fichiers.len()))
    } else {
        None
    };
    // Jeux, caches et préfixes Wine sont énormes et produisent des faux positifs (cracks, outils anti-triche).
    // Un dossier choisi est analysé en entier : seules les quarantaines restent à l'écart.
    let tout = [
        "Games",
        ".steam",
        ".local/share/Steam",
        ".cache",
        "Windows",
        ".cargo/registry",
        ".rustup",
        "target",
        "node_modules",
        // Dossiers privés des services systemd (root seul) : illisibles, ils feraient compter des erreurs.
        "systemd-private-[^/]*",
        // Quarantaine de Vanguard.
        ".local/share/vanguard/quarantaine",
        ".snapshots",
        ".Trash",
        // macOS : caches et conteneurs d'apps (énormes), quarantaine de Vanguard.
        "Library/Caches",
        "Library/Containers",
        "Library/Application Support/vanguard/quarantaine",
    ];
    let exclusions: &[&str] = if matches!(portee, Portee::Dossier(_)) {
        &[
            ".local/share/vanguard/quarantaine",
            "Library/Application Support/vanguard/quarantaine",
        ]
    } else {
        &tout
    };
    let mut cmd = Command::new(outil_clamav("clamscan"));
    // Le bilan final (fichiers analysés, infectés, erreurs) sert à juger si l'analyse a vraiment eu lieu.
    cmd.args(["-r", "-i", "--max-filesize=200M", "--max-scansize=400M"]);
    cmd.args(option_base());
    for e in exclusions {
        cmd.arg(format!("--exclude-dir={}", regex_echappe(e)));
    }
    cmd.args(&cibles);
    if let Some((chemin, _)) = &liste_tmp {
        cmd.arg(format!("--file-list={}", chemin.display()));
    }
    let mut decrites: Vec<String> = cibles.iter().map(|p| chemin_affichable(p)).collect();
    if let Some((_, n)) = &liste_tmp {
        decrites.push(trf!(
            "/tmp ({n} fichier(s) de moins de 7 jours)",
            "/tmp ({n} file(s) under 7 days old)"
        ));
    }
    trp!(
        "  {GRIS}Moteur : ClamAV. Analyse de : {}{RESET}",
        "  {GRIS}Engine: ClamAV. Scanning: {}{RESET}",
        decrites.join(", ")
    );
    trp!(
        "  {GRIS}Cela peut prendre de quelques secondes à plusieurs minutes…{RESET}",
        "  {GRIS}This can take from a few seconds to several minutes…{RESET}"
    );

    let sortie = cmd.output();
    if let Some((chemin, _)) = &liste_tmp {
        let _ = std::fs::remove_file(chemin);
    }
    let Ok(sortie) = sortie else {
        trp!("  Impossible de lancer clamscan.", "  Could not start clamscan.");
        return;
    };
    let Some(bilan) = lire_resultat(sortie.status.code(), &String::from_utf8_lossy(&sortie.stdout)) else {
        let erreur = String::from_utf8_lossy(&sortie.stderr);
        trp!(
            "  {}✖ L'analyse a échoué : le résultat n'est pas fiable.{RESET}",
            "  {}✖ The scan failed: the result is not reliable.{RESET}",
            couleur(Niveau::Eleve)
        );
        // Les erreurs de ClamAV citent souvent un fichier, au nom choisi par n'importe qui.
        for l in erreur.lines().filter(|l| l.contains("ERROR")).take(5) {
            println!("    {GRIS}{}{RESET}", affichable(l));
        }
        return;
    };

    let illisibles = if bilan.illisibles > 0 {
        trf!(
            " ; {} élément(s) illisible(s) sans droits root, ignoré(s)",
            "; {} item(s) unreadable without root rights, skipped",
            bilan.illisibles
        )
    } else {
        String::new()
    };
    trp!(
        "  {GRIS}{} fichier(s) analysé(s){illisibles}.{RESET}",
        "  {GRIS}{} file(s) scanned{illisibles}.{RESET}",
        bilan.analyses
    );
    // Ceinture et bretelles : un même fichier n'est proposé qu'une fois (sinon la 2e mise en quarantaine échoue).
    let mut infectes = bilan.infectes;
    let mut vus = std::collections::HashSet::new();
    infectes.retain(|(f, _)| vus.insert(f.clone()));
    if infectes.is_empty() {
        trp!(
            "  {VERT}✔ Aucun malware trouvé.{RESET}",
            "  {VERT}✔ No malware found.{RESET}"
        );
        return;
    }
    // Le chemin reste tel quel pour la quarantaine ; montré, il est rendu inoffensif.
    for (f, m) in &infectes {
        println!("  {}✖ {m}{RESET}  {}", couleur(Niveau::Critique), affichable(f));
    }
    trp!(
        "\n  {} fichier(s) suspect(s).",
        "\n  {} suspicious file(s).",
        infectes.len()
    );
    let rep = demander(tr!(
        "  [q]uarantaine (recommandé, réversible) / [s]upprimer / [r]ien : ",
        "  [q]uarantine (recommended, reversible) / [d]elete / [n]othing: "
    ))
    .to_lowercase();
    for (f, detection) in &infectes {
        let chemin = std::path::Path::new(f);
        let resultat = match rep.as_str() {
            // Le seul chemin vers la quarantaine : relevé d'abord, puis noté dans « Ce que Vanguard a changé ».
            "q" => crate::protection::quarantaine::isoler(
                chemin,
                detection,
                crate::protection::quarantaine::demande_d_analyse(chemin, detection),
            )
            .map(|_| ()),
            // Relevé et noté aussi : supprimé, le fichier n'a plus d'empreinte à chercher ni à comparer.
            "s" | "d" => crate::protection::quarantaine::supprimer_apres_analyse(chemin, detection),
            _ => continue,
        };
        let f = affichable(f);
        match resultat {
            Ok(()) => println!("  {VERT}✔{RESET} {f}"),
            Err(e) => trp!(
                "  ✖ {f} : {e} (fichier système ? relancer avec sudo)",
                "  ✖ {f}: {e} (system file? run again with sudo)"
            ),
        }
    }
    if !matches!(rep.as_str(), "q" | "s" | "d") {
        trp!(
            "  Rien n'a été fait : les fichiers restent à leur place.",
            "  Nothing was done: the files stay where they are."
        );
    }
    if rep == "q" {
        trp!(
            "  {GRIS}Quarantaine : {} ; un fichier se remet à sa place par le menu Virus et logiciels espions › Quarantaine.{RESET}",
            "  {GRIS}Quarantine: {}; a file goes back to its place through the menu Viruses and spyware › Quarantine.{RESET}",
            crate::protection::quarantaine::dossier().display()
        );
    }
}

/// Fichiers modifiés depuis moins de `jours` jours sous `dossier`, au plus `max` (les dossiers illisibles sont
/// sautés sans bruit).
#[cfg(unix)]
fn fichiers_recents(dossier: &std::path::Path, jours: u64, max: usize) -> Vec<PathBuf> {
    let limite = std::time::SystemTime::now() - std::time::Duration::from_secs(jours * 86_400);
    let mut trouves = Vec::new();
    let mut a_voir = vec![dossier.to_path_buf()];
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            if trouves.len() >= max {
                return trouves;
            }
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                a_voir.push(e.path());
            } else if m.is_file() && m.modified().is_ok_and(|t| t >= limite) {
                trouves.push(e.path());
            }
        }
    }
    trouves
}

/// Dossiers à analyser sans recouvrement : un ~/Desktop qui pointe vers ~/Bureau, ou un dossier contenu dans un
/// autre, faisait analyser deux fois les mêmes fichiers ; un fichier infecté était alors signalé deux fois et sa
/// seconde mise en quarantaine échouait (« fichier système ? »). Vu en test.
#[cfg(unix)]
fn sans_doublons(cibles: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut reels: Vec<PathBuf> = cibles.into_iter().map(|p| p.canonicalize().unwrap_or(p)).collect();
    // Trié, un dossier parent passe avant ce qu'il contient.
    reels.sort();
    reels.dedup();
    let mut garde: Vec<PathBuf> = Vec::new();
    for p in reels {
        if !garde.iter().any(|g| p.starts_with(g)) {
            garde.push(p);
        }
    }
    garde
}

/// Bilan d'une analyse ClamAV qui a vraiment eu lieu.
#[cfg(unix)]
#[derive(Debug, PartialEq)]
struct Bilan {
    infectes: Vec<(String, String)>,
    analyses: u64,
    /// Fichiers illisibles sans droits root (ignorés) : ClamAV renvoie alors le code 2 même si tout s'est bien passé.
    illisibles: u64,
}

/// Résultat de clamscan, `None` si l'analyse n'a pas eu lieu (base absente, plantage…).
/// On se fie au bilan final plutôt qu'au code de retour : sur un Linux normal, quelques dossiers de /tmp
/// appartiennent à root, et ClamAV répond « erreur » (code 2) après avoir analysé tout le reste (vu en réel).
#[cfg(unix)]
fn lire_resultat(code: Option<i32>, sortie: &str) -> Option<Bilan> {
    // Le chemin reste tel quel : c'est lui qu'on isole ou qu'on efface. Le nom de la menace est seulement montré.
    let infectes: Vec<(String, String)> = sortie
        .lines()
        .filter_map(|l| {
            let (fichier, menace) = l.strip_suffix(" FOUND")?.rsplit_once(": ")?;
            Some((fichier.to_string(), affichable(menace)))
        })
        .collect();
    let champ = |nom: &str| {
        sortie
            .lines()
            .find_map(|l| l.strip_prefix(nom)?.trim().parse::<u64>().ok())
    };
    let analyses = champ("Scanned files:")?;
    let annonces = champ("Infected files:")?;
    let illisibles = champ("Total errors:").unwrap_or(0);
    // Le nombre de fichiers infectés annoncé doit correspondre aux lignes lues, sinon on ne sait pas quoi isoler.
    if !matches!(code, Some(0..=2)) || annonces != infectes.len() as u64 {
        return None;
    }
    Some(Bilan {
        infectes,
        analyses,
        illisibles,
    })
}

/// --exclude-dir attend une expression régulière : on échappe les points.
#[cfg(unix)]
fn regex_echappe(dossier: &str) -> String {
    // Le chemin du dossier n'a pas de « / » final : on accepte la fin de chaîne.
    format!("/{}(/|$)", dossier.replace('.', "\\."))
}

// ───────────────────────────── Démarrage automatique ─────────────────────────────

fn demarrage() {
    titre(tr!(
        "Programmes lancés au démarrage (à vérifier)",
        "Programs started at boot (to check)"
    ));
    // Chaque entrée est écrite par qui l'a posée (le programme qui veut se faire relancer) : montrée rendue inoffensive.
    let mut entrees: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let h = home();
        for d in [".config/autostart", ".config/systemd/user"] {
            for f in std::fs::read_dir(h.join(d)).into_iter().flatten().flatten() {
                if f.path().is_file() {
                    entrees.push(chemin_affichable(&f.path()));
                }
            }
        }
        if let Some(o) = crate::commande::lancer(Command::new("crontab").arg("-l"), 10) {
            for l in o.sortie.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
                let l = affichable(l);
                entrees.push(trf!("crontab : {l}", "crontab: {l}"));
            }
        }
        for f in std::fs::read_dir("/etc/systemd/system").into_iter().flatten().flatten() {
            let p = f.path();
            // Services ajoutés à la main (pas par un paquet) : endroit classique pour une persistance root.
            if p.extension().is_some_and(|e| e == "service") && p.is_file() && !p.is_symlink() {
                let possede = crate::machine::linux::Paquets::detecter().is_none_or(|g| g.possede(&p));
                if !possede {
                    entrees.push(trf!(
                        "{} (service système hors paquet)",
                        "{} (system service not from a package)",
                        chemin_affichable(&p)
                    ));
                }
            }
        }
    }

    // macOS : agents et démons de launchd ajoutés par des programmes (ceux d'Apple sont dans /System).
    #[cfg(target_os = "macos")]
    {
        let h = home();
        for d in [
            h.join("Library/LaunchAgents"),
            "/Library/LaunchAgents".into(),
            "/Library/LaunchDaemons".into(),
        ] {
            for f in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                if f.path().extension().is_some_and(|e| e == "plist") {
                    entrees.push(chemin_affichable(&f.path()));
                }
            }
        }
    }

    // Windows : clés Run et RunOnce (winreg), dossiers Démarrage, tâches planifiées hors \Microsoft\ (ITaskService),
    // sans PowerShell ; Get-ScheduledTask seulement si le planificateur ne répond pas. Ce qui n'a pas été lu est dit.
    #[cfg(windows)]
    let non_lus = {
        let (lignes, mut non_lus) = demarrage_windows();
        entrees.extend(lignes);
        std::mem::take(&mut non_lus)
    };
    #[cfg(not(windows))]
    let non_lus: Vec<String> = Vec::new();

    if !non_lus.is_empty() {
        let liste = non_lus.join(", ");
        afficher_aligne(
            "  ",
            &trf!(
                "Non vérifié : {liste} (illisible d'ici) ; la liste ci-dessous peut être incomplète.",
                "Not verified: {liste} (unreadable from here); the list below may be incomplete."
            ),
            2,
            GRIS,
        );
    }
    // « Rien de particulier » seulement quand tout a été lu : une source illisible ne passe pas pour vide.
    if entrees.is_empty() && non_lus.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Rien de particulier.",
            "  {VERT}✔{RESET} Nothing special."
        );
    }
    for e in entrees {
        println!("  • {e}");
    }
    trp!(
        "  {GRIS}Si vous ne reconnaissez pas une entrée, renseignez-vous avant de la supprimer.{RESET}",
        "  {GRIS}If you do not recognize an entry, look it up before deleting it.{RESET}"
    );
    afficher_aligne(
        "  ",
        tr!(
            "Pour qu'un programme ne se lance plus à l'ouverture de session, sans le désinstaller et de façon annulable : vanguard demarrage (ou Optimiser et installer › Programmes au démarrage).",
            "To stop a program from starting at login, without uninstalling it and in an undoable way: vanguard startup (or Optimize and install › Startup programs)."
        ),
        2,
        GRIS,
    );
}

/// Ce qui se lance à l'ouverture de session sous Windows, lu sans PowerShell : (lignes à montrer, sources non lues).
/// Win32_StartupCommand lisait les mêmes clés et dossiers (en administrateur, aussi les clés Run des autres comptes
/// ouverts, qui manquent ici).
#[cfg(windows)]
fn demarrage_windows() -> (Vec<String>, Vec<String>) {
    let mut lignes = Vec::new();
    let (run, cles_non_lues) = crate::machine::windows::persistance::lignes_run();
    let mut non_lus: Vec<String> = cles_non_lues.iter().map(|c| (*c).to_string()).collect();
    for v in run {
        let nom = if v.nom.is_empty() {
            tr!("(par défaut)", "(default)").to_string()
        } else {
            affichable(&v.nom)
        };
        lignes.push(format!("{nom} — {}", affichable(&v.valeur)));
    }
    for (variable, sous_dossier) in [
        ("APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
        ("ProgramData", r"Microsoft\Windows\Start Menu\Programs\StartUp"),
    ] {
        let Some(base) = std::env::var_os(variable) else {
            non_lus.push(trf!(
                "dossier Démarrage (%{variable}% inconnu)",
                "Startup folder (%{variable}% unknown)"
            ));
            continue;
        };
        let dossier = std::path::PathBuf::from(base).join(sous_dossier);
        match std::fs::read_dir(&dossier) {
            Ok(fichiers) => {
                for f in fichiers.flatten() {
                    let nom = f.file_name().to_string_lossy().into_owned();
                    // desktop.ini : la mise en forme du dossier par l'Explorateur, rien qui se lance.
                    if !nom.eq_ignore_ascii_case("desktop.ini") {
                        lignes.push(trf!(
                            "{} (dossier Démarrage)",
                            "{} (Startup folder)",
                            chemin_affichable(&f.path())
                        ));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => non_lus.push(chemin_affichable(&dossier)),
        }
    }
    // Chaque tâche active, à programme ou à gestionnaire COM (une persistance connue, que Get-ScheduledTask montrait
    // aussi).
    if let Some(taches) = crate::machine::windows::planificateur::lancements() {
        for (nom, programme) in taches {
            lignes.push(trf!(
                "tâche planifiée : {} — {}",
                "scheduled task: {} — {}",
                affichable(&nom),
                affichable(&programme)
            ));
        }
    } else {
        let script = tr!(
            "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | \
             ForEach-Object { \"tâche planifiée : $($_.TaskName) — $($_.Actions.Execute)\" }",
            "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | \
             ForEach-Object { \"scheduled task: $($_.TaskName) — $($_.Actions.Execute)\" }"
        );
        match crate::machine::windows::ps(script) {
            Some(sortie) => lignes.extend(sortie.lines().filter(|l| !l.trim().is_empty()).map(affichable)),
            None => non_lus.push(tr!("tâches planifiées", "scheduled tasks").to_string()),
        }
    }
    (lignes, non_lus)
}

#[cfg(test)]
mod tests_cle {
    use super::*;

    #[test]
    fn volumes_de_lsblk() {
        let texte = "RM=\"0\" HOTPLUG=\"0\" LABEL=\"\" SIZE=\"931,5G\" MOUNTPOINT=\"/\"\n\
                     RM=\"1\" HOTPLUG=\"1\" LABEL=\"\" SIZE=\"28,9G\" MOUNTPOINT=\"\"\n\
                     RM=\"1\" HOTPLUG=\"1\" LABEL=\"MA\\x20CLE\" SIZE=\"28,8G\" MOUNTPOINT=\"/run/media/alice/MA\\x20CLE\"\n\
                     RM=\"0\" HOTPLUG=\"1\" LABEL=\"\" SIZE=\"1T\" MOUNTPOINT=\"/run/media/alice/disque\"\n";
        let v = lire_lsblk(texte);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].0, PathBuf::from("/run/media/alice/MA CLE"));
        assert_eq!(v[0].1, "MA CLE · 28,8G");
        assert_eq!(v[1].1, "1T");
        // L'étiquette d'une clé USB est choisie par qui l'a préparée : piégée, elle arrive inoffensive.
        let piege = "RM=\"1\" HOTPLUG=\"1\" LABEL=\"CLE\x1b]52;c;eA==\x07\u{202e}\" SIZE=\"8G\" MOUNTPOINT=\"/run/media/alice/CLE\"\n";
        assert_eq!(lire_lsblk(piege)[0].1, "CLE�]52;c;eA==�� · 8G");
    }

    #[test]
    fn tailles_et_etiquettes_comme_lsblk() {
        assert_eq!(taille_lsblk(512), "512B");
        assert_eq!(taille_lsblk(47 << 30), "47G");
        assert_eq!(taille_lsblk(32 << 20), "32M");
        // 2,9 Gio + un peu : le dixième est arrondi, comme util-linux.
        let t = taille_lsblk((29 << 30) / 10 + 1);
        assert!(t == "2,9G" || t == "2.9G", "{t}");
        // 1023,96 Mio s'arrondit à 1024M, pas à « 1023,10M ».
        assert_eq!(taille_lsblk((1 << 30) - (40 << 10)), "1024M");
        assert_eq!(sans_hex("MA\\x20CLE"), "MA CLE");
        assert_eq!(sans_hex("caf\\xc3\\xa9\\x2"), "café\\x2");
    }

    /// Une arborescence inventée : une clé USB (amovible), un disque USB branché à chaud, le disque interne, un
    /// volume chiffré sur la clé, un sous-volume Btrfs monté avant le volume entier.
    #[cfg(target_os = "linux")]
    #[test]
    fn volumes_lus_dans_sys() {
        use std::os::unix::fs::symlink;
        let r = std::env::temp_dir().join(format!("vanguard-antivirus-volumes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        let ecrire = |chemin: &str, texte: &str| {
            let f = sous(&r, chemin);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, texte).unwrap();
        };
        let usb = "/sys/devices/pci0/usb2/2-1";
        ecrire(&format!("{usb}/removable"), "removable\n");
        ecrire("/sys/devices/pci0/ata1/removable", "fixed\n");
        for (disque, appareil, amovible, parts) in [
            ("sdb", format!("{usb}/host6/block/sdb"), "1", 1),
            ("sdc", format!("{usb}/host7/block/sdc"), "0", 1),
            ("sda", "/sys/devices/pci0/ata1/host0/block/sda".to_string(), "0", 2),
        ] {
            ecrire(&format!("{appareil}/removable"), amovible);
            std::fs::create_dir_all(sous(&r, &format!("{appareil}/appareil"))).unwrap();
            symlink(
                sous(&r, &format!("{appareil}/appareil")),
                sous(&r, &format!("{appareil}/device")),
            )
            .unwrap();
            for p in 1..=parts {
                ecrire(&format!("{appareil}/{disque}{p}/partition"), &p.to_string());
                ecrire(&format!("{appareil}/{disque}{p}/size"), "61440000");
                ecrire(&format!("/dev/{disque}{p}"), "");
                std::fs::create_dir_all(sous(&r, "/sys/class/block")).unwrap();
                symlink(
                    sous(&r, &format!("{appareil}/{disque}{p}")),
                    sous(&r, &format!("/sys/class/block/{disque}{p}")),
                )
                .unwrap();
            }
        }
        // Le volume chiffré dm-0 repose sur sdb1 ; /dev/mapper/coffre pointe vers lui.
        ecrire("/sys/devices/virtual/block/dm-0/size", "2048");
        ecrire("/sys/devices/virtual/block/dm-0/removable", "0");
        std::fs::create_dir_all(sous(&r, "/sys/devices/virtual/block/dm-0/slaves")).unwrap();
        symlink(
            sous(&r, "/sys/class/block/sdb1"),
            sous(&r, "/sys/devices/virtual/block/dm-0/slaves/sdb1"),
        )
        .unwrap();
        symlink(
            sous(&r, "/sys/devices/virtual/block/dm-0"),
            sous(&r, "/sys/class/block/dm-0"),
        )
        .unwrap();
        ecrire("/dev/dm-0", "");
        std::fs::create_dir_all(sous(&r, "/dev/mapper")).unwrap();
        symlink("../dm-0", sous(&r, "/dev/mapper/coffre")).unwrap();
        std::fs::create_dir_all(sous(&r, "/dev/disk/by-label")).unwrap();
        symlink("../../sdb1", sous(&r, "/dev/disk/by-label/MA\\x20CLE")).unwrap();
        let mountinfo = "22 1 259:2 / / rw - ext4 /dev/sda2 rw\n\
                         30 22 8:17 /@donnees /run/media/alice/sous-volume rw - btrfs /dev/sdc1 rw\n\
                         31 22 8:17 / /run/media/alice/disque\\040USB rw - btrfs /dev/sdc1 rw\n\
                         32 22 8:17 / /run/media/alice/MA\\040CLE rw - vfat /dev/sdb1 rw\n\
                         33 22 254:0 / /run/media/alice/coffre rw - ext4 /dev/mapper/coffre rw\n\
                         34 22 0:5 / /proc rw - proc proc rw\n\
                         35 22 8:1 / /boot rw - vfat /dev/sda1 rw\n";
        let v = volumes_amovibles_sous(&r, mountinfo);
        let points: Vec<&std::path::Path> = v.iter().map(|(p, _)| p.as_path()).collect();
        assert_eq!(
            points,
            [
                std::path::Path::new("/run/media/alice/disque USB"),
                std::path::Path::new("/run/media/alice/MA CLE"),
                std::path::Path::new("/run/media/alice/coffre")
            ]
        );
        assert!(v[1].1.starts_with("MA CLE · 29"), "{}", v[1].1);
        assert_eq!(v[2].1, "1M");
        let _ = std::fs::remove_dir_all(&r);
    }

    /// Sur cet ordinateur, chaque volume amovible que lsblk montre se retrouve dans la lecture directe, avec la
    /// même étiquette ; en plus, seulement des volumes chiffrés ou LVM posés sur un disque amovible.
    #[cfg(target_os = "linux")]
    #[test]
    fn volumes_comme_lsblk() {
        let Some(r) = crate::commande::lancer(
            Command::new("lsblk").args(["-Pno", "RM,HOTPLUG,LABEL,SIZE,MOUNTPOINT"]),
            10,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("lsblk absent");
        };
        let Ok(montages) = std::fs::read_to_string("/proc/self/mountinfo") else {
            return crate::essais::saute("/proc/self/mountinfo illisible");
        };
        let lus = volumes_amovibles_sous(std::path::Path::new("/"), &montages);
        let dits = lire_lsblk(&r.sortie);
        for (point, nom) in &dits {
            let etiquette = |n: &str| n.rsplit_once(" · ").map(|(e, _)| e.to_string());
            let trouve = lus.iter().find(|(p, _)| p == point);
            assert!(trouve.is_some(), "{point:?} : {lus:?}");
            assert_eq!(etiquette(nom), etiquette(&trouve.unwrap().1), "{point:?}");
        }
        for (point, _) in &lus {
            let dm = montages.lines().any(|l| {
                l.contains(&format!(" {} ", point.display().to_string().replace(' ', "\\040")))
                    && (l.contains(" /dev/mapper/") || l.contains(" /dev/dm-"))
            });
            assert!(dm || dits.iter().any(|(p, _)| p == point), "{point:?} : {dits:?}");
        }
    }

    #[test]
    fn pieges_de_cle() {
        let e = |l: &[(&str, bool)]| l.iter().map(|(n, d)| ((*n).to_string(), *d)).collect::<Vec<_>>();
        // Ver de raccourcis : dossier caché + raccourci du même nom, autorun, script.
        let s = signes_de_ver(&e(&[
            ("Photos", true),
            ("Photos.lnk", false),
            ("autorun.inf", false),
            ("x.vbs", false),
            ("notes.txt", false),
        ]));
        assert_eq!(s.len(), 3);
        assert_eq!(s.iter().filter(|(n, _)| *n == Niveau::Eleve).count(), 2);
        // Clé normale.
        assert_eq!(
            signes_de_ver(&e(&[
                ("Photos", true),
                ("cv.pdf", false),
                ("jeu.lnk", false),
                ("a", false),
                ("b", false)
            ])),
            vec![]
        );
        // Clé Vanguard : son autorun et son lanceur sont attendus.
        assert_eq!(
            signes_de_ver(&e(&[("vanguard.cle", false), ("autorun.inf", false)])),
            vec![]
        );
    }

    #[test]
    fn menaces_de_defender() {
        let sortie = "Scan starting...\nScan finished.\nScanning C:\\Users\\alice\\Downloads\\x.exe found 1 threats.\n\n\
                      ----------------------------- Threat information ------------------------------\n\
                      Threat                  : Virus:DOS/EICAR_Test_File\n\
                      Resources               : 1 total\n";
        assert_eq!(menaces_mpcmdrun(sortie), ["Virus:DOS/EICAR_Test_File"]);
        assert_eq!(
            lire_mpcmdrun(Some(2), sortie, false),
            Examen::Trouve(vec!["Virus:DOS/EICAR_Test_File".into()])
        );
        // Nommée, la menace l'emporte même sur une phrase « skipped » ailleurs dans la sortie.
        assert!(matches!(
            lire_mpcmdrun(Some(2), &format!("{sortie}Scanning C:\\autre was skipped.\n"), true),
            Examen::Trouve(_)
        ));
        // Fichier exclu de Defender : code 2, rien d'analysé, ce n'est pas une menace (CI de GitHub).
        let saute = "Scan starting...\nScan finished.\n  Scanning C:\\Users\\alice\\notes.txt was skipped.  \n";
        assert!(matches!(lire_mpcmdrun(Some(2), saute, true), Examen::Impossible(r) if r == raison_sautee()));
        // La phrase dans le nom du fichier, ou une menace comptée sans être nommée : pas un saut.
        for piege in [
            "Scanning C:\\Users\\alice\\facture was skipped.exe found 1 threats.\n",
            "Scanning C:\\a was skipped. b.exe found 1 threats.\nScanning C:\\a was skipped.\n",
            "Scan finished. was skipped.\n",
        ] {
            assert!(
                matches!(lire_mpcmdrun(Some(2), piege, true), Examen::Trouve(_)),
                "{piege}"
            );
        }
        // La ligne citée a une borne, quel que soit le chemin.
        let long = format!("Scanning C:\\{} found 1 threats.\n", "a".repeat(5000));
        let Examen::Trouve(n) = lire_mpcmdrun(Some(2), &long, true) else {
            panic!("long")
        };
        assert!(n[0].chars().count() < 300, "{}", n[0].len());
        // Sauté mais le fichier a disparu : Defender l'a retiré, c'est une menace.
        assert!(matches!(lire_mpcmdrun(Some(2), saute, false), Examen::Trouve(_)));
        // Sortie inattendue : la menace est quand même dite, avec la dernière ligne de MpCmdRun pour comprendre.
        let Examen::Trouve(noms) = lire_mpcmdrun(Some(2), "Scan starting...\nAnalyse terminée\x1b[2K\n", true) else {
            panic!("code 2 sans nom")
        };
        assert_eq!(noms.len(), 1);
        assert!(noms[0].contains("Analyse terminée�[2K"), "{noms:?}");
        assert!(matches!(lire_mpcmdrun(Some(2), "", true), Examen::Trouve(n) if n.len() == 1));
        assert_eq!(menaces_mpcmdrun(""), Vec::<String>::new());
        assert_eq!(lire_mpcmdrun(Some(0), "", true), Examen::Sain);
        assert!(matches!(lire_mpcmdrun(Some(1), "", true), Examen::Impossible(_)));
        assert!(matches!(lire_mpcmdrun(None, "", true), Examen::Impossible(_)));
        assert_eq!(
            menaces_mpcmdrun("Threat                  : Trojan\x1b[2K\rFaux\u{202e}\n"),
            ["Trojan�[2K�Faux�"]
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn resultat_clamscan() {
        let bilan = |infectes: u64, erreurs: u64| {
            format!(
                "\n----------- SCAN SUMMARY -----------\nScanned files: 12683\nInfected files: {infectes}\nTotal errors: {erreurs}\n"
            )
        };
        // Cas réel : 0 infecté, 7 dossiers de /tmp illisibles, code 2 → analyse valable.
        let r = lire_resultat(Some(2), &bilan(0, 7)).unwrap();
        assert_eq!((r.infectes.len(), r.analyses, r.illisibles), (0, 12683, 7));
        let deux = format!(
            "/home/x/Téléchargements/eicar.com: Eicar-Test-Signature FOUND\n/tmp/a b.exe: Win.Trojan.Agent-123 FOUND\n{}",
            bilan(2, 0)
        );
        let r = lire_resultat(Some(1), &deux).unwrap();
        assert_eq!(
            r.infectes[1],
            ("/tmp/a b.exe".to_string(), "Win.Trojan.Agent-123".to_string())
        );
        // Pas de bilan (base absente, plantage) : jamais « aucun malware ».
        assert!(lire_resultat(Some(2), "ERROR: Can't open database").is_none());
        assert!(lire_resultat(None, &bilan(0, 0)).is_none());
        // Infectés annoncés mais lignes illisibles : pas fiable.
        assert!(lire_resultat(Some(1), &bilan(1, 0)).is_none());
    }

    #[test]
    fn dossiers_analyses_une_seule_fois() {
        let base = std::env::temp_dir().join(format!("vanguard-cibles-{}", std::process::id()));
        let bureau = base.join("Bureau");
        std::fs::create_dir_all(bureau.join("sous")).unwrap();
        std::os::unix::fs::symlink(&bureau, base.join("Desktop")).unwrap();
        let reel = bureau.canonicalize().unwrap();
        // Desktop → Bureau, et un sous-dossier de Bureau : il ne reste que Bureau.
        assert_eq!(
            sans_doublons(vec![base.join("Desktop"), bureau.clone(), bureau.join("sous")]),
            vec![reel]
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn exclusions_en_expression_reguliere() {
        assert_eq!(regex_echappe(".steam"), "/\\.steam(/|$)");
    }

    /// E5-I1 (campagne 5) : le dossier des signatures choisi dans freshclam.conf est lu ; une ligne mise en
    /// commentaire ne compte pas, la dernière l'emporte.
    #[cfg(unix)]
    #[test]
    fn base_dans_le_dossier_de_freshclam_conf() {
        let d = std::env::temp_dir().join(format!("vanguard-base-clamav-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let conf = format!(
            "# DatabaseDirectory /var/lib/ailleurs\nDatabaseMirror database.clamav.net\nDatabaseDirectory /nulle/part\n  DatabaseDirectory \"{}\"\n",
            d.display()
        );
        assert_eq!(dossier_de_la_base(&conf), Some(d.clone()));
        assert_eq!(dossier_de_la_base("#DatabaseDirectory /x\nUpdateLogFile /y\n"), None);
        assert!(!base_dans(&d));
        std::fs::write(d.join("main.cvd"), b"").unwrap();
        assert!(base_dans(&d));
        // La configuration l'emporte sur un dossier fixe qui a aussi une base ; sans elle, le dossier fixe.
        let fixe = d.join("fixe");
        std::fs::create_dir(&fixe).unwrap();
        std::fs::write(fixe.join("daily.cld"), b"").unwrap();
        let chemin_conf = d.join("freshclam.conf");
        std::fs::write(&chemin_conf, &conf).unwrap();
        let (c, f) = (chemin_conf.to_str().unwrap(), fixe.to_str().unwrap());
        assert_eq!(dossier_de_base_parmi(&[c], &[f]), Some(d.clone()));
        assert_eq!(dossier_de_base_parmi(&["/nulle/part.conf"], &[f]), Some(fixe.clone()));
        assert_eq!(dossier_de_base_parmi(&[], &["/nulle/part"]), None);
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// Propriétés de la lecture de lsblk : rien ne plante, quelle que soit la sortie ; une clé amovible bien décrite
/// redonne son point de montage et son étiquette, rendue prête à montrer.
#[cfg(test)]
mod proprietes {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lsblk_sans_plantage(t in prop::collection::vec(prop_oneof![any::<String>(), "([A-Z]+=\"[ -~\u{1b}é]{0,12}\" ?){0,6}"], 0..8)) {
            for (point, nom) in lire_lsblk(&t.join("\n")) {
                prop_assert!(point.is_absolute());
                prop_assert!(!crate::ui::contient_un_piege(&nom));
            }
        }

        #[test]
        fn lsblk_redonne_ses_valeurs(etiquette in "[A-Za-z0-9_-]{1,11}", taille in "[0-9]{1,3}(,[0-9])?[GM]", amovible in prop_oneof![Just("RM=\"1\" HOTPLUG=\"0\""), Just("RM=\"0\" HOTPLUG=\"1\"")]) {
            let ligne = format!("{amovible} LABEL=\"{etiquette}\" SIZE=\"{taille}\" MOUNTPOINT=\"/run/media/alice/{etiquette}\"\n");
            let l = lire_lsblk(&ligne);
            prop_assert_eq!(l.len(), 1);
            prop_assert_eq!(&l[0].0, &PathBuf::from(format!("/run/media/alice/{etiquette}")));
            prop_assert_eq!(&l[0].1, &format!("{etiquette} · {taille}"));
            // Ni amovible ni branchée à chaud : pas une clé.
            prop_assert!(lire_lsblk(&ligne.replace("=\"1\"", "=\"0\"")).is_empty());
        }
    }
}
