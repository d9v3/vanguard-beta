//! Santé de l'ordinateur : espace disque, état des disques (SMART), usure de la batterie, températures.
//! Un disque qui lâche ou plein, c'est des données perdues ; seuls ces deux cas comptent dans la note.
//! Batterie et chaleur sont de simples informations.

use super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Santé";

const GIO: u64 = 1 << 30;

fn taille(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let go = octets as f64 / GIO as f64;
    if go >= 1000.0 {
        trf!("{} To", "{} TB", crate::langue::decimal(go / 1024.0, 1))
    } else if go >= 10.0 {
        trf!("{go:.0} Go", "{go:.0} GB")
    } else {
        trf!("{} Go", "{} GB", crate::langue::decimal(go, 1))
    }
}

/// Un volume monté : point de montage, octets libres (pour l'utilisateur), octets au total.
struct Volume {
    point: String,
    libre: u64,
    total: u64,
}

/// `None` si la place suffit. Petits volumes (partition de démarrage) : seul le pourcentage compte.
fn juger_volume(v: &Volume) -> Option<Constat> {
    if v.total == 0 {
        return None;
    }
    let pourcent = v.libre * 100 / v.total;
    let petit = v.total < 8 * GIO;
    let niveau = if pourcent < 5 || (!petit && v.libre < GIO) {
        Niveau::Eleve
    } else if pourcent < 10 && (petit || v.libre < 20 * GIO) {
        Niveau::Moyen
    } else {
        return None;
    };
    let commande = if cfg!(windows) {
        // « C: » seul désigne le dossier courant sur C:, pas la racine du disque : « C:\ ».
        let racine = crate::commande::ps_texte(&if v.point.ends_with(':') {
            format!("{}\\", v.point)
        } else {
            v.point.clone()
        });
        format!(
            "Get-ChildItem '{racine}' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {{ [pscustomobject]@{{ Go = [math]::Round(((Get-ChildItem $_.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum) / 1GB, 1); Dossier = $_.FullName }} }} | Sort-Object Go -Descending | Select-Object -First 15 | Format-Table -AutoSize"
        )
    } else if cfg!(target_os = "macos") {
        format!(
            "du -xh -d 2 {} 2>/dev/null | sort -h | tail -15",
            crate::commande::sh_chaine(&v.point)
        )
    } else {
        format!(
            "du -xh --max-depth=2 {} 2>/dev/null | sort -h | tail -15",
            crate::commande::sh_chaine(&v.point)
        )
    };
    Some(
        alerte(
            CAT,
            niveau,
            trf!(
                "Disque presque plein : {} n'a plus que {} libres sur {} ({pourcent} %). Un disque plein bloque les mises à jour et peut abîmer des fichiers.",
                "Disk almost full: {} has only {} free out of {} ({pourcent}%). A full disk blocks updates and can damage files.",
                v.point,
                taille(v.libre),
                taille(v.total)
            ),
        )
        .manuel(
            tr!(
                "Voir les plus gros dossiers, puis « Optimiser → Nettoyer le système »",
                "See the biggest folders, then “Optimize → Clean up the system”"
            ),
            &[&commande],
        ),
    )
}

fn constats_volumes(volumes: &[Volume]) -> Vec<Constat> {
    let mut constats: Vec<Constat> = volumes.iter().filter_map(juger_volume).collect();
    if constats.is_empty() && !volumes.is_empty() {
        let resume = volumes
            .iter()
            // « C: » se termine déjà par deux-points : « C: 36 Go libres », pas « C:: ».
            .map(|v| {
                if v.point.ends_with(':') {
                    trf!("{} {} libres", "{} {} free", v.point, taille(v.libre))
                } else {
                    trf!("{} : {} libres", "{}: {} free", v.point, taille(v.libre))
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        constats.push(ok(
            CAT,
            trf!("Espace disque suffisant ({resume}).", "Enough disk space ({resume})."),
        ));
    }
    constats
}

/// État d'un disque d'après SMART.
#[derive(Default)]
struct Disque {
    modele: String,
    /// Le disque annonce lui-même une panne proche (avertissement critique NVMe, SMART « failing »).
    defaillant: bool,
    /// Usure annoncée (NVMe), en pourcentage de sa durée de vie prévue.
    usure: Option<u64>,
    /// Secteurs défectueux (SATA) ou erreurs de support (NVMe).
    erreurs: u64,
    /// Son état SMART n'a pas pu être lu (attributs NVMe refusés, délai dépassé) : ni sain ni malade, non vérifié.
    illisible: bool,
}

fn constats_disques(disques: &[Disque]) -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut sains = Vec::new();
    for d in disques {
        if d.defaillant {
            constats.push(
                alerte(
                    CAT,
                    Niveau::Eleve,
                    trf!(
                        "Le disque {} annonce une panne proche (SMART). Sauvegardez vos fichiers maintenant et prévoyez de le remplacer.",
                        "The {} disk announces an upcoming failure (SMART). Back up your files now and plan to replace it.",
                        d.modele
                    ),
                )
                .manuel(tr!("Sauvegarder puis remplacer le disque", "Back up, then replace the disk"), &[]),
            );
        } else if d.illisible {
            constats.push(impossible(
                CAT,
                &trf!("état SMART du disque {}", "SMART status of the {} disk", d.modele),
            ));
        } else if d.usure.is_some_and(|u| u >= 90) || d.erreurs > 0 {
            let detail = match (d.usure.filter(|u| *u >= 90), d.erreurs) {
                (Some(u), 0) => trf!("usé à {u} %", "{u}% worn"),
                (Some(u), e) => trf!("usé à {u} %, {e} erreur(s)", "{u}% worn, {e} error(s)"),
                (None, e) => trf!("{e} erreur(s) de lecture enregistrée(s)", "{e} read error(s) recorded"),
            };
            constats.push(alerte(
                CAT,
                Niveau::Moyen,
                trf!(
                    "Le disque {} vieillit ({detail}) : gardez une sauvegarde à jour.",
                    "The {} disk is aging ({detail}): keep a backup up to date.",
                    d.modele
                ),
            ));
        } else {
            sains.push(match d.usure {
                Some(u) => trf!("{} (usé à {u} %)", "{} ({u}% worn)", d.modele),
                None => d.modele.clone(),
            });
        }
    }
    if !sains.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "Disques en bonne santé : {}.",
                "Disks in good health: {}.",
                sains.join(", ")
            ),
        ));
    }
    constats
}

fn constat_batterie(sante: u64) -> Constat {
    if sante < 80 {
        alerte(
            CAT,
            Niveau::Info,
            trf!(
                "Batterie usée : elle ne garde plus que {sante} % de sa capacité d'origine (autonomie réduite d'autant).",
                "Worn battery: it holds only {sante}% of its original capacity (battery life reduced accordingly)."
            ),
        )
    } else {
        ok(
            CAT,
            trf!(
                "Batterie en bon état ({sante} % de sa capacité d'origine).",
                "Battery in good condition ({sante}% of its original capacity)."
            ),
        )
    }
}

/// Températures relevées : (composant, degrés, seuil au-delà duquel c'est trop chaud au repos).
fn constat_temperatures(mesures: &[(&'static str, f64, f64)]) -> Option<Constat> {
    if mesures.is_empty() {
        return None;
    }
    let texte = |(nom, t, _): &(&str, f64, f64)| format!("{nom} {t:.0} °C");
    let chauds: Vec<String> = mesures.iter().filter(|(_, t, seuil)| t >= seuil).map(texte).collect();
    Some(if chauds.is_empty() {
        let liste = mesures.iter().map(texte).collect::<Vec<_>>().join(", ");
        ok(
            CAT,
            trf!("Températures normales : {liste}.", "Normal temperatures: {liste}."),
        )
    } else {
        alerte(
            CAT,
            Niveau::Info,
            trf!(
                "Ça chauffe : {}. Au repos, c'est souvent de la poussière dans les ventilateurs ou une pâte thermique sèche.",
                "Running hot: {}. At rest, it is often dust in the fans or dried thermal paste.",
                chauds.join(", ")
            ),
        )
    })
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
fn degres_nvidia() -> Option<f64> {
    let r = crate::commande::lancer(
        crate::commande::systeme("nvidia-smi").args(["--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"]),
        10,
    )?;
    if r.code != Some(0) {
        return None;
    }
    r.sortie
        .lines()
        .filter_map(|l| l.trim().parse::<f64>().ok())
        .reduce(f64::max)
}

#[cfg(target_os = "linux")]
mod systeme {
    use std::path::Path;

    use super::{Disque, Volume};
    use crate::machine::linux::dbus::{Bus, Valeur, service_absent};

    const SYSTEMES_DE_FICHIERS: &[&str] = &[
        "ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3", "zfs", "bcachefs", "jfs",
    ];

    /// Volumes montés (un par périphérique : les sous-volumes btrfs partagent la même place), hors supports amovibles.
    pub fn volumes() -> Vec<Volume> {
        let montages = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        let mut vus = Vec::new();
        let mut volumes = Vec::new();
        for l in montages.lines() {
            let c: Vec<&str> = l.split_whitespace().collect();
            let [peripherique, point, genre, ..] = c[..] else {
                continue;
            };
            // /proc/mounts écrit les espaces en « \040 ».
            let point = point.replace("\\040", " ");
            if !SYSTEMES_DE_FICHIERS.contains(&genre)
                || vus.contains(&peripherique)
                || ["/run/media/", "/media/", "/mnt/", "/var/lib/docker", "/snap/"]
                    .iter()
                    .any(|p| point.starts_with(p))
            {
                continue;
            }
            vus.push(peripherique);
            let Ok(chemin) = std::ffi::CString::new(point.as_bytes()) else {
                continue;
            };
            // SAFETY : statvfs remplit la structure fournie à partir d'un chemin C valide.
            let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statvfs(chemin.as_ptr(), &raw mut s) } != 0 {
                continue;
            }
            #[allow(clippy::useless_conversion)]
            let (bloc, libres, total) = (u64::from(s.f_frsize), u64::from(s.f_bavail), u64::from(s.f_blocks));
            // Seulement montré : prêt à montrer, comme le modèle des disques plus bas.
            volumes.push(Volume {
                point: crate::ui::affichable(&point),
                libre: libres * bloc,
                total: total * bloc,
            });
        }
        volumes
    }

    const UDISKS: &str = "org.freedesktop.UDisks2";

    /// Disques internes lus par udisks2 sur le bus système, sans droits root : NVMe (attributs SMART complets) et
    /// SATA (verdict SMART). Tous les objets d'udisks2 arrivent en un appel (`GetManagedObjects`) ; seuls les
    /// attributs NVMe demandent le leur. Bus ou udisks2 absent : aucun disque, comme avant sans `busctl`. Une
    /// lecture qui échoue, elle, est dite : `Err` pour la liste des disques, `illisible` pour les attributs d'un
    /// disque.
    pub fn disques() -> Result<Vec<Disque>, String> {
        let Ok(mut bus) = Bus::systeme() else {
            return Ok(Vec::new());
        };
        let objets = match bus.objets(UDISKS, "/org/freedesktop/UDisks2") {
            Ok(objets) => objets,
            Err(e) if service_absent(&e) => return Ok(Vec::new()),
            Err(e) => {
                return Err(crate::trf!(
                    "état SMART des disques : {e}",
                    "SMART status of the disks: {e}"
                ));
            }
        };
        let mut disques = Vec::new();
        for (chemin, interfaces) in &objets {
            if !chemin.starts_with("/org/freedesktop/UDisks2/drives/") {
                continue;
            }
            let propriete = |interface: &str, nom: &str| interfaces.champ(interface).and_then(|i| i.champ(nom));
            // Le disque dit son modèle lui-même (une clé USB dit ce qu'elle veut) : lu prêt à montrer.
            let modele = propriete("org.freedesktop.UDisks2.Drive", "Model")
                .and_then(Valeur::texte)
                .map(crate::ui::affichable)
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| crate::ui::affichable(&chemin.rsplit('/').next().unwrap_or("?").replace('_', " ")));
            let nvme = "org.freedesktop.UDisks2.NVMe.Controller";
            if let Some(avertissements) = propriete(nvme, "SmartCriticalWarning") {
                let attributs = bus
                    .appeler(
                        UDISKS,
                        chemin,
                        nvme,
                        "SmartGetAttributes",
                        "a{sv}",
                        vec![Valeur::Dictionnaire(Vec::new())],
                    )
                    .map(|corps| corps.into_iter().next());
                let illisible = attributs.is_err();
                let attributs = attributs.ok().flatten();
                let nombre = |cle: &str| attributs.as_ref().and_then(|a| a.champ(cle)).and_then(Valeur::entier);
                let reserve_epuisee =
                    matches!((nombre("avail_spare"), nombre("spare_thresh")), (Some(r), Some(s)) if r < s);
                disques.push(Disque {
                    modele,
                    defaillant: !avertissements.elements().is_empty() || reserve_epuisee,
                    usure: nombre("percent_used"),
                    erreurs: nombre("media_errors").unwrap_or(0),
                    illisible,
                });
                continue;
            }
            let ata = "org.freedesktop.UDisks2.Drive.Ata";
            if propriete(ata, "SmartEnabled").and_then(Valeur::booleen) == Some(true) {
                disques.push(Disque {
                    modele,
                    defaillant: propriete(ata, "SmartFailing").and_then(Valeur::booleen) == Some(true),
                    usure: None,
                    // SmartNumBadSectors est signé (x) : un négatif n'est pas un nombre de secteurs.
                    erreurs: propriete(ata, "SmartNumBadSectors")
                        .and_then(Valeur::entier)
                        .unwrap_or(0),
                    illisible: false,
                });
            }
        }
        Ok(disques)
    }

    fn lire(chemin: &Path) -> Option<String> {
        std::fs::read_to_string(chemin).ok().map(|t| t.trim().to_string())
    }

    /// Santé de la batterie de l'ordinateur (pas celle d'une souris ou d'une manette), en pourcentage.
    pub fn batterie() -> Option<u64> {
        for e in std::fs::read_dir("/sys/class/power_supply")
            .into_iter()
            .flatten()
            .flatten()
        {
            let d = e.path();
            if lire(&d.join("type")).as_deref() != Some("Battery")
                || lire(&d.join("scope")).as_deref() == Some("Device")
            {
                continue;
            }
            let nombre = |f: &str| lire(&d.join(f)).and_then(|t| t.parse::<u64>().ok());
            let (plein, origine) = match (nombre("energy_full"), nombre("energy_full_design")) {
                (Some(p), Some(o)) => (p, o),
                _ => (nombre("charge_full")?, nombre("charge_full_design")?),
            };
            if let Some(sante) = (plein * 100).checked_div(origine) {
                return Some(sante.min(100));
            }
        }
        None
    }

    /// Températures des capteurs du noyau : processeur, carte graphique AMD, SSD NVMe (le plus chaud de chaque).
    pub fn temperatures() -> Vec<(&'static str, f64, f64)> {
        let mut processeur: Option<f64> = None;
        let mut graphique: Option<f64> = None;
        let mut ssd: Option<f64> = None;
        for e in std::fs::read_dir("/sys/class/hwmon").into_iter().flatten().flatten() {
            let d = e.path();
            let nom = lire(&d.join("name")).unwrap_or_default();
            let mut valeurs = Vec::new();
            for n in 1..=16 {
                let Some(t) = lire(&d.join(format!("temp{n}_input"))).and_then(|t| t.parse::<f64>().ok()) else {
                    continue;
                };
                valeurs.push((lire(&d.join(format!("temp{n}_label"))).unwrap_or_default(), t / 1000.0));
            }
            let choisir = |etiquettes: &[&str]| {
                valeurs
                    .iter()
                    .filter(|(l, _)| etiquettes.is_empty() || etiquettes.iter().any(|e| l.starts_with(e)))
                    .map(|(_, t)| *t)
                    .reduce(f64::max)
                    .or_else(|| valeurs.iter().map(|(_, t)| *t).reduce(f64::max))
            };
            let plus_chaud = |actuel: Option<f64>, nouveau: Option<f64>| match (actuel, nouveau) {
                (Some(a), Some(n)) => Some(a.max(n)),
                (a, n) => a.or(n),
            };
            match nom.as_str() {
                "k10temp" | "zenpower" | "coretemp" | "cpu_thermal" => {
                    processeur = plus_chaud(processeur, choisir(&["Tctl", "Tdie", "Package"]));
                }
                "amdgpu" | "nouveau" => graphique = plus_chaud(graphique, choisir(&["edge"])),
                "nvme" => ssd = plus_chaud(ssd, choisir(&["Composite"])),
                _ => {}
            }
        }
        let mut mesures = Vec::new();
        if let Some(t) = processeur {
            mesures.push((crate::tr!("processeur", "processor"), t, 90.0));
        }
        if let Some(t) = super::degres_nvidia().or(graphique) {
            mesures.push((crate::tr!("carte graphique", "graphics card"), t, 88.0));
        }
        if let Some(t) = ssd {
            mesures.push(("SSD", t, 75.0));
        }
        mesures
    }
}

#[cfg(target_os = "macos")]
mod systeme {
    use super::{Disque, Volume};

    fn sortie(cmd: &str, args: &[&str]) -> String {
        crate::commande::lancer(std::process::Command::new(cmd).args(args), 20)
            .map(|r| r.sortie)
            .unwrap_or_default()
    }

    /// Le volume de données (le volume système scellé partage la même place), par statfs : ce que lit `df`, sans le
    /// lancer. Libre = la place disponible pour un compte ordinaire (la colonne « Available » de df).
    pub fn volumes() -> Vec<Volume> {
        let point = if std::path::Path::new("/System/Volumes/Data").is_dir() {
            c"/System/Volumes/Data"
        } else {
            c"/"
        };
        // SAFETY : une struct statfs faite de nombres, que statfs remplit avant toute lecture.
        let mut infos: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY : chemin C terminé par un nul, infos vit pendant l'appel.
        if unsafe { libc::statfs(point.as_ptr(), &raw mut infos) } != 0 {
            return Vec::new();
        }
        let bloc = u64::from(infos.f_bsize);
        vec![Volume {
            point: "/".into(),
            libre: infos.f_bavail.saturating_mul(bloc),
            total: infos.f_blocks.saturating_mul(bloc),
        }]
    }

    /// Disques physiques internes et leur état SMART selon diskutil (« Verified », « Failing », « Not Supported »),
    /// lus dans ses sorties -plist : des clés qui ne changent pas avec la langue du Mac.
    pub fn disques() -> Vec<Disque> {
        let liste = crate::plist::lire(sortie("diskutil", &["list", "-plist", "internal", "physical"]).as_bytes());
        liste
            .as_ref()
            .map(crate::machine::darwin::disques_entiers)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|disque| {
                let info = crate::machine::darwin::info_disque(&crate::plist::lire(
                    sortie("diskutil", &["info", "-plist", &disque]).as_bytes(),
                )?);
                let etat = info.smart?;
                (etat != "Not Supported").then(|| Disque {
                    modele: crate::ui::affichable(&info.modele.unwrap_or(disque)),
                    defaillant: etat == "Failing",
                    ..Disque::default()
                })
            })
            .collect()
    }

    /// Santé de la batterie en % : capacité maximale actuelle / capacité d'origine, d'après `ioreg -a` (sa sortie en
    /// plist, lue par crate::plist).
    pub fn batterie() -> Option<u64> {
        let ioreg = sortie("ioreg", &["-a", "-rn", "AppleSmartBattery"]);
        crate::machine::darwin::sante_batterie(&crate::plist::lire(ioreg.as_bytes())?)
    }

    /// Les capteurs de température demandent les droits root sous macOS (powermetrics) : rien sans eux.
    pub fn temperatures() -> Vec<(&'static str, f64, f64)> {
        Vec::new()
    }
}

#[cfg(windows)]
mod systeme {
    use super::{Disque, Volume};

    use crate::machine::windows::wmi::{self, Ligne};

    const STOCKAGE: &str = r"root\Microsoft\Windows\Storage";

    /// Les quatre lectures, chacune avec son script de secours : volumes fixes, disques physiques, batterie,
    /// zones thermiques.
    const SCRIPTS: [(&str, &str); 4] = [
        (
            "VOL",
            "try { Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' } | ForEach-Object { \
             \"VOL|$($_.DriveLetter):|$($_.SizeRemaining)|$($_.Size)\" }; 'VOL_FIN' } catch {}",
        ),
        (
            "DSK",
            "try { Get-PhysicalDisk | ForEach-Object { \"DSK|$($_.HealthStatus)|$($_.FriendlyName)\" }; 'DSK_FIN' } catch {}",
        ),
        (
            "BAT",
            "try { $p = @(Get-CimInstance -Namespace root\\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop)[0].FullChargedCapacity; \
             $o = @(Get-CimInstance -Namespace root\\wmi -ClassName BatteryStaticData -ErrorAction Stop)[0].DesignedCapacity; \
             if ($p -and $o) { \"BAT|$p|$o\" }; 'BAT_FIN' } catch {}",
        ),
        (
            "TZ",
            "try { Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction Stop | ForEach-Object { \
             \"TZ|$($_.HighPrecisionTemperature)\" }; 'TZ_FIN' } catch {}",
        ),
    ];

    /// Un texte de champ comme PowerShell l'écrirait (`$($_.Champ)`) : vide s'il manque.
    fn texte(ligne: &Ligne, champ: &str) -> String {
        match &ligne[champ] {
            wmi::Valeur::Texte(t) => t.clone(),
            wmi::Valeur::Entier(n) => n.to_string(),
            _ => String::new(),
        }
    }

    /// Volumes fixes avec une lettre (MSFT_Volume : DriveType 3 = Fixed ; la lettre est un caractère UTF-16).
    fn volumes_wmi() -> Option<Vec<String>> {
        let lignes = wmi::requete(
            STOCKAGE,
            "MSFT_Volume",
            "DriveType = 3",
            &["DriveLetter", "SizeRemaining", "Size"],
        )?;
        Some(
            lignes
                .iter()
                .filter_map(|l| {
                    let lettre = u32::try_from(l["DriveLetter"].entier()?)
                        .ok()
                        .and_then(char::from_u32)?;
                    (lettre != '\0')
                        .then(|| format!("VOL|{lettre}:|{}|{}", texte(l, "SizeRemaining"), texte(l, "Size")))
                })
                .collect(),
        )
    }

    /// État de chaque disque (MSFT_PhysicalDisk.HealthStatus), écrit comme Get-PhysicalDisk l'écrit.
    /// Sous Wine, cette classe n'est qu'une ébauche (« Wine disk », toujours Healthy) : rien à en conclure là-bas,
    /// et aucun test ne s'appuie sur cet état.
    fn disques_wmi() -> Option<Vec<String>> {
        let lignes = wmi::requete(STOCKAGE, "MSFT_PhysicalDisk", "", &["HealthStatus", "FriendlyName"])?;
        Some(
            lignes
                .iter()
                .map(|l| {
                    let etat = match l["HealthStatus"].entier() {
                        Some(0) => "Healthy",
                        Some(1) => "Warning",
                        Some(2) => "Unhealthy",
                        _ => "Unknown",
                    };
                    format!("DSK|{etat}|{}", texte(l, "FriendlyName"))
                })
                .collect(),
        )
    }

    /// Capacité de la batterie, pleine et d'origine (la première de chaque, comme `@(…)[0]`) ; sans batterie, rien.
    fn batterie_wmi() -> Option<Vec<String>> {
        let plein = wmi::requete(r"root\wmi", "BatteryFullChargedCapacity", "", &["FullChargedCapacity"])?;
        let origine = wmi::requete(r"root\wmi", "BatteryStaticData", "", &["DesignedCapacity"])?;
        let premiere = |l: &[Ligne], champ: &str| l.first().and_then(|x| x[champ].entier()).filter(|n| *n != 0);
        Some(
            premiere(&plein, "FullChargedCapacity")
                .zip(premiere(&origine, "DesignedCapacity"))
                .map(|(p, o)| format!("BAT|{p}|{o}"))
                .into_iter()
                .collect(),
        )
    }

    fn temperatures_wmi() -> Option<Vec<String>> {
        let lignes = wmi::requete(
            r"root\cimv2",
            "Win32_PerfFormattedData_Counters_ThermalZoneInformation",
            "",
            &["HighPrecisionTemperature"],
        )?;
        Some(
            lignes
                .iter()
                .map(|l| format!("TZ|{}", texte(l, "HighPrecisionTemperature")))
                .collect(),
        )
    }

    /// Les sections « NOM|… » puis « NOM_FIN » que lisent les fonctions suivantes : par WMI (quelques millisecondes),
    /// et un seul PowerShell pour celles que WMI n'a pas pu lire.
    pub fn lectures() -> Option<String> {
        let wmi = [volumes_wmi(), disques_wmi(), batterie_wmi(), temperatures_wmi()];
        let mut sortie = String::new();
        let mut secours = Vec::new();
        for ((nom, script), lu) in SCRIPTS.iter().zip(wmi) {
            match lu {
                Some(lignes) => {
                    for l in lignes {
                        sortie.push_str(&l);
                        sortie.push('\n');
                    }
                    sortie.push_str(nom);
                    sortie.push_str("_FIN\n");
                }
                None => secours.push(*script),
            }
        }
        if !secours.is_empty()
            && let Some(ps) = crate::machine::windows::ps(&secours.join("; "))
        {
            sortie.push_str(&ps);
        }
        (!sortie.is_empty()).then_some(sortie)
    }

    pub fn volumes(lectures: Option<&str>) -> Vec<Volume> {
        crate::commande::section(lectures, "VOL")
            .unwrap_or_default()
            .iter()
            .filter_map(|l| {
                let c: Vec<&str> = l.trim().split('|').collect();
                let [point, libre, total] = c[..] else { return None };
                Some(Volume {
                    point: crate::ui::affichable(point),
                    libre: libre.parse().ok()?,
                    total: total.parse().ok()?,
                })
            })
            .collect()
    }

    /// État donné par Windows (Healthy, Warning, Unhealthy) : le pilote lit SMART lui-même.
    pub fn disques(lectures: Option<&str>) -> Vec<Disque> {
        crate::commande::section(lectures, "DSK")
            .unwrap_or_default()
            .iter()
            .filter_map(|l| {
                let (etat, nom) = l.trim().split_once('|')?;
                Some(Disque {
                    modele: crate::ui::affichable(nom),
                    defaillant: etat.eq_ignore_ascii_case("Unhealthy"),
                    usure: None,
                    erreurs: u64::from(etat.eq_ignore_ascii_case("Warning")),
                    illisible: false,
                })
            })
            .collect()
    }

    pub fn batterie(lectures: Option<&str>) -> Option<u64> {
        let l = crate::commande::section(lectures, "BAT")?;
        let (plein, origine) = l.first()?.trim().split_once('|')?;
        let (plein, origine): (u64, u64) = (plein.parse().ok()?, origine.parse().ok()?);
        (plein * 100).checked_div(origine).map(|s| s.min(100))
    }

    /// Zones thermiques de la carte mère (en dixièmes de kelvin, sans droits admin ; souvent le processeur sur un
    /// portable), la plus chaude, et la carte graphique NVIDIA. Une VM n'a pas de zone thermique.
    pub fn temperatures(lectures: Option<&str>) -> Vec<(&'static str, f64, f64)> {
        let mut mesures = Vec::new();
        let zone = crate::commande::section(lectures, "TZ")
            .unwrap_or_default()
            .iter()
            .filter_map(|l| l.trim().parse::<f64>().ok())
            .map(|dixiemes_kelvin| dixiemes_kelvin / 10.0 - 273.15)
            // Zones factices de certaines cartes mères (0 K ou valeur figée absurde).
            .filter(|t| (5.0..130.0).contains(t))
            .reduce(f64::max);
        if let Some(t) = zone {
            mesures.push((crate::tr!("zone thermique", "thermal zone"), t, 90.0));
        }
        if let Some(t) = super::degres_nvidia() {
            mesures.push((crate::tr!("carte graphique", "graphics card"), t, 88.0));
        }
        mesures
    }
}

pub fn sante() -> Vec<Constat> {
    #[cfg(unix)]
    let (volumes, disques, batterie) = (systeme::volumes(), systeme::disques(), systeme::batterie());
    #[cfg(windows)]
    let lectures = systeme::lectures();
    #[cfg(windows)]
    let (volumes, disques, batterie) = (
        systeme::volumes(lectures.as_deref()),
        systeme::disques(lectures.as_deref()),
        systeme::batterie(lectures.as_deref()),
    );
    // Seul Linux sait dire que la liste des disques n'a pas pu être lue.
    #[cfg(not(target_os = "linux"))]
    let disques: Result<_, String> = Ok(disques);
    let mut constats = constats_volumes(&volumes);
    match disques {
        Ok(disques) => constats.extend(constats_disques(&disques)),
        Err(raison) => constats.push(impossible(CAT, &raison)),
    }
    constats.extend(batterie.map(constat_batterie));
    #[cfg(unix)]
    let temperatures = systeme::temperatures();
    #[cfg(windows)]
    let temperatures = systeme::temperatures(lectures.as_deref());
    constats.extend(constat_temperatures(&temperatures));
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chaque section rendue est complète (son marqueur de fin) et lisible par les fonctions de toujours ; sous Wine,
    /// une classe absente n'est pas une section vide.
    #[cfg(windows)]
    #[test]
    fn lectures_windows_completes() {
        if let Some(lu) = systeme::lectures().as_deref() {
            for nom in ["VOL", "DSK", "BAT", "TZ"] {
                let lignes = lu.lines().filter(|l| l.starts_with(&format!("{nom}|"))).count();
                assert!(lignes == 0 || lu.lines().any(|l| l == format!("{nom}_FIN")), "{nom}");
            }
            for v in systeme::volumes(Some(lu)) {
                assert!(v.point.ends_with(':') && v.total >= v.libre);
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lecture_de_diskutil() {
        let plist = "<dict>\n\t<key>MediaName</key>\n\t<string>APPLE SSD AP0512Z</string>\n\t<key>SMARTStatus</key>\n\t<string>Verified</string>\n</dict>";
        let info = crate::machine::darwin::info_disque(&crate::plist::lire(plist.as_bytes()).unwrap());
        assert_eq!(info.smart.as_deref(), Some("Verified"));
        assert_eq!(info.modele.as_deref(), Some("APPLE SSD AP0512Z"));
        assert_eq!(info.taille, None);
    }

    #[test]
    fn place_sur_les_disques() {
        let v = |libre: u64, total: u64| Volume {
            point: "/".into(),
            libre: libre * GIO,
            total: total * GIO,
        };
        assert!(juger_volume(&v(500, 1800)).is_none());
        // 30 Go libres sur 1 To : 3 %, sous le seuil de 5 %.
        assert_eq!(juger_volume(&v(30, 1000)).unwrap().probleme, Some(Niveau::Eleve));
        assert_eq!(juger_volume(&v(15, 200)).unwrap().probleme, Some(Niveau::Moyen));
        // 60 Go libres sur 1 To (6 %) : assez de place, pas d'alerte.
        assert!(juger_volume(&v(60, 1000)).is_none());
        // Petite partition de démarrage (1 Go) : 8 % libres = moyen, sous 5 % = élevé (un noyau ne s'installe plus).
        let demarrage = |libre| Volume {
            point: "/boot".into(),
            libre,
            total: GIO,
        };
        assert_eq!(
            juger_volume(&demarrage(GIO / 12)).unwrap().probleme,
            Some(Niveau::Moyen)
        );
        assert_eq!(
            juger_volume(&demarrage(GIO / 25)).unwrap().probleme,
            Some(Niveau::Eleve)
        );
        assert_eq!(constats_volumes(&[v(500, 1800)])[0].probleme, None);
    }

    #[test]
    fn etat_des_disques() {
        let d = |defaillant, usure, erreurs| Disque {
            modele: "SSD".into(),
            defaillant,
            usure,
            erreurs,
            illisible: false,
        };
        assert_eq!(constats_disques(&[d(false, Some(6), 0)])[0].probleme, None);
        assert_eq!(
            constats_disques(&[d(true, Some(6), 0)])[0].probleme,
            Some(Niveau::Eleve)
        );
        assert_eq!(
            constats_disques(&[d(false, Some(95), 0)])[0].probleme,
            Some(Niveau::Moyen)
        );
        assert_eq!(constats_disques(&[d(false, None, 3)])[0].probleme, Some(Niveau::Moyen));
        // SMART illisible : non vérifié, jamais « en bonne santé » ; un disque qui annonce lui-même sa panne le reste.
        let illisible = |defaillant| Disque {
            illisible: true,
            ..d(defaillant, None, 0)
        };
        let c = constats_disques(&[illisible(false), d(false, Some(6), 0)]);
        assert_eq!(c.len(), 2);
        assert!(!c[0].verifie && c[0].message.contains("SSD"));
        assert!(c[1].verifie && c[1].probleme.is_none());
        assert_eq!(constats_disques(&[illisible(true)])[0].probleme, Some(Niveau::Eleve));
        assert_eq!(constat_batterie(72).probleme, Some(Niveau::Info));
        assert_eq!(
            constat_temperatures(&[("processeur", 43.0, 90.0)]).unwrap().probleme,
            None
        );
        assert_eq!(
            constat_temperatures(&[("processeur", 96.0, 90.0)]).unwrap().probleme,
            Some(Niveau::Info)
        );
        assert!(constat_temperatures(&[]).is_none());
    }

    /// Sur cet ordinateur, quand `busctl` répond : les disques lus par le client D-Bus sont ceux que `busctl` lisait
    /// (modèle, usure NVMe, erreurs de support).
    #[cfg(target_os = "linux")]
    #[test]
    fn disques_comme_busctl() {
        let busctl = |args: &[&str]| {
            crate::commande::lancer(std::process::Command::new("busctl").args(args), 10)
                .filter(|r| r.code == Some(0))
                .map(|r| r.sortie)
        };
        let json = |args: &[&str]| {
            let mut tous = vec!["--json=short"];
            tous.extend(args);
            busctl(&tous)
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .map(|v| v["data"].clone())
        };
        let Some(arbre) = busctl(&["--list", "tree", "org.freedesktop.UDisks2"]) else {
            return crate::essais::saute("busctl ou UDisks2 absent");
        };
        let mut attendus = Vec::new();
        for chemin in arbre
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("/org/freedesktop/UDisks2/drives/"))
        {
            let propriete = |i: &str, n: &str| json(&["get-property", "org.freedesktop.UDisks2", chemin, i, n]);
            let nvme = "org.freedesktop.UDisks2.NVMe.Controller";
            let modele =
                propriete("org.freedesktop.UDisks2.Drive", "Model").and_then(|v| v.as_str().map(crate::ui::affichable));
            if propriete(nvme, "SmartCriticalWarning").is_some() {
                let a = json(&[
                    "call",
                    "org.freedesktop.UDisks2",
                    chemin,
                    nvme,
                    "SmartGetAttributes",
                    "a{sv}",
                    "0",
                ])
                .and_then(|d| d.get(0).cloned())
                .unwrap_or_default();
                attendus.push((
                    modele,
                    a["percent_used"]["data"].as_u64(),
                    a["media_errors"]["data"].as_u64().unwrap_or(0),
                ));
            } else if propriete("org.freedesktop.UDisks2.Drive.Ata", "SmartEnabled").and_then(|v| v.as_bool())
                == Some(true)
            {
                attendus.push((modele, None, 0));
            }
        }
        let lus: Vec<_> = systeme::disques()
            .expect("busctl lit udisks2 : le client D-Bus aussi")
            .into_iter()
            .map(|d| (Some(d.modele), d.usure, if d.usure.is_some() { d.erreurs } else { 0 }))
            .collect();
        assert_eq!(lus, attendus);
    }
}
