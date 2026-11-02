//! Le matériel, pour le relevé local (plan d'auto-amélioration, §1) : des classes fermées (fabricant, sorte de disque,
//! machine virtuelle, mémoire arrondie à une puissance de 2), et le seul modèle du processeur en voie ouverte, nettoyé.
//! Jamais de numéro de série, jamais `journal::systeme()`, jamais de commande : des lectures natives seulement (/proc
//! et /sys sous Linux, WMI et le registre sous Windows, sysctl sous macOS). Ce qui n'a pas pu être lu le dit
//! (`TroisEtats::Inconnu`, `Disque::Inconnu`).

use crate::compte_rendu::envoi::{
    COEURS_MAX, Disque, FILS_MAX, Graphique, Materiel, MemoireGo, Nombre, Processeur, TroisEtats, Virtuelle,
};

/// Le fichier du matériel n'a pas de raison de dépasser quelques centaines d'octets.
pub(crate) const MATERIEL_MAX: usize = 4096;

/// Le matériel de cet ordinateur ; `None` si l'essentiel (processeur, mémoire) n'a pas pu être lu.
pub(crate) fn lire() -> Option<Materiel> {
    systeme::lire()
}

/// Le fabricant du processeur, d'après ce que le processeur dit de lui-même (`vendor_id`, `Manufacturer`, marque).
pub(crate) fn processeur_de(vendeur: &str) -> Processeur {
    let v = vendeur.to_ascii_lowercase();
    if v.contains("intel") {
        Processeur::Intel
    } else if v.contains("amd") || v.contains("advanced micro") {
        Processeur::Amd
    } else if v.contains("apple") {
        Processeur::Apple
    } else if v.contains("qualcomm") || v.contains("snapdragon") {
        Processeur::Qualcomm
    } else {
        Processeur::Autre
    }
}

/// Le fabricant d'une carte graphique, d'après son identifiant PCI de fabricant.
pub(crate) fn graphique_de_pci(fabricant: u32) -> Graphique {
    match fabricant {
        0x10de => Graphique::Nvidia,
        0x1002 | 0x1022 => Graphique::Amd,
        0x8086 => Graphique::Intel,
        0x106b => Graphique::Apple,
        0x5143 => Graphique::Qualcomm,
        _ => Graphique::Autre,
    }
}

/// Parmi plusieurs cartes, celle qui compte pour les lenteurs : la carte dédiée avant celle du processeur.
pub(crate) fn principale(cartes: impl IntoIterator<Item = Graphique>) -> Graphique {
    let rang = |g: &Graphique| match g {
        Graphique::Nvidia => 0,
        Graphique::Amd => 1,
        Graphique::Apple | Graphique::Qualcomm => 2,
        Graphique::Autre => 3,
        Graphique::Intel => 4,
        Graphique::Aucune => 5,
    };
    cartes.into_iter().min_by_key(rang).unwrap_or(Graphique::Aucune)
}

/// La machine virtuelle, d'après le fabricant et le modèle que le micrologiciel annonce.
pub(crate) fn virtuelle_de(fabricant: &str, modele: &str) -> Option<Virtuelle> {
    let t = format!("{fabricant} {modele}").to_ascii_lowercase();
    if t.contains("vmware") {
        Some(Virtuelle::Vmware)
    } else if t.contains("virtualbox") || t.contains("innotek") {
        Some(Virtuelle::Virtualbox)
    } else if t.contains("parallels") {
        Some(Virtuelle::Parallels)
    } else if t.contains("qemu") || t.contains("kvm") || t.contains("bochs") {
        Some(Virtuelle::Kvm)
    } else if t.contains("microsoft") && t.contains("virtual") {
        Some(Virtuelle::Hyperv)
    } else {
        None
    }
}

/// La mémoire en Go, arrondie : le total que le système voit, un peu sous la barrette (le noyau en garde), compté au
/// Go supérieur avant l'arrondi à la puissance de 2.
pub(crate) fn memoire_de_octets(octets: u64) -> MemoireGo {
    MemoireGo::arrondie(octets.div_ceil(1 << 30))
}

/// Le modèle du processeur, nettoyé comme tout nom venu de l'ordinateur ; refusé, il manque, c'est tout.
fn modele(brut: &str) -> Option<crate::amelioration::NomLogiciel> {
    let brut = brut.split_whitespace().collect::<Vec<_>>().join(" ");
    super::nom(&brut).ok()
}

fn nombre<const M: u32>(n: u64) -> Option<Nombre<M>> {
    Nombre::new(n.min(u64::from(M)))
}

/// Les fils du processeur, que la bibliothèque standard lit sans commande.
fn fils() -> u64 {
    std::thread::available_parallelism().map_or(1, |n| u64::try_from(n.get()).unwrap_or(1))
}

#[cfg(target_os = "linux")]
mod systeme {
    use super::*;
    use std::collections::BTreeSet;
    use std::io::Read;
    use std::path::{Path, PathBuf};

    /// Un petit fichier de /proc ou /sys, en texte, borné.
    fn court(chemin: &Path, max: u64) -> Option<String> {
        let mut t = String::new();
        std::fs::File::open(chemin)
            .ok()?
            .take(max)
            .read_to_string(&mut t)
            .ok()?;
        Some(t)
    }

    fn mot(chemin: impl AsRef<Path>) -> Option<String> {
        court(chemin.as_ref(), 256).map(|t| t.trim().to_string())
    }

    /// La valeur d'une ligne « clé : valeur » de /proc/cpuinfo.
    pub(crate) fn champ<'a>(ligne: &'a str, cle: &str) -> Option<&'a str> {
        let (k, v) = ligne.split_once(':')?;
        (k.trim() == cle).then(|| v.trim())
    }

    /// Fabricant, modèle et cœurs, d'après /proc/cpuinfo : les paires (boîtier, cœur) distinctes ; sans elles
    /// (processeurs ARM), un cœur par fil.
    pub(crate) fn processeur(cpuinfo: &str) -> (Processeur, Option<String>, u64) {
        let mut vendeur = None;
        let mut modele = None;
        let mut paires = BTreeSet::new();
        let mut boitier = "";
        for l in cpuinfo.lines() {
            if let Some(v) = champ(l, "vendor_id") {
                vendeur.get_or_insert(v.to_string());
            } else if let Some(v) = champ(l, "CPU implementer") {
                // Les fabricants ARM (0x41 ARM, 0x51 Qualcomm, 0x61 Apple).
                let p = match v {
                    "0x51" => "qualcomm",
                    "0x61" => "apple",
                    _ => "autre",
                };
                vendeur.get_or_insert(p.to_string());
            } else if let Some(v) = champ(l, "model name").or_else(|| champ(l, "Hardware")) {
                modele.get_or_insert(v.to_string());
            } else if let Some(v) = champ(l, "physical id") {
                boitier = v;
            } else if let Some(v) = champ(l, "core id") {
                paires.insert((boitier, v));
            }
        }
        let coeurs = u64::try_from(paires.len()).unwrap_or(0);
        (processeur_de(vendeur.as_deref().unwrap_or("")), modele, coeurs)
    }

    /// « MemTotal: 16318324 kB » en octets.
    pub(crate) fn memoire(meminfo: &str) -> Option<u64> {
        let v = meminfo.lines().find_map(|l| champ(l, "MemTotal"))?;
        let kio: u64 = v.split_whitespace().next()?.parse().ok()?;
        kio.checked_mul(1024)
    }

    /// Le périphérique monté sur « / », d'après /proc/self/mounts.
    pub(crate) fn racine(mounts: &str) -> Option<&str> {
        mounts.lines().find_map(|l| {
            let mut m = l.split_whitespace();
            let dev = m.next()?;
            (m.next()? == "/" && dev.starts_with("/dev/")).then_some(dev)
        })
    }

    /// Le disque sous un périphérique de bloc : la partition remonte à son disque, un volume chiffré ou logique
    /// (dm-N) au premier de ses dessous ; trois étages au plus.
    fn disque_de(nom: &str, etages: u8) -> Disque {
        let bloc = PathBuf::from("/sys/class/block").join(nom);
        if etages > 0
            && let Some(dessous) = std::fs::read_dir(bloc.join("slaves"))
                .ok()
                .and_then(|mut d| d.next())
                .and_then(Result::ok)
        {
            return disque_de(&dessous.file_name().to_string_lossy(), etages.saturating_sub(1));
        }
        let disque = if bloc.join("partition").exists() {
            std::fs::canonicalize(&bloc)
                .ok()
                .and_then(|p| {
                    p.parent()
                        .and_then(Path::file_name)
                        .map(|n| n.to_string_lossy().into_owned())
                })
                .unwrap_or_else(|| nom.to_string())
        } else {
            nom.to_string()
        };
        if disque.starts_with("nvme") {
            return Disque::Nvme;
        }
        match mot(PathBuf::from("/sys/block").join(&disque).join("queue/rotational")).as_deref() {
            Some("0") => Disque::Ssd,
            Some("1") => Disque::Hdd,
            _ => Disque::Inconnu,
        }
    }

    fn disque() -> Disque {
        let Some(mounts) = court(Path::new("/proc/self/mounts"), 1 << 20) else {
            return Disque::Inconnu;
        };
        let Some(dev) = racine(&mounts) else {
            return Disque::Inconnu;
        };
        let reel = std::fs::canonicalize(dev).unwrap_or_else(|_| PathBuf::from(dev));
        match reel.file_name() {
            Some(n) => disque_de(&n.to_string_lossy(), 3),
            None => Disque::Inconnu,
        }
    }

    fn virtuelle(cpuinfo: &str) -> Virtuelle {
        let noyau = mot("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if noyau.contains("microsoft") || noyau.contains("wsl") {
            return Virtuelle::Wsl;
        }
        let fabricant = mot("/sys/class/dmi/id/sys_vendor").unwrap_or_default();
        let modele = mot("/sys/class/dmi/id/product_name").unwrap_or_default();
        if let Some(v) = virtuelle_de(&fabricant, &modele) {
            return v;
        }
        let hyperviseur = cpuinfo
            .lines()
            .find_map(|l| champ(l, "flags"))
            .is_some_and(|f| f.split_whitespace().any(|x| x == "hypervisor"));
        if hyperviseur {
            Virtuelle::Autre
        } else {
            Virtuelle::Aucune
        }
    }

    /// Un boîtier portable (types SMBIOS 8 à 14, 30 à 32), ou une batterie.
    fn portable() -> bool {
        let boitier = mot("/sys/class/dmi/id/chassis_type").and_then(|t| t.parse::<u8>().ok());
        if boitier.is_some_and(|t| matches!(t, 8..=14 | 30..=32)) {
            return true;
        }
        std::fs::read_dir("/sys/class/power_supply").is_ok_and(|d| {
            d.flatten()
                .any(|e| mot(e.path().join("type")).as_deref() == Some("Battery"))
        })
    }

    fn tpm() -> TroisEtats {
        if Path::new("/sys/class/tpm/tpm0").exists() {
            TroisEtats::Oui
        } else if Path::new("/sys/class/tpm").is_dir() {
            TroisEtats::Non
        } else {
            TroisEtats::Inconnu
        }
    }

    /// La variable EFI SecureBoot : 4 octets d'attributs, puis 1 ou 0. Sans EFI, pas de démarrage sécurisé.
    pub(crate) fn demarrage_securise(variable: Option<&[u8]>, efi: bool) -> TroisEtats {
        match variable.and_then(|v| v.get(4)) {
            Some(1) => TroisEtats::Oui,
            Some(0) => TroisEtats::Non,
            _ if !efi => TroisEtats::Non,
            _ => TroisEtats::Inconnu,
        }
    }

    fn graphique() -> Graphique {
        let Ok(d) = std::fs::read_dir("/sys/class/drm") else {
            return Graphique::Aucune;
        };
        let cartes: Vec<Graphique> = d
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with("card") && !n.contains('-')
            })
            .filter_map(|e| mot(e.path().join("device/vendor")))
            .filter_map(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .map(graphique_de_pci)
            .collect();
        principale(cartes)
    }

    pub(crate) fn lire() -> Option<Materiel> {
        let cpuinfo = court(Path::new("/proc/cpuinfo"), 1 << 20)?;
        let memoire = memoire(&court(Path::new("/proc/meminfo"), 1 << 16)?)?;
        let (processeur, nom, coeurs) = processeur(&cpuinfo);
        let fils = fils();
        let efi = Path::new("/sys/firmware/efi").is_dir();
        let variable = std::fs::read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").ok();
        Some(Materiel {
            processeur,
            coeurs: nombre::<COEURS_MAX>(if coeurs == 0 { fils } else { coeurs })?,
            fils: nombre::<FILS_MAX>(fils)?,
            memoire_go: memoire_de_octets(memoire),
            disque: disque(),
            virtuelle: virtuelle(&cpuinfo),
            portable: portable(),
            tpm: tpm(),
            demarrage_securise: demarrage_securise(variable.as_deref(), efi),
            graphique: graphique(),
            modele_processeur: nom.as_deref().and_then(modele),
            modele_graphique: None,
        })
    }
}

#[cfg(windows)]
mod systeme {
    use super::*;
    use crate::machine::windows::wmi::{self, Ligne};

    fn texte<'a>(l: &'a Ligne, champ: &str) -> &'a str {
        l.get(champ).and_then(wmi::Valeur::texte).unwrap_or("")
    }

    fn entier(l: &Ligne, champ: &str) -> Option<u64> {
        l.get(champ)
            .and_then(wmi::Valeur::entier)
            .and_then(|n| u64::try_from(n).ok())
    }

    /// « PCI\VEN_10DE&DEV_… » : le fabricant de la carte.
    pub(crate) fn fabricant_pci(pnp: &str) -> Option<u32> {
        let i = pnp.to_ascii_uppercase().find("VEN_")?;
        u32::from_str_radix(pnp.get(i.saturating_add(4)..i.saturating_add(8))?, 16).ok()
    }

    /// MSFT_PhysicalDisk : BusType 17 = NVMe ; MediaType 4 = SSD, 3 = disque dur.
    pub(crate) fn disque_de(bus: Option<u64>, media: Option<u64>) -> Disque {
        match (bus, media) {
            (Some(17), _) => Disque::Nvme,
            (_, Some(4)) => Disque::Ssd,
            (_, Some(3)) => Disque::Hdd,
            _ => Disque::Inconnu,
        }
    }

    fn demarrage_securise() -> TroisEtats {
        let cle = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
        match cle.and_then(|c| c.get_value::<u32, _>("UEFISecureBootEnabled")) {
            Ok(1) => TroisEtats::Oui,
            Ok(0) => TroisEtats::Non,
            _ => TroisEtats::Inconnu,
        }
    }

    pub(crate) fn lire() -> Option<Materiel> {
        let cpu = wmi::requete(
            r"root\cimv2",
            "Win32_Processor",
            "",
            &["Manufacturer", "Name", "NumberOfCores", "NumberOfLogicalProcessors"],
        )?;
        let cpu = cpu.first()?;
        let systeme = wmi::requete(
            r"root\cimv2",
            "Win32_ComputerSystem",
            "",
            &["Manufacturer", "Model", "TotalPhysicalMemory", "PCSystemType"],
        )?;
        let systeme = systeme.first()?;
        let memoire = entier(systeme, "TotalPhysicalMemory")?;
        // Un zéro (pilote ou machine virtuelle qui ne le remplit pas) vaut une valeur absente, pas un matériel perdu.
        let fils = entier(cpu, "NumberOfLogicalProcessors")
            .filter(|n| *n > 0)
            .unwrap_or_else(fils);
        let cartes = wmi::requete(r"root\cimv2", "Win32_VideoController", "", &["PNPDeviceID"]).unwrap_or_default();
        let disque = wmi::requete(
            r"root\Microsoft\Windows\Storage",
            "MSFT_PhysicalDisk",
            "DeviceId='0'",
            &["BusType", "MediaType"],
        )
        .and_then(|l| l.into_iter().next())
        .map_or(Disque::Inconnu, |l| {
            disque_de(entier(&l, "BusType"), entier(&l, "MediaType"))
        });
        // Win32_Tpm demande les droits d'administrateur : sans eux, inconnu, jamais « non ».
        let tpm = match wmi::requete(
            r"root\cimv2\Security\MicrosoftTpm",
            "Win32_Tpm",
            "",
            &["IsEnabled_InitialValue"],
        ) {
            Some(l) if l.is_empty() => TroisEtats::Non,
            Some(l)
                if l.iter()
                    .any(|x| x.get("IsEnabled_InitialValue").and_then(wmi::Valeur::entier) == Some(1)) =>
            {
                TroisEtats::Oui
            }
            _ => TroisEtats::Inconnu,
        };
        let fabricant = texte(systeme, "Manufacturer");
        let modele_systeme = texte(systeme, "Model");
        Some(Materiel {
            processeur: processeur_de(texte(cpu, "Manufacturer")),
            coeurs: nombre::<COEURS_MAX>(entier(cpu, "NumberOfCores").filter(|n| *n > 0).unwrap_or(fils))?,
            fils: nombre::<FILS_MAX>(fils)?,
            memoire_go: memoire_de_octets(memoire),
            disque,
            virtuelle: virtuelle_de(fabricant, modele_systeme).unwrap_or(Virtuelle::Aucune),
            // PCSystemType 2 : mobile.
            portable: entier(systeme, "PCSystemType") == Some(2),
            tpm,
            demarrage_securise: demarrage_securise(),
            graphique: principale(
                cartes
                    .iter()
                    .filter_map(|l| fabricant_pci(texte(l, "PNPDeviceID")))
                    .map(graphique_de_pci),
            ),
            modele_processeur: modele(texte(cpu, "Name")),
            modele_graphique: None,
        })
    }
}

#[cfg(target_os = "macos")]
mod systeme {
    use super::*;
    use crate::machine::macos::{sysctl_nombre, sysctl_texte};

    pub(crate) fn lire() -> Option<Materiel> {
        let memoire = sysctl_nombre("hw.memsize")?;
        let fils = sysctl_nombre("hw.logicalcpu").unwrap_or_else(fils);
        let marque = sysctl_texte("machdep.cpu.brand_string").unwrap_or_default();
        let apple = cfg!(target_arch = "aarch64");
        let modele_mac = sysctl_texte("hw.model").unwrap_or_default();
        Some(Materiel {
            processeur: if apple {
                Processeur::Apple
            } else {
                processeur_de(&marque)
            },
            coeurs: nombre::<COEURS_MAX>(sysctl_nombre("hw.physicalcpu").unwrap_or(fils))?,
            fils: nombre::<FILS_MAX>(fils)?,
            memoire_go: memoire_de_octets(memoire),
            // Sans IOKit (FFI), la sorte du disque reste inconnue.
            disque: Disque::Inconnu,
            virtuelle: if sysctl_nombre("kern.hv_vmm_present") == Some(1) {
                Virtuelle::Autre
            } else {
                Virtuelle::Aucune
            },
            portable: modele_mac.starts_with("MacBook"),
            tpm: TroisEtats::Inconnu,
            demarrage_securise: TroisEtats::Inconnu,
            graphique: if apple { Graphique::Apple } else { Graphique::Autre },
            modele_processeur: modele(&marque),
            modele_graphique: None,
        })
    }
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
mod systeme {
    pub(crate) fn lire() -> Option<super::Materiel> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_fermees() {
        assert_eq!(processeur_de("GenuineIntel"), Processeur::Intel);
        assert_eq!(processeur_de("AuthenticAMD"), Processeur::Amd);
        assert_eq!(processeur_de("Advanced Micro Devices, Inc."), Processeur::Amd);
        assert_eq!(processeur_de("RISC-V maison"), Processeur::Autre);
        assert_eq!(graphique_de_pci(0x10de), Graphique::Nvidia);
        assert_eq!(graphique_de_pci(0x1234), Graphique::Autre);
        assert_eq!(principale([Graphique::Intel, Graphique::Nvidia]), Graphique::Nvidia);
        assert_eq!(principale([]), Graphique::Aucune);
        assert_eq!(
            virtuelle_de("QEMU", "Standard PC (Q35 + ICH9, 2009)"),
            Some(Virtuelle::Kvm)
        );
        assert_eq!(
            virtuelle_de("Microsoft Corporation", "Virtual Machine"),
            Some(Virtuelle::Hyperv)
        );
        assert_eq!(virtuelle_de("Microsoft Corporation", "Surface Laptop 5"), None);
        assert_eq!(virtuelle_de("innotek GmbH", "VirtualBox"), Some(Virtuelle::Virtualbox));
        // 15,6 Gio vus par le système pour une barrette de 16 Go.
        assert_eq!(memoire_de_octets(16_318_324 * 1024), MemoireGo::arrondie(16));
        assert_eq!(memoire_de_octets(0), MemoireGo::arrondie(1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lectures_de_linux() {
        use super::systeme::*;
        let cpuinfo = "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD Ryzen 7 7800X3D 8-Core Processor\n\
                       physical id\t: 0\ncore id\t\t: 0\nflags\t\t: fpu hypervisor\n\nprocessor\t: 1\n\
                       vendor_id\t: AuthenticAMD\nphysical id\t: 0\ncore id\t\t: 0\n\nprocessor\t: 2\nphysical id\t: 0\n\
                       core id\t\t: 1\n";
        let (p, m, c) = processeur(cpuinfo);
        assert_eq!(
            (p, m.as_deref(), c),
            (Processeur::Amd, Some("AMD Ryzen 7 7800X3D 8-Core Processor"), 2)
        );
        let arm = "processor\t: 0\nCPU implementer\t: 0x51\n";
        assert_eq!(processeur(arm), (Processeur::Qualcomm, None, 0));
        assert_eq!(
            memoire("MemTotal:       16318324 kB\nMemFree: 1 kB\n"),
            Some(16_318_324 * 1024)
        );
        assert_eq!(memoire("rien"), None);
        let mounts = "proc /proc proc rw 0 0\n/dev/nvme0n1p2 / btrfs rw 0 0\n/dev/nvme0n1p1 /boot vfat rw 0 0\n";
        assert_eq!(racine(mounts), Some("/dev/nvme0n1p2"));
        assert_eq!(racine("overlay / overlay rw 0 0\n"), None);
        assert_eq!(demarrage_securise(Some(&[6, 0, 0, 0, 1]), true), TroisEtats::Oui);
        assert_eq!(demarrage_securise(Some(&[6, 0, 0, 0, 0]), true), TroisEtats::Non);
        assert_eq!(demarrage_securise(None, false), TroisEtats::Non);
        assert_eq!(demarrage_securise(None, true), TroisEtats::Inconnu);
    }

    #[cfg(windows)]
    #[test]
    fn lectures_de_windows() {
        use super::systeme::*;
        assert_eq!(fabricant_pci(r"PCI\VEN_10DE&DEV_2684&SUBSYS_0"), Some(0x10de));
        assert_eq!(fabricant_pci("ROOT\\DISPLAY\\0000"), None);
        assert_eq!(disque_de(Some(17), Some(4)), Disque::Nvme);
        assert_eq!(disque_de(Some(11), Some(4)), Disque::Ssd);
        assert_eq!(disque_de(Some(11), Some(3)), Disque::Hdd);
        assert_eq!(disque_de(None, None), Disque::Inconnu);
    }

    /// Le matériel de la machine qui fait l'essai, lu pour de vrai (lecture seulement) : il tient dans son fichier
    /// et se relit à l'identique.
    #[test]
    fn le_vrai_materiel_tient_dans_son_fichier() {
        let Some(m) = lire() else {
            return crate::essais::saute("matériel illisible ici (WMI absent sous Wine ?)");
        };
        let o = serde_json::to_vec(&m).unwrap();
        assert!(o.len() <= MATERIEL_MAX, "{} octets", o.len());
        assert_eq!(serde_json::from_slice::<Materiel>(&o).unwrap(), m);
    }
}
