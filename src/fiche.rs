//! Fiche de l'ordinateur : ce qu'on demande au téléphone ou pour acheter une pièce. Modèle, carte mère, processeur,
//! mémoire (barrettes quand le système les dit), carte graphique et son pilote, disques, système. Lecture seule.
//! Les numéros de série s'affichent à l'écran seulement : ni dans le JSON (`vanguard fiche-ordinateur --json`), ni dans un
//! fichier, ni dans le journal des erreurs. Ils identifient un appareil, et une fiche se partage facilement.

use serde::Serialize;

use crate::ui::*;

/// Ce que le système dit de l'ordinateur. Un champ vide : le système ne le dit pas (ou pas sans droits).
#[derive(Serialize, Default, Debug)]
pub struct Fiche {
    pub systeme: String,
    pub modele: String,
    pub carte_mere: String,
    pub bios: String,
    pub processeur: String,
    pub coeurs: Option<u32>,
    pub fils: Option<u32>,
    /// Mémoire totale, en octets.
    pub memoire: Option<u64>,
    pub barrettes: Vec<Barrette>,
    /// Les barrettes n'ont pas pu être lues : on le dit, sans rien inventer.
    pub barrettes_illisibles: bool,
    pub graphique: Vec<Graphique>,
    pub disques: Vec<Disque>,
    /// (ce qui porte le numéro, le numéro) : montrés à l'écran, jamais écrits.
    #[serde(skip)]
    pub series: Vec<(String, String)>,
}

#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Barrette {
    /// En octets.
    pub taille: u64,
    /// « DDR5 », « LPDDR4X »…
    pub sorte: String,
    /// En MT/s (millions de transferts par seconde, ce que les fabricants appellent « MHz »).
    pub vitesse: Option<u32>,
    pub fabricant: String,
    pub reference: String,
    pub emplacement: String,
}

#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Graphique {
    pub nom: String,
    pub pilote: String,
}

#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Disque {
    /// Nom du disque pour le système : « nvme0n1 », « disk0 », « 0 ».
    pub nom: String,
    pub modele: String,
    /// En octets.
    pub taille: u64,
    /// « SSD NVMe », « SSD », « disque dur », « USB ».
    pub sorte: String,
}

/// Textes d'usine des cartes mères vendues nues, séparés par « | » : ils ne disent rien.
const TEXTES_D_USINE: &str = "\
to be filled by o.e.m.|default string|system product name|system manufacturer|system serial number|\
system version|not specified|not applicable|unknown|none|o.e.m.|oem|0|00000000|0123456789|123456789|\
base board serial number|chassis serial number|invalid|n/a";

/// Valeur réellement renseignée par le fabricant, pas un texte d'usine.
fn renseigne(valeur: &str) -> bool {
    let v = valeur.trim().to_ascii_lowercase();
    !v.is_empty() && !TEXTES_D_USINE.split('|').any(|x| x == v) && !v.starts_with("type1productconfigid")
}

fn propre(valeur: &str) -> String {
    let v = valeur.trim();
    if renseigne(v) { v.to_string() } else { String::new() }
}

impl Fiche {
    /// Un numéro de série renseigné, rangé à part : il ne s'affiche qu'à l'écran.
    fn serie(&mut self, quoi: &str, numero: &str) {
        if renseigne(numero) {
            self.series.push((quoi.to_string(), numero.trim().to_string()));
        }
    }

    /// La fiche prête à montrer (écran et JSON) : chaque texte vient du système ou du matériel lui-même (un disque
    /// branché dit son modèle, une barrette sa référence), rendu `affichable`. Appelé au bout de chaque lecture.
    fn prete_a_montrer(mut self) -> Self {
        let textes = [
            &mut self.systeme,
            &mut self.modele,
            &mut self.carte_mere,
            &mut self.bios,
            &mut self.processeur,
        ];
        for t in textes {
            *t = affichable(t);
        }
        for b in &mut self.barrettes {
            for t in [&mut b.sorte, &mut b.fabricant, &mut b.reference, &mut b.emplacement] {
                *t = affichable(t);
            }
        }
        for g in &mut self.graphique {
            (g.nom, g.pilote) = (affichable(&g.nom), affichable(&g.pilote));
        }
        for d in &mut self.disques {
            for t in [&mut d.nom, &mut d.modele, &mut d.sorte] {
                *t = affichable(t);
            }
        }
        for (quoi, numero) in &mut self.series {
            (*quoi, *numero) = (affichable(quoi), affichable(numero));
        }
        self
    }
}

/// « fabricant modèle », sans répéter le fabricant quand le modèle le contient déjà (« LENOVO » + « LENOVO 21AH »).
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn avec_fabricant(fabricant: &str, modele: &str) -> String {
    let (f, m) = (propre(fabricant), propre(modele));
    match (f.is_empty(), m.is_empty()) {
        (_, true) => f,
        (true, false) => m,
        (false, false) if m.to_lowercase().starts_with(&f.to_lowercase()) => m,
        (false, false) => format!("{f} {m}"),
    }
}

/// « version (date) » du BIOS ou d'un pilote : la version seule sans date, rien sans version.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn version_datee(version: &str, date: &str) -> String {
    match (propre(version), date.trim()) {
        (v, d) if v.is_empty() || d.is_empty() => v,
        (v, d) => format!("{v} ({d})"),
    }
}

/// « 09/04/2026 » (mois/jour/année, comme les BIOS l'écrivent) → « 2026-09-04 ».
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn date_bios(date: &str) -> String {
    let parties: Vec<&str> = date.trim().split('/').collect();
    match parties[..] {
        [m, j, a] if a.len() == 4 && m.len() <= 2 && j.len() <= 2 => format!("{a}-{m:0>2}-{j:0>2}"),
        _ => date.trim().to_string(),
    }
}

/// Nom d'une carte graphique d'après lspci : le nom court du fabricant (« NVIDIA Corporation » → « NVIDIA »), puis le
/// nom commercial, entre crochets (« GB205 [GeForce RTX 5070] »), sinon le nom de la puce.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nom_graphique(fabricant: &str, puce: &str) -> String {
    let n = fabricant.to_lowercase();
    // « ati » se cherche comme un mot : « Intel Corporation » le contient aussi.
    let mots: Vec<&str> = n.split(|c: char| !c.is_alphanumeric()).collect();
    let court = if n.contains("nvidia") {
        "NVIDIA"
    } else if n.contains("intel") {
        "Intel"
    } else if n.contains("advanced micro devices") || mots.contains(&"amd") || mots.contains(&"ati") {
        "AMD"
    } else {
        fabricant.trim()
    };
    let commercial = match puce.rsplit_once('[').and_then(|(_, reste)| reste.split_once(']')) {
        Some((nom, _)) => nom,
        None => puce,
    };
    let nom = format!("{court} {}", commercial.trim());
    nom.trim().to_string()
}

/// Les cartes graphiques de `lspci -vmmk` (fiches séparées par une ligne vide) : (nom, module du pilote). La fiche
/// lit sysfs elle-même ; ce lecteur sert à comparer les deux sur un ordinateur où lspci est là.
#[cfg(all(test, target_os = "linux"))]
fn graphiques_lspci(texte: &str) -> Vec<(String, String)> {
    texte
        .split("\n\n")
        .filter_map(|fiche| {
            let champ = |cle: &str| {
                fiche
                    .lines()
                    .find_map(|l| l.strip_prefix(cle)?.strip_prefix(':'))
                    .map_or_else(String::new, |v| v.trim().to_string())
            };
            let classe = champ("Class");
            (classe.contains("VGA") || classe.contains("3D") || classe.contains("Display"))
                .then(|| (nom_graphique(&champ("Vendor"), &champ("Device")), champ("Driver")))
        })
        .collect()
}

/// Une carte graphique de /sys/bus/pci/devices, nommée comme `lspci` la nomme.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CartePci {
    /// « NVIDIA Corporation », « Advanced Micro Devices, Inc. [AMD/ATI] »…
    pub fabricant: String,
    /// « GB205 [GeForce RTX 5070] » : la puce, puis le nom commercial entre crochets.
    pub puce: String,
    /// Le module du pilote en service (« nvidia », « amdgpu ») ; vide si aucun n'est chargé.
    pub pilote: String,
}

/// La liste des noms PCI : celle de hwdata (Arch, Fedora, openSUSE), puis celle de pciutils (Debian, Ubuntu).
#[cfg(target_os = "linux")]
const LISTES_PCI: [&str; 3] = [
    "/usr/share/hwdata/pci.ids",
    "/usr/share/misc/pci.ids",
    "/usr/share/pci.ids",
];

/// Les cartes graphiques (`lspci -vmmk`), lues dans sysfs. Pas de commande en secours : lspci lit les mêmes
/// fichiers, et sa liste de noms est celle-ci (pciutils en dépend) ; sans elle, lspci aussi ne donne que des
/// numéros.
#[cfg(target_os = "linux")]
pub(crate) fn cartes_graphiques() -> Vec<CartePci> {
    cartes_graphiques_sous(std::path::Path::new("/"))
}

#[cfg(target_os = "linux")]
fn cartes_graphiques_sous(racine: &std::path::Path) -> Vec<CartePci> {
    let lire = |chemin: &std::path::Path| {
        std::fs::read_to_string(chemin)
            .map(|t| t.trim().to_string())
            .unwrap_or_default()
    };
    let hexa = |t: String| u32::from_str_radix(t.trim_start_matches("0x"), 16).ok();
    let mut appareils: Vec<(String, u16, u16, String)> = std::fs::read_dir(racine.join("sys/bus/pci/devices"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let d = e.path();
            // Classe 03 (affichage), sous-classes VGA (00), 3D (02) et « Display controller » (80) : celles
            // que retenait la lecture de lspci, la carte NVIDIA d'un portable et bien des AMD de portable comprises.
            let classe = hexa(lire(&d.join("class")))?;
            if classe >> 16 != 0x03 || ![0x00, 0x02, 0x80].contains(&(classe >> 8 & 0xff)) {
                return None;
            }
            let fabricant = u16::try_from(hexa(lire(&d.join("vendor")))?).ok()?;
            let appareil = u16::try_from(hexa(lire(&d.join("device")))?).ok()?;
            let pilote = std::fs::read_link(d.join("driver"))
                .ok()
                .and_then(|l| Some(l.file_name()?.to_string_lossy().into_owned()))
                .unwrap_or_default();
            Some((
                e.file_name().to_string_lossy().into_owned(),
                fabricant,
                appareil,
                pilote,
            ))
        })
        .collect();
    if appareils.is_empty() {
        return Vec::new();
    }
    // L'adresse (« 0000:01:00.0 », chiffres hexadécimaux de largeur fixe) : l'ordre de lspci.
    appareils.sort();
    let ids = LISTES_PCI
        .iter()
        .find_map(|f| std::fs::read(racine.join(f.trim_start_matches('/'))).ok())
        .map(|o| String::from_utf8_lossy(&o).into_owned())
        .unwrap_or_default();
    appareils
        .into_iter()
        .map(|(_, fabricant, appareil, pilote)| {
            let (nom_fabricant, nom_puce) = noms_pci(&ids, fabricant, appareil);
            CartePci {
                // Inconnus de la liste : les numéros, écrits comme lspci les écrit.
                fabricant: nom_fabricant.map_or_else(|| format!("Vendor {fabricant:04x}"), str::to_string),
                puce: nom_puce.map_or_else(|| format!("Device {appareil:04x}"), str::to_string),
                pilote,
            }
        })
        .collect()
}

/// Les noms d'un fabricant et d'une puce dans pci.ids : « 10de  NVIDIA Corporation », puis ses puces en retrait
/// d'une tabulation (« \t2f04  GB205 [GeForce RTX 5070] ») ; deux tabulations, c'est une carte d'un assembleur.
/// La liste des classes (« C 03 … ») suit celle des fabricants : la lecture s'y arrête.
#[cfg(target_os = "linux")]
fn noms_pci<'a>(ids: &'a str, fabricant: u16, appareil: u16) -> (Option<&'a str>, Option<&'a str>) {
    // « <4 chiffres hexadécimaux>  <nom> » : le nom, si la ligne porte ce numéro.
    let nom = |ligne: &'a str, id: &str| ligne.strip_prefix(id)?.strip_prefix("  ").map(str::trim);
    let (f, a) = (format!("{fabricant:04x}"), format!("{appareil:04x}"));
    let mut trouve: Option<&str> = None;
    for l in ids.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        match (l.strip_prefix('\t'), trouve) {
            (Some(puce), Some(_)) if !puce.starts_with('\t') => {
                if let Some(n) = nom(puce, &a) {
                    return (trouve, Some(n));
                }
            }
            (Some(_), _) => {}
            // Le fabricant suivant, ou la liste des classes : la puce n'y est pas.
            (None, Some(_)) => break,
            (None, None) if l.starts_with("C ") => break,
            (None, None) => trouve = nom(l, &f),
        }
    }
    (trouve, None)
}

/// Un disque entier, ce que `lsblk` dit « disk » : ni lecteur optique, ni loop, ni device-mapper (natif les met à
/// part), ni grappe RAID logicielle, que lsblk dit « raid1 », « raid5 »… et que sysfs range avec les disques.
#[cfg(target_os = "linux")]
pub(crate) fn disque_entier(d: &crate::machine::linux::natif::Disque) -> bool {
    d.genre == "disk" && !d.nom.starts_with("md")
}

/// Les barrettes de mémoire, d'après les propriétés que udev tire de la table DMI (`udevadm info -q property -p
/// /sys/class/dmi/id`), lisibles sans droits : « MEMORY_DEVICE_1_SIZE=17179869184 »… Un emplacement vide n'en est
/// pas une. Rend aussi les numéros de série (emplacement, numéro).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn barrettes_udev(texte: &str) -> (Vec<Barrette>, Vec<(String, String)>) {
    use std::collections::BTreeMap;
    let mut champs: BTreeMap<u32, BTreeMap<&str, &str>> = BTreeMap::new();
    let lus = texte.lines().filter_map(|l| {
        let (cle, valeur) = l.trim().split_once('=')?;
        let (numero, nom) = cle.strip_prefix("MEMORY_DEVICE_")?.split_once('_')?;
        Some((numero.parse::<u32>().ok()?, nom, valeur.trim()))
    });
    for (numero, nom, valeur) in lus {
        champs.entry(numero).or_default().insert(nom, valeur);
    }
    let mut f = Fiche::default();
    for c in champs.values() {
        let lire = |nom: &str| c.get(nom).copied().unwrap_or_default();
        let taille: u64 = lire("SIZE").parse().unwrap_or(0);
        if lire("PRESENT") == "0" || taille == 0 {
            continue;
        }
        let emplacement = propre(lire("LOCATOR"));
        let quoi = trf!("Barrette {emplacement}", "Memory module {emplacement}");
        f.serie(&quoi, lire("SERIAL_NUMBER"));
        f.barrettes.push(Barrette {
            taille,
            sorte: propre(lire("TYPE")),
            vitesse: [lire("CONFIGURED_SPEED_MTS"), lire("SPEED_MTS")]
                .iter()
                .find_map(|v| v.parse::<u32>().ok().filter(|&v| v > 0)),
            fabricant: propre(lire("MANUFACTURER")),
            reference: propre(lire("PART_NUMBER")),
            emplacement,
        });
    }
    (f.barrettes, f.series)
}

/// Le type de mémoire d'après son code SMBIOS (Win32_PhysicalMemory.SMBIOSMemoryType).
#[cfg_attr(not(windows), allow(dead_code))]
fn sorte_smbios(code: u64) -> &'static str {
    #[rustfmt::skip] // cinq codes par ligne, que rustfmt étalerait sur dix
    const SORTES: [(u64, &str); 10] = [
        (20, "DDR"), (21, "DDR2"), (24, "DDR3"), (26, "DDR4"), (27, "LPDDR"),
        (28, "LPDDR2"), (29, "LPDDR3"), (30, "LPDDR4"), (34, "DDR5"), (35, "LPDDR5"),
    ];
    SORTES.iter().find(|(c, _)| *c == code).map_or("", |&(_, sorte)| sorte)
}

/// « SSD NVMe », « disque dur »… d'après le transport et la rotation (lsblk), ou le type et le bus (Windows).
fn sorte_disque(transport: &str, rotatif: bool) -> String {
    match transport.to_ascii_lowercase().as_str() {
        "nvme" => "SSD NVMe".into(),
        "usb" => "USB".into(),
        _ if rotatif => tr!("disque dur", "hard drive").into(),
        _ => "SSD".into(),
    }
}

/// Les propriétés que udev garde d'un appareil (/run/udev/data, lisible par tous : « E:CLÉ=valeur ») dans la forme
/// « CLÉ=valeur » de `udevadm info --query=property`, qui lit ce même fichier. Absent, udevadm n'en dirait pas
/// plus : pas de commande en secours.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn proprietes_udev(texte: &str) -> String {
    texte
        .lines()
        .filter_map(|l| l.strip_prefix("E:"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Le nom du cœur d'un processeur ARM d'après son fabricant et son numéro de pièce (registre MIDR), comme la
/// table de lscpu : /proc/cpuinfo n'a pas de « model name » sur ARM 64 bits. Un code absent de la table ne
/// donne rien : mieux vaut un champ vide qu'un nom faux (le nom de la carte, par exemple, n'est pas celui du
/// processeur).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn coeur_arm(fabricant: u32, piece: u32) -> Option<&'static str> {
    let nom = match (fabricant, piece) {
        (0x41, 0xc07) => "Cortex-A7",
        (0x41, 0xc09) => "Cortex-A9",
        (0x41, 0xc0f) => "Cortex-A15",
        (0x41, 0xd03) => "Cortex-A53",
        (0x41, 0xd04) => "Cortex-A35",
        (0x41, 0xd05) => "Cortex-A55",
        (0x41, 0xd07) => "Cortex-A57",
        (0x41, 0xd08) => "Cortex-A72",
        (0x41, 0xd09) => "Cortex-A73",
        (0x41, 0xd0a) => "Cortex-A75",
        (0x41, 0xd0b) => "Cortex-A76",
        (0x41, 0xd0c) => "Neoverse-N1",
        (0x41, 0xd0d) => "Cortex-A77",
        (0x41, 0xd40) => "Neoverse-V1",
        (0x41, 0xd41) => "Cortex-A78",
        (0x41, 0xd44) => "Cortex-X1",
        (0x41, 0xd46) => "Cortex-A510",
        (0x41, 0xd47) => "Cortex-A710",
        (0x41, 0xd48) => "Cortex-X2",
        (0x41, 0xd49) => "Neoverse-N2",
        (0x41, 0xd4f) => "Neoverse-V2",
        _ => return None,
    };
    Some(nom)
}

/// Le cœur d'après les lignes « CPU implementer » et « CPU part » de /proc/cpuinfo (« 0x41 », « 0xd08 »).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn coeur_cpuinfo(fabricant: &str, piece: &str) -> Option<&'static str> {
    let hexa = |t: &str| u32::from_str_radix(t.trim().strip_prefix("0x")?, 16).ok();
    coeur_arm(hexa(fabricant)?, hexa(piece)?)
}

/// Le cœur d'après /sys/devices/system/cpu/cpu0/regs/identification/midr_el1 (« 0x00000000410fd083 ») :
/// fabricant aux bits 31 à 24, pièce aux bits 15 à 4.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn coeur_midr(texte: &str) -> Option<&'static str> {
    let midr = u64::from_str_radix(texte.trim().strip_prefix("0x")?, 16).ok()?;
    let champ = |decalage: u32, masque: u64| u32::try_from((midr >> decalage) & masque).ok();
    coeur_arm(champ(24, 0xff)?, champ(4, 0xfff)?)
}

/// Le nom du processeur, dans l'ordre de lscpu : « model name » (x86, ARM 32 bits), « cpu » (POWER :
/// « POWER9, altivec supported »), puis le numéro du cœur ARM, de /proc/cpuinfo ou du registre MIDR. Rien
/// d'autre : un champ vide se lit « non renseigné », alors qu'un nom de carte se lirait comme celui du
/// processeur.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nom_du_processeur(cpuinfo: &str, midr: &str) -> String {
    let valeur = |cle: &str| {
        cpuinfo
            .lines()
            .find_map(|l| l.strip_prefix(cle)?.trim_start().strip_prefix(':'))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    valeur("model name")
        .or_else(|| valeur("cpu"))
        .or_else(|| coeur_cpuinfo(&valeur("CPU implementer")?, &valeur("CPU part")?).map(str::to_string))
        .or_else(|| coeur_midr(midr).map(str::to_string))
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn lire() -> Fiche {
    let fichier = |chemin: &str| std::fs::read_to_string(chemin).unwrap_or_default().trim().to_string();
    let dmi = |f: &str| fichier(&format!("/sys/class/dmi/id/{f}"));
    let os = crate::socle::systeme::nom();
    let mut f = Fiche {
        systeme: trf!(
            "{os} · noyau {}",
            "{os} · kernel {}",
            fichier("/proc/sys/kernel/osrelease")
        ),
        modele: avec_fabricant(&dmi("sys_vendor"), &dmi("product_name")),
        carte_mere: avec_fabricant(&dmi("board_vendor"), &dmi("board_name")),
        bios: version_datee(&dmi("bios_version"), &date_bios(&dmi("bios_date"))),
        ..Fiche::default()
    };
    // Numéros de l'ordinateur et de la carte mère : lisibles par root seulement, le plus souvent.
    f.serie(tr!("Ordinateur", "Computer"), &dmi("product_serial"));
    f.serie(tr!("Carte mère", "Motherboard"), &dmi("board_serial"));

    let cpuinfo = fichier("/proc/cpuinfo");
    let valeur = |cle: &str| {
        cpuinfo
            .lines()
            .find_map(|l| l.strip_prefix(cle)?.trim_start().strip_prefix(':'))
            .map(|v| v.trim().to_string())
    };
    f.processeur = nom_du_processeur(
        &cpuinfo,
        &fichier("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1"),
    );
    let processeurs: std::collections::BTreeSet<&str> = cpuinfo
        .lines()
        .filter_map(|l| l.strip_prefix("physical id")?.split(':').nth(1).map(str::trim))
        .collect();
    f.coeurs = valeur("cpu cores")
        .and_then(|c| c.parse::<u32>().ok())
        .map(|c| c * u32::try_from(processeurs.len().max(1)).unwrap_or(1));
    f.fils = u32::try_from(cpuinfo.lines().filter(|l| l.starts_with("processor")).count())
        .ok()
        .filter(|&n| n > 0);

    f.memoire = fichier("/proc/meminfo")
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        .map(|ko| ko * 1024);
    let (barrettes, series) = barrettes_udev(&proprietes_udev(&fichier("/run/udev/data/+dmi:id")));
    f.barrettes_illisibles = barrettes.is_empty();
    f.barrettes = barrettes;
    f.series.extend(series);

    let noyau = fichier("/proc/sys/kernel/osrelease");
    for carte in cartes_graphiques() {
        let nom = nom_graphique(&carte.fabricant, &carte.puce);
        let pilote = match carte.pilote.as_str() {
            "nvidia" => fichier("/proc/driver/nvidia/version")
                .split_whitespace()
                .find(|m| m.contains('.') && m.chars().all(|c| c.is_ascii_digit() || c == '.'))
                .map_or_else(|| "nvidia".to_string(), |v| format!("nvidia {v}")),
            "" => tr!("aucun pilote chargé", "no driver loaded").to_string(),
            autre => trf!("{autre} (noyau {noyau})", "{autre} (kernel {noyau})"),
        };
        f.graphique.push(Graphique { nom, pilote });
    }

    for d in crate::machine::linux::natif::disques() {
        if !disque_entier(&d) || ["zram", "loop", "ram", "sr"].iter().any(|p| d.nom.starts_with(p)) {
            continue;
        }
        f.serie(&trf!("Disque {}", "Disk {}", d.nom), &d.serie);
        f.disques.push(Disque {
            modele: propre(&d.modele),
            taille: d.octets,
            sorte: sorte_disque(&d.bus, d.rotatif),
            nom: d.nom,
        });
    }
    f.prete_a_montrer()
}

/// Ce que lit le script PowerShell (Windows) : un objet JSON, aux champs du même nom que dans le script.
type LectureWindows = serde_json::Map<String, serde_json::Value>;

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn champ<'a>(objet: &'a serde_json::Value, cle: &str) -> &'a str {
    objet[cle].as_str().unwrap_or_default()
}

/// La fiche d'après la lecture PowerShell (séparée pour être testée partout).
#[cfg_attr(not(windows), allow(dead_code))]
fn fiche_windows(l: LectureWindows) -> Fiche {
    // Lu comme ses barrettes, cartes et disques : un champ absent se lit vide, ou zéro.
    let l = serde_json::Value::Object(l);
    let nombre = |objet: &serde_json::Value, cle: &str| objet[cle].as_u64().filter(|&n| n > 0);
    let build = format!("({})", champ(&l, "build").trim());
    let mut f = Fiche {
        systeme: [champ(&l, "systeme").trim(), champ(&l, "version").trim(), &build]
            .into_iter()
            .filter(|p| !p.is_empty() && *p != "()")
            .collect::<Vec<_>>()
            .join(" "),
        modele: avec_fabricant(champ(&l, "fabricant"), champ(&l, "modele")),
        carte_mere: avec_fabricant(champ(&l, "carte_fabricant"), champ(&l, "carte")),
        bios: version_datee(champ(&l, "bios"), champ(&l, "bios_date")),
        processeur: champ(&l, "processeur").trim().to_string(),
        coeurs: nombre(&l, "coeurs").and_then(|c| u32::try_from(c).ok()),
        fils: nombre(&l, "fils").and_then(|c| u32::try_from(c).ok()),
        memoire: nombre(&l, "memoire"),
        barrettes_illisibles: l["barrettes"].as_array().is_none_or(Vec::is_empty),
        ..Fiche::default()
    };
    f.serie(tr!("Ordinateur", "Computer"), champ(&l, "serie"));
    f.serie(tr!("Carte mère", "Motherboard"), champ(&l, "serie_carte"));
    for b in l["barrettes"].as_array().into_iter().flatten() {
        let emplacement = champ(b, "emplacement");
        let quoi = trf!("Barrette {}", "Memory module {}", emplacement.trim());
        f.serie(&quoi, champ(b, "serie"));
        f.barrettes.push(Barrette {
            taille: nombre(b, "taille").unwrap_or(0),
            sorte: sorte_smbios(nombre(b, "sorte").unwrap_or(0)).to_string(),
            vitesse: nombre(b, "vitesse").and_then(|v| u32::try_from(v).ok()),
            fabricant: propre(champ(b, "fabricant")),
            reference: propre(champ(b, "reference")),
            emplacement: propre(emplacement),
        });
    }
    for g in l["graphique"].as_array().into_iter().flatten() {
        let pilote = match champ(g, "date").trim() {
            "" => champ(g, "pilote").trim().to_string(),
            date => format!("{} ({date})", champ(g, "pilote").trim()),
        };
        let nom = champ(g, "nom").trim().to_string();
        f.graphique.push(Graphique { nom, pilote });
    }
    for d in l["disques"].as_array().into_iter().flatten() {
        let nom = champ(d, "nom").to_string();
        f.serie(&trf!("Disque {}", "Disk {}", nom), champ(d, "serie"));
        let sorte = match (champ(d, "bus").to_ascii_lowercase().as_str(), champ(d, "sorte")) {
            (bus @ ("nvme" | "usb"), _) => sorte_disque(bus, false),
            (_, "HDD") => sorte_disque("", true),
            (_, "SSD") => sorte_disque("", false),
            _ => tr!("type inconnu", "unknown type").into(),
        };
        f.disques.push(Disque {
            modele: champ(d, "modele").trim().to_string(),
            taille: nombre(d, "taille").unwrap_or(0),
            sorte,
            nom,
        });
    }
    f.prete_a_montrer()
}

/// Le JSON qu'écrivait le script, lu sans PowerShell : WMI (les mêmes classes) et le registre. `None` sans
/// Win32_OperatingSystem.
#[cfg(windows)]
fn lire_directement() -> Option<serde_json::Value> {
    use crate::machine::windows::wmi::{self, Ligne};
    use serde_json::json;
    const CIMV2: &str = r"root\cimv2";
    let toutes = |classe: &str, champs: &[&str]| wmi::requete(CIMV2, classe, "", champs).unwrap_or_default();
    let os = wmi::requete(CIMV2, "Win32_OperatingSystem", "", &["Caption", "BuildNumber"])?
        .into_iter()
        .next()?;
    let premiere = |classe: &str, champs: &[&str]| toutes(classe, champs).into_iter().next().unwrap_or_default();
    let cs = premiere(
        "Win32_ComputerSystem",
        &["Manufacturer", "Model", "TotalPhysicalMemory"],
    );
    let bb = premiere("Win32_BaseBoard", &["Manufacturer", "Product", "SerialNumber"]);
    let bios = premiere("Win32_BIOS", &["SMBIOSBIOSVersion", "ReleaseDate", "SerialNumber"]);
    let cpu = toutes(
        "Win32_Processor",
        &["Name", "NumberOfCores", "NumberOfLogicalProcessors"],
    );
    let cv = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .ok();
    let version: String = cv
        .as_ref()
        .and_then(|k| k.get_value("DisplayVersion").ok())
        .unwrap_or_default();
    let ubr = cv
        .as_ref()
        .and_then(|k| k.get_value::<u32, _>("UBR").ok())
        .map(|u| u.to_string())
        .unwrap_or_default();
    // Un champ comme `"$($x.Champ)"` l'écrit : vide s'il manque ; un nombre comme `[uint64]` (0 s'il manque).
    let texte = |l: &Ligne, c: &str| match l.get(c) {
        Some(wmi::Valeur::Texte(t)) => t.clone(),
        Some(wmi::Valeur::Entier(n)) => n.to_string(),
        _ => String::new(),
    };
    let nombre = |l: &Ligne, c: &str| {
        l.get(c)
            .and_then(wmi::Valeur::entier)
            .map_or(0, |n| u64::try_from(n).unwrap_or(0))
    };
    // Une date CIM (« 20240115000000.000000+000 ») en « 2024-01-15 », comme `.ToString('yyyy-MM-dd')`.
    let date = |l: &Ligne, c: &str| {
        let d = texte(l, c);
        chrono::NaiveDate::parse_from_str(d.get(..8).unwrap_or_default(), "%Y%m%d")
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default()
    };
    let somme = |c: &str| cpu.iter().map(|p| nombre(p, c)).sum::<u64>();
    let barrettes: Vec<serde_json::Value> = toutes(
        "Win32_PhysicalMemory",
        &[
            "Capacity",
            "SMBIOSMemoryType",
            "ConfiguredClockSpeed",
            "Speed",
            "Manufacturer",
            "PartNumber",
            "DeviceLocator",
            "SerialNumber",
        ],
    )
    .iter()
    .map(|b| {
        let vitesse = match nombre(b, "ConfiguredClockSpeed") {
            0 => nombre(b, "Speed"),
            v => v,
        };
        json!({
            "taille": nombre(b, "Capacity"), "sorte": nombre(b, "SMBIOSMemoryType"), "vitesse": vitesse,
            "fabricant": texte(b, "Manufacturer"), "reference": texte(b, "PartNumber"),
            "emplacement": texte(b, "DeviceLocator"), "serie": texte(b, "SerialNumber"),
        })
    })
    .collect();
    let graphique: Vec<serde_json::Value> = toutes("Win32_VideoController", &["Name", "DriverVersion", "DriverDate"])
        .iter()
        .map(|g| json!({ "nom": texte(g, "Name"), "pilote": texte(g, "DriverVersion"), "date": date(g, "DriverDate") }))
        .collect();
    let disques: Vec<serde_json::Value> = wmi::requete(
        r"root\Microsoft\Windows\Storage",
        "MSFT_PhysicalDisk",
        "",
        &[
            "DeviceId",
            "FriendlyName",
            "Size",
            "MediaType",
            "BusType",
            "SerialNumber",
        ],
    )
    .unwrap_or_default()
    .iter()
    .map(|d| {
        // MediaType et BusType écrits comme Get-PhysicalDisk les écrit (seuls NVMe, USB, HDD et SSD sont lus).
        let sorte = match d["MediaType"].entier() {
            Some(3) => "HDD",
            Some(4) => "SSD",
            Some(5) => "SCM",
            _ => "Unspecified",
        };
        let bus = match d["BusType"].entier() {
            Some(3) => "ATA",
            Some(7) => "USB",
            Some(8) => "RAID",
            Some(10) => "SAS",
            Some(11) => "SATA",
            Some(17) => "NVMe",
            _ => "Unknown",
        };
        json!({
            "nom": texte(d, "DeviceId"), "modele": texte(d, "FriendlyName"), "taille": nombre(d, "Size"),
            "sorte": sorte, "bus": bus, "serie": texte(d, "SerialNumber"),
        })
    })
    .collect();
    Some(json!({
        "systeme": texte(&os, "Caption"), "version": version, "build": format!("{}.{ubr}", texte(&os, "BuildNumber")),
        "fabricant": texte(&cs, "Manufacturer"), "modele": texte(&cs, "Model"),
        "carte_fabricant": texte(&bb, "Manufacturer"), "carte": texte(&bb, "Product"),
        "bios": texte(&bios, "SMBIOSBIOSVersion"), "bios_date": date(&bios, "ReleaseDate"),
        "processeur": cpu.first().map(|c| texte(c, "Name")).unwrap_or_default().trim(),
        "coeurs": somme("NumberOfCores"), "fils": somme("NumberOfLogicalProcessors"),
        "memoire": nombre(&cs, "TotalPhysicalMemory"),
        "barrettes": barrettes, "graphique": graphique, "disques": disques,
        "serie": texte(&bios, "SerialNumber"), "serie_carte": texte(&bb, "SerialNumber"),
    }))
}

#[cfg(windows)]
fn lire() -> Fiche {
    if let Some(serde_json::Value::Object(l)) = lire_directement() {
        return fiche_windows(l);
    }
    crate::machine::windows::ps(
        r#"$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
           $bb = Get-CimInstance Win32_BaseBoard; $bios = Get-CimInstance Win32_BIOS; $cpu = @(Get-CimInstance Win32_Processor)
           $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
           [pscustomobject]@{
             systeme = "$($os.Caption)"; version = "$($cv.DisplayVersion)"; build = "$($os.BuildNumber).$($cv.UBR)"
             fabricant = "$($cs.Manufacturer)"; modele = "$($cs.Model)"; carte_fabricant = "$($bb.Manufacturer)"; carte = "$($bb.Product)"
             bios = "$($bios.SMBIOSBIOSVersion)"; bios_date = $(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { '' })
             processeur = "$($cpu[0].Name)".Trim()
             coeurs = [uint32](($cpu | Measure-Object NumberOfCores -Sum).Sum); fils = [uint32](($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum)
             memoire = [uint64]$cs.TotalPhysicalMemory
             barrettes = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { @{ taille = [uint64]$_.Capacity; sorte = [uint32]$_.SMBIOSMemoryType
               vitesse = [uint32]$(if ($_.ConfiguredClockSpeed) { $_.ConfiguredClockSpeed } else { $_.Speed }); fabricant = "$($_.Manufacturer)"
               reference = "$($_.PartNumber)"; emplacement = "$($_.DeviceLocator)"; serie = "$($_.SerialNumber)" } })
             graphique = @(Get-CimInstance Win32_VideoController | ForEach-Object { @{ nom = "$($_.Name)"; pilote = "$($_.DriverVersion)"
               date = $(if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' }) } })
             disques = @(try { Get-PhysicalDisk | ForEach-Object { @{ nom = "$($_.DeviceId)"; modele = "$($_.FriendlyName)"; taille = [uint64]$_.Size
               sorte = "$($_.MediaType)"; bus = "$($_.BusType)"; serie = "$($_.SerialNumber)" } } } catch { })
             serie = "$($bios.SerialNumber)"; serie_carte = "$($bb.SerialNumber)"
           } | ConvertTo-Json -Compress -Depth 3"#,
    )
    .and_then(|json| serde_json::from_str(&json).ok())
    .map_or_else(Fiche::default, fiche_windows)
}

/// La fiche d'après `system_profiler -json SPHardwareDataType SPMemoryDataType SPDisplaysDataType` (séparée pour être
/// testée partout).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn fiche_macos(json: &serde_json::Value) -> Fiche {
    let texte = |objet: &serde_json::Value, cle: &str| champ(objet, cle).trim().to_string();
    let materiel = &json["SPHardwareDataType"][0];
    let mut f = Fiche {
        modele: [texte(materiel, "machine_name"), texte(materiel, "machine_model")]
            .into_iter()
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join(" · "),
        processeur: [texte(materiel, "chip_type"), texte(materiel, "cpu_type")]
            .into_iter()
            .find(|t| !t.is_empty())
            .unwrap_or_default(),
        bios: texte(materiel, "boot_rom_version"),
        // « proc 10:4:6 » (Apple Silicon : total, performance, efficacité) ou un nombre (Intel).
        coeurs: texte(materiel, "number_processors")
            .trim_start_matches("proc ")
            .split(':')
            .next()
            .and_then(|n| n.trim().parse().ok())
            .or_else(|| materiel["number_processors"].as_u64().and_then(|n| n.try_into().ok())),
        memoire: taille_lue(&texte(materiel, "physical_memory")),
        ..Fiche::default()
    };
    let numero = texte(materiel, "serial_number");
    if !numero.is_empty() {
        f.series.push((tr!("Ordinateur", "Computer").to_string(), numero));
    }
    let memoire = &json["SPMemoryDataType"][0];
    if let Some(items) = memoire["_items"].as_array() {
        // Mac Intel : une fiche par barrette.
        for b in items {
            let Some(taille) = taille_lue(&texte(b, "dimm_size")) else {
                continue;
            };
            let quoi = trf!("Barrette {}", "Memory module {}", texte(b, "_name"));
            f.serie(&quoi, &texte(b, "dimm_serial_number"));
            f.barrettes.push(Barrette {
                taille,
                sorte: texte(b, "dimm_type"),
                vitesse: texte(b, "dimm_speed")
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok()),
                fabricant: propre(&texte(b, "dimm_manufacturer")),
                reference: propre(&texte(b, "dimm_part_number")),
                emplacement: texte(b, "_name"),
            });
        }
    } else if let Some(taille) = taille_lue(&texte(memoire, "SPMemoryDataType")) {
        // Apple Silicon : la mémoire fait partie de la puce, une seule « barrette ».
        f.barrettes.push(Barrette {
            taille,
            sorte: texte(memoire, "dimm_type"),
            fabricant: texte(memoire, "dimm_manufacturer"),
            emplacement: tr!("dans la puce", "on the chip").into(),
            ..Barrette::default()
        });
    }
    f.barrettes_illisibles = f.barrettes.is_empty();
    for g in json["SPDisplaysDataType"].as_array().into_iter().flatten() {
        let nom = [texte(g, "sppci_model"), texte(g, "_name")]
            .into_iter()
            .find(|t| !t.is_empty())
            .unwrap_or_default();
        let nom = match texte(g, "sppci_cores") {
            coeurs if coeurs.is_empty() => nom,
            coeurs => trf!("{nom} ({coeurs} cœurs)", "{nom} ({coeurs} cores)"),
        };
        let pilote = tr!("intégré à macOS", "built into macOS").into();
        f.graphique.push(Graphique { nom, pilote });
    }
    f
}

/// « 16 GB », « 8 Go », « 512 MB » → octets.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn taille_lue(texte: &str) -> Option<u64> {
    let mut mots = texte.split_whitespace();
    let nombre: f64 = mots.next()?.replace(',', ".").parse().ok()?;
    let facteur: u64 = match mots.next()?.to_ascii_uppercase().as_str() {
        "TB" | "TO" => 1 << 40,
        "GB" | "GO" => 1 << 30,
        "MB" | "MO" => 1 << 20,
        _ => return None,
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    #[allow(clippy::cast_precision_loss)]
    Some((nombre * facteur as f64) as u64)
}

#[cfg(target_os = "macos")]
fn lire() -> Fiche {
    let sortie = |cmd: &str, args: &[&str]| {
        crate::commande::lancer(std::process::Command::new(cmd).args(args), 60)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie.trim().to_string())
            .unwrap_or_default()
    };
    let sections = ["-json", "SPHardwareDataType", "SPMemoryDataType", "SPDisplaysDataType"];
    let profil = sortie("system_profiler", &sections);
    let mut f = fiche_macos(&serde_json::from_str(&profil).unwrap_or_default());
    let version = |cle: &str| crate::machine::macos::version_systeme(cle).unwrap_or_default();
    f.systeme = format!(
        "{} {} ({})",
        version("ProductName"),
        version("ProductVersion"),
        version("ProductBuildVersion")
    );
    // diskutil en -plist : des clés qui ne changent pas avec la langue du Mac (« Solid State: Yes » se traduit).
    let plist = |args: &[&str]| crate::plist::lire(sortie("diskutil", args).as_bytes());
    let disques = plist(&["list", "-plist", "internal", "physical"])
        .map(|l| crate::machine::darwin::disques_entiers(&l))
        .unwrap_or_default();
    for disque in disques {
        let info = plist(&["info", "-plist", &disque])
            .map(|i| crate::machine::darwin::info_disque(&i))
            .unwrap_or_default();
        f.disques.push(Disque {
            modele: info.modele.unwrap_or_default(),
            taille: info.taille.unwrap_or(0),
            sorte: sorte_disque("", info.ssd != Some(true)),
            nom: disque,
        });
    }
    f.prete_a_montrer()
}

fn taille(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let g = octets as f64 / f64::from(1u32 << 30);
    if g >= 1000.0 {
        trf!("{} To", "{} TB", crate::langue::decimal(g / 1024.0, 1))
    } else if g >= 10.0 {
        trf!("{g:.0} Go", "{g:.0} GB")
    } else {
        trf!("{} Go", "{} GB", crate::langue::decimal(g, 1))
    }
}

/// Ajoute « séparateur partie » au texte, sauf si la partie est vide.
fn ajouter(texte: &mut String, separateur: &str, partie: &str) {
    if !partie.is_empty() {
        texte.push_str(separateur);
        texte.push_str(partie);
    }
}

fn barrette_en_texte(b: &Barrette) -> String {
    let vitesse = b.vitesse.map_or_else(String::new, |v| format!("{v} MT/s"));
    let mut texte = taille(b.taille);
    ajouter(&mut texte, " ", &b.sorte);
    ajouter(&mut texte, " ", &vitesse);
    for detail in [&b.fabricant, &b.reference, &b.emplacement] {
        ajouter(&mut texte, " · ", detail);
    }
    texte
}

/// Une ligne « libellé  valeur », la valeur coupée et alignée dans 76 colonnes.
fn ligne(libelle: &str, valeur: &str) {
    if !valeur.is_empty() {
        afficher_aligne(&format!("  {GRAS}{}{RESET} ", ajuster(libelle, 17)), valeur, 20, "");
    }
}

fn afficher(f: &Fiche) {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("FICHE DE L'ORDINATEUR", "COMPUTER SPECS")),
        &format!("{GRIS}{}{RESET}", tr!("lecture seule", "read only")),
    );
    section(tr!("ORDINATEUR", "COMPUTER"));
    ligne(tr!("Modèle", "Model"), &f.modele);
    ligne(tr!("Carte mère", "Motherboard"), &f.carte_mere);
    ligne("BIOS", &f.bios);
    ligne(tr!("Système", "System"), &f.systeme);

    section(tr!("PROCESSEUR ET MÉMOIRE", "PROCESSOR AND MEMORY"));
    let coeurs = match (f.coeurs, f.fils) {
        (Some(c), Some(t)) if c != t => trf!(" ({c} cœurs, {t} fils)", " ({c} cores, {t} threads)"),
        (Some(c), _) => trf!(" ({c} cœurs)", " ({c} cores)"),
        (None, Some(t)) => trf!(" ({t} fils)", " ({t} threads)"),
        (None, None) => String::new(),
    };
    ligne(tr!("Processeur", "Processor"), &format!("{}{coeurs}", f.processeur));
    // Installée (les barrettes) et utilisable (le système en garde une part, pour la carte graphique intégrée…).
    let installee: u64 = f.barrettes.iter().map(|b| b.taille).sum();
    let memoire = match (installee, f.memoire) {
        (i, Some(u)) if i > u => trf!("{} ({} utilisables)", "{} ({} usable)", taille(i), taille(u)),
        (_, Some(u)) => taille(u),
        (i, None) if i > 0 => taille(i),
        _ => String::new(),
    };
    ligne(tr!("Mémoire", "Memory"), &memoire);
    for b in &f.barrettes {
        ligne(tr!("  barrette", "  module"), &barrette_en_texte(b));
    }
    if f.barrettes_illisibles {
        let illisible = tr!("détail illisible ici", "details not readable here");
        ligne(tr!("  barrettes", "  modules"), &format!("{GRIS}{illisible}{RESET}"));
    }

    section(tr!("GRAPHISME", "GRAPHICS"));
    if f.graphique.is_empty() {
        ligne(tr!("Carte graphique", "Graphics card"), tr!("non trouvée", "not found"));
    }
    for g in &f.graphique {
        ligne(tr!("Carte graphique", "Graphics card"), &g.nom);
        ligne(tr!("  pilote", "  driver"), &g.pilote);
    }

    section(tr!("DISQUES", "DISKS"));
    for d in &f.disques {
        let mut texte = format!("{} · {} · {}", d.nom, taille(d.taille), d.sorte);
        ajouter(&mut texte, " · ", &d.modele);
        ligne(tr!("Disque", "Disk"), &texte);
    }

    if !f.series.is_empty() {
        section(tr!(
            "NUMÉROS DE SÉRIE (à l'écran seulement)",
            "SERIAL NUMBERS (on screen only)"
        ));
        for (quoi, numero) in &f.series {
            ligne(quoi, numero);
        }
        let nulle_part = tr!(
            "Ils ne sont écrits nulle part : ni rapport, ni fichier, ni journal. Recopiez-les vous-même si un service après-vente les demande.",
            "They are written nowhere: no report, no file, no log. Copy them yourself if an after-sales service asks for them."
        );
        afficher_aligne("  ", nulle_part, 2, DISCRET);
    }
}

/// « vanguard fiche-ordinateur » : la fiche à l'écran ; `--json` pour les scripts, sans les numéros de série.
pub fn fiche(json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(&lire()).unwrap_or_default());
    } else {
        trp!(
            "  {DISCRET}Lecture du matériel…{RESET}",
            "  {DISCRET}Reading the hardware…{RESET}"
        );
        afficher(&lire());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn textes_d_usine_ecartes() {
        assert!(!renseigne("To be filled by O.E.M."));
        assert!(!renseigne(" Default string "));
        assert!(!renseigne("Unknown"));
        assert!(renseigne("ThinkPad T14"));
        assert_eq!(avec_fabricant("LENOVO", "LENOVO 21AH"), "LENOVO 21AH");
        assert_eq!(avec_fabricant("Dell Inc.", "XPS 13"), "Dell Inc. XPS 13");
        assert_eq!(avec_fabricant("System manufacturer", "System Product Name"), "");
        assert_eq!(date_bios("09/04/2026"), "2026-09-04");
        assert_eq!(date_bios("2026-09-04"), "2026-09-04");
    }

    /// Un dossier jetable qui tient lieu de racine du système.
    #[cfg(target_os = "linux")]
    fn racine(nom: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-fiche-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[cfg(target_os = "linux")]
    fn ecrire(racine: &std::path::Path, chemin: &str, texte: &str) {
        let f = racine.join(chemin.trim_start_matches('/'));
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, texte).unwrap();
    }

    /// Un appareil PCI inventé : classe, fabricant, puce, et son pilote s'il en a un (le lien `driver` de sysfs).
    #[cfg(target_os = "linux")]
    fn appareil(racine: &std::path::Path, adresse: &str, ids: [&str; 3], pilote: Option<&str>) {
        let d = format!("/sys/bus/pci/devices/{adresse}");
        for (f, v) in ["class", "vendor", "device"].iter().zip(ids) {
            ecrire(racine, &format!("{d}/{f}"), &format!("{v}\n"));
        }
        if let Some(p) = pilote {
            let cible = racine.join(format!("sys/bus/pci/drivers/{p}"));
            std::fs::create_dir_all(&cible).unwrap();
            std::os::unix::fs::symlink(cible, racine.join(d.trim_start_matches('/')).join("driver")).unwrap();
        }
    }

    /// Les cartes graphiques lues dans sysfs : VGA, 3D (la carte NVIDIA d'un portable, ici sans pilote chargé) et
    /// « Display controller » (bien des AMD de portable) ; ni la carte réseau, ni la vieille classe XGA, que la
    /// lecture de lspci ne retenait pas non plus. Une puce absente de pci.ids garde son numéro, comme dans lspci.
    #[cfg(target_os = "linux")]
    #[test]
    fn cartes_graphiques_de_sysfs() {
        let d = racine("pci");
        appareil(&d, "0000:00:02.0", ["0x030000", "0x8086", "0x46a6"], Some("i915"));
        appareil(&d, "0000:01:00.0", ["0x030200", "0x10de", "0x25a2"], None);
        appareil(&d, "0000:03:00.0", ["0x038000", "0x1002", "0x743f"], Some("amdgpu"));
        appareil(&d, "0000:04:00.0", ["0x028000", "0x8086", "0x51f0"], Some("iwlwifi"));
        appareil(&d, "0000:05:00.0", ["0x030100", "0x1002", "0x743f"], None);
        appareil(&d, "0000:06:00.0", ["0x030000", "0x1d0f", "0xabcd"], None);
        ecrire(
            &d,
            "/usr/share/hwdata/pci.ids",
            "# Liste inventée, à la forme de pci.ids\n\
             1002  Advanced Micro Devices, Inc. [AMD/ATI]\n\
             \t743f  Navi 24 [Radeon RX 6500M]\n\
             \t\t1002 0b0e  Carte d'un assembleur\n\
             10de  NVIDIA Corporation\n\
             \t25a2  GA107M [GeForce RTX 3050 Mobile]\n\
             1d0f  Fabricant Essai\n\
             8086  Intel Corporation\n\
             \t46a6  Alder Lake-P GT2 [Iris Xe Graphics]\n\
             \t51f0  Wi-Fi 6E\n\
             C 03  Display controller\n\
             \t00  VGA compatible controller\n",
        );
        let cartes = cartes_graphiques_sous(&d);
        let vus: Vec<(String, &str)> = cartes
            .iter()
            .map(|c| (nom_graphique(&c.fabricant, &c.puce), c.pilote.as_str()))
            .collect();
        assert_eq!(
            vus,
            [
                ("Intel Iris Xe Graphics".to_string(), "i915"),
                ("NVIDIA GeForce RTX 3050 Mobile".to_string(), ""),
                ("AMD Radeon RX 6500M".to_string(), "amdgpu"),
                ("Fabricant Essai Device abcd".to_string(), ""),
            ]
        );
        assert_eq!(cartes[1].fabricant, "NVIDIA Corporation");
        // Sans liste de noms : les numéros, rien d'inventé.
        let _ = std::fs::remove_file(d.join("usr/share/hwdata/pci.ids"));
        let sans_noms = cartes_graphiques_sous(&d);
        assert_eq!(
            (sans_noms[0].fabricant.as_str(), sans_noms[0].puce.as_str()),
            ("Vendor 8086", "Device 46a6")
        );
        // Sans sysfs : aucune carte, et la liste n'est pas lue.
        assert_eq!(cartes_graphiques_sous(&d.join("vide")), []);
        assert_eq!(
            nom_graphique("Advanced Micro Devices, Inc. [AMD/ATI]", "Navi 31 [Radeon RX 7900 XT]"),
            "AMD Radeon RX 7900 XT"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// pci.ids : la puce se cherche sous son seul fabricant (le même numéro existe ailleurs), jamais dans les cartes
    /// des assembleurs (deux tabulations) ni dans la liste des classes qui suit les fabricants.
    #[cfg(target_os = "linux")]
    #[test]
    fn noms_de_pci_ids() {
        let ids = "1002  AMD\n\t\t1234 5678  Sous-système\n\t0001  Puce AMD\n\
                   10de  NVIDIA\n\t0002  Puce NVIDIA\nC 12  Classe\n\t1234  Pas une puce\n";
        assert_eq!(noms_pci(ids, 0x1002, 0x0001), (Some("AMD"), Some("Puce AMD")));
        assert_eq!(noms_pci(ids, 0x1002, 0x0002), (Some("AMD"), None));
        assert_eq!(noms_pci(ids, 0x1002, 0x1234), (Some("AMD"), None));
        assert_eq!(noms_pci(ids, 0x10de, 0x0002), (Some("NVIDIA"), Some("Puce NVIDIA")));
        assert_eq!(noms_pci(ids, 0x0c12, 0x1234), (None, None));
        assert_eq!(noms_pci("", 0x10de, 0x0002), (None, None));
    }

    /// Sur cet ordinateur, sysfs donne les mêmes cartes graphiques et les mêmes pilotes que `lspci -vmmk`, quand il
    /// est là.
    #[cfg(target_os = "linux")]
    #[test]
    fn graphiques_comme_lspci() {
        let Some(r) =
            crate::commande::lancer(std::process::Command::new("lspci").arg("-vmmk"), 20).filter(|r| r.code == Some(0))
        else {
            return crate::essais::saute("lspci absent");
        };
        let natifs: Vec<(String, String)> = cartes_graphiques()
            .into_iter()
            .map(|c| (nom_graphique(&c.fabricant, &c.puce), c.pilote))
            .collect();
        assert_eq!(natifs, graphiques_lspci(&r.sortie));
    }

    /// Le fichier de udev (« E:CLÉ=valeur », d'autres lignes pour ses liens et ses étiquettes) se lit comme la
    /// sortie de udevadm.
    #[test]
    fn proprietes_du_fichier_de_udev() {
        let fichier = "I:12345678\nE:ID_VENDOR=Essai\nE:MEMORY_DEVICE_0_SIZE=8589934592\nG:etiquette\n\
                       E:MEMORY_DEVICE_0_LOCATOR=DIMM_A1\n";
        assert_eq!(
            proprietes_udev(fichier),
            "ID_VENDOR=Essai\nMEMORY_DEVICE_0_SIZE=8589934592\nMEMORY_DEVICE_0_LOCATOR=DIMM_A1"
        );
        let (barrettes, _) = barrettes_udev(&proprietes_udev(fichier));
        assert_eq!(barrettes.len(), 1);
        assert_eq!(barrettes[0].emplacement, "DIMM_A1");
        assert_eq!(proprietes_udev(""), "");
    }

    /// Sur cet ordinateur, le fichier de udev donne les mêmes barrettes que `udevadm info`, quand il est là.
    #[cfg(target_os = "linux")]
    #[test]
    fn barrettes_comme_udevadm() {
        let Some(r) = crate::commande::lancer(
            std::process::Command::new("udevadm").args(["info", "--query=property", "--path=/sys/class/dmi/id"]),
            20,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("udevadm absent");
        };
        let fichier = std::fs::read_to_string("/run/udev/data/+dmi:id").unwrap_or_default();
        assert_eq!(barrettes_udev(&proprietes_udev(&fichier)), barrettes_udev(&r.sortie));
    }

    /// Le nom du cœur ARM, comme lscpu, d'après /proc/cpuinfo ou le registre MIDR ; un code inconnu ne donne rien.
    #[test]
    fn coeurs_arm() {
        assert_eq!(coeur_cpuinfo("0x41", "0xd08"), Some("Cortex-A72"));
        assert_eq!(coeur_cpuinfo(" 0x41", "0xd0c "), Some("Neoverse-N1"));
        assert_eq!(coeur_cpuinfo("0x41", "0xfff"), None);
        assert_eq!(coeur_cpuinfo("65", "3336"), None, "toujours en hexadécimal");
        assert_eq!(coeur_midr("0x00000000410fd083\n"), Some("Cortex-A72"));
        assert_eq!(coeur_midr("0x00000000413fd0c1"), Some("Neoverse-N1"));
        assert_eq!(coeur_midr("0x000000004e0f0030"), None, "fabricant inconnu");
        assert_eq!(coeur_midr(""), None);
    }

    /// Le nom du processeur selon le système : x86, POWER, ARM 64 bits par /proc/cpuinfo ou par MIDR seul, et
    /// une carte ARM inconnue, qui reste vide (jamais le nom de la carte).
    #[test]
    fn noms_des_processeurs() {
        let x86 = "processor\t: 0\ncpu family\t: 25\nmodel name\t: Processeur Essai 8 cœurs\ncpu cores\t: 8\n";
        assert_eq!(nom_du_processeur(x86, ""), "Processeur Essai 8 cœurs");
        let power = "processor\t: 0\ncpu\t\t: POWER9, altivec supported\nclock\t\t: 2300.000000MHz\n";
        assert_eq!(nom_du_processeur(power, ""), "POWER9, altivec supported");
        let arm = "processor\t: 0\nBogoMIPS\t: 108.00\nCPU implementer\t: 0x41\nCPU part\t: 0xd08\n";
        assert_eq!(nom_du_processeur(arm, ""), "Cortex-A72");
        assert_eq!(nom_du_processeur("", "0x00000000413fd0c1\n"), "Neoverse-N1");
        let inconnu = "processor\t: 0\nCPU implementer\t: 0x99\nCPU part\t: 0x001\n";
        assert_eq!(nom_du_processeur(inconnu, "0x00000000990f0010"), "");
    }

    /// Le nom du processeur, comme le « Model name » de lscpu quand il est là.
    #[cfg(target_os = "linux")]
    #[test]
    fn processeur_comme_lscpu() {
        let Some(r) = crate::commande::lancer(std::process::Command::new("lscpu").env("LC_ALL", "C"), 20)
            .filter(|r| r.code == Some(0))
        else {
            return crate::essais::saute("lscpu absent");
        };
        let Some(attendu) = r
            .sortie
            .lines()
            .find_map(|l| l.strip_prefix("Model name:"))
            .map(str::trim)
        else {
            return crate::essais::saute("lscpu sans « Model name »");
        };
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let midr =
            std::fs::read_to_string("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1").unwrap_or_default();
        let natif = nom_du_processeur(&cpuinfo, &midr);
        // Un cœur absent de notre petite table reste vide : non renseigné, jamais un autre nom.
        assert!(natif.is_empty() || natif == attendu, "{natif} ≠ {attendu}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disques_entiers() {
        let disque = |nom: &str, genre: &str| crate::machine::linux::natif::Disque {
            nom: nom.into(),
            octets: 1,
            rotatif: false,
            amovible: false,
            modele: String::new(),
            serie: String::new(),
            bus: String::new(),
            genre: genre.into(),
        };
        assert!(disque_entier(&disque("nvme0n1", "disk")));
        assert!(disque_entier(&disque("mmcblk0", "disk")));
        assert!(!disque_entier(&disque("md127", "disk")), "RAID logiciel");
        assert!(!disque_entier(&disque("sr0", "rom")));
        assert!(!disque_entier(&disque("dm-0", "dm")));
    }

    /// Les disques de la fiche sont ceux que lsblk dit « disk » (sans zram, loop, ram ni lecteur), quand il est là :
    /// une grappe RAID logicielle n'en est pas un.
    #[cfg(target_os = "linux")]
    #[test]
    fn disques_comme_lsblk() {
        let Some(r) = crate::commande::lancer(std::process::Command::new("lsblk").args(["-dno", "NAME,TYPE"]), 20)
            .filter(|r| r.code == Some(0))
        else {
            return crate::essais::saute("lsblk absent");
        };
        let garde = |nom: &str| !["zram", "loop", "ram", "sr"].iter().any(|p| nom.starts_with(p));
        let mut attendus: Vec<&str> = r
            .sortie
            .lines()
            .filter_map(|l| l.split_once(' ').map(|(n, t)| (n, t.trim())))
            .filter(|&(n, t)| t == "disk" && garde(n))
            .map(|(n, _)| n)
            .collect();
        attendus.sort_unstable();
        let natifs: Vec<String> = crate::machine::linux::natif::disques()
            .into_iter()
            .filter(|d| disque_entier(d) && garde(&d.nom))
            .map(|d| d.nom)
            .collect();
        assert_eq!(natifs, attendus);
    }

    #[test]
    fn barrettes_lues_par_udev() {
        // Valeurs inventées : un emplacement vide, deux barrettes.
        let texte = "MEMORY_ARRAY_LOCATION=System Board Or Motherboard\n\
                     MEMORY_DEVICE_0_PRESENT=0\nMEMORY_DEVICE_0_LOCATOR=DIMMA1\n\
                     MEMORY_DEVICE_1_SIZE=17179869184\nMEMORY_DEVICE_1_TYPE=DDR5\nMEMORY_DEVICE_1_SPEED_MTS=6400\n\
                     MEMORY_DEVICE_1_CONFIGURED_SPEED_MTS=6000\nMEMORY_DEVICE_1_MANUFACTURER=Unknown\n\
                     MEMORY_DEVICE_1_PART_NUMBER=ESSAI-6400 \nMEMORY_DEVICE_1_LOCATOR=DIMMA2\nMEMORY_DEVICE_1_SERIAL_NUMBER=ABCD1234\n\
                     MEMORY_DEVICE_2_SIZE=17179869184\nMEMORY_DEVICE_2_TYPE=DDR5\nMEMORY_DEVICE_2_LOCATOR=DIMMB2\n\
                     MEMORY_DEVICE_2_SERIAL_NUMBER=Unknown\n";
        let (barrettes, series) = barrettes_udev(texte);
        assert_eq!(barrettes.len(), 2);
        assert_eq!(
            barrettes[0],
            Barrette {
                taille: 17_179_869_184,
                sorte: "DDR5".into(),
                vitesse: Some(6000),
                fabricant: String::new(),
                reference: "ESSAI-6400".into(),
                emplacement: "DIMMA2".into(),
            }
        );
        assert_eq!(barrettes[1].vitesse, None);
        // Le numéro de série, à part : jamais dans la fiche écrite.
        assert_eq!(series, [("Barrette DIMMA2".to_string(), "ABCD1234".to_string())]);
        assert_eq!(
            barrette_en_texte(&barrettes[0]),
            "16 Go DDR5 6000 MT/s · ESSAI-6400 · DIMMA2"
        );
    }

    #[test]
    fn fiche_windows_sans_series_dans_le_json() {
        let lecture: LectureWindows = serde_json::from_str(
            r#"{"systeme":"Microsoft Windows 11 Famille","version":"24H2","build":"26100.2033","fabricant":"LENOVO",
                "modele":"21AH","carte_fabricant":"LENOVO","carte":"21AH00XXUS","bios":"N3MET16W","bios_date":"2023-05-11",
                "processeur":"AMD Ryzen 7 PRO 6850U","coeurs":8,"fils":16,"memoire":34359738368,
                "barrettes":[{"taille":17179869184,"sorte":34,"vitesse":4800,"fabricant":"Samsung","reference":"ESSAI","emplacement":"DIMM 0","serie":"00000000"}],
                "graphique":[{"nom":"AMD Radeon(TM) Graphics","pilote":"31.0.21001.45002","date":"2024-03-01"}],
                "disques":[{"nom":"0","modele":"Disque d'essai 1 To","taille":1024209543168,"sorte":"SSD","bus":"NVMe","serie":"E823_8FA6_BF53_0001."}],
                "serie":"PF0ESSAI","serie_carte":"To be filled by O.E.M."}"#,
        )
        .unwrap();
        let f = fiche_windows(lecture);
        assert_eq!(f.systeme, "Microsoft Windows 11 Famille 24H2 (26100.2033)");
        assert_eq!(f.modele, "LENOVO 21AH");
        assert_eq!(f.bios, "N3MET16W (2023-05-11)");
        assert_eq!(f.barrettes[0].sorte, "DDR5");
        assert_eq!(f.disques[0].sorte, "SSD NVMe");
        assert_eq!(f.graphique[0].pilote, "31.0.21001.45002 (2024-03-01)");
        // Numéros d'usine écartés ; les vrais à part.
        assert_eq!(f.series.len(), 2, "{:?}", f.series);
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("PF0ESSAI") && !json.contains("E823_8FA6"), "{json}");
    }

    #[test]
    fn fiche_macos_apple_silicon_et_intel() {
        let silicon: serde_json::Value = serde_json::from_str(
            r#"{"SPHardwareDataType":[{"machine_name":"MacBook Air","machine_model":"Mac14,2","chip_type":"Apple M2",
                "number_processors":"proc 8:4:4","physical_memory":"16 GB","serial_number":"C02ESSAI"}],
                "SPMemoryDataType":[{"SPMemoryDataType":"16 GB","dimm_manufacturer":"Hynix","dimm_type":"LPDDR5"}],
                "SPDisplaysDataType":[{"_name":"Apple M2","sppci_model":"Apple M2","sppci_cores":"10"}]}"#,
        )
        .unwrap();
        let f = fiche_macos(&silicon);
        assert_eq!(f.modele, "MacBook Air · Mac14,2");
        assert_eq!((f.processeur.as_str(), f.coeurs), ("Apple M2", Some(8)));
        assert_eq!(f.memoire, Some(16 << 30));
        assert_eq!(f.barrettes[0].sorte, "LPDDR5");
        assert_eq!(f.graphique[0].nom, "Apple M2 (10 cœurs)");
        assert!(!serde_json::to_string(&f).unwrap().contains("C02ESSAI"));
        let intel: serde_json::Value = serde_json::from_str(
            r#"{"SPHardwareDataType":[{"machine_name":"iMac","cpu_type":"Quad-Core Intel Core i5","number_processors":4,"physical_memory":"8 GB"}],
                "SPMemoryDataType":[{"_items":[{"_name":"BANK 0/DIMM0","dimm_size":"4 GB","dimm_speed":"2400 MHz","dimm_type":"DDR4"},
                                               {"_name":"BANK 1/DIMM0","dimm_size":"empty","dimm_type":"empty"}]}]}"#,
        )
        .unwrap();
        let f = fiche_macos(&intel);
        assert_eq!(f.coeurs, Some(4));
        assert_eq!(f.barrettes.len(), 1);
        assert_eq!(f.barrettes[0].vitesse, Some(2400));
        assert_eq!(taille_lue("512 MB"), Some(512 << 20));
        assert_eq!(taille_lue("vide"), None);
    }

    /// Le WMI de Wine connaît le système : la fiche se lit sans PowerShell, avec les clés qu'attend fiche_windows.
    #[cfg(windows)]
    #[test]
    fn fiche_windows_directe() {
        let l = lire_directement().expect("Win32_OperatingSystem répond");
        for cle in [
            "systeme",
            "build",
            "processeur",
            "fils",
            "barrettes",
            "graphique",
            "disques",
            "serie",
        ] {
            assert!(l.get(cle).is_some(), "{cle}");
        }
        assert!(l["systeme"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn fiche_windows_cas_limites() {
        // Valeurs inventées : textes d'usine, champs vides ou absents, zéros, chaque sorte de disque.
        let lecture: LectureWindows = serde_json::from_str(
            r#"{"systeme":" Microsoft Windows 10 Pro ","version":"","build":"","fabricant":"System manufacturer",
                "modele":"Essai 3000","carte_fabricant":"ASUSTeK","carte":"ASUSTeK PRIME B450","bios":"Default string",
                "bios_date":"2020-01-01","processeur":" Processeur d'essai ","coeurs":0,"fils":12,"memoire":0,
                "barrettes":[{"taille":8589934592,"sorte":26,"vitesse":0,"fabricant":"Unknown","reference":" REF-1 ",
                              "emplacement":" DIMM 1 ","serie":"ABCD"},
                             {"taille":8589934592,"sorte":99,"vitesse":3200,"emplacement":"","serie":"Unknown"}],
                "graphique":[{"nom":" Carte d'essai ","pilote":" 1.2.3 ","date":""},
                             {"nom":"Autre","pilote":"","date":"2024-01-01"}],
                "disques":[{"nom":"1","modele":" Clé d'essai ","taille":32000000000,"sorte":"Unspecified","bus":"USB",
                            "serie":"0"},
                           {"nom":"2","modele":"Disque d'essai","taille":2000000000000,"sorte":"HDD","bus":"SATA",
                            "serie":"WD-ESSAI"},
                           {"nom":"3","modele":"","taille":0,"sorte":"Unspecified","bus":"SATA"},
                           {"nom":"4","modele":"SSD d'essai","taille":500000000000,"sorte":"SSD","bus":"SAS"}]}"#,
        )
        .unwrap();
        let f = fiche_windows(lecture);
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            serde_json::json!({
                "systeme": "Microsoft Windows 10 Pro", "modele": "Essai 3000", "carte_mere": "ASUSTeK PRIME B450",
                "bios": "", "processeur": "Processeur d'essai", "coeurs": null, "fils": 12, "memoire": null,
                "barrettes": [
                    {"taille": 8_589_934_592_u64, "sorte": "DDR4", "vitesse": null, "fabricant": "",
                     "reference": "REF-1", "emplacement": "DIMM 1"},
                    {"taille": 8_589_934_592_u64, "sorte": "", "vitesse": 3200, "fabricant": "", "reference": "",
                     "emplacement": ""}
                ],
                "barrettes_illisibles": false,
                "graphique": [{"nom": "Carte d'essai", "pilote": "1.2.3"}, {"nom": "Autre", "pilote": " (2024-01-01)"}],
                "disques": [
                    {"nom": "1", "modele": "Clé d'essai", "taille": 32_000_000_000_u64, "sorte": "USB"},
                    {"nom": "2", "modele": "Disque d'essai", "taille": 2_000_000_000_000_u64, "sorte": "disque dur"},
                    {"nom": "3", "modele": "", "taille": 0, "sorte": "type inconnu"},
                    {"nom": "4", "modele": "SSD d'essai", "taille": 500_000_000_000_u64, "sorte": "SSD"}
                ]
            })
        );
        assert_eq!(
            f.series,
            [
                ("Barrette DIMM 1".to_string(), "ABCD".to_string()),
                ("Disque 2".to_string(), "WD-ESSAI".to_string())
            ]
        );
    }

    /// Un disque branché dit son modèle, une barrette sa référence, le micrologiciel son fabricant : piégés, ils
    /// arrivent inoffensifs à l'écran comme dans le JSON.
    #[test]
    fn fiche_aux_textes_pieges() {
        let lecture: LectureWindows = serde_json::from_str(
            r#"{"modele":"Essai\u001b]52;c;eA==\u0007","processeur":"CPU\u001b[2K\r",
                "barrettes":[{"taille":1,"reference":"REF\u001b[8m","emplacement":"DIMM\u001b]0;t\u0007","serie":"X\u001b[1A"}],
                "graphique":[{"nom":"Carte\u001b[2K","pilote":"1.2\u0007"}],
                "disques":[{"nom":"1","modele":"Cle\u001b]52;c;eA==\u0007","taille":1,"bus":"USB","serie":"S\u001b[2K"}]}"#,
        )
        .unwrap();
        let f = fiche_windows(lecture);
        let json = serde_json::to_string(&f).unwrap();
        assert!(
            !json.contains("\\u001b") && !json.contains("\\u0007") && !json.contains("\\r"),
            "{json}"
        );
        assert_eq!(f.modele, "Essai�]52;c;eA==�");
        assert_eq!(f.disques[0].modele, "Cle�]52;c;eA==�");
        assert!(
            f.series
                .iter()
                .all(|(q, n)| !crate::ui::contient_un_piege(q) && !crate::ui::contient_un_piege(n))
        );
    }

    #[test]
    fn fiche_macos_cas_limites() {
        // Rien de lisible : une fiche vide, qui le dit pour les barrettes.
        let vide = fiche_macos(&serde_json::json!({"SPHardwareDataType": {"machine_name": "pas un tableau"}}));
        assert_eq!(
            serde_json::to_value(&vide).unwrap(),
            serde_json::json!({
                "systeme": "", "modele": "", "carte_mere": "", "bios": "", "processeur": "", "coeurs": null,
                "fils": null, "memoire": null, "barrettes": [], "barrettes_illisibles": true, "graphique": [],
                "disques": []
            })
        );
        assert_eq!(vide.series, Vec::<(String, String)>::new());
        let mac: serde_json::Value = serde_json::from_str(
            r#"{"SPHardwareDataType":[{"machine_model":"Macmini9,1","chip_type":" ","cpu_type":"Intel",
                "number_processors":"6","boot_rom_version":"1.0","serial_number":"Unknown","physical_memory":"1,5 TB"}],
                "SPMemoryDataType":[{"_items":[{"_name":"DIMM0","dimm_size":"8 Go","dimm_speed":"vite",
                    "dimm_manufacturer":"0x80CE","dimm_part_number":"Unknown","dimm_serial_number":"ESSAI42"}]}],
                "SPDisplaysDataType":[{"_name":"Carte d'essai"},{"sppci_model":"","_name":""}]}"#,
        )
        .unwrap();
        let f = fiche_macos(&mac);
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            serde_json::json!({
                "systeme": "", "modele": "Macmini9,1", "carte_mere": "", "bios": "1.0", "processeur": "Intel",
                "coeurs": 6, "fils": null, "memoire": 1_649_267_441_664_u64,
                "barrettes": [{"taille": 8_589_934_592_u64, "sorte": "", "vitesse": null, "fabricant": "0x80CE",
                               "reference": "", "emplacement": "DIMM0"}],
                "barrettes_illisibles": false,
                "graphique": [{"nom": "Carte d'essai", "pilote": "intégré à macOS"},
                              {"nom": "", "pilote": "intégré à macOS"}],
                "disques": []
            })
        );
        // Sur Mac, le numéro de l'ordinateur est montré tel qu'il est lu ; celui d'une barrette, s'il est renseigné.
        assert_eq!(
            f.series,
            [
                ("Ordinateur".to_string(), "Unknown".to_string()),
                ("Barrette DIMM0".to_string(), "ESSAI42".to_string())
            ]
        );
    }

    #[test]
    fn barrettes_udev_cas_limites() {
        let texte = "MEMORY_DEVICE_X_SIZE=4096\n  MEMORY_DEVICE_3_SIZE=8589934592  \nMEMORY_DEVICE_3_SPEED_MTS=0\n\
                     MEMORY_DEVICE_3_CONFIGURED_SPEED_MTS=abc\nMEMORY_DEVICE_3_TYPE=Unknown\n\
                     MEMORY_DEVICE_3_SERIAL_NUMBER= 00000000 \nMEMORY_DEVICE_4_SIZE=0\n\
                     MEMORY_DEVICE_4_SERIAL_NUMBER=PERDU\nMEMORY_DEVICE_5_SIZE=4294967296\nMEMORY_DEVICE_5_PRESENT=1\n\
                     MEMORY_DEVICE_5_SPEED_MTS=3200\nMEMORY_DEVICE_5_LOCATOR=ChannelA-DIMM0\n\
                     MEMORY_DEVICE_5_SERIAL_NUMBER=SERIE5\nautre ligne\n";
        let (barrettes, series) = barrettes_udev(texte);
        assert_eq!(
            barrettes,
            [
                Barrette {
                    taille: 8_589_934_592,
                    ..Barrette::default()
                },
                Barrette {
                    taille: 4_294_967_296,
                    vitesse: Some(3200),
                    emplacement: "ChannelA-DIMM0".into(),
                    ..Barrette::default()
                }
            ]
        );
        assert_eq!(series, [("Barrette ChannelA-DIMM0".to_string(), "SERIE5".to_string())]);
    }
}
