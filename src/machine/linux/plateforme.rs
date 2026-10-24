//! Plateforme : ce que le matériel et le noyau protègent sous le système. La sécurité de la plateforme vue par fwupd
//! (attributs HSI : TPM, protection en écriture du BIOS, IOMMU…), le verrouillage du noyau et la signature de ses
//! modules, BPF réservé à root, les espaces de noms ouverts à tous, et le journal d'audit quand auditd est installé.

use super::*;
use crate::machine::regles::{Os, Regle};

inventory::submit! {
    Regle {
        id: "LNX-PLT-001",
        systeme: Os::Linux,
        rang: 233,
        sujet: ("sécurité de la plateforme d'après fwupd (HSI)", "platform security according to fwupd (HSI)"),
        references: &["CIS Controls v8 4.1", "fwupd : Host Security ID"],
        verifier: || vec![securite_plateforme()],
    }
}

inventory::submit! {
    Regle {
        id: "LNX-NOY-001",
        systeme: Os::Linux,
        rang: 231,
        sujet: ("verrouillage du noyau et signature des modules", "kernel lockdown and module signing"),
        references: &["CIS Controls v8 10.5", "ANSSI BP-028 (configuration d'un système GNU/Linux)", "kernel.org : kernel_lockdown(7)"],
        verifier: || verrouillage_noyau().into_iter().collect(),
    }
}

inventory::submit! {
    Regle {
        id: "LNX-NOY-002",
        systeme: Os::Linux,
        rang: 232,
        sujet: ("BPF réservé à root", "BPF reserved for root"),
        references: &["CIS Controls v8 10.5", "kernel.org : unprivileged_bpf_disabled"],
        verifier: || bpf().into_iter().collect(),
    }
}

inventory::submit! {
    Regle {
        id: "LNX-NOY-005",
        systeme: Os::Linux,
        rang: 232,
        sujet: ("espaces de noms ouverts à tous", "user namespaces open to all"),
        references: &["CIS Controls v8 10.5", "kernel.org : user_namespaces(7)"],
        verifier: || espaces_de_noms().into_iter().collect(),
    }
}

inventory::submit! {
    Regle {
        id: "LNX-JRN-001",
        systeme: Os::Linux,
        rang: 234,
        sujet: ("journal d'audit du noyau (auditd)", "kernel audit log (auditd)"),
        references: &["CIS : auditd"],
        verifier: || journal_audit().into_iter().collect(),
    }
}

/// Un attribut de sécurité de la plateforme, d'après fwupd.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Attribut {
    /// Niveau HSI de 1 (protections de base) à 4.
    pub niveau: u8,
    /// Identifiant de fwupd (« org.fwupd.hsi.Tpm.Version20 »).
    pub id: String,
    /// Nom donné par fwupd, en anglais : montré seulement quand Vanguard ne connaît pas l'attribut.
    pub nom: String,
    pub reussi: bool,
}

/// Les attributs à niveau de `fwupdmgr security --json` (1 à 4). Ceux qui dépendent de l'usage (noyau, échange) n'en
/// ont pas ; ceux marqués « obsolètes » ne comptent plus.
pub(super) fn lire_attributs(json: &str) -> Option<Vec<Attribut>> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let attributs = v.get("SecurityAttributes")?.as_array()?;
    Some(
        attributs
            .iter()
            .filter_map(|a| {
                let niveau = u8::try_from(a.get("HsiLevel")?.as_u64()?)
                    .ok()
                    .filter(|n| (1..=4).contains(n))?;
                let drapeaux: Vec<&str> = a
                    .get("Flags")
                    .and_then(|f| f.as_array())
                    .map(|f| f.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                (!drapeaux.contains(&"obsoleted")).then(|| Attribut {
                    niveau,
                    id: a
                        .get("AppstreamId")
                        .and_then(|i| i.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    nom: a.get("Name").and_then(|n| n.as_str()).unwrap_or_default().to_string(),
                    reussi: drapeaux.contains(&"success"),
                })
            })
            .collect(),
    )
}

/// Le niveau HSI : le plus haut niveau dont tous les attributs, et ceux des niveaux en dessous, sont satisfaits ; 0
/// quand une protection de base manque.
pub(super) fn niveau_hsi(attributs: &[Attribut]) -> u8 {
    (1..=4)
        .take_while(|&n| attributs.iter().filter(|a| a.niveau <= n).all(|a| a.reussi))
        .last()
        .unwrap_or(0)
}

/// Les noms à l'écran des attributs les plus courants ; les autres gardent le nom anglais de fwupd.
const NOMS: &[(&str, &str, &str)] = &[
    ("org.fwupd.hsi.Tpm.Version20", "TPM 2.0", "TPM 2.0"),
    (
        "org.fwupd.hsi.Tpm.EmptyPcr",
        "registres du TPM remplis",
        "filled TPM registers",
    ),
    (
        "org.fwupd.hsi.Tpm.ReconstructionPcr0",
        "mesure du démarrage (PCR0)",
        "boot measurement (PCR0)",
    ),
    (
        "org.fwupd.hsi.Uefi.SecureBoot",
        "démarrage sécurisé (Secure Boot)",
        "Secure Boot",
    ),
    ("org.fwupd.hsi.Uefi.Pk", "clé de plateforme UEFI", "UEFI platform key"),
    (
        "org.fwupd.hsi.Uefi.BootserviceVars",
        "variables de démarrage verrouillées",
        "locked boot variables",
    ),
    (
        "org.fwupd.hsi.Spi.Bioswe",
        "protection en écriture du BIOS",
        "BIOS write protection",
    ),
    ("org.fwupd.hsi.Spi.Ble", "verrou d'écriture du BIOS", "BIOS lock"),
    (
        "org.fwupd.hsi.Spi.SmmBwp",
        "protection du BIOS par le mode SMM",
        "SMM BIOS write protection",
    ),
    (
        "org.fwupd.hsi.Amd.SpiWriteProtection",
        "protection en écriture du BIOS",
        "BIOS write protection",
    ),
    (
        "org.fwupd.hsi.Amd.PlatformSecureBoot",
        "démarrage sécurisé du processeur (AMD PSB)",
        "processor secure boot (AMD PSB)",
    ),
    (
        "org.fwupd.hsi.IntelBootguard.Enabled",
        "Intel Boot Guard",
        "Intel Boot Guard",
    ),
    (
        "org.fwupd.hsi.Iommu",
        "IOMMU (contre les accès directs à la mémoire)",
        "IOMMU (against direct memory access)",
    ),
    (
        "org.fwupd.hsi.PrebootDma",
        "protection DMA avant le démarrage",
        "pre-boot DMA protection",
    ),
    (
        "org.fwupd.hsi.PlatformDebugLocked",
        "débogage de la plateforme verrouillé",
        "platform debugging locked",
    ),
    (
        "org.fwupd.hsi.PlatformFused",
        "plateforme verrouillée en usine",
        "platform fused at the factory",
    ),
    (
        "org.fwupd.hsi.Bios.CapsuleUpdates",
        "mises à jour du BIOS",
        "BIOS updates",
    ),
    ("org.fwupd.hsi.EncryptedRam", "mémoire chiffrée", "encrypted memory"),
];

fn nom_de(a: &Attribut) -> String {
    match NOMS.iter().find(|(id, ..)| *id == a.id) {
        Some((_, fr, en)) => (if crate::langue::anglais() { *en } else { *fr }).to_string(),
        // Un texte venu d'un autre programme : neutralisé avant d'être montré.
        None => crate::ui::affichable(&a.nom),
    }
}

/// Les attributs manquants d'un niveau, sans doublon (deux identifiants pour la même protection, Intel et AMD).
fn manquants(attributs: &[Attribut], niveau: u8) -> String {
    let mut noms: Vec<String> = Vec::new();
    for a in attributs.iter().filter(|a| a.niveau == niveau && !a.reussi) {
        let nom = nom_de(a);
        if !noms.contains(&nom) {
            noms.push(nom);
        }
    }
    noms.join(", ")
}

pub(super) fn juger_plateforme(attributs: Option<&[Attribut]>) -> Constat {
    let Some(attributs) = attributs.filter(|a| !a.is_empty()) else {
        return impossible("Plateforme", tr!("fwupd ne répond pas", "fwupd does not answer"));
    };
    match niveau_hsi(attributs) {
        0 => alerte(
            "Plateforme",
            Niveau::Moyen,
            trf!(
                "Sécurité de la plateforme HSI:0 : protections de base absentes ({}). Un logiciel malveillant qui s'installe dans le BIOS ou lit la mémoire y a la voie libre.",
                "Platform security HSI:0: basic protections missing ({}). Malware that settles in the BIOS or reads memory has a free path.",
                manquants(attributs, 1)
            ),
        )
        .manuel(
            tr!(
                "Les activer dans les réglages du BIOS ou de l'UEFI (souvent le TPM et la protection du BIOS) ; le détail :",
                "Turn them on in the BIOS or UEFI settings (often the TPM and BIOS protection); the details:"
            ),
            &["fwupdmgr security"],
        ),
        1 => alerte(
            "Plateforme",
            Niveau::Info,
            trf!(
                "Sécurité de la plateforme HSI:1 : les protections de base sont là ; il manque {} (un réglage du BIOS, ou une limite du fabricant).",
                "Platform security HSI:1: the basic protections are there; missing: {} (a BIOS setting, or a manufacturer limit).",
                manquants(attributs, 2)
            ),
        )
        .manuel(tr!("Le détail", "The details"), &["fwupdmgr security"]),
        n => ok(
            "Plateforme",
            trf!(
                "Sécurité de la plateforme HSI:{n} : TPM, protections du BIOS et de la mémoire en place.",
                "Platform security HSI:{n}: TPM, BIOS and memory protections in place."
            ),
        ),
    }
}

/// La sécurité de la plateforme d'après fwupd, sans droits. Pas dans un espace de noms d'utilisateur (la suite de tests
/// sans réseau) : le service de fwupd y voit un autre compte.
pub(super) fn securite_plateforme() -> Constat {
    if !Path::new("/usr/bin/fwupdmgr").exists() && !Path::new("/bin/fwupdmgr").exists() {
        return impossible(
            "Plateforme",
            tr!("fwupd absent : paquet fwupd", "fwupd missing: fwupd package"),
        );
    }
    if std::fs::read_to_string("/proc/self/uid_map").is_ok_and(|m| !crate::machine::bluetooth::identite(&m)) {
        return impossible("Plateforme", tr!("espace de noms isolé", "isolated namespace"));
    }
    let json = crate::commande::lancer(Command::new("fwupdmgr").args(["security", "--json"]), 20)
        .filter(|r| r.code == Some(0))
        .map(|r| r.sortie);
    juger_plateforme(json.as_deref().and_then(lire_attributs).as_deref())
}

/// Le verrouillage du noyau (« [none] integrity confidentiality ») et la signature obligatoire des modules (« Y »).
/// `None` : un noyau sans l'un ni l'autre, rien à dire.
pub(super) fn juger_verrouillage(lockdown: Option<&str>, signature: Option<&str>) -> Option<Constat> {
    let mode = lockdown
        .and_then(|l| l.split_whitespace().find(|m| m.starts_with('[')))
        .map(|m| m.trim_matches(['[', ']']));
    Some(match (mode, signature.map(str::trim)) {
        (Some(m @ ("integrity" | "confidentiality")), _) => ok(
            "Noyau durci",
            trf!(
                "Noyau verrouillé (mode {m}) : même root ne peut pas le modifier en marche.",
                "Kernel locked down ({m} mode): even root cannot change it while it runs."
            ),
        ),
        (_, Some("Y")) => ok(
            "Noyau durci",
            tr!("Le noyau n'accepte que des modules signés.", "The kernel only accepts signed modules."),
        ),
        (None, None) => return None,
        _ => alerte(
            "Noyau durci",
            Niveau::Info,
            tr!(
                "Noyau non verrouillé, modules non signés acceptés : un programme qui obtient les droits root peut y charger un pilote piégé.",
                "Kernel not locked down, unsigned modules accepted: a program that gets root rights can load a rigged driver into it."
            ),
        )
        .manuel(
            tr!(
                "Paramètre de démarrage lockdown=integrity (ou module.sig_enforce=1), seulement quand tous les pilotes sont signés : ceux de NVIDIA et de DKMS doivent l'être d'abord, sinon ils ne se chargent plus",
                "Boot parameter lockdown=integrity (or module.sig_enforce=1), only once all drivers are signed: NVIDIA and DKMS ones must be first, or they no longer load"
            ),
            &[],
        ),
    })
}

pub(super) fn verrouillage_noyau() -> Option<Constat> {
    juger_verrouillage(
        std::fs::read_to_string("/sys/kernel/security/lockdown").ok().as_deref(),
        std::fs::read_to_string("/sys/module/module/parameters/sig_enforce")
            .ok()
            .as_deref(),
    )
}

/// BPF permis à tous (`kernel.unprivileged_bpf_disabled` à 0) : une porte connue vers les droits root. 2, que les
/// grandes distributions posent, se rechange par root ; 1 se verrouille jusqu'au redémarrage.
pub(super) fn juger_bpf(valeur: Option<i64>) -> Option<Constat> {
    (valeur == Some(0)).then(|| {
        alerte(
            "Noyau durci",
            Niveau::Info,
            tr!(
                "Tout programme peut charger du code BPF dans le noyau : une porte souvent utilisée pour obtenir les droits root.",
                "Any program can load BPF code into the kernel: a door often used to get root rights."
            ),
        )
        .manuel(
            tr!("Le réserver à root jusqu'au redémarrage", "Reserve it for root until restart"),
            &["sudo sysctl -w kernel.unprivileged_bpf_disabled=2"],
        )
    })
}

pub(super) fn bpf() -> Option<Constat> {
    juger_bpf(
        std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
            .ok()
            .and_then(|v| v.trim().parse().ok()),
    )
}

/// Espaces de noms sans droits : un programme ordinaire s'y donne des droits root à l'intérieur et atteint ainsi des
/// parties du noyau d'habitude réservées à root, une voie fréquente des failles du noyau. Flatpak, Chrome, Steam et
/// Podman en ont besoin : une information, jamais une correction, qui casserait ces programmes. Sont fermés : le
/// réglage de Debian (`unprivileged_userns_clone` à 0), aucun espace permis (`max_user_namespaces` à 0), ou AppArmor
/// qui les réserve aux programmes qu'il connaît (Ubuntu 23.10 et suivantes).
pub(super) fn juger_espaces_de_noms(
    clone: Option<i64>,
    maximum: Option<i64>,
    apparmor: Option<i64>,
) -> Option<Constat> {
    let fermes = clone == Some(0) || maximum == Some(0) || apparmor == Some(1);
    // Réglage illisible : noyau sans espaces de noms, ou rien à conclure.
    (maximum.is_some() && !fermes).then(|| {
        alerte(
            "Noyau durci",
            Niveau::Info,
            tr!(
                "Tout programme peut créer des espaces de noms et s'y donner des droits root : une voie fréquente des failles du noyau. Flatpak, Chrome et Steam en ont besoin, Vanguard n'y touche pas.",
                "Any program can create user namespaces and give itself root rights inside: a frequent path for kernel flaws. Flatpak, Chrome and Steam need them, Vanguard leaves them alone."
            ),
        )
    })
}

pub(super) fn espaces_de_noms() -> Option<Constat> {
    let lire = |chemin: &str| std::fs::read_to_string(chemin).ok().and_then(|v| v.trim().parse().ok());
    juger_espaces_de_noms(
        lire("/proc/sys/kernel/unprivileged_userns_clone"),
        lire("/proc/sys/user/max_user_namespaces"),
        lire("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
    )
}

/// Le journal d'audit du noyau : seulement quand auditd est installé (Fedora le lance ; ailleurs, il vient souvent avec
/// d'autres paquets sans être voulu, d'où une information, jamais une alerte).
pub(super) fn juger_journal_audit(installe: bool, actif: bool) -> Option<Constat> {
    if !installe {
        return None;
    }
    Some(if actif {
        ok(
            "Journal d'audit",
            tr!(
                "auditd tient le journal d'audit du noyau.",
                "auditd keeps the kernel audit log."
            ),
        )
    } else {
        alerte(
            "Journal d'audit",
            Niveau::Info,
            tr!(
                "auditd est installé mais arrêté : le noyau ne garde pas trace des accès sensibles (comptes, sudo, réglages).",
                "auditd is installed but stopped: the kernel keeps no trace of sensitive access (accounts, sudo, settings)."
            ),
        )
        .corriger(
            tr!("Le lancer, et le garder au démarrage", "Start it, and keep it at boot"),
            &["sudo systemctl enable --now auditd"],
        )
        .annulable(vec![crate::optimiser::Geste::unite("auditd")])
    })
}

pub(super) fn journal_audit() -> Option<Constat> {
    // Sans systemd (Alpine, Void, Gentoo openrc), « systemctl enable auditd » ne marcherait pas : rien à dire.
    if !super::systemd() {
        return None;
    }
    let installe = ["/usr/bin/auditd", "/usr/sbin/auditd", "/sbin/auditd"]
        .iter()
        .any(|p| Path::new(p).exists());
    let actif = installe
        && service_tourne_dans(&RACINES_CGROUP.map(Path::new), "auditd.service")
            .unwrap_or_else(|| super::service_actif("auditd"));
    juger_journal_audit(installe, actif)
}

/// Les hiérarchies où systemd range ses services : cgroup2 seul, cgroup2 d'un système hybride, puis l'arbre
/// « name=systemd » de cgroup1.
const RACINES_CGROUP: [&str; 3] = ["/sys/fs/cgroup", "/sys/fs/cgroup/unified", "/sys/fs/cgroup/systemd"];

/// Le service tourne-t-il, comme `systemctl is-active` le dirait ? systemd place chaque service dans son groupe de
/// contrôle, sous system.slice (ou une tranche à lui, system-cups.slice) : il tourne tant que ce groupe a des
/// processus. `None` sans hiérarchie lisible (pas de systemd, /sys absent) : non vérifié.
fn service_tourne_dans(racines: &[&Path], unite: &str) -> Option<bool> {
    let systeme = racines.iter().map(|r| r.join("system.slice")).find(|d| d.is_dir())?;
    let mut a_voir = vec![(systeme, 0u8)];
    while let Some((dossier, profondeur)) = a_voir.pop() {
        for e in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
            if !e.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let nom = e.file_name();
            if nom == unite {
                return Some(
                    std::fs::read_to_string(e.path().join("cgroup.procs")).is_ok_and(|p| !p.trim().is_empty()),
                );
            }
            // Seules les tranches contiennent d'autres services ; quatre étages suffisent à toutes.
            if profondeur < 4 && nom.to_string_lossy().ends_with(".slice") {
                a_voir.push((e.path(), profondeur + 1));
            }
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_actif_selon_son_groupe() {
        let racine = std::env::temp_dir().join(format!("vanguard-cgroup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&racine);
        let ecrire = |c: &str, t: &str| {
            let f = racine.join(c);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, t).unwrap();
        };
        ecrire("unified/system.slice/auditd.service/cgroup.procs", "812\n");
        ecrire(
            "unified/system.slice/system-cups.slice/cups.service/cgroup.procs",
            "940\n",
        );
        ecrire("unified/system.slice/arrete.service/cgroup.procs", "");
        // Un système hybride : la première racine n'a pas de system.slice.
        let racines = [racine.as_path(), &racine.join("unified")];
        assert_eq!(service_tourne_dans(&racines, "auditd.service"), Some(true));
        assert_eq!(service_tourne_dans(&racines, "cups.service"), Some(true));
        assert_eq!(service_tourne_dans(&racines, "arrete.service"), Some(false));
        assert_eq!(service_tourne_dans(&racines, "absent.service"), Some(false));
        assert_eq!(
            service_tourne_dans(&[racine.join("rien").as_path()], "auditd.service"),
            None
        );
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Sur cet ordinateur, les mêmes réponses que `systemctl is-active`, quand il est là.
    #[test]
    fn service_actif_comme_systemctl() {
        for unite in [
            "auditd",
            "systemd-journald",
            "systemd-resolved",
            "sshd",
            "cups",
            "avahi-daemon",
        ] {
            // Sans réponse (pas de bus de systemd, comme dans un espace de noms d'utilisateur), rien à comparer.
            let Some(r) = crate::commande::lancer(Command::new("systemctl").args(["is-active", unite]), 10)
                .filter(|r| !r.sortie.trim().is_empty())
            else {
                return crate::essais::saute("systemctl sans réponse");
            };
            let Some(natif) = service_tourne_dans(&RACINES_CGROUP.map(Path::new), &format!("{unite}.service")) else {
                return crate::essais::saute("cgroups illisibles");
            };
            assert_eq!(natif, r.sortie.trim() == "active", "{unite} : {}", r.sortie.trim());
        }
    }

    /// La forme de `fwupdmgr security --json` (fwupd 2), relevée sur un vrai ordinateur et raccourcie.
    const JSON: &str = r#"{"SecurityAttributes":[
        {"AppstreamId":"org.fwupd.hsi.Kernel.Lockdown","HsiResult":"not-enabled","Name":"Linux kernel lockdown","Flags":["runtime-issue","action-config-os"]},
        {"AppstreamId":"org.fwupd.hsi.Tpm.Version20","HsiLevel":1,"HsiResult":"found","Name":"TPM v2.0","Flags":["success"]},
        {"AppstreamId":"org.fwupd.hsi.Uefi.SecureBoot","HsiLevel":1,"HsiResult":"enabled","Name":"UEFI secure boot","Flags":["success"]},
        {"AppstreamId":"org.fwupd.hsi.Iommu","HsiLevel":2,"HsiResult":"enabled","Name":"IOMMU","Flags":["success"]},
        {"AppstreamId":"org.fwupd.hsi.Amd.PlatformSecureBoot","HsiLevel":2,"HsiResult":"not-enabled","Name":"Platform secure boot","Flags":["action-contact-oem"]},
        {"AppstreamId":"org.fwupd.hsi.EncryptedRam","HsiLevel":4,"HsiResult":"not-supported","Name":"Encrypted RAM","Flags":["action-config-fw"]},
        {"AppstreamId":"org.fwupd.hsi.Ancien","HsiLevel":1,"HsiResult":"not-enabled","Name":"Old","Flags":["obsoleted"]}
    ],"SecurityEvents":[]}"#;

    #[test]
    fn niveau_de_la_plateforme_d_apres_fwupd() {
        let attributs = lire_attributs(JSON).unwrap();
        // Les attributs de l'usage (sans niveau) et l'obsolète sont laissés.
        assert_eq!(attributs.len(), 5);
        assert_eq!(niveau_hsi(&attributs), 1);
        let c = juger_plateforme(Some(&attributs));
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(
            c.message.contains("HSI:1") && c.message.contains("AMD PSB"),
            "{}",
            c.message
        );
        // Sans TPM : HSI:0, une alerte.
        let sans_tpm = JSON.replace(
            r#""HsiResult":"found","Name":"TPM v2.0","Flags":["success"]"#,
            r#""HsiResult":"not-found","Name":"TPM v2.0","Flags":[]"#,
        );
        let attributs = lire_attributs(&sans_tpm).unwrap();
        assert_eq!(niveau_hsi(&attributs), 0);
        let c = juger_plateforme(Some(&attributs));
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("TPM 2.0"), "{}", c.message);
        // Rien de lisible : dit, jamais compté comme sain.
        assert!(!juger_plateforme(None).verifie);
        assert_eq!(lire_attributs("pas du json"), None);
    }

    #[test]
    fn un_nom_inconnu_est_neutralise() {
        let a = Attribut {
            niveau: 2,
            id: "org.fwupd.hsi.Nouveau".into(),
            nom: "Piège\x1b[2Kfin".into(),
            reussi: false,
        };
        assert!(!nom_de(&a).contains('\x1b'));
    }

    #[test]
    fn verrouillage_du_noyau() {
        let v = |l: Option<&str>, s: Option<&str>| juger_verrouillage(l, s).map(|c| c.probleme);
        assert_eq!(v(Some("none [integrity] confidentiality\n"), Some("N\n")), Some(None));
        assert_eq!(v(Some("[none] integrity confidentiality\n"), Some("Y\n")), Some(None));
        assert_eq!(
            v(Some("[none] integrity confidentiality\n"), Some("N\n")),
            Some(Some(Niveau::Info))
        );
        assert_eq!(v(None, None), None);
    }

    #[test]
    fn bpf_et_journal_d_audit() {
        assert!(juger_bpf(Some(2)).is_none() && juger_bpf(Some(1)).is_none() && juger_bpf(None).is_none());
        assert_eq!(juger_bpf(Some(0)).map(|c| c.probleme), Some(Some(Niveau::Info)));
        assert!(juger_journal_audit(false, false).is_none());
        assert_eq!(juger_journal_audit(true, true).map(|c| c.probleme), Some(None));
        assert!(juger_journal_audit(true, false).is_some_and(|c| c.correctif.is_some()));
        // Espaces de noms : ouverts (Fedora, Arch), fermés par Debian, par le maximum ou par AppArmor (Ubuntu).
        let ouverts = juger_espaces_de_noms(None, Some(63_000), None).unwrap();
        assert!(ouverts.probleme == Some(Niveau::Info) && ouverts.correctif.is_none());
        assert!(juger_espaces_de_noms(Some(1), Some(63_000), Some(0)).is_some());
        assert!(juger_espaces_de_noms(Some(0), Some(63_000), None).is_none());
        assert!(juger_espaces_de_noms(None, Some(0), None).is_none());
        assert!(juger_espaces_de_noms(None, Some(63_000), Some(1)).is_none());
        assert!(juger_espaces_de_noms(None, None, None).is_none());
    }
}
