//! La plateforme du lot (plan de l'envoi, §3) : toujours réduite à une liste fermée, jamais le texte que le système
//! donne. Un nom de distribution inconnu devient « linux-autre », un noyau compilé à la main garde son majeur.mineur
//! seulement, et ce qui ne se lit pas ne fait pas de lot (`None`) plutôt qu'un lot deviné.

use crate::compte_rendu::envoi::{Arch, Edition, FamilleFine, Langue, Plateforme, SystemeVersion};

/// La famille d'après os-release : `ID` d'abord, puis chaque mot d'`ID_LIKE` ; jamais `NAME` ni `PRETTY_NAME`, que
/// n'importe qui peut écrire.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn famille_linux(os_release: &str) -> FamilleFine {
    let de = |id: &str| match id {
        "arch" => Some(FamilleFine::Arch),
        "debian" => Some(FamilleFine::Debian),
        "ubuntu" => Some(FamilleFine::Ubuntu),
        "fedora" => Some(FamilleFine::Fedora),
        "linuxmint" => Some(FamilleFine::Mint),
        _ if id.starts_with("opensuse") || id == "suse" => Some(FamilleFine::Opensuse),
        _ => None,
    };
    let valeur = |cle| crate::socle::systeme::valeur(os_release, cle).unwrap_or_default();
    let id = valeur("ID").to_ascii_lowercase();
    if let Some(f) = de(&id) {
        return f;
    }
    let semblables = valeur("ID_LIKE").to_ascii_lowercase();
    semblables
        .split_whitespace()
        .find_map(de)
        .unwrap_or(FamilleFine::LinuxAutre)
}

/// « 6.17.2-arch1-1 » → « 6.17 » : le majeur.mineur seulement, le reste dirait un noyau fait à la main.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn noyau_reduit(osrelease: &str) -> Option<SystemeVersion> {
    let chiffres = |s: &str| s.bytes().take_while(u8::is_ascii_digit).count();
    let t = osrelease.trim();
    let majeur = &t[..chiffres(t)];
    let reste = t[majeur.len()..].strip_prefix('.').unwrap_or_default();
    let mineur = &reste[..chiffres(reste)];
    if mineur.is_empty() {
        SystemeVersion::new(majeur)
    } else {
        SystemeVersion::new(&format!("{majeur}.{mineur}"))
    }
}

/// Windows : la famille par le numéro de build (22000 et plus : Windows 11), la version est ce numéro.
#[cfg(any(windows, test))]
pub(crate) fn windows(build: &str) -> Option<(FamilleFine, SystemeVersion)> {
    let b: u32 = build.trim().parse().ok()?;
    let famille = if b >= 22_000 {
        FamilleFine::Windows11
    } else {
        FamilleFine::Windows10
    };
    Some((famille, SystemeVersion::new(&b.to_string())?))
}

/// L'édition de Windows d'après `EditionID` ; une valeur inconnue n'en donne aucune.
#[cfg(any(windows, test))]
pub(crate) fn edition_windows(id: &str) -> Option<Edition> {
    let id = id.trim();
    if id.starts_with("Server") {
        Some(Edition::Serveur)
    } else if id.starts_with("Enterprise") || id.starts_with("Education") || id.starts_with("IoTEnterprise") {
        Some(Edition::Entreprise)
    } else if id.starts_with("Professional") {
        Some(Edition::Pro)
    } else if id.starts_with("Core") {
        Some(Edition::Home)
    } else {
        None
    }
}

/// L'architecture de ce programme ; une autre que les deux de la liste ne fait pas de lot.
fn arch() -> Option<Arch> {
    if cfg!(target_arch = "x86_64") {
        Some(Arch::X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(Arch::Aarch64)
    } else {
        None
    }
}

/// La famille, la version réduite et l'édition de ce système.
#[cfg(target_os = "linux")]
fn systeme() -> Option<(FamilleFine, SystemeVersion, Option<Edition>)> {
    let noyau = crate::socle::lire_texte_ordinaire(std::path::Path::new("/proc/sys/kernel/osrelease"), 256).ok()?;
    Some((
        famille_linux(crate::socle::systeme::os_release()),
        noyau_reduit(&noyau)?,
        None,
    ))
}

#[cfg(windows)]
fn systeme() -> Option<(FamilleFine, SystemeVersion, Option<Edition>)> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let v = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .ok()?;
    let build: String = v.get_value("CurrentBuildNumber").ok()?;
    let edition: String = v.get_value("EditionID").unwrap_or_default();
    let (famille, version) = windows(&build)?;
    Some((famille, version, edition_windows(&edition)))
}

/// La plateforme de ce processus. `administrateur` : lancé élevé sous Windows ; ailleurs toujours faux, puisqu'en
/// root rien n'est relevé ni envoyé (`amelioration::Lieu::en_root`).
pub(crate) fn plateforme() -> Option<Plateforme> {
    let (famille, systeme_version, edition) = systeme()?;
    #[cfg(windows)]
    let administrateur = crate::machine::windows::processus::eleve();
    #[cfg(not(windows))]
    let administrateur = false;
    Some(Plateforme {
        famille,
        systeme_version,
        arch: arch()?,
        langue: if crate::langue::anglais() {
            Langue::En
        } else {
            Langue::Fr
        },
        edition,
        administrateur,
    })
}
