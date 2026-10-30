//! L'heure réglée automatiquement : une horloge qui dérive de quelques minutes fait échouer les sites sécurisés
//! (certificats « pas encore valides » ou « expirés »), Windows Update et les codes de double authentification.
//! Vanguard regarde si le système règle l'heure tout seul (NTP) ; il ne mesure pas l'écart lui-même, ce qui
//! demanderait d'interroger un serveur. Sous macOS, le réglage ne se lit pas sans droits administrateur : rien n'est dit.

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::tr;

const CAT: &str = "Heure";

/// L'état lu : synchronisation activée, et faite (`None` : on ne sait pas).
#[derive(Debug, PartialEq, Eq)]
struct Etat {
    automatique: bool,
    synchronisee: Option<bool>,
}

fn juger(e: &Etat) -> Constat {
    if !e.automatique {
        let c = alerte(
            CAT,
            Niveau::Moyen,
            tr!(
                "L'heure n'est pas réglée automatiquement : une horloge qui dérive fait échouer les sites sécurisés, les mises à jour et les codes de double authentification.",
                "The time is not set automatically: a drifting clock makes secure sites, updates and two-factor codes fail."
            ),
        );
        return if cfg!(windows) {
            c.corriger(
                tr!("Régler l'heure automatiquement (service de temps de Windows)", "Set the time automatically (Windows time service)"),
                &[
                    r"Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name Type -Value NTP",
                    "Set-Service w32time -StartupType Automatic",
                    "Start-Service w32time",
                    "w32tm /resync /force",
                ],
            )
        } else {
            let c = c.corriger(
                tr!(
                    "Régler l'heure automatiquement (NTP)",
                    "Set the time automatically (NTP)"
                ),
                &["sudo timedatectl set-ntp true"],
            );
            // Se défait : l'état d'avant (« no ») est relevé, puis remis par timedatectl.
            #[cfg(target_os = "linux")]
            let c = c.annulable(vec![crate::optimiser::Geste::ntp()]);
            c
        };
    }
    match e.synchronisee {
        Some(false) => alerte(
            CAT,
            Niveau::Info,
            tr!(
                "Réglage automatique de l'heure activé, mais pas encore synchronisé (pas d'Internet, ou démarrage récent).",
                "Automatic time setting is on, but not synchronized yet (no Internet, or recent startup)."
            ),
        ),
        _ => ok(
            CAT,
            tr!("L'heure est réglée automatiquement.", "The time is set automatically."),
        ),
    }
}

/// Les services de temps que systemd sait piloter (listes de ntp-units.d : systemd-timesyncd, chronyd…), installés ;
/// l'heure est automatique si l'un d'eux est activé. C'est la règle de timedated (« NTP » de timedatectl), lue sans le
/// lancer. Aucun service installé (un conteneur) : rien à dire, comme « CanNTP=no ».
#[cfg(any(target_os = "linux", test))]
fn juger_unites(
    listes: &str,
    installee: impl Fn(&str) -> bool,
    activee: impl Fn(&str) -> bool,
    synchronisee: Option<bool>,
) -> Option<Etat> {
    let unites: Vec<&str> = listes
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|u| installee(u))
        .collect();
    if unites.is_empty() {
        return None;
    }
    Some(Etat {
        automatique: unites.iter().any(|u| activee(u)),
        synchronisee,
    })
}

#[cfg(target_os = "linux")]
fn lire() -> Option<Etat> {
    use std::path::Path;
    if !Path::new("/run/systemd/system").is_dir() {
        return None;
    }
    let mut listes = String::new();
    for d in [
        "/etc/systemd/ntp-units.d",
        "/run/systemd/ntp-units.d",
        "/usr/local/lib/systemd/ntp-units.d",
        "/usr/lib/systemd/ntp-units.d",
    ] {
        for f in std::fs::read_dir(d).into_iter().flatten().flatten() {
            if f.path().extension().is_some_and(|e| e == "list") {
                listes.push_str(&std::fs::read_to_string(f.path()).unwrap_or_default());
                listes.push('\n');
            }
        }
    }
    let installee = |u: &str| {
        [
            "/etc/systemd/system",
            "/usr/local/lib/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
        ]
        .iter()
        .any(|d| Path::new(d).join(u).exists())
    };
    // Activé : un lien dans un dossier « .wants » de l'administrateur ou du démarrage en cours.
    let activee = |u: &str| {
        ["/etc/systemd/system", "/run/systemd/system"].iter().any(|d| {
            std::fs::read_dir(d).into_iter().flatten().flatten().any(|w| {
                w.file_name().to_string_lossy().ends_with(".wants") && w.path().join(u).symlink_metadata().is_ok()
            })
        })
    };
    juger_unites(&listes, installee, activee, synchronisee())
}

/// L'horloge est-elle synchronisée ? Le noyau le sait (adjtimex), jugé comme timedated : une erreur estimée sous
/// 16 secondes. Pas sur le drapeau « non synchronisée » : chrony sans « rtcsync » le laisse posé pour toujours.
/// `None` : le noyau refuse.
#[cfg(target_os = "linux")]
fn synchronisee() -> Option<bool> {
    // SAFETY: avec `modes` à zéro, adjtimex ne change rien ; il remplit seulement la structure, à nous, passée par
    // un pointeur valable pendant l'appel.
    let (etat, t) = unsafe {
        let mut t: libc::timex = std::mem::zeroed();
        (libc::adjtimex(&raw mut t), t)
    };
    (etat >= 0).then_some(t.maxerror < 16_000_000)
}

/// Windows : le service de temps (Start = 4 : désactivé) et son type de synchronisation (« NoSync » : aucune).
#[cfg(windows)]
fn lire() -> Option<Etat> {
    let cle = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Services\W32Time")
        .ok()?;
    let demarrage: u32 = cle.get_value("Start").unwrap_or(3);
    let genre: String = cle
        .open_subkey("Parameters")
        .and_then(|p| p.get_value("Type"))
        .unwrap_or_default();
    Some(Etat {
        automatique: demarrage != 4 && !genre.eq_ignore_ascii_case("NoSync"),
        synchronisee: None,
    })
}

#[cfg(target_os = "macos")]
fn lire() -> Option<Etat> {
    None
}

pub fn constat() -> Option<Constat> {
    lire().map(|e| juger(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heure_automatique() {
        let listes = "# commentaire\n\nchronyd.service\nsystemd-timesyncd.service\n";
        let installee = |u: &str| u == "systemd-timesyncd.service";
        let e = juger_unites(listes, installee, |u| u == "systemd-timesyncd.service", Some(true)).unwrap();
        assert!(juger(&e).probleme.is_none());
        let e = juger_unites(listes, installee, |_| true, Some(false)).unwrap();
        assert_eq!(juger(&e).probleme, Some(Niveau::Info));
        // chronyd activé mais pas installé ne compte pas : timesyncd, lui, est installé et pas activé.
        let e = juger_unites(listes, installee, |u| u == "chronyd.service", Some(false)).unwrap();
        let c = juger(&e);
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.correctif.as_ref().unwrap().automatique);
        // Aucun service de temps installé, ou aucune liste : rien à dire.
        assert_eq!(juger_unites(listes, |_| false, |_| true, None), None);
        assert_eq!(juger_unites("", |_| true, |_| true, None), None);
    }

    /// Sur cet ordinateur, la lecture directe dit la même chose que timedatectl, quand il est là.
    #[cfg(target_os = "linux")]
    #[test]
    fn comme_timedatectl() {
        let Some(r) = crate::commande::lancer_en_anglais(
            std::process::Command::new("timedatectl").args(["show", "-p", "NTP", "-p", "NTPSynchronized"]),
            10,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("timedatectl absent");
        };
        let Some(e) = lire() else {
            return crate::essais::saute("état NTP illisible par D-Bus");
        };
        assert_eq!(r.sortie.contains("NTP=yes"), e.automatique, "{}", r.sortie);
        if let Some(s) = e.synchronisee {
            assert_eq!(r.sortie.contains("NTPSynchronized=yes"), s, "{}", r.sortie);
        }
    }
}
