//! Deux protections propres au Mac : les définitions de XProtect (l'antivirus intégré) qui arrivent vraiment, et les
//! profils de configuration installés hors gestion d'entreprise, qu'un adware pose pour imposer un proxy, un DNS ou un
//! certificat.

use std::path::Path;
use std::time::SystemTime;

use super::{Constat, alerte, impossible, ok, preference, sortie};
use crate::risk::Niveau;
use crate::{tr, trf};

/// Les définitions de XProtect, aux endroits où macOS les range : depuis Sonoma, son service les met dans
/// /private/var/protected ; avant, dans le système. La plus récente compte.
const XPROTECT: &[&str] = &[
    "/private/var/protected/xprotect/XProtect.bundle/Contents/Info",
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info",
    "/System/Library/CoreServices/XProtect.bundle/Contents/Info",
];

/// Âge des définitions (en jours) et leur version : Apple les met à jour toutes les deux à quatre semaines environ.
fn juger_xprotect(jours: u64, version: Option<&str>) -> Constat {
    let version = version.map_or_else(String::new, |v| trf!(" (version {v})", " (version {v})"));
    if jours > 90 {
        alerte(
            "Protection système",
            Niveau::Moyen,
            trf!(
                "Les définitions de XProtect, l'antivirus intégré du Mac{version}, datent de {jours} jours : ce Mac ne reconnaît pas les logiciels malveillants récents.",
                "XProtect definitions, the Mac's built-in antivirus{version}, are {jours} days old: this Mac does not recognize recent malware."
            ),
        )
        .manuel(
            tr!(
                "Réglages Système › Général › Mise à jour de logiciels › Options : activer « Installer les fichiers de réponses de sécurité et les fichiers système », puis redémarrer",
                "System Settings › General › Software Update › Options: turn on “Install Security Responses and system files”, then restart"
            ),
            &[],
        )
    } else if jours > 45 {
        alerte(
            "Protection système",
            Niveau::Info,
            trf!(
                "Les définitions de XProtect{version} datent de {jours} jours : un peu vieilles, Apple en publie environ chaque mois.",
                "XProtect definitions{version} are {jours} days old: a little old, Apple publishes some about every month."
            ),
        )
    } else {
        ok(
            "Protection système",
            trf!(
                "Définitions de XProtect à jour{version}, il y a {jours} jour(s).",
                "XProtect definitions up to date{version}, {jours} day(s) ago."
            ),
        )
    }
}

pub(super) fn xprotect() -> Constat {
    let trouve = XPROTECT
        .iter()
        .filter_map(|base| {
            let modifie = std::fs::metadata(format!("{base}.plist"))
                .and_then(|m| m.modified())
                .ok()?;
            Some((modifie, *base))
        })
        .max_by_key(|(modifie, _)| *modifie);
    let Some((modifie, base)) = trouve else {
        return impossible(
            "Protection système",
            tr!("définitions de XProtect introuvables", "XProtect definitions not found"),
        );
    };
    let jours = SystemTime::now()
        .duration_since(modifie)
        .map_or(0, |d| d.as_secs() / 86_400);
    let version = Path::new(&format!("{base}.plist"))
        .is_file()
        .then(|| preference(base, "CFBundleShortVersionString"))
        .flatten();
    juger_xprotect(jours, version.as_deref())
}

/// Les identifiants des profils dans la sortie de `profiles list` : « alice[1] attribute: profileIdentifier:
/// com.exemple.profil ». `None` : sortie qui ne ressemble à aucune des deux formes connues (illisible).
fn lire_profils(texte: &str) -> Option<Vec<String>> {
    let profils: Vec<String> = texte
        .lines()
        .filter_map(|l| l.split_once("profileIdentifier:").map(|(_, id)| id.trim().to_string()))
        .filter(|id| !id.is_empty())
        .collect();
    if profils.is_empty() && !texte.contains("no configuration profiles") {
        return None;
    }
    Some(profils)
}

fn juger_profils(profils: &[String], gere: bool) -> Constat {
    if profils.is_empty() {
        return ok(
            "Gestion à distance",
            tr!(
                "Aucun profil de configuration installé pour ce compte.",
                "No configuration profile installed for this account."
            ),
        );
    }
    let liste = profils
        .iter()
        .take(5)
        .map(|p| crate::ui::affichable(p))
        .collect::<Vec<_>>()
        .join(", ");
    if gere {
        return alerte(
            "Gestion à distance",
            Niveau::Info,
            trf!(
                "{} profil(s) de configuration, posés par l'organisation qui gère ce Mac : {liste}.",
                "{} configuration profile(s), set by the organization that manages this Mac: {liste}.",
                profils.len()
            ),
        );
    }
    alerte(
        "Gestion à distance",
        Niveau::Moyen,
        trf!(
            "{} profil(s) de configuration installé(s) hors gestion d'entreprise : {liste}. Un profil peut imposer un proxy, un DNS ou un certificat : des logiciels publicitaires s'en servent pour détourner la navigation.",
            "{} configuration profile(s) installed outside company management: {liste}. A profile can force a proxy, a DNS or a certificate: adware uses them to hijack browsing.",
            profils.len()
        ),
    )
    .manuel(
        tr!(
            "Si vous ne les reconnaissez pas : Réglages Système › Confidentialité et sécurité › Profils, puis les retirer",
            "If you do not recognize them: System Settings › Privacy & Security › Profiles, then remove them"
        ),
        &[],
    )
}

/// Les profils de configuration du compte (sans droits d'administrateur, `profiles list`), jugés selon que ce Mac est
/// géré par une organisation (MDM) ou non.
pub(super) fn profils_de_configuration() -> Option<Constat> {
    let texte = sortie("profiles", &["list"])?;
    let Some(profils) = lire_profils(&texte) else {
        return Some(impossible(
            "Gestion à distance",
            tr!("liste des profils illisible", "profile list unreadable"),
        ));
    };
    let gere = sortie("profiles", &["status", "-type", "enrollment"])
        .is_some_and(|t| t.lines().any(|l| l.contains("MDM enrollment:") && l.contains("Yes")));
    Some(juger_profils(&profils, gere))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xprotect_selon_son_age() {
        assert!(juger_xprotect(10, Some("5272")).probleme.is_none());
        assert!(juger_xprotect(10, Some("5272")).message.contains("5272"));
        assert_eq!(juger_xprotect(60, None).probleme, Some(Niveau::Info));
        assert_eq!(juger_xprotect(120, None).probleme, Some(Niveau::Moyen));
    }

    #[test]
    fn profils_lus_et_juges() {
        assert_eq!(
            lire_profils("There are no configuration profiles installed\n"),
            Some(Vec::new())
        );
        let deux = "alice[1] attribute: profileIdentifier: com.exemple.proxy\n\
                    alice[2] attribute: profileIdentifier: com.exemple.dns\n\
                    There are 2 configuration profiles installed\n";
        assert_eq!(lire_profils(deux).unwrap(), ["com.exemple.proxy", "com.exemple.dns"]);
        assert_eq!(lire_profils("profiles: erreur inattendue"), None);
        let profils = lire_profils(deux).unwrap();
        assert_eq!(juger_profils(&profils, false).probleme, Some(Niveau::Moyen));
        assert_eq!(juger_profils(&profils, true).probleme, Some(Niveau::Info));
        assert!(juger_profils(&[], false).probleme.is_none());
    }
}
