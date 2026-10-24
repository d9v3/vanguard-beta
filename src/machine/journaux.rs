//! Journaux du système : peut-on se fier à leur historique ? Sous Linux, le journal est-il scellé (Forward Secure
//! Sealing de journald : une entrée modifiée ou retirée se voit à la vérification) ; sous Windows, un journal
//! d'événements a-t-il été effacé récemment (Windows note lui-même chaque effacement, événement 104).
//! Aucun programme local ne peut empêcher l'administrateur d'agir : seule une copie hors de la machine le peut.

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Journaux";

/// État du journal de journald : conservé sur disque ou non, scellé ou non.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn juger_journald(persistant: bool, scelle: bool) -> Constat {
    match (persistant, scelle) {
        (false, _) => alerte(
            CAT,
            Niveau::Info,
            tr!(
                "Journal système non conservé après un redémarrage : en cas d'incident, l'historique est perdu.",
                "System journal not kept after a restart: after an incident, the history is lost."
            ),
        )
        .manuel(
            tr!("Conserver le journal sur disque", "Keep the journal on disk"),
            &["sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald"],
        ),
        (true, false) => alerte(
            CAT,
            Niveau::Info,
            tr!(
                "Journal système non scellé : une entrée effacée ou modifiée ne se verrait pas.",
                "System journal not sealed: an erased or modified entry would go unnoticed."
            ),
        )
        .manuel(
            tr!(
                "Sceller le journal, puis noter la clé de vérification affichée ailleurs que sur cet ordinateur",
                "Seal the journal, then write down the verification key it shows somewhere other than this computer"
            ),
            &[
                "sudo journalctl --setup-keys",
                "sudo journalctl --verify --verify-key=<clé notée>",
            ],
        ),
        (true, true) => ok(
            CAT,
            tr!(
                "Journal système scellé : une modification se verrait avec journalctl --verify.",
                "System journal sealed: a change would show with journalctl --verify."
            ),
        ),
    }
}

#[cfg(target_os = "linux")]
pub fn journaux() -> Vec<Constat> {
    let racine = std::path::Path::new("/var/log/journal");
    let persistant = racine.is_dir();
    // journalctl --setup-keys dépose un fichier « fss » dans le dossier de la machine.
    let scelle = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .any(|d| d.path().join("fss").exists());
    vec![juger_journald(persistant, scelle)]
}

/// Effacements de journaux relevés par Windows : (date AAAA-MM-JJ, détail), les plus récents d'abord.
#[cfg_attr(not(windows), allow(dead_code))]
fn juger_effacements(effacements: &[(String, String)], aujourdhui: chrono::NaiveDate) -> Constat {
    let Some((date, detail)) = effacements.first() else {
        return ok(CAT, tr!("Aucun journal d'événements effacé.", "No event log cleared."));
    };
    let recent = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok_and(|d| (aujourdhui - d).num_days() <= 30);
    alerte(
        CAT,
        if recent { Niveau::Moyen } else { Niveau::Info },
        trf!(
            "Journal d'événements effacé le {date} ({detail}). Si ce n'est pas vous, quelqu'un a pu effacer ses traces.",
            "Event log cleared on {date} ({detail}). If it was not you, someone may have erased their tracks."
        ),
    )
}

/// macOS : le journal unifié est géré par le système, qui le garde et ne permet pas de l'effacer simplement ;
/// rien à vérifier ici.
#[cfg(target_os = "macos")]
pub fn journaux() -> Vec<Constat> {
    Vec::new()
}

#[cfg(windows)]
pub fn journaux() -> Vec<Constat> {
    // Événement 104 du journal Système : « le journal … a été effacé », lisible sans droits administrateur. Lu par
    // wevtapi, les valeurs de l'événement dans leur ordre (comme Properties) ; PowerShell si le journal refuse.
    let fin = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let natif = super::windows::evenements::parcourir("System", "*[System[(EventID=104)]]", 5, fin, |_, date, v| {
        let jour: String = super::windows::evenements::date_locale(date)?
            .chars()
            .take(10)
            .collect();
        Some(format!("EFF|{jour}|{}", v.join(" ")))
    });
    let Some(sortie) = natif.map(|l| l.join("\n")).or_else(|| {
        super::windows::ps(
        "Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104 } -MaxEvents 5 -ErrorAction SilentlyContinue | \
         ForEach-Object { \"EFF|$($_.TimeCreated.ToString('yyyy-MM-dd'))|$(($_.Properties | ForEach-Object { $_.Value }) -join ' ')\" }",
        )
    }) else {
        return vec![super::windows::illisible(CAT)];
    };
    vec![juger_effacements(
        &lire_effacements(&sortie),
        chrono::Local::now().date_naive(),
    )]
}

/// Lignes « EFF|date|détail » : le détail (compte qui a effacé, journal) vient de l'événement lui-même, lu prêt à
/// montrer.
#[cfg_attr(not(windows), allow(dead_code))]
fn lire_effacements(sortie: &str) -> Vec<(String, String)> {
    sortie
        .lines()
        .filter_map(|l| l.trim().strip_prefix("EFF|"))
        .filter_map(|l| l.split_once('|'))
        .map(|(d, x)| (crate::ui::affichable(d), crate::ui::affichable(x.trim())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les vraies fonctions de Windows (Wine ici, où wevtapi refuse : la VM dit le reste) : un seul constat, sans
    /// planter.
    #[cfg(windows)]
    #[test]
    fn effacements_lus_par_windows() {
        assert_eq!(journaux().len(), 1);
    }

    #[test]
    fn etat_des_journaux() {
        assert_eq!(juger_journald(false, false).probleme, Some(Niveau::Info));
        assert_eq!(juger_journald(true, false).probleme, Some(Niveau::Info));
        assert_eq!(juger_journald(true, true).probleme, None);
        let jour = chrono::NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        assert_eq!(juger_effacements(&[], jour).probleme, None);
        let recent = [("2026-10-10".to_string(), "alice System".to_string())];
        assert_eq!(juger_effacements(&recent, jour).probleme, Some(Niveau::Moyen));
        let ancien = [("2025-01-02".to_string(), "alice System".to_string())];
        assert_eq!(juger_effacements(&ancien, jour).probleme, Some(Niveau::Info));
        // Le détail de l'événement, piégé, arrive inoffensif dans le message.
        let lus = lire_effacements("EFF|2026-10-10|alice\x1b]52;c;eA==\x07\x1b[2K\r\u{202e} System\nautre ligne\n");
        assert_eq!(
            lus,
            [("2026-10-10".to_string(), "alice�]52;c;eA==��[2K�� System".to_string())]
        );
        assert!(!crate::ui::contient_un_piege(&juger_effacements(&lus, jour).message));
    }
}
