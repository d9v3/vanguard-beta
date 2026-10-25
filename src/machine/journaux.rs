//! Journaux du système : peut-on se fier à leur historique ? Sous Linux, le journal est-il scellé (Forward Secure
//! Sealing de journald : une entrée modifiée ou retirée se voit à la vérification) ; sous Windows, un journal
//! d'événements a-t-il été effacé récemment (Windows note lui-même chaque effacement, événement 104).
//! Aucun programme local ne peut empêcher l'administrateur d'agir : seule une copie hors de la machine le peut.

use super::{Constat, alerte, ok};
use crate::modele::Objet;
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

/// Un effacement dit : récent (moins de 30 jours) ou non.
#[cfg_attr(not(windows), allow(dead_code))]
fn effacement_dit(date: &str, detail: &str, aujourdhui: chrono::NaiveDate) -> Constat {
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

/// L'objet du constat de l'effacement le plus récent des `jours` derniers jours : ceux que WIN-JRN-003 lit aussi.
const DANS_LA_PERIODE: &str = "dans-la-periode";

/// Effacements de journaux relevés par Windows : (date AAAA-MM-JJ, détail), les plus récents d'abord. Le plus récent
/// des `jours` derniers jours (ceux que WIN-JRN-003 lit aussi, par EVT-EFF-001) a son constat à lui, que
/// `ceder_au_bilan_des_journaux` remplace si WIN-JRN-003 a lu le journal System en entier : l'événement n'est dit
/// qu'une fois. Le plus récent d'avant, que WIN-JRN-003 ne lit pas, garde le sien. Une date illisible compte comme
/// d'avant : elle reste dite ici.
#[cfg_attr(not(windows), allow(dead_code))]
fn juger_effacements(effacements: &[(String, String)], aujourdhui: chrono::NaiveDate, jours: u32) -> Vec<Constat> {
    if effacements.is_empty() {
        return vec![ok(
            CAT,
            tr!("Aucun journal d'événements effacé.", "No event log cleared."),
        )];
    }
    // Le jour d'il y a `jours` - 1 jours, minuit compris, est toujours dans les `jours` × 24 h que lit WIN-JRN-003.
    let dans_la_periode = |date: &str| {
        chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
            .is_ok_and(|d| d <= aujourdhui && (aujourdhui - d).num_days() < i64::from(jours))
    };
    let mut constats = Vec::new();
    if let Some((date, detail)) = effacements.iter().find(|(d, _)| dans_la_periode(d)) {
        constats.push(effacement_dit(date, detail, aujourdhui).avec_objet(Objet::de("effacement", DANS_LA_PERIODE)));
    }
    if let Some((date, detail)) = effacements.iter().find(|(d, _)| !dans_la_periode(d)) {
        constats.push(effacement_dit(date, detail, aujourdhui));
    }
    constats
}

/// Sous Windows, WIN-JRN-003 dit déjà, par EVT-EFF-001, chaque journal effacé (104) qu'il a lu : quand il a lu le
/// journal System en entier pendant ce bilan (`systeme_lu`, et ses constats sont là), le constat de COM-JRN-001 sur
/// la même période lui cède la place, pour que l'événement ne soit dit qu'une fois. S'il n'a pas pu le lire (droits,
/// délai, journal coupé, règle en panne ou pas lancée), COM-JRN-001 le dit, comme avant.
pub(super) fn ceder_au_bilan_des_journaux(constats: &mut [Constat], systeme_lu: bool, jours: u32) {
    // Un constat vérifié de WIN-JRN-003 : une règle hors délai ne rend que son « non vérifié », et ses alertes,
    // rendues trop tard, sont perdues ; COM-JRN-001 garde alors le sien.
    if !systeme_lu || !constats.iter().any(|c| c.regle == BILAN_DES_JOURNAUX && c.verifie) {
        return;
    }
    let periode = Objet::de("effacement", DANS_LA_PERIODE);
    for c in constats.iter_mut().filter(|c| c.regle == REGLE && c.objet == periode) {
        let mut cede = ok(
            CAT,
            trf!(
                "Journaux d'événements effacés ces {jours} derniers jours : dits par {BILAN_DES_JOURNAUX} (EVT-EFF-001).",
                "Event logs cleared over the last {jours} days: reported by {BILAN_DES_JOURNAUX} (EVT-EFF-001)."
            ),
        )
        .avec_objet(periode.clone());
        cede.regle = REGLE;
        *c = cede;
    }
}

/// Cette règle, et celle qui lit les journaux de Windows pour le bilan.
const REGLE: &str = "COM-JRN-001";
const BILAN_DES_JOURNAUX: &str = "WIN-JRN-003";

/// Le numéro du bilan pendant lequel WIN-JRN-003 a lu le journal System en entier (`u64::MAX` : aucun).
static SYSTEME_LU: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

/// WIN-JRN-003 a lu le journal System en entier pendant le bilan `bilan`.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn noter_systeme_lu(bilan: u64) {
    SYSTEME_LU.store(bilan, std::sync::atomic::Ordering::Relaxed);
}

/// WIN-JRN-003 a-t-il lu le journal System en entier pendant le bilan `bilan` ? Un bilan lancé pendant celui-ci
/// change le numéro : la réponse est alors non, et COM-JRN-001 garde son constat (dit deux fois plutôt que perdu).
pub(super) fn systeme_lu(bilan: u64) -> bool {
    SYSTEME_LU.load(std::sync::atomic::Ordering::Relaxed) == bilan
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
    juger_effacements(
        &lire_effacements(&sortie),
        chrono::Local::now().date_naive(),
        super::windows::evenements::JOURS,
    )
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
        assert!((1..=2).contains(&journaux().len()));
    }

    #[test]
    fn etat_des_journaux() {
        assert_eq!(juger_journald(false, false).probleme, Some(Niveau::Info));
        assert_eq!(juger_journald(true, false).probleme, Some(Niveau::Info));
        assert_eq!(juger_journald(true, true).probleme, None);
        let jour = chrono::NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        let juger = |e: &[(String, String)]| juger_effacements(e, jour, 7);
        let niveaux = |c: &[Constat]| c.iter().map(|c| c.probleme).collect::<Vec<_>>();
        assert_eq!(niveaux(&juger(&[])), [None]);
        let recent = [("2026-10-10".to_string(), "alice System".to_string())];
        assert_eq!(niveaux(&juger(&recent)), [Some(Niveau::Moyen)]);
        let ancien = [("2025-01-02".to_string(), "alice System".to_string())];
        assert_eq!(niveaux(&juger(&ancien)), [Some(Niveau::Info)]);
        // Le détail de l'événement, piégé, arrive inoffensif dans le message.
        let lus = lire_effacements("EFF|2026-10-10|alice\x1b]52;c;eA==\x07\x1b[2K\r\u{202e} System\nautre ligne\n");
        assert_eq!(
            lus,
            [("2026-10-10".to_string(), "alice�]52;c;eA==��[2K�� System".to_string())]
        );
        assert!(!crate::ui::contient_un_piege(&juger(&lus)[0].message));
    }

    /// Le même 104 n'est dit qu'une fois au bilan : COM-JRN-001 cède à WIN-JRN-003 l'effacement de la période que
    /// celui-ci a lue, garde celui d'avant, et dit tout quand WIN-JRN-003 n'a pas pu lire le journal System.
    #[test]
    fn effacement_dit_une_seule_fois() {
        let jour = chrono::NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        let effacements = [
            ("2026-10-15".to_string(), "alice Application".to_string()),
            ("2026-10-12".to_string(), "alice System".to_string()),
            ("2026-09-30".to_string(), "alice Setup".to_string()),
            ("date illisible".to_string(), "alice Setup".to_string()),
        ];
        let bilan = |systeme_lu: bool, avec_win: bool| {
            let mut constats: Vec<Constat> = juger_effacements(&effacements, jour, 7)
                .into_iter()
                .map(|mut c| {
                    c.regle = REGLE;
                    c
                })
                .collect();
            if avec_win {
                let mut c = alerte(
                    "Journaux d'événements",
                    Niveau::Eleve,
                    "EVT-EFF-001 : un journal d'événements a été effacé".to_string(),
                );
                c.regle = BILAN_DES_JOURNAUX;
                constats.push(c);
            }
            ceder_au_bilan_des_journaux(&mut constats, systeme_lu, 7);
            constats
                .into_iter()
                .filter(|c| c.regle == REGLE)
                .map(|c| (c.probleme, c.message))
                .collect::<Vec<_>>()
        };
        let bilan_hors_delai = || {
            let mut constats = juger_effacements(&effacements, jour, 7);
            for c in &mut constats {
                c.regle = REGLE;
            }
            let mut c = super::super::impossible("Audit", "délai dépassé");
            c.regle = BILAN_DES_JOURNAUX;
            constats.push(c);
            ceder_au_bilan_des_journaux(&mut constats, true, 7);
            constats
                .into_iter()
                .filter(|c| c.regle == REGLE)
                .map(|c| (c.probleme, c.message))
                .collect::<Vec<_>>()
        };
        // WIN-JRN-003 a lu System : le 15 n'est dit que par lui ; le 30 septembre, hors de sa période, reste ici.
        let cede = bilan(true, true);
        assert_eq!(cede.len(), 2, "{cede:?}");
        assert_eq!(cede[0].0, None);
        assert!(cede[0].1.contains("WIN-JRN-003"), "{}", cede[0].1);
        assert!(
            !cede
                .iter()
                .any(|(_, m)| m.contains("2026-10-15") || m.contains("2026-10-12"))
        );
        assert_eq!(cede[1].0, Some(Niveau::Moyen));
        assert!(cede[1].1.contains("2026-09-30"), "{}", cede[1].1);
        // Pas lu, WIN-JRN-003 absent du bilan (règle pas lancée) ou seulement non vérifié (hors délai) : COM-JRN-001
        // dit le plus récent lui-même.
        for garde in [bilan(false, true), bilan(true, false), bilan_hors_delai()] {
            assert_eq!(garde[0].0, Some(Niveau::Moyen));
            assert!(garde[0].1.contains("2026-10-15"), "{}", garde[0].1);
            assert!(garde[1].1.contains("2026-09-30"), "{}", garde[1].1);
        }
        // Le bord de la période : il y a 6 jours en est, il y a 7 non (WIN-JRN-003 lit 7 × 24 h depuis maintenant).
        let bord = |d: &str| {
            juger_effacements(&[(d.to_string(), "alice".to_string())], jour, 7)[0].objet
                == Objet::de("effacement", DANS_LA_PERIODE)
        };
        assert!(bord("2026-10-11") && bord("2026-10-17"));
        assert!(!bord("2026-10-10") && !bord("2026-10-18"));
        // Le numéro du bilan pendant lequel System a été lu : un autre bilan ne s'en sert pas.
        noter_systeme_lu(1 << 60);
        assert!(systeme_lu(1 << 60) && !systeme_lu((1 << 60) + 1));
    }
}
