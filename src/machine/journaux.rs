//! Journaux du système : peut-on se fier à leur historique ? Sous Linux, le journal est-il scellé (Forward Secure
//! Sealing de journald : une entrée modifiée ou retirée se voit à la vérification) ; sous Windows, un journal
//! d'événements a-t-il été effacé récemment (Windows note lui-même chaque effacement, événement 104).
//! Aucun programme local ne peut empêcher l'administrateur d'agir : seule une copie hors de la machine le peut.

use super::{Constat, alerte, ok};
use chrono::{DateTime, Utc};

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

/// Un journal effacé, relevé par Windows (événement 104) : le jour (AAAA-MM-JJ, à l'heure de l'ordinateur), l'instant
/// exact (UTC, s'il est lisible) et le détail (compte qui a effacé, journal), prêts à montrer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
struct Effacement {
    jour: String,
    instant: Option<DateTime<Utc>>,
    detail: String,
}

/// Le genre de l'objet d'un effacement : sa clé porte son instant et son détail, propre à lui (une normale apprise sur
/// un effacement n'en tait pas un autre), et `ceder_au_bilan_des_journaux` y relit l'instant.
const GENRE: &str = "effacement";

/// Chaque effacement relevé (Windows en rend 5 au plus, les plus récents d'abord), un constat chacun : récent (moins
/// de 30 jours) ou non. Ceux que WIN-JRN-003 a lus aussi lui sont cédés au bilan (`ceder_au_bilan_des_journaux`).
#[cfg_attr(not(windows), allow(dead_code))]
fn juger_effacements(effacements: &[Effacement], aujourdhui: chrono::NaiveDate) -> Vec<Constat> {
    if effacements.is_empty() {
        return vec![ok(
            CAT,
            tr!("Aucun journal d'événements effacé.", "No event log cleared."),
        )];
    }
    effacements
        .iter()
        .map(|e| {
            let (date, detail) = (&e.jour, &e.detail);
            let recent = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
                .is_ok_and(|d| (aujourdhui - d).num_days() <= 30);
            let instant = e
                .instant
                .map_or_else(|| date.clone(), |i| i.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
            let detail_court: String = detail.chars().take(64).collect();
            alerte(
                CAT,
                if recent { Niveau::Moyen } else { Niveau::Info },
                trf!(
                    "Journal d'événements effacé le {date} ({detail}). Si ce n'est pas vous, quelqu'un a pu effacer ses traces.",
                    "Event log cleared on {date} ({detail}). If it was not you, someone may have erased their tracks."
                ),
            )
            .avec_objet(Objet::de(GENRE, &format!("{instant}|{detail_court}")))
        })
        .collect()
}

/// L'instant d'un effacement, relu dans l'objet de son constat ; rien pour un autre constat, ou un instant illisible.
fn instant_de(c: &Constat) -> Option<DateTime<Utc>> {
    let Objet::De(o) = &c.objet else {
        return None;
    };
    let (instant, _) = o.strip_prefix(GENRE)?.strip_prefix(':')?.split_once('|')?;
    DateTime::parse_from_rfc3339(instant).ok().map(|d| d.to_utc())
}

/// Ce que WIN-JRN-003 a lu du journal System, en entier, pendant un bilan : depuis quand, et l'instant où sa lecture
/// a commencé (un effacement écrit après, il a pu ne pas le voir).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SystemeLu {
    pub depuis: DateTime<Utc>,
    pub debut: DateTime<Utc>,
}

/// Sous Windows, WIN-JRN-003 dit déjà, par EVT-EFF-001, chaque journal effacé (104) qu'il a lu : quand il a lu le
/// journal System en entier pendant ce bilan (`lu`) et que ses constats sont là, chaque effacement de COM-JRN-001
/// qu'il a forcément vu (son instant exact entre le début de la période lue et le début de la lecture) lui est cédé,
/// pour qu'il ne soit dit qu'une fois. Les autres, et tous quand WIN-JRN-003 n'a pas pu lire (droits, délai, journal
/// coupé, règle en panne ou pas lancée), restent dits par COM-JRN-001 : deux fois plutôt que zéro.
pub(super) fn ceder_au_bilan_des_journaux(constats: &mut Vec<Constat>, lu: Option<SystemeLu>) {
    // Un constat vérifié de WIN-JRN-003 : une règle hors délai ne rend que son « non vérifié », et ses alertes,
    // rendues trop tard, sont perdues ; COM-JRN-001 garde alors les siens.
    let Some(lu) = lu else {
        return;
    };
    if !constats.iter().any(|c| c.regle == BILAN_DES_JOURNAUX && c.verifie) {
        return;
    }
    // Une seconde de marge au début : la requête arrondit l'instant du début de la période.
    let vu = |c: &Constat| {
        c.regle == REGLE
            && c.probleme.is_some()
            && instant_de(c).is_some_and(|t| t > lu.depuis + chrono::Duration::seconds(1) && t < lu.debut)
    };
    let Some(premier) = constats.iter().position(vu) else {
        return;
    };
    let mut cede = ok(
        CAT,
        trf!(
            "Journaux d'événements effacés pendant la période lue par {BILAN_DES_JOURNAUX} : dits par lui (EVT-EFF-001).",
            "Event logs cleared over the period read by {BILAN_DES_JOURNAUX}: reported by it (EVT-EFF-001)."
        ),
    );
    cede.regle = REGLE;
    let mut i = 0;
    constats.retain(|c| {
        let garde = i == premier || !vu(c);
        i += 1;
        garde
    });
    constats[premier] = cede;
}

/// Cette règle, et celle qui lit les journaux de Windows pour le bilan.
const REGLE: &str = "COM-JRN-001";
const BILAN_DES_JOURNAUX: &str = "WIN-JRN-003";

/// Ce que WIN-JRN-003 a lu du journal System, avec le numéro du bilan pendant lequel il l'a fait : celui que la
/// vérification de la règle a reçu en partant (`machine::bilan_du_fil`), pas le compteur relu.
static SYSTEME_LU: std::sync::Mutex<Option<(u64, SystemeLu)>> = std::sync::Mutex::new(None);

/// WIN-JRN-003 a lu le journal System en entier pendant le bilan `bilan`.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn noter_systeme_lu(bilan: u64, lu: SystemeLu) {
    *SYSTEME_LU.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some((bilan, lu));
}

/// Ce que WIN-JRN-003 a lu du journal System pendant le bilan `bilan`. Un autre bilan qui l'a noté depuis efface la
/// note de celui-ci : rien alors, et COM-JRN-001 garde ses constats (dits deux fois plutôt que perdus).
pub(super) fn systeme_lu(bilan: u64) -> Option<SystemeLu> {
    SYSTEME_LU
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .filter(|(n, _)| *n == bilan)
        .map(|(_, lu)| lu)
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
        Some(format!("EFF|{jour}|{}|{}", date.trim(), v.join(" ")))
    });
    let Some(sortie) = natif.map(|l| l.join("\n")).or_else(|| {
        super::windows::ps(
        "Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104 } -MaxEvents 5 -ErrorAction SilentlyContinue | \
         ForEach-Object { \"EFF|$($_.TimeCreated.ToString('yyyy-MM-dd'))|$($_.TimeCreated.ToUniversalTime().ToString('o'))|$(($_.Properties | ForEach-Object { $_.Value }) -join ' ')\" }",
        )
    }) else {
        return vec![super::windows::illisible(CAT)];
    };
    juger_effacements(&lire_effacements(&sortie), chrono::Local::now().date_naive())
}

/// Lignes « EFF|jour|instant|détail » : l'instant en UTC (RFC 3339 ; illisible, l'effacement n'est jamais cédé), le
/// détail (compte qui a effacé, journal) venu de l'événement lui-même, lu prêt à montrer.
#[cfg_attr(not(windows), allow(dead_code))]
fn lire_effacements(sortie: &str) -> Vec<Effacement> {
    sortie
        .lines()
        .filter_map(|l| l.trim().strip_prefix("EFF|"))
        .filter_map(|l| {
            let mut champs = l.splitn(3, '|');
            Some((champs.next()?, champs.next()?, champs.next()?))
        })
        .map(|(jour, instant, detail)| Effacement {
            jour: crate::ui::affichable(jour),
            instant: DateTime::parse_from_rfc3339(instant.trim()).ok().map(|d| d.to_utc()),
            detail: crate::ui::affichable(detail.trim()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les vraies fonctions de Windows (Wine ici, où wevtapi refuse : la VM dit le reste) : un constat par
    /// effacement relevé (5 au plus), ou un seul, sans planter.
    #[cfg(windows)]
    #[test]
    fn effacements_lus_par_windows() {
        assert!((1..=5).contains(&journaux().len()));
    }

    fn utc(t: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(t).unwrap().to_utc()
    }

    fn effacement(jour: &str, instant: Option<&str>, detail: &str) -> Effacement {
        Effacement {
            jour: jour.to_string(),
            instant: instant.map(utc),
            detail: detail.to_string(),
        }
    }

    #[test]
    fn etat_des_journaux() {
        assert_eq!(juger_journald(false, false).probleme, Some(Niveau::Info));
        assert_eq!(juger_journald(true, false).probleme, Some(Niveau::Info));
        assert_eq!(juger_journald(true, true).probleme, None);
        let jour = chrono::NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        let juger = |e: &[Effacement]| juger_effacements(e, jour);
        let niveaux = |c: &[Constat]| c.iter().map(|c| c.probleme).collect::<Vec<_>>();
        assert_eq!(niveaux(&juger(&[])), [None]);
        let recent = effacement("2026-10-10", None, "alice System");
        let ancien = effacement("2025-01-02", None, "alice System");
        assert_eq!(niveaux(&juger(std::slice::from_ref(&recent))), [Some(Niveau::Moyen)]);
        assert_eq!(niveaux(&juger(std::slice::from_ref(&ancien))), [Some(Niveau::Info)]);
        assert_eq!(
            niveaux(&juger(&[recent, ancien])),
            [Some(Niveau::Moyen), Some(Niveau::Info)]
        );
        // Le détail de l'événement, piégé, arrive inoffensif dans le message ; l'instant, en UTC.
        let lus = lire_effacements(
            "EFF|2026-10-10|2026-10-10T12:00:00.1234567Z|alice\x1b]52;c;eA==\x07\x1b[2K\r\u{202e} System|x\n\
             EFF|2026-10-09|illisible|bob\nautre ligne\n",
        );
        assert_eq!(
            lus,
            [
                Effacement {
                    jour: "2026-10-10".to_string(),
                    instant: Some(utc("2026-10-10T12:00:00.1234567Z")),
                    detail: "alice�]52;c;eA==��[2K�� System|x".to_string(),
                },
                effacement("2026-10-09", None, "bob"),
            ]
        );
        let c = juger(&lus);
        assert!(!crate::ui::contient_un_piege(&c[0].message));
        assert_eq!(instant_de(&c[0]), Some(utc("2026-10-10T12:00:00Z")));
        assert_eq!(instant_de(&c[1]), None);
    }

    /// Chaque effacement a sa clé : une normale apprise sur l'un (celui d'un désinstalleur) ne tait pas un autre,
    /// même jour, même compte, même journal (celui d'un intrus, une heure plus tard).
    #[test]
    fn chaque_effacement_a_sa_cle() {
        let jour = chrono::NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        let mut c = juger_effacements(
            &[
                effacement("2026-10-15", Some("2026-10-15T13:00:00Z"), "alice Application"),
                effacement("2026-10-15", Some("2026-10-15T12:00:00Z"), "alice Application"),
            ],
            jour,
        );
        for c in &mut c {
            c.regle = REGLE;
        }
        let (a, b) = (c[0].cle().unwrap(), c[1].cle().unwrap());
        assert_ne!(a, b);
        assert!(a.to_string().contains("2026-10-15T13:00:00Z"), "{a}");
        assert_eq!(c[0].message, c[1].message);
    }

    /// Le même 104 n'est dit qu'une fois au bilan : COM-JRN-001 cède à WIN-JRN-003 les effacements que celui-ci a
    /// forcément lus (entre le début de sa période et le début de sa lecture de System, à l'instant près), garde les
    /// autres, et dit tout quand WIN-JRN-003 n'a pas pu lire le journal System.
    #[test]
    fn effacement_dit_une_seule_fois() {
        let jour = chrono::NaiveDate::from_ymd_opt(2026, 11, 6).unwrap();
        // Québec : l'heure recule le 1er novembre 2026. Bilan le 6 novembre à 23 h 30 HNE (7 nov. 04 h 30 UTC) :
        // WIN-JRN-003 lit 7 × 24 h, depuis le 31 octobre 00 h 30 HAE.
        let lu = SystemeLu {
            depuis: utc("2026-10-31T04:30:00Z"),
            debut: utc("2026-11-07T04:30:05Z"),
        };
        let effacements = [
            // Écrit après le début de la lecture de System (course) : WIN-JRN-003 a pu ne pas le voir.
            effacement("2026-11-06", Some("2026-11-07T04:30:06Z"), "alice Application"),
            effacement("2026-11-06", Some("2026-11-06T20:00:00Z"), "alice System"),
            effacement("2026-11-01", Some("2026-11-01T12:00:00Z"), "alice Setup"),
            // 31 octobre 00 h 15 HAE : 6 jours du calendrier avant le 6, mais avant la période lue.
            effacement("2026-10-31", Some("2026-10-31T04:15:00Z"), "alice Setup"),
            effacement("2026-10-30", None, "alice Setup"),
        ];
        let win = |verifie: bool| {
            let mut c = if verifie {
                alerte(
                    "Journaux d'événements",
                    Niveau::Eleve,
                    "EVT-EFF-001 : un journal d'événements a été effacé".to_string(),
                )
            } else {
                super::super::impossible("Audit", "délai dépassé")
            };
            c.regle = BILAN_DES_JOURNAUX;
            c
        };
        let bilan = |lu: Option<SystemeLu>, win: Option<Constat>| {
            let mut constats: Vec<Constat> = juger_effacements(&effacements, jour)
                .into_iter()
                .map(|mut c| {
                    c.regle = REGLE;
                    c
                })
                .collect();
            constats.extend(win);
            ceder_au_bilan_des_journaux(&mut constats, lu);
            constats.into_iter().filter(|c| c.regle == REGLE).collect::<Vec<_>>()
        };
        let instants = |c: &[Constat]| c.iter().map(instant_de).collect::<Vec<_>>();
        // WIN-JRN-003 a lu System : les deux qu'il a forcément vus lui sont cédés, en une ligne saine à leur place.
        let cede = bilan(Some(lu), Some(win(true)));
        assert_eq!(cede.len(), 4);
        assert_eq!(cede[1].probleme, None);
        assert!(cede[1].message.contains("WIN-JRN-003"), "{}", cede[1].message);
        assert_eq!(
            instants(&cede),
            [
                Some(utc("2026-11-07T04:30:06Z")),
                None,
                Some(utc("2026-10-31T04:15:00Z")),
                None
            ]
        );
        assert_eq!(cede.iter().filter(|c| c.probleme.is_some()).count(), 3);
        // Pas lu, WIN-JRN-003 absent du bilan (règle pas lancée) ou seulement non vérifié (hors délai) : COM-JRN-001
        // dit chacun lui-même, et rien n'est dit cédé.
        for garde in [
            bilan(None, Some(win(true))),
            bilan(Some(lu), None),
            bilan(Some(lu), Some(win(false))),
        ] {
            assert_eq!(garde.len(), 5);
            assert!(garde.iter().all(|c| c.probleme.is_some()));
            assert!(!garde.iter().any(|c| c.message.contains("WIN-JRN-003")));
        }
        // La note d'un bilan ne sert qu'à lui : celle d'un autre bilan l'efface.
        noter_systeme_lu(1 << 60, lu);
        assert_eq!(systeme_lu(1 << 60), Some(lu));
        assert_eq!(systeme_lu((1 << 60) + 1), None);
        noter_systeme_lu((1 << 60) + 1, lu);
        assert_eq!(systeme_lu(1 << 60), None);
    }
}
