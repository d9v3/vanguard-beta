//! Les logiciels de surveillance d'un ordinateur, écrits pour Vanguard : ceux vendus pour épier quelqu'un, et ceux,
//! légaux, du contrôle parental ou de la surveillance des employés, qu'un proche peut détourner. Chaque motif est le
//! nom réel d'un programme, d'un dossier ou d'un service du logiciel, confirmé par la source citée à sa ligne (page de
//! l'éditeur, ou d'une autorité : Échap, Microsoft, Trend Micro, F-Secure) ; un logiciel sans source n'est pas écrit
//! (Actual Keylogger, SpyAgent, Wolfeye, Bark et Hubstaff, le 23 oct. 2026). « bark » seul serait un mot courant.
//!
//! Un motif se reconnaît au début d'un mot (`distance::contient_mot`) : « refog » dans « Refog Personal Monitor », pas
//! dans « prefogged ». Les logiciels de prise de contrôle à distance restent à « Mon ordinateur est-il contrôlé ? »
//! (`distance.rs`) : aucun motif commun.

/// Pourquoi ce logiciel surveille.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Genre {
    /// Vendu pour épier quelqu'un à son insu (frappes, écran, messages).
    Espion,
    /// Contrôle parental : normal sur l'ordinateur d'un enfant, s'il a été installé exprès.
    Parental,
    /// Surveillance des employés : normale sur un ordinateur de travail.
    Employeur,
}

pub(crate) struct Surveillance {
    pub nom: &'static str,
    /// En minuscules.
    motifs: &'static [&'static str],
    pub genre: Genre,
}

#[rustfmt::skip] // une ligne par logiciel, sa source en commentaire au-dessus
const SURVEILLANCE: &[Surveillance] = &[
    // Échap, ioc.yaml, entrée « FlexiSpy » (https://github.com/AssoEchap/stalkerware-indicators).
    Surveillance { nom: "FlexiSPY", motifs: &["flexispy"], genre: Genre::Espion },
    // Trend Micro, PUA.Win32.Spyrix.GA ; Échap, alias « Spyrix » de l'entrée « EvaSpy ».
    Surveillance { nom: "Spyrix", motifs: &["spyrix"], genre: Genre::Espion },
    // Échap, alias « Refog » de l'entrée « Hoverwatch ».
    Surveillance { nom: "Refog", motifs: &["refog"], genre: Genre::Espion },
    // Échap, alias « KidLogger » de l'entrée « KidsShield » ; SecureMac, définition « KidLogger ».
    Surveillance { nom: "KidLogger", motifs: &["kidlogger"], genre: Genre::Espion },
    // Échap, entrée « Hoverwatch ».
    Surveillance { nom: "Hoverwatch", motifs: &["hoverwatch"], genre: Genre::Espion },
    // Échap, entrée « pcTattletale ».
    Surveillance { nom: "pcTattletale", motifs: &["pctattletale"], genre: Genre::Espion },
    // Échap, entrée « SentryPC ».
    Surveillance { nom: "SentryPC", motifs: &["sentrypc"], genre: Genre::Espion },
    // Échap, entrée « WebWatcher ».
    Surveillance { nom: "WebWatcher", motifs: &["webwatcher"], genre: Genre::Espion },
    // Échap, entrée « RealtimeSpy ».
    Surveillance { nom: "Realtime-Spy", motifs: &["realtime-spy", "realtimespy"], genre: Genre::Espion },
    // Échap, entrée « iKeyMonitor ».
    Surveillance { nom: "iKeyMonitor", motifs: &["ikeymonitor"], genre: Genre::Espion },
    // Microsoft, MonitoringTool:Win32/Ardamax (dossier « Ardamax Keylogger » sous Program Files).
    Surveillance { nom: "Ardamax Keylogger", motifs: &["ardamax"], genre: Genre::Espion },
    // Microsoft, MonitoringTool:Win32/RevealerKeylogger : %ProgramFiles%\rvlkl\rvlkl.exe, %ProgramFiles%\RKFree\rkfree.exe.
    Surveillance { nom: "Revealer Keylogger", motifs: &["revealer keylogger", "rvlkl", "rkfree"], genre: Genre::Espion },
    // F-Secure, « EliteKeylogger » ; Malwarebytes, PUP.Elite Keylogger.
    Surveillance { nom: "Elite Keylogger", motifs: &["elite keylogger", "elitekeylogger"], genre: Genre::Espion },
    // https://github.com/kernc/logkeys : « a GNU/Linux keylogger », programme logkeys.
    Surveillance { nom: "logkeys", motifs: &["logkeys"], genre: Genre::Espion },
    // Qustodio, « How to uninstall Qustodio for Windows » (help.qustodio.com/hc/articles/360005221838).
    Surveillance { nom: "Qustodio", motifs: &["qustodio"], genre: Genre::Parental },
    // Net Nanny, « How do I uninstall Net Nanny » (netnanny.com/kb/38) : « Net Nanny » dans les programmes.
    Surveillance { nom: "Net Nanny", motifs: &["net nanny", "netnanny"], genre: Genre::Parental },
    // Norton, « Uninstall Norton Family from your device » (support.norton.com, v40472774).
    Surveillance { nom: "Norton Family", motifs: &["norton family"], genre: Genre::Parental },
    // Kaspersky, « Kaspersky Safe Kids for Windows » (support.kaspersky.com/safe-kids-for-windows/94504).
    Surveillance { nom: "Kaspersky Safe Kids", motifs: &["kaspersky safe kids"], genre: Genre::Parental },
    // Teramind, « Antivirus & EDR Configuration Guide » (kb.teramind.co/en/articles/8791033) : service tsvchst,
    // pilote tmfsdrv2, « Teramind Agent », com.teramind.* ; pas dwm.exe ni svc.exe, noms de Windows ou trop communs.
    Surveillance { nom: "Teramind", motifs: &["teramind", "tsvchst", "tmfsdrv2"], genre: Genre::Employeur },
    // ActivTrak, support.activtrak.com/hc/en-us/articles/360034165131 : svctcom, scthost, com.bgrove.activtrak.
    Surveillance { nom: "ActivTrak", motifs: &["activtrak", "svctcom", "scthost"], genre: Genre::Employeur },
    // Veriato, « Windows Agent Exclusions » (techsupport.veriato.com/hc/en-us/articles/25483058189335).
    Surveillance { nom: "Veriato", motifs: &["veriato"], genre: Genre::Employeur },
    // Échap, alias « Interguard » de l'entrée « WebWatcher ».
    Surveillance { nom: "InterGuard", motifs: &["interguard"], genre: Genre::Employeur },
];

/// Le logiciel de surveillance dont un motif est reconnu au début d'un mot de `texte` (nom de programme installé, de
/// processus, de service, de clé Run, d'application, d'identifiant de paquet).
pub(crate) fn reconnu(texte: &str) -> Option<&'static Surveillance> {
    let bas = texte.to_lowercase();
    SURVEILLANCE.iter().find(|s| {
        s.motifs
            .iter()
            .any(|m| crate::protection::distance::contient_mot(&bas, m))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnus_au_debut_d_un_mot() {
        assert_eq!(reconnu("Refog Personal Monitor").map(|s| s.nom), Some("Refog"));
        assert!(reconnu("prefogged").is_none());
        assert_eq!(
            reconnu("C:\\Program Files\\rvlkl\\rvlkl.exe").map(|s| s.nom),
            Some("Revealer Keylogger")
        );
        assert_eq!(reconnu("com.bgrove.activtrak.agent").map(|s| s.nom), Some("ActivTrak"));
        assert_eq!(reconnu("Spyrix Free Keylogger").map(|s| s.genre), Some(Genre::Espion));
        assert_eq!(reconnu("Qustodio").map(|s| s.genre), Some(Genre::Parental));
        assert_eq!(reconnu("Teramind Agent").map(|s| s.genre), Some(Genre::Employeur));
        for ordinaire in [
            "dwm",
            "svc",
            "bark",
            "Steam",
            "OBS Studio",
            "Code",
            "KeePassXC",
            "Bitwarden",
            "Hyprland",
        ] {
            assert!(reconnu(ordinaire).is_none(), "{ordinaire}");
        }
    }

    #[test]
    fn aucun_motif_commun_avec_la_prise_de_controle() {
        for s in SURVEILLANCE {
            assert!(
                !s.motifs.is_empty() && s.motifs.iter().all(|m| *m == m.to_lowercase()),
                "{}",
                s.nom
            );
            for m in s.motifs {
                assert!(!crate::protection::distance::controle_a_distance(m), "{m}");
                assert!(m.len() >= 5, "motif trop court : {m}");
            }
        }
    }
}
