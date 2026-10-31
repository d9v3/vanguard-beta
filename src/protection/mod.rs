//! Les outils du groupe « Antivirus et protection » du menu : antivirus, YARA, fichiers-pièges, bac à sable, intégrité
//! des fichiers critiques, mots de passe fuités, connexions sortantes, logiciels de prise de contrôle à distance (faux
//! technicien), logiciels espions (`espions`), logiciels pas à jour sous Windows et macOS (`perimes`), liens, courriels
//! suspects et fichiers téléchargés, caméra et micro, bilan de confidentialité (`acces`), blocage des menaces, d'un
//! clic ou tout seul pour le certain (`blocage`), l'interrupteur de la protection en temps réel (`temps_reel`) ; et,
//! sous Linux et macOS, la protection de la clé USB (`cle`).

pub(crate) mod abuse_ch;
pub mod acces;
pub mod antivirus;
pub mod blocage;
pub mod camera;
#[cfg(unix)]
pub mod cle;
pub mod cles_connues;
pub mod conteneurs;
pub mod courriel_suspect;
pub mod distance;
pub(crate) mod empreintes;
pub mod environnement;
pub mod espions;
pub mod fuites;
pub mod integrite;
pub mod isoler;
pub mod kev;
pub mod lien;
pub mod manifeste;
pub mod memoire;
pub(crate) mod memoire_dns;
pub(crate) mod moteur_yara;
pub(crate) mod motifs;
pub(crate) mod normales;
// Hors de Miri : YARA-X, son oracle, n'y compile pas (Cargo.toml). `cfg(test)` reste à part : clippy ne reconnaît
// un module d'essais (règles allégées de clippy.toml) qu'à cette forme exacte.
#[cfg(test)]
#[cfg(not(miri))]
mod oracle_yara;
pub(crate) mod outil;
pub mod perimes;
pub mod pieges;
pub(crate) mod preuve;
pub mod quarantaine;
pub(crate) mod regles_yara;
pub mod secrets_git;
pub mod sites_bloques;
pub mod sortantes;
pub(crate) mod sources;
pub mod telechargement;
pub(crate) mod temps_reel;
pub mod yara;
// Palier 1 Linux (inotify, /proc) ; le veilleur anti-rançongiciel Windows (ReadDirectoryChangesW, Toolhelp32) viendra
// après une mesure en VM (voir conception-rancongiciel.md).
#[cfg(target_os = "linux")]
pub(crate) mod rancongiciel;
