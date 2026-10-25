//! Le veilleur anti-rançongiciel : une écoute en direct des dossiers personnels et des fichiers-pièges, un score à
//! règles par groupe de processus sur une fenêtre de 10 secondes, et une réponse graduée. Il complète les
//! fichiers-pièges (vérifiés une fois par heure) par une alerte en quelques secondes, et, avec la protection active
//! et un cas quasi certain, un gel puis un arrêt du rançongiciel, preuve relevée avant.
//!
//! Palier 1 : sans root, sans administrateur, sans nouvelle crate. « Quoi » (les changements de fichiers) par la
//! crate `notify` déjà présente (inotify sous Linux, ReadDirectoryChangesW sous Windows) ; « qui » par les compteurs
//! d'écriture des processus (`/proc/<pid>/io` et fd sous Linux, GetProcessIoCounters sous Windows), relevés seulement au
//! début d'une rafale. fanotify (root), Aya (eBPF) et ETW (Windows) sont des paliers suivants, qui attendent un
//! service privilégié et la signature du code.
//!
//! Limite connue du palier 1 : inotify ne signale une écriture qu'au dossier du chemin employé ; une réécriture par un
//! lien physique placé hors des dossiers surveillés ne produit aucun événement (fanotify, palier suivant, la verrait).
//! Les pièges, vérifiés chaque heure, restent le filet.
//!
//! Toutes les décisions sont des fonctions pures (score, contenu, noms, copies, attribution), testées sous Linux et
//! sous Wine ; seules la lecture des flux du noyau, l'échantillonnage borné et la réponse touchent au système, sous
//! les garde-fous du blocage.

pub(crate) mod attribution;
pub(crate) mod contenu;
pub(crate) mod copies;
pub(crate) mod fenetre;
pub(crate) mod noms;
pub(crate) mod score;

#[cfg(target_os = "linux")]
pub(crate) mod reponse;
#[cfg(target_os = "linux")]
pub(crate) mod veille;

use crate::sceau;

/// Le fichier des réglages du veilleur anti-rançongiciel, scellé : des dossiers surveillés en plus et des exclusions
/// écrits hors de Vanguard ne changent rien (sens sûr).
pub(crate) const REGLAGES: &str = "rancongiciel-reglages.json";

/// Les réglages de la personne : dossiers surveillés en plus des dossiers personnels standards, et exclusions
/// ajoutées à celles d'office. Scellés (`sceau`), comme normales.rs.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(crate) struct Reglages {
    /// Dossiers surveillés en plus (chemins absolus).
    pub dossiers_en_plus: Vec<String>,
    /// Dossiers (ou motifs) à ne jamais surveiller, en plus des exclusions d'office. Pas encore appliqué (aucune
    /// commande ne l'écrit) : gardé pour que les fichiers déjà écrits restent lisibles.
    pub exclusions: Vec<String>,
}

impl Reglages {
    /// Les réglages scellés ; les défauts (rien en plus, rien d'exclu) si le fichier est absent, illisible ou falsifié
    /// (« non vérifié = dit » : un réglage falsifié n'ouvre pas de dossier en silence).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn charger() -> Reglages {
        // Acceptés tels quels après des sceaux refaits, pas plus crus que changés (`sceau::juge`).
        sceau::juge(REGLAGES)
            .cru()
            .and_then(|o| serde_json::from_slice(&o).ok())
            .unwrap_or_default()
    }
}
