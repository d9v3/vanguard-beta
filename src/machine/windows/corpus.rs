//! Les cas du corpus de détection propres à Windows (`modele::corpus`) : ils tournent sous Wine dans verifier.sh,
//! les données fabriquées données aux fonctions de jugement, sans rien lire du registre.

use crate::machine::Constat;
use crate::modele::corpus::{Entree, Juge};

pub(crate) const CAS: &[(&str, Juge)] = &[
    ("WIN-ANV-002", exclusions),
    ("WIN-PRS-001", super::persistance::corpus),
    ("WIN-PRS-002", super::portes::corpus_ifeo),
    ("WIN-PRS-003", super::portes::corpus_remplaces),
    ("WIN-PRS-004", super::portes::corpus_winlogon),
    ("WIN-PRS-005", super::portes::corpus_appinit),
    ("WIN-PRS-006", super::portes::corpus_wmi),
    ("WIN-PRS-007", super::ancrages::corpus_lsa),
    ("WIN-PRS-008", super::ancrages::corpus_appcert),
    ("WIN-PRS-009", super::ancrages::corpus_moniteurs),
    ("WIN-PRS-010", super::ancrages::corpus_fournisseurs),
    ("WIN-PRS-011", super::ancrages::corpus_winsock),
    ("WIN-PRS-012", super::pilotes::corpus),
    ("WIN-SRV-001", services),
];

/// WIN-ANV-002 : `chemin|…`, `processus|…`, `extension|…`, les exclusions de Defender.
fn exclusions(e: &Entree) -> Vec<Constat> {
    let liste = |genre: &str| -> Vec<String> { e.de(genre).iter().map(|c| c[0].to_string()).collect() };
    super::exclusions::juger(&liste("chemin"), &liste("processus"), &liste("extension"))
        .into_iter()
        .collect()
}

/// WIN-SRV-001 : la sortie de la lecture des services telle quelle (lignes SVC|…, puis SVC_FIN).
fn services(e: &Entree) -> Vec<Constat> {
    super::services::juger(&e.texte).into_iter().collect()
}
