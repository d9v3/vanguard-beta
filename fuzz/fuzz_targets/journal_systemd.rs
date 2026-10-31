//! Le lecteur du journal de systemd (src/machine/linux/journal_systemd.rs) : ses fichiers sont écrits par journald,
//! mais un journal rapporté d'une autre machine, ou un disque lu depuis la clé de secours, peut avoir été forgé.
//! En-têtes qui mentent, objets qui se chevauchent, chaînes de hachage et tableaux d'entrées en boucle, champs
//! compressés (zstd, LZ4) abîmés.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/machine/linux/zstd.rs"]
mod zstd;

#[allow(dead_code)]
#[path = "../../src/machine/linux/journal_systemd.rs"]
mod journal_systemd;

use std::path::PathBuf;

/// Le lecteur lit un fichier (par positions, sans tout charger) : les octets y sont écrits à chaque essai, et effacés
/// après, pour que le fuzzer arrêté ne laisse rien dans le dossier temporaire (un plantage l'y laisse : c'est l'essai).
fn fichier() -> &'static PathBuf {
    static F: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    F.get_or_init(|| std::env::temp_dir().join(format!("vanguard-fuzz-journal-{}.journal", std::process::id())))
}

const CHAMPS: &[&str] = &["MESSAGE", "_COMM", "PRIORITY", "SYSLOG_IDENTIFIER", "_PID"];

fn lire(octets: &[u8]) {
    let f = fichier();
    std::fs::write(f, octets).unwrap();
    let requete = journal_systemd::Requete {
        un_de: &["PRIORITY=3", "_COMM=sshd"],
        depuis: None,
        demarrage: None,
        champs: CHAMPS,
    };
    let entrees = journal_systemd::chercher(std::slice::from_ref(f), &requete);
    let _ = std::fs::remove_file(f);
    let Some(entrees) = entrees else { return };
    // De la plus ancienne à la plus récente, et seulement les champs demandés.
    assert!(entrees.windows(2).all(|p| p[0].quand <= p[1].quand));
    for e in &entrees {
        assert!(e.champs.iter().all(|(n, _)| CHAMPS.contains(&n.as_str())));
        let _ = journal_systemd::ligne_courte(e);
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    lire(octets);
    // Derrière la signature « LPKSHHRH » : le fuzzer n'a pas à la deviner.
    let mut journal = b"LPKSHHRH".to_vec();
    journal.extend_from_slice(octets);
    lire(&journal);
});
