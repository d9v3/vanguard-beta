//! Le lecteur SQLite fait maison (src/sqlite.rs) : les bases des navigateurs (Login Data, logins.json à côté) et la
//! base des autorisations de macOS (TCC.db) viennent d'un ordinateur peut-être infecté. Pages qui renvoient à
//! elles-mêmes, débordements sans fin, arbres trop profonds, cellules partagées, schémas qui mentent.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/sqlite.rs"]
mod sqlite;

/// Une base ne se lit qu'à partir de l'en-tête « SQLite format 3 » et d'une taille de page : le fuzzer n'a pas à les
/// deviner. Les octets reçus remplacent la suite de l'en-tête et les pages.
fn avec_entete(octets: &[u8]) -> Vec<u8> {
    let mut base = b"SQLite format 3\0".to_vec();
    base.extend_from_slice(&512u16.to_be_bytes());
    base.extend_from_slice(octets);
    base
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    for base in [octets.to_vec(), avec_entete(octets)] {
        let _ = sqlite::compter_lignes(&base, "logins");
        let _ = sqlite::compteur(&base);
        if let Some(lignes) =
            sqlite::lignes(&base, "access", &["service", "client", "client_type", "auth_value", "allowed"])
        {
            // Chaque ligne a autant de valeurs que de colonnes demandées : jamais une de plus, jamais décalée.
            assert!(lignes.iter().all(|l| l.len() == 5));
        }
    }
});
