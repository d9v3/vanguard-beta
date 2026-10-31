//! Les bases GVDB (src/machine/linux/gvdb.rs) : celles de dconf, que le compte écrit lui-même et qu'un programme du
//! compte peut forger, lues pour les réglages de verrouillage et de confidentialité de GNOME. Tables qui se
//! chevauchent, parents en boucle, noms hors du fichier, valeurs GVariant imbriquées sans fin.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/machine/linux/gvdb.rs"]
mod gvdb;

/// Un fichier ne se lit qu'à partir de la signature « GVariant » et de la version 0 : le fuzzer n'a pas à les
/// deviner. Les octets reçus remplacent la suite de l'en-tête et les tables.
fn avec_entete(octets: &[u8]) -> Vec<u8> {
    let mut base = b"GVariant\0\0\0\0".to_vec();
    base.extend_from_slice(octets);
    base
}

fn parcourir(table: &gvdb::Table) {
    let Some(noms) = table.noms_des_valeurs() else { return };
    // Triés et sans doublon, comme gvdb_table_get_names.
    assert!(noms.windows(2).all(|p| p[0] < p[1]));
    for nom in noms.iter().take(64) {
        let _ = table.contient_valeur(nom);
        if let Some(v) = table.valeur(nom) {
            let _ = v.texte();
        }
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    for brut in [octets.to_vec(), avec_entete(octets)] {
        let Some(racine) = gvdb::Gvdb::depuis(brut).and_then(|b| b.racine()) else {
            continue;
        };
        parcourir(&racine);
        if let Ok(Some(verrous)) = racine.table(".locks") {
            parcourir(&verrous);
        }
    }
    // Un type GVariant jusqu'au premier octet nul, et une valeur de ce type dans la suite : décodée, elle a ce type.
    if let Some(fin) = octets.iter().position(|&c| c == 0)
        && let Some(genre) = gvdb::Genre::depuis(&octets[..fin])
        && let Some(v) = gvdb::decoder(&genre, &octets[fin + 1..])
    {
        assert_eq!(v.genre(), genre);
    }
});
