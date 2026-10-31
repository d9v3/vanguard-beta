//! La liste d'indicateurs d'Échap (ioc.yaml, téléchargée depuis GitHub) : le sous-ensemble YAML lu sans
//! bibliothèque (src/protection/espions/echap.rs), puis les serveurs, adresses et sites qui en sont tirés. Retraits
//! qui changent, guillemets non fermés, clés sans valeur, blocs « | », lignes et entrées en nombre.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[path = "../cale/langue.rs"]
mod langue;
#[path = "../cale/protection.rs"]
mod protection;
#[path = "../cale/http.rs"]
mod http;
#[path = "../cale/parametres.rs"]
mod parametres;
#[path = "../cale/reseau.rs"]
mod reseau;
#[path = "../cale/socle.rs"]
mod socle;
#[path = "../cale/ui.rs"]
mod ui;

#[allow(dead_code)]
#[path = "../../src/protection/espions/echap.rs"]
mod echap;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(texte) = std::str::from_utf8(octets) else {
        return;
    };
    let Some(lecture) = echap::lire_yaml(texte) else {
        return;
    };
    // Jamais plus d'entrées que de lignes qui commencent une entrée.
    assert!(lecture.entrees.len() <= texte.split('\n').count());
    if let Some(ind) = echap::indicateurs_de(&lecture.entrees) {
        // Aucune adresse de la maison n'est tirée de la liste : un appareil local ne doit jamais passer pour un
        // serveur d'espionnage.
        for locale in ["192.168.1.1", "10.0.0.1", "127.0.0.1", "100.64.0.1", "fe80::1", "::ffff:192.168.1.1"] {
            let ip: std::net::IpAddr = locale.parse().unwrap();
            assert!(!protection::sortantes::sur_internet(ip) && ind.ip(ip).is_none(), "{locale}");
        }
    }
});
