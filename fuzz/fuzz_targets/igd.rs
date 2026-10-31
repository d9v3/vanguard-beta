//! Le XML UPnP et SOAP de la box (ou d'un appareil qui se fait passer pour elle), et ses réponses SSDP.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[path = "../cale/reseau.rs"]
mod reseau;

#[path = "../cale/ui.rs"]
mod ui;

#[allow(dead_code)]
#[path = "../../src/audit/http_local.rs"]
mod http_local;

/// igd.rs lit `crate::audit::http_local` : le même module, à la place où il l'attend.
mod audit {
    pub(crate) use crate::http_local;
}

#[allow(dead_code)]
#[path = "../../src/audit/igd.rs"]
mod igd;

/// Longueur gardée d'un texte écrit par la box (igd::TEXTE_MAX).
const TEXTE_MAX: usize = 80;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(xml) = std::str::from_utf8(octets) else {
        return;
    };
    let base = http_local::Adresse::lire("http://10.0.0.1:5000/rootDesc.xml").unwrap();
    let (description, service) = igd::lire_description(xml, &base);
    for champ in [
        description.nom,
        description.fabricant,
        description.modele,
        description.version,
    ]
    .iter()
    .flatten()
    {
        assert!(champ.chars().count() <= TEXTE_MAX);
    }
    if let Some(s) = service {
        assert!(s.genre.chars().all(|c| c.is_ascii_alphanumeric() || ":-._".contains(c)));
    }
    if let Some(r) = igd::redirection(xml) {
        for champ in [&r.protocole, &r.appareil, &r.description, &r.hote_distant] {
            assert!(champ.chars().count() <= TEXTE_MAX);
        }
    }
    let _ = igd::erreur_soap(xml);
    let _ = igd::valeur(xml, "NewExternalIPAddress");
    if let Some(r) = igd::lire_reponse_ssdp(xml, std::net::Ipv4Addr::new(10, 0, 0, 1)) {
        // Jamais un autre appareil que celui qui a répondu.
        assert!(http_local::Adresse::lire(&r.emplacement).is_some_and(|a| a.ip == r.source));
    }
});
