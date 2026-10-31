//! Les avis de sécurité de Mozilla, lus sans bibliothèque YAML (`.yml` depuis 2017, en-tête des `.md` avant) : lignes
//! démesurées, en-têtes non fermés, CVE tronquées, versions de toutes formes.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/protection/perimes/version.rs"]
mod version;

#[allow(dead_code)]
#[path = "../../src/protection/perimes/mozilla_avis.rs"]
mod mozilla_avis;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let mut index = mozilla_avis::Index::default();
    for nom in ["announce/2099/mfsa2099-01.yml", "announce/2015/mfsa2015-01.md"] {
        if let Some(avis) = mozilla_avis::avis(nom, octets) {
            index.ajouter(&avis);
        }
    }
    let Some(v) = version::Version::lire("128.3.0") else {
        return;
    };
    for cve in index.cves.keys().take(4) {
        for branche in [
            mozilla_avis::BrancheFx::Release,
            mozilla_avis::BrancheFx::Esr(128),
            mozilla_avis::BrancheFx::Inconnue,
        ] {
            let _ = mozilla_avis::juger(&index, cve, v, branche);
        }
    }
});
