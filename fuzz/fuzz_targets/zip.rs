//! Les archives zip téléchargées (tldr-pages), lues ou contrôlées entières : répertoire central qui ment sur les
//! tailles et les positions, noms démesurés, flux deflate abîmés, CRC faux, entrées en nombre.
#![no_main]

/// Les bornes du lecteur (`archives::Bornes`), à la place où il les attend.
#[derive(Clone, Copy)]
pub struct Bornes {
    pub entrees: usize,
    pub fichier: usize,
    pub total: usize,
}

#[path = "../../src/archives/crc32.rs"]
mod crc32;

#[allow(dead_code)]
#[path = "../../src/archives/deflate.rs"]
mod deflate;

#[allow(dead_code)]
#[path = "../../src/archives/zip.rs"]
mod zip;

const BORNES: Bornes = Bornes {
    entrees: 1000,
    fichier: 1 << 16,
    total: 1 << 18,
};

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    // Le parcours entrée par entrée de l'analyse des fichiers, puis chaque entrée extraite, bornée.
    let p = zip::parcourir(octets, BORNES.entrees);
    assert!(p.entrees.len() <= BORNES.entrees);
    for vue in &p.entrees {
        if let Ok(x) = zip::extraire_avant(octets, vue, BORNES.fichier, None) {
            assert!(x.contenu.len() <= BORNES.fichier);
        }
    }
    let lus = zip::lire(octets, &BORNES);
    assert!(lus.len() <= BORNES.entrees);
    assert!(lus.iter().map(|(_, c)| c.len()).sum::<usize>() <= BORNES.total);
    assert!(lus.iter().all(|(_, c)| c.len() <= BORNES.fichier));
    // Une échéance déjà passée : la première entrée seulement se lit, et l'archive est alors refusée entière s'il en
    // reste d'autres ; jamais une liste partielle prise pour l'archive.
    let presse = zip::lire_avant(octets, &BORNES, std::time::Instant::now());
    assert!(presse.is_empty() || presse == lus);
    let flux = deflate::inflater_avant(octets, BORNES.fichier, Some(std::time::Instant::now()));
    assert!(flux.contenu.len() <= BORNES.fichier && flux.lus <= octets.len());
    // Le contrôle entier (archives de tldr-pages de la clé) : une archive acceptée a des noms lisibles par `lire`
    // aussi, entrée pour entrée.
    if let Ok(noms) = zip::controler(octets, &BORNES) {
        assert!(noms.len() <= BORNES.entrees);
        assert_eq!(noms.len(), lus.len());
    }
});
