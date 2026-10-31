//! Les journaux .evtx (src/journaux_windows/evtx/) : un fichier rapporté d'un Windows piraté, ou lu sur son disque
//! depuis la clé de secours. En-têtes qui mentent, morceaux abîmés, enregistrements qui se chevauchent, gabarits
//! désignés n'importe où, valeurs BinXml imbriquées, substitutions démultipliées.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/journaux_windows/evtx/mod.rs"]
mod evtx;

/// Plus petites que celles du programme : chaque exécution reste brève, et un dépassement se voit aussi vite.
fn bornes() -> evtx::Bornes {
    evtx::Bornes {
        enregistrements: 2000,
        noeuds: 512,
        travail: 20_000,
        texte: 4096,
        texte_enregistrement: 1 << 16,
        ..evtx::Bornes::default()
    }
}

fn verifier(octets: &[u8], bornes: &evtx::Bornes) {
    let Ok(lu) = evtx::lire_octets(octets, bornes) else { return };
    assert!(lu.enregistrements.len() <= bornes.enregistrements);
    assert_eq!(lu.bilan.enregistrements_lus, lu.enregistrements.len() as u64);
    // Un récapitulatif par morceau, dans l'ordre du fichier, borné ; chaque événement d'un morceau lu (vérifié) ou
    // relu malgré son CRC faux (non vérifié), et compté comme tel.
    assert!(lu.bilan.morceaux.len() <= evtx::MAX_RECAPS);
    assert!(lu.bilan.morceaux.windows(2).all(|p| p[0].rang < p[1].rang));
    for e in &lu.enregistrements {
        let etat = if e.verifie { evtx::EtatMorceau::Lu } else { evtx::EtatMorceau::NonVerifie };
        assert!(lu.bilan.morceaux.iter().any(|m| m.etat == etat && m.rang == e.morceau));
    }
    let non_verifies = lu.enregistrements.iter().filter(|e| !e.verifie).count() as u64;
    assert_eq!(lu.bilan.enregistrements_non_verifies, non_verifies);
    for e in &lu.enregistrements {
        let (mut noeuds, mut texte) = (0, 0);
        let mut pile = vec![&e.evenement];
        while let Some(n) = pile.pop() {
            noeuds += 1;
            texte += n.texte.len() + n.attributs.iter().map(|(_, v)| v.len()).sum::<usize>();
            pile.extend(&n.enfants);
        }
        assert!(noeuds <= bornes.noeuds);
        assert!(texte <= bornes.texte_enregistrement);
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let bornes = bornes();
    // Tel quel : signatures et CRC presque toujours faux, les morceaux écartés.
    verifier(octets, &bornes);
    // Puis rendu cohérent, pour atteindre ce qui suit les CRC : l'en-tête « ElfFile » ajouté s'il manque, les
    // morceaux complétés à 64 Kio par des zéros (les graines s'arrêtent à la place libre), les CRC recalculés.
    let mut fichier = Vec::with_capacity(octets.len() + 65_536 + 4096);
    if !octets.starts_with(b"ElfFile\0") {
        fichier.extend_from_slice(b"ElfFile\0");
        fichier.resize(4096, 0);
    }
    fichier.extend_from_slice(octets);
    if fichier.len() > 4096 {
        let morceaux = (fichier.len() - 4096).div_ceil(65_536);
        fichier.resize(4096 + morceaux * 65_536, 0);
    }
    evtx::recalculer_crc(&mut fichier);
    verifier(&fichier, &bornes);
});
