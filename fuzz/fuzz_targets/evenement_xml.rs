//! Le XML d'un événement de Windows (src/journaux_windows/xml.rs), changé en la forme commune
//! (src/journaux_windows/evenement.rs) : ce que rend le service des journaux, dont les valeurs viennent de qui a
//! écrit l'événement. Éléments imbriqués sans fin, milliers d'attributs, références de caractères, entités
//! inconnues, DOCTYPE, XML coupé.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/journaux_windows/evtx/mod.rs"]
mod evtx;

#[allow(dead_code)]
#[path = "../../src/journaux_windows/xml.rs"]
mod xml;

#[allow(dead_code)]
#[path = "../../src/journaux_windows/evenement.rs"]
mod evenement;

/// Plus petites que celles du programme : un dépassement se voit vite.
fn bornes() -> evtx::Bornes {
    evtx::Bornes {
        noeuds: 256,
        profondeur: 16,
        texte: 512,
        texte_enregistrement: 1 << 14,
        ..evtx::Bornes::default()
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(x) = std::str::from_utf8(octets) else { return };
    let bornes = bornes();
    if let Ok(a) = xml::arbre(x, &bornes) {
        let (mut noeuds, mut texte) = (0, 0);
        let mut pile = vec![(&a.racine, 1usize)];
        while let Some((n, p)) = pile.pop() {
            assert!(p <= bornes.profondeur);
            assert!(n.texte.chars().count() <= bornes.texte);
            noeuds += 1 + n.attributs.len();
            texte += n.texte.len() + n.attributs.iter().map(|(_, v)| v.len()).sum::<usize>();
            pile.extend(n.enfants.iter().map(|e| (e, p + 1)));
        }
        assert!(noeuds <= bornes.noeuds);
        assert!(texte <= bornes.texte_enregistrement);
    }
    if let Ok((e, _)) = xml::enregistrement(x, &bornes) {
        let numero = e.numero_systeme;
        if let Some(v) = evenement::EvenementWindows::depuis(e, evenement::Origine::Vivant) {
            assert_eq!(v.numero, numero);
            let _ = evenement::Filtre::default().juger(&v);
        }
    }
    let _ = xml::numero_de_secours(x);
});
