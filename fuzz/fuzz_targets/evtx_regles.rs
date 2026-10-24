//! Les règles des journaux d'événements de Windows (src/journaux_windows/regles/) sur des événements hostiles : un
//! journal rapporté d'un Windows piraté, dont chaque champ peut avoir été écrit par l'attaquant (nom de compte,
//! chemin de service, bloc de script, adresse web). L'entrée est coupée aux octets nuls : chaque morceau est le XML
//! d'un événement (tel que le rend le service des journaux), et l'entrée entière est aussi lue comme un fichier
//! .evtx. Aucune panique, et les bornes du moteur tenues : trouvailles, exemples, textes gardés.
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

#[allow(dead_code)]
#[path = "../../src/journaux_windows/trous.rs"]
mod trous;

#[allow(dead_code)]
#[path = "../../src/journaux_windows/regles/moteur.rs"]
mod moteur;

#[allow(dead_code)]
#[path = "../../src/journaux_windows/regles/jeu.rs"]
mod jeu;

/// Plus petites que celles du programme : un dépassement se voit vite.
fn bornes() -> evtx::Bornes {
    evtx::Bornes {
        enregistrements: 500,
        noeuds: 512,
        travail: 20_000,
        texte: 4096,
        texte_enregistrement: 1 << 16,
        ..evtx::Bornes::default()
    }
}

fn bornes_moteur() -> moteur::BornesMoteur {
    moteur::BornesMoteur {
        trouvailles: 16,
        reperes: 3,
        dates: 200,
        cles: 8,
        arrets: 8,
        journaux: 8,
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let bornes = bornes();
    let b = bornes_moteur();
    let mut m = moteur::Moteur::nouveau(jeu::REGLES, moteur::Options::default(), b.clone());
    let mut recus = 0usize;
    for morceau in octets.split(|&o| o == 0) {
        let Ok(x) = std::str::from_utf8(morceau) else { continue };
        if let Ok((e, _)) = xml::enregistrement(x, &bornes)
            && let Some(v) = evenement::EvenementWindows::depuis(e, evenement::Origine::Vivant)
        {
            // Le même événement deux fois, l'une d'un morceau abîmé : la réserve doit suivre.
            let mut abime = v.clone();
            abime.verifie = false;
            m.recevoir(&v);
            m.recevoir(&abime);
            recus += 2;
        }
    }
    if let Ok(lu) = evtx::lire_octets(octets, &bornes) {
        for e in lu.enregistrements {
            if let Some(v) = evenement::EvenementWindows::depuis(e, evenement::Origine::Vivant) {
                m.recevoir(&v);
                recus += 1;
            }
        }
    }
    let etats: Vec<moteur::EtatJournal> = jeu::JOURNAUX
        .iter()
        .map(|j| moteur::EtatJournal {
            nom: (*j).to_string(),
            lecture: moteur::Lecture::Lu(Vec::new()),
            active: None,
            suites: Vec::new(),
        })
        .collect();
    for j in m.conclure(&etats) {
        assert!(j.trouvailles.len() <= b.trouvailles, "{}", j.regle.id);
        assert!(j.examines <= recus as u64 * 8);
        for t in &j.trouvailles {
            assert!(t.reperes.len() <= b.reperes);
            assert!(t.objet.chars().count() <= moteur::TEXTE_MAX + 1);
            assert!(t.details.iter().all(|(_, v)| v.chars().count() <= moteur::TEXTE_MAX + 1));
            assert!(t.verifies <= t.nombre);
            assert!(t.verifies > 0 || t.reserves.contains(&moteur::Reserve::MorceauAbime));
        }
    }
});
