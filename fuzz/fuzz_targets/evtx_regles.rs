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

// Le vrai module de masquage (autonome) : jeu.rs y prend `liste_masquee!`/`mot_masque!` comme dans le programme.
#[allow(dead_code)]
#[path = "../../src/masque.rs"]
mod masque;

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
    let mut tous: Vec<evenement::EvenementWindows> = Vec::new();
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
            tous.push(v);
            tous.push(abime);
            recus += 2;
        }
    }
    if let Ok(lu) = evtx::lire_octets(octets, &bornes) {
        for e in lu.enregistrements {
            if let Some(v) = evenement::EvenementWindows::depuis(e, evenement::Origine::Vivant) {
                m.recevoir(&v);
                tous.push(v);
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
            principal: true,
            suites: Vec::new(),
        })
        .collect();
    // Les mêmes événements à l'envers (la source vivante lit les plus récents d'abord) : sans borne atteinte, les
    // mêmes trouvailles.
    let mut inverse = moteur::Moteur::nouveau(jeu::REGLES, moteur::Options::default(), b.clone());
    for e in tous.iter().rev() {
        inverse.recevoir(e);
    }
    let resume = |js: &[moteur::Jugement]| -> Vec<(usize, usize, String, String, u64, u64)> {
        let mut v: Vec<_> = js
            .iter()
            .enumerate()
            .flat_map(|(r, j)| {
                j.trouvailles
                    .iter()
                    .map(move |t| (r, t.volet, t.objet.clone(), format!("{:?}", t.gravite), t.nombre, t.verifies))
            })
            .collect();
        v.sort();
        v
    };
    let a = m.conclure(&etats);
    let z = inverse.conclure(&etats);
    let borne = a.iter().chain(&z).any(|j| {
        j.au_dela > 0 || j.manques.iter().any(|x| matches!(x, moteur::Manque::Bornes(_)))
    });
    if !borne {
        assert_eq!(resume(&a), resume(&z));
    }
    for j in a {
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
