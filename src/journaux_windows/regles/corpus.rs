//! Les cas du corpus de détection des règles EVT- (`modele::corpus`) : des événements fabriqués, un par ligne, passés
//! au moteur des règles comme la source vivante les lui donne, sous les trois systèmes (le moteur n'a rien de
//! Windows). Seules comptent les trouvailles de la règle du cas, rendues en constats pour le corpus.
//!
//! Une ligne : `journal|fournisseur|numéro|secondes|champ=valeur|…`. Commencée par `*N|`, elle compte pour N
//! événements, une minute d'écart chacun (une rafale).

use chrono::{DateTime, Duration, Utc};

use super::jeu::REGLES;
use super::moteur::{BornesMoteur, EtatJournal, Gravite, Lecture, Moteur, Options};
use crate::journaux_windows::evenement::{EvenementWindows, Origine};
use crate::machine::{Constat, alerte, ok};
use crate::modele::corpus::{Entree, Juge};
use crate::risk::Niveau;

pub(crate) const CAS: &[(&str, Juge)] = &[
    ("EVT-ADM-001", evenements),
    ("EVT-AUD-001", evenements),
    ("EVT-BIT-001", evenements),
    ("EVT-DEF-001", evenements),
    ("EVT-EFF-001", evenements),
    ("EVT-IDE-001", evenements),
    ("EVT-MDP-001", evenements),
    ("EVT-PSH-001", evenements),
    ("EVT-RDP-001", evenements),
    ("EVT-SRV-001", evenements),
    ("EVT-TAC-001", evenements),
    ("EVT-WMI-001", evenements),
];

fn lire(e: &Entree) -> Vec<EvenementWindows> {
    let t0: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-10-18T14:00:00Z").unwrap().to_utc();
    let mut evenements = Vec::new();
    let mut numero = 1;
    for mut c in e.champs() {
        let fois: i64 = match c[0].strip_prefix('*') {
            Some(n) => {
                c.remove(0);
                n.parse().unwrap()
            }
            None => 1,
        };
        let secondes: i64 = c[3].parse().unwrap();
        let champs: Vec<(String, String)> = c[4..]
            .iter()
            .filter_map(|f| f.split_once('='))
            .map(|(n, v)| (n.to_string(), v.replace("\\n", "\n")))
            .collect();
        for i in 0..fois {
            evenements.push(EvenementWindows {
                journal: c[0].into(),
                id: c[2].parse().unwrap(),
                niveau: Some(4),
                date: Some(t0 + Duration::seconds(secondes + 60 * i)),
                ordinateur: "poste-alice".into(),
                numero: Some(numero),
                fournisseur: c[1].into(),
                utilisateur: None,
                champs: champs.clone(),
                origine: Origine::Vivant,
                verifie: true,
            });
            numero += 1;
        }
    }
    evenements
}

/// La règle du cas (le nom de son dossier) jugée sur ses événements, tous les journaux lus en entier.
fn evenements(e: &Entree) -> Vec<Constat> {
    let id = e.dossier.file_name().unwrap().to_string_lossy().into_owned();
    let options = Options {
        depuis: None,
        defender_antivirus: Some(true),
        installation: None,
    };
    let mut moteur = Moteur::nouveau(REGLES, options, BornesMoteur::default());
    for ev in lire(e) {
        moteur.recevoir(&ev);
    }
    let journaux: Vec<EtatJournal> = super::jeu::JOURNAUX
        .iter()
        .map(|j| EtatJournal {
            nom: (*j).to_string(),
            lecture: Lecture::Lu(Vec::new()),
            active: Some(true),
            principal: true,
            suites: Vec::new(),
        })
        .collect();
    let jugement = moteur
        .conclure(&journaux)
        .into_iter()
        .find(|j| j.regle.id == id)
        .unwrap_or_else(|| panic!("{id} : pas une règle du jeu"));
    let mut constats: Vec<Constat> = jugement
        .trouvailles
        .iter()
        .map(|t| {
            let niveau = match t.gravite {
                Gravite::Info => Niveau::Info,
                Gravite::Alerte => Niveau::Eleve,
                Gravite::Critique => Niveau::Critique,
            };
            let details: Vec<&str> = t.details.iter().map(|(_, v)| v.as_str()).collect();
            Constat {
                verifie: t.verifies > 0,
                ..alerte("Journaux", niveau, format!("{} : {}", t.objet, details.join(" ; ")))
            }
        })
        .collect();
    if constats.is_empty() {
        constats.push(ok("Journaux", format!("{id} : rien trouvé")));
    }
    constats
}
