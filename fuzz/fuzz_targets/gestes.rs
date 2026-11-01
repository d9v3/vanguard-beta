//! La grammaire des lignes que le processus élevé de Windows lit du Vanguard non élevé (src/machine/windows/
//! gestes.rs) : script vérifié par empreinte, programme fixe de la table, acte sur un service ou un dossier de la
//! table, sur le pare-feu ou la catégorie d'un réseau (GUID), sur une clé du registre désignée par un nom en
//! hexadécimal UTF-16 (IFEO, SilentProcessExit, service), liste validée, découpe d'une liste de correctifs en
//! morceaux natifs et PowerShell, états d'un script en échec. Chemins piégés (« .. », NUL, lecteur manquant),
//! hexadécimal en majuscules ou en demi-paire, noms hors de la liste fermée, lignes et correctifs en nombre.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/machine/windows/gestes.rs"]
mod gestes;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(texte) = std::str::from_utf8(octets) else {
        return;
    };
    let lignes: Vec<String> = texte.split('\n').map(str::to_string).collect();
    for l in &lignes {
        // Une ligne relue se réécrit à l'identique : rien d'autre que sa forme exacte n'est accepté.
        if let Some(a) = gestes::analyser_programme(l) {
            assert_eq!(a.ligne(), *l);
            assert!(l.len() <= 256 && l.is_ascii());
            // Les arguments sont ceux de la table : le nom reçu n'en ajoute pas un, ni une espace.
            let args = a.arguments("C:");
            assert_eq!(args.len(), a.programme.arguments.len());
            assert!(args.iter().all(|x| !x.contains(['\n', '\r', '"'])));
        }
        // Un acte : de la table, écrit à l'identique, court, ASCII ; jamais accepté sans en avoir le verbe. Seuls les
        // actes nommés du registre dépassent 256 octets.
        if let Some(a) = gestes::analyser_acte(l) {
            assert_eq!(a.ligne(), *l);
            let nomme = matches!(
                a,
                gestes::Acte::IfeoDebugger(..) | gestes::Acte::IfeoSilencieux(..) | gestes::Acte::ServiceGuillemets(_)
            );
            let borne = if nomme { gestes::ACTE_NOM_MAX } else { gestes::ACTE_MAX };
            assert!(l.len() <= borne && l.is_ascii());
            assert!(gestes::est_un_acte(l));
            assert!(!(a.durcit() && a.affaiblit()));
            match a {
                gestes::Acte::Service(s) => {
                    assert!(!(s.durcit && s.affaiblit));
                    assert!(gestes::SERVICES.iter().any(|t| t.nom == s.nom));
                }
                // Aucune ligne ne coupe le pare-feu ; « absent » ne vise que les règles d'entrée.
                gestes::Acte::PareFeuPublic(p) => {
                    for (r, v) in p.reglages() {
                        assert!(r != gestes::ReglagePublic::Actif || v == gestes::ValeurPublic::Oui);
                        assert!(
                            v != gestes::ValeurPublic::Absent || r == gestes::ReglagePublic::ReglesEntrantes
                        );
                    }
                }
                gestes::Acte::ReseauCategorie(r) => {
                    assert_eq!(gestes::GuidReseau::lire(&r.guid.texte()), Some(r.guid));
                }
                // Un nom ne sort jamais de sa racine : ni séparateur, ni « .. », ni contrôle, 260 unités au plus.
                gestes::Acte::IfeoDebugger(_, n) | gestes::Acte::IfeoSilencieux(_, n) | gestes::Acte::ServiceGuillemets(n) => {
                    let t = n.texte();
                    assert!(!t.is_empty() && t.encode_utf16().count() <= gestes::NOM_MAX);
                    assert!(!t.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) && !t.contains(".."));
                    assert!(!t.chars().any(char::is_control) && t != ".");
                    assert_eq!(gestes::NomFichier::lire(&n.hex()).as_ref(), Some(&n));
                    assert_eq!(gestes::NomFichier::nouveau(t).as_ref(), Some(&n));
                }
                _ => {}
            }
        }
        if let Some(s) = gestes::analyser_script(l) {
            assert_eq!(gestes::ligne_script(&s.empreinte, &s.chemin), *l);
            assert!(!s.chemin.split(['\\', '/']).any(|c| c == "." || c == ".."));
            assert!(!s.chemin.contains(['\0', '\n', '\r']));
        }
        if let Some(etats) = gestes::etats_du_script(l) {
            assert!(etats.len() <= gestes::ETATS_MAX);
            // Relus depuis la raison qu'en écrit le processus élevé : les mêmes.
            let code: i32 = l
                .strip_prefix("echec code=")
                .and_then(|r| r.split(' ').next())
                .and_then(|c| c.parse().ok())
                .unwrap();
            let raison = format!("echec {}", gestes::raison_du_script(code, &etats));
            assert_eq!(gestes::etats_du_script(&raison), Some(etats));
        }
    }
    // La liste : acceptée, elle a une entrée par ligne ; les « autres » lignes ne passent que par le validateur donné,
    // qui admet ici toute longueur (comme un ordre du blocage et son chemin) : seule la borne de `valider` arrête une
    // ligne démesurée (graine « longue », -max_len d'outils/fuzz.sh).
    let autre = |l: &str| l.starts_with("autre").then_some(());
    // Deux lignes de script de même empreinte : la liste est refusée, quel que soit le chemin de chacune.
    let empreintes: Vec<String> = lignes
        .iter()
        .filter_map(|l| gestes::analyser_script(l))
        .map(|s| s.empreinte)
        .collect();
    let doublon = empreintes.iter().enumerate().any(|(i, e)| empreintes[..i].contains(e));
    match gestes::valider(&lignes, autre) {
        Some(v) => {
            assert_eq!(v.len(), lignes.len());
            assert!(!lignes.is_empty() && lignes.len() <= gestes::LIGNES_MAX);
            assert!(lignes.iter().all(|l| l.len() <= gestes::LIGNE_MAX));
            assert!(!doublon, "script en double accepté");
        }
        None => {
            // Refusée : il y a une raison, jamais une liste bonne refusée sans cause.
            let bonne = |l: &String| {
                l.len() <= gestes::LIGNE_MAX
                    && if l.starts_with(gestes::SCRIPT) {
                        gestes::analyser_script(l).is_some()
                    } else if l.starts_with(gestes::PROGRAMME) {
                        gestes::analyser_programme(l).is_some()
                    } else if gestes::est_un_acte(l) {
                        gestes::analyser_acte(l).is_some()
                    } else {
                        autre(l).is_some()
                    }
            };
            assert!(
                lignes.is_empty() || lignes.len() > gestes::LIGNES_MAX || doublon || !lignes.iter().all(bonne),
                "liste bonne refusée"
            );
        }
    }
    // La découpe : des correctifs séparés par une ligne vide ; chaque ligne est dans un seul morceau, dans l'ordre, et
    // un morceau natif n'a que des lignes natives (le point de restauration n'est jamais mêlé au script).
    let correctifs: Vec<Vec<String>> = texte
        .split("\n\n")
        .map(|c| c.split('\n').filter(|l| !l.is_empty()).map(str::to_string).collect())
        .collect();
    let natif = |l: &str| l.starts_with('#');
    let mut vues = Vec::new();
    for m in gestes::decouper(&correctifs, natif) {
        match m {
            gestes::Morceau::Natif(v) => {
                assert!(!v.is_empty());
                for (i, j) in v {
                    assert!(natif(&correctifs[i][j]));
                    vues.push((i, j));
                }
            }
            gestes::Morceau::Script(v) => {
                assert!(!v.is_empty());
                for (i, suite) in v {
                    assert!(!suite.is_empty());
                    for j in suite {
                        assert!(!natif(&correctifs[i][j]));
                        vues.push((i, j));
                    }
                }
            }
        }
    }
    let attendues: Vec<(usize, usize)> = correctifs
        .iter()
        .enumerate()
        .flat_map(|(i, c)| (0..c.len()).map(move |j| (i, j)))
        .collect();
    assert_eq!(vues, attendues);
});
