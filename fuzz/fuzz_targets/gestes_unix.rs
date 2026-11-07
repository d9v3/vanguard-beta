//! La grammaire des gestes de Linux que l'assistant élevé lit du Vanguard non élevé (src/machine/gestes_unix.rs), et
//! la découpe commune (src/machine/decoupe.rs) telle que Linux s'en sert : une ligne « vanguard:… » est
//! native, toute autre passe à bash. Familles et identifiants hors de la table, espaces doublées, champs en plus,
//! octets nuls, majuscules, lignes démesurées ; noms d'unité hostiles (remontée, gabarit, sans suffixe, pare-feu
//! désigné) ; gestes de défense (identifiant de note, chemins désignés, identifiant fixe d'un pare-feu coupé).
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/machine/gestes_unix.rs"]
mod gestes_unix;

#[allow(dead_code)]
#[path = "../../src/machine/decoupe.rs"]
mod decoupe;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(texte) = std::str::from_utf8(octets) else {
        return;
    };
    for l in texte.split('\n') {
        let Some(g) = gestes_unix::analyser(l) else {
            continue;
        };
        // Une ligne relue se réécrit à l'identique : rien d'autre que sa forme exacte n'est accepté.
        assert_eq!(g.ligne(), l);
        assert_eq!(gestes_unix::analyser(&g.ligne()), Some(g));
        assert!(l.len() <= gestes_unix::GESTE_MAX && l.is_ascii());
        assert!(gestes_unix::a_le_prefixe(l));
        assert!(!l.contains(['\0', '\r', '\t', '/']));
        match g {
            // Un programme de la table, et lui seul : la ligne ne lui ajoute ni argument, ni chemin.
            gestes_unix::GesteUnix::Programme(p) => {
                assert!(gestes_unix::PROGRAMMES.iter().any(|t| std::ptr::eq(*t, p)));
                assert_eq!(l.split(' ').count(), 3);
                assert!(!p.outil.contains('/'));
            }
            // Une unité de la table, et elle seule ; jamais un geste refusé (un pare-feu coupé).
            gestes_unix::GesteUnix::Unite(_, u) => {
                assert!(gestes_unix::UNITES_CONNUES.iter().any(|t| std::ptr::eq(*t, u)));
                assert_eq!(l.split(' ').count(), 4);
            }
            // Un nom désigné suit la règle stricte, et n'est jamais celui d'une unité de la table.
            gestes_unix::GesteUnix::Designee(_, n) => {
                assert!(gestes_unix::nom_admis(n.as_str()));
                assert!(!gestes_unix::UNITES_CONNUES.iter().any(|t| t.nom == n.as_str()));
                assert!(!n.as_str().contains(".."));
                assert_eq!(l.split(' ').count(), 4);
            }
            gestes_unix::GesteUnix::ReinitialiserEchecs => assert_eq!(l.split(' ').count(), 3),
            gestes_unix::GesteUnix::SignaturesClamav => assert_eq!(l.split(' ').count(), 2),
            // Un geste de défense : une note à l'identifiant strict, un chemin désigné absolu sans « . » ni « .. »,
            // et toujours l'accord de la personne demandé sur son terminal. Seuls refus possibles : une unité de
            // session, une ligne d'un fichier que Vanguard ne connaît pas.
            gestes_unix::GesteUnix::Defense(d, id) => {
                use gestes_unix::Defense as D;
                assert!(gestes_unix::IdNote::nouveau(id.as_str()) == Some(id));
                assert_eq!(l.split(' ').nth(1), Some("defense"));
                assert!(g.demande_accord());
                if let D::RetirerSetuid(c)
                | D::RetirerCapacites(c)
                | D::RendreDossierARoot(c)
                | D::RetirerLigne(_, c)
                | D::RetirerAncre(c)
                | D::CommenterProxy(_, c)
                | D::RemettreProgramme(c) = d
                {
                    assert!(gestes_unix::chemin_admis(c.octets()));
                }
                // Une ancre hors des dossiers d'ajouts, un proxy hors des fichiers connus, le PID 0 ou 1, un programme
                // à remettre qui n'est pas celui de Vanguard : jamais relus.
                match d {
                    D::RetirerAncre(c) => assert!(gestes_unix::ancre_admise(c.octets())),
                    D::CommenterProxy(_, c) => assert!(gestes_unix::fichier_de_ligne_admis(c.octets())),
                    D::ArreterProgramme(pid, _) => assert!(pid > 1),
                    D::RemettreProgramme(c) => assert!(gestes_unix::programme_pose_admis(c.octets())),
                    _ => {}
                }
                // Lot D7c : une coupure de pare-feu ne se note que sous l'identifiant fixe de son pare-feu, et ces
                // identifiants ne servent à aucun autre geste que Remettre.
                match d {
                    D::CouperPareFeu(p) => assert!(id == p.note()),
                    D::Remettre => {}
                    _ => assert!(gestes_unix::PareFeu::de_la_note(id).is_none()),
                }
                if g.refus().is_some() {
                    assert!(match d {
                        D::DesactiverService(u) => gestes_unix::UNITES_DE_SESSION.contains(&u.as_str()),
                        D::RetirerLigne(_, c) => !gestes_unix::fichier_de_ligne_admis(c.octets()),
                        _ => false,
                    });
                }
                continue;
            }
        }
        assert!(g.refus().is_none());
    }
    // La découpe à la façon de Linux : des correctifs séparés par une ligne vide. Un correctif n'est fait
    // par l'assistant que s'il ne donne qu'un morceau natif, par bash que s'il ne donne qu'un morceau de commandes ;
    // une ligne native et une commande dans le même correctif donnent toujours plusieurs morceaux (refusé).
    let correctifs: Vec<Vec<String>> = texte
        .split("\n\n")
        .map(|c| c.split('\n').filter(|l| !l.is_empty()).map(str::to_string).collect())
        .collect();
    let natif = |l: &str| l.starts_with("vanguard:");
    for c in &correctifs {
        let morceaux = decoupe::decouper(std::slice::from_ref(c), natif);
        let natives = c.iter().filter(|l| natif(l)).count();
        match morceaux.as_slice() {
            [] => assert!(c.is_empty()),
            [decoupe::Morceau::Natif(v)] => {
                assert_eq!(natives, c.len());
                assert_eq!(v.len(), c.len());
            }
            [decoupe::Morceau::Script(v)] => {
                assert_eq!(natives, 0);
                assert_eq!(v.iter().map(|(_, s)| s.len()).sum::<usize>(), c.len());
            }
            _ => assert!(natives > 0 && natives < c.len(), "correctif d'un seul genre coupé"),
        }
    }
});
