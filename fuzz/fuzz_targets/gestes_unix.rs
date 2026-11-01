//! La grammaire des gestes de Linux que l'assistant élevé lit du Vanguard non élevé (src/machine/gestes_unix.rs), et
//! la découpe commune (src/machine/decoupe.rs) telle que Linux et macOS s'en servent : une ligne « vanguard:… » est
//! native, toute autre passe à bash. Familles et identifiants hors de la table, espaces doublées, champs en plus,
//! octets nuls, majuscules, lignes démesurées.
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
        }
    }
    // La découpe à la façon de Linux et macOS : des correctifs séparés par une ligne vide. Un correctif n'est fait
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
