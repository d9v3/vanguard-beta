//! Les trous de la suite des numéros : cas écrits à la main, puis proptest contre un modèle naïf (numéro par numéro),
//! et l'absence de faux trou quand rien n'a été retiré, quel que soit l'ordre des morceaux dans le fichier.

use proptest::prelude::*;

use super::*;

fn morceau(rang: u64, lu: bool, annonce: Option<(u64, u64)>, non_rendus: u64) -> RecapMorceau {
    RecapMorceau {
        rang,
        lu,
        annonce,
        non_rendus,
    }
}

fn presents(numeros: impl IntoIterator<Item = u64>) -> Vec<Present> {
    numeros
        .into_iter()
        .map(|numero| Present {
            numero,
            date: DateTime::from_timestamp(i64::try_from(numero).unwrap_or(0) * 60, 0),
        })
        .collect()
}

fn plages(s: &Suite) -> Vec<(u64, u64, Nature)> {
    s.trous.iter().map(|t| (t.de, t.a, t.nature)).collect()
}

fn juger_simple(numeros: impl IntoIterator<Item = u64>, morceaux: &[RecapMorceau], entre: Nature) -> Suite {
    let contexte = Contexte {
        morceaux,
        entre_morceaux: entre,
    };
    juger(Numerotation::Journal, presents(numeros), &contexte, 1000)
}

#[test]
fn une_suite_entiere_n_a_pas_de_trou_meme_tournante_ou_effacee() {
    // Le journal tournant (les plus anciens écrasés) commence à 500 ; un journal effacé continue sa suite (le 1102
    // au numéro 227126) : ni l'un ni l'autre n'est un trou.
    for debut in [1u64, 500, 227_126] {
        let s = juger_simple(debut..debut + 300, &[], Nature::Absents);
        assert_eq!(
            (s.premier, s.dernier, s.presents),
            (Some(debut), Some(debut + 299), 300)
        );
        assert!(s.trous.is_empty(), "{s:?}");
    }
    let vide = juger_simple([], &[], Nature::Absents);
    assert_eq!(
        (vide.premier, vide.dernier, vide.presents, vide.trous.len()),
        (None, None, 0, 0)
    );
}

#[test]
fn un_trou_dans_un_morceau_intact_est_un_retrait() {
    let morceaux = [morceau(0, true, Some((1, 10)), 0), morceau(1, true, Some((11, 20)), 0)];
    let numeros = (1..=20).filter(|n| !(4..=6).contains(n) && *n != 20);
    let s = juger_simple(numeros, &morceaux, Nature::Absents);
    // 4 à 6 au milieu du premier morceau ; 20, le dernier annoncé, ôté avec la place libre reculée.
    assert_eq!(plages(&s), [(4, 6, Nature::Retires), (20, 20, Nature::Retires)]);
    // Les dates autour : celles des présents voisins (3 et 7) ; rien après le dernier.
    assert_eq!(s.trous[0].avant, DateTime::from_timestamp(3 * 60, 0));
    assert_eq!(s.trous[0].apres, DateTime::from_timestamp(7 * 60, 0));
    assert_eq!(s.trous[1].apres, None);
    assert_eq!(s.trous[0].nombre(), 3);
}

#[test]
fn entre_deux_morceaux_la_nature_vient_du_fichier() {
    let morceaux = [morceau(0, true, Some((1, 10)), 0), morceau(1, true, Some((21, 30)), 0)];
    let numeros = || (1..=10).chain(21..=30);
    for entre in [Nature::Absents, Nature::CopieAChaud, Nature::Illisible] {
        let s = juger_simple(numeros(), &morceaux, entre);
        assert_eq!(plages(&s), [(11, 20, entre)]);
    }
}

#[test]
fn ce_que_la_lecture_a_perdu_n_est_pas_un_retrait() {
    // Le morceau du milieu écarté (CRC faux), son en-tête juste : sa plage est illisible, pas retirée.
    let ecarte = [
        morceau(0, true, Some((1, 10)), 0),
        morceau(1, false, Some((11, 20)), 0),
        morceau(2, true, Some((21, 30)), 0),
    ];
    let s = juger_simple((1..=10).chain(21..=30), &ecarte, Nature::Absents);
    assert_eq!(plages(&s), [(11, 20, Nature::Illisible)]);
    // Un morceau lu dont deux enregistrements n'ont pas été rendus : un trou chez lui est peut-être eux.
    let incomplet = [morceau(0, true, Some((1, 10)), 2)];
    let s = juger_simple((1..=10).filter(|n| *n != 5), &incomplet, Nature::Absents);
    assert_eq!(plages(&s), [(5, 5, Nature::Illisible)]);
    // Un trou qui déborde d'un morceau écarté sur un morceau intact : la part du morceau intact reste un retrait.
    let deborde = [morceau(0, true, Some((1, 10)), 0), morceau(1, false, Some((11, 20)), 0)];
    let s = juger_simple((1..=7).chain(21..=22), &deborde, Nature::Absents);
    assert_eq!(plages(&s), [(8, 10, Nature::Retires), (11, 20, Nature::Illisible)]);
}

#[test]
fn doublons_et_extremes() {
    let s = juger_simple([5, 5, 6, 6, 6, 7], &[], Nature::Absents);
    assert_eq!((s.presents, s.doublons, s.trous.len()), (3, 3, 0));
    // Les numéros aux bords de u64 : aucun débordement, le trou entre eux est dit.
    let s = juger_simple([0, u64::MAX], &[], Nature::Absents);
    assert_eq!(plages(&s), [(1, u64::MAX - 1, Nature::Absents)]);
    assert_eq!(s.trous[0].nombre(), u64::MAX - 1);
    let s = juger_simple(
        [u64::MAX],
        &[morceau(0, true, Some((u64::MAX - 2, u64::MAX)), 0)],
        Nature::Absents,
    );
    assert_eq!(plages(&s), [(u64::MAX - 2, u64::MAX - 1, Nature::Retires)]);
    // La borne des trous : les suivants comptés.
    let contexte = Contexte {
        morceaux: &[],
        entre_morceaux: Nature::Absents,
    };
    let s = juger(Numerotation::Journal, presents((0..100).map(|n| n * 2)), &contexte, 10);
    assert_eq!((s.trous.len(), s.trous_au_dela), (10, 89));
}

// ---- proptest ----

/// La nature d'un numéro manquant, calculée naïvement : la définition du module, numéro par numéro.
fn nature_naive(n: u64, morceaux: &[RecapMorceau], entre: Nature) -> Nature {
    let dans = |m: &&RecapMorceau| m.annonce.is_some_and(|(p, d)| p <= n && n <= d);
    if morceaux.iter().filter(dans).any(|m| !m.lu || m.non_rendus > 0) {
        Nature::Illisible
    } else if morceaux.iter().filter(dans).any(|m| m.lu) {
        Nature::Retires
    } else {
        entre
    }
}

/// Les numéros manquants et leur nature, d'après le modèle naïf.
fn modele(numeros: &[u64], morceaux: &[RecapMorceau], entre: Nature) -> Vec<(u64, Nature)> {
    let lus = morceaux.iter().filter(|m| m.lu).filter_map(|m| m.annonce);
    let lo = numeros.iter().copied().chain(lus.clone().map(|a| a.0)).min();
    let hi = numeros.iter().copied().chain(lus.map(|a| a.1)).max();
    let (Some(lo), Some(hi)) = (lo, hi) else {
        return Vec::new();
    };
    (lo..=hi)
        .filter(|n| !numeros.contains(n))
        .map(|n| (n, nature_naive(n, morceaux, entre)))
        .collect()
}

/// Les trous rendus, numéro par numéro ; et deux trous qui se touchent n'ont jamais la même nature.
fn deplies(s: &Suite) -> Vec<(u64, Nature)> {
    for paire in s.trous.windows(2) {
        assert!(paire[0].a < paire[1].de, "{s:?}");
        if paire[0].a + 1 == paire[1].de {
            assert_ne!(paire[0].nature, paire[1].nature, "{s:?}");
        }
    }
    s.trous
        .iter()
        .flat_map(|t| (t.de..=t.a).map(move |n| (n, t.nature)))
        .collect()
}

fn nature() -> impl Strategy<Value = Nature> {
    prop::sample::select(vec![Nature::Absents, Nature::CopieAChaud, Nature::Illisible])
}

/// Un journal : des morceaux de numéros qui se suivent depuis `debut`, rangés dans le fichier dans un ordre tourné
/// (journal circulaire) ; chacun lu, lu avec des pertes, ou écarté (annonce gardée ou non).
fn journal() -> impl Strategy<Value = (u64, Vec<(u64, u8, bool)>, usize)> {
    (
        prop_oneof![Just(1u64), 1u64..1_000_000, Just(u64::MAX - 5000)],
        prop::collection::vec((1u64..40, 0u8..6, any::<bool>()), 1..12),
        any::<prop::sample::Index>().prop_map(|i| i.index(12)),
    )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    /// Rien retiré, tous les morceaux lus : aucun trou, quel que soit l'ordre des morceaux dans le fichier.
    #[test]
    fn aucun_faux_trou((debut, tailles, tour) in journal(), entre in nature()) {
        let mut morceaux = Vec::new();
        let mut numeros = Vec::new();
        let mut n = debut;
        for (rang, (taille, _, _)) in tailles.iter().enumerate() {
            morceaux.push(morceau(rang as u64, true, Some((n, n + taille - 1)), 0));
            numeros.extend(n..n + taille);
            n += taille;
        }
        let tour = tour % morceaux.len();
        morceaux.rotate_left(tour);
        let s = juger_simple(numeros.iter().copied().rev(), &morceaux, entre);
        prop_assert!(s.trous.is_empty(), "{:?}", s);
        prop_assert_eq!(s.presents, numeros.len() as u64);
    }

    /// Des numéros ôtés au hasard, des morceaux écartés ou disparus : les trous rendus sont exactement ceux du
    /// modèle naïf, numéro par numéro, avec la même nature.
    #[test]
    fn comme_le_modele((debut, tailles, tour) in journal(), entre in nature(), otes in prop::collection::vec(0u64..400, 0..30)) {
        let mut morceaux = Vec::new();
        let mut numeros = Vec::new();
        let mut n = debut;
        for (rang, (taille, sorte, annonce)) in tailles.iter().enumerate() {
            let plage = (n, n + taille - 1);
            let present = |k: u64| !otes.contains(&(k - debut));
            match sorte {
                // Lu en entier.
                0..=2 => {
                    morceaux.push(morceau(rang as u64, true, Some(plage), 0));
                    numeros.extend((n..n + taille).filter(|k| present(*k)));
                }
                // Lu avec des pertes : les ôtés de ce morceau sont des non-rendus.
                3 => {
                    morceaux.push(morceau(rang as u64, true, Some(plage), 1));
                    numeros.extend((n..n + taille).filter(|k| present(*k)));
                }
                // Écarté, son annonce gardée ou non.
                4 => morceaux.push(morceau(rang as u64, false, annonce.then_some(plage), 0)),
                // Disparu du fichier (remis à zéro, jamais écrit sur le disque).
                _ => {}
            }
            n += taille;
        }
        if !morceaux.is_empty() {
            let tour = tour % morceaux.len();
        morceaux.rotate_left(tour);
        }
        let s = juger_simple(numeros.iter().copied(), &morceaux, entre);
        prop_assert_eq!(deplies(&s), modele(&numeros, &morceaux, entre));
        // Chaque trou est encadré par ses voisins présents, s'il en a.
        for t in &s.trous {
            prop_assert!(!numeros.contains(&t.de) && !numeros.contains(&t.a));
        }
    }
}
