//! Les trous de la suite des numéros : cas écrits à la main, puis proptest contre un modèle naïf (numéro par numéro),
//! et l'absence de faux trou quand rien n'a été retiré, quel que soit l'ordre des morceaux dans le fichier.

use proptest::prelude::*;

use super::*;
use crate::journaux_windows::evtx::CAPACITE_MORCEAU;

fn lu(rang: u64, annonce: Option<(u64, u64)>, non_rendus: u64) -> RecapMorceau {
    RecapMorceau {
        rang,
        etat: EtatMorceau::Lu,
        annonce,
        non_rendus,
        incoherent: false,
        capacite: CAPACITE_MORCEAU,
    }
}

fn ecarte(rang: u64, annonce: Option<(u64, u64)>) -> RecapMorceau {
    RecapMorceau {
        etat: EtatMorceau::Ecarte,
        ..lu(rang, annonce, 0)
    }
}

/// Des présents, chacun dans le morceau que donne `morceau(numéro)`.
fn presents_dans(numeros: impl IntoIterator<Item = u64>, morceau: impl Fn(u64) -> Option<u64>) -> Vec<Present> {
    numeros
        .into_iter()
        .map(|numero| Present {
            numero,
            date: DateTime::from_timestamp(i64::try_from(numero % (1 << 40)).unwrap_or(0) * 60, 0),
            morceau: morceau(numero),
            verifie: true,
        })
        .collect()
}

fn non_verifie(rang: u64, annonce: Option<(u64, u64)>, non_rendus: u64) -> RecapMorceau {
    RecapMorceau {
        etat: EtatMorceau::NonVerifie,
        ..lu(rang, annonce, non_rendus)
    }
}

/// Des présents d'un morceau non vérifié.
fn non_verifies(numeros: impl IntoIterator<Item = u64>, rang: u64) -> Vec<Present> {
    presents_dans(numeros, |_| Some(rang))
        .into_iter()
        .map(|p| Present { verifie: false, ..p })
        .collect()
}

fn plages(s: &Suite) -> Vec<(u64, u64, Nature)> {
    s.trous.iter().map(|t| (t.de, t.a, t.nature)).collect()
}

/// Les morceaux de 10 numéros : 1 à 10 au rang 0, 11 à 20 au rang 1…
#[allow(clippy::unnecessary_wraps)] // passé là où un morceau peut manquer
fn par_dix(n: u64) -> Option<u64> {
    Some((n - 1) / 10)
}

fn juger_avec(presents: Vec<Present>, contexte: &Contexte) -> Suite {
    juger(Numerotation::Journal, presents, contexte, 1000)
}

fn contexte<'a>(morceaux: &'a [RecapMorceau], entre: Nature, pertes: &'a [u64]) -> Contexte<'a> {
    Contexte {
        morceaux,
        entre_morceaux: entre,
        pertes,
        prochain: None,
        prochain_peut_retarder: false,
        capacite: 0,
    }
}

#[test]
fn une_suite_entiere_n_a_pas_de_trou_meme_tournante_ou_effacee() {
    // Le journal tournant (les plus anciens écrasés) commence à 500 ; un journal effacé continue sa suite (le 1102
    // au numéro 227126) : ni l'un ni l'autre n'est un trou.
    for debut in [1u64, 500, 227_126] {
        let s = juger_avec(
            presents_dans(debut..debut + 300, |_| None),
            &Contexte::nu(Nature::Absents),
        );
        assert_eq!(
            (s.premier, s.dernier, s.presents),
            (Some(debut), Some(debut + 299), 300)
        );
        assert_eq!(s.trous, []);
    }
    let vide = juger_avec(Vec::new(), &Contexte::nu(Nature::Absents));
    assert_eq!(
        (vide.premier, vide.dernier, vide.presents, vide.trous.len()),
        (None, None, 0, 0)
    );
}

#[test]
fn un_trou_dans_un_morceau_lu_est_un_retrait() {
    let morceaux = [lu(0, Some((1, 10)), 0), lu(1, Some((11, 20)), 0)];
    let numeros = (1..=20).filter(|n| !(4..=6).contains(n) && *n != 20);
    let s = juger_avec(
        presents_dans(numeros, par_dix),
        &contexte(&morceaux, Nature::Absents, &[]),
    );
    // 4 à 6 au milieu du premier morceau ; 20, le dernier annoncé, ôté avec la place libre reculée.
    assert_eq!(plages(&s), [(4, 6, Nature::Retires), (20, 20, Nature::Retires)]);
    assert_eq!(s.trous[0].avant, DateTime::from_timestamp(3 * 60, 0));
    assert_eq!(s.trous[0].apres, DateTime::from_timestamp(7 * 60, 0));
    assert_eq!(s.trous[1].apres, None);
    assert_eq!(s.trous[0].nombre(), 3);
    // L'annonce effacée ou rétrécie n'y change rien : entre deux enregistrements d'un même morceau lu, c'est un
    // retrait (et l'en-tête est compté incohérent).
    let mut sans = [lu(0, None, 0), lu(1, Some((11, 20)), 0)];
    sans[0].incoherent = true;
    let numeros = (1..=20).filter(|n| !(4..=6).contains(n));
    let s = juger_avec(
        presents_dans(numeros, par_dix),
        &contexte(&sans, Nature::CopieAChaud, &[1000]),
    );
    assert_eq!(plages(&s), [(4, 6, Nature::Retires)]);
    assert_eq!(s.incoherences, 1);
    // Un morceau écarté qui annoncerait les mêmes numéros non plus : un numéro n'a qu'un morceau.
    let leurre = [
        lu(0, Some((1, 10)), 0),
        lu(1, Some((11, 20)), 0),
        ecarte(2, Some((4, 6))),
    ];
    let numeros = (1..=20).filter(|n| !(4..=6).contains(n));
    let s = juger_avec(
        presents_dans(numeros, par_dix),
        &contexte(&leurre, Nature::Absents, &[]),
    );
    assert_eq!(plages(&s), [(4, 6, Nature::Retires)]);
}

#[test]
fn les_non_rendus_d_un_morceau_ne_couvrent_que_leur_nombre() {
    // Deux enregistrements non rendus : un trou de deux numéros est peut-être eux ; un trou de trois, non.
    let deux = [lu(0, Some((1, 10)), 2)];
    let s = juger_avec(
        presents_dans((1..=10).filter(|n| !(5..=6).contains(n)), par_dix),
        &contexte(&deux, Nature::Absents, &[]),
    );
    assert_eq!(plages(&s), [(5, 6, Nature::Illisible)]);
    let s = juger_avec(
        presents_dans((1..=10).filter(|n| !(4..=6).contains(n)), par_dix),
        &contexte(&deux, Nature::Absents, &[]),
    );
    assert_eq!(plages(&s), [(4, 6, Nature::Retires)]);
}

#[test]
fn entre_deux_morceaux_les_pertes_ne_couvrent_que_ce_qu_elles_peuvent_porter() {
    let morceaux = [lu(0, Some((1, 10)), 0), lu(2, Some((21, 30)), 0)];
    let numeros = || presents_dans((1..=10).chain(21..=30), par_dix);
    for entre in [Nature::Absents, Nature::CopieAChaud] {
        assert_eq!(
            plages(&juger_avec(numeros(), &contexte(&morceaux, entre, &[]))),
            [(11, 20, entre)]
        );
    }
    // Un morceau écarté sans plage connue, capable de 10 numéros : il peut être eux.
    assert_eq!(
        plages(&juger_avec(numeros(), &contexte(&morceaux, Nature::Absents, &[10]))),
        [(11, 20, Nature::Illisible)]
    );
    // Capable de 9, ou de rien (un octet en fin de fichier) : non.
    for perte in [9, 0] {
        assert_eq!(
            plages(&juger_avec(numeros(), &contexte(&morceaux, Nature::Absents, &[perte]))),
            [(11, 20, Nature::Absents)]
        );
    }
    // Deux pertes ensemble couvrent un même trou ; une seule ne couvre pas deux trous.
    assert_eq!(
        plages(&juger_avec(numeros(), &contexte(&morceaux, Nature::Absents, &[5, 5]))),
        [(11, 20, Nature::Illisible)]
    );
    let trois = [
        lu(0, Some((1, 10)), 0),
        lu(2, Some((21, 30)), 0),
        lu(4, Some((41, 50)), 0),
    ];
    let s = juger_avec(
        presents_dans((1..=10).chain(21..=30).chain(41..=50), par_dix),
        &contexte(&trois, Nature::Absents, &[10]),
    );
    assert_eq!(
        plages(&s).iter().filter(|t| t.2 == Nature::Illisible).count(),
        1,
        "{s:?}"
    );
    // Un morceau écarté à la plage connue : exactement elle.
    let avec = [
        lu(0, Some((1, 10)), 0),
        ecarte(1, Some((11, 15))),
        lu(2, Some((21, 30)), 0),
    ];
    assert_eq!(
        plages(&juger_avec(numeros(), &contexte(&avec, Nature::Absents, &[]))),
        [(11, 15, Nature::Illisible), (16, 20, Nature::Absents)]
    );
}

#[test]
fn l_en_tete_du_fichier_attend_les_derniers() {
    let morceaux = [lu(0, Some((1, 10)), 0), lu(1, Some((11, 20)), 0)];
    let mut c = contexte(&morceaux, Nature::Absents, &[]);
    c.prochain = Some(31);
    let s = juger_avec(presents_dans(1..=20, par_dix), &c);
    assert_eq!(plages(&s), [(21, 30, Nature::Absents)]);
    assert_eq!(s.dernier, Some(30));
    // Un prochain numéro en retard sur les présents : l'en-tête ne se tient pas.
    c.prochain = Some(5);
    let s = juger_avec(presents_dans(1..=20, par_dix), &c);
    assert_eq!((plages(&s), s.incoherences), (vec![], 1));
    // Tout remis à zéro : rien de présent, l'en-tête attend jusqu'à 60 dans un fichier de deux morceaux.
    let rien = Contexte {
        prochain: Some(61),
        capacite: 2 * CAPACITE_MORCEAU,
        ..Contexte::nu(Nature::Absents)
    };
    let s = juger_avec(Vec::new(), &rien);
    assert_eq!(plages(&s), [(1, 60, Nature::Absents)]);
    // Un journal neuf (prochain : 1) n'attend rien.
    let neuf = Contexte {
        prochain: Some(1),
        ..rien
    };
    assert_eq!(juger_avec(Vec::new(), &neuf).trous, []);
}

#[test]
fn doublons_extremes_et_borne() {
    let s = juger_avec(
        presents_dans([5, 5, 6, 6, 6, 7], |_| None),
        &Contexte::nu(Nature::Absents),
    );
    assert_eq!((s.presents, s.doublons, s.trous.len()), (3, 3, 0));
    // Les numéros aux bords de u64 : aucun débordement, le trou entre eux est dit.
    let s = juger_avec(presents_dans([0, u64::MAX], |_| None), &Contexte::nu(Nature::Absents));
    assert_eq!(plages(&s), [(1, u64::MAX - 1, Nature::Absents)]);
    assert_eq!(s.trous[0].nombre(), u64::MAX - 1);
    let haut = [lu(0, Some((u64::MAX - 2, u64::MAX)), 0)];
    let s = juger_avec(
        presents_dans([u64::MAX], |_| Some(0)),
        &contexte(&haut, Nature::Absents, &[]),
    );
    assert_eq!(plages(&s), [(u64::MAX - 2, u64::MAX - 1, Nature::Retires)]);
    // La borne des trous : les suivants comptés.
    let s = juger(
        Numerotation::Journal,
        presents_dans((0..100).map(|n| n * 2), |_| None),
        &Contexte::nu(Nature::Absents),
        10,
    );
    assert_eq!((s.trous.len(), s.trous_au_dela), (10, 89));
}

// ---- proptest ----

/// Un fichier imaginé : ses morceaux (dans l'ordre du fichier), ses présents, ses pertes.
#[derive(Debug, Clone)]
struct Cas {
    morceaux: Vec<RecapMorceau>,
    presents: Vec<Present>,
    pertes: Vec<u64>,
    prochain: Option<u64>,
}

/// Le modèle naïf, numéro par numéro : la définition du module.
fn modele(cas: &Cas, entre: Nature) -> (Vec<(u64, Nature)>, u64) {
    let verifies: Vec<Present> = cas.presents.iter().copied().filter(|p| p.verifie).collect();
    // L'étendue de chaque morceau lu : son annonce et ses enregistrements.
    let etendue = |i: usize| -> Option<(u64, u64)> {
        let m = &cas.morceaux[i];
        if m.etat != EtatMorceau::Lu {
            return None;
        }
        let siens = verifies.iter().filter(|p| p.morceau == Some(m.rang)).map(|p| p.numero);
        let bornes = m.annonce.into_iter().flat_map(|(a, b)| [a, b]).chain(siens);
        let (lo, hi) = bornes.fold((None, None), |(lo, hi): (Option<u64>, Option<u64>), n| {
            (Some(lo.map_or(n, |l| l.min(n))), Some(hi.map_or(n, |h| h.max(n))))
        });
        Some((lo?, hi?))
    };
    // Le premier indice de chaque rang lu (comme `etendues`, un rang en double ne compte qu'une fois).
    let premiers: Vec<usize> = (0..cas.morceaux.len())
        .filter(|&i| {
            cas.morceaux[i].etat == EtatMorceau::Lu
                && !cas.morceaux[..i]
                    .iter()
                    .any(|m| m.etat == EtatMorceau::Lu && m.rang == cas.morceaux[i].rang)
        })
        .collect();
    let etendues: Vec<(usize, (u64, u64))> = premiers.iter().filter_map(|&i| Some((i, etendue(i)?))).collect();
    // Ce que couvre chaque morceau non vérifié : son annonce et ses enregistrements relus (tous, même ceux qu'un
    // morceau lu réclame).
    let zones_nv: Vec<(u64, u64)> = cas
        .morceaux
        .iter()
        .filter(|m| m.etat == EtatMorceau::NonVerifie)
        .filter_map(|m| {
            let siens = cas
                .presents
                .iter()
                .filter(|p| !p.verifie && p.morceau == Some(m.rang))
                .map(|p| p.numero);
            let bornes = m.annonce.into_iter().flat_map(|(a, b)| [a, b]).chain(siens);
            let lo = bornes.clone().min()?;
            Some((lo, bornes.max()?))
        })
        .collect();
    let dans_un_lu = |n: u64| etendues.iter().any(|(_, (a, b))| *a <= n && n <= *b);
    let numeros: BTreeSet<u64> = cas
        .presents
        .iter()
        .filter(|p| p.verifie || !dans_un_lu(p.numero))
        .map(|p| p.numero)
        .collect();
    let numeros_verifies: BTreeSet<u64> = verifies.iter().map(|p| p.numero).collect();
    let nombre_nv = numeros.iter().filter(|n| !numeros_verifies.contains(n)).count() as u64;
    let mut lo = numeros
        .iter()
        .next()
        .copied()
        .into_iter()
        .chain(etendues.iter().map(|e| e.1.0))
        .min();
    let mut hi = numeros
        .iter()
        .next_back()
        .copied()
        .into_iter()
        .chain(etendues.iter().map(|e| e.1.1))
        .max();
    if let Some(attendu) = cas.prochain.and_then(|p| p.checked_sub(1)) {
        match hi {
            Some(h) if attendu < h => {}
            Some(_) => hi = Some(attendu),
            // Rien de connu : seul le dernier attendu (la capacité du fichier est nulle ici).
            None if attendu >= 1 => {
                lo = Some(attendu);
                hi = Some(attendu);
            }
            None => {}
        }
    }
    let (Some(lo), Some(hi)) = (lo.take(), hi) else {
        return (Vec::new(), nombre_nv);
    };
    let classe = |n: u64| -> Classe {
        let proprietaire = etendues
            .iter()
            .filter(|(_, (a, b))| *a <= n && n <= *b)
            .min_by_key(|(i, (a, _))| (*a, cas.morceaux[*i].rang, *i));
        if let Some((i, _)) = proprietaire {
            return Classe::Morceau(*i);
        }
        let ecarte = cas
            .morceaux
            .iter()
            .any(|m| m.etat == EtatMorceau::Ecarte && m.annonce.is_some_and(|(a, b)| a <= n && n <= b))
            || zones_nv.iter().any(|(a, b)| *a <= n && n <= *b);
        if ecarte { Classe::Ecarte } else { Classe::Libre }
    };
    let manquants: Vec<(u64, Classe)> = (lo..=hi)
        .filter(|n| !numeros.contains(n))
        .map(|n| (n, classe(n)))
        .collect();
    let mut par_morceau: HashMap<usize, u64> = HashMap::new();
    for (_, c) in &manquants {
        if let Classe::Morceau(i) = c {
            *par_morceau.entry(*i).or_default() += 1;
        }
    }
    // Les plages libres : les suites de numéros manquants libres qui se touchent.
    let mut libres: Vec<(u64, u64)> = Vec::new();
    for (n, c) in &manquants {
        if *c == Classe::Libre {
            match libres.last_mut() {
                Some(l) if l.1 + 1 == *n => l.1 = *n,
                _ => libres.push((*n, *n)),
            }
        }
    }
    let tailles: Vec<u64> = libres.iter().map(|(a, b)| b - a + 1).collect();
    let couvert = couvertes(&tailles, &cas.pertes);
    let sortie = manquants
        .iter()
        .map(|&(n, c)| {
            let nature = match c {
                Classe::Morceau(i) if par_morceau[&i] <= cas.morceaux[i].non_rendus => Nature::Illisible,
                Classe::Morceau(_) => Nature::Retires,
                Classe::Ecarte => Nature::Illisible,
                Classe::Libre => {
                    let k = libres.iter().position(|(a, b)| *a <= n && n <= *b).unwrap();
                    if couvert[k] { Nature::Illisible } else { entre }
                }
            };
            (n, nature)
        })
        .collect::<Vec<_>>();
    (sortie, nombre_nv)
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
    prop::sample::select(vec![Nature::Absents, Nature::CopieAChaud, Nature::AvantExport])
}

/// Un journal : des morceaux de numéros qui se suivent depuis `debut` ; chacun lu (annonce juste, effacée ou
/// rétrécie, quelques enregistrements non rendus), écarté (plage connue ou non), disparu, ou un leurre écarté qui
/// annonce une plage au hasard ; des numéros ôtés ; l'ordre du fichier tourné ; des pertes et un prochain numéro.
fn cas() -> impl Strategy<Value = Cas> {
    (
        prop_oneof![Just(1u64), 1u64..1_000_000, Just(u64::MAX - 5000)],
        prop::collection::vec((1u64..30, 0u8..11, 0u64..4), 1..10),
        prop::collection::vec(0u64..300, 0..25),
        any::<prop::sample::Index>(),
        prop::collection::vec(0u64..40, 0..3),
        prop::option::of(0u64..400),
    )
        .prop_map(|(debut, tailles, otes, tour, pertes, prochain)| {
            let mut morceaux = Vec::new();
            let mut presents = Vec::new();
            let mut n = debut;
            for (rang, (taille, sorte, k)) in tailles.iter().enumerate() {
                let rang = rang as u64;
                let plage = (n, n + taille - 1);
                let siens = (n..n + taille).filter(|x| !otes.contains(&(x - debut)));
                match sorte {
                    0..=2 => morceaux.push(lu(rang, Some(plage), 0)),
                    3 => morceaux.push(lu(rang, Some(plage), *k)),
                    4 => morceaux.push(lu(rang, None, 0)),
                    5 => morceaux.push(lu(rang, Some((plage.0, plage.0 + taille / 2)), 0)),
                    6 => morceaux.push(ecarte(rang, (*k > 1).then_some(plage))),
                    7 => {
                        morceaux.push(lu(rang, Some(plage), 0));
                        morceaux.push(ecarte(100 + rang, Some((plage.0 + k, plage.0 + k + 3))));
                    }
                    // Non vérifié (CRC faux), relu : ses enregistrements non vérifiés, son annonce crue ou non.
                    8 => {
                        morceaux.push(non_verifie(rang, (*k > 1).then_some(plage), *k));
                        presents.extend(non_verifies(siens.clone(), rang));
                    }
                    // Un leurre non vérifié qui porte des numéros d'un morceau lu (ôtés ou non).
                    9 => {
                        morceaux.push(lu(rang, Some(plage), 0));
                        morceaux.push(non_verifie(200 + rang, None, 0));
                        presents.extend(non_verifies(plage.0..=plage.0 + k, 200 + rang));
                    }
                    _ => {}
                }
                if matches!(sorte, 0..=5 | 7 | 9) {
                    presents.extend(presents_dans(siens, |_| Some(rang)));
                }
                n += taille;
            }
            let i = tour.index(morceaux.len().max(1));
            let i = i.min(morceaux.len());
            morceaux.rotate_left(i);
            Cas {
                morceaux,
                presents,
                pertes,
                prochain: prochain.map(|p| debut + p),
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 768, failure_persistence: None, ..ProptestConfig::default() })]

    /// Rien retiré, tous les morceaux lus et justes : aucun trou, quel que soit l'ordre des morceaux dans le
    /// fichier, et un prochain numéro juste n'en ajoute pas.
    #[test]
    fn aucun_faux_trou(debut in prop_oneof![Just(1u64), 1u64..1_000_000], tailles in prop::collection::vec(1u64..40, 1..12), tour in any::<prop::sample::Index>(), entre in nature()) {
        let mut morceaux = Vec::new();
        let mut presents = Vec::new();
        let mut n = debut;
        for (rang, taille) in tailles.iter().enumerate() {
            morceaux.push(lu(rang as u64, Some((n, n + taille - 1)), 0));
            presents.extend(presents_dans(n..n + taille, |_| Some(rang as u64)));
            n += taille;
        }
        let i = tour.index(morceaux.len());
        morceaux.rotate_left(i);
        presents.reverse();
        let c = Contexte { prochain: Some(n), ..contexte(&morceaux, entre, &[]) };
        let s = juger_avec(presents, &c);
        prop_assert_eq!(&s.trous, &Vec::<Trou>::new());
        prop_assert_eq!(s.incoherences, 0);
    }

    /// Des numéros ôtés, des morceaux écartés, disparus, réécrits, des leurres : les trous rendus sont exactement
    /// ceux du modèle naïf, numéro par numéro, avec la même nature.
    #[test]
    fn comme_le_modele(cas in cas(), entre in nature()) {
        let c = Contexte {
            morceaux: &cas.morceaux,
            entre_morceaux: entre,
            pertes: &cas.pertes,
            prochain: cas.prochain,
            prochain_peut_retarder: false,
            capacite: 0,
        };
        let s = juger_avec(cas.presents.clone(), &c);
        let (attendus, nv) = modele(&cas, entre);
        prop_assert_eq!(deplies(&s), attendus);
        prop_assert_eq!(s.non_verifies, nv);
        // Un trou ne tombe jamais sur un numéro vérifié présent.
        let numeros: BTreeSet<u64> = cas.presents.iter().filter(|p| p.verifie).map(|p| p.numero).collect();
        for t in &s.trous {
            prop_assert!(!numeros.contains(&t.de) && !numeros.contains(&t.a));
        }
    }
}
