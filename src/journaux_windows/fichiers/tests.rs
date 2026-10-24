//! La source « fichiers » : des journaux fabriqués octet par octet (les fabriques du lecteur, evtx::tests), écrits
//! dans un dossier jetable, puis abîmés comme le serait un journal effacé en partie, copié à chaud ou exporté.

use std::path::PathBuf;

use chrono::DateTime;

use super::*;
use crate::journaux_windows::evtx::recalculer_crc;
use crate::journaux_windows::evtx::tests::{fichier, morceau_aux_numeros};
use crate::journaux_windows::trous::CLE_MAX;

fn jetable(nom: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vanguard-journaux-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Un morceau aux numéros `de..=a` sauf `sauf`, EventRecordID égal au numéro (un journal copié tel quel).
fn morceau(de: u64, a: u64, sauf: &[u64]) -> Vec<u8> {
    let numeros: Vec<u64> = (de..=a).filter(|n| !sauf.contains(n)).collect();
    morceau_aux_numeros(&numeros, |n| n)
}

/// Le fichier lu, tous ses événements donnés.
fn lire(octets: &[u8], nom: &str) -> (BilanFichier, Vec<EvenementWindows>) {
    let d = jetable(nom);
    let chemin = d.join("Security.evtx");
    std::fs::write(&chemin, octets).unwrap();
    let mut vus = Vec::new();
    let b = lire_fichier(&chemin, &Filtre::default(), &BornesFichiers::default(), |e| vus.push(e));
    let _ = std::fs::remove_dir_all(&d);
    (b, vus)
}

fn trous_du_journal(b: &BilanFichier) -> Vec<(u64, u64, Nature)> {
    assert_eq!(b.suites[0].numerotation, Numerotation::Journal);
    b.suites[0].trous.iter().map(|t| (t.de, t.a, t.nature)).collect()
}

/// Le fichier marqué « sale » (fermé pendant une écriture, ou copié ouvert), CRC recalculés.
fn sale(mut f: Vec<u8>) -> Vec<u8> {
    f[120] |= 1;
    recalculer_crc(&mut f);
    f
}

#[test]
fn un_journal_entier_se_lit_dans_la_forme_commune_sans_trou() {
    // Tournant : le morceau le plus récent rangé avant les plus anciens, la suite commençant à 500.
    let f = fichier(&[morceau(560, 590, &[]), morceau(500, 529, &[]), morceau(530, 559, &[])]);
    let (b, vus) = lire(&f, "entier");
    assert!(b.complet(), "{b:?}");
    assert_eq!((b.donnes, b.filtres, b.sans_identifiant), (91, 0, 0));
    assert_eq!(b.journaux, ["Security"]);
    assert!(!b.exporte);
    assert_eq!(b.suites.len(), 1);
    let s = &b.suites[0];
    assert_eq!(
        (s.premier, s.dernier, s.presents, s.doublons),
        (Some(500), Some(590), 91, 0)
    );
    assert!(s.trous.is_empty(), "{s:?}");
    let e = vus.iter().find(|e| e.numero == Some(500)).unwrap();
    assert_eq!((e.journal.as_str(), e.id, e.niveau), ("Security", 4625, Some(0)));
    assert_eq!(e.fournisseur, "Microsoft-Windows-Security-Auditing");
    assert_eq!(e.ordinateur, "poste-alice");
    assert_eq!(e.utilisateur.as_deref(), Some("S-1-5-18"));
    assert_eq!(e.champ("TargetUserName"), Some("alice"));
    assert!(e.date.is_some());
    assert!(
        matches!(&e.origine, Origine::Fichier { numero_fichier: 500, chemin } if chemin.ends_with("Security.evtx"))
    );
}

#[test]
fn des_enregistrements_retires_d_un_morceau_sont_un_retrait() {
    // 14 à 16 ôtés du premier morceau, CRC recalculés (comme un outil qui réécrit le journal) ; l'en-tête du
    // morceau annonce toujours 1 à 30, et le lecteur les compte absents.
    let f = fichier(&[morceau(1, 30, &[14, 15, 16]), morceau(31, 60, &[])]);
    let (b, _) = lire(&f, "retires");
    assert_eq!(b.lecture.as_ref().unwrap().enregistrements_absents, 3);
    assert_eq!(trous_du_journal(&b), [(14, 16, Nature::Retires)]);
    let t = &b.suites[0].trous[0];
    assert!(t.avant.is_some() && t.apres.is_some() && t.avant < t.apres, "{t:?}");
    // Les derniers d'un morceau ôtés (place libre reculée) : le morceau les annonce encore.
    let mut m = morceau(1, 30, &[]);
    // Le dernier numéro annoncé passé à 33 : trois enregistrements de plus que ceux qui restent.
    m[16..24].copy_from_slice(&33u64.to_le_bytes());
    m[32..40].copy_from_slice(&33u64.to_le_bytes());
    let (b, _) = lire(&fichier(&[m]), "fin-otee");
    assert_eq!(trous_du_journal(&b), [(31, 33, Nature::Retires)]);
}

#[test]
fn un_morceau_disparu_se_dit_selon_l_etat_du_fichier() {
    // Le morceau 31 à 60 remis à zéro au milieu d'un fichier fermé proprement : des enregistrements manquent.
    let propre = fichier(&[morceau(1, 30, &[]), vec![0; 65_536], morceau(61, 90, &[])]);
    let (b, _) = lire(&propre, "propre");
    assert!(b.complet(), "{b:?}");
    assert_eq!(trous_du_journal(&b), [(31, 60, Nature::Absents)]);
    // Le même, fichier sale : copié pendant que Windows l'écrivait, pas une preuve.
    let (b, _) = lire(&sale(propre), "sale");
    assert!(b.lecture.as_ref().unwrap().sale);
    assert_eq!(trous_du_journal(&b), [(31, 60, Nature::CopieAChaud)]);
}

#[test]
fn un_morceau_ecarte_n_est_pas_un_effacement() {
    // Un octet de ses enregistrements changé, son en-tête (qui porte leur CRC) juste : sa plage annoncée (31 à
    // 60) est illisible.
    let mut f = fichier(&[morceau(1, 30, &[]), morceau(31, 60, &[]), morceau(61, 90, &[])]);
    f[4096 + 65_536 + 600] ^= 0xFF;
    let (b, _) = lire(&f, "ecarte");
    assert!(!b.complet());
    assert_eq!(b.lecture.as_ref().unwrap().morceaux_illisibles, 1);
    assert_eq!(trous_du_journal(&b), [(31, 60, Nature::Illisible)]);
    // En-tête du morceau faux : la place de ses numéros n'est pas connue, et tout trou entre morceaux du fichier
    // est illisible ; un retrait dans un morceau intact reste un retrait.
    let mut f = fichier(&[morceau(1, 30, &[5]), morceau(31, 60, &[]), morceau(61, 90, &[])]);
    f[4096 + 65_536 + 124] ^= 0xFF;
    let (b, _) = lire(&f, "en-tete-faux");
    assert_eq!(
        trous_du_journal(&b),
        [(5, 5, Nature::Retires), (31, 60, Nature::Illisible)]
    );
}

#[test]
fn un_fichier_exporte_garde_ses_eventrecordid_d_origine() {
    // Renuméroté depuis 1 (wevtutil epl), les EventRecordID d'origine 1001 à 1010 sans 1004 à 1006.
    let origine = |n: u64| if n <= 3 { 1000 + n } else { 1003 + n };
    let f = fichier(&[morceau_aux_numeros(&(1..=7).collect::<Vec<_>>(), origine)]);
    let (b, vus) = lire(&f, "exporte");
    assert!(b.exporte);
    assert_eq!(trous_du_journal(&b), []);
    assert_eq!(b.suites.len(), 2);
    let s = &b.suites[1];
    assert_eq!(
        s.numerotation,
        Numerotation::Origine {
            ordinateur: "poste-alice".into(),
            journal: "Security".into()
        }
    );
    assert_eq!(
        s.trous.iter().map(|t| (t.de, t.a, t.nature)).collect::<Vec<_>>(),
        [(1004, 1006, Nature::AvantExport)]
    );
    // La forme commune porte l'EventRecordID, l'origine le numéro dans le fichier.
    let e = &vus[3];
    assert_eq!(e.numero, Some(1007));
    assert!(matches!(e.origine, Origine::Fichier { numero_fichier: 4, .. }));
}

#[test]
fn le_filtre_ne_change_pas_la_suite() {
    let d = jetable("filtre");
    let chemin = d.join("Security.evtx");
    std::fs::write(&chemin, fichier(&[morceau(1, 30, &[10])])).unwrap();
    let lire_avec = |filtre: &Filtre| {
        let mut n = 0;
        let b = lire_fichier(&chemin, filtre, &BornesFichiers::default(), |_| n += 1);
        (b, n)
    };
    // Un autre numéro d'événement : rien donné, la suite jugée quand même sur tous les enregistrements.
    let (b, n) = lire_avec(&Filtre {
        ids: vec![4624],
        ..Filtre::default()
    });
    assert_eq!((n, b.donnes, b.filtres), (0, 0, 29));
    assert_eq!(trous_du_journal(&b), [(10, 10, Nature::Retires)]);
    // Une fenêtre de dates : la date de chacun est DATE + son numéro (en centaines de nanosecondes).
    let date = |n: u64| {
        let ft = 134_373_207_091_234_567u64 + n;
        let secondes = i64::try_from(ft / 10_000_000).unwrap() - 11_644_473_600;
        DateTime::from_timestamp(secondes, u32::try_from(ft % 10_000_000).unwrap() * 100).unwrap()
    };
    let (b, n) = lire_avec(&Filtre {
        depuis: Some(date(20)),
        ..Filtre::default()
    });
    assert_eq!((n, b.donnes, b.filtres), (11, 11, 18));
    // Un autre journal : rien donné, la suite jugée quand même (un journal renommé dans les enregistrements ne la
    // fait pas taire).
    let (b, n) = lire_avec(&Filtre {
        journaux: vec!["system".into()],
        ..Filtre::default()
    });
    assert_eq!((n, b.filtres), (0, 29));
    assert_eq!(trous_du_journal(&b), [(10, 10, Nature::Retires)]);
    // Le journal voulu, sans égard à la casse.
    let (_, n) = lire_avec(&Filtre {
        journaux: vec!["SECURITY".into()],
        ..Filtre::default()
    });
    assert_eq!(n, 29);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn un_dossier_se_lit_fichier_par_fichier_et_dit_ce_qu_il_n_a_pas_lu() {
    let d = jetable("dossier");
    std::fs::write(d.join("a-Security.evtx"), fichier(&[morceau(1, 10, &[])])).unwrap();
    std::fs::write(d.join("SECURITY.evtx"), fichier(&[morceau(1, 3, &[])])).unwrap();
    std::fs::write(d.join("b.EVTX"), fichier(&[morceau(1, 5, &[])])).unwrap();
    std::fs::write(d.join("c.evtx"), b"pas un journal").unwrap();
    std::fs::write(d.join("notes.txt"), b"ignore").unwrap();
    std::fs::create_dir(d.join("dossier.evtx")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(d.join("a-Security.evtx"), d.join("d-lien.evtx")).unwrap();
    let mut n = 0;
    let b = lire_dossier(&d, &Filtre::default(), &BornesFichiers::default(), |_| n += 1).unwrap();
    assert_eq!(n, 18);
    assert_eq!(b.autres, 1);
    let noms: Vec<String> = b
        .fichiers
        .iter()
        .map(|f| f.chemin.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    // Le journal de sécurité d'abord, quel que soit son nom en majuscules ou minuscules ; les autres du plus petit
    // au plus grand.
    assert_eq!(noms[0], "SECURITY.evtx");
    let mut tries = noms.clone();
    tries.sort();
    #[cfg(unix)]
    assert_eq!(
        tries,
        [
            "SECURITY.evtx",
            "a-Security.evtx",
            "b.EVTX",
            "c.evtx",
            "d-lien.evtx",
            "dossier.evtx"
        ]
    );
    let lecture = |nom: &str| &b.fichiers[noms.iter().position(|x| x == nom).unwrap()].lecture;
    assert!(lecture("a-Security.evtx").is_ok());
    assert_eq!(*lecture("c.evtx"), Err(ErreurFichier::PasUnEvtx));
    assert_eq!(*lecture("dossier.evtx"), Err(ErreurFichier::PasUnFichier));
    #[cfg(unix)]
    assert_eq!(*lecture("d-lien.evtx"), Err(ErreurFichier::PasUnFichier));
    assert!(!b.complet());
    // Les bornes : un fichier au plus, puis des octets au plus.
    let un = BornesFichiers {
        fichiers: 1,
        ..BornesFichiers::default()
    };
    let b = lire_dossier(&d, &Filtre::default(), &un, |_| {}).unwrap();
    assert_eq!((b.fichiers.len(), b.hors_borne), (1, noms.len() as u64 - 1));
    assert!(b.fichiers[0].chemin.ends_with("SECURITY.evtx"));
    let peu = BornesFichiers {
        octets: 10,
        ..BornesFichiers::default()
    };
    let b = lire_dossier(&d, &Filtre::default(), &peu, |_| {}).unwrap();
    assert!(b.hors_borne >= 2 && !b.complet(), "{b:?}");
    // Un dossier absent : une erreur, pas un bilan vide.
    assert!(
        lire_dossier(
            &d.join("absent"),
            &Filtre::default(),
            &BornesFichiers::default(),
            |_| {}
        )
        .is_err()
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// Un tube nommé « .evtx » n'est jamais ouvert : l'ouvrir pour lire bloquerait jusqu'à ce qu'un autre y écrive.
#[cfg(unix)]
#[test]
fn un_tube_n_est_pas_ouvert() {
    let d = jetable("tube");
    let tube = d.join("Security.evtx");
    let fait = std::process::Command::new("mkfifo").arg(&tube).status();
    if !fait.is_ok_and(|s| s.success()) {
        let _ = std::fs::remove_dir_all(&d);
        return crate::essais::saute("mkfifo absent : pas de tube à essayer");
    }
    let b = lire_fichier(&tube, &Filtre::default(), &BornesFichiers::default(), |_| {});
    assert_eq!(b.lecture, Err(ErreurFichier::PasUnFichier));
    let _ = std::fs::remove_dir_all(&d);
}

// ---- Ce que les relectures adverses ont essayé ----

/// Le fichier, son en-tête réécrit : dernier morceau, prochain numéro, nombre de morceaux, CRC recalculés.
fn avec_en_tete(mut f: Vec<u8>, dernier_morceau: u64, prochain: u64, nombre: u16) -> Vec<u8> {
    f[16..24].copy_from_slice(&dernier_morceau.to_le_bytes());
    f[24..32].copy_from_slice(&prochain.to_le_bytes());
    f[42..44].copy_from_slice(&nombre.to_le_bytes());
    recalculer_crc(&mut f);
    f
}

/// Les derniers enregistrements ôtés (le cas le plus courant : l'attaquant efface sa propre activité) : l'en-tête
/// du fichier, couvert par son CRC, attend encore leurs numéros.
#[test]
fn les_derniers_otes_se_voient_a_l_en_tete_du_fichier() {
    // Le morceau le plus récent remis à zéro.
    let f = avec_en_tete(fichier(&[morceau(1, 30, &[]), vec![0; 65_536]]), 1, 61, 2);
    assert_eq!(trous_du_journal(&lire(&f, "recent").0), [(31, 60, Nature::Absents)]);
    // Les derniers d'un morceau ôtés, son en-tête recalculé pour ne plus les annoncer.
    let f = avec_en_tete(fichier(&[morceau(1, 30, &[]), morceau(31, 57, &[])]), 1, 61, 2);
    assert_eq!(trous_du_journal(&lire(&f, "fin").0), [(58, 60, Nature::Absents)]);
    // Tout remis à zéro, sans 1102 : rien de présent, tout ce que le fichier pouvait porter manque (depuis 1 ici).
    let f = avec_en_tete(fichier(&[vec![0; 65_536], vec![0; 65_536]]), 1, 61, 2);
    let (b, vus) = lire(&f, "tout");
    assert_eq!(vus.len(), 0);
    assert_eq!(trous_du_journal(&b), [(1, 60, Nature::Absents)]);
    // Le même fichier sale (l'en-tête d'un fichier sale retarde) : le prochain numéro n'est pas cru.
    let mut g = fichier(&[morceau(1, 30, &[]), morceau(31, 57, &[])]);
    g[24..32].copy_from_slice(&61u64.to_le_bytes());
    let (b, _) = lire(&sale(g), "fin-sale");
    assert_eq!(trous_du_journal(&b), []);
}

/// Le drapeau « sale » (hors du CRC de l'en-tête) ou un en-tête abîmé, posés sans rien recalculer, ne suffisent pas
/// à faire passer un morceau disparu pour une copie à chaud : il en faut les signes (un morceau à zéro avant un
/// morceau écrit, des morceaux d'époques mêlées).
#[test]
fn le_drapeau_sale_seul_ne_change_rien() {
    // Un morceau ôté du fichier (les suivants remontés) : aucun morceau à zéro.
    let propre = fichier(&[morceau(1, 30, &[]), morceau(61, 90, &[])]);
    assert_eq!(
        trous_du_journal(&lire(&propre, "propre").0),
        [(31, 60, Nature::Absents)]
    );
    let mut f = propre.clone();
    f[120] |= 1;
    let (b, _) = lire(&f, "drapeau");
    assert!(b.lecture.as_ref().unwrap().sale);
    assert_eq!(trous_du_journal(&b), [(31, 60, Nature::Absents)]);
    let mut f = propre.clone();
    f[8] ^= 0xFF;
    let (b, _) = lire(&f, "abime");
    assert!(b.lecture.as_ref().unwrap().en_tete_abime);
    assert_eq!(trous_du_journal(&b), [(31, 60, Nature::Absents)]);
    // Des morceaux d'époques mêlées dans un fichier sale : copie à chaud.
    let melange = sale(fichier(&[
        morceau(301, 330, &[]),
        morceau(1, 30, &[]),
        morceau(201, 230, &[]),
        morceau(101, 130, &[]),
    ]));
    let (b, _) = lire(&melange, "melange");
    let t = trous_du_journal(&b);
    assert!(!t.is_empty() && t.iter().all(|t| t.2 == Nature::CopieAChaud), "{t:?}");
}

/// Un octet ajouté au fichier, ou un morceau à l'en-tête faux : la lecture a perdu ce qu'ils peuvent porter, pas
/// plus. Un trou plus grand qu'un morceau reste un constat.
#[test]
fn une_perte_ne_couvre_que_ce_qu_elle_peut_porter() {
    let propre = fichier(&[morceau(1, 30, &[]), vec![0; 65_536], morceau(61, 90, &[])]);
    let mut f = propre.clone();
    f.push(0);
    let (b, _) = lire(&f, "octet");
    assert!(!b.complet());
    assert_eq!(trous_du_journal(&b), [(31, 60, Nature::Absents)]);
    let mut f = fichier(&[
        morceau(1, 30, &[]),
        morceau(10_031, 10_060, &[]),
        morceau(10_061, 10_090, &[]),
    ]);
    f[4096 + 2 * 65_536 + 100] ^= 0xFF;
    let (b, _) = lire(&f, "gros");
    // Le morceau perdu peut être 10 061 à 10 090 (l'en-tête du fichier les attend) ; pas les 10 000 d'avant.
    assert_eq!(
        trous_du_journal(&b),
        [(31, 10_030, Nature::Absents), (10_061, 10_090, Nature::Illisible)]
    );
}

/// Un retrait dans un morceau intact reste un retrait, même son en-tête réécrit pour ne rien annoncer, rétréci, ou
/// un faux morceau écarté qui annonce les mêmes numéros.
#[test]
fn un_retrait_ne_se_deguise_pas() {
    let mut m = morceau(1, 30, &[14, 15, 16]);
    m[32..40].copy_from_slice(&0u64.to_le_bytes());
    m[16..24].copy_from_slice(&0u64.to_le_bytes());
    let (b, _) = lire(&fichier(&[m, morceau(31, 60, &[])]), "annonce-effacee");
    assert_eq!(trous_du_journal(&b), [(14, 16, Nature::Retires)]);
    assert_eq!(b.suites[0].incoherences, 1);
    let mut m = morceau(1, 30, &[14, 15, 16]);
    m[32..40].copy_from_slice(&13u64.to_le_bytes());
    let (b, _) = lire(&fichier(&[m, morceau(31, 60, &[])]), "annonce-retrecie");
    assert_eq!(trous_du_journal(&b), [(14, 16, Nature::Retires)]);
    assert_eq!(b.suites[0].incoherences, 1);
    // Le leurre : un morceau d'en-tête juste qui annonce 14 à 16, ses enregistrements abîmés.
    let mut seul = fichier(&[morceau(14, 16, &[])]);
    seul[4096 + 600] ^= 0xFF;
    let mut f = fichier(&[morceau(1, 30, &[14, 15, 16]), morceau(31, 60, &[])]);
    f.extend_from_slice(&seul[4096..4096 + 65_536]);
    let (b, _) = lire(&f, "leurre");
    assert_eq!(b.lecture.as_ref().unwrap().morceaux[2].annonce, Some((14, 16)));
    assert_eq!(trous_du_journal(&b), [(14, 16, Nature::Retires)]);
}

/// Les numéros des enregistrements renumérotés après un retrait (les EventRecordID gardés) : le fichier passe pour
/// un export, et le retrait se dit avant l'export. Inévitable (un export filtré a la même forme) : il reste dit.
#[test]
fn une_renumerotation_laisse_le_trou_en_numeros_d_origine() {
    let decale = |n: u64| if n <= 13 { n } else { n + 3 };
    let f = fichier(&[
        morceau_aux_numeros(&(1..=27).collect::<Vec<_>>(), decale),
        morceau_aux_numeros(&(28..=57).collect::<Vec<_>>(), decale),
    ]);
    let (b, _) = lire(&f, "renum");
    assert!(b.exporte);
    assert_eq!(
        b.suites[1]
            .trous
            .iter()
            .map(|t| (t.de, t.a, t.nature))
            .collect::<Vec<_>>(),
        [(14, 16, Nature::AvantExport)]
    );
}

/// Des noms d'ordinateur démesurés : la clé de chaque suite d'origine coupée, et les trous d'un dossier bornés.
#[test]
fn la_memoire_gardee_est_bornee() {
    use crate::journaux_windows::evtx::tests::morceau_ordinateur;
    let mut morceaux = Vec::new();
    for k in 0..64u64 {
        let nom: &'static str = Box::leak(format!("{k:02}{}", "x".repeat(15_000)).into_boxed_str());
        morceaux.push(morceau_ordinateur(
            &[2 * k + 1, 2 * k + 2],
            |n| if n % 2 == 1 { 1 } else { 3 },
            nom,
        ));
    }
    let (b, _) = lire(&fichier(&morceaux), "memoire");
    assert_eq!(b.suites.len(), 65);
    for s in &b.suites[1..] {
        let Numerotation::Origine { ordinateur, journal } = &s.numerotation else {
            panic!("{s:?}")
        };
        assert!(ordinateur.chars().count() <= CLE_MAX && journal.chars().count() <= CLE_MAX);
    }
    let d = jetable("trous-dossier");
    for i in 0..3 {
        let numeros: Vec<u64> = (1..=40).map(|n| n * 2).collect();
        std::fs::write(
            d.join(format!("j{i}.evtx")),
            fichier(&[morceau_aux_numeros(&numeros, |n| n)]),
        )
        .unwrap();
    }
    let bornes = BornesFichiers {
        trous_dossier: 50,
        ..BornesFichiers::default()
    };
    let b = lire_dossier(&d, &Filtre::default(), &bornes, |_| {}).unwrap();
    let gardes: usize = b.fichiers.iter().flat_map(|f| &f.suites).map(|s| s.trous.len()).sum();
    let au_dela: u64 = b.fichiers.iter().flat_map(|f| &f.suites).map(|s| s.trous_au_dela).sum();
    assert_eq!((gardes, au_dela), (50, 3 * 39 - 50));
    let _ = std::fs::remove_dir_all(&d);
}
