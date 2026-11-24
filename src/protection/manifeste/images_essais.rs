//! Essais des images de la clé jugées à la taille : la rotation, l'usure, la recopie pas finie, ce qui en est dit.

use std::path::PathBuf;

use super::super::{Relecture, comparer_avant_deploiement, comparer_avec, ecrire_dans, rafraichir_images_dans};
use super::super::{relire_image_dans, retirer_le_suspens};
use super::*;
use crate::reseau::TEMOIN_CLE;

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AUTRE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// Seuil de taille des essais : au-delà, jugée à la taille.
const GROS: u64 = 64;

struct Cle {
    racine: PathBuf,
    reference: PathBuf,
}

impl Cle {
    /// Une clé et sa référence, avec ces images (posées, donc avec leur empreinte et relues).
    fn neuve(nom: &str, images: &[&str]) -> Cle {
        let base = crate::essais::temporaire().join(format!("vanguard-images-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cle = Cle {
            racine: base.join("cle"),
            reference: base.join("ref").join("ref.json"),
        };
        std::fs::create_dir_all(cle.racine.join("ISO")).unwrap();
        std::fs::create_dir_all(cle.racine.join(TEMOIN_CLE).parent().unwrap()).unwrap();
        std::fs::write(cle.racine.join(TEMOIN_CLE), b"t").unwrap();
        for i in images {
            cle.image(i);
        }
        ecrire_dans(&cle.racine, &cle.reference, GROS, true).unwrap();
        cle.rafraichir(images);
        cle
    }

    fn image(&self, nom: &str) {
        std::fs::write(self.racine.join("ISO").join(nom), [b'x'; 100]).unwrap();
    }

    fn retirer(&self, nom: &str) {
        std::fs::remove_file(self.racine.join("ISO").join(nom)).unwrap();
    }

    fn rafraichir(&self, posees: &[&str]) {
        let posees: Vec<_> = posees
            .iter()
            .map(|n| ((*n).to_string(), Some(SHA.to_string())))
            .collect();
        rafraichir_images_dans(&self.racine, &self.reference, &posees, GROS).unwrap();
    }

    fn relire(&self, lue: Option<&str>) -> Relecture {
        relire_image_dans(&self.racine, &self.reference, &[], |_| lue.map(String::from)).unwrap()
    }

    fn debut(&self, par: &str, noms: &[&str]) {
        let noms: Vec<String> = noms.iter().map(|n| (*n).to_string()).collect();
        recopie_dans(&self.racine, &self.reference, &Geste::Debut { par, noms: &noms }).unwrap();
    }

    fn voir(&self) -> Recopies {
        recopie_dans(&self.racine, &self.reference, &Geste::Voir).unwrap()
    }

    fn m(&self) -> Manifeste {
        lire(&self.reference).unwrap()
    }

    /// Toutes les images relues « il y a longtemps » : la rotation ne dépend plus de la minute de l'essai.
    fn vieillir(&self) {
        let mut m = self.m();
        for e in &mut m.fichiers {
            e.relue = e.relue.as_ref().map(|_| "2026-01-01 00:00".to_string());
            e.illisible = e.illisible.as_ref().map(|_| "2026-01-01 00:00".to_string());
        }
        enregistrer(&self.reference, &m).unwrap();
    }
}

impl Drop for Cle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.racine.parent().unwrap());
    }
}

/// Une image illisible est notée et laisse passer les autres : avant, sa date de relecture ne bougeait pas, et elle
/// repassait seule, pour toujours.
#[test]
fn image_illisible_ne_bloque_plus_la_rotation() {
    let cle = Cle::neuve("rotation", &["a.iso", "b.iso"]);
    cle.vieillir();
    assert_eq!(cle.relire(None), Relecture::Illisible("ISO/a.iso".into()));
    assert_eq!(cle.relire(Some(SHA)), Relecture::Pareille("ISO/b.iso".into()));
    let e = etat(&cle.m(), chrono::Local::now().date_naive());
    assert_eq!(e.illisibles, ["ISO/a.iso"]);
    // Le bilan ne la dit ni saine ni changée, et la clé reste celle de sa référence.
    let ecart = comparer_avec(&cle.racine, &cle.m(), GROS);
    assert!(ecart.vide(), "{ecart:?}");
    assert!(!ecart.etat.constat("x", String::new()).verifie);
    // Relue, elle n'est plus à vérifier.
    cle.vieillir();
    assert_eq!(cle.relire(Some(SHA)), Relecture::Pareille("ISO/a.iso".into()));
    assert_eq!(
        etat(&cle.m(), chrono::Local::now().date_naive()).illisibles,
        Vec::<String>::new()
    );
}

/// Une référence réécrite par un déploiement garde qu'une image est illisible ; acceptée telle quelle, non.
#[test]
fn illisible_et_usure_gardees_par_une_reecriture() {
    let cle = Cle::neuve("garde", &["a.iso", "b.iso"]);
    cle.vieillir();
    cle.relire(None);
    assert_eq!(
        cle.relire(Some(AUTRE)),
        Relecture::Differente("ISO/b.iso".into(), false)
    );
    ecrire_dans(&cle.racine, &cle.reference, GROS, true).unwrap();
    let m = cle.m();
    assert_eq!(m.incidents.len(), 1);
    assert!(m.fichiers.iter().any(|e| e.illisible.is_some()));
    ecrire_dans(&cle.racine, &cle.reference, GROS, false).unwrap();
    let m = cle.m();
    assert_eq!(m.incidents, Vec::new());
    assert!(m.fichiers.iter().all(|e| e.illisible.is_none() && e.recopie.is_none()));
}

/// Deux images aux octets changés : la clé est à remplacer. Une image restée différente n'est comptée qu'une fois ;
/// reposée puis de nouveau différente, elle l'est deux fois.
#[test]
fn cle_a_remplacer_apres_deux_images_changees() {
    let cle = Cle::neuve("usee", &["a.iso"]);
    assert_eq!(
        cle.relire(Some(AUTRE)),
        Relecture::Differente("ISO/a.iso".into(), false)
    );
    assert_eq!(
        cle.relire(Some(AUTRE)),
        Relecture::Differente("ISO/a.iso".into(), false)
    );
    assert!(!cle.voir().1);
    cle.rafraichir(&["a.iso"]);
    assert_eq!(cle.relire(Some(AUTRE)), Relecture::Differente("ISO/a.iso".into(), true));
    assert!(cle.voir().1);
    cle.rafraichir(&["a.iso"]);
    let ecart = comparer_avec(&cle.racine, &cle.m(), GROS);
    assert!(ecart.vide(), "{ecart:?}");
    assert_eq!(ecart.etat.constat("x", String::new()).probleme, Some(Niveau::Moyen));
}

/// Deux recopies pas retrouvées sur la clé disent la même chose.
#[test]
fn cle_a_remplacer_apres_deux_recopies_ratees() {
    let cle = Cle::neuve("ratee", &["a.iso"]);
    let rater = || {
        recopie_dans(&cle.racine, &cle.reference, &Geste::Ratee { par: "a.iso" })
            .unwrap()
            .1
    };
    assert!(!rater());
    assert!(rater());
    // Une de chaque ne suffit pas : deux pannes différentes ne font pas une clé usée.
    let cle = Cle::neuve("une-de-chaque", &["a.iso"]);
    recopie_dans(&cle.racine, &cle.reference, &Geste::Ratee { par: "a.iso" }).unwrap();
    assert_eq!(
        cle.relire(Some(AUTRE)),
        Relecture::Differente("ISO/a.iso".into(), false)
    );
    assert!(!cle.voir().1);
    // Une image relue différente n'est pas comptée parmi les images relues et retrouvées.
    let e = etat(&cle.m(), chrono::Local::now().date_naive());
    assert_eq!((e.total, e.jamais, e.plus_ancienne), (1, 1, None));
}

/// Retirée pour être recopiée, puis clé débranchée : la clé n'est pas « changée » et le déploiement la reprend ; la même
/// absence sans la note reste un changement, comme un autre fichier que l'image notée.
#[test]
fn recopie_pas_finie_jamais_cle_changee() {
    let cle = Cle::neuve("recopie", &["a-1.iso", "b.iso"]);
    cle.debut("a-2.iso", &["a-1.iso"]);
    cle.retirer("a-1.iso");
    assert_eq!(cle.voir().0, [("a-1.iso".to_string(), "a-2.iso".to_string())]);
    let ecart = comparer_avec(&cle.racine, &cle.m(), GROS);
    assert!(ecart.vide(), "{ecart:?}");
    assert_eq!(ecart.etat.recopies, ["ISO/a-1.iso"]);
    assert!(!ecart.etat.constat("x", String::new()).verifie);
    assert!(comparer_avant_deploiement(&cle.racine, &cle.m(), true, GROS).is_ok());
    // Une réécriture par le déploiement, puis le menu redit par images-cle.sh : toujours en attente.
    ecrire_dans(&cle.racine, &cle.reference, GROS, true).unwrap();
    cle.rafraichir(&[]);
    assert_eq!(cle.voir().0.len(), 1);
    // Rien à relire d'elle : elle n'est pas « illisible ».
    assert_eq!(cle.relire(Some(SHA)), Relecture::Pareille("ISO/b.iso".into()));
    // Une autre image disparue, sans note : la clé a changé.
    cle.retirer("b.iso");
    let ecart = comparer_avec(&cle.racine, &cle.m(), GROS);
    assert_eq!(ecart.disparus, ["ISO/b.iso"]);
    assert!(comparer_avant_deploiement(&cle.racine, &cle.m(), true, GROS).is_err());
    cle.image("b.iso");
    // L'image neuve posée : plus rien en attente, et l'ancienne est oubliée.
    cle.image("a-2.iso");
    cle.rafraichir(&["a-2.iso"]);
    assert_eq!(cle.voir().0, []);
    let m = cle.m();
    assert!(
        m.fichiers
            .iter()
            .all(|e| e.chemin != "ISO/a-1.iso" && e.recopie.is_none())
    );
    assert!(comparer_avec(&cle.racine, &m, GROS).vide());
}

/// La note admet une absence, jamais d'autres octets : une image notée, présente avec une autre taille, reste changée,
/// et la même image revenue différente aussi.
#[test]
fn recopie_notee_n_admet_jamais_d_autres_octets() {
    let cle = Cle::neuve("octets", &["a.iso"]);
    cle.debut("a.iso", &["a.iso"]);
    std::fs::write(cle.racine.join("ISO/a.iso"), [b'x'; 101]).unwrap();
    let ecart = comparer_avec(&cle.racine, &cle.m(), GROS);
    assert_eq!(ecart.modifies.len(), 1, "{ecart:?}");
    cle.image("a.iso");
    assert!(matches!(cle.relire(Some(AUTRE)), Relecture::Differente(..)));
    assert_eq!(comparer_avec(&cle.racine, &cle.m(), GROS).modifies.len(), 1);
}

/// Notée puis gardée (la copie n'a pas eu lieu), la référence redite l'oublie : partie ensuite, la clé a changé.
#[test]
fn recopie_abandonnee_n_admet_plus_l_absence() {
    let cle = Cle::neuve("abandon", &["a-1.iso"]);
    cle.debut("a-2.iso", &["a-1.iso"]);
    cle.rafraichir(&[]);
    cle.retirer("a-1.iso");
    let ecart = comparer_avec(&cle.racine, &cle.m(), GROS);
    assert_eq!(ecart.disparus, ["ISO/a-1.iso"]);
    assert!(comparer_avant_deploiement(&cle.racine, &cle.m(), true, GROS).is_err());
}

/// La note ne vise que des images de ISO/ : un chemin est refusé, et le programme de la clé ne peut jamais manquer.
#[test]
fn recopie_ne_vise_que_des_images() {
    let cle = Cle::neuve("vise", &["a.iso"]);
    for mauvais in ["../vanguard", "x/y.iso", "", "..", "x\\y"] {
        let noms = [mauvais.to_string()];
        assert!(
            recopie_dans(
                &cle.racine,
                &cle.reference,
                &Geste::Debut {
                    par: "a.iso",
                    noms: &noms
                }
            )
            .is_err()
        );
        assert!(
            recopie_dans(
                &cle.racine,
                &cle.reference,
                &Geste::Debut {
                    par: mauvais,
                    noms: &[]
                }
            )
            .is_err()
        );
        assert!(recopie_dans(&cle.racine, &cle.reference, &Geste::Ratee { par: mauvais }).is_err());
    }
    std::fs::create_dir_all(cle.racine.join("Linux")).unwrap();
    std::fs::write(cle.racine.join("Linux/vanguard"), b"programme").unwrap();
    ecrire_dans(&cle.racine, &cle.reference, GROS, true).unwrap();
    cle.debut("vanguard", &["vanguard"]);
    std::fs::remove_file(cle.racine.join("Linux/vanguard")).unwrap();
    assert_eq!(comparer_avec(&cle.racine, &cle.m(), GROS).disparus, ["Linux/vanguard"]);
}

/// La phrase : combien d'images, la plus ancienne relecture, celles jamais relues, jamais un âge inventé.
#[test]
fn phrase_des_images() {
    let cle = Cle::neuve("phrase", &["a.iso", "b.iso", "c.iso"]);
    let mut m = cle.m();
    let mut images = m.fichiers.iter_mut().filter(|e| e.chemin.starts_with("ISO/"));
    images.next().unwrap().relue = Some("2026-03-01 10:00".into());
    let b = images.next().unwrap();
    (b.relue, b.sha256) = (None, None);
    // À venir (horloge reculée) : pas une relecture.
    images.next().unwrap().relue = Some("2026-04-01 10:00".into());
    let le_11 = NaiveDate::from_ymd_opt(2026, 3, 11).unwrap();
    let e = etat(&m, le_11);
    assert_eq!(
        (e.total, e.jamais, e.sans_empreinte, e.plus_ancienne),
        (3, 2, 1, Some(10))
    );
    let phrase = e.lignes().join(" ");
    assert!(
        phrase.contains("10") && phrase.contains('(') && phrase.contains('3'),
        "{phrase}"
    );
    // Aucune relue : jamais un âge.
    for e in &mut m.fichiers {
        e.relue = None;
    }
    assert_eq!(etat(&m, le_11).plus_ancienne, None);
    // Une clé sans image jugée à la taille n'a rien à dire ; une référence d'avant les images non plus.
    m.images = false;
    assert_eq!(etat(&m, le_11).lignes(), Vec::<String>::new());
}

/// Une recopie en attente : elle reprend seule, sauf sur une clé à remplacer, où rien n'est recopié de soi-même.
#[test]
fn recopie_en_attente_jamais_promise_sur_une_cle_a_remplacer() {
    let cle = Cle::neuve("promesse", &["a.iso"]);
    cle.debut("b.iso", &["a.iso"]);
    cle.retirer("a.iso");
    let mut e = comparer_avec(&cle.racine, &cle.m(), GROS).etat;
    assert_eq!(e.recopies, ["ISO/a.iso"]);
    let (seule, main) = (tr!("reprend seule", "by itself"), tr!("à la main", "by hand"));
    let dite = |e: &Etat| {
        e.lignes()
            .into_iter()
            .find(|l| l.contains("a.iso") && !l.contains("octet"))
            .unwrap()
    };
    assert!(dite(&e).contains(seule) && !dite(&e).contains(main), "{}", dite(&e));
    e.ratees = USEE;
    assert!(dite(&e).contains(main) && !dite(&e).contains(seule), "{}", dite(&e));
    assert!(
        e.lignes()
            .iter()
            .any(|l| l.contains(tr!("Clé à remplacer", "Key to replace")))
    );
}

/// La reprise du programme par le déploiement garde les images en attente dans l'écart qu'elle rend.
#[test]
fn reprise_avec_recopie_en_attente() {
    let cle = Cle::neuve("reprise", &["a.iso"]);
    cle.debut("a.iso", &["a.iso"]);
    cle.retirer("a.iso");
    let (reste, retires) = retirer_le_suspens(&cle.racine, comparer_avec(&cle.racine, &cle.m(), GROS)).unwrap();
    assert!(reste.vide() && retires.is_empty());
    assert_eq!(reste.etat.recopies, ["ISO/a.iso"]);
}

/// Un nom exclu (celui d'une copie en cours, d'un fichier de macOS) ne vaut que pour un fichier : un dossier de ce nom
/// est parcouru, et ce qu'on y pose fait dire la clé changée. Les simples fichiers restent de côté.
#[test]
fn dossier_au_nom_exclu_parcouru() {
    let cle = Cle::neuve("cache", &["a.iso"]);
    for fichier in ["ISO/.a.iso.part", "ISO/._a.iso", ".DS_Store"] {
        std::fs::write(cle.racine.join(fichier), b"reste").unwrap();
    }
    assert!(comparer_avec(&cle.racine, &cle.m(), GROS).vide());
    for dossier in ["ISO/.x.part", "ISO/._x", ".DS_Store.d/.DS_Store", "ISO/sous/.y.part"] {
        std::fs::create_dir_all(cle.racine.join(dossier)).unwrap();
        std::fs::write(cle.racine.join(dossier).join("plantee.iso"), b"piege").unwrap();
        let ecart = comparer_avec(&cle.racine, &cle.m(), GROS);
        assert_eq!(ecart.nouveaux, [format!("{dossier}/plantee.iso")], "{ecart:?}");
        std::fs::remove_dir_all(cle.racine.join(dossier)).unwrap();
    }
    // Une copie en cours n'existe qu'au premier niveau de ISO/ : ailleurs, ce nom ne cache rien.
    std::fs::create_dir_all(cle.racine.join("ISO/sous")).unwrap();
    std::fs::write(cle.racine.join("ISO/sous/.z.iso.part"), b"piege").unwrap();
    assert_eq!(
        comparer_avec(&cle.racine, &cle.m(), GROS).nouveaux,
        ["ISO/sous/.z.iso.part"]
    );
}

/// Une image est celle de son chemin exact : le même nom dans un sous-dossier de ISO/ n'entre pas dans la référence
/// avec l'empreinte de la vraie, et celle du cache ne sert pas à le relire.
#[test]
fn image_reconnue_a_son_chemin_exact() {
    let cle = Cle::neuve("chemin", &["a.iso"]);
    std::fs::create_dir_all(cle.racine.join("ISO/sous")).unwrap();
    cle.image("sous/a.iso");
    cle.rafraichir(&["a.iso"]);
    assert_eq!(comparer_avec(&cle.racine, &cle.m(), GROS).nouveaux, ["ISO/sous/a.iso"]);
    // Déjà dans la référence (clé acceptée telle quelle) : ni empreinte ni relecture.
    ecrire_dans(&cle.racine, &cle.reference, GROS, true).unwrap();
    cle.rafraichir(&["a.iso"]);
    let m = cle.m();
    let sous = m.fichiers.iter().find(|e| e.chemin == "ISO/sous/a.iso").unwrap();
    assert_eq!((&sous.sha256, &sous.relue), (&None, &None));
    cle.vieillir();
    let cache = [("a.iso".to_string(), Some(SHA.to_string()))];
    for _ in 0..2 {
        let lue = relire_image_dans(&cle.racine, &cle.reference, &cache, |_| Some(SHA.to_string()));
        assert_eq!(lue.unwrap(), Relecture::Pareille("ISO/a.iso".into()));
    }
}
