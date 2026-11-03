//! Les preuves de la réception : chaque refus compté, la quarantaine jamais recopiée, une voix par source et par
//! jour, le même état quel que soit l'ordre des lignes et des fichiers, l'état borné, gardé et retiré comme dit.

use super::*;
use crate::compte_rendu::envoi::tests::{complet, minimal};
use crate::compte_rendu::envoi::{Compte, IdInstallation, Lot};
use crate::essais::Jetable;
use proptest::prelude::*;

pub(super) const T: &str = "2026-11-02";

pub(super) fn j(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
}

pub(super) fn v(s: &str) -> Version {
    Version::new(s).unwrap()
}

pub(super) fn refs() -> References {
    let publiees = [
        ("0.86.0", "2026-07-01"),
        ("0.87.0", "2026-08-01"),
        ("0.88.0", "2026-09-01"),
        ("0.89.0", "2026-09-25"),
        ("0.89.1", "2026-10-20"),
    ]
    .into_iter()
    .map(|(x, d)| (v(x), j(d)))
    .collect();
    let arbre = Arbre {
        regles: ["LNX-MAJ-001", "LNX-PFE-001"].into_iter().map(String::from).collect(),
        outils: ["mots-de-passe-navigateurs", "bilan"]
            .into_iter()
            .map(String::from)
            .collect(),
        fichiers: ["src/machine/mod.rs"].into_iter().map(String::from).collect(),
    };
    let arbres = [(v("0.89.0"), arbre.clone()), (v("0.89.1"), arbre)]
        .into_iter()
        .collect();
    References::de(publiees, arbres).unwrap()
}

/// Une source du relais : 32 chiffres hexadécimaux.
pub(super) fn src(i: u64) -> String {
    format!("{i:032x}")
}

pub(super) fn ecrit(lot: &Lot) -> String {
    String::from_utf8(lot.ecrire()).unwrap()
}

/// Un lot tel que le relais le rend : (jour de réception, source, réseau large, lot brut).
pub(super) type Recu<'a> = (&'a str, String, String, String);

/// Une réponse du relais.
pub(super) fn reponse(lots: &[Recu<'_>], refus: &str) -> String {
    let morceaux: Vec<String> = lots
        .iter()
        .enumerate()
        .map(|(i, (r, s, l, lot))| {
            format!(r#"{{"id":{i},"jour":"{r}","source":"{s}","source_large":"{l}","lot":{lot}}}"#)
        })
        .collect();
    format!(
        r#"{{"releve":1,"lots":[{}],"refus":{refus},"reste":false}}"#,
        morceaux.join(",")
    )
}

struct Banc {
    _d: Jetable,
    envois: PathBuf,
    etat: PathBuf,
}

impl Banc {
    fn new() -> Banc {
        let d = Jetable::nouveau("flotte");
        let envois = d.join("envois");
        let etat = d.join("etat");
        std::fs::create_dir_all(&envois).unwrap();
        Banc { _d: d, envois, etat }
    }

    fn poser(&self, jour: &str, lignes: &[String]) {
        let mut t = lignes.join("\n");
        t.push('\n');
        std::fs::write(self.envois.join(format!("{jour}.jsonl")), t).unwrap();
    }

    fn nuit_max(&self, refs: &References, ecrire: bool, max: usize) -> Comptes {
        let d = Demande {
            dossier: &self.envois,
            references: refs,
            etat: ecrire.then_some(self.etat.as_path()),
            aujourdhui: j(T),
            etat_max: max,
        };
        executer(&d).unwrap()
    }

    fn nuit(&self) -> Comptes {
        self.nuit_max(&refs(), true, ETAT_MAX)
    }

    fn etat(&self, version: &str) -> EtatVersion {
        let o = std::fs::read(self.etat.join(format!("{version}.json"))).unwrap();
        EtatVersion::lire(&o, &v(version)).unwrap()
    }

    /// Tout ce que la nuit a écrit, en texte.
    fn tout_ecrit(&self) -> String {
        let mut t = String::new();
        for e in std::fs::read_dir(&self.etat).unwrap() {
            t.push_str(&String::from_utf8_lossy(&std::fs::read(e.unwrap().path()).unwrap()));
        }
        t
    }
}

fn r1() -> String {
    src(0xa1)
}

fn large() -> String {
    src(0xb1)
}

#[test]
fn un_lot_complet_compte_par_ses_cles() {
    let b = Banc::new();
    let lot = ecrit(&complet());
    // Le détecteur passe chaîne par chaîne, comme à la réception (le JSON entier, lui, a l'entropie d'un JSON).
    let balaye: Balayage = serde_json::from_str(&lot).unwrap();
    assert_eq!(balaye.0, 0, "le lot complet ne doit pas sonner");
    b.poser("2026-11-02", &[reponse(&[("2026-11-01", r1(), large(), lot)], "[]")]);
    let c = b.nuit();
    assert_eq!(
        (c.lots, c.acceptes, c.votes, c.refuses(), c.versions),
        (1, 1, 1, 0, 1),
        "{c:?}"
    );
    let e = b.etat("0.89.1");
    let jour = &e.jours[&Jour::new("2026-11-01").unwrap()];
    assert_eq!(
        (
            jour.tous.sources,
            jour.tous.larges,
            jour.tous.lots,
            jour.tous.installations
        ),
        (1, 1, 1, 1)
    );
    let s = &jour.tous.stats;
    assert_eq!(s["regle|LNX-MAJ-001|vue"], [1, 1, 1]);
    assert_eq!(s["regle|LNX-MAJ-001|n"], [1, 1, 5]);
    assert_eq!(s["regle|LNX-MAJ-001|raison|delai"], [1, 1, 1]);
    assert_eq!(
        s["cause|echec|wmi|LNX-MAJ-001|src/machine/mod.rs:12|droits|n"],
        [1, 1, 3]
    );
    assert_eq!(s["outil|mots-de-passe-navigateurs|menu|lances"], [1, 1, 4]);
    assert_eq!(s["version-avant|0.89.0"], [1, 1, 1]);
    assert_eq!(s["materiel|memoire|16"], [1, 1, 1]);
    assert!(
        s.keys().any(|k| k.starts_with("objet|LNX-MAJ-001|service|probleme|#")),
        "{s:?}"
    );
    assert!(
        jour.groupes.contains_key("arch|physique-nvme-f9-16"),
        "{:?}",
        jour.groupes.keys()
    );
    // Aucun texte de la voie ouverte : seulement des empreintes.
    let tout = b.tout_ecrit();
    for texte in [
        "Service de test",
        "Processeur de test",
        "Carte graphique",
        "échec de lecture",
        "délai dépassé",
        "1.2.3",
    ] {
        assert!(!tout.contains(texte), "{texte} recopié");
    }
    assert!(s.keys().chain(jour.groupes.keys()).all(|k| est_cle(k)));
}

#[test]
fn mille_lots_d_une_source_font_une_voix() {
    let b = Banc::new();
    let lots: Vec<_> = (1..=1000u64)
        .map(|i| {
            let mut l = minimal();
            l.activite.bilans_manuels = Compte::new(i);
            ("2026-11-01", r1(), large(), ecrit(&l))
        })
        .collect();
    let mut autre = minimal();
    autre.activite.bilans_manuels = Compte::new(5);
    let seconde = vec![("2026-11-01", src(0xa2), src(0xb2), ecrit(&autre))];
    b.poser("2026-11-02", &[reponse(&lots, "[]"), reponse(&seconde, "[]")]);
    let c = b.nuit();
    assert_eq!((c.lots, c.acceptes, c.votes), (1001, 1001, 2), "{c:?}");
    let e = b.etat("0.89.1");
    let jour = &e.jours[&Jour::new("2026-11-01").unwrap()];
    assert_eq!((jour.tous.sources, jour.tous.larges, jour.tous.lots), (2, 2, 1001));
    // Le maximum de la source qui a envoyé mille lots, plus la voix de l'autre.
    assert_eq!(jour.tous.stats["activite|bilans_manuels"], [2, 2, 1005]);
    assert_eq!(jour.tous.stats["activite|surveillance"], [2, 2, 2]);
}

/// Un lot hostile de chaque sorte, et ce qu'il doit donner.
#[allow(clippy::too_many_lines)]
fn hostiles() -> Vec<(Option<Rejet>, Recu<'static>)> {
    let faux = ["gh", "p_", "FAUXjetonInventePourLesEssais0123"].concat();
    let bon = || ecrit(&complet());
    let avec = |f: &dyn Fn(&mut Lot)| {
        let mut l = complet();
        f(&mut l);
        ecrit(&l)
    };
    let r = "2026-11-01";
    vec![
        (None, (r, r1(), large(), bon())),
        (Some(Rejet::Doublon), (r, r1(), large(), bon())),
        (Some(Rejet::Enveloppe), (r, "pas-une-source".into(), large(), bon())),
        (Some(Rejet::Enveloppe), ("2026-12-25", r1(), large(), bon())),
        (
            Some(Rejet::Quarantaine),
            (
                r,
                src(2),
                large(),
                bon().replacen("\"6.17\"", &format!("\"{faux}\""), 1),
            ),
        ),
        (
            Some(Rejet::Quarantaine),
            (r, src(3), large(), bon().replacen('{', &format!("{{\"{faux}\":1,"), 1)),
        ),
        (
            Some(Rejet::TropGros),
            (
                r,
                src(4),
                large(),
                bon().replacen('{', &format!("{{{}", " ".repeat(100_000)), 1),
            ),
        ),
        (
            Some(Rejet::HorsSchema),
            (r, src(5), large(), bon().replacen('{', "{\"en_trop\":1,", 1)),
        ),
        (
            Some(Rejet::HorsSchema),
            (
                r,
                src(6),
                large(),
                bon().replacen("Service de test", "Service \\u001b[31mrouge\\u001b[0m", 1),
            ),
        ),
        (
            Some(Rejet::HorsSchema),
            (r, src(7), large(), bon().replacen('{', "{\"version\":\"0.89.1\",", 1)),
        ),
        (
            Some(Rejet::VersionNonPubliee),
            (r, src(8), large(), avec(&|l| l.version = v("0.99.0"))),
        ),
        (
            Some(Rejet::VersionAncienne),
            (
                r,
                src(9),
                large(),
                avec(&|l| {
                    l.version = v("0.86.0");
                    l.version_avant = None;
                }),
            ),
        ),
        (
            Some(Rejet::VersionAvant),
            (r, src(10), large(), avec(&|l| l.version_avant = Some(v("0.89.5")))),
        ),
        (
            Some(Rejet::VersionAvant),
            (r, src(11), large(), avec(&|l| l.version_avant = Some(v("0.89.1")))),
        ),
        (
            Some(Rejet::Jour),
            (
                r,
                src(12),
                large(),
                avec(&|l| l.jour = Jour::new("2026-10-01").unwrap()),
            ),
        ),
        (
            Some(Rejet::Futur),
            (
                "2026-10-19",
                src(13),
                large(),
                avec(&|l| l.jour = Jour::new("2026-10-18").unwrap()),
            ),
        ),
        (
            Some(Rejet::SansReference),
            (
                r,
                src(14),
                large(),
                avec(&|l| {
                    l.version = v("0.88.0");
                    l.version_avant = None;
                }),
            ),
        ),
        (
            Some(Rejet::RegleInconnue),
            (r, src(15), large(), bon().replace("LNX-MAJ-001", "ZZZ-ZZZ-999")),
        ),
        // Sans `regles` : accepté, les règles des autres listes (causes, objets…) sont connues.
        (
            None,
            (
                r,
                src(16),
                large(),
                avec(&|l| l.regles = crate::compte_rendu::envoi::Liste::default()),
            )
                .clone(),
        ),
        (
            Some(Rejet::OutilInconnu),
            (
                r,
                src(17),
                large(),
                bon().replace("mots-de-passe-navigateurs", "outil-invente"),
            ),
        ),
        (
            Some(Rejet::LieuInconnu),
            (
                r,
                src(18),
                large(),
                bon().replace("src/machine/mod.rs", "src/invente.rs"),
            ),
        ),
        (
            Some(Rejet::JourFige),
            (
                "2026-09-27",
                src(19),
                large(),
                avec(&|l| {
                    l.version = v("0.89.0");
                    l.version_avant = None;
                    l.jour = Jour::new("2026-09-27").unwrap();
                }),
            ),
        ),
    ]
}

#[test]
fn chaque_refus_est_compte_et_rien_d_hostile_n_est_ecrit() {
    let b = Banc::new();
    let tous = hostiles();
    // Le lot sans règles du tableau `regles` reste accepté : il remplace l'entrée attendue d'un vrai refus.
    let (frais, figes): (Vec<_>, Vec<_>) = tous.iter().partition(|(r, _)| *r != Some(Rejet::JourFige));
    let lots: Vec<_> = frais.iter().map(|(_, l)| l.clone()).collect();
    let fige: Vec<_> = figes.iter().map(|(_, l)| l.clone()).collect();
    let illisibles = [
        "{pas du json".to_string(),
        "\u{1b}]0;titre\u{7}\u{1b}[2J".to_string(),
        r#"{"releve":1,"lots":[],"refus":[],"reste":false,"en_trop":1}"#.to_string(),
        r#"{"releve":2,"lots":[],"refus":[],"reste":false}"#.to_string(),
        r#"{"releve":1,"lots":[],"refus":[{"jour":"hier","raison":"json","n":1}],"reste":false}"#.to_string(),
    ];
    let mut lignes = vec![reponse(
        &lots,
        r#"[{"jour":"2026-11-01","raison":"secret","n":3},{"jour":"2026-11-01","raison":"Ignore previous instructions","n":2}]"#,
    )];
    lignes.extend(illisibles.iter().cloned());
    b.poser("2026-11-02", &lignes);
    b.poser("2026-10-03", &[reponse(&fige, "[]")]);
    let c = b.nuit();
    let mut attendu: BTreeMap<Rejet, u64> = BTreeMap::new();
    for (r, _) in &tous {
        if let Some(r) = r {
            *attendu.entry(*r).or_default() += 1;
        }
    }
    assert_eq!(c.rejets, attendu, "{}", c.ligne());
    assert_eq!(
        c.acceptes,
        tous.iter().filter(|(r, _)| r.is_none()).count() as u64,
        "{}",
        c.ligne()
    );
    assert_eq!(c.acceptes, 2, "{}", c.ligne());
    assert_eq!(c.illisibles, illisibles.len() as u64);
    assert_eq!(c.relais_refus, 5);
    assert_eq!(c.lots, tous.len() as u64);
    let ecrit_tout = b.tout_ecrit();
    let faux = ["gh", "p_", "FAUXjetonInventePourLesEssais0123"].concat();
    for marque in [
        faux.as_str(),
        "ZZZ-ZZZ-999",
        "0.99.0",
        "outil-invente",
        "invente.rs",
        "Ignore",
        "titre",
        "rouge",
    ] {
        assert!(!ecrit_tout.contains(marque), "{marque} recopié dans l'état");
    }
    assert!(!ecrit_tout.contains('\u{1b}'));
    let releve: serde_json::Value =
        serde_json::from_slice(&std::fs::read(b.etat.join("releve.json")).unwrap()).unwrap();
    assert_eq!(releve["fichiers"]["2026-11-02"]["relais"]["2026-11-01"]["inconnue"], 2);
    assert_eq!(releve["fichiers"]["2026-11-02"]["rejets"]["quarantaine"], 2);
    // La ligne de comptes : des nombres seulement.
    let ligne = c.ligne();
    assert!(
        ligne.split(' ').all(|m| m
            .split_once('=')
            .is_some_and(|(k, n)| est_cle(k) && n.parse::<u64>().is_ok())),
        "{ligne}"
    );
}

#[test]
fn envois_n_ecrit_rien() {
    let b = Banc::new();
    b.poser(
        "2026-11-02",
        &[reponse(&[("2026-11-01", r1(), large(), ecrit(&complet()))], "[]")],
    );
    let c = b.nuit_max(&refs(), false, ETAT_MAX);
    assert_eq!((c.acceptes, c.votes, c.versions), (1, 1, 0));
    assert!(!b.etat.exists());
}

#[test]
fn fichiers_hors_fenetre_lien_ou_trop_gros() {
    let b = Banc::new();
    let ligne = reponse(&[("2026-11-01", r1(), large(), ecrit(&complet()))], "[]");
    b.poser("2026-09-01", std::slice::from_ref(&ligne));
    b.poser("2026-11-04", std::slice::from_ref(&ligne));
    std::fs::write(b.envois.join("notes.jsonl"), &ligne).unwrap();
    std::fs::write(
        b.envois.join("2026-11-01.jsonl"),
        vec![b' '; usize::try_from(FICHIER_MAX + 1).unwrap()],
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(b.envois.join("2026-09-01.jsonl"), b.envois.join("2026-11-02.jsonl")).unwrap();
    let c = b.nuit();
    assert_eq!(c.fichiers, 0, "{c:?}");
    assert_eq!(c.acceptes, 0);
    assert_eq!(c.fichiers_ignores, if cfg!(unix) { 2 } else { 1 });
    // Un fichier de la fenêtre écarté : l'état n'avance pas, dit.
    assert!(c.etat_retenu);
    assert!(!b.etat.join("releve.json").exists());
    #[cfg(unix)]
    {
        // Un tube nommé à la place de l'état : écarté sans attendre (il figeait la nuit dans open()).
        let b = Banc::new();
        std::fs::create_dir_all(&b.etat).unwrap();
        let tube = b.etat.join("0.89.1.json");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&tube)
                .status()
                .is_ok_and(|s| s.success())
        );
        b.poser("2026-11-02", std::slice::from_ref(&ligne));
        let c = b.nuit();
        assert_eq!((c.acceptes, c.etats_illisibles), (1, 1), "{c:?}");
    }
}

#[test]
fn une_source_ne_gonfle_ni_les_cles_ni_les_installations() {
    // Mille lots d'une source, chacun avec ses propres noms d'objets et sa propre installation : la voix reste
    // bornée, et le résultat ne dépend pas de l'ordre.
    let lots: Vec<String> = (0..1000u32)
        .map(|i| {
            let mut l = complet();
            l.installation = Some(crate::compte_rendu::envoi::IdInstallation::de_octets(
                u64::from(i).to_be_bytes(),
            ));
            let mut e: serde_json::Value = serde_json::from_str(&ecrit(&l)).unwrap();
            e["objets"][0]["nom"] = serde_json::Value::String(format!("Objet {i}"));
            e["objets"][0]["version"] = serde_json::Value::String(format!("1.{i}.0"));
            e.to_string()
        })
        .collect();
    let etat = |ordre: &mut dyn Iterator<Item = &String>| {
        let b = Banc::new();
        let recus: Vec<Recu<'_>> = ordre.map(|l| ("2026-11-01", r1(), large(), l.clone())).collect();
        let lignes: Vec<String> = recus.chunks(500).map(|c| reponse(c, "[]")).collect();
        b.poser("2026-11-02", &lignes);
        let c = b.nuit();
        assert_eq!(c.votes, 1, "{c:?}");
        let e = b.etat("0.89.1");
        let j = e.jours[&Jour::new("2026-11-01").unwrap()].tous.clone();
        (j, std::fs::read(b.etat.join("0.89.1.json")).unwrap())
    };
    let (j, octets) = etat(&mut lots.iter());
    assert_eq!(j.installations, INSTALLATIONS_VOIX_MAX as u64);
    assert!(j.stats.len() <= CLES_VOIX_MAX, "{}", j.stats.len());
    let (_, a_rebours) = etat(&mut lots.iter().rev());
    assert_eq!(octets, a_rebours);
}

#[test]
fn jours_figes_gardes_fenetre_recalculee_mineures_sorties_retirees() {
    let b = Banc::new();
    std::fs::create_dir_all(&b.etat).unwrap();
    let vieux_jour = JourFlotte {
        tous: Agregat {
            sources: 7,
            larges: 7,
            lots: 7,
            installations: 7,
            stats: [("activite|cle".to_string(), [7, 7, 7])].into_iter().collect(),
        },
        groupes: BTreeMap::new(),
        // Un état écrit avant A9 : sans familles (relu vide).
        familles: BTreeMap::new(),
    };
    let ancien = EtatVersion {
        schema: ETAT_SCHEMA,
        version: v("0.89.1"),
        jours: [
            (Jour::new("2026-09-01").unwrap(), vieux_jour.clone()),
            (Jour::new("2026-10-30").unwrap(), vieux_jour.clone()),
        ]
        .into_iter()
        .collect(),
    };
    std::fs::write(b.etat.join("0.89.1.json"), serde_json::to_vec(&ancien).unwrap()).unwrap();
    let sortie = EtatVersion {
        version: v("0.86.0"),
        ..ancien.clone()
    };
    std::fs::write(b.etat.join("0.86.0.json"), serde_json::to_vec(&sortie).unwrap()).unwrap();
    // Une version récente sans jour figé ni lot frais : son état part.
    let vide = EtatVersion {
        version: v("0.88.0"),
        jours: [(Jour::new("2026-10-30").unwrap(), vieux_jour)].into_iter().collect(),
        ..ancien.clone()
    };
    std::fs::write(b.etat.join("0.88.0.json"), serde_json::to_vec(&vide).unwrap()).unwrap();
    std::fs::write(b.etat.join("notes.txt"), "à moi").unwrap();
    std::fs::write(b.etat.join("0.87.0.json"), "{pas un état").unwrap();
    b.poser(
        "2026-11-02",
        &[reponse(&[("2026-11-01", r1(), large(), ecrit(&complet()))], "[]")],
    );
    let c = b.nuit();
    assert_eq!(c.etats_illisibles, 1, "{c:?}");
    let e = b.etat("0.89.1");
    let jours: Vec<&str> = e.jours.keys().map(Jour::as_str).collect();
    assert_eq!(jours, ["2026-09-01", "2026-11-01"]);
    assert_eq!(e.jours[&Jour::new("2026-09-01").unwrap()].tous.sources, 7);
    assert!(!b.etat.join("0.86.0.json").exists());
    assert!(!b.etat.join("0.88.0.json").exists());
    assert!(!b.etat.join("0.87.0.json").exists());
    assert_eq!(std::fs::read_to_string(b.etat.join("notes.txt")).unwrap(), "à moi");
    // Relire la même relève ne compte rien deux fois.
    let avant = std::fs::read(b.etat.join("0.89.1.json")).unwrap();
    let c2 = b.nuit();
    assert_eq!(c2.acceptes, 1);
    assert_eq!(std::fs::read(b.etat.join("0.89.1.json")).unwrap(), avant);
}

#[test]
fn etat_borne_et_elague() {
    let b = Banc::new();
    let mut lots = Vec::new();
    for jour in 20..=31u64 {
        for s in 0..3u64 {
            let mut l = complet();
            l.jour = Jour::new(&format!("2026-10-{jour}")).unwrap();
            l.installation = Some(IdInstallation::de_octets([
                0,
                0,
                0,
                0,
                0,
                0,
                u8::try_from(s).unwrap(),
                u8::try_from(jour).unwrap(),
            ]));
            lots.push((format!("2026-10-{jour}"), src(jour * 10 + s), large(), ecrit(&l)));
        }
    }
    let lots: Vec<(&str, String, String, String)> = lots
        .iter()
        .map(|(r, s, l, x)| (r.as_str(), s.clone(), l.clone(), x.clone()))
        .collect();
    b.poser("2026-11-01", &[reponse(&lots, "[]")]);
    let entier = b.nuit();
    assert_eq!((entier.acceptes, entier.elagues), (36, 0), "{entier:?}");
    let max = 6000;
    let c = b.nuit_max(&refs(), true, max);
    assert!(c.elagues > 0, "{c:?}");
    let taille = std::fs::metadata(b.etat.join("0.89.1.json")).unwrap().len();
    assert!(taille <= max as u64, "{taille}");
    // Les jours les plus récents restent.
    assert!(b.etat("0.89.1").jours.contains_key(&Jour::new("2026-10-31").unwrap()));
}

#[test]
fn references_lues_et_refusees() {
    let d = Jetable::nouveau("references");
    assert!(References::lire(&d).is_err(), "sans versions.tsv");
    std::fs::write(d.join("versions.tsv"), "").unwrap();
    assert!(References::lire(&d).is_err(), "aucune version");
    std::fs::write(d.join("versions.tsv"), "0.89.1\t2026-10-20\n0.89.0\t2026-09-25\n").unwrap();
    let a = d.join("0.89.1");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::write(a.join("regles.txt"), "LNX-MAJ-001\n").unwrap();
    std::fs::write(a.join("outils.txt"), "bilan\n").unwrap();
    assert!(References::lire(&d).is_err(), "fichiers.txt manquant");
    std::fs::write(a.join("fichiers.txt"), "src/main.rs\n").unwrap();
    let r = References::lire(&d).unwrap();
    assert!(r.arbres[&v("0.89.1")].regles.contains("LNX-MAJ-001"));
    assert!(!r.arbres.contains_key(&v("0.89.0")));
    for (fichier, mauvais) in [
        ("regles.txt", "lnx-maj-1\n"),
        ("outils.txt", "rm -rf /\n"),
        ("fichiers.txt", "../../etc/passwd\n"),
    ] {
        let garde = std::fs::read(a.join(fichier)).unwrap();
        std::fs::write(a.join(fichier), mauvais).unwrap();
        assert!(References::lire(&d).is_err(), "{fichier} : {mauvais}");
        std::fs::write(a.join(fichier), garde).unwrap();
    }
    std::fs::write(d.join("versions.tsv"), "0.89.1 2026-10-20\n").unwrap();
    assert!(References::lire(&d).is_err(), "sans tabulation");
}

#[test]
fn etat_hostile_ignore() {
    let b = Banc::new();
    std::fs::create_dir_all(&b.etat).unwrap();
    for hostile in [
        r#"{"schema":1,"version":"0.89.0","jours":{}}"#,
        r#"{"schema":1,"version":"0.89.1","jours":{"hier":{"tous":{"sources":1,"larges":1,"lots":1,"installations":1,"stats":{}},"groupes":{}}}}"#,
        r#"{"schema":1,"version":"0.89.1","jours":{"2026-09-01":{"tous":{"sources":1,"larges":1,"lots":1,"installations":1,"stats":{"<script>":[1,1,1]}},"groupes":{}}}}"#,
    ] {
        std::fs::write(b.etat.join("0.89.1.json"), hostile).unwrap();
        let c = b.nuit();
        assert_eq!(c.etats_illisibles, 1, "{hostile}");
        assert!(!b.etat.join("0.89.1.json").exists(), "{hostile}");
    }
}

/// Une nuit sur des lignes réparties en fichiers : l'état de la version et les comptes.
fn nuit_de(fichiers: &[(&str, Vec<String>)]) -> (Vec<u8>, Comptes) {
    let b = Banc::new();
    for (jour, lignes) in fichiers {
        b.poser(jour, lignes);
    }
    let c = b.nuit();
    let etat = std::fs::read(b.etat.join("0.89.1.json")).unwrap_or_default();
    (etat, c)
}

fn variante(i: usize) -> Lot {
    let mut l = complet();
    l.jour = Jour::new("2026-10-29").unwrap();
    match i % 4 {
        0 => {}
        1 => l.activite.bilans_manuels = Compte::new(9),
        2 => l.materiel = None,
        _ => l.plateforme.famille = envoi::FamilleFine::Windows11,
    }
    l
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    /// L'agrégat ne dépend ni de l'ordre des lots, ni de celui des lignes, ni du fichier où une ligne tombe.
    #[test]
    fn stable_quel_que_soit_l_ordre(
        choix in prop::collection::vec((0usize..6, 0u64..5, 0usize..3), 1..40),
        graine in any::<u64>(),
    ) {
        let jours_r = ["2026-10-29", "2026-10-30", "2026-10-31"];
        let fichiers = ["2026-10-31", "2026-11-01", "2026-11-02"];
        let lots: Vec<(&str, String, String, String)> = choix
            .iter()
            .map(|&(var, s, r)| (jours_r[r], src(s), src(100 + s % 2), ecrit(&variante(var))))
            .collect();
        // Une ligne par paquet de trois lots, et chaque ligne dans un fichier tiré.
        let repartir = |lots: &[(&str, String, String, String)], x: &mut u64| {
            let mut par_fichier: Vec<Vec<String>> = vec![Vec::new(); 3];
            for paquet in lots.chunks(3) {
                *x ^= *x << 13;
                *x ^= *x >> 7;
                *x ^= *x << 17;
                par_fichier[usize::try_from(*x % 3).unwrap()].push(reponse(paquet, "[]"));
            }
            fichiers.iter().copied().zip(par_fichier).filter(|(_, l)| !l.is_empty()).collect::<Vec<_>>()
        };
        let mut x = graine | 1;
        let a = nuit_de(&repartir(&lots, &mut x));
        let mut melange = lots.clone();
        for i in (1..melange.len()).rev() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            melange.swap(i, usize::try_from(x % (i as u64 + 1)).unwrap());
        }
        let b = nuit_de(&repartir(&melange, &mut x));
        prop_assert_eq!(&a.0, &b.0);
        let sans_fichiers = |c: &Comptes| Comptes { fichiers: 0, lignes: 0, ..c.clone() };
        prop_assert_eq!(sans_fichiers(&a.1), sans_fichiers(&b.1));
        prop_assert!(a.1.votes <= 5 * 3, "une voix par source et par jour : {}", a.1.votes);
    }
}
