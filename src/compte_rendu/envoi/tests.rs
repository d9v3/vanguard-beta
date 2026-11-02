//! Les preuves du lot de schéma 2 : relu tel qu'écrit, lu tout ou rien, le schéma JSON et les types Rust d'accord
//! champ par champ et motif par motif, la troncature dans l'ordre dit, et des gardes sur la source elle-même (aucun
//! texte libre, aucune source exclue, rien qui envoie).

use super::*;
use crate::amelioration::texte::{EXTENSION_MAX, MARQUEURS, NOM_MAX, TEXTE_MAX, VERSION_MAX, permis};
use proptest::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::OnceLock;

mod schema;
use schema::{ANNOTATIONS, Motif, Pas, Schema as Js};

/// Le schéma que le relais (A7) et les outils de nuit reproduisent.
const SCHEMA_ENVOI: &str = include_str!("../../../outils/veille/schema-envoi.json");
/// La source du module, pour les gardes qui la lisent.
const SOURCE: &str = include_str!("../envoi.rs");

fn js() -> &'static Js {
    static S: OnceLock<Js> = OnceLock::new();
    S.get_or_init(|| Js::new(SCHEMA_ENVOI))
}

// --- Des lots d'essai ------------------------------------------------------------------------------------------

fn regle(s: &str) -> Regle {
    Regle::new(s).unwrap()
}

fn texte(s: &str) -> TexteNettoye {
    TexteNettoye::lire(s).unwrap_or_else(|| panic!("{s:?} n'est pas un texte nettoyé"))
}

fn nom(s: &str) -> NomLogiciel {
    NomLogiciel::lire(s).unwrap_or_else(|| panic!("{s:?} n'est pas un nom nettoyé"))
}

fn nb<const M: u32>(x: u64) -> Nombre<M> {
    Nombre::new(x).unwrap()
}

fn ct<const M: u32>(x: u64) -> Compte<M> {
    Compte::new(x)
}

fn liste<T: Entree + fmt::Debug, const M: usize>(entrees: Vec<T>) -> Liste<T, M> {
    let mut l = Liste::default();
    for t in entrees {
        l.pousser(t).unwrap();
    }
    l
}

fn minimal() -> Lot {
    Lot::new(
        Version::new("0.89.1").unwrap(),
        Jour::new("2026-11-01").unwrap(),
        Anciennete::Moins30,
        Plateforme {
            famille: FamilleFine::Arch,
            systeme_version: SystemeVersion::new("6.17").unwrap(),
            arch: Arch::X86_64,
            langue: Langue::Fr,
            edition: None,
            administrateur: false,
        },
        Activite {
            bilans_manuels: Compte::default(),
            passes_horaires: Compte::default(),
            surveillance: true,
            veilleur: false,
            cle: false,
        },
    )
}

/// Un lot où chaque champ est écrit : chaque facultatif présent, chaque compte non nul, chaque tableau non vide.
fn complet() -> Lot {
    let r = regle("LNX-MAJ-001");
    let mut l = minimal();
    l.version_avant = Version::new("0.89.0");
    l.installation = Some(IdInstallation::de_octets([
        0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
    ]));
    l.plateforme.edition = Some(Edition::Pro);
    l.plateforme.administrateur = true;
    l.materiel = Some(Materiel {
        processeur: Processeur::Amd,
        coeurs: nb(8),
        fils: nb(16),
        memoire_go: MemoireGo::arrondie(24),
        disque: Disque::Nvme,
        virtuelle: Virtuelle::Aucune,
        portable: true,
        tpm: TroisEtats::Oui,
        demarrage_securise: TroisEtats::Inconnu,
        graphique: Graphique::Nvidia,
        modele_processeur: Some(nom("Processeur de test")),
        modele_graphique: Some(nom("Carte graphique de test")),
    });
    l.activite = Activite {
        bilans_manuels: ct(2),
        passes_horaires: ct(24),
        surveillance: true,
        veilleur: true,
        cle: true,
    };
    l.causes = liste(vec![CauseEnvoyee {
        genre: Genre::Echec,
        contexte: Contexte::Wmi,
        regle: Some(r.clone()),
        lieu: Lieu::new("src/machine/mod.rs:12:5"),
        code: Code::new("droits"),
        n: nb(3),
        duree_ms: ct(arrondir_ms(1234)),
        en_plus: ct(1),
        en_moins: ct(2),
        differents: ct(3),
        gabarit: Some(Gabarit::de(&texte("échec de lecture"))),
    }]);
    l.regles = liste(vec![RegleEnvoyee {
        id: r.clone(),
        n: nb(5),
        med_ms: ct(120),
        p90_ms: ct(900),
        hors_delai: ct(1),
        problemes: ct(1),
        sains: ct(3),
        non_verifies: ct(1),
        raisons: liste(vec![RaisonNombre {
            code: Code::new("delai").unwrap(),
            n: nb(1),
        }]),
        delai_s: nb(30),
    }]);
    l.objets = liste(vec![ObjetEnvoye {
        regle: r.clone(),
        sorte: Sorte::Service,
        nom: nom("Service de test"),
        version: VersionTierce::lire("1.2.3"),
        etat: Etat::Probleme,
        n: nb(1),
    }]);
    l.textes = liste(vec![TexteEnvoye::new(
        texte("délai dépassé après 30 s"),
        Contexte::Autotest,
        Some(r.clone()),
        nb(2),
    )]);
    l.corrections = liste(vec![Correction {
        regle: r.clone(),
        proposees: ct(7),
        acceptees: ct(6),
        refusees: ct(1),
        reussies: ct(5),
        echouees: ct(1),
        annulees: ct(1),
        revenues: ct(1),
        codes: liste(vec![RaisonNombre {
            code: Code::new("-5").unwrap(),
            n: nb(1),
        }]),
    }]);
    l.choix = liste(vec![Choix {
        regle: r.clone(),
        normales: ct(1),
        oublis: ct(1),
        refus: ct(2),
        echap: ct(3),
    }]);
    l.outils = liste(vec![OutilEnvoye {
        outil: NomOutil::new("mots-de-passe-navigateurs").unwrap(),
        origine: Origine::Menu,
        lances: ct(4),
        finis: ct(3),
        abandonnes: ct(1),
        plantes: ct(1),
        med_ms: ct(2500),
    }]);
    l.cache = liste(vec![CacheRegle {
        regle: r.clone(),
        repris: ct(10),
        a_neuf: ct(2),
        age_total_s: ct(36_000),
        gagne_ms: ct(45_000),
        comparees: ct(1),
        ecarts: ct(1),
    }]);
    l.reglages = liste(vec![Reglage {
        levier: Levier::Delai,
        regle: Some(r),
        avant: ct(30),
        apres: ct(45),
        annule: true,
    }]);
    l.refus_locaux = ct(4);
    l.retires = Retires {
        regles: ct(1),
        textes: ct(2),
        objets: ct(3),
        cache: ct(4),
        outils: ct(5),
        choix: ct(6),
        corrections: ct(7),
        reglages: ct(8),
        causes: ct(9),
    };
    l
}

/// Un tirage déterministe (splitmix64) : la graine vient de proptest, qui sait la rejouer et la réduire.
struct Hasard(u64);

impl Hasard {
    fn suivant(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn sous(&mut self, n: usize) -> usize {
        usize::try_from(self.suivant() % n as u64).unwrap()
    }

    fn oui(&mut self) -> bool {
        self.suivant() & 1 == 1
    }

    fn choisir<T: Clone>(&mut self, t: &[T]) -> T {
        t[self.sous(t.len())].clone()
    }

    /// Les bornes d'abord : zéro (non écrit), 1, le maximum, au-delà (plafonné).
    fn compte<const M: u32>(&mut self) -> Compte<M> {
        let m = u64::from(M);
        Compte::new(match self.sous(5) {
            0 => 0,
            1 => 1,
            2 => m,
            3 => m + 9,
            _ => self.suivant() % m,
        })
    }

    fn nombre<const M: u32>(&mut self) -> Nombre<M> {
        let m = u64::from(M);
        Nombre::new(match self.sous(4) {
            0 => 1,
            1 => m,
            2 => u64::MAX,
            _ => 1 + self.suivant() % m,
        })
        .unwrap()
    }

    fn regle(&mut self) -> Regle {
        let s = format!(
            "{}-{}-{:03}",
            self.choisir(&["LNX", "WIN", "MAC"]),
            self.choisir(&["MAJ", "PAR", "RES"]),
            self.sous(1000)
        );
        regle(&s)
    }

    fn code(&mut self) -> Code {
        let s = match self.sous(3) {
            0 => self.choisir(crate::compte_rendu::champs::CODES).to_string(),
            1 => format!("-{}", self.sous(100_000)),
            _ => self.suivant().to_string().chars().take(10).collect(),
        };
        Code::new(&s).unwrap()
    }

    fn contexte(&mut self) -> Contexte {
        let ids: Vec<&str> = Contexte::tous_les_id().collect();
        Contexte::de_id(self.choisir(&ids)).unwrap()
    }

    fn facultatif<T>(&mut self, f: impl FnOnce(&mut Hasard) -> T) -> Option<T> {
        if self.oui() { Some(f(self)) } else { None }
    }
}

/// Les textes de la voie ouverte que le tirage pioche (tirés par proptest, puis gardés s'ils sont nettoyés).
struct Ouverts {
    textes: Vec<TexteNettoye>,
    noms: Vec<NomLogiciel>,
    versions: Vec<VersionTierce>,
}

impl Ouverts {
    fn new(bruts: &[String], versions: &[String]) -> Ouverts {
        let mut o = Ouverts {
            textes: vec![texte("échec de lecture")],
            noms: vec![nom("Service de test")],
            versions: vec![VersionTierce::lire("1.2.3").unwrap()],
        };
        o.textes.extend(bruts.iter().filter_map(|b| TexteNettoye::lire(b)));
        o.noms.extend(bruts.iter().filter_map(|b| NomLogiciel::lire(b)));
        o.versions
            .extend(versions.iter().filter_map(|b| VersionTierce::lire(b)));
        o
    }
}

/// Un lot tiré au hasard, avec au plus `tailles[i]` entrées par tableau (dans l'ordre des champs du lot).
fn au_hasard(h: &mut Hasard, tailles: [usize; 9], o: &Ouverts) -> Lot {
    let mut l = minimal();
    l.version_avant = h.facultatif(|h| Version::new(&format!("0.{}.{}", h.sous(1000), h.sous(10))).unwrap());
    l.jour = Jour::new(&format!(
        "20{:02}-{:02}-{:02}",
        h.sous(100),
        1 + h.sous(12),
        1 + h.sous(28)
    ))
    .unwrap();
    l.installation = h.facultatif(|h| IdInstallation::de_octets(h.suivant().to_le_bytes()));
    l.anciennete = h.choisir(Anciennete::TOUS);
    l.plateforme = Plateforme {
        famille: h.choisir(FamilleFine::TOUS),
        systeme_version: SystemeVersion::new(h.choisir(&["26100", "15", "6.17", "999999.999"])).unwrap(),
        arch: h.choisir(Arch::TOUS),
        langue: h.choisir(Langue::TOUS),
        edition: h.facultatif(|h| h.choisir(Edition::TOUS)),
        administrateur: h.oui(),
    };
    l.materiel = h.facultatif(|h| Materiel {
        processeur: h.choisir(Processeur::TOUS),
        coeurs: h.nombre(),
        fils: h.nombre(),
        memoire_go: MemoireGo::arrondie(h.suivant() % 10_000),
        disque: h.choisir(Disque::TOUS),
        virtuelle: h.choisir(Virtuelle::TOUS),
        portable: h.oui(),
        tpm: h.choisir(TroisEtats::TOUS),
        demarrage_securise: h.choisir(TroisEtats::TOUS),
        graphique: h.choisir(Graphique::TOUS),
        modele_processeur: h.facultatif(|h| h.choisir(&o.noms)),
        modele_graphique: h.facultatif(|h| h.choisir(&o.noms)),
    });
    l.activite = Activite {
        bilans_manuels: h.compte(),
        passes_horaires: h.compte(),
        surveillance: h.oui(),
        veilleur: h.oui(),
        cle: h.oui(),
    };
    for _ in 0..tailles[0] {
        let c = CauseEnvoyee {
            genre: h.choisir(Genre::TOUS),
            contexte: h.contexte(),
            regle: h.facultatif(Hasard::regle),
            lieu: h.facultatif(|h| {
                Lieu::new(&format!(
                    "src/a_b/c{}.rs:{}:{}",
                    h.sous(10),
                    1 + h.sous(999_999),
                    h.sous(99_999)
                ))
                .unwrap()
            }),
            code: h.facultatif(Hasard::code),
            n: h.nombre(),
            duree_ms: ct(arrondir_ms(u64::from(h.compte::<MS_MAX>().get()))),
            en_plus: h.compte(),
            en_moins: h.compte(),
            differents: h.compte(),
            gabarit: h.facultatif(|h| Gabarit::de(&h.choisir(&o.textes))),
        };
        let _ = l.causes.pousser(c);
    }
    for _ in 0..tailles[1] {
        let r = RegleEnvoyee {
            id: h.regle(),
            n: h.nombre(),
            med_ms: h.compte(),
            p90_ms: h.compte(),
            hors_delai: h.compte(),
            problemes: h.compte(),
            sains: h.compte(),
            non_verifies: h.compte(),
            raisons: {
                let mut r = Liste::default();
                for _ in 0..h.sous(RAISONS_MAX + 2) {
                    let _ = r.pousser(RaisonNombre {
                        code: h.code(),
                        n: h.nombre(),
                    });
                }
                r
            },
            delai_s: h.nombre(),
        };
        let _ = l.regles.pousser(r);
    }
    for _ in 0..tailles[2] {
        let x = ObjetEnvoye {
            regle: h.regle(),
            sorte: h.choisir(Sorte::TOUS),
            nom: h.choisir(&o.noms),
            version: h.facultatif(|h| h.choisir(&o.versions)),
            etat: h.choisir(Etat::TOUS),
            n: h.nombre(),
        };
        let _ = l.objets.pousser(x);
    }
    for _ in 0..tailles[3] {
        let t = TexteEnvoye::new(
            h.choisir(&o.textes),
            h.contexte(),
            h.facultatif(Hasard::regle),
            h.nombre(),
        );
        let _ = l.textes.pousser(t);
    }
    for _ in 0..tailles[4] {
        let c = Correction {
            regle: h.regle(),
            proposees: h.compte(),
            acceptees: h.compte(),
            refusees: h.compte(),
            reussies: h.compte(),
            echouees: h.compte(),
            annulees: h.compte(),
            revenues: h.compte(),
            codes: {
                let mut r = Liste::default();
                for _ in 0..h.sous(RAISONS_MAX + 2) {
                    let _ = r.pousser(RaisonNombre {
                        code: h.code(),
                        n: h.nombre(),
                    });
                }
                r
            },
        };
        let _ = l.corrections.pousser(c);
    }
    for _ in 0..tailles[5] {
        let c = Choix {
            regle: h.regle(),
            normales: h.compte(),
            oublis: h.compte(),
            refus: h.compte(),
            echap: h.compte(),
        };
        let _ = l.choix.pousser(c);
    }
    for _ in 0..tailles[6] {
        let outil = format!("{}-{}", h.choisir(&["bilan", "corriger", "scan-reseau"]), h.sous(100));
        let x = OutilEnvoye {
            outil: NomOutil::new(&outil).unwrap(),
            origine: h.choisir(Origine::TOUS),
            lances: h.compte(),
            finis: h.compte(),
            abandonnes: h.compte(),
            plantes: h.compte(),
            med_ms: h.compte(),
        };
        let _ = l.outils.pousser(x);
    }
    for _ in 0..tailles[7] {
        let c = CacheRegle {
            regle: h.regle(),
            repris: h.compte(),
            a_neuf: h.compte(),
            age_total_s: h.compte(),
            gagne_ms: h.compte(),
            comparees: h.compte(),
            ecarts: h.compte(),
        };
        let _ = l.cache.pousser(c);
    }
    for _ in 0..tailles[8] {
        let r = Reglage {
            levier: h.choisir(Levier::TOUS),
            regle: h.facultatif(Hasard::regle),
            avant: h.compte(),
            apres: h.compte(),
            annule: h.oui(),
        };
        let _ = l.reglages.pousser(r);
    }
    l.refus_locaux = h.compte();
    l
}

fn ouverts_bruts() -> impl Strategy<Value = (Vec<String>, Vec<String>)> {
    (
        prop::collection::vec(
            prop_oneof![
                prop::collection::vec(prop::sample::select(MOTS), 1..30).prop_map(|m| m.join(" ")),
                "\\PC{1,40}",
            ],
            0..12,
        ),
        prop::collection::vec("[0-9][0-9a-zA-Z.+_:~-]{0,24}", 0..6),
    )
}

/// Des mots pour tirer des textes que le nettoyage garde tels quels : lettres de plusieurs écritures, accents
/// combinants, marqueurs, ponctuation permise.
const MOTS: &[&str] = &[
    "échec",
    "délai",
    "dépassé",
    "de",
    "la",
    "lecture",
    "Salon",
    "après",
    "30",
    "s",
    "(code",
    "5)",
    "<chemin .txt>",
    "<chemin>",
    "<url>",
    "<numéro>",
    "<utilisateur>",
    "erreur:",
    "fichier",
    "accès",
    "refusé",
    "Ölçü",
    "日本語",
    "e\u{301}cole",
    "100%",
    "[x]",
    "a/b",
    "_",
    "+",
    "=",
    "'",
    ";",
    ",",
    "service",
];

// --- Lecture et écriture ---------------------------------------------------------------------------------------

fn octets(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn valeur(l: &Lot) -> Value {
    serde_json::from_slice(&l.ecrire()).unwrap()
}

#[test]
fn relu_tel_quel() {
    for l in [minimal(), complet()] {
        let o = l.ecrire();
        assert_eq!(lire(&o), Ok(l.clone()));
        assert_eq!(lire(&o).unwrap().ecrire(), o, "une seule écriture");
        assert!(js().valide(&valeur(&l)), "le schéma refuse un lot de Rust");
    }
    // Le minimal n'écrit que l'obligatoire.
    let v = valeur(&minimal());
    let clefs: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(clefs.len(), 6, "{clefs:?}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn tout_lot_se_relit((bruts, versions) in ouverts_bruts(), graine in any::<u64>(), t in prop::array::uniform9(0usize..6)) {
        let o = Ouverts::new(&bruts, &versions);
        let mut l = au_hasard(&mut Hasard(graine), t, &o);
        l.tronquer();
        let ecrit = l.ecrire();
        prop_assert!(ecrit.len() <= LOT_MAX);
        let relu = lire(&ecrit);
        prop_assert_eq!(relu.as_ref(), Ok(&l));
        prop_assert_eq!(relu.unwrap().ecrire(), ecrit.clone());
        let v: Value = serde_json::from_slice(&ecrit).unwrap();
        prop_assert!(js().valide(&v), "le schéma refuse {}", String::from_utf8_lossy(&ecrit));
        voie_fermee_sobre(&v);
    }
}

/// Tout texte de la voie fermée n'a que des lettres et chiffres ASCII et `:._/-` : rien qui se lise comme une
/// consigne ou une balise. Seuls les types marqués « x-voie » (voie ouverte) portent autre chose.
fn voie_fermee_sobre(v: &Value) {
    let mut tous = Vec::new();
    chemins(v, &mut Vec::new(), &mut tous);
    for chemin in tous {
        let Some(s) = suivre(v, &chemin).as_str() else { continue };
        if js().feuille(&chemin).iter().any(|d| d.get("x-voie").is_some()) {
            continue;
        }
        assert!(
            s.chars().all(|x| x.is_ascii_alphanumeric() || ":._/-".contains(x)),
            "voie fermée : {s:?} en {chemin:?}"
        );
    }
}

#[test]
fn lecture_stricte() {
    let base = valeur(&complet());
    let refuse = |v: &Value, quoi: &str| {
        assert_eq!(lire(&octets(v)), Err(Refus::HorsSchema), "{quoi} devrait être refusé");
    };
    let avec = |f: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        f(&mut v);
        v
    };
    refuse(&avec(&|v| v["inconnu"] = json!(1)), "une clé inconnue");
    refuse(
        &avec(&|v| v["plateforme"]["inconnu"] = json!(1)),
        "une clé inconnue dans un objet",
    );
    refuse(
        &avec(&|v| v["textes"][0]["inconnu"] = json!(1)),
        "une clé inconnue dans un texte",
    );
    refuse(
        &avec(&|v| v["plateforme"]["administrateur"] = json!("oui")),
        "un mauvais type",
    );
    refuse(&avec(&|v| v["regles"][0]["n"] = json!("5")), "un nombre écrit en texte");
    refuse(&avec(&|v| v["regles"][0]["n"] = json!(5.0)), "un entier écrit 5.0");
    refuse(
        &avec(&|v| v["regles"][0]["n"] = json!(N_MAX + 1)),
        "un nombre trop grand",
    );
    refuse(
        &avec(&|v| v["causes"][0]["n"] = json!(CAUSE_N_MAX + 1)),
        "une cause trop nombreuse",
    );
    refuse(
        &avec(&|v| v["textes"][0]["texte"] = json!("é".repeat(151))),
        "un texte de plus de 300 octets",
    );
    refuse(
        &avec(&|v| v["objets"][0]["nom"] = json!("a".repeat(NOM_MAX + 1))),
        "un nom trop long",
    );
    refuse(&avec(&|v| v["jour"] = json!("2026-11-1")), "un jour hors motif");
    refuse(&avec(&|v| v["jour"] = json!("2026-02-30")), "un jour qui n'existe pas");
    refuse(
        &avec(&|v| v["causes"][0]["lieu"] = json!("/home/alice/src/main.rs:1:1")),
        "un lieu hors du code",
    );
    refuse(&avec(&|v| v["version_avant"] = Value::Null), "un null");
    refuse(&avec(&|v| v["refus_locaux"] = json!(0)), "un zéro écrit");
    refuse(&avec(&|v| v["causes"] = json!([])), "un tableau vide écrit");
    refuse(&avec(&|v| v["retires"] = json!({})), "des retraits vides écrits");
    refuse(&avec(&|v| v["schema"] = json!(1)), "un autre schéma");
    refuse(
        &avec(&|v| v["materiel"]["memoire_go"] = json!(12)),
        "une mémoire hors puissance de 2",
    );
    refuse(
        &avec(&|v| {
            let e = v["choix"][0].clone();
            v["choix"].as_array_mut().unwrap().push(e);
        }),
        "une entrée en double",
    );
    refuse(
        &avec(&|v| v["textes"][0]["gabarit"] = json!("0123456789abcdef")),
        "le gabarit d'un autre texte",
    );
    refuse(
        &avec(&|v| {
            v["regles"][0]["raisons"] = json!(
                (0..5)
                    .map(|i| json!({"code": format!("-{i}"), "n": 1}))
                    .collect::<Vec<_>>()
            );
        }),
        "un tableau trop long",
    );
    let causes: Vec<Value> = (0..=CAUSES_MAX)
        .map(|i| json!({"genre": "echec", "contexte": "wmi", "code": format!("-{i}"), "n": 1}))
        .collect();
    refuse(&avec(&|v| v["causes"] = json!(causes)), "51 causes");
    let mut moins = base.clone();
    moins["causes"] = json!(causes[..CAUSES_MAX]);
    assert!(lire(&octets(&moins)).is_ok(), "50 causes passent");

    // Ce que serde_json lirait sans broncher, et que Rust refuse quand même.
    let o = minimal().ecrire();
    let mut double = b"{\"schema\":2,".to_vec();
    double.extend_from_slice(&o[1..]);
    assert_eq!(lire(&double), Err(Refus::HorsSchema), "une clé écrite deux fois");
    let mut queue = o.clone();
    queue.extend_from_slice(b"x");
    assert_eq!(lire(&queue), Err(Refus::HorsSchema), "des octets après le lot");
    assert_eq!(lire(b""), Err(Refus::HorsSchema));
    assert_eq!(lire(&vec![b' '; LOT_MAX + 1]), Err(Refus::TropGros));
    let mut juste = o.clone();
    juste.resize(LOT_MAX, b' ');
    assert_eq!(lire(&juste), Ok(minimal()), "96 Kio pile passent");

    // Le refus ne recopie rien du lot.
    let r = lire(&octets(&avec(&|v| v["alice-secret"] = json!("Salon")))).unwrap_err();
    assert!(!r.to_string().contains("alice") && !r.to_string().contains("Salon"));
}

// --- Le schéma JSON et les types Rust disent la même chose -----------------------------------------------------

fn chemins(v: &Value, ici: &mut Vec<Pas>, sortie: &mut Vec<Vec<Pas>>) {
    sortie.push(ici.clone());
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                ici.push(Pas::Clef(k.clone()));
                chemins(x, ici, sortie);
                ici.pop();
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                ici.push(Pas::Rang(i));
                chemins(x, ici, sortie);
                ici.pop();
            }
        }
        _ => {}
    }
}

fn suivre<'a>(v: &'a Value, chemin: &[Pas]) -> &'a Value {
    chemin.iter().fold(v, |v, p| match p {
        Pas::Clef(k) => &v[k.as_str()],
        Pas::Rang(i) => &v[*i],
    })
}

fn aller<'a>(v: &'a mut Value, chemin: &[Pas]) -> &'a mut Value {
    chemin.iter().fold(v, |v, p| match p {
        Pas::Clef(k) => &mut v[k.as_str()],
        Pas::Rang(i) => &mut v[*i],
    })
}

/// Les textes essayés à chaque feuille : bons et mauvais exemples de chaque motif, et les longueurs aux bornes.
fn sondes() -> Vec<String> {
    let mut s: Vec<String> = [
        "LNX-MAJ-001",
        "lnx-maj-001",
        "LNX-MAJ-01",
        "0.89.1",
        "0.89",
        "1000.0.0",
        "2026-11-01",
        "2026-02-30",
        "2026-13-01",
        "+202-11-01",
        "0123456789abcdef",
        "0123456789ABCDEF",
        "0123456789abcde",
        "src/main.rs:1:1",
        "src/../main.rs:1:1",
        "/home/alice/src/main.rs:1:1",
        "droits",
        "-12",
        "12345678901",
        "windows-11",
        "6.17",
        "26100",
        "1.2.3.4",
        "mots-de-passe-navigateurs",
        "a-",
        "Salon",
        "alice <url>",
        "<système>",
        "1.2.3-beta",
        "1.2.3-",
        "x\n",
        " ",
        "",
        "é",
        "\u{FF21}",
    ]
    .iter()
    .map(|x| (*x).to_string())
    .collect();
    for (x, n) in [
        ("a", 32),
        ("a", 64),
        ("a", TEXTE_MAX),
        ("é", TEXTE_MAX / 2),
        ("1", VERSION_MAX),
    ] {
        s.push(x.repeat(n));
        s.push(x.repeat(n + 1));
    }
    s
}

/// Les valeurs essayées à une feuille : les générales, ses propres listes et bornes, d'autres listes, les sondes.
fn candidats(feuille: &[&Value]) -> Vec<Value> {
    let mut c = vec![
        json!(0),
        json!(1),
        json!(2),
        json!(1.5),
        json!(1.0),
        json!(-1),
        Value::Null,
        json!(true),
        json!(false),
        json!([]),
        json!({}),
        json!(u64::from(u32::MAX) + 1),
    ];
    for d in feuille {
        if let Some(e) = d.get("enum").and_then(Value::as_array) {
            c.extend(e.iter().cloned());
        }
        if let Some(m) = d.get("maximum").and_then(Value::as_u64) {
            c.extend([json!(m - 1), json!(m), json!(m + 1)]);
        }
    }
    for d in js().defs().values() {
        if let Some(premier) = d.get("enum").and_then(|e| e.get(0)) {
            c.push(premier.clone());
        }
    }
    c.extend(sondes().into_iter().map(Value::String));
    c
}

/// Rust et le schéma tranchent pareil ; seule exception permise, Rust plus strict là où le schéma le dit
/// (« x-verifie-en-rust » sur la feuille changée) ou pour un entier écrit avec une décimale (1.0).
fn trancher(m: &Value, feuille: Option<&[Pas]>, quoi: &dyn Fn() -> String, oui_non: &mut [usize; 2]) {
    let rust = lire(&octets(m)).is_ok();
    let schema = js().valide(m);
    oui_non[usize::from(rust)] += 1;
    if rust == schema {
        return;
    }
    let permis_ = !rust
        && feuille.is_some_and(|chemin| {
            let f = suivre(m, chemin);
            js().feuille(chemin)
                .iter()
                .any(|d| d.get("x-verifie-en-rust").is_some())
                || (f.is_f64() && f.as_f64().is_some_and(|x| x.fract() == 0.0))
        });
    assert!(permis_, "{} : Rust {rust}, schéma {schema}", quoi());
}

#[test]
fn chaque_feuille_changee_tranche_pareil() {
    let base = valeur(&complet());
    let mut tous = Vec::new();
    chemins(&base, &mut Vec::new(), &mut tous);
    let mut oui_non = [0usize; 2];
    for chemin in &tous {
        let ici = suivre(&base, chemin).clone();
        match &ici {
            Value::Object(o) => {
                let mut m = base.clone();
                aller(&mut m, chemin)["inconnu"] = json!(1);
                trancher(&m, None, &|| format!("clé inconnue en {chemin:?}"), &mut oui_non);
                for k in o.keys() {
                    let mut m = base.clone();
                    aller(&mut m, chemin).as_object_mut().unwrap().remove(k);
                    trancher(&m, None, &|| format!("{k} retiré en {chemin:?}"), &mut oui_non);
                }
            }
            Value::Array(a) => {
                let mut m = base.clone();
                *aller(&mut m, chemin) = json!([]);
                trancher(&m, None, &|| format!("tableau vidé en {chemin:?}"), &mut oui_non);
                // Une copie de la première entrée, changée en un point : refusée si ce point n'est pas dans la clé
                // d'unicité (Rust : `Entree::clef`, schéma : « x-cle-unique »), acceptée sinon. Les deux pareil.
                let e0 = &a[0];
                let mut dedans = Vec::new();
                chemins(e0, &mut Vec::new(), &mut dedans);
                for sous in &dedans {
                    let mut copie_chemin = chemin.clone();
                    copie_chemin.push(Pas::Rang(1));
                    copie_chemin.extend(sous.iter().cloned());
                    let feuille = js().feuille(&copie_chemin);
                    for cand in candidats(&feuille) {
                        let mut copie = e0.clone();
                        *aller(&mut copie, sous) = cand.clone();
                        let mut m = base.clone();
                        *aller(&mut m, chemin) = json!([e0, copie]);
                        trancher(
                            &m,
                            Some(&copie_chemin),
                            &|| format!("copie avec {cand} en {copie_chemin:?}"),
                            &mut oui_non,
                        );
                    }
                    if let Some((Pas::Clef(k), parent)) = sous.split_last() {
                        let mut copie = e0.clone();
                        aller(&mut copie, parent).as_object_mut().unwrap().remove(k);
                        let mut m = base.clone();
                        *aller(&mut m, chemin) = json!([e0, copie]);
                        trancher(&m, None, &|| format!("copie sans {k} en {chemin:?}"), &mut oui_non);
                    }
                }
            }
            _ => {
                for cand in candidats(&js().feuille(chemin)) {
                    let mut m = base.clone();
                    *aller(&mut m, chemin) = cand.clone();
                    trancher(&m, Some(chemin), &|| format!("{cand} en {chemin:?}"), &mut oui_non);
                }
            }
        }
    }
    // L'essai a vu les deux issues, souvent : il n'a pas tout refusé (ou tout accepté) sans rien comparer.
    assert!(oui_non[0] > 1000 && oui_non[1] > 1000, "{oui_non:?}");
}

/// Une valeur JSON lue comme le type `T` par serde : la porte de `lire`, champ par champ.
fn lu<T: DeserializeOwned>(s: &str) -> bool {
    serde_json::from_value::<T>(Value::String(s.to_string())).is_ok()
}

/// Chaque type à motif, avec la porte Rust qui le lit. Exact : le motif accepte exactement ce que Rust accepte ;
/// sinon Rust vérifie plus (« x-verifie-en-rust ») et le motif accepte au moins tout ce que Rust accepte.
type Porte = fn(&str) -> bool;
fn motifs() -> Vec<(&'static str, Porte)> {
    vec![
        ("Version", lu::<Version>),
        ("Jour", lu::<Jour>),
        ("IdInstallation", lu::<IdInstallation>),
        ("SystemeVersion", lu::<SystemeVersion>),
        ("NomOutil", lu::<NomOutil>),
        ("Regle", lu::<Regle>),
        ("Lieu", lu::<Lieu>),
        ("Code", lu::<Code>),
        ("Gabarit", lu::<Gabarit>),
        ("TexteNettoye", lu::<TexteNettoye>),
        ("NomLogiciel", lu::<NomLogiciel>),
        ("VersionTierce", lu::<VersionTierce>),
    ]
}

fn exact(def: &str) -> bool {
    js().def(def).get("x-verifie-en-rust").is_none()
}

fn comparer_motif(def: &str, porte: Porte, s: &str) {
    let rust = porte(s);
    let schema = js().valide_def(def, &json!(s));
    if exact(def) {
        assert_eq!(rust, schema, "{def} : {s:?} (Rust {rust}, schéma {schema})");
    } else {
        assert!(!rust || schema, "{def} : Rust accepte {s:?}, le schéma le refuse");
    }
}

#[test]
fn motifs_aux_bornes() {
    let mut s = sondes();
    s.extend(
        [
            // Jour : signes, chiffres d'autres écritures, années aux bords, 29 février.
            "-202-11-01",
            "2026-1-012",
            "2026-11-1 ",
            " 026-11-01",
            "\u{FF12}026-11-01",
            "2026-11-01\n",
            "0000-01-01",
            "2024-02-29",
            "2025-02-29",
            "9999-12-31",
            // Lieu.
            "src/main.rs:0:0",
            "src/.rs:1:1",
            "src/a//b.rs:1:1",
            "src/a/b.rs:1234567:1",
            "src/a/b.rs:1:123456",
            "src/a.rs:1:1:1",
            "src/A.rs:1:1",
            "src/a.rs::1",
            // Code.
            "-",
            "-0",
            "+1",
            "01",
            "--1",
            "1234567890",
            "-1234567890",
            "DROITS",
            "droits ",
            // Versions du système, outils, identifiants.
            "1234567",
            "1.",
            ".1",
            "1.1234",
            "15",
            "a",
            "a1",
            "1a",
            "-a",
            "a--b",
            "A",
            "abcdef0123456789",
            "abcdef01234567890",
            "0.0.0",
            "01.2.3",
            "1.2",
            // Versions tierces.
            "1",
            "1.2.3-beta.4+build",
            "1.",
            "a1",
            "1aaaaaaaaaaa",
            "1.2.3~deb",
            "1:2.3",
            // Textes : marqueurs, chevrons seuls, accents combinants, invisibles.
            "échec <chemin .docx> fin",
            "échec <chemin .docxyz> fin",
            "échec <chemin .DOC> fin",
            "a < b",
            "e\u{301}cole",
            "a\u{200B}b",
            "a\u{00AD}b",
            "*gras*",
            "`code`",
            "[lien](x)",
        ]
        .map(String::from),
    );
    s.push(format!("src/{}.rs:1:1", "a".repeat(113)));
    s.push(format!("src/{}.rs:1:1", "a".repeat(114)));
    for (def, porte) in motifs() {
        for x in &s {
            comparer_motif(def, porte, x);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn motifs_au_hasard(s in prop_oneof![
        "[ -~]{0,40}",
        "[A-Za-z0-9.:/_-]{0,24}",
        "[0-9a-fA-F]{14,18}",
        "[A-Z]{2,4}-[A-Z]{2,4}-[0-9]{2,4}",
        "[0-9]{0,7}(\\.[0-9]{0,4}){0,3}",
        "[0-9]{4}-[0-9]{2}-[0-9]{2}",
        "src/[a-z_/]{0,10}\\.rs:[0-9]{0,7}:[0-9]{0,6}",
        "-?[0-9]{0,12}",
        "[a-z][a-z0-9-]{0,33}",
        "[0-9][0-9a-zA-Z.+_:~-]{0,34}",
        "\\PC{0,12}",
    ]) {
        for (def, porte) in motifs() {
            comparer_motif(def, porte, &s);
        }
    }

    #[test]
    fn textes_gardes_acceptes_par_le_schema((bruts, versions) in ouverts_bruts()) {
        for b in &bruts {
            comparer_motif("TexteNettoye", lu::<TexteNettoye>, b);
            comparer_motif("NomLogiciel", lu::<NomLogiciel>, b);
        }
        for v in &versions {
            comparer_motif("VersionTierce", lu::<VersionTierce>, v);
        }
    }
}

#[test]
fn le_motif_ouvert_suit_le_nettoyage() {
    // Les marqueurs du motif sont ceux du nettoyage, ni plus ni moins, et l'extension a la même borne.
    let mut marqueurs: Vec<&str> = Vec::new();
    for m in MARQUEURS {
        let m = m.trim_start_matches('<').trim_end_matches('>');
        if !marqueurs.contains(&m) {
            marqueurs.push(m);
        }
    }
    let fin = format!(
        "|<(?:{})>|<chemin \\.[a-z0-9]{{1,{EXTENSION_MAX}}}>)+$",
        marqueurs.join("|")
    );
    for def in ["TexteNettoye", "NomLogiciel"] {
        let p = js().def(def)["pattern"].as_str().unwrap();
        assert!(p.ends_with(&fin), "{def} : {p}");
        assert!(p.starts_with("^(?:[^"), "{def} : {p}");
        // Chaque caractère que le nettoyage garde, la classe du motif l'accepte (après une lettre, pour les accents
        // combinants) ; les chevrons seuls, non.
        let m = Motif::new(&p.replace(&fin, ")+$"));
        let classe = js().motif(p);
        for x in (0..=0x10_FFFFu32).filter_map(char::from_u32).filter(|x| permis(*x)) {
            assert!(
                m.accepte(&format!("a{x}")),
                "{def} refuse {x:?} (U+{:04X})",
                u32::from(x)
            );
        }
        for x in ('\u{0300}'..='\u{036F}').filter(|x| *x != '\u{034F}') {
            assert!(
                m.accepte(&format!("e{x}")),
                "{def} refuse l'accent U+{:04X}",
                u32::from(x)
            );
        }
        for faux in ["<", ">", "a<b", "<url", "<chemin .>", "<chemin .abcdef>", "<autre>"] {
            assert!(!classe.accepte(faux), "{def} accepte {faux:?}");
        }
    }
    let d = js().def("TexteNettoye");
    assert_eq!(d["maxLength"], json!(TEXTE_MAX));
    assert_eq!(d["x-octets-max"], json!(TEXTE_MAX));
    assert_eq!(js().def("NomLogiciel")["x-octets-max"], json!(NOM_MAX));
    assert_eq!(js().def("VersionTierce")["x-octets-max"], json!(VERSION_MAX));
}

/// Les listes fermées : identifiants de Rust (et ce que serde écrit) contre l'`enum` du schéma.
fn listes_fermees() -> Vec<(&'static str, Vec<Value>)> {
    fn ids<T: Copy + Serialize>(tous: &[T], id: fn(T) -> &'static str) -> Vec<Value> {
        tous.iter()
            .map(|x| {
                assert_eq!(
                    serde_json::to_value(x).unwrap(),
                    json!(id(*x)),
                    "serde n'écrit pas l'identifiant"
                );
                json!(id(*x))
            })
            .collect()
    }
    vec![
        ("Anciennete", ids(Anciennete::TOUS, Anciennete::id)),
        ("FamilleFine", ids(FamilleFine::TOUS, FamilleFine::id)),
        ("Arch", ids(Arch::TOUS, Arch::id)),
        ("Langue", ids(Langue::TOUS, Langue::id)),
        ("Edition", ids(Edition::TOUS, Edition::id)),
        ("Processeur", ids(Processeur::TOUS, Processeur::id)),
        ("Disque", ids(Disque::TOUS, Disque::id)),
        ("Virtuelle", ids(Virtuelle::TOUS, Virtuelle::id)),
        ("TroisEtats", ids(TroisEtats::TOUS, TroisEtats::id)),
        ("Graphique", ids(Graphique::TOUS, Graphique::id)),
        ("Sorte", ids(Sorte::TOUS, Sorte::id)),
        ("Etat", ids(Etat::TOUS, Etat::id)),
        ("Origine", ids(Origine::TOUS, Origine::id)),
        ("Levier", ids(Levier::TOUS, Levier::id)),
        ("Genre", ids(Genre::TOUS, Genre::id)),
        ("Contexte", Contexte::tous_les_id().map(|x| json!(x)).collect()),
        ("MemoireGo", MemoireGo::permises().map(|x| json!(x)).collect()),
    ]
}

#[test]
fn listes_fermees_identiques() {
    let listes = listes_fermees();
    for (def, ids) in &listes {
        assert_eq!(js().def(def)["enum"], json!(ids), "{def}");
    }
    // Chaque liste fermée de la source est dans la table (les deux de `champs` en plus).
    assert_eq!(
        SOURCE.matches("\nfermee!(").count() + 3,
        listes.len(),
        "une liste fermée manque à la table"
    );
    // Chaque définition feuille du schéma est couverte : liste fermée, type à motif, ou `Schema`.
    let mut couvertes: BTreeSet<&str> = listes.iter().map(|(d, _)| *d).collect();
    couvertes.extend(motifs().iter().map(|(d, _)| *d));
    couvertes.insert("Schema");
    let feuilles: BTreeSet<&str> = js()
        .defs()
        .iter()
        .filter(|(_, d)| d["type"] != "object")
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(feuilles, couvertes);
    assert_eq!(js().def("Schema"), &json!({"type": "integer", "const": SCHEMA}));
}

/// Un champ d'une structure de la source : nom, type écrit, attributs serde.
#[derive(Debug)]
struct Champ {
    nom: String,
    genre: String,
    attributs: String,
}

/// Les structures à champs nommés de la source (avant les essais), avec les attributs de chaque structure.
fn structures() -> BTreeMap<String, (String, Vec<Champ>)> {
    let lignes: Vec<&str> = SOURCE.lines().take_while(|l| !l.starts_with("#[cfg(test)]")).collect();
    let mut r = BTreeMap::new();
    for (i, l) in lignes.iter().enumerate() {
        let tete = l
            .strip_prefix("pub(crate) struct ")
            .or_else(|| l.strip_prefix("struct "));
        let Some(nom) = tete.and_then(|t| t.strip_suffix(" {")) else {
            continue;
        };
        let mut avant = String::new();
        for x in lignes[..i]
            .iter()
            .rev()
            .take_while(|x| x.starts_with("#[") || x.starts_with("///"))
        {
            avant.push_str(x);
        }
        let mut champs = Vec::new();
        let mut attributs = String::new();
        // Un attribut que rustfmt a coupé sur plusieurs lignes se lit jusqu'à sa fermeture `)]`.
        let mut dans_attribut = false;
        for x in lignes[i + 1..].iter().map(|x| x.trim()).take_while(|x| *x != "}") {
            if dans_attribut || x.starts_with("#[") {
                attributs.push_str(x);
                dans_attribut = !x.ends_with(']');
            } else if !x.starts_with("//") {
                let x = x.strip_prefix("pub(crate) ").unwrap_or(x);
                let (n, g) = x
                    .strip_suffix(',')
                    .and_then(|x| x.split_once(": "))
                    .unwrap_or_else(|| panic!("champ illisible : {x}"));
                champs.push(Champ {
                    nom: n.to_string(),
                    genre: g.to_string(),
                    attributs: std::mem::take(&mut attributs),
                });
            }
        }
        r.insert(nom.to_string(), (avant, champs));
    }
    r
}

fn constante(nom: &str) -> u64 {
    match nom {
        "N_MAX" => N_MAX.into(),
        "CAUSE_N_MAX" => CAUSE_N_MAX.into(),
        "MS_MAX" => MS_MAX.into(),
        "DELAI_MAX" => DELAI_MAX.into(),
        "TOTAL_MAX" => TOTAL_MAX.into(),
        "VALEUR_MAX" => VALEUR_MAX.into(),
        "COEURS_MAX" => COEURS_MAX.into(),
        "FILS_MAX" => FILS_MAX.into(),
        "CAUSES_MAX" => CAUSES_MAX as u64,
        "REGLES_MAX" => REGLES_MAX as u64,
        "RAISONS_MAX" => RAISONS_MAX as u64,
        "OBJETS_MAX" => OBJETS_MAX as u64,
        "TEXTES_MAX" => TEXTES_MAX as u64,
        "CORRECTIONS_MAX" => CORRECTIONS_MAX as u64,
        "CHOIX_MAX" => CHOIX_MAX as u64,
        "OUTILS_MAX" => OUTILS_MAX as u64,
        "CACHE_MAX" => CACHE_MAX as u64,
        "REGLAGES_MAX" => REGLAGES_MAX as u64,
        autre => panic!("constante {autre} inconnue de l'essai"),
    }
}

/// Le fragment de schéma qu'un type Rust de champ doit avoir.
fn fragment(genre: &str) -> Value {
    let entre = |g: &str, p: &str| g.strip_prefix(p).and_then(|g| g.strip_suffix('>')).map(str::to_string);
    if let Some(t) = entre(genre, "Option<") {
        fragment(&t)
    } else if let Some(m) = entre(genre, "Compte<").or_else(|| entre(genre, "Nombre<")) {
        json!({"type": "integer", "minimum": 1, "maximum": constante(&m)})
    } else if let Some(x) = entre(genre, "Liste<") {
        let (t, m) = x.split_once(", ").unwrap();
        json!({"type": "array", "items": {"$ref": format!("#/$defs/{t}")}, "minItems": 1, "maxItems": constante(m)})
    } else if genre == "bool" {
        json!({"type": "boolean"})
    } else {
        assert!(
            genre.chars().all(char::is_alphanumeric),
            "type de champ inattendu : {genre}"
        );
        json!({"$ref": format!("#/$defs/{genre}")})
    }
}

/// Le schéma sans ce qui ne valide rien (annotations) ni les clés d'unicité, vérifiées à part.
fn sans_annotations(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(
            o.iter()
                .filter(|(k, _)| !ANNOTATIONS.contains(&k.as_str()) && *k != "x-cle-unique")
                .map(|(k, x)| (k.clone(), sans_annotations(x)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(sans_annotations).collect()),
        autre => autre.clone(),
    }
}

/// Chaque valeur d'un arbre JSON, la racine comprise.
fn parcourir(v: &Value, f: &mut dyn FnMut(&Value)) {
    f(v);
    match v {
        Value::Object(o) => o.values().for_each(|x| parcourir(x, f)),
        Value::Array(a) => a.iter().for_each(|x| parcourir(x, f)),
        _ => {}
    }
}

#[test]
fn memes_champs_memes_types_memes_bornes() {
    let s = structures();
    let (_, texte_lu) = &s["TexteLu"];
    let (_, texte_envoye) = &s["TexteEnvoye"];
    let paires = |c: &[Champ]| c.iter().map(|x| (x.nom.clone(), x.genre.clone())).collect::<Vec<_>>();
    assert_eq!(
        paires(texte_lu),
        paires(texte_envoye),
        "TexteLu et TexteEnvoye divergent"
    );
    let mut vus = BTreeSet::new();
    for (nom, (avant, champs)) in &s {
        if nom == "TexteLu" {
            continue;
        }
        // Lu tout ou rien : chaque structure lue refuse les champs inconnus (TexteEnvoye par TexteLu).
        assert!(
            avant.contains("deny_unknown_fields") || avant.contains("try_from = \"TexteLu\""),
            "{nom} sans deny_unknown_fields"
        );
        let champs = if nom == "TexteEnvoye" { texte_lu } else { champs };
        let mut proprietes = serde_json::Map::new();
        let mut requis = Vec::new();
        for c in champs {
            let facultatif = c.attributs.contains("default");
            let par_type = ["Option<", "Compte<", "Liste<", "Retires"]
                .iter()
                .any(|p| c.genre.starts_with(p));
            assert_eq!(
                facultatif, par_type,
                "{nom}.{} : facultatif par le type, pas par l'attribut",
                c.nom
            );
            // Une seule écriture : chaque facultatif absent n'est pas écrit, et son null ou son vide est refusé.
            if c.genre.starts_with("Option<") {
                assert!(
                    c.attributs.contains("deserialize_with = \"present\""),
                    "{nom}.{} lirait null",
                    c.nom
                );
            }
            for (debut, saut) in [
                ("Option<", "Option::is_none"),
                ("Compte<", "Compte::est_nul"),
                ("Liste<", "Liste::est_vide"),
            ] {
                if c.genre.starts_with(debut) && nom != "TexteEnvoye" {
                    assert!(c.attributs.contains(saut), "{nom}.{} écrirait son vide", c.nom);
                }
            }
            if !facultatif {
                requis.push(json!(c.nom));
            }
            proprietes.insert(c.nom.clone(), fragment(&c.genre));
        }
        let mut attendu =
            json!({"type": "object", "additionalProperties": false, "required": requis, "properties": proprietes});
        if nom == "Retires" {
            attendu["minProperties"] = json!(1);
        }
        let ecrit = if nom == "Lot" { &js().racine } else { js().def(nom) };
        assert_eq!(sans_annotations(ecrit), attendu, "{nom} : le schéma et Rust divergent");
        vus.insert(nom.as_str());
    }
    // Chaque objet du schéma est une structure de Rust, et l'inverse.
    let objets: BTreeSet<&str> = js()
        .defs()
        .iter()
        .filter(|(_, d)| d["type"] == "object")
        .map(|(n, _)| n.as_str())
        .chain(["Lot"])
        .collect();
    assert_eq!(objets, vus);
    // Chaque tableau du schéma a sa clé d'unicité.
    let mut tableaux = 0;
    parcourir(&js().racine, &mut |v| {
        if v["type"] == "array" {
            tableaux += 1;
            assert!(
                v["x-cle-unique"].as_array().is_some_and(|c| !c.is_empty()),
                "tableau sans clé : {v}"
            );
        }
    });
    assert_eq!(tableaux, 11);
    // Ce que la troncature retire, elle le compte : un compte par tableau du lot.
    let (_, lot) = &s["Lot"];
    let (_, retires) = &s["Retires"];
    let tableaux_du_lot: BTreeSet<&str> = lot
        .iter()
        .filter(|c| c.genre.starts_with("Liste<"))
        .map(|c| c.nom.as_str())
        .collect();
    let comptes: BTreeSet<&str> = retires.iter().map(|c| c.nom.as_str()).collect();
    assert_eq!(tableaux_du_lot, comptes);
}

#[test]
fn constantes_du_schema() {
    assert_eq!(js().racine["x-lot-octets-max"], json!(LOT_MAX));
    assert_eq!(js().racine["x-corps-octets-max"], json!(CORPS_MAX));
    const { assert!(CORPS_MAX > LOT_MAX) };
    // La voie ouverte : ces trois types et eux seuls, chacun dit présenté comme une donnée, jamais en Markdown.
    let ouverts: BTreeSet<&str> = js()
        .defs()
        .iter()
        .filter(|(_, d)| d.get("x-voie").is_some())
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(
        ouverts,
        BTreeSet::from(["NomLogiciel", "TexteNettoye", "VersionTierce"])
    );
    for n in ouverts {
        let d = js().def(n);
        assert_eq!(d["x-voie"], "ouverte");
        let desc = d["description"].as_str().unwrap();
        assert!(desc.contains("donnée") && desc.contains("Markdown"), "{n} : {desc}");
    }
    // Le commentaire dit aux lecteurs du schéma ce qui ne se voit pas dans les mots-clés.
    let c = js().racine["$comment"].as_str().unwrap();
    for dit in [
        "re.fullmatch",
        "drapeau u",
        "1.0",
        "deux fois",
        "x-octets-max",
        "x-cle-unique",
        "x-voie",
        "x-verifie-en-rust",
        "Markdown",
    ] {
        assert!(c.contains(dit), "$comment ne dit pas « {dit} »");
    }
}

// --- La troncature -----------------------------------------------------------------------------------------------

/// Un lot plein partout, largement au-dessus de 96 Kio : chaque tableau à son maximum, des intérêts variés.
fn gros() -> Lot {
    let mut l = complet();
    let long = |i: usize| {
        texte(&format!(
            "le service numéro {i} de test ne répond plus après le délai prévu et la lecture du fichier de réglages \
             échoue encore une fois sur cet ordinateur, puis le second essai échoue aussi et la règle rend la main \
             sans conclure ; rien de plus à dire sur cette erreur"
        ))
    };
    let interet = |i: usize| ((i * 7) % 13 + 1) as u64;
    let quatre_codes = || {
        liste(
            ["droits", "delai", "-1234567890", "1234567890"]
                .map(|c| RaisonNombre {
                    code: Code::new(c).unwrap(),
                    n: nb(N_MAX.into()),
                })
                .into(),
        )
    };
    let r = |prefixe: &str, i: usize| regle(&format!("{prefixe}-{i:03}"));
    l.causes = liste(
        (0..CAUSES_MAX)
            .map(|i| CauseEnvoyee {
                genre: Genre::TOUS[i % Genre::TOUS.len()],
                contexte: Contexte::Wmi,
                regle: Some(r("LNX-CAU", i)),
                lieu: Lieu::new("src/machine/windows/wmi.rs:183:9"),
                code: Code::new(&format!("-{i}")),
                n: nb(interet(i)),
                duree_ms: ct(1200),
                en_plus: ct(1),
                en_moins: ct(1),
                differents: ct(1),
                gabarit: Some(Gabarit::de(&long(i))),
            })
            .collect(),
    );
    l.regles = liste(
        (0..REGLES_MAX)
            .map(|i| RegleEnvoyee {
                id: r("LNX-REG", i),
                n: nb(interet(i)),
                med_ms: ct(1500),
                p90_ms: ct(2500),
                hors_delai: ct(u64::from(i % 3 == 0)),
                problemes: ct(1),
                sains: ct(10),
                non_verifies: Compte::default(),
                // Une règle sur trois notable (dépassement et raisons) : les autres partent en premier.
                raisons: if i % 3 == 0 { quatre_codes() } else { Liste::default() },
                delai_s: nb(30),
            })
            .collect(),
    );
    l.objets = liste(
        (0..OBJETS_MAX)
            .map(|i| ObjetEnvoye {
                regle: r("LNX-OBJ", i),
                sorte: Sorte::TOUS[i % Sorte::TOUS.len()],
                nom: nom("Service de test avec un nom assez long pour peser dans le lot"),
                version: VersionTierce::lire("1.2.3-beta.4"),
                etat: Etat::Probleme,
                n: nb(interet(i)),
            })
            .collect(),
    );
    l.textes = liste(
        (0..TEXTES_MAX)
            .map(|i| TexteEnvoye::new(long(i), Contexte::Autotest, Some(r("LNX-TXT", i)), nb(interet(i))))
            .collect(),
    );
    l.corrections = liste(
        (0..CORRECTIONS_MAX)
            .map(|i| Correction {
                regle: r("LNX-COR", i),
                proposees: ct(interet(i)),
                acceptees: ct(1),
                refusees: ct(1),
                reussies: ct(1),
                echouees: ct(1),
                annulees: ct(1),
                revenues: ct(1),
                codes: quatre_codes(),
            })
            .collect(),
    );
    l.choix = liste(
        (0..CHOIX_MAX)
            .map(|i| Choix {
                regle: r("LNX-CHO", i),
                normales: ct(interet(i)),
                oublis: ct(1),
                refus: ct(1),
                echap: ct(1),
            })
            .collect(),
    );
    l.outils = liste(
        (0..OUTILS_MAX)
            .map(|i| OutilEnvoye {
                outil: NomOutil::new(&format!("outil-de-test-{i}")).unwrap(),
                origine: Origine::Ligne,
                lances: ct(interet(i)),
                finis: ct(1),
                abandonnes: ct(1),
                plantes: ct(1),
                med_ms: ct(1500),
            })
            .collect(),
    );
    l.cache = liste(
        (0..CACHE_MAX)
            .map(|i| CacheRegle {
                regle: r("LNX-CAC", i),
                repris: ct(interet(i)),
                a_neuf: ct(1),
                age_total_s: ct(36_000),
                gagne_ms: ct(45_000),
                comparees: ct(1),
                ecarts: ct(1),
            })
            .collect(),
    );
    l.reglages = liste(
        (0..REGLAGES_MAX)
            .map(|i| Reglage {
                levier: Levier::TOUS[i % Levier::TOUS.len()],
                regle: Some(r("LNX-RGL", i)),
                avant: ct(30),
                apres: ct(45),
                annule: i % 2 == 0,
            })
            .collect(),
    );
    l.retires = Retires::default();
    l
}

/// Ce qu'une étape a retiré (entrées `garde` d'avant absentes d'après) et ce qu'il en reste. Vérifie au passage que
/// l'après est l'avant moins des entrées, dans le même ordre, et que chaque partie avait moins d'intérêt que chaque
/// gardée (à égalité, la plus loin dans le tableau part la première).
fn bilan<T: Entree + PartialEq + fmt::Debug, const M: usize>(
    avant: &Liste<T, M>,
    apres: &Liste<T, M>,
    garde: impl Fn(&T) -> bool,
) -> (u64, usize) {
    let restants: BTreeSet<T::Clef> = apres.entrees().iter().map(Entree::clef).collect();
    let sous_suite: Vec<&T> = avant
        .entrees()
        .iter()
        .filter(|t| restants.contains(&t.clef()))
        .collect();
    assert_eq!(
        sous_suite,
        apres.entrees().iter().collect::<Vec<_>>(),
        "la troncature a changé ou déplacé une entrée"
    );
    let (mut partis, mut gardes) = (Vec::new(), Vec::new());
    for (i, t) in avant.entrees().iter().enumerate().filter(|(_, t)| garde(t)) {
        let rang = (t.interet(), Reverse(i));
        if restants.contains(&t.clef()) {
            gardes.push(rang);
        } else {
            partis.push(rang);
        }
    }
    if let (Some(p), Some(g)) = (partis.iter().max(), gardes.iter().min()) {
        assert!(
            p < g,
            "une entrée plus intéressante est partie avant une autre : {p:?} contre {g:?}"
        );
    }
    (partis.len() as u64, gardes.len())
}

/// La troncature suit l'ordre du plan : une étape ne commence que si les précédentes n'ont plus rien à retirer.
fn verifier_troncature(avant: &Lot, apres: &Lot) {
    let o = apres.ecrire();
    assert!(o.len() <= LOT_MAX, "{} octets après troncature", o.len());
    assert_eq!(lire(&o).as_ref(), Ok(apres));
    let (ordinaires, ordinaires_restantes) = bilan(&avant.regles, &apres.regles, |r| !r.notable());
    let (notables, notables_restantes) = bilan(&avant.regles, &apres.regles, RegleEnvoyee::notable);
    let etapes = [
        ("règles ordinaires", (ordinaires, ordinaires_restantes)),
        ("textes", bilan(&avant.textes, &apres.textes, |_| true)),
        ("objets", bilan(&avant.objets, &apres.objets, |_| true)),
        ("règles notables", (notables, notables_restantes)),
        ("cache", bilan(&avant.cache, &apres.cache, |_| true)),
        ("outils", bilan(&avant.outils, &apres.outils, |_| true)),
        ("choix", bilan(&avant.choix, &apres.choix, |_| true)),
        ("corrections", bilan(&avant.corrections, &apres.corrections, |_| true)),
        ("réglages", bilan(&avant.reglages, &apres.reglages, |_| true)),
        ("causes", bilan(&avant.causes, &apres.causes, |_| true)),
    ];
    if let Some(derniere) = etapes.iter().rposition(|(_, (partis, _))| *partis > 0) {
        for (nom, (_, restantes)) in &etapes[..derniere] {
            assert_eq!(
                *restantes, 0,
                "{nom} gardées alors que {} a été entamé",
                etapes[derniere].0
            );
        }
    }
    let r = &apres.retires;
    let attendu = |i: usize| etapes[i].1.0;
    assert_eq!(
        [
            r.regles,
            r.textes,
            r.objets,
            r.cache,
            r.outils,
            r.choix,
            r.corrections,
            r.reglages,
            r.causes
        ]
        .map(|c| u64::from(c.get())),
        [
            attendu(0) + attendu(3),
            attendu(1),
            attendu(2),
            attendu(4),
            attendu(5),
            attendu(6),
            attendu(7),
            attendu(8),
            attendu(9)
        ],
        "retires ne compte pas ce qui est parti"
    );
}

#[test]
fn troncature_dans_l_ordre() {
    let avant = gros();
    let taille = avant.ecrire().len();
    assert!(
        taille > LOT_MAX + LOT_MAX / 4,
        "le lot d'essai devrait déborder largement : {taille}"
    );
    let mut apres = avant.clone();
    apres.tronquer();
    verifier_troncature(&avant, &apres);
    // Ce lot-là entame les règles notables : textes et objets sont partis, le reste est entier.
    assert!(apres.textes.est_vide() && apres.objets.est_vide());
    assert!(apres.regles.entrees().iter().all(RegleEnvoyee::notable));
    assert!(!apres.causes.est_vide() && apres.causes.entrees().len() == CAUSES_MAX);

    // Un lot qui ne déborde que par ses règles ordinaires : seules elles partent, les notables restent.
    let mut juste = gros();
    juste.textes = Liste::default();
    juste.objets = Liste::default();
    juste.cache = Liste::default();
    let taille = juste.ecrire().len();
    assert!(taille > LOT_MAX, "{taille}");
    let mut apres = juste.clone();
    apres.tronquer();
    verifier_troncature(&juste, &apres);
    assert!(apres.retires.regles.get() > 0);
    assert_eq!(
        apres.retires.textes.get() + apres.retires.causes.get() + apres.retires.reglages.get(),
        0
    );
    let notables = |l: &Lot| l.regles.entrees().iter().filter(|r| r.notable()).count();
    assert_eq!(notables(&apres), notables(&juste));

    // Un lot qui tient déjà ne change pas.
    let mut petit = complet();
    petit.tronquer();
    assert_eq!(petit, complet());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    #[test]
    fn troncature_au_hasard(graine in any::<u64>(), t in prop::array::uniform9(0usize..=1)) {
        // Chaque tableau vide ou plein (tiré au hasard, doublons écartés) : assez de combinaisons pour que chaque
        // étape soit la dernière entamée dans l'un ou l'autre cas.
        let maxima = [CAUSES_MAX, REGLES_MAX, OBJETS_MAX, TEXTES_MAX, CORRECTIONS_MAX, CHOIX_MAX, OUTILS_MAX, CACHE_MAX, REGLAGES_MAX];
        let tailles = std::array::from_fn(|i| t[i] * maxima[i]);
        let o = Ouverts::new(&[], &[]);
        let avant = au_hasard(&mut Hasard(graine), tailles, &o);
        let mut apres = avant.clone();
        apres.tronquer();
        verifier_troncature(&avant, &apres);
    }
}

#[test]
fn arrondis() {
    for (ms, attendu) in [
        (0, 0),
        (7, 7),
        (99, 99),
        (100, 100),
        (1234, 1200),
        (99_999, 99_000),
        (u64::MAX, 18_000_000_000_000_000_000),
    ] {
        assert_eq!(arrondir_ms(ms), attendu, "{ms}");
    }
    assert_eq!(MemoireGo::arrondie(0).0, 1);
    assert_eq!(MemoireGo::arrondie(24).0, 16);
    assert_eq!(MemoireGo::arrondie(1 << 40).0, MEMOIRE_MAX);
    assert_eq!(Anciennete::de_jours(6), Anciennete::Moins7);
    assert_eq!(Anciennete::de_jours(90), Anciennete::Plus90);
    assert_eq!(Compte::<10>::new(u64::MAX).get(), 10);
    assert!(Nombre::<10>::new(0).is_none());
    assert_eq!(IdInstallation::de_octets([0xab; 8]).as_str(), "abababababababab");
    let mut l: Liste<Choix, 1> = Liste::default();
    let choix = |r: &str| Choix {
        regle: regle(r),
        normales: ct(1),
        oublis: Compte::default(),
        refus: Compte::default(),
        echap: Compte::default(),
    };
    assert!(l.pousser(choix("LNX-MAJ-001")).is_ok());
    assert!(l.pousser(choix("LNX-MAJ-002")).is_err(), "liste pleine");
    let mut l: Liste<Choix, 2> = Liste::default();
    assert!(l.pousser(choix("LNX-MAJ-001")).is_ok());
    assert!(l.pousser(choix("LNX-MAJ-001")).is_err(), "clé en double");
}

// --- Gardes sur la source ----------------------------------------------------------------------------------------

/// Les lignes de code de la source, avant les essais, sans les commentaires.
fn code() -> Vec<&'static str> {
    SOURCE
        .lines()
        .take_while(|l| !l.starts_with("#[cfg(test)]"))
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect()
}

/// Les segments de nom de champ qui diraient ce qui ne doit pas sortir.
const INTERDITS: &[&str] = &[
    "chemin",
    "commande",
    "detail",
    "message",
    "ip",
    "mac",
    "reseau",
    "compte",
    "machine",
    "hote",
    "utilisateur",
    "argument",
    "arguments",
    "fichier",
    "url",
    "courriel",
    "adresse",
    "serie",
    "ssid",
];

#[test]
fn source_sans_texte_libre() {
    // Chaque type de champ est fait de types du lot, de `bool` et des bornes : ni String, ni chemin, ni valeur JSON
    // libre, ni table.
    let s = structures();
    let noms: BTreeSet<&str> = s
        .keys()
        .map(String::as_str)
        .chain(js().defs().keys().map(String::as_str))
        .collect();
    for (st, (_, champs)) in &s {
        for c in champs {
            for mot in c
                .genre
                .split(|x: char| !x.is_alphanumeric() && x != '_')
                .filter(|m| !m.is_empty())
            {
                let permis_ = noms.contains(mot)
                    || ["Option", "Compte", "Nombre", "Liste", "bool"].contains(&mot)
                    || mot.ends_with("_MAX");
                assert!(permis_, "{st}.{} : type {mot} hors de la liste permise", c.nom);
            }
        }
    }
    // Les seules structures à un champ : les briques et les types à motif, dont le `String` est validé à l'entrée.
    let tuples: BTreeSet<String> = code()
        .iter()
        .map(|l| l.trim())
        .filter_map(|l| {
            l.strip_prefix("pub(crate) struct ")
                .or_else(|| l.strip_prefix("struct "))
        })
        .filter(|l| l.contains('('))
        .map(str::to_string)
        .collect();
    let attendus: BTreeSet<String> = [
        "Compte<const MAX: u32>(u32);",
        "Nombre<const MAX: u32>(u32);",
        "Liste<T, const MAX: usize>(Vec<T>);",
        "Visiteur<T, const MAX: usize>(PhantomData<T>);",
        "$nom(String);",
        "MemoireGo(u32);",
    ]
    .map(String::from)
    .into();
    assert_eq!(tuples, attendus);
    // Aucun nom de champ ne dit ce qui ne doit pas sortir.
    for (st, (_, champs)) in &s {
        for c in champs {
            for seg in c.nom.split('_') {
                assert!(!INTERDITS.contains(&seg), "{st}.{} : « {seg} »", c.nom);
            }
        }
    }
    // Le texte libre n'entre que par les portes de la voie ouverte (A1) : rien ici ne nettoie ni ne construit un
    // texte brut.
    for l in code() {
        for porte in ["::nettoyer(", "sans_chevrons", "passer("] {
            assert!(!l.contains(porte), "{l}");
        }
    }
}

#[test]
fn source_sans_source_exclue_ni_envoi() {
    let imports: BTreeSet<&str> = code()
        .into_iter()
        .map(str::trim)
        .filter(|l| l.starts_with("use "))
        .collect();
    let attendus: BTreeSet<&str> = [
        "use std::cmp::Reverse;",
        "use std::collections::BTreeSet;",
        "use std::fmt;",
        "use std::fmt::Write as _;",
        "use std::marker::PhantomData;",
        "use serde::de::{Error as _, SeqAccess, Visitor};",
        "use serde::{Deserialize, Deserializer, Serialize, Serializer};",
        "use crate::amelioration::texte::{Gabarit, NomLogiciel, TexteNettoye, VersionTierce};",
        "use crate::compte_rendu::champs::{Code, Contexte, Genre, Jour, Lieu, Regle, Version};",
    ]
    .into();
    assert_eq!(
        imports, attendus,
        "un import nouveau : le lot ne lit que ses propres types"
    );
    // Rien qui lise le journal, les fichiers, le réseau, la ligne de commande ou l'inventaire des logiciels, rien qui
    // envoie (plan, §1 : sources exclues ; l'envoi est à A4).
    for l in code() {
        for exclu in [
            "crate::journal",
            "crate::http",
            "crate::commande",
            "std::fs",
            "std::net",
            "std::process",
            "std::env",
            "anonymiser",
            "commande_anonyme",
            "logiciels_vus",
            "reqwest",
            "ureq",
            "TcpStream",
            "HOTES",
        ] {
            assert!(!l.contains(exclu), "« {exclu} » dans : {l}");
        }
    }
    // Aucune sorte d'objet ne désigne une source exclue.
    let sortes: BTreeSet<&str> = Sorte::TOUS.iter().map(|s| s.id()).collect();
    for exclue in [
        "dns",
        "lien",
        "https",
        "connexion-site",
        "nom-site",
        "site",
        "clavier",
        "fichier",
        "compte",
        "reseau",
        "appareil",
        "netbios",
        "nom-serveur",
        "navigateur",
        "commande",
    ] {
        assert!(!sortes.contains(exclue), "sorte exclue : {exclue}");
    }
}
