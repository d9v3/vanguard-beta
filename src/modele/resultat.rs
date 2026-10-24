//! Le résultat d'un outil de protection, séparé de son affichage : ce qu'il a jugé (des constats relisibles), ce
//! qu'il a pu vérifier (sa couverture), quand et en combien de temps. Écrit en JSON (`--json`), gardé dans
//! `examens/<outil>.json` pour le rapport, et noté dans le journal des événements (l'historique des examens).
//!
//! Pourquoi : chaque outil avait son verdict à lui (espions::Releve, perimes::Verdict…), mêlé à ce qu'il affichait ;
//! ni le rapport, ni l'historique, ni un script ne pouvaient le reprendre. `Constat` n'est pas relisible (il n'a que
//! des `&'static str`) : `ConstatEcrit` en est le reflet possédé, qui se relit.

use serde::{Deserialize, Serialize};

use super::evenement::{Evenement, Genre, Source};
use crate::machine::Constat;
use crate::risk::Niveau;

/// La version du format d'un résultat.
pub(crate) const SCHEMA: u16 = 1;

/// Le sous-dossier des derniers examens, un fichier par outil.
pub(crate) const EXAMENS: &str = "examens";

/// Les outils qui rendent déjà un `Resultat` : les autres (`registre::OUTILS`) suivront, un par livraison. Le test
/// `outils_sans_resultat` tient le compte de ceux qui restent.
pub(crate) const AVEC_RESULTAT: &[&str] = &[
    "PRO-ESP-001",
    "PRO-PER-001",
    "PRO-COU-001",
    "AUT-VAN-001",
    "PRO-DIA-001",
    "PRO-LEN-001",
    "PRO-SOR-001",
    "PRO-DIS-001",
    "PRO-ACC-001",
    "PRO-CNX-001",
    "PRO-LIE-001",
    "PRO-OBJ-001",
    "PRO-LNO-001",
];

/// Le fichier de chaque outil de `AVEC_RESULTAT`, scellé (`sceau`) : un « rien trouvé » réécrit par un programme du
/// compte s'affichait en vert dans le rapport. Inventoriés (`modele::inventaire`) ; un outil qui s'ajoute à
/// `AVEC_RESULTAT` s'ajoute ici aussi (`fichiers_scelles`).
pub(crate) const FICHIERS: [&str; 13] = [
    "examens/PRO-ESP-001.json",
    "examens/PRO-PER-001.json",
    "examens/PRO-COU-001.json",
    "examens/AUT-VAN-001.json",
    "examens/PRO-DIA-001.json",
    "examens/PRO-LEN-001.json",
    "examens/PRO-SOR-001.json",
    "examens/PRO-DIS-001.json",
    "examens/PRO-ACC-001.json",
    "examens/PRO-CNX-001.json",
    "examens/PRO-LIE-001.json",
    "examens/PRO-OBJ-001.json",
    "examens/PRO-LNO-001.json",
];

/// Le fichier scellé d'un outil, s'il en a un.
fn fichier(outil: &str) -> Option<&'static str> {
    FICHIERS
        .iter()
        .find(|f| f.strip_prefix(EXAMENS).and_then(|r| r.strip_prefix('/')) == Some(&format!("{outil}.json")))
        .copied()
}

/// Un constat tel qu'il s'écrit et se relit.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConstatEcrit {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub regle: String,
    /// L'objet jugé (« programme:Spyrix »), sans langue ; absent : reconnu à son texte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objet: Option<String>,
    pub categorie: String,
    /// « sain », « sans-objet », « non-verifie », « probleme » (`Etat::code`).
    pub etat: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub niveau: Option<Niveau>,
    /// Le code de la raison d'un « non vérifié » (`Raison::code`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raison: Option<String>,
    pub message: String,
    /// Une correction est proposée (montrée et confirmée ailleurs).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub corrigeable: bool,
}

/// Un texte venu de l'extérieur (nom de pièce jointe, de réseau, de programme), prêt à écrire dans un résultat :
/// chaque caractère piégé (`ui::piege` : contrôles, sens d'écriture, invisibles) devient « � », comme à l'écran.
/// `lignes` : le saut de ligne et la tabulation restent (mise en forme d'un message de Vanguard).
pub(crate) fn sans_piege(texte: &str, lignes: bool) -> String {
    texte
        .chars()
        .map(|x| {
            if (lignes && (x == '\n' || x == '\t')) || !crate::ui::piege(x) {
                x
            } else {
                '\u{fffd}'
            }
        })
        .collect()
}

/// Un nom venu de l'extérieur, sans piège et sur une ligne, coupé à `n` caractères (« … » compris).
pub(crate) fn nom_sans_piege(nom: &str, n: usize) -> String {
    let sur = sans_piege(nom, false);
    if sur.chars().count() <= n {
        return sur;
    }
    sur.chars()
        .take(n.saturating_sub(1))
        .chain(std::iter::once('…'))
        .collect()
}

impl From<&Constat> for ConstatEcrit {
    fn from(c: &Constat) -> ConstatEcrit {
        use super::Etat;
        let etat = c.etat();
        let (niveau, raison) = match &etat {
            Etat::Probleme { niveau } => (Some(*niveau), None),
            Etat::NonVerifie(r) => (c.probleme, Some(r.code().to_string())),
            Etat::Sain | Etat::SansObjet(_) => (None, None),
        };
        ConstatEcrit {
            regle: c.regle.to_string(),
            objet: c.objet.texte().filter(|o| !o.is_empty()).map(str::to_string),
            categorie: c.categorie.to_string(),
            etat: etat.code().to_string(),
            niveau,
            raison,
            // Défense en profondeur : un message reprend souvent un nom venu de l'extérieur (pièce jointe, réseau,
            // programme), et ce qui est écrit ici va au rapport et à `--json`. Le saut de ligne et la tabulation
            // restent (mise en forme de Vanguard) ; les autres caractères piégés deviennent « � ».
            message: sans_piege(&c.message, true),
            corrigeable: c.correctif.is_some(),
        }
    }
}

/// Ce que l'outil a pu vérifier. Jamais « sain » si quelque chose manque, ou si rien n'a été vérifié.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Couverture {
    pub verifies: u32,
    /// Ce qui n'a pas pu l'être, et pourquoi, dans la langue du moment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub non_verifies: Vec<String>,
}

/// Le résultat d'un examen.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Resultat {
    /// L'identifiant de l'outil (`registre::OUTILS`, « PRO-ESP-001 »).
    pub outil: String,
    pub schema: u16,
    /// « AAAA-MM-JJTHH:MM:SSZ ».
    pub debut: String,
    pub duree_ms: u64,
    pub couverture: Couverture,
    pub constats: Vec<ConstatEcrit>,
}

impl Resultat {
    /// Le résultat d'un examen commencé à `debut`, ses constats et sa couverture.
    pub(crate) fn nouveau(
        outil: &str,
        debut: (chrono::DateTime<chrono::Utc>, std::time::Instant),
        constats: &[Constat],
        couverture: Couverture,
    ) -> Resultat {
        Resultat {
            outil: outil.to_string(),
            schema: SCHEMA,
            debut: debut.0.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            duree_ms: u64::try_from(debut.1.elapsed().as_millis()).unwrap_or(u64::MAX),
            couverture,
            constats: constats.iter().map(ConstatEcrit::from).collect(),
        }
    }

    /// Le plus grave des problèmes trouvés.
    pub(crate) fn pire(&self) -> Option<Niveau> {
        self.constats
            .iter()
            .filter(|c| c.etat == "probleme")
            .filter_map(|c| c.niveau)
            .max()
    }

    /// Le verdict, stable : « probleme », « non-verifie » (quelque chose manque, ou rien n'a pu être vérifié),
    /// « sain » seulement quand tout ce qui devait l'être l'a été.
    pub(crate) fn verdict(&self) -> &'static str {
        if self.pire().is_some() {
            "probleme"
        } else if self.couverture.verifies == 0
            || !self.couverture.non_verifies.is_empty()
            || self.constats.iter().any(|c| c.etat == "non-verifie")
        {
            "non-verifie"
        } else {
            "sain"
        }
    }

    /// L'événement de cet examen, pour le journal. Celui de l'autotest est un essai : ni alerte, ni historique (il
    /// juge Vanguard, pas la machine).
    pub(crate) fn evenement(&self) -> Evenement {
        let mut e = Evenement::nouveau(
            Source::Outil,
            Genre::Examen {
                outil: self.outil.clone(),
                verdict: self.verdict().to_string(),
                problemes: u32::try_from(self.constats.iter().filter(|c| c.etat == "probleme").count())
                    .unwrap_or(u32::MAX),
                non_verifies: u32::try_from(self.couverture.non_verifies.len()).unwrap_or(u32::MAX),
            },
        )
        .cle(Some(&self.outil));
        e.essai = self.outil.starts_with("AUT-");
        match self.pire() {
            Some(n) => e.gravite(n),
            None => e,
        }
    }
}

/// Verse le résultat : `examens/<outil>.json` (le dernier, que le rapport reprend), et un événement au journal.
/// Un échec d'écriture ne retient pas l'affichage : il va au journal des erreurs.
pub(crate) fn verser(r: &Resultat) {
    verser_dans(&crate::socle::dossier_local(), r);
}

fn verser_dans(dossier: &std::path::Path, r: &Resultat) {
    let ecrit = serde_json::to_vec_pretty(r)
        .map_err(std::io::Error::other)
        .and_then(|o| match fichier(&r.outil) {
            Some(nom) => crate::sceau::ecrire_dans(dossier, nom, &o),
            None => Err(std::io::Error::other(format!("{} : pas de fichier scellé", r.outil))),
        });
    if let Err(e) = ecrit {
        super::Echec::io("examens/ecrire", &e).journaliser();
    }
    super::journal::noter(r.evenement());
}

/// Les derniers résultats versés, pour le rapport : ceux qui se relisent, du plus ancien au plus récent. Un
/// fichier illisible (abîmé, d'une version plus récente) est laissé de côté. Relus par leur sceau : un fichier changé
/// hors de Vanguard n'est jamais cru (son contenu peut être un « rien trouvé » forgé) et se montre non vérifié ; un
/// fichier accepté tel quel au premier sceau garde ce qu'il dit, mais n'est pas vert.
pub(crate) fn derniers() -> Vec<Resultat> {
    derniers_dans(&crate::socle::dossier_local())
}

fn derniers_dans(dossier: &std::path::Path) -> Vec<Resultat> {
    use crate::sceau::Lecture;
    let relu = |o: &[u8], id: &str| {
        serde_json::from_slice::<Resultat>(o)
            .ok()
            .filter(|r| r.schema <= SCHEMA && r.outil == id)
    };
    let mut tous: Vec<Resultat> = AVEC_RESULTAT
        .iter()
        .filter_map(|id| match crate::sceau::lire_dans(dossier, fichier(id)?) {
            Lecture::Intact(o) => relu(&o, id),
            Lecture::Adopte(o) => relu(&o, id).map(|mut r| {
                r.couverture.non_verifies.push(
                    crate::tr!(
                        "résultat accepté tel quel au premier sceau : rien ne prouve qu'il n'a pas été changé",
                        "result accepted as is at the first seal: nothing proves it was not changed"
                    )
                    .to_string(),
                );
                r
            }),
            // Rien de ce qu'il dit n'est repris : seulement la date, s'il en a une, et le non vérifié.
            Lecture::Falsifie(o) => Some(Resultat {
                outil: (*id).to_string(),
                schema: SCHEMA,
                debut: o.and_then(|o| relu(&o, id)).map(|r| r.debut).unwrap_or_default(),
                duree_ms: 0,
                couverture: Couverture {
                    verifies: 0,
                    non_verifies: vec![
                        crate::tr!(
                            "non vérifié : résultat changé hors de Vanguard",
                            "not verified: result changed outside Vanguard"
                        )
                        .to_string(),
                    ],
                },
                constats: Vec::new(),
            }),
            Lecture::Absent | Lecture::Inconnu | Lecture::Illisible(_) => None,
        })
        .collect();
    tous.sort_by(|a, b| a.debut.cmp(&b.debut));
    tous
}

/// Le résultat en JSON, pour `--json`.
pub(crate) fn json(r: &Resultat) -> String {
    serde_json::to_string_pretty(r).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{alerte, impossible, ok};
    use proptest::prelude::*;

    fn debut() -> (chrono::DateTime<chrono::Utc>, std::time::Instant) {
        (
            chrono::DateTime::parse_from_rfc3339("2026-10-23T10:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            std::time::Instant::now(),
        )
    }

    /// Un message qui reprend un nom piégé ne passe jamais tel quel dans ce qui est écrit (rapport, `--json`).
    #[test]
    fn message_ecrit_sans_piege() {
        let c = alerte(
            "Logiciels espions",
            Niveau::Eleve,
            "facture\u{202e}fdp.exe\u{1b}]52;c;x\u{7}\nsuite",
        );
        let e = ConstatEcrit::from(&c);
        assert!(
            !crate::ui::contient_un_piege(&e.message.replace('\n', "")),
            "{:?}",
            e.message
        );
        assert!(e.message.ends_with("\nsuite"), "{:?}", e.message);
    }

    /// Jamais « sain » avec un manque, ni sans rien de vérifié ; le pire problème décide.
    #[test]
    fn verdict_jamais_sain_par_defaut() {
        let sain = Resultat::nouveau(
            "PRO-ESP-001",
            debut(),
            &[ok("Logiciels espions", "Aucun signe.")],
            Couverture {
                verifies: 3,
                non_verifies: Vec::new(),
            },
        );
        assert_eq!(sain.verdict(), "sain");
        let manque = Resultat {
            couverture: Couverture {
                verifies: 3,
                non_verifies: vec!["mémoire DNS".into()],
            },
            ..sain.clone()
        };
        assert_eq!(manque.verdict(), "non-verifie");
        let rien = Resultat {
            couverture: Couverture::default(),
            ..sain.clone()
        };
        assert_eq!(rien.verdict(), "non-verifie");
        let impossible = Resultat::nouveau(
            "PRO-ESP-001",
            debut(),
            &[impossible("Logiciels espions", "rien de lisible")],
            Couverture {
                verifies: 1,
                non_verifies: Vec::new(),
            },
        );
        assert_eq!(impossible.verdict(), "non-verifie");
        let grave = Resultat::nouveau(
            "PRO-ESP-001",
            debut(),
            &[
                alerte("Logiciels espions", Niveau::Moyen, "a"),
                alerte("Logiciels espions", Niveau::Eleve, "b")
                    .avec_objet(super::super::Objet::de("programme", "Spyrix")),
            ],
            Couverture::default(),
        );
        assert_eq!(grave.verdict(), "probleme");
        assert_eq!(grave.pire(), Some(Niveau::Eleve));
        assert_eq!(grave.constats[1].objet.as_deref(), Some("programme:Spyrix"));
        let ev = grave.evenement();
        assert_eq!(ev.gravite, Some(Niveau::Eleve));
        assert!(matches!(ev.quoi, Genre::Examen { problemes: 2, .. }));
    }

    /// Versé puis relu, tel quel ; un fichier abîmé ou d'un autre outil est laissé de côté.
    #[test]
    fn verse_puis_relu() {
        let d = crate::socle::dossier_local().join("essai-examens");
        let _ = std::fs::remove_dir_all(&d);
        let r = Resultat::nouveau(
            "PRO-PER-001",
            debut(),
            &[alerte("Logiciels pas à jour", Niveau::Eleve, "Firefox 128.0")],
            Couverture {
                verifies: 7,
                non_verifies: Vec::new(),
            },
        );
        verser_dans(&d, &r);
        assert_eq!(derniers_dans(&d), vec![r.clone()]);
        // Écrit par Vanguard mais abîmé, ou d'un autre outil : laissé de côté.
        crate::sceau::ecrire_dans(&d, fichier("PRO-ESP-001").unwrap(), b"{abime").unwrap();
        let autre = Resultat {
            outil: "PRO-ESP-001".into(),
            ..r.clone()
        };
        crate::sceau::ecrire_dans(&d, fichier("PRO-COU-001").unwrap(), json(&autre).as_bytes()).unwrap();
        assert_eq!(derniers_dans(&d), vec![r]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un programme du compte réécrit le résultat d'un outil en « rien trouvé » : le sceau ne le reconnaît pas, le
    /// rapport le montre non vérifié, jamais vert, et rien de ce qu'il dit n'est repris.
    #[test]
    fn resultat_forge_jamais_vert() {
        let d = crate::socle::dossier_local().join("essai-examens-forge");
        let _ = std::fs::remove_dir_all(&d);
        let grave = Resultat::nouveau(
            "PRO-ESP-001",
            debut(),
            &[alerte("Logiciels espions", Niveau::Eleve, "programme espion trouvé")],
            Couverture {
                verifies: 3,
                non_verifies: Vec::new(),
            },
        );
        verser_dans(&d, &grave);
        let forge = Resultat::nouveau(
            "PRO-ESP-001",
            debut(),
            &[ok("Logiciels espions", "Aucun signe.")],
            Couverture {
                verifies: 3,
                non_verifies: Vec::new(),
            },
        );
        assert_eq!(forge.verdict(), "sain");
        std::fs::write(d.join(EXAMENS).join("PRO-ESP-001.json"), json(&forge)).unwrap();
        let lus = derniers_dans(&d);
        assert_eq!(lus.len(), 1);
        assert_eq!(lus[0].verdict(), "non-verifie");
        assert_eq!(lus[0].constats, Vec::<ConstatEcrit>::new());
        assert_eq!(lus[0].debut, forge.debut);
        // Effacé hors de Vanguard : non vérifié aussi.
        std::fs::remove_file(d.join(EXAMENS).join("PRO-ESP-001.json")).unwrap();
        assert_eq!(derniers_dans(&d)[0].verdict(), "non-verifie");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Chaque outil qui rend un résultat a son fichier scellé et inventorié.
    #[test]
    fn chaque_resultat_scelle() {
        assert_eq!(AVEC_RESULTAT.len(), FICHIERS.len());
        for id in AVEC_RESULTAT {
            let f = fichier(id).unwrap_or_else(|| panic!("{id} sans fichier scellé"));
            assert!(
                super::super::inventaire::scelles().any(|n| n == f),
                "{f} hors de l'inventaire"
            );
        }
    }

    /// Le compte des outils sans résultat ne fait que baisser : un outil migré s'ajoute à `AVEC_RESULTAT`, et
    /// chaque identifiant y est un outil connu.
    #[test]
    fn outils_sans_resultat() {
        const OUTILS_SANS_RESULTAT: usize = 7;
        let outils: Vec<&str> = super::super::registre::OUTILS
            .iter()
            .map(|o| o.id)
            .filter(|id| id.starts_with("PRO-") || id.starts_with("AUT-"))
            .collect();
        for id in AVEC_RESULTAT {
            assert!(outils.contains(id), "{id} : pas un outil du registre");
        }
        let restent = outils.iter().filter(|id| !AVEC_RESULTAT.contains(id)).count();
        assert!(
            restent <= OUTILS_SANS_RESULTAT,
            "{restent} outils sans résultat, plafond {OUTILS_SANS_RESULTAT} : un outil ajouté rend un Resultat"
        );
    }

    /// T10 (minimal) : le jugement des outils migrés vit dans un fichier qui n'importe pas l'interface.
    #[test]
    fn jugement_sans_interface() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protection");
        for f in [
            "espions/resultat.rs",
            "perimes/resultat.rs",
            "courriel_suspect/resultat.rs",
        ] {
            let texte = std::fs::read_to_string(racine.join(f)).unwrap();
            let code = texte.find("#[cfg(test)]\nmod ").map_or(texte.as_str(), |t| &texte[..t]);
            assert!(!code.contains("crate::ui"), "{f} importe l'interface");
        }
    }

    fn constat_ecrit() -> impl Strategy<Value = ConstatEcrit> {
        let t = "[a-zA-Zé0-9 :/|.]{0,30}";
        (
            t,
            proptest::option::of(t),
            t,
            prop_oneof![Just("sain"), Just("probleme"), Just("non-verifie"), Just("sans-objet")],
            proptest::option::of(prop_oneof![Just(Niveau::Info), Just(Niveau::Critique)]),
            proptest::option::of(t),
            t,
            any::<bool>(),
        )
            .prop_map(
                |(regle, objet, categorie, etat, niveau, raison, message, corrigeable)| ConstatEcrit {
                    regle,
                    objet,
                    categorie,
                    etat: etat.to_string(),
                    niveau,
                    raison,
                    message,
                    corrigeable,
                },
            )
    }

    proptest! {
        /// T6 : un résultat écrit puis relu est le même.
        #[test]
        fn aller_retour(constats in proptest::collection::vec(constat_ecrit(), 0..5),
                        verifies in any::<u32>(), manques in proptest::collection::vec("[a-z ]{1,20}", 0..3)) {
            let r = Resultat {
                outil: "PRO-ESP-001".into(),
                schema: SCHEMA,
                debut: "2026-10-23T10:00:00Z".into(),
                duree_ms: 12,
                couverture: Couverture { verifies, non_verifies: manques },
                constats,
            };
            let relu: Resultat = serde_json::from_str(&json(&r)).unwrap();
            prop_assert_eq!(relu, r);
        }
    }
}
