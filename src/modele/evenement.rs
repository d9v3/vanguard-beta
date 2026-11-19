//! Un événement du journal commun (`journal`) : ce que Vanguard a vu, relevé, fait, défait ou accepté, daté en UTC,
//! avec ce dont il parle (sa clé) et ce qui l'a causé (l'identifiant d'un autre événement). L'alerte d'un serveur de
//! botnet, la preuve relevée avant le blocage, le blocage et son annulation sont ainsi quatre lignes reliées, au lieu
//! de deux ou trois alertes sans lien entre elles.
//!
//! Le texte montré (titre, ce qui a été fait) est gardé dans la langue du moment : c'est la clé, jamais traduite, qui
//! compare. Une sorte d'événement écrite par une version plus récente se relit `Inconnu` : gardée telle quelle sur
//! le disque (le journal ne se réécrit jamais), jamais jugée.

use serde::{Deserialize, Serialize};

use crate::risk::Niveau;

/// La version du format d'un événement : une version plus ancienne qui lit un événement plus récent sait au moins
/// qu'elle ne le comprend pas en entier.
pub(crate) const FORMAT: u16 = 1;

/// Longueur gardée d'un texte d'événement, en caractères : un nom choisi par n'importe qui (appareil, fichier) ne
/// doit pas gonfler le journal.
const TEXTE_MAX: usize = 1000;
/// Commandes gardées pour une correction : ce qu'il faut pour la reconnaître, pas un second relevé des changements.
const COMMANDES_MAX: usize = 10;

/// Qui a produit l'événement.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Source {
    /// La surveillance horaire (alertes de la machine, du réseau, des fichiers).
    Surveillance,
    /// Le veilleur (Linux), entre deux passes.
    Veilleur,
    /// La protection active : un blocage, la preuve relevée avant.
    Blocage,
    /// Une analyse lancée à la main (antivirus, YARA) qui isole ou supprime un fichier.
    Analyse,
    /// Une correction du bilan, d'Optimiser ou de Réparer, après accord.
    Correction,
    /// Un choix de l'utilisateur (une alerte déclarée normale, puis oubliée).
    Utilisateur,
    /// Vanguard lui-même (passage de version, rupture du journal).
    Vanguard,
    /// Un outil de protection lancé seul (`modele::resultat`).
    Outil,
    /// La porte de lecture des assistants d'IA (`vanguard mcp`, `porte_mcp`).
    PorteMcp,
    /// Une source écrite par une version plus récente.
    #[serde(other)]
    Autre,
}

/// Ce qui s'est passé.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "sorte", rename_all = "kebab-case")]
pub(crate) enum Genre {
    /// Une alerte notifiée : `famille` est le genre stable du tableau de bord (« botnet », « blocage »).
    Alerte {
        famille: String,
        titre: String,
        texte: String,
    },
    /// Ce qui a été relevé juste avant un geste (`protection::preuve`).
    Preuve { releve: crate::protection::preuve::Preuve },
    /// Un geste : blocage, quarantaine, suppression, correction. `blocage` : l'identifiant du blocage noté dans les
    /// changements (ce qui l'annule) ; `annulable` : celui de la note qui garde les valeurs d'avant d'une correction.
    Action {
        quoi: String,
        reussi: bool,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        automatique: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blocage: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annulable: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        commandes: Vec<String>,
    },
    /// Un geste défait (`objet` : l'identifiant du blocage ou de la note), ou un fichier isolé supprimé pour de bon
    /// depuis la quarantaine (`supprime`). `cause` pointe l'Action quand elle est connue.
    Annulation {
        objet: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        supprime: bool,
    },
    /// Une alerte déclarée normale (« c'est normal ») pour 90 jours.
    Normale { titre: String },
    /// Une alerte normale oubliée : elle revient.
    NormaleOubliee,
    /// Une autre version de Vanguard écrit le journal (`de` : celle d'avant, absente au premier événement).
    Version {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        de: Option<String>,
        vers: String,
    },
    /// À l'écriture, la fin du journal n'était pas celle que sa tête scellée attendait (lignes retirées, tête
    /// effacée) : la rupture est notée dans le journal même, qui ne la fait jamais oublier.
    Rupture { attendu: String, trouve: String },
    /// L'examen d'un outil de protection (`modele::resultat`) : son verdict stable (« sain », « non-verifie »,
    /// « probleme »), le nombre de problèmes et de points non vérifiés ; le détail est dans `examens/<outil>.json`.
    Examen {
        outil: String,
        verdict: String,
        problemes: u32,
        non_verifies: u32,
    },
    /// Une session de la porte de lecture des assistants d'IA (`porte_mcp`) : sa durée, ses appels par outil et ses
    /// refus par code (des noms fermés, jamais ce que le client a envoyé), et pourquoi elle s'est finie.
    SessionPorte {
        duree_s: u64,
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        appels: std::collections::BTreeMap<String, u32>,
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        refus: std::collections::BTreeMap<String, u32>,
        /// « ouverte » pour la note du premier appel servi (écrite avant sa réponse), sinon la fin de la session.
        fin: String,
        /// Les notes de session et les alertes que le frein de l'heure a retenues depuis la note d'avant
        /// (`journal::PORTE_NOTES_PAR_HEURE`) ; `retenues_au_moins` : le compte était plein, il y en a eu plus.
        #[serde(default, skip_serializing_if = "est_zero")]
        retenues: u32,
        #[serde(default, skip_serializing_if = "est_zero")]
        alertes_retenues: u32,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        retenues_au_moins: bool,
    },
    /// Écrit par une version plus récente : gardé tel quel, jamais jugé.
    #[serde(other)]
    Inconnu,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // la forme que demande `skip_serializing_if`
fn est_zero(n: &u32) -> bool {
    *n == 0
}

impl Genre {
    /// Le nom stable de la sorte, pour l'affichage compact et les scripts.
    pub(crate) fn sorte(&self) -> &'static str {
        match self {
            Genre::Alerte { .. } => "alerte",
            Genre::Preuve { .. } => "preuve",
            Genre::Action { .. } => "action",
            Genre::Annulation { .. } => "annulation",
            Genre::Normale { .. } => "normale",
            Genre::NormaleOubliee => "normale-oubliee",
            Genre::Version { .. } => "version",
            Genre::Rupture { .. } => "rupture",
            Genre::Examen { .. } => "examen",
            Genre::SessionPorte { .. } => "session-porte",
            Genre::Inconnu => "inconnu",
        }
    }
}

/// Une ligne du journal.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Evenement {
    pub v: u16,
    /// Unique : l'heure, le processus, un compteur et quatre octets tirés au hasard.
    pub id: String,
    /// « AAAA-MM-JJTHH:MM:SSZ », en UTC : un changement d'heure ne met pas deux événements dans le désordre.
    pub quand: String,
    pub source: Source,
    /// La gravité portée par l'événement, et non plus devinée de son genre à l'affichage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gravite: Option<Niveau>,
    /// Ce dont il parle, stable et jamais traduit (« botnet|… », « connexion:203.0.113.7 », « LNX-PFE-001|… »).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cle: Option<String>,
    /// L'événement qui l'a causé : l'alerte pour la preuve, la preuve pour le geste, le geste pour l'annulation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    /// Produit par un essai (autotest) : ni alerte, ni historique.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub essai: bool,
    pub quoi: Genre,
    /// L'empreinte des octets exacts de la ligne d'avant (`journal`), posée à l'écriture.
    #[serde(default)]
    pub precedent: String,
}

/// Les `max` premiers caractères, coupés à la dernière espace, suivis de « … » s'il y en avait plus. Coupé au milieu,
/// un secret ou un chemin à cheval sur la borne laissait son début, trop court pour que le masquage le reconnaisse
/// (relecture 0.97) ; ce qui est à cheval disparaît entier.
pub(crate) fn borne(texte: &str, max: usize) -> String {
    match texte.char_indices().nth(max) {
        Some((i, _)) => {
            let debut = &texte[..i];
            let fin = debut.rfind(char::is_whitespace).unwrap_or(0);
            format!("{}…", &debut[..fin])
        }
        None => texte.to_string(),
    }
}

/// Les `max` premiers caractères, coupés net : pour la clé, qui reconnaît une alerte déjà vue et n'est pas un texte
/// montré. Coupée à une espace, deux longues clés sans espace devenaient toutes deux « … » et se confondaient
/// (relecture 0.97, bas).
fn borne_cle(cle: &str, max: usize) -> String {
    cle.char_indices()
        .nth(max)
        .map_or_else(|| cle.to_string(), |(i, _)| cle[..i].to_string())
}

/// Un identifiant neuf : l'heure, le processus et un compteur suffisent dans un processus ; les quatre octets tirés au
/// hasard séparent deux Vanguard lancés dans la même seconde avec le même numéro (un conteneur, une autre machine
/// qui partage le dossier).
fn nouvel_id(quand: chrono::DateTime<chrono::Utc>) -> String {
    static SUITE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = SUITE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut sel = [0u8; 4];
    let _ = getrandom::fill(&mut sel);
    format!(
        "{}-{:x}-{n}-{:08x}",
        quand.format("%Y%m%dT%H%M%S"),
        std::process::id(),
        u32::from_le_bytes(sel)
    )
}

impl Evenement {
    /// Un événement daté de maintenant.
    pub(crate) fn nouveau(source: Source, quoi: Genre) -> Evenement {
        Evenement::le(source, quoi, chrono::Utc::now())
    }

    /// Un événement daté de `quand` (les tests datent leurs journaux).
    pub(crate) fn le(source: Source, quoi: Genre, quand: chrono::DateTime<chrono::Utc>) -> Evenement {
        Evenement {
            v: FORMAT,
            id: nouvel_id(quand),
            quand: quand.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            source,
            gravite: None,
            cle: None,
            cause: None,
            essai: false,
            quoi,
            precedent: String::new(),
        }
    }

    pub(crate) fn gravite(mut self, n: Niveau) -> Evenement {
        self.gravite = Some(n);
        self
    }

    pub(crate) fn cle(mut self, cle: Option<&str>) -> Evenement {
        self.cle = cle.map(|c| borne_cle(c, TEXTE_MAX));
        self
    }

    pub(crate) fn cause(mut self, cause: Option<&str>) -> Evenement {
        self.cause = cause.map(str::to_string);
        self
    }

    /// Une alerte notifiée.
    pub(crate) fn alerte(source: Source, famille: &str, titre: &str, texte: &str) -> Evenement {
        Evenement::nouveau(
            source,
            Genre::Alerte {
                famille: famille.to_string(),
                titre: borne(titre, TEXTE_MAX / 5),
                texte: borne(texte, TEXTE_MAX),
            },
        )
    }

    /// Un geste, avec ses commandes bornées.
    pub(crate) fn action(source: Source, quoi: &str, reussi: bool, commandes: &[String]) -> Evenement {
        Evenement::nouveau(
            source,
            Genre::Action {
                quoi: borne(quoi, TEXTE_MAX),
                reussi,
                automatique: false,
                blocage: None,
                annulable: None,
                commandes: commandes
                    .iter()
                    .take(COMMANDES_MAX)
                    .map(|c| borne(c, TEXTE_MAX / 2))
                    .collect(),
            },
        )
    }

    /// L'heure de cet ordinateur (« AAAA-MM-JJ HH:MM:SS »), comme le tableau de bord et les traces la montrent.
    pub(crate) fn date_locale(&self) -> Option<String> {
        let utc = chrono::DateTime::parse_from_rfc3339(&self.quand).ok()?;
        Some(
            utc.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        )
    }

    /// Ce qu'il dit, en une ligne : pour `vanguard evenements` et les traces.
    pub(crate) fn resume(&self) -> String {
        match &self.quoi {
            Genre::Alerte { titre, texte, .. } => format!("{titre} : {texte}"),
            Genre::Preuve { releve } => releve.resume(),
            Genre::Action { quoi, reussi, .. } => {
                if *reussi {
                    quoi.clone()
                } else {
                    format!("{quoi} (échec/failed)")
                }
            }
            Genre::Annulation { objet, supprime } => {
                if *supprime {
                    format!("supprimé/deleted {objet}")
                } else {
                    format!("annulé/undone {objet}")
                }
            }
            Genre::Normale { titre } => format!("normale/normal : {titre}"),
            Genre::NormaleOubliee => "normale oubliée/normal forgotten".to_string(),
            Genre::Version { de, vers } => match de {
                Some(d) => format!("{d} → {vers}"),
                None => format!("{vers} (premier événement/first event)"),
            },
            Genre::Rupture { attendu, trouve } => {
                format!("rupture : attendu/expected {attendu}, trouvé/found {trouve}")
            }
            Genre::Examen {
                outil,
                verdict,
                problemes,
                non_verifies,
            } => format!(
                "{outil} : {verdict} ({problemes} problème(s)/problem(s), {non_verifies} non vérifié(s)/not checked)"
            ),
            Genre::SessionPorte { duree_s, fin, .. } => {
                format!("porte de lecture des assistants/assistants' read-only door : {duree_s} s, fin/end {fin}")
            }
            Genre::Inconnu => "?".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Relecture 0.97 : la coupe se fait à une espace ; un jeton à cheval sur la borne disparaît entier (valeur
    /// inventée), au lieu de laisser un début trop court pour être masqué.
    #[test]
    fn borne_coupe_a_une_espace() {
        assert_eq!(borne("ab ghp_aB3dE5fG7hJ9kL1m fin", 10), "ab…");
        assert_eq!(borne("sans_espace_du_tout", 5), "…");
        assert_eq!(borne("court", 10), "court");
    }

    /// Deux longues clés sans espace restent distinctes (valeurs inventées).
    #[test]
    fn longues_cles_distinctes() {
        let a = Evenement::le(Source::Vanguard, Genre::NormaleOubliee, quand())
            .cle(Some(&format!("blocage|/a{}", "x".repeat(2000))));
        let b = Evenement::le(Source::Vanguard, Genre::NormaleOubliee, quand())
            .cle(Some(&format!("blocage|/b{}", "x".repeat(2000))));
        assert_eq!(a.cle.as_deref().map(|c| c.chars().count()), Some(TEXTE_MAX));
        assert_ne!(a.cle, b.cle);
        assert_eq!(borne_cle("abcdef", 3), "abc");
    }
    use proptest::prelude::*;

    fn quand() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-23T14:05:09Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn identifiants_uniques_et_dates_utc() {
        let a = Evenement::le(Source::Vanguard, Genre::NormaleOubliee, quand());
        let b = Evenement::le(Source::Vanguard, Genre::NormaleOubliee, quand());
        assert_ne!(a.id, b.id);
        assert!(a.id.starts_with("20261023T140509-"), "{}", a.id);
        assert_eq!(a.quand, "2026-10-23T14:05:09Z");
        assert!(a.date_locale().is_some());
    }

    /// Une sorte ou une source écrite par une version plus récente se relit sans erreur, `Inconnu` et `Autre` : la
    /// ligne reste au journal, rien ne la juge.
    #[test]
    fn sorte_plus_recente_relue_inconnue() {
        let ligne = r#"{"v":2,"id":"x","quand":"2026-10-23T14:05:09Z","source":"rancongiciel","quoi":{"sorte":"rafale","n":3},"precedent":""}"#;
        let e: Evenement = serde_json::from_str(ligne).unwrap();
        assert_eq!(e.quoi, Genre::Inconnu);
        assert_eq!(e.source, Source::Autre);
        assert_eq!(e.v, 2);
    }

    #[test]
    fn textes_bornes() {
        let long = "é".repeat(5000);
        let e = Evenement::alerte(Source::Surveillance, "port", &long, &long).cle(Some(&long));
        let Genre::Alerte { titre, texte, .. } = &e.quoi else {
            panic!()
        };
        assert!(titre.chars().count() <= TEXTE_MAX / 5 + 1);
        assert!(texte.chars().count() <= TEXTE_MAX + 1);
        assert!(e.cle.unwrap().chars().count() <= TEXTE_MAX + 1);
        let cmd: Vec<String> = (0..50).map(|i| format!("ufw deny {i}")).collect();
        let Genre::Action { commandes, .. } = Evenement::action(Source::Correction, "x", true, &cmd).quoi else {
            panic!()
        };
        assert_eq!(commandes.len(), COMMANDES_MAX);
    }

    fn genre() -> impl Strategy<Value = Genre> {
        let t = "[a-zA-Zé0-9 :/|.\"\\\\]{0,40}";
        prop_oneof![
            (t, t, t).prop_map(|(famille, titre, texte)| Genre::Alerte { famille, titre, texte }),
            (t, any::<bool>(), any::<bool>(), proptest::option::of(t)).prop_map(|(quoi, reussi, automatique, b)| {
                Genre::Action {
                    quoi,
                    reussi,
                    automatique,
                    blocage: b.clone(),
                    annulable: b,
                    commandes: vec!["ufw deny 23".into()],
                }
            }),
            (t, any::<bool>()).prop_map(|(objet, supprime)| Genre::Annulation { objet, supprime }),
            t.prop_map(|titre| Genre::Normale { titre }),
            Just(Genre::NormaleOubliee),
            (proptest::option::of(t), t).prop_map(|(de, vers)| Genre::Version { de, vers }),
            (t, t).prop_map(|(attendu, trouve)| Genre::Rupture { attendu, trouve }),
            (t, t, any::<u32>()).prop_map(|(outil, verdict, n)| Genre::Examen {
                outil,
                verdict,
                problemes: n,
                non_verifies: n / 2
            }),
            (t, any::<u32>()).prop_map(|(chemin, pid)| Genre::Preuve {
                releve: crate::protection::preuve::Preuve {
                    date: "2026-10-23 10:00:00".into(),
                    processus: Some(crate::protection::preuve::Processus {
                        pid,
                        ..Default::default()
                    }),
                    fichier: Some(crate::protection::preuve::Fichier {
                        chemin,
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            }),
        ]
    }

    proptest! {
        /// T6 : un événement écrit puis relu est le même, quelle que soit sa sorte.
        #[test]
        fn aller_retour(quoi in genre(), cle in proptest::option::of("[a-z|:0-9./]{1,30}"),
                        cause in proptest::option::of("[a-z0-9-]{1,20}"), essai in any::<bool>()) {
            let mut e = Evenement::le(Source::Blocage, quoi, quand())
                .gravite(Niveau::Critique)
                .cle(cle.as_deref())
                .cause(cause.as_deref());
            e.essai = essai;
            let relu: Evenement = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
            prop_assert_eq!(relu, e);
        }
    }
}
