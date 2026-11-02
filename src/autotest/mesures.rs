//! Le journal des mesures : combien de temps chaque règle du bilan a pris, à chaque bilan (manuel ou horaire), gardé
//! en résumé par jour pendant 8 semaines dans `autotest/mesures.json`. À part du journal des événements, qui garde
//! les décisions, pas la télémétrie ; jamais envoyé, il sert à voir une règle qui ralentit.
//!
//! Limites dites : les règles tournent en parallèle, une durée est « au mur », gonflée par les voisines. Deux
//! processus (surveillance et bilan manuel) peuvent noter en même temps : `ecrire_atomique` évite le fichier cassé,
//! pas la mesure perdue (statistique, accepté). Scellé (`sceau`) depuis la 0.89.1 : il ne décide d'aucune alerte, mais
//! de l'auto-réglage (`super::reglage` : ordre de départ des règles, délai monté d'une règle qui frôle le sien) ; un
//! fichier douteux vaut un fichier vide, et sa lecture est bornée.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Le fichier, sous le dossier de données.
pub(crate) const MESURES: &str = "autotest/mesures.json";
/// Au-delà, ce n'est pas le fichier de Vanguard (le vrai fait quelques centaines de Kio au plus).
const TAILLE_MAX: u64 = 4 << 20;
/// Jours gardés : 8 semaines.
const JOURS_GARDES: i64 = 56;
/// Durées gardées par règle pour le jour en cours (la médiane du jour se calcule sur elles).
const PAR_JOUR_MAX: usize = 48;
/// Une règle régresse quand sa médiane de la semaine dépasse ce multiple de celle des 4 semaines d'avant…
const FACTEUR: u64 = 3;
/// … et ce seuil (en millisecondes) : une règle de 20 ms qui passe à 70 ms ne gêne personne.
const SEUIL_MS: u64 = 5_000;
/// Avant 5 semaines de mesures, rien n'est conclu.
const JOURS_MIN: usize = 35;

/// Le résumé d'un jour pour une règle (millisecondes).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Resume {
    pub n: u32,
    pub min: u64,
    pub med: u64,
    pub max: u64,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub(crate) struct Mesures {
    pub v: u16,
    /// Le jour en cours (« AAAA-MM-JJ ») et ses durées brutes, par règle.
    #[serde(default)]
    pub jour: String,
    #[serde(default)]
    pub en_cours: BTreeMap<String, Vec<u64>>,
    /// Les jours clos : jour → règle → résumé.
    #[serde(default)]
    pub jours: BTreeMap<String, BTreeMap<String, Resume>>,
    /// Ce que la cache des passages automatiques a fait de chaque règle de sa table (`super::cache::TABLE`) : des
    /// nombres seulement, rangés sous l'identifiant de la règle.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cache: BTreeMap<String, Cache>,
}

/// Comparaisons récentes gardées par règle : ce que juge l'auto-réglage pour raccourcir une durée.
const RECENTES_MAX: usize = 16;

/// Les mesures de la cache pour une règle, depuis le début (des nombres, jamais un texte lu sur la machine).
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cache {
    /// Résultats repris au lieu d'être vérifiés.
    #[serde(default)]
    pub repris: u32,
    /// Vérifications à neuf de la règle par un passage automatique.
    #[serde(default)]
    pub a_neuf: u32,
    /// La somme des âges des résultats repris (s) : l'âge moyen est `age_total_s / repris`.
    #[serde(default)]
    pub age_total_s: u64,
    /// Le temps gagné (ms) : pour chaque reprise, la médiane de la semaine de la règle.
    #[serde(default)]
    pub gagne_ms: u64,
    /// Vérifications à neuf juste après une reprise, et celles dont l'état différait du résultat repris.
    #[serde(default)]
    pub comparees: u32,
    #[serde(default)]
    pub ecarts: u32,
    /// Les dernières comparaisons : (date du passage en secondes depuis 1970, écart), 16 au plus.
    #[serde(default)]
    pub recentes: Vec<(i64, bool)>,
}

impl Cache {
    /// L'âge moyen d'un résultat repris (s).
    pub(crate) fn age_moyen_s(&self) -> u64 {
        self.age_total_s.checked_div(u64::from(self.repris)).unwrap_or(0)
    }
}

fn mediane(v: &mut [u64]) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let Some(&milieu) = v.get(v.len() / 2) else { return 0 };
    milieu
}

fn resumer(durees: &[u64]) -> Resume {
    let mut v = durees.to_vec();
    Resume {
        n: u32::try_from(v.len()).unwrap_or(u32::MAX),
        min: v.iter().copied().min().unwrap_or(0),
        max: v.iter().copied().max().unwrap_or(0),
        med: mediane(&mut v),
    }
}

/// Le fichier relu : `None` s'il est absent ; un fichier trop gros, tube, lien ou illisible vaut un fichier vide
/// (on repart de zéro plutôt que de bloquer le bilan).
pub(crate) fn lire_de(octets: &[u8]) -> Mesures {
    serde_json::from_slice::<Mesures>(octets)
        .ok()
        .filter(|m| m.v <= 1 && m.jours.len() <= 400 && m.en_cours.len() <= 2_000)
        .map(|mut m| {
            m.cache.retain(|r, _| super::cache::en_cache(r).is_some());
            for c in m.cache.values_mut() {
                let trop = c.recentes.len().saturating_sub(RECENTES_MAX);
                c.recentes.drain(..trop);
            }
            m
        })
        .unwrap_or_default()
}

fn lire_dans(dossier: &std::path::Path) -> Mesures {
    crate::sceau::juge_dans(dossier, MESURES)
        .cru()
        .filter(|o| u64::try_from(o.len()).is_ok_and(|n| n <= TAILLE_MAX))
        .map_or_else(Mesures::default, |o| lire_de(&o))
}

/// Les mesures de cet ordinateur (scellées ; douteuses : vides).
pub(crate) fn lues() -> Mesures {
    lire_dans(&crate::socle::dossier_local())
}

impl Mesures {
    /// Ajoute les durées d'un bilan au jour `jour`, clôt les jours passés, oublie ceux de plus de 8 semaines.
    pub(crate) fn ajouter(&mut self, durees: &[(&str, Duration)], jour: chrono::NaiveDate) {
        let texte = jour.format("%Y-%m-%d").to_string();
        if self.jour != texte {
            if !self.jour.is_empty() && !self.en_cours.is_empty() {
                let clos: BTreeMap<String, Resume> =
                    self.en_cours.iter().map(|(r, d)| (r.clone(), resumer(d))).collect();
                self.jours.insert(self.jour.clone(), clos);
            }
            self.en_cours.clear();
            self.jour = texte;
        }
        for (regle, d) in durees {
            let v = self.en_cours.entry((*regle).to_string()).or_default();
            if v.len() < PAR_JOUR_MAX {
                v.push(u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            }
        }
        let limite = (jour - chrono::Duration::days(JOURS_GARDES))
            .format("%Y-%m-%d")
            .to_string();
        self.jours.retain(|j, _| *j > limite);
        self.v = 1;
    }

    /// Les médianes par jour d'une règle, des jours `de` à `a` jours avant `aujourd_hui` (aujourd'hui compris : 0).
    fn medianes(&self, regle: &str, aujourd_hui: chrono::NaiveDate, de: i64, a: i64) -> Vec<u64> {
        let mut v = Vec::new();
        for ecart in de..=a {
            let jour = (aujourd_hui - chrono::Duration::days(ecart))
                .format("%Y-%m-%d")
                .to_string();
            if jour == self.jour {
                if let Some(d) = self.en_cours.get(regle) {
                    v.push(resumer(d).med);
                }
            } else if let Some(r) = self.jours.get(&jour).and_then(|j| j.get(regle)) {
                v.push(r.med);
            }
        }
        v
    }

    fn max_semaine(&self, regle: &str, aujourd_hui: chrono::NaiveDate) -> u64 {
        (0..7)
            .filter_map(|ecart| {
                let jour = (aujourd_hui - chrono::Duration::days(ecart))
                    .format("%Y-%m-%d")
                    .to_string();
                if jour == self.jour {
                    self.en_cours.get(regle).and_then(|d| d.iter().copied().max())
                } else {
                    self.jours.get(&jour).and_then(|j| j.get(regle)).map(|r| r.max)
                }
            })
            .max()
            .unwrap_or(0)
    }

    /// Note ce que la cache a fait à ce passage (`super::cache::Evenement`), le jour `jour` : le temps gagné par une
    /// reprise est la médiane de la semaine de la règle, mesurée sur ses vérifications à neuf.
    pub(crate) fn ajouter_cache(&mut self, evenements: &[super::cache::Evenement], jour: chrono::NaiveDate) {
        use super::cache::Evenement;
        for ev in evenements {
            match ev {
                Evenement::Repris { regle, age_s } => {
                    let gagne = mediane(&mut self.medianes(regle, jour, 0, 6));
                    let c = self.cache.entry((*regle).to_string()).or_default();
                    c.repris = c.repris.saturating_add(1);
                    c.age_total_s = c.age_total_s.saturating_add(*age_s);
                    c.gagne_ms = c.gagne_ms.saturating_add(gagne);
                }
                Evenement::ANeuf { regle } => {
                    let c = self.cache.entry((*regle).to_string()).or_default();
                    c.a_neuf = c.a_neuf.saturating_add(1);
                }
                Evenement::Compare { regle, ecart, quand } => {
                    let c = self.cache.entry((*regle).to_string()).or_default();
                    c.comparees = c.comparees.saturating_add(1);
                    c.ecarts = c.ecarts.saturating_add(u32::from(*ecart));
                    c.recentes.push((*quand, *ecart));
                    let trop = c.recentes.len().saturating_sub(RECENTES_MAX);
                    c.recentes.drain(..trop);
                }
            }
        }
        self.cache.retain(|r, _| super::cache::en_cache(r).is_some());
        self.v = 1;
    }

    /// Les jours où quelque chose a été mesuré.
    fn jours_mesures(&self) -> usize {
        self.jours.len() + usize::from(!self.en_cours.is_empty())
    }
}

/// Note les durées d'un bilan. Pendant un autotest manuel, rien n'est noté : ses durées vont dans son résultat.
pub(crate) fn noter(durees: &[(&str, Duration)]) {
    noter_avec(durees, &[]);
}

/// `noter`, avec ce que la cache a fait à ce passage automatique, en une écriture.
pub(crate) fn noter_avec(durees: &[(&str, Duration)], evenements: &[super::cache::Evenement]) {
    noter_dans(
        &crate::socle::dossier_local(),
        durees,
        evenements,
        chrono::Local::now().date_naive(),
    );
}

fn noter_dans(
    dossier: &std::path::Path,
    durees: &[(&str, Duration)],
    evenements: &[super::cache::Evenement],
    jour: chrono::NaiveDate,
) {
    if (durees.is_empty() && evenements.is_empty())
        || super::lecture_seule::active()
        || !crate::socle::ecriture_sure(dossier)
    {
        return;
    }
    let mut m = lire_dans(dossier);
    m.ajouter(durees, jour);
    m.ajouter_cache(evenements, jour);
    if let Ok(o) = serde_json::to_vec(&m) {
        let _ = crate::sceau::ecrire_dans(dossier, MESURES, &o);
    }
}

/// Une règle lente : sa médiane de la semaine et celle des 4 semaines d'avant (ms).
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Lente {
    pub regle: String,
    pub semaine_ms: u64,
    pub avant_ms: u64,
}

/// Une règle qui frôle son délai : sa plus longue durée de la semaine et son délai (ms).
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Frole {
    pub regle: String,
    pub max_ms: u64,
    pub delai_ms: u64,
}

/// Le verdict des mesures.
#[allow(clippy::struct_field_names)] // « verdict » : le nom du champ dans le JSON, comme ailleurs
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Verdict {
    /// « pas-assez » (moins de 5 semaines : non vérifié, jamais « aucune régression »), « sans-regression »,
    /// « regressions ».
    pub verdict: &'static str,
    pub jours: usize,
    pub lentes: Vec<Lente>,
    pub frolent_le_delai: Vec<Frole>,
}

/// Juge les mesures : régressions (médiane de la semaine > 3 × celle des 4 semaines d'avant, et > 5 s), règles au-delà
/// de la moitié de leur délai. `delai` : le délai de chaque règle.
pub(crate) fn juger(m: &Mesures, aujourd_hui: chrono::NaiveDate, delai: impl Fn(&str) -> Duration) -> Verdict {
    let regles: std::collections::BTreeSet<&String> = m
        .en_cours
        .keys()
        .chain(m.jours.values().flat_map(BTreeMap::keys))
        .collect();
    let mut lentes = Vec::new();
    let mut frolent = Vec::new();
    let assez = m.jours_mesures() >= JOURS_MIN;
    for r in regles {
        let max = m.max_semaine(r, aujourd_hui);
        let delai_ms = u64::try_from(delai(r).as_millis()).unwrap_or(u64::MAX);
        if max > delai_ms / 2 {
            frolent.push(Frole {
                regle: r.clone(),
                max_ms: max,
                delai_ms,
            });
        }
        if !assez {
            continue;
        }
        let semaine = mediane(&mut m.medianes(r, aujourd_hui, 0, 6));
        let avant = m.medianes(r, aujourd_hui, 7, 34);
        if avant.is_empty() {
            continue;
        }
        let avant = mediane(&mut avant.clone());
        if semaine > SEUIL_MS && semaine > avant.saturating_mul(FACTEUR) {
            lentes.push(Lente {
                regle: r.clone(),
                semaine_ms: semaine,
                avant_ms: avant,
            });
        }
    }
    let verdict = if !lentes.is_empty() {
        "regressions"
    } else if assez {
        "sans-regression"
    } else {
        "pas-assez"
    };
    Verdict {
        verdict,
        jours: m.jours_mesures(),
        lentes,
        frolent_le_delai: frolent,
    }
}

/// La médiane de la semaine (aujourd'hui et les 6 jours d'avant) de chaque règle mesurée : ce que lit l'ordre de
/// départ du bilan (`super::reglage`).
pub(crate) fn medianes_de_la_semaine(m: &Mesures, aujourd_hui: chrono::NaiveDate) -> BTreeMap<String, u64> {
    let regles: std::collections::BTreeSet<&String> = m
        .en_cours
        .keys()
        .chain(m.jours.values().flat_map(BTreeMap::keys))
        .collect();
    regles
        .into_iter()
        .filter_map(|r| {
            let mut v = m.medianes(r, aujourd_hui, 0, 6);
            (!v.is_empty()).then(|| (r.clone(), mediane(&mut v)))
        })
        .collect()
}

/// Les médianes de la semaine de cet ordinateur, aujourd'hui.
pub(crate) fn medianes_recentes() -> BTreeMap<String, u64> {
    medianes_de_la_semaine(
        &lire_dans(&crate::socle::dossier_local()),
        chrono::Local::now().date_naive(),
    )
}

/// Le verdict des mesures de cet ordinateur, aujourd'hui, contre le délai appliqué de chaque règle (celui du code, ou
/// monté par l'auto-réglage).
pub(crate) fn verdict() -> Verdict {
    let m = lire_dans(&crate::socle::dossier_local());
    let longs = super::reglage::delais_longs();
    juger(&m, chrono::Local::now().date_naive(), |id| {
        crate::machine::regles::regles(crate::machine::regles::Os::actuel())
            .into_iter()
            .find(|r| r.id == id)
            .map_or(crate::machine::regles::DELAI, |r| r.delai_avec(&longs))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn jour(j: &str) -> chrono::NaiveDate {
        chrono::NaiveDate::parse_from_str(j, "%Y-%m-%d").unwrap()
    }

    /// Les jours se closent en résumé, les plus de 8 semaines partent, le jour en cours est borné.
    #[test]
    fn rotation_et_resume() {
        let mut m = Mesures::default();
        let d = |ms| Duration::from_millis(ms);
        m.ajouter(&[("LNX-PFE-001", d(10)), ("LNX-PFE-001", d(30))], jour("2026-08-01"));
        m.ajouter(&[("LNX-PFE-001", d(20))], jour("2026-08-01"));
        m.ajouter(&[("LNX-PFE-001", d(5))], jour("2026-08-02"));
        assert_eq!(
            m.jours["2026-08-01"]["LNX-PFE-001"],
            Resume {
                n: 3,
                min: 10,
                med: 20,
                max: 30
            }
        );
        for _ in 0..100 {
            m.ajouter(&[("LNX-PFE-001", d(1))], jour("2026-08-02"));
        }
        assert_eq!(m.en_cours["LNX-PFE-001"].len(), PAR_JOUR_MAX);
        m.ajouter(&[("LNX-PFE-001", d(1))], jour("2026-10-23"));
        assert!(!m.jours.contains_key("2026-08-01"), "plus de 8 semaines : oublié");
        assert_eq!(m.jour, "2026-10-23");
    }

    /// Avant 5 semaines : « pas assez », jamais « sans régression ». Ensuite : 3 × et plus de 5 s, seulement.
    #[test]
    fn seuils_de_regression_et_de_delai() {
        let delai = |_: &str| Duration::from_secs(600);
        let mut m = Mesures::default();
        let auj = jour("2026-10-23");
        for ecart in (7..45).rev() {
            m.ajouter(
                &[
                    ("COM-FIC-001", Duration::from_secs(2)),
                    ("COM-LOG-001", Duration::from_millis(10)),
                ],
                auj - chrono::Duration::days(ecart),
            );
        }
        assert_eq!(juger(&m, auj, delai).verdict, "sans-regression");
        let mut courte = Mesures::default();
        courte.ajouter(&[("COM-FIC-001", Duration::from_secs(2))], auj);
        assert_eq!(juger(&courte, auj, delai).verdict, "pas-assez");
        for ecart in (0..7).rev() {
            m.ajouter(
                &[
                    ("COM-FIC-001", Duration::from_secs(7)),
                    ("COM-LOG-001", Duration::from_millis(100)),
                ],
                auj - chrono::Duration::days(ecart),
            );
        }
        let v = juger(&m, auj, delai);
        assert_eq!(v.verdict, "regressions");
        // 10 ms → 100 ms : dix fois plus, mais sous 5 s, ce n'est pas une régression.
        assert_eq!(v.lentes.len(), 1);
        assert_eq!(v.lentes[0].regle, "COM-FIC-001");
        assert_eq!((v.lentes[0].semaine_ms, v.lentes[0].avant_ms), (7_000, 2_000));
        assert_eq!(v.frolent_le_delai, Vec::<Frole>::new());
        let v = juger(&m, auj, |_| Duration::from_secs(10));
        assert_eq!(
            v.frolent_le_delai.len(),
            1,
            "7 s pour un délai de 10 s : au-delà de la moitié"
        );
    }

    /// Un fichier tronqué, trop gros, un tube ou un lien à sa place : refusé, on repart de zéro, sans bloquer.
    #[cfg(unix)]
    #[test]
    fn fichier_abime_ou_piege() {
        let d = crate::socle::dossier_local().join("essai-mesures");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("autotest")).unwrap();
        let f = d.join(MESURES);
        std::fs::write(&f, b"{\"v\":1,\"jour\":\"2026-").unwrap();
        assert_eq!(lire_dans(&d), Mesures::default());
        std::fs::remove_file(&f).unwrap();
        std::fs::File::create(&f).unwrap().set_len(1 << 30).unwrap();
        assert_eq!(lire_dans(&d), Mesures::default());
        std::fs::remove_file(&f).unwrap();
        crate::essais::tube_nomme(&f).unwrap();
        let debut = std::time::Instant::now();
        assert_eq!(lire_dans(&d), Mesures::default());
        assert!(debut.elapsed() < Duration::from_secs(2));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Pendant un autotest, rien n'est noté ; hors de lui, oui.
    #[test]
    fn rien_de_note_en_lecture_seule() {
        let d = crate::socle::dossier_local().join("essai-mesures-lecture-seule");
        let _ = std::fs::remove_dir_all(&d);
        let duree = [("COM-FIC-001", Duration::from_secs(1))];
        super::super::lecture_seule::poser();
        noter_dans(&d, &duree, &[], jour("2026-10-23"));
        super::super::lecture_seule::relever_pour_le_test();
        assert!(!d.join(MESURES).exists());
        noter_dans(&d, &duree, &[], jour("2026-10-23"));
        assert_eq!(lire_dans(&d).en_cours["COM-FIC-001"], vec![1000]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'ordre de départ lit la médiane de la semaine de chaque règle mesurée ; une règle vue il y a plus de 7 jours
    /// n'y est plus.
    #[test]
    fn medianes_de_la_semaine_pour_l_ordre_de_depart() {
        let ms = Duration::from_millis;
        let mut m = Mesures::default();
        m.ajouter(&[("VIEILLE", ms(9_000))], jour("2026-10-01"));
        for (j, d) in [("2026-10-20", 100), ("2026-10-21", 300), ("2026-10-22", 200)] {
            m.ajouter(&[("A", ms(d))], jour(j));
        }
        m.ajouter(&[("B", ms(50)), ("B", ms(70)), ("B", ms(60))], jour("2026-10-23"));
        let med = medianes_de_la_semaine(&m, jour("2026-10-23"));
        assert_eq!(med.get("A"), Some(&200));
        assert_eq!(med.get("B"), Some(&60));
        assert_eq!(med.get("VIEILLE"), None);
        assert_eq!(medianes_de_la_semaine(&Mesures::default(), jour("2026-10-23")).len(), 0);
    }

    proptest! {
        /// Petit fuzz du lecteur : n'importe quels octets se lisent sans paniquer, en un fichier de taille bornée.
        #[test]
        fn lecteur_ne_panique_jamais(octets in proptest::collection::vec(any::<u8>(), 0..512)) {
            let m = lire_de(&octets);
            prop_assert!(m.jours.len() <= 400);
        }

        #[test]
        fn lecteur_sur_du_json_presque_valide(jour in "[0-9-]{0,12}", n in any::<u32>(), med in any::<u64>()) {
            let texte = format!("{{\"v\":1,\"jour\":\"{jour}\",\"en_cours\":{{}},\"jours\":{{\"{jour}\":{{\"COM-FIC-001\":{{\"n\":{n},\"min\":0,\"med\":{med},\"max\":{med}}}}}}}}}");
            let m = lire_de(texte.as_bytes());
            let _ = juger(&m, chrono::NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(), |_| Duration::from_secs(600));
        }
    }

    /// La cache se mesure : reprises, vérifications à neuf, âge moyen, temps gagné (médiane de la semaine), écarts ;
    /// seules les règles de sa table, 16 comparaisons récentes au plus, des nombres seulement.
    #[test]
    fn la_cache_se_mesure() {
        use super::super::cache::Evenement;
        let d = crate::socle::dossier_local().join("essai-mesures-cache");
        let _ = std::fs::remove_dir_all(&d);
        let j = jour("2026-10-23");
        noter_dans(
            &d,
            &[("LNX-MAJ-001", Duration::from_millis(400))],
            &[Evenement::ANeuf { regle: "LNX-MAJ-001" }],
            j,
        );
        noter_dans(
            &d,
            &[],
            &[Evenement::Repris {
                regle: "LNX-MAJ-001",
                age_s: 3_000,
            }],
            j,
        );
        let mut evenements = vec![
            Evenement::ANeuf { regle: "LNX-MAJ-001" },
            Evenement::Repris {
                regle: "LNX-PFE-001",
                age_s: 1,
            },
        ];
        for i in 0..20 {
            evenements.push(Evenement::Compare {
                regle: "LNX-MAJ-001",
                ecart: i % 2 == 0,
                quand: i,
            });
        }
        noter_dans(&d, &[("LNX-MAJ-001", Duration::from_millis(600))], &evenements, j);
        let m = lire_dans(&d);
        assert_eq!(
            m.cache.keys().collect::<Vec<_>>(),
            ["LNX-MAJ-001"],
            "hors de la table : rien"
        );
        let c = &m.cache["LNX-MAJ-001"];
        assert_eq!((c.repris, c.a_neuf, c.age_moyen_s(), c.gagne_ms), (1, 2, 3_000, 400));
        assert_eq!((c.comparees, c.ecarts, c.recentes.len()), (20, 10, RECENTES_MAX));
        assert_eq!(c.recentes.first(), Some(&(4, true)));
        // Un fichier qui en garderait plus, ou pour une autre règle, est ramené dans ses bornes.
        let mut texte = serde_json::to_value(&m).unwrap();
        texte["cache"]["LNX-PFE-001"] = serde_json::json!({"repris": 1});
        texte["cache"]["LNX-MAJ-001"]["recentes"] = serde_json::json!(vec![serde_json::json!([1, true]); 40]);
        let relu = lire_de(&serde_json::to_vec(&texte).unwrap());
        assert_eq!(relu.cache.len(), 1);
        assert_eq!(relu.cache["LNX-MAJ-001"].recentes.len(), RECENTES_MAX);
        let _ = std::fs::remove_dir_all(&d);
    }
}
