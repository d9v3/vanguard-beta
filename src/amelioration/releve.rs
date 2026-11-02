//! Le relevé d'un jour (plan, §1) : des compteurs agrégés par clé, jamais un événement brut. C'est la forme écrite
//! dans `amelioration/jours/AAAA-MM-JJ.json` et celle que la mémoire du programme tient entre deux écritures
//! (`Brouillon`). Elle reprend les entrées du lot de schéma 2 (`compte_rendu::envoi`) quand elles conviennent telles
//! quelles, et n'ajoute que ce que le lot calcule à l'envoi : les résultats d'une règle au bilan (sa durée vient de
//! `mesures.json`), un texte sans son gabarit (recalculé), les durées brutes d'un outil (sa médiane).
//!
//! Pourquoi un fichier à part, pur : il entre tel quel dans le banc de fuzzing (cible `amelioration_releve`). Un
//! fichier du jour se relit sans confiance : trop gros, hors forme, avec une clé en double ou un nombre hors bornes,
//! il vaut un jour vide (le relevé repart de zéro, sans rien perdre d'autre).

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::cmp::Reverse;
use std::collections::BTreeMap;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::amelioration::texte::{Gabarit, TexteNettoye};
use crate::compte_rendu::champs::{Code, Contexte, Regle};
use crate::compte_rendu::envoi::{
    CACHE_MAX, CAUSE_N_MAX, CAUSES_MAX, CHOIX_MAX, CORRECTIONS_MAX, CacheRegle, CauseEnvoyee, Choix, Compte,
    Correction, Entree, Etat, Liste, Lot, MS_MAX, N_MAX, NomOutil, Nombre, OBJETS_MAX, OUTILS_MAX, ObjetEnvoye,
    Origine, OutilEnvoye, RAISONS_MAX, REGLES_MAX, RaisonNombre, Reglage, RegleEnvoyee, Retires, TEXTES_MAX,
    TexteEnvoye, arrondir_ms,
};

/// Un fichier du jour fait au plus 96 Kio (plan, réponse de l'auteur) : `Brouillon::ecrire` l'y ramène, `lire`
/// refuse au-delà.
pub(crate) const JOUR_MAX: usize = 98_304;
/// Tout `amelioration/` tient dans 10 Mo : au-delà, les jours les plus anciens partent d'abord.
pub(crate) const BUDGET: u64 = 10_000_000;
/// Un jour est gardé 90 jours.
pub(crate) const JOURS_GARDES: i64 = 90;
/// Les durées d'un outil gardées pour sa médiane : les dernières seulement.
pub(crate) const DUREES_MAX: usize = 48;

// --- Les entrées propres au jour ---------------------------------------------------------------------------------

/// Les résultats d'une règle aux bilans du jour ; ses durées sont dans `mesures.json`, jointes à l'envoi.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegleJour {
    pub(crate) id: Regle,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) problemes: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) sains: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) non_verifies: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) hors_delai: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) raisons: Liste<RaisonNombre, RAISONS_MAX>,
}

impl RegleJour {
    pub(crate) fn new(id: Regle) -> RegleJour {
        RegleJour {
            id,
            problemes: Compte::default(),
            sains: Compte::default(),
            non_verifies: Compte::default(),
            hors_delai: Compte::default(),
            raisons: Liste::default(),
        }
    }

    /// Combien de fois la règle a rendu un résultat ce jour-là.
    pub(crate) fn passages(&self) -> u64 {
        somme(&[self.problemes, self.sains, self.non_verifies])
    }
}

/// Un texte d'erreur nettoyé, son contexte et sa règle ; le gabarit se recalcule (il n'est jamais écrit à part).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TexteJour {
    pub(crate) texte: TexteNettoye,
    pub(crate) contexte: Contexte,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) regle: Option<Regle>,
    pub(crate) n: Nombre<N_MAX>,
}

/// Un outil lancé, par son nom seul, et ses dernières durées (ms) : la médiane se calcule à l'envoi.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutilJour {
    pub(crate) outil: NomOutil,
    pub(crate) origine: Origine,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) lances: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) finis: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) abandonnes: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) plantes: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "durees")]
    pub(crate) durees: Vec<u32>,
}

impl OutilJour {
    pub(crate) fn new(outil: NomOutil, origine: Origine) -> OutilJour {
        OutilJour {
            outil,
            origine,
            lances: Compte::default(),
            finis: Compte::default(),
            abandonnes: Compte::default(),
            plantes: Compte::default(),
            durees: Vec::new(),
        }
    }

    /// La médiane des durées gardées (ms), 0 sans durée.
    pub(crate) fn mediane_ms(&self) -> u32 {
        let mut v = self.durees.clone();
        v.sort_unstable();
        v.get(v.len().checked_div(2).unwrap_or(0)).copied().unwrap_or(0)
    }
}

/// Au plus `DUREES_MAX` durées, chacune d'une journée au plus.
fn durees<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u32>, D::Error> {
    let v = Vec::<u32>::deserialize(d)?;
    if v.len() > DUREES_MAX || v.iter().any(|ms| *ms > MS_MAX) {
        return Err(D::Error::custom("durées hors bornes"));
    }
    Ok(v)
}

/// La somme de comptes.
fn somme<const M: u32>(comptes: &[Compte<M>]) -> u64 {
    comptes.iter().fold(0u64, |s, c| s.saturating_add(u64::from(c.get())))
}

impl Entree for RegleJour {
    type Clef = Regle;
    fn clef(&self) -> Regle {
        self.id.clone()
    }
    fn interet(&self) -> u64 {
        // Ce qui n'a pas conclu ou a sonné d'abord : une règle saine tous les jours est la moins utile.
        somme(&[self.problemes, self.non_verifies, self.hors_delai])
            .saturating_mul(4)
            .saturating_add(u64::from(self.sains.get()))
    }
}

impl Entree for TexteJour {
    type Clef = (Gabarit, Contexte, Option<Regle>);
    fn clef(&self) -> Self::Clef {
        (Gabarit::de(&self.texte), self.contexte, self.regle.clone())
    }
    fn interet(&self) -> u64 {
        u64::from(self.n.get())
    }
}

impl Entree for OutilJour {
    type Clef = (NomOutil, Origine);
    fn clef(&self) -> Self::Clef {
        (self.outil.clone(), self.origine)
    }
    fn interet(&self) -> u64 {
        somme(&[self.lances, self.abandonnes, self.plantes])
    }
}

// --- Cumuler deux entrées de même clé ----------------------------------------------------------------------------

/// Deux entrées de même clé n'en font qu'une : leurs comptes s'additionnent (plafonnés, jamais en débordement).
pub(crate) trait Cumul: Entree + Clone {
    fn cumuler(&mut self, autre: &Self);
}

fn plus<const M: u32>(a: &mut Compte<M>, b: Compte<M>) {
    a.ajouter(u64::from(b.get()));
}

fn nombre_plus<const M: u32>(a: Nombre<M>, b: Nombre<M>) -> Nombre<M> {
    Nombre::new(u64::from(a.get()).saturating_add(u64::from(b.get()))).unwrap_or(a)
}

/// Les codes de deux listes, additionnés ; les `RAISONS_MAX` plus fréquents gardés.
pub(crate) fn codes_plus(
    a: &Liste<RaisonNombre, RAISONS_MAX>,
    b: &Liste<RaisonNombre, RAISONS_MAX>,
) -> Liste<RaisonNombre, RAISONS_MAX> {
    let mut tous: BTreeMap<Code, u64> = BTreeMap::new();
    for r in a.entrees().iter().chain(b.entrees()) {
        let n = tous.entry(r.code.clone()).or_insert(0);
        *n = n.saturating_add(u64::from(r.n.get()));
    }
    let mut v: Vec<(Code, u64)> = tous.into_iter().collect();
    v.sort_by_key(|(c, n)| (Reverse(*n), c.clone()));
    let mut l = Liste::default();
    for (code, n) in v {
        if let Some(n) = Nombre::new(n) {
            let _ = l.pousser(RaisonNombre { code, n });
        }
    }
    l
}

/// Un code de plus dans une liste de codes.
pub(crate) fn code_plus(l: &Liste<RaisonNombre, RAISONS_MAX>, code: Code) -> Liste<RaisonNombre, RAISONS_MAX> {
    let mut un = Liste::default();
    if let Some(n) = Nombre::new(1) {
        let _ = un.pousser(RaisonNombre { code, n });
    }
    codes_plus(l, &un)
}

impl Cumul for RegleJour {
    fn cumuler(&mut self, b: &RegleJour) {
        plus(&mut self.problemes, b.problemes);
        plus(&mut self.sains, b.sains);
        plus(&mut self.non_verifies, b.non_verifies);
        plus(&mut self.hors_delai, b.hors_delai);
        self.raisons = codes_plus(&self.raisons, &b.raisons);
    }
}

impl Cumul for CauseEnvoyee {
    fn cumuler(&mut self, b: &CauseEnvoyee) {
        self.n = nombre_plus::<CAUSE_N_MAX>(self.n, b.n);
        // La plus longue : une cause lente se juge à son pire.
        self.duree_ms = self.duree_ms.max(b.duree_ms);
        plus(&mut self.en_plus, b.en_plus);
        plus(&mut self.en_moins, b.en_moins);
        plus(&mut self.differents, b.differents);
    }
}

/// Le pire état d'abord : un problème vu une fois dans la journée reste un problème.
fn gravite(e: Etat) -> u8 {
    match e {
        Etat::Probleme => 2,
        Etat::NonVerifie => 1,
        Etat::Sain => 0,
    }
}

impl Cumul for ObjetEnvoye {
    fn cumuler(&mut self, b: &ObjetEnvoye) {
        self.n = nombre_plus(self.n, b.n);
        if gravite(b.etat) > gravite(self.etat) {
            self.etat = b.etat;
        }
    }
}

impl Cumul for TexteJour {
    fn cumuler(&mut self, b: &TexteJour) {
        self.n = nombre_plus(self.n, b.n);
    }
}

impl Cumul for Correction {
    fn cumuler(&mut self, b: &Correction) {
        plus(&mut self.proposees, b.proposees);
        plus(&mut self.acceptees, b.acceptees);
        plus(&mut self.refusees, b.refusees);
        plus(&mut self.reussies, b.reussies);
        plus(&mut self.echouees, b.echouees);
        plus(&mut self.annulees, b.annulees);
        plus(&mut self.revenues, b.revenues);
        self.codes = codes_plus(&self.codes, &b.codes);
    }
}

impl Cumul for Choix {
    fn cumuler(&mut self, b: &Choix) {
        plus(&mut self.normales, b.normales);
        plus(&mut self.oublis, b.oublis);
        plus(&mut self.refus, b.refus);
        plus(&mut self.echap, b.echap);
    }
}

impl Cumul for OutilJour {
    fn cumuler(&mut self, b: &OutilJour) {
        plus(&mut self.lances, b.lances);
        plus(&mut self.finis, b.finis);
        plus(&mut self.abandonnes, b.abandonnes);
        plus(&mut self.plantes, b.plantes);
        self.durees.extend(b.durees.iter().map(|ms| (*ms).min(MS_MAX)));
        let trop = self.durees.len().saturating_sub(DUREES_MAX);
        self.durees.drain(..trop);
    }
}

impl Cumul for CacheRegle {
    fn cumuler(&mut self, b: &CacheRegle) {
        plus(&mut self.repris, b.repris);
        plus(&mut self.a_neuf, b.a_neuf);
        plus(&mut self.age_total_s, b.age_total_s);
        plus(&mut self.gagne_ms, b.gagne_ms);
        plus(&mut self.comparees, b.comparees);
        plus(&mut self.ecarts, b.ecarts);
    }
}

/// Une entrée de `CORRECTIONS` vide, pour une règle.
pub(crate) fn correction(regle: Regle) -> Correction {
    Correction {
        regle,
        proposees: Compte::default(),
        acceptees: Compte::default(),
        refusees: Compte::default(),
        reussies: Compte::default(),
        echouees: Compte::default(),
        annulees: Compte::default(),
        revenues: Compte::default(),
        codes: Liste::default(),
    }
}

/// Une entrée de choix vide, pour une règle.
pub(crate) fn choix(regle: Regle) -> Choix {
    Choix {
        regle,
        normales: Compte::default(),
        oublis: Compte::default(),
        refus: Compte::default(),
        echap: Compte::default(),
    }
}

// --- La table en mémoire -----------------------------------------------------------------------------------------

/// Une table bornée d'entrées par clé : la mémoire du jour, et l'outil de la fusion. Une clé nouvelle quand la table
/// est pleine est perdue, et comptée par l'appelant (`Retires`).
pub(crate) struct Tas<T: Entree, const MAX: usize>(BTreeMap<T::Clef, T>);

impl<T: Entree, const MAX: usize> Default for Tas<T, MAX> {
    fn default() -> Self {
        Tas(BTreeMap::new())
    }
}

impl<T: Cumul, const MAX: usize> Tas<T, MAX> {
    /// Cumule `t` dans l'entrée de même clé, ou l'ajoute ; `false` : la table était pleine, `t` est perdue.
    pub(crate) fn ajouter(&mut self, t: T) -> bool {
        let clef = t.clef();
        if let Some(x) = self.0.get_mut(&clef) {
            x.cumuler(&t);
            return true;
        }
        if self.0.len() >= MAX {
            return false;
        }
        self.0.insert(clef, t);
        true
    }

    /// Cumule toute une liste ; rend le nombre d'entrées perdues.
    pub(crate) fn ajouter_tous<'a>(&mut self, ts: impl IntoIterator<Item = &'a T>) -> u64
    where
        T: 'a,
    {
        ts.into_iter().fold(0u64, |perdues, t| {
            perdues.saturating_add(u64::from(!self.ajouter(t.clone())))
        })
    }

    pub(crate) fn est_vide(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn valeurs(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    /// Les entrées, de la plus intéressante à la moins (à égalité, dans l'ordre des clés).
    fn rangees(&self) -> Vec<&T> {
        let mut v: Vec<&T> = self.0.values().collect();
        v.sort_by_key(|t| Reverse(t.interet()));
        v
    }

    /// La liste écrite : tout tient, la table ayant la même borne que la liste.
    pub(crate) fn liste(&self) -> Liste<T, MAX> {
        let mut l = Liste::default();
        for t in self.rangees() {
            let _ = l.pousser(t.clone());
        }
        l
    }

    /// Retire les entrées de moindre intérêt jusqu'à couvrir `exces` octets écrits ; rend le nombre retiré.
    fn retirer(&mut self, exces: usize) -> u64
    where
        T: Serialize,
    {
        let mut v: Vec<T> = std::mem::take(&mut self.0).into_values().collect();
        // La moins intéressante d'abord ; la dernière des égales part la première, comme dans le lot.
        v.sort_by_key(Entree::interet);
        let mut reste = exces;
        let mut retirees = 0u64;
        for t in v {
            if reste > 0 {
                let taille = serde_json::to_vec(&t).map_or(1, |o| o.len().saturating_add(1));
                reste = reste.saturating_sub(taille);
                retirees = retirees.saturating_add(1);
            } else {
                self.0.insert(t.clef(), t);
            }
        }
        retirees
    }
}

/// Le relevé du jour en mémoire : la même chose que le fichier, en tables qu'on cumule.
#[derive(Default)]
pub(crate) struct Brouillon {
    pub(crate) bilans_manuels: u64,
    pub(crate) passes_horaires: u64,
    pub(crate) regles: Tas<RegleJour, REGLES_MAX>,
    pub(crate) causes: Tas<CauseEnvoyee, CAUSES_MAX>,
    pub(crate) objets: Tas<ObjetEnvoye, OBJETS_MAX>,
    pub(crate) textes: Tas<TexteJour, TEXTES_MAX>,
    pub(crate) corrections: Tas<Correction, CORRECTIONS_MAX>,
    pub(crate) choix: Tas<Choix, CHOIX_MAX>,
    pub(crate) outils: Tas<OutilJour, OUTILS_MAX>,
    pub(crate) cache: Tas<CacheRegle, CACHE_MAX>,
    pub(crate) refus_locaux: u64,
    pub(crate) retires: Retires,
}

/// Le fichier d'un jour, tel qu'il s'écrit et se relit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Releve {
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) bilans_manuels: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) passes_horaires: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) regles: Liste<RegleJour, REGLES_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) causes: Liste<CauseEnvoyee, CAUSES_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) objets: Liste<ObjetEnvoye, OBJETS_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) textes: Liste<TexteJour, TEXTES_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) corrections: Liste<Correction, CORRECTIONS_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) choix: Liste<Choix, CHOIX_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) outils: Liste<OutilJour, OUTILS_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) cache: Liste<CacheRegle, CACHE_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) refus_locaux: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Retires::est_vide")]
    pub(crate) retires: Retires,
}

/// Relit un fichier du jour : un fichier trop gros ou hors forme vaut un jour vide, jamais une erreur.
pub(crate) fn lire(octets: &[u8]) -> Releve {
    if octets.len() > JOUR_MAX {
        return Releve::default();
    }
    serde_json::from_slice(octets).unwrap_or_default()
}

/// Ajoute les retraits de `b` à `a`.
fn retires_plus(a: &mut Retires, b: &Retires) {
    plus(&mut a.regles, b.regles);
    plus(&mut a.textes, b.textes);
    plus(&mut a.objets, b.objets);
    plus(&mut a.cache, b.cache);
    plus(&mut a.outils, b.outils);
    plus(&mut a.choix, b.choix);
    plus(&mut a.corrections, b.corrections);
    plus(&mut a.reglages, b.reglages);
    plus(&mut a.causes, b.causes);
}

impl Brouillon {
    /// Rien à écrire.
    pub(crate) fn est_vide(&self) -> bool {
        self.bilans_manuels == 0
            && self.passes_horaires == 0
            && self.regles.est_vide()
            && self.causes.est_vide()
            && self.objets.est_vide()
            && self.textes.est_vide()
            && self.corrections.est_vide()
            && self.choix.est_vide()
            && self.outils.est_vide()
            && self.cache.est_vide()
            && self.refus_locaux == 0
            && self.retires.est_vide()
    }

    /// Le brouillon d'un fichier relu.
    pub(crate) fn de(r: &Releve) -> Brouillon {
        let mut b = Brouillon::default();
        b.ajouter_releve(r);
        b
    }

    /// Cumule un fichier relu dans ce brouillon ; ce qui ne tient plus est compté dans `retires`.
    pub(crate) fn ajouter_releve(&mut self, r: &Releve) {
        self.bilans_manuels = self.bilans_manuels.saturating_add(u64::from(r.bilans_manuels.get()));
        self.passes_horaires = self.passes_horaires.saturating_add(u64::from(r.passes_horaires.get()));
        let p = self.regles.ajouter_tous(r.regles.entrees());
        self.retires.regles.ajouter(p);
        let p = self.causes.ajouter_tous(r.causes.entrees());
        self.retires.causes.ajouter(p);
        let p = self.objets.ajouter_tous(r.objets.entrees());
        self.retires.objets.ajouter(p);
        let p = self.textes.ajouter_tous(r.textes.entrees());
        self.retires.textes.ajouter(p);
        let p = self.corrections.ajouter_tous(r.corrections.entrees());
        self.retires.corrections.ajouter(p);
        let p = self.choix.ajouter_tous(r.choix.entrees());
        self.retires.choix.ajouter(p);
        let p = self.outils.ajouter_tous(r.outils.entrees());
        self.retires.outils.ajouter(p);
        let p = self.cache.ajouter_tous(r.cache.entrees());
        self.retires.cache.ajouter(p);
        self.refus_locaux = self.refus_locaux.saturating_add(u64::from(r.refus_locaux.get()));
        retires_plus(&mut self.retires, &r.retires);
    }

    /// Cumule un autre brouillon (la mémoire du programme dans le jour relu).
    pub(crate) fn fusionner(&mut self, b: &Brouillon) {
        self.ajouter_releve(&b.releve());
    }

    /// La forme écrite, sans troncature.
    pub(crate) fn releve(&self) -> Releve {
        Releve {
            bilans_manuels: Compte::new(self.bilans_manuels),
            passes_horaires: Compte::new(self.passes_horaires),
            regles: self.regles.liste(),
            causes: self.causes.liste(),
            objets: self.objets.liste(),
            textes: self.textes.liste(),
            corrections: self.corrections.liste(),
            choix: self.choix.liste(),
            outils: self.outils.liste(),
            cache: self.cache.liste(),
            refus_locaux: Compte::new(self.refus_locaux),
            retires: self.retires.clone(),
        }
    }

    /// Le fichier du jour, ramené à `JOUR_MAX` octets au plus. L'ordre est celui du lot (plan, §3) : les textes,
    /// puis les objets, les règles, le cache, les outils, les choix, les corrections et enfin les causes ; dans
    /// chaque table, l'entrée de moindre intérêt part la première. Chaque retrait est compté dans `retires`.
    pub(crate) fn ecrire(&mut self) -> Vec<u8> {
        loop {
            let o = serde_json::to_vec(&self.releve()).unwrap_or_default();
            let exces = o.len().saturating_sub(JOUR_MAX);
            if exces == 0 {
                return o;
            }
            macro_rules! puis {
                ($($champ:ident),+) => {
                    $(
                        if !self.$champ.est_vide() {
                            let r = self.$champ.retirer(exces);
                            self.retires.$champ.ajouter(r);
                            continue;
                        }
                    )+
                };
            }
            puis!(textes, objets, regles, cache, outils, choix, corrections, causes);
            // Plus aucune table : quelques nombres tiennent toujours sous 96 Kio.
            return o;
        }
    }
}

// --- Vers le lot d'A3 --------------------------------------------------------------------------------------------

/// Les durées d'une règle (`mesures.json`) pour le jour du lot : combien de passages, médiane et 90e centile (ms).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Durees {
    pub(crate) n: u64,
    pub(crate) med_ms: u64,
    pub(crate) p90_ms: u64,
}

/// Le jour `b`, versé dans `lot` (plateforme et activité déjà posées par l'appelant) : les règles jointes à leurs
/// durées et à leur délai, les textes avec leur gabarit, les outils avec leur médiane, les réglages de `reglages`.
/// Une règle dont on ne connaît pas le délai n'est pas une règle de ce programme : laissée de côté. Le lot est
/// ensuite ramené à 96 Kio (`Lot::tronquer`) ; tout ce qui n'y entre pas est compté dans `retires`.
pub(crate) fn vers_lot(
    b: &Brouillon,
    mut lot: Lot,
    durees: &BTreeMap<Regle, Durees>,
    delai_s: impl Fn(&Regle) -> Option<u64>,
    reglages: &[Reglage],
) -> Lot {
    lot.activite.bilans_manuels = Compte::new(b.bilans_manuels);
    lot.activite.passes_horaires = Compte::new(b.passes_horaires);
    let mut ids: Vec<&Regle> = durees.keys().chain(b.regles.0.keys()).collect();
    ids.sort();
    ids.dedup();
    let mut regles: Vec<RegleEnvoyee> = Vec::new();
    for id in ids {
        let d = durees.get(id).copied().unwrap_or_default();
        let jour = b.regles.0.get(id);
        let passages = jour.map_or(0, RegleJour::passages);
        let (Some(n), Some(delai)) = (Nombre::new(d.n.max(passages)), delai_s(id).and_then(Nombre::new)) else {
            continue;
        };
        let vide = RegleJour::new(id.clone());
        let j = jour.unwrap_or(&vide);
        regles.push(RegleEnvoyee {
            id: id.clone(),
            n,
            med_ms: Compte::new(arrondir_ms(d.med_ms)),
            p90_ms: Compte::new(arrondir_ms(d.p90_ms)),
            hors_delai: j.hors_delai,
            problemes: j.problemes,
            sains: j.sains,
            non_verifies: j.non_verifies,
            raisons: j.raisons.clone(),
            delai_s: delai,
        });
    }
    regles.sort_by_key(|r| Reverse(r.interet()));
    for r in regles {
        if lot.regles.pousser(r).is_err() {
            lot.retires.regles.ajouter(1);
        }
    }
    let textes = b
        .textes
        .rangees()
        .into_iter()
        .map(|t| TexteEnvoye::new(t.texte.clone(), t.contexte, t.regle.clone(), t.n));
    for t in textes {
        if lot.textes.pousser(t).is_err() {
            lot.retires.textes.ajouter(1);
        }
    }
    for o in b.outils.rangees() {
        let e = OutilEnvoye {
            outil: o.outil.clone(),
            origine: o.origine,
            lances: o.lances,
            finis: o.finis,
            abandonnes: o.abandonnes,
            plantes: o.plantes,
            med_ms: Compte::new(arrondir_ms(u64::from(o.mediane_ms()))),
        };
        if lot.outils.pousser(e).is_err() {
            lot.retires.outils.ajouter(1);
        }
    }
    for r in reglages {
        if lot.reglages.pousser(r.clone()).is_err() {
            lot.retires.reglages.ajouter(1);
        }
    }
    lot.causes = b.causes.liste();
    lot.objets = b.objets.liste();
    lot.corrections = b.corrections.liste();
    lot.choix = b.choix.liste();
    lot.cache = b.cache.liste();
    lot.refus_locaux = Compte::new(b.refus_locaux);
    retires_plus(&mut lot.retires, &b.retires);
    lot.tronquer();
    lot
}

// --- Purge -------------------------------------------------------------------------------------------------------

/// Les jours à effacer, de `jours` (nom « AAAA-MM-JJ », taille en octets) : ceux d'avant `limite` (90 jours), puis les
/// plus anciens tant que le tout, `autres` octets compris (le suivi, le matériel), dépasse `BUDGET`. Le jour `garde`
/// (aujourd'hui) ne part jamais.
pub(crate) fn a_purger(jours: &[(String, u64)], limite: &str, garde: &str, autres: u64) -> Vec<String> {
    let mut v: Vec<&(String, u64)> = jours.iter().collect();
    v.sort();
    let mut total = v.iter().fold(autres, |s, (_, taille)| s.saturating_add(*taille));
    let mut partants = Vec::new();
    for (nom, taille) in v {
        if nom.as_str() == garde {
            continue;
        }
        if nom.as_str() < limite || total > BUDGET {
            total = total.saturating_sub(*taille);
            partants.push(nom.clone());
        }
    }
    partants
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::as_conversions)]
mod tests {
    use super::*;

    fn regle(s: &str) -> Regle {
        Regle::new(s).unwrap()
    }

    fn texte(s: &str) -> TexteNettoye {
        TexteNettoye::nettoyer(s).unwrap()
    }

    #[test]
    fn un_jour_hors_forme_vaut_un_jour_vide() {
        for o in [
            &b"pas du json"[..],
            br#"{"inconnu": 1}"#,
            br#"{"regles": []}"#,
            br#"{"bilans_manuels": 0}"#,
            br#"{"regles": [{"id": "LNX-PLT-001"}, {"id": "LNX-PLT-001"}]}"#,
            br#"{"outils": [{"outil": "bilan", "origine": "menu", "durees": [86400001]}]}"#,
        ] {
            assert_eq!(lire(o), Releve::default(), "{}", String::from_utf8_lossy(o));
        }
        assert_eq!(lire(&vec![b' '; JOUR_MAX + 1]), Releve::default());
    }

    #[test]
    fn cumul_par_clef() {
        let mut b = Brouillon::default();
        let mut r = RegleJour::new(regle("LNX-PLT-001"));
        r.problemes = Compte::new(1);
        r.raisons = code_plus(&r.raisons, Code::new("delai").unwrap());
        assert!(b.regles.ajouter(r.clone()));
        assert!(b.regles.ajouter(r));
        let lu = b.regles.valeurs().next().unwrap();
        assert_eq!(lu.problemes.get(), 2);
        assert_eq!(lu.raisons.entrees()[0].n.get(), 2);
        // Un texte de même forme, chiffres changés, est la même entrée.
        let t = |s: &str| TexteJour {
            texte: texte(s),
            contexte: Contexte::Autotest,
            regle: None,
            n: Nombre::new(1).unwrap(),
        };
        assert!(b.textes.ajouter(t("délai de 30 secondes dépassé")));
        assert!(b.textes.ajouter(t("délai de 45 secondes dépassé")));
        assert_eq!(b.textes.len(), 1);
        assert_eq!(b.textes.valeurs().next().unwrap().n.get(), 2);
    }

    #[test]
    fn les_durees_d_un_outil_restent_bornees() {
        let mut a = OutilJour::new(NomOutil::new("bilan").unwrap(), Origine::Menu);
        for i in 0..100 {
            let mut b = a.clone();
            b.durees = vec![i];
            a.cumuler(&b);
        }
        assert_eq!(a.durees.len(), DUREES_MAX);
        assert_eq!(a.durees.last(), Some(&99));
    }

    #[test]
    fn plein_le_jour_reste_sous_96_kio() {
        let mut b = Brouillon::default();
        for i in 0..REGLES_MAX + 10 {
            let mut r = RegleJour::new(regle(&format!("LNX-PLT-{:03}", i % 1000)));
            r.sains = Compte::new(i as u64 + 1);
            r.non_verifies = Compte::new(3);
            r.raisons = code_plus(&r.raisons, Code::new("delai").unwrap());
            r.raisons = code_plus(&r.raisons, Code::new("illisible").unwrap());
            b.regles.ajouter(r);
        }
        for i in 0..TEXTES_MAX {
            b.textes.ajouter(TexteJour {
                texte: texte(&format!(
                    "une erreur assez longue numéro {} {}",
                    i,
                    "mot ".repeat(60 + i)
                )),
                contexte: Contexte::Autotest,
                regle: None,
                n: Nombre::new(1).unwrap(),
            });
        }
        for i in 0..OUTILS_MAX {
            let mut o = OutilJour::new(NomOutil::new(&format!("outil-{i}")).unwrap(), Origine::Menu);
            o.lances = Compte::new(1);
            o.durees = vec![MS_MAX; DUREES_MAX];
            b.outils.ajouter(o);
        }
        for i in 0..CACHE_MAX {
            b.cache.ajouter(CacheRegle {
                regle: regle(&format!("WIN-PRS-{i:03}")),
                repris: Compte::new(999_999),
                a_neuf: Compte::new(999_999),
                age_total_s: Compte::new(u64::MAX),
                gagne_ms: Compte::new(u64::MAX),
                comparees: Compte::new(999_999),
                ecarts: Compte::new(999_999),
            });
        }
        let avant = serde_json::to_vec(&b.releve()).unwrap().len();
        assert!(avant > JOUR_MAX, "l'essai doit dépasser : {avant}");
        let o = b.ecrire();
        assert!(o.len() <= JOUR_MAX, "{}", o.len());
        let relu = lire(&o);
        assert!(!relu.retires.est_vide());
        // Les textes partent les premiers : tant qu'il en reste, rien d'autre n'est retiré.
        assert!(relu.retires.textes.get() > 0, "{:?}", relu.retires);
        if !relu.textes.est_vide() {
            let r = &relu.retires;
            assert_eq!(
                [r.objets, r.regles, r.cache, r.outils, r.choix, r.corrections, r.causes].map(|c| u64::from(c.get())),
                [0; 7],
                "{r:?}"
            );
        }
        // Relu, réécrit : les mêmes octets.
        assert_eq!(Brouillon::de(&relu).ecrire(), o);
    }

    #[test]
    fn une_table_pleine_compte_ce_qu_elle_perd() {
        let mut r = Releve::default();
        let mut a = Brouillon::default();
        for i in 0..CHOIX_MAX {
            let mut c = choix(regle(&format!("COM-NAV-{i:03}")));
            c.normales = Compte::new(1);
            a.choix.ajouter(c);
        }
        let mut b = Brouillon::default();
        let mut c = choix(regle("COM-NAV-999"));
        c.refus = Compte::new(1);
        b.choix.ajouter(c);
        r.retires.choix = Compte::new(2);
        a.ajouter_releve(&r);
        a.fusionner(&b);
        assert_eq!(a.choix.len(), CHOIX_MAX);
        assert_eq!(a.retires.choix.get(), 3);
    }

    #[test]
    fn purge_par_age_puis_par_budget() {
        let j = |n: &str, t: u64| (n.to_string(), t);
        let jours = vec![
            j("2026-07-01", 10),
            j("2026-08-15", 4_000_000),
            j("2026-09-01", 4_000_000),
            j("2026-11-02", 4_000_000),
        ];
        // Le 1er juillet a plus de 90 jours ; le reste fait 12 Mo : le plus ancien gardé part aussi.
        assert_eq!(
            a_purger(&jours, "2026-08-04", "2026-11-02", 0),
            vec!["2026-07-01".to_string(), "2026-08-15".to_string()]
        );
        // Aujourd'hui ne part jamais, même seul au-dessus du budget.
        assert_eq!(
            a_purger(&[j("2026-11-02", 20_000_000)], "2026-08-04", "2026-11-02", 0),
            Vec::<String>::new()
        );
        // Les autres fichiers comptent dans le budget.
        assert_eq!(
            a_purger(
                &[j("2026-10-01", 10), j("2026-11-02", 10)],
                "2026-08-04",
                "2026-11-02",
                BUDGET
            ),
            vec!["2026-10-01".to_string()]
        );
    }
}
