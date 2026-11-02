//! L'auto-réglage local du bilan : ce que Vanguard ajuste de lui-même, sur cet ordinateur, d'après les durées
//! mesurées de ses règles (`super::mesures`). Rien ne sort de l'ordinateur, rien ne passe par une IA.
//!
//! Ce qui peut bouger, et seulement entre des bornes écrites ici :
//! - l'**ordre de départ** des règles, la plus longue d'abord (médiane de la semaine), pour que le bilan ne finisse
//!   pas sur elle. Les règles tournent toutes en même temps, chacune dans son fil ; l'ordre ne change ni ce qu'elles
//!   rendent ni l'ordre affiché (celui des rangs) ;
//! - le **délai** d'une règle qui frôle le sien (sa plus longue durée de la semaine au-delà de la moitié) deux
//!   semaines de suite : il monte de `DELAI` à `DELAI_LONG`, jamais plus haut, jamais sous la valeur du code. Chaque
//!   montée est notée (date, règle, avant, après, mesure), 50 au plus, dans `autotest/reglage.json`, scellé.
//!
//! Chaque montée s'annule seule dans Paramètres (la règle n'est plus jamais montée), « tout remettre » vide le fichier
//! et coupe le réglage, l'interrupteur à « non » rend les délais du code sans rien oublier. Fichier douteux (sceau) :
//! les délais du code, et rien n'y est réécrit tout seul.
//!
//! Ce qui ne bouge **jamais** ici : un seuil, un niveau, une règle ou une liste de détection, le blocage, la fraîcheur
//! des sources de menaces ; un bilan lance toujours toutes ses règles. Ce module n'importe ni `risk` ni un module de
//! détection (garde : `reglage_ne_touche_pas_la_detection`).
//!
//! Limite dite : deux processus (surveillance et Paramètres) qui écrivent en même temps, le dernier l'emporte ;
//! l'écriture scellée évite le fichier cassé, pas le changement perdu (rare : une passe par heure).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::machine::regles::{DELAI, DELAI_LONG};
use crate::ui::*;
use crate::{tr, trf, trp};

/// Le fichier, sous le dossier de données. Scellé : il décide du délai de règles du bilan.
pub(crate) const REGLAGE: &str = "autotest/reglage.json";
/// Au-delà, ce n'est pas le fichier de Vanguard (50 montées font quelques Kio).
const TAILLE_MAX: usize = 256 << 10;
/// Montées gardées au plus : autant de règles au délai monté.
const MONTEES_MAX: usize = 50;
/// Règles suivies (qui frôlent) ou refusées (montée annulée), au plus chacune.
const SUIVIES_MAX: usize = 200;
/// Une règle qui frôle encore son délai 7 jours après la première fois (deux semaines de mesures qui ne se recouvrent
/// pas) voit le sien monter.
const JOURS_DE_SUITE: i64 = 7;

/// Une montée de délai.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Montee {
    /// Le jour (« AAAA-MM-JJ »).
    pub quand: String,
    pub regle: String,
    /// Les délais d'avant et d'après, en secondes.
    pub avant_s: u64,
    pub apres_s: u64,
    /// La mesure qui l'a décidée : sa plus longue durée de la semaine (ms).
    pub mesure_ms: u64,
}

/// L'état de l'auto-réglage.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Etat {
    #[serde(default)]
    pub v: u16,
    /// Coupé (« non » dans Paramètres, ou « tout remettre ») : les délais du code, rien n'est ajusté.
    #[serde(default)]
    pub coupe: bool,
    /// Les montées en vigueur, dans l'ordre où elles sont venues.
    #[serde(default)]
    pub montees: Vec<Montee>,
    /// Les règles qui frôlent leur délai, et depuis quel jour.
    #[serde(default)]
    pub frolent_depuis: BTreeMap<String, String>,
    /// Les règles dont la montée a été annulée : jamais remontées.
    #[serde(default)]
    pub refusees: BTreeSet<String>,
}

/// Ce que le fichier donne.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lu {
    /// Pas encore de fichier : le réglage est en marche, rien n'est monté.
    Absent,
    Cru(Etat),
    /// Falsifié, adopté, illisible (`sceau`) : les délais du code, et rien n'y est réécrit tout seul.
    Douteux,
}

/// « AAA-AAA-000 », comme chaque règle du registre : rien d'autre ne se garde ni ne se montre.
fn id_valide(id: &str) -> bool {
    let o = id.as_bytes();
    o.len() == 11
        && o.iter().enumerate().all(|(i, c)| match i {
            0..=2 | 4..=6 => c.is_ascii_uppercase(),
            3 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

fn date(texte: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(texte, "%Y-%m-%d").ok()
}

fn jour(d: chrono::NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

fn secondes(d: Duration) -> u64 {
    d.as_secs()
}

impl Etat {
    /// Serré dans ses bornes : identifiants de règle et dates bien formés, délais exactement `DELAI` → `DELAI_LONG`,
    /// une montée par règle, aucune pour une règle refusée, 50 montées et 200 règles suivies au plus.
    fn borne(mut self) -> Etat {
        let mut vues = BTreeSet::new();
        self.refusees.retain(|r| id_valide(r));
        while self.refusees.len() > SUIVIES_MAX {
            self.refusees.pop_last();
        }
        let refusees = &self.refusees;
        self.montees.retain(|m| {
            id_valide(&m.regle)
                && date(&m.quand).is_some()
                && m.avant_s == secondes(DELAI)
                && m.apres_s == secondes(DELAI_LONG)
                && !refusees.contains(&m.regle)
                && vues.insert(m.regle.clone())
        });
        self.montees.truncate(MONTEES_MAX);
        self.frolent_depuis
            .retain(|r, d| id_valide(r) && date(d).is_some() && !vues.contains(r) && !refusees.contains(r));
        while self.frolent_depuis.len() > SUIVIES_MAX {
            self.frolent_depuis.pop_last();
        }
        self.v = 1;
        self
    }

    /// Les règles au délai monté, telles que le bilan les applique : aucune quand le réglage est coupé.
    pub(crate) fn delais_longs(&self) -> BTreeSet<String> {
        if self.coupe {
            BTreeSet::new()
        } else {
            self.montees.iter().map(|m| m.regle.clone()).collect()
        }
    }
}

/// Le contenu du fichier, serré dans ses bornes ; illisible ou trop gros : l'état d'origine.
pub(crate) fn lire_de(octets: &[u8]) -> Etat {
    if octets.len() > TAILLE_MAX {
        return Etat::default();
    }
    serde_json::from_slice::<Etat>(octets).map_or_else(|_| Etat::default(), Etat::borne)
}

fn lire_dans(dossier: &Path) -> Lu {
    match crate::sceau::juge_dans(dossier, REGLAGE) {
        crate::sceau::Juge::Absent => Lu::Absent,
        crate::sceau::Juge::Cru(o) => Lu::Cru(lire_de(&o)),
        _ => Lu::Douteux,
    }
}

impl Lu {
    pub(crate) fn delais_longs(&self) -> BTreeSet<String> {
        match self {
            Lu::Cru(e) => e.delais_longs(),
            Lu::Absent | Lu::Douteux => BTreeSet::new(),
        }
    }
}

/// Les règles au délai monté sur cet ordinateur (le bilan les lit une fois).
pub(crate) fn delais_longs() -> BTreeSet<String> {
    lire_dans(&crate::socle::dossier_local()).delais_longs()
}

fn ecrire_dans(dossier: &Path, e: &Etat) -> std::io::Result<()> {
    let o = serde_json::to_vec(e).map_err(std::io::Error::other)?;
    crate::sceau::ecrire_dans(dossier, REGLAGE, &o)
}

/// Ajuste l'état d'après les règles qui frôlent leur délai (`frolent` : identifiant et plus longue durée de la
/// semaine, en ms, jugées contre le délai du code). `delai_du_code` : celui de chaque règle de ce système, `None`
/// pour une règle inconnue. Seule une règle au délai `DELAI` peut monter, une fois, à `DELAI_LONG`. Rend vrai si
/// l'état a changé.
fn ajuster_etat(
    e: &mut Etat,
    aujourd_hui: chrono::NaiveDate,
    frolent: &[(String, u64)],
    delai_du_code: impl Fn(&str) -> Option<Duration>,
) -> bool {
    let avant = e.clone();
    let montees: BTreeSet<String> = e.montees.iter().map(|m| m.regle.clone()).collect();
    let candidates: BTreeMap<&str, u64> = frolent
        .iter()
        .filter(|(r, _)| {
            id_valide(r) && !montees.contains(r) && !e.refusees.contains(r) && delai_du_code(r) == Some(DELAI)
        })
        .map(|(r, ms)| (r.as_str(), *ms))
        .collect();
    e.frolent_depuis.retain(|r, _| candidates.contains_key(r.as_str()));
    for (regle, mesure_ms) in candidates {
        let depuis = match e.frolent_depuis.get(regle).and_then(|d| date(d)) {
            // Une date à venir (horloge reculée) repart d'aujourd'hui.
            Some(d) if d <= aujourd_hui => d,
            _ if e.frolent_depuis.len() >= SUIVIES_MAX && !e.frolent_depuis.contains_key(regle) => continue,
            _ => {
                e.frolent_depuis.insert(regle.to_string(), jour(aujourd_hui));
                aujourd_hui
            }
        };
        if aujourd_hui.signed_duration_since(depuis).num_days() >= JOURS_DE_SUITE && e.montees.len() < MONTEES_MAX {
            e.frolent_depuis.remove(regle);
            e.montees.push(Montee {
                quand: jour(aujourd_hui),
                regle: regle.to_string(),
                avant_s: secondes(DELAI),
                apres_s: secondes(DELAI_LONG),
                mesure_ms,
            });
        }
    }
    *e != avant
}

/// Après un bilan noté (`super::mesures::noter`) : ajuste les délais d'après les mesures de cet ordinateur. Rien
/// pendant un autotest manuel, ni quand le réglage est coupé ou son fichier douteux.
pub(crate) fn ajuster() {
    ajuster_dans(
        &crate::socle::dossier_local(),
        chrono::Local::now().date_naive(),
        &super::mesures::lues(),
        |id| {
            crate::machine::regles::regles(crate::machine::regles::Os::actuel())
                .into_iter()
                .find(|r| r.id == id)
                .map(crate::machine::regles::Regle::delai)
        },
    );
}

fn ajuster_dans(
    dossier: &Path,
    aujourd_hui: chrono::NaiveDate,
    mesures: &super::mesures::Mesures,
    delai_du_code: impl Fn(&str) -> Option<Duration>,
) {
    if super::lecture_seule::active() {
        return;
    }
    let mut e = match lire_dans(dossier) {
        Lu::Absent => Etat::default(),
        Lu::Cru(e) => e,
        Lu::Douteux => return,
    };
    if e.coupe {
        return;
    }
    let verdict = super::mesures::juger(mesures, aujourd_hui, |id| delai_du_code(id).unwrap_or(DELAI));
    let frolent: Vec<(String, u64)> = verdict
        .frolent_le_delai
        .into_iter()
        .map(|f| (f.regle, f.max_ms))
        .collect();
    if ajuster_etat(&mut e, aujourd_hui, &frolent, delai_du_code) {
        let _ = ecrire_dans(dossier, &e.borne());
    }
}

/// L'état de départ d'un changement voulu : celui du fichier, ou celui d'origine s'il est absent ou douteux (le
/// changement le réécrit, scellé).
fn pour_changer(dossier: &Path) -> Etat {
    match lire_dans(dossier) {
        Lu::Cru(e) => e,
        Lu::Absent | Lu::Douteux => Etat::default(),
    }
}

/// Met le réglage en marche ou le coupe ; les montées restent, appliquées seulement en marche.
fn mettre_en_marche_dans(dossier: &Path, en_marche: bool) -> std::io::Result<()> {
    let mut e = pour_changer(dossier);
    e.coupe = !en_marche;
    ecrire_dans(dossier, &e.borne())
}

/// Annule la montée de `regle` : son délai redevient celui du code, et elle ne remontera plus. Rend vrai si elle
/// était montée.
fn annuler_dans(dossier: &Path, regle: &str) -> std::io::Result<bool> {
    let mut e = pour_changer(dossier);
    let avant = e.montees.len();
    e.montees.retain(|m| m.regle != regle);
    if e.montees.len() == avant {
        return Ok(false);
    }
    e.refusees.insert(regle.to_string());
    ecrire_dans(dossier, &e.borne())?;
    Ok(true)
}

/// Tout remettre comme à l'origine : plus rien de monté, suivi ni refusé, et le réglage coupé jusqu'à ce qu'on le
/// remette en marche.
fn tout_remettre_dans(dossier: &Path) -> std::io::Result<()> {
    ecrire_dans(
        dossier,
        &Etat {
            coupe: true,
            ..Etat::default()
        }
        .borne(),
    )
}

/// L'ordre de départ : les positions de `ids` (une par vérification, `None` pour une vérification sans règle du
/// registre), la plus longue médiane d'abord. Une règle jamais mesurée part après les mesurées, dans l'ordre des
/// rangs, comme deux règles de même médiane. Toujours une permutation de `0..ids.len()` : aucune règle perdue ni
/// lancée deux fois.
pub(crate) fn ordre_de_depart(ids: &[Option<&str>], medianes: &BTreeMap<String, u64>) -> Vec<usize> {
    let mut ordre: Vec<usize> = (0..ids.len()).collect();
    let duree = |i: &usize| ids.get(*i).copied().flatten().and_then(|id| medianes.get(id)).copied();
    // Tri stable : à égalité (ou sans mesure), l'ordre des rangs reste.
    ordre.sort_by_key(|i| std::cmp::Reverse(duree(i)));
    ordre
}

/// `depart` s'il est une permutation de `0..n`, sinon l'ordre des rangs : un ordre faux ne fait jamais sauter ni
/// doubler une règle.
pub(crate) fn permutation_ou_rangs(depart: Vec<usize>, n: usize) -> Vec<usize> {
    let mut vus = vec![false; n];
    let juste = depart.len() == n
        && depart.iter().all(|&i| match vus.get_mut(i) {
            Some(v) if !*v => {
                *v = true;
                true
            }
            _ => false,
        });
    if juste { depart } else { (0..n).collect() }
}

/// La valeur montrée dans Paramètres.
pub(crate) fn etat_court() -> String {
    match lire_dans(&crate::socle::dossier_local()) {
        Lu::Absent => tr!("oui", "yes").to_string(),
        Lu::Cru(e) if e.coupe => tr!("non", "no").to_string(),
        Lu::Cru(e) if e.montees.is_empty() => tr!("oui", "yes").to_string(),
        Lu::Cru(e) => trf!("oui ({} changement(s))", "yes ({} change(s))", e.montees.len()),
        Lu::Douteux => tr!(
            "oui (fichier douteux : délais d'origine)",
            "yes (doubtful file: original time limits)"
        )
        .to_string(),
    }
}

/// Une montée, telle qu'elle se montre : « LNX-NOY-001 : délai 10 → 30 min, le 2026-11-02 (mesure 6 min 12 s) ».
fn montree(m: &Montee) -> String {
    let mesure = m.mesure_ms / 1000;
    trf!(
        "{} : délai {} → {} min, le {} (mesuré : {} min {:02} s)",
        "{}: time limit {} → {} min, on {} (measured: {} min {:02} s)",
        m.regle,
        m.avant_s / 60,
        m.apres_s / 60,
        m.quand,
        mesure / 60,
        mesure % 60
    )
}

fn dire_echec(e: &std::io::Error) {
    trp!(
        "  ✖ Rien n'a changé : {} ne s'écrit pas ({e}).",
        "  ✖ Nothing changed: {} cannot be written ({e}).",
        REGLAGE
    );
}

fn dire_en_marche(en_marche: bool) {
    match mettre_en_marche_dans(&crate::socle::dossier_local(), en_marche) {
        Ok(()) if en_marche => trp!(
            "  {VERT}✔{RESET} Réglage automatique de la vitesse : en marche.",
            "  {VERT}✔{RESET} Automatic speed tuning: on."
        ),
        Ok(()) => trp!(
            "  {VERT}✔{RESET} Réglage automatique de la vitesse : coupé. Les délais du code servent ; les changements restent notés, et reviennent s'il est remis en marche.",
            "  {VERT}✔{RESET} Automatic speed tuning: off. The code's time limits are used; the changes stay noted, and come back if it is turned on again."
        ),
        Err(e) => dire_echec(&e),
    }
}

fn dire_annule(regle: &str) {
    match annuler_dans(&crate::socle::dossier_local(), regle) {
        Ok(true) => trp!(
            "  {VERT}✔{RESET} {regle} : délai remis à {} min, et il ne montera plus.",
            "  {VERT}✔{RESET} {regle}: time limit back to {} min, and it will not go up again.",
            secondes(DELAI) / 60
        ),
        Ok(false) => trp!(
            "  Rien n'a changé : le délai de cette règle n'est pas monté.",
            "  Nothing changed: this rule's time limit has not gone up."
        ),
        Err(e) => dire_echec(&e),
    }
}

fn dire_tout_remis() {
    match tout_remettre_dans(&crate::socle::dossier_local()) {
        Ok(()) => trp!(
            "  {VERT}✔{RESET} Tout est remis comme à l'origine, et le réglage est coupé. « vanguard parametres auto-reglage oui » le remet en marche.",
            "  {VERT}✔{RESET} Everything is back to the original, and tuning is off. “vanguard settings auto-tuning yes” turns it back on."
        ),
        Err(e) => dire_echec(&e),
    }
}

/// `vanguard parametres auto-reglage [oui|non|tout-remettre|annuler <règle>]` : sans mot, l'état et les changements.
pub(crate) fn commande(mots: &[String]) {
    let mots: Vec<String> = mots.iter().map(|m| m.trim().to_lowercase()).collect();
    match mots.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => {
            afficher();
        }
        ["oui" | "o" | "yes" | "y" | "on"] => dire_en_marche(true),
        ["non" | "n" | "no" | "off"] => dire_en_marche(false),
        ["tout-remettre" | "reset" | "origine" | "original"] => dire_tout_remis(),
        ["annuler" | "undo", regle] => dire_annule(&regle.to_uppercase()),
        _ => trp!(
            "  Valeurs : oui, non, tout-remettre, annuler <règle> (par exemple « annuler LNX-NOY-001 »).",
            "  Values: yes, no, reset, undo <rule> (for example “undo LNX-NOY-001”)."
        ),
    }
}

/// L'état et les changements en vigueur ; rend les montées montrées, numérotées à partir de 1.
fn afficher() -> Vec<Montee> {
    titre(tr!("Réglage automatique de la vitesse", "Automatic speed tuning"));
    afficher_aligne("  ", explication(), 2, GRIS);
    println!();
    let lu = lire_dans(&crate::socle::dossier_local());
    trp!("  En marche : {}", "  On: {}", etat_court());
    let montees = match lu {
        Lu::Cru(e) => e.montees,
        Lu::Absent | Lu::Douteux => Vec::new(),
    };
    if montees.is_empty() {
        trp!(
            "  Aucun changement : chaque règle a le délai du code.",
            "  No change: every rule has the code's time limit."
        );
    }
    for (i, m) in montees.iter().enumerate() {
        afficher_aligne(&format!("  {TOUCHE}{:>2}{RESET} ", i + 1), &montree(m), 5, "");
    }
    montees
}

/// Ce que fait le réglage, en une phrase.
pub(crate) fn explication() -> &'static str {
    tr!(
        "Oui : le bilan lance d'abord ses règles les plus longues, et le délai d'une règle qui le frôle deux semaines de suite monte de 10 à 30 minutes, jamais plus. Les règles et ce qu'elles jugent ne changent jamais. Chaque changement est noté avec sa valeur d'avant et s'annule ici. Rien n'est envoyé.",
        "Yes: the check starts its longest rules first, and the time limit of a rule that comes close to it two weeks in a row goes up from 10 to 30 minutes, never more. The rules and how they judge never change. Each change is noted with its previous value and can be undone here. Nothing is sent."
    )
}

/// L'écran de Paramètres : l'état, les changements, et de quoi les défaire.
pub(crate) fn menu() {
    let montees = afficher();
    let reponse = demander(tr!(
        "\n  Numéro : annuler celui-ci ; « oui » ou « non » : mettre en marche ou couper ; « t » : tout remettre comme à l'origine ; Entrée pour revenir : ",
        "\n  Number: undo this one; “yes” or “no”: turn on or off; “a”: put everything back to the original; Enter to go back: "
    ));
    let reponse = reponse.trim();
    if reponse.is_empty() {
        return;
    }
    if crate::langue::tout(reponse) {
        dire_tout_remis();
    } else if crate::langue::oui(reponse) {
        dire_en_marche(true);
    } else if matches!(reponse.to_lowercase().as_str(), "n" | "non" | "no") {
        dire_en_marche(false);
    } else if let Some(m) = reponse
        .parse::<usize>()
        .ok()
        .and_then(|i| montees.get(i.checked_sub(1)?))
    {
        dire_annule(&m.regle);
    } else {
        trp!("  Rien n'a changé.", "  Nothing changed.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn medianes(paires: &[(&str, u64)]) -> BTreeMap<String, u64> {
        paires.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
    }

    #[test]
    fn la_plus_longue_d_abord_puis_les_rangs() {
        let ids = [Some("A"), None, Some("B"), Some("C"), Some("D")];
        let m = medianes(&[("B", 9_000), ("D", 9_000), ("A", 100)]);
        // B et D ex aequo : dans l'ordre des rangs ; A mesurée avant la vérification sans règle et C jamais mesurée.
        assert_eq!(ordre_de_depart(&ids, &m), vec![2, 4, 0, 1, 3]);
        assert_eq!(ordre_de_depart(&ids, &BTreeMap::new()), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn un_ordre_faux_rend_les_rangs() {
        assert_eq!(permutation_ou_rangs(vec![2, 0, 1], 3), vec![2, 0, 1]);
        assert_eq!(permutation_ou_rangs(vec![0, 0, 1], 3), vec![0, 1, 2]);
        assert_eq!(permutation_ou_rangs(vec![0, 1], 3), vec![0, 1, 2]);
        assert_eq!(permutation_ou_rangs(vec![0, 1, 3], 3), vec![0, 1, 2]);
    }

    /// Le module ne nomme rien de la détection : ni niveau de risque, ni module de règles ou de protection.
    #[test]
    fn reglage_ne_touche_pas_la_detection() {
        let source = include_str!("reglage.rs");
        let code: String = source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(source)
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        for interdit in [
            "risk",
            "Niveau",
            "protection",
            "regles_communes",
            "seuil",
            "SEUIL",
            "blocage",
        ] {
            assert!(!code.contains(interdit), "reglage.rs nomme « {interdit} »");
        }
    }

    fn j(t: &str) -> chrono::NaiveDate {
        date(t).unwrap()
    }

    /// Le délai du code des règles de l'essai : LNX-TST-010 ordinaire, LNX-MAJ-010 déjà long, le reste inconnu.
    fn du_code(id: &str) -> Option<Duration> {
        match id {
            "LNX-TST-010" | "LNX-TST-011" => Some(DELAI),
            "LNX-MAJ-010" => Some(DELAI_LONG),
            _ => None,
        }
    }

    fn frole(ids: &[&str]) -> Vec<(String, u64)> {
        ids.iter().map(|r| ((*r).to_string(), 400_000)).collect()
    }

    /// Frôler une fois ne suffit pas ; 7 jours plus tard, toujours : le délai monte, une fois, noté avec sa valeur
    /// d'avant. Une règle qui cesse de frôler repart de zéro ; une règle déjà longue ou inconnue ne monte jamais.
    #[test]
    fn deux_semaines_de_suite_puis_monte_une_fois() {
        let mut e = Etat::default();
        let tous = [
            "LNX-TST-010",
            "LNX-TST-011",
            "LNX-MAJ-010",
            "LNX-ABC-999",
            "pas une règle",
        ];
        assert!(ajuster_etat(&mut e, j("2026-11-01"), &frole(&tous), du_code));
        assert_eq!(e.montees.len(), 0);
        assert_eq!(
            e.frolent_depuis.keys().map(String::as_str).collect::<Vec<_>>(),
            ["LNX-TST-010", "LNX-TST-011"]
        );
        // LNX-TST-011 cesse de frôler : oubliée.
        assert!(ajuster_etat(&mut e, j("2026-11-05"), &frole(&["LNX-TST-010"]), du_code));
        assert!(!e.frolent_depuis.contains_key("LNX-TST-011"));
        assert!(!ajuster_etat(
            &mut e,
            j("2026-11-07"),
            &frole(&["LNX-TST-010"]),
            du_code
        ));
        assert!(ajuster_etat(&mut e, j("2026-11-08"), &frole(&tous), du_code));
        assert_eq!(
            e.montees,
            vec![Montee {
                quand: "2026-11-08".into(),
                regle: "LNX-TST-010".into(),
                avant_s: 600,
                apres_s: 1800,
                mesure_ms: 400_000,
            }]
        );
        assert_eq!(e.delais_longs(), BTreeSet::from(["LNX-TST-010".to_string()]));
        // Déjà montée : plus rien pour elle ; LNX-TST-011, qui frôle de nouveau depuis le 8, attend ses 7 jours.
        let deux = frole(&["LNX-TST-010", "LNX-TST-011"]);
        assert!(!ajuster_etat(&mut e, j("2026-11-14"), &deux, du_code));
        assert_eq!(e.montees.len(), 1);
        assert!(ajuster_etat(&mut e, j("2026-11-15"), &deux, du_code));
        assert_eq!(
            e.montees.iter().map(|m| m.regle.as_str()).collect::<Vec<_>>(),
            ["LNX-TST-010", "LNX-TST-011"]
        );
        assert_eq!(e.frolent_depuis.len(), 0);
    }

    fn dossier_d_essai(nom: &str) -> std::path::PathBuf {
        let d = crate::socle::dossier_local().join(format!("essai-reglage-{nom}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Annuler une montée rend le délai du code et ne la refait jamais ; couper rend les délais du code sans rien
    /// oublier ; « tout remettre » vide tout et coupe.
    #[test]
    fn chaque_changement_s_annule_exactement() {
        let d = dossier_d_essai("annuler");
        let mut e = Etat::default();
        e.frolent_depuis.insert("LNX-TST-010".into(), "2026-11-01".into());
        e.frolent_depuis.insert("LNX-TST-011".into(), "2026-11-01".into());
        assert!(ajuster_etat(
            &mut e,
            j("2026-11-08"),
            &frole(&["LNX-TST-010", "LNX-TST-011"]),
            du_code
        ));
        ecrire_dans(&d, &e).unwrap();
        assert_eq!(lire_dans(&d).delais_longs().len(), 2);

        mettre_en_marche_dans(&d, false).unwrap();
        assert_eq!(lire_dans(&d).delais_longs(), BTreeSet::new());
        mettre_en_marche_dans(&d, true).unwrap();
        assert_eq!(lire_dans(&d).delais_longs().len(), 2);

        assert!(annuler_dans(&d, "LNX-TST-010").unwrap());
        assert!(!annuler_dans(&d, "LNX-TST-010").unwrap());
        let Lu::Cru(mut apres) = lire_dans(&d) else {
            panic!("illisible")
        };
        assert_eq!(apres.delais_longs(), BTreeSet::from(["LNX-TST-011".to_string()]));
        // Elle frôle encore deux semaines : jamais remontée.
        apres.frolent_depuis.insert("LNX-TST-010".into(), "2026-11-08".into());
        ajuster_etat(&mut apres, j("2026-11-30"), &frole(&["LNX-TST-010"]), du_code);
        assert!(!apres.delais_longs().contains("LNX-TST-010"));

        tout_remettre_dans(&d).unwrap();
        assert_eq!(
            lire_dans(&d),
            Lu::Cru(Etat {
                v: 1,
                coupe: true,
                ..Etat::default()
            })
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un fichier posé hors de Vanguard (sans sceau) : les délais du code, et l'ajustement ne le réécrit pas.
    #[test]
    fn fichier_douteux_delais_du_code_et_rien_ecrit() {
        let d = dossier_d_essai("douteux");
        ecrire_dans(&d, &Etat::default()).unwrap();
        let force = br#"{"v":1,"montees":[{"quand":"2026-11-01","regle":"LNX-TST-010","avant_s":600,"apres_s":1800,"mesure_ms":1}]}"#;
        std::fs::write(d.join(REGLAGE), force).unwrap();
        assert_eq!(lire_dans(&d), Lu::Douteux);
        assert_eq!(lire_dans(&d).delais_longs(), BTreeSet::new());
        ajuster_dans(&d, j("2026-11-08"), &super::super::mesures::Mesures::default(), du_code);
        assert_eq!(std::fs::read(d.join(REGLAGE)).unwrap(), force);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Coupé, rien n'est ajusté.
    #[test]
    fn coupe_rien_n_est_ajuste() {
        let d = dossier_d_essai("coupe");
        tout_remettre_dans(&d).unwrap();
        let avant = std::fs::read(d.join(REGLAGE)).unwrap();
        let mut m = super::super::mesures::Mesures::default();
        m.ajouter(&[("LNX-TST-010", Duration::from_mins(9))], j("2026-11-08"));
        ajuster_dans(&d, j("2026-11-08"), &m, du_code);
        assert_eq!(std::fs::read(d.join(REGLAGE)).unwrap(), avant);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Chaque règle du registre, sur chaque système, a un identifiant que l'auto-réglage garde.
    #[test]
    fn chaque_regle_a_un_identifiant_garde() {
        use crate::machine::regles::{Os, regles};
        for os in [Os::Linux, Os::Windows, Os::MacOs, Os::Tous] {
            for r in regles(os) {
                assert!(id_valide(r.id), "{}", r.id);
            }
        }
        assert!(!id_valide("LNX-TST-01") && !id_valide("lnx-TST-010") && !id_valide("LNX_TST_010"));
    }

    proptest! {
        /// Quel que soit le contenu du fichier, chaque règle garde un délai entre celui du code et `DELAI_LONG`, et
        /// « tout remettre » rend exactement ceux du code.
        #[test]
        fn tout_fichier_reste_dans_les_bornes(
            octets in proptest::collection::vec(any::<u8>(), 0..400),
            ids in proptest::collection::vec("[A-Z]{3}-[A-Z]{3}-[0-9]{3}|LNX-[A-Z]{3}-0[0-9]{2}", 0..80),
            coupe in any::<bool>(),
            secs in any::<u64>(),
        ) {
            use crate::machine::regles::{Os, regles};
            let montees: Vec<serde_json::Value> = ids
                .iter()
                .map(|r| serde_json::json!({"quand": "2026-11-01", "regle": r, "avant_s": 600, "apres_s": secs % 3 * 1200 + 600, "mesure_ms": 1}))
                .collect();
            let json = serde_json::to_vec(&serde_json::json!({"v": 1, "coupe": coupe, "montees": montees})).unwrap();
            let toutes: Vec<_> = [Os::Linux, Os::Windows, Os::MacOs, Os::Tous].into_iter().flat_map(regles).collect();
            for contenu in [octets, json] {
                let e = lire_de(&contenu);
                prop_assert!(e.montees.len() <= MONTEES_MAX);
                prop_assert!(e.frolent_depuis.len() <= SUIVIES_MAX && e.refusees.len() <= SUIVIES_MAX);
                let longs = Lu::Cru(e).delais_longs();
                for r in &toutes {
                    let d = r.delai_avec(&longs);
                    prop_assert!(d >= r.delai() && d >= DELAI && d <= DELAI_LONG, "{} {:?}", r.id, d);
                }
            }
            let d = crate::socle::dossier_local().join("essai-reglage-bornes");
            let _ = std::fs::remove_dir_all(&d);
            tout_remettre_dans(&d).unwrap();
            let longs = lire_dans(&d).delais_longs();
            for r in &toutes {
                prop_assert_eq!(r.delai_avec(&longs), r.delai());
            }
            let _ = std::fs::remove_dir_all(&d);
        }

        /// Quelles que soient les mesures, l'ordre de départ lance chaque vérification une fois et une seule.
        #[test]
        fn toujours_une_permutation(
            n in 0usize..80,
            mesures in proptest::collection::btree_map("[A-C]{1,2}", any::<u64>(), 0..12),
            noms in proptest::collection::vec(proptest::option::of("[A-C]{1,2}"), 80),
        ) {
            let ids: Vec<Option<&str>> = noms.iter().take(n).map(Option::as_deref).collect();
            let mut ordre = ordre_de_depart(&ids, &mesures);
            prop_assert_eq!(permutation_ou_rangs(ordre.clone(), ids.len()), ordre.clone());
            ordre.sort_unstable();
            prop_assert_eq!(ordre, (0..ids.len()).collect::<Vec<_>>());
        }
    }
}
