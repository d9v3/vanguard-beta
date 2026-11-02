//! L'Agent Vanguard (sans IA) : un petit agent intégré, sans modèle d'IA, qui observe ce que Vanguard mesure sur cet
//! ordinateur, juge, puis règle ou propose, entre des bornes écrites ici. Rien ne sort de l'ordinateur.
//!
//! Une liste fermée de missions (`MissionId`), chacune avec son genre (`Genre`) : un réglage ajuste Vanguard lui-même
//! dans le sens sûr ou propose ; une détection signale ou propose ; un relevé note. Un tour (`tic`) passe, à un moment
//! donné (`Moment`), les missions qui l'écoutent : état lu, observation (lecture seulement, dans un budget), jugement
//! (pur, sur des types fermés), décisions vérifiées (genre, levier, sens sûr), ajustements appliqués, faits notés au
//! journal chaîné, état écrit.
//!
//! Les garde-fous, chacun essayé :
//! - **jamais de baisse de la détection** : un délai ne fait que monter (de `DELAI` à `DELAI_LONG`), une durée de
//!   cache que descendre (jamais sous le plancher de `autotest::cache::TABLE`, pour ses seules règles) ou revenir
//!   d'un pas que l'agent avait fait lui-même (jamais au-dessus de la durée du code), une cache que se couper ; un
//!   second essai ne relance qu'une fois, dans le délai total du bilan, et ne remplace un résultat que s'il conclut ;
//!   un seuil, un niveau, une règle, le blocage ne sont jamais à portée. Couper l'agent rend les valeurs du code : il
//!   ne retire aucune détection, les règles du bilan ne dépendent pas de lui ;
//! - **jamais sans accord** : une proposition ne fait rien ; l'agent n'a accès ni aux corrections ni au blocage. Il
//!   lit seulement l'issue des corrections appliquées (une règle, réussie ou non, une empreinte) pour en dire un
//!   avis, sans en retirer ni en masquer aucune ;
//! - **rien ne sort** : ni réseau, ni commande, ni élévation ; les droits de la personne seulement ;
//! - **jamais obéir à un texte** : aucune observation, aucun état, aucune ligne du journal ne porte de texte libre ;
//! - **jamais d'attente** : le verrou déjà pris, un jeu en cours (GameMode) ou l'autotest en lecture seule, et le
//!   tour est sauté ; un journal douteux aussi (l'agent n'agit pas sur un journal qu'il ne peut prolonger) ;
//! - **jamais sans ses bornes** : une mission dont l'état (le compte du jour) ne s'écrit pas n'agit pas.
//!
//! L'interrupteur de l'agent est celui de l'auto-réglage (Paramètres, « oui » par défaut) : « non » le coupe tout
//! entier, « tout remettre » vide aussi la cache, remet ses états à zéro et repart d'un journal neuf. Un geste de
//! Paramètres attend la fin d'un tour en cours (`geste_dans`) : il ne se perd pas au milieu d'un tour. Chaque mission
//! se coupe aussi seule, dans Paramètres (`couper_dans`, `agent/agent.json`, scellé) : coupée, elle ne prend plus
//! aucun tour ; un fichier des interrupteurs douteux (changé, retiré ou remplacé hors de Vanguard) les coupe toutes,
//! sauf une détection, qui ne fait qu'ajouter. Couper une mission ne retire rien au bilan : ses règles tournent
//! toutes ; la cache, sans sa mission, ne sert plus (tout se vérifie à neuf).
//!
//! Ce que l'agent dit de lui-même (`sortie`, `vanguard agent --json`) se lit de ses fichiers, sans rien écrire.

mod budget;
mod decision;
pub(crate) mod etat;
mod forme;
pub(crate) mod journal;
mod mission;
mod missions;
pub(crate) mod sortie;

use std::collections::BTreeSet;
use std::path::Path;

pub(crate) use budget::{Arret, Budget};
pub(crate) use decision::{Ajustement, Decision, Levier, Proposition, Signal};
pub(crate) use etat::Compteurs;
pub(crate) use forme::{Genre, Issue, MissionId, Moment, RegleId, ResumeBilan};
pub(crate) use mission::{Lecture, Mission};

use crate::machine::regles::{DELAI, DELAI_LONG};

/// Une mission vue par le tour, sans ses types : elle lit son état, observe, juge et écrit son état ; le tour fait le
/// reste.
pub(crate) trait Tourne: Send + Sync {
    fn id(&self) -> MissionId;
    fn genre(&self) -> Genre;
    fn moments(&self) -> &'static [Moment];
    /// Les décisions du tour, au plus ce que permet le budget ; `None` : mission sautée (état douteux, arrêt).
    fn tourner(&self, lu: &Lecture<'_>) -> Option<Vec<Decision>>;
}

impl<M: Mission> Tourne for M {
    fn id(&self) -> MissionId {
        Mission::id(self)
    }
    fn genre(&self) -> Genre {
        Mission::genre(self)
    }
    fn moments(&self) -> &'static [Moment] {
        Mission::moments(self)
    }
    fn tourner(&self, lu: &Lecture<'_>) -> Option<Vec<Decision>> {
        let nom = etat::nom_etat(Mission::id(self));
        let etat = etat::lire_dans::<M::Etat>(lu.dossier, nom).utilisable()?;
        let mut b = self.budget();
        let obs = self.observer(lu, &mut b).ok()?;
        b.temps().ok()?;
        let (mut decisions, nouvel) = self.juger(&obs, &etat);
        let nouvel = etat::Borne::borne(nouvel);
        // Le compte du jour (`etat::PAR_JOUR_MAX`) ne tient que s'il s'écrit : sinon, chaque tour repartirait de zéro.
        // Une mission qui décide l'écrit donc toujours, et n'agit pas s'il ne s'écrit pas. C'est aussi la preuve que le
        // dossier de l'agent prend encore une écriture scellée, juste avant le journal.
        if (nouvel != etat || !decisions.is_empty()) && etat::ecrire_dans(lu.dossier, nom, &nouvel).is_err() {
            return None;
        }
        decisions.truncate(usize::from(b.decisions()));
        Some(decisions)
    }
}

/// Les missions, dans l'ordre de `MissionId::TOUTES`.
fn missions() -> [&'static dyn Tourne; 4] {
    [
        &missions::Reglage,
        &missions::Cache,
        &missions::Releve,
        &missions::Corrections,
    ]
}

/// Pourquoi un tour n'a pas eu lieu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Saut {
    /// Aucune mission n'écoute ce moment.
    PersonneNEcoute,
    /// L'autotest tourne en lecture seule.
    LectureSeule,
    /// Un jeu tourne (GameMode) : rien ne doit le ralentir.
    EnJeu,
    /// Un autre tour tient le verrou : jamais d'attente.
    Occupe,
    /// Le journal est douteux ou rompu : l'agent n'agit pas sur un journal qu'il ne peut prolonger.
    JournalDouteux,
}

/// Ce qu'a fait un tour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tour {
    Saute(Saut),
    /// L'interrupteur de l'agent est à « non ».
    Coupe,
    Fait {
        appliquees: usize,
        montrees: usize,
        refusees: usize,
    },
}

/// Ce qu'un tour sait de son environnement.
pub(crate) struct Contexte<'a> {
    pub lecture: Lecture<'a>,
    /// Secondes depuis 1970.
    pub quand: i64,
    pub en_jeu: bool,
    /// L'interrupteur de l'agent (celui de l'auto-réglage) : `None` quand son fichier est douteux.
    pub en_marche: Option<bool>,
    /// Le relevé local (`amelioration`), appelé quand la mission du relevé a tourné, verrou de l'agent tenu : deux
    /// processus ne fusionnent donc jamais le même jour en même temps. Le tour ne sait pas ce qu'il écrit.
    pub relever: &'a dyn Fn(&Lecture<'_>, Moment),
}

/// Applique des ajustements déjà vérifiés ; rend ceux qui l'ont été vraiment.
pub(crate) type Appliquer<'f> = &'f dyn Fn(&Lecture<'_>, &[(MissionId, Ajustement)]) -> Vec<(MissionId, Ajustement)>;

/// L'empreinte d'une ligne du journal : BLAKE3, à clé dérivée propre (elle ne vaut pour aucun autre usage).
fn empreinte(o: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("vanguard agent journal 1");
    h.update(o);
    *h.finalize().as_bytes()
}

/// Le sens sûr d'un levier, et lui seul : un délai qui monte de `DELAI` (celui du code) à `DELAI_LONG`, une durée de
/// cache qui descend d'un pas sans passer sous le plancher, pour une règle de `autotest::cache::TABLE`, ou qui
/// remonte d'un pas sans dépasser la durée du code (l'application ne défait qu'un pas de l'agent lui-même), une cache
/// coupée pour une règle de la table, un second essai pour une règle du bilan dont plus de la moitié des « non
/// vérifiée » passagers ont conclu au bilan suivant.
pub(crate) fn sens_sur(lu: &Lecture<'_>, l: &Levier) -> bool {
    match *l {
        Levier::Delai {
            regle,
            avant_s,
            apres_s,
        } => {
            avant_s == DELAI.as_secs()
                && apres_s == DELAI_LONG.as_secs()
                && apres_s >= DELAI.as_secs()
                && (lu.delai_du_code)(regle.texte()) == Some(DELAI)
        }
        Levier::Cache {
            regle,
            avant_min,
            apres_min,
        } => crate::autotest::cache::en_cache(regle.texte()).is_some_and(|t| {
            t.plancher_min <= apres_min
                && apres_min < avant_min
                && avant_min <= t.duree_min
                && avant_min - apres_min == crate::autotest::cache::PAS_MIN
        }),
        Levier::CacheRallonge {
            regle,
            avant_min,
            apres_min,
        } => crate::autotest::cache::en_cache(regle.texte()).is_some_and(|t| {
            t.plancher_min <= avant_min
                && avant_min < apres_min
                && apres_min <= t.duree_min
                && apres_min - avant_min == crate::autotest::cache::PAS_MIN
        }),
        Levier::CacheCoupee { regle } => crate::autotest::cache::en_cache(regle.texte()).is_some(),
        Levier::SecondEssai {
            regle,
            passageres,
            reprises,
        } => {
            (lu.delai_du_code)(regle.texte()).is_some()
                && passageres >= 2
                && reprises <= passageres
                && u32::from(reprises) * 2 > u32::from(passageres)
        }
    }
}

/// La décision est-elle permise à cette mission : de son genre, d'un levier à elle, dans le sens sûr.
fn verifiee(lu: &Lecture<'_>, m: &dyn Tourne, d: &Decision) -> bool {
    decision::permise(m.genre(), d)
        && match d {
            Decision::Ajuster(a) => decision::levier_de(m.id(), &a.levier) && sens_sur(lu, &a.levier),
            Decision::Proposer(_) | Decision::Signaler(_) => true,
        }
}

/// Un tour : voir le commentaire du module.
pub(crate) fn tic_dans(ctx: &Contexte<'_>, moment: Moment, missions: &[&dyn Tourne], appliquer: Appliquer<'_>) -> Tour {
    let ecoutent: Vec<&dyn Tourne> = missions
        .iter()
        .copied()
        .filter(|m| m.moments().contains(&moment))
        .collect();
    if ecoutent.is_empty() {
        return Tour::Saute(Saut::PersonneNEcoute);
    }
    if crate::autotest::lecture_seule::active() {
        return Tour::Saute(Saut::LectureSeule);
    }
    if ctx.en_jeu {
        return Tour::Saute(Saut::EnJeu);
    }
    if ctx.en_marche == Some(false) {
        return Tour::Coupe;
    }
    let lu = &ctx.lecture;
    let Ok(_verrou) = crate::socle::Verrou::prendre(lu.dossier, "agent.lock", false, std::time::Duration::ZERO) else {
        return Tour::Saute(Saut::Occupe);
    };
    let entrees = match crate::sceau::juge_dans(lu.dossier, journal::JOURNAL) {
        crate::sceau::Juge::Absent => Vec::new(),
        crate::sceau::Juge::Cru(o) => {
            let j = journal::lire_de(&o, empreinte);
            if !j.intact() {
                return Tour::Saute(Saut::JournalDouteux);
            }
            j.entrees
        }
        _ => return Tour::Saute(Saut::JournalDouteux),
    };
    let interrupteurs = etat::lire_dans::<etat::Interrupteurs>(lu.dossier, etat::AGENT).utilisable();
    let mut faits = Vec::new();
    let mut ajustements = Vec::new();
    let (mut montrees, mut refusees) = (0, 0);
    // Une mission de réglage a tourné : l'application passe, même sans ajustement, pour que le suivi des règles qui
    // frôlent leur délai s'écrive (une montée écartée aujourd'hui se reprendra).
    let mut reglage_a_tourne = false;
    for m in ecoutent {
        let en_marche = match &interrupteurs {
            Some(i) => !i.coupees.contains(&m.id()),
            // Douteux : seule une détection (qui ne fait qu'ajouter) continue.
            None => m.genre() == Genre::Detection,
        };
        // Un réglage demande l'interrupteur de l'agent lisible et à « oui ».
        if !en_marche || (m.genre() == Genre::Reglage && ctx.en_marche != Some(true)) {
            continue;
        }
        let Some(decisions) = m.tourner(lu) else {
            continue;
        };
        reglage_a_tourne |= m.genre() == Genre::Reglage;
        if m.genre() == Genre::Releve {
            (ctx.relever)(lu, moment);
        }
        for d in decisions {
            if !verifiee(lu, m, &d) {
                refusees += 1;
                faits.push(journal::Fait::Refus {
                    mission: m.id(),
                    decision: d,
                });
            } else if let Decision::Ajuster(a) = d {
                ajustements.push((m.id(), a));
            } else {
                montrees += 1;
                faits.push(journal::Fait::Decision {
                    mission: m.id(),
                    decision: d,
                });
            }
        }
    }
    let appliquees = if ajustements.is_empty() && !reglage_a_tourne {
        Vec::new()
    } else {
        appliquer(lu, &ajustements)
    };
    // Rien n'est noté comme appliqué qui n'ait été demandé et vérifié.
    let appliquees: Vec<_> = appliquees.into_iter().filter(|a| ajustements.contains(a)).collect();
    faits.extend(appliquees.iter().map(|(mission, a)| journal::Fait::Decision {
        mission: *mission,
        decision: Decision::Ajuster(*a),
    }));
    // Rien n'a été appliqué sans que l'état de sa mission, scellé dans le même dossier, vienne de s'écrire
    // (`Tourne::tourner`) : l'écriture du journal réussit donc d'ordinaire. Si elle échoue quand même (disque plein
    // entre-temps), rien ne peut plus défaire le changement, mais il reste dans `reglage.json`, scellé, que Paramètres
    // montre et sait annuler.
    if !faits.is_empty() {
        let o = journal::ajouter(entrees, &faits, ctx.quand, empreinte);
        let _ = crate::sceau::ecrire_dans(lu.dossier, journal::JOURNAL, &o);
    }
    Tour::Fait {
        appliquees: appliquees.len(),
        montrees,
        refusees,
    }
}

/// Les corrections appliquées depuis le tour d'avant, en mémoire seulement (R6) : le tour suivant de ce processus
/// (la fin d'un bilan, ou la sortie) les remet à la mission des corrections. Bornées : une liste qui déborde perd les
/// plus récentes, ce qui ne fait que taire un avis.
static NOTES: std::sync::Mutex<Vec<forme::NoteCorrection>> = std::sync::Mutex::new(Vec::new());
const NOTES_MAX: usize = 64;

/// Note le résultat d'une correction appliquée (R6) : sa règle, réussie ou non, et l'empreinte du problème qu'elle
/// corrigeait (jamais son texte). Une règle inconnue n'est pas notée.
pub(crate) fn noter_correction(regle: &str, reussie: bool, empreinte: Option<u64>) {
    let Some(regle) = forme::RegleId::depuis(regle) else {
        return;
    };
    let issue = if reussie {
        forme::IssueCorrection::Reussie { empreinte }
    } else {
        forme::IssueCorrection::Echouee(forme::CodeEchec::Echoue)
    };
    let note = forme::NoteCorrection {
        regle,
        issue,
        quand_ms: chrono::Utc::now().timestamp_millis(),
    };
    let mut n = NOTES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if n.len() < NOTES_MAX {
        n.push(note);
    }
}

fn notes_prises() -> Vec<forme::NoteCorrection> {
    std::mem::take(&mut *NOTES.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
}

/// Un tour sauté rend ses notes : le tour suivant les reprendra. Au-delà de `NOTES_MAX`, les plus vieilles
/// tombent.
fn notes_rendues(mut v: Vec<forme::NoteCorrection>) {
    let mut n = NOTES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    v.append(&mut n);
    let trop = v.len().saturating_sub(NOTES_MAX);
    v.drain(..trop);
    *n = v;
}

fn notes_en_attente() -> bool {
    !NOTES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_empty()
}

/// Ce que l'agent sait des corrections de cet ordinateur (R6), pour les dire : rien quand l'auto-réglage est coupé
/// ou douteux, la mission coupée, ou son état douteux.
#[derive(Default)]
pub(crate) struct AvisCorrections {
    etat: etat::EtatCorrections,
}

/// Ce que l'agent dit d'une correction (R6) : de l'information seulement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Avis {
    /// Échouée `n` fois de suite ici (2 au moins), avec ce code.
    pub fragile: Option<(u16, &'static str)>,
    /// Son problème est revenu après la correction.
    pub ne_tient_pas: bool,
}

impl AvisCorrections {
    pub(crate) fn de(&self, regle: &str) -> Avis {
        let Some(id) = forme::RegleId::depuis(regle) else {
            return Avis::default();
        };
        let (fragile, ne_tient_pas) = self.etat.avis(id);
        Avis {
            fragile: fragile.map(|(n, code)| (n, code.code())),
            ne_tient_pas,
        }
    }
}

/// L'avis de l'agent sur les corrections, lu de son état (`agent/etat/corrections.json`).
pub(crate) fn avis_corrections() -> AvisCorrections {
    avis_corrections_dans(&crate::socle::dossier_local(), chrono::Local::now().date_naive())
}

/// L'avis lu dans `dossier`, le jour `aujourd_hui` : ce qui a passé sa durée ne se dit plus, même sans tour depuis.
pub(crate) fn avis_corrections_dans(dossier: &Path, aujourd_hui: chrono::NaiveDate) -> AvisCorrections {
    if crate::autotest::reglage::en_marche_dans(dossier) != Some(true) {
        return AvisCorrections::default();
    }
    let coupee = etat::lire_dans::<etat::Interrupteurs>(dossier, etat::AGENT)
        .utilisable()
        .is_none_or(|i| i.coupees.contains(&MissionId::Corrections));
    if coupee {
        return AvisCorrections::default();
    }
    let lu = etat::lire_dans::<etat::EtatCorrections>(dossier, etat::nom_etat(MissionId::Corrections));
    AvisCorrections {
        etat: lu
            .utilisable()
            .unwrap_or_default()
            .au_jour(mission::jour_de(aujourd_hui)),
    }
}

/// Un tour de l'agent, au moment `moment`, sur cet ordinateur. Jamais d'attente : voir `tic_dans`.
pub(crate) fn tic(moment: Moment) {
    tic_avec(moment, None);
}

/// Le tour de la fin d'un bilan, avec ce qu'il a trouvé (R4, R6).
pub(crate) fn tic_bilan(bilan: &forme::ResumeBilan) {
    tic_avec(Moment::FinDeBilan, Some(bilan));
}

fn tic_avec(moment: Moment, bilan: Option<&forme::ResumeBilan>) {
    let missions = missions();
    if !missions.iter().any(|m| m.moments().contains(&moment)) {
        return;
    }
    // À la sortie, rien à noter, rien à lire : une commande courte ne paie pas le tour.
    if moment == Moment::Sortie && !crate::amelioration::a_noter() && !notes_en_attente() {
        return;
    }
    let notes = notes_prises();
    let dossier = crate::socle::dossier_local();
    let mesures = crate::autotest::mesures::lues();
    let delai_du_code = |id: &str| {
        crate::machine::regles::regles(crate::machine::regles::Os::actuel())
            .into_iter()
            .find(|r| r.id == id)
            .map(crate::machine::regles::Regle::delai)
    };
    let ctx = Contexte {
        lecture: Lecture {
            dossier: &dossier,
            aujourd_hui: chrono::Local::now().date_naive(),
            mesures: &mesures,
            delai_du_code: &delai_du_code,
            bilan,
            corrections: &notes,
        },
        quand: chrono::Utc::now().timestamp(),
        en_jeu: en_jeu(),
        en_marche: crate::autotest::reglage::en_marche_dans(&dossier),
        relever: &|lu, m| crate::amelioration::relever(lu.dossier, lu.aujourd_hui, lu.mesures, m),
    };
    if let Tour::Saute(_) = tic_dans(&ctx, moment, &missions, &appliquer) {
        notes_rendues(notes);
    }
}

/// Les ajustements appliqués, par l'auto-réglage (`autotest::reglage`, où vivent les leviers) : seuls ceux demandés
/// ici, déjà vérifiés, sont retenus ; rend ceux qui ont été écrits.
fn appliquer(lu: &Lecture<'_>, a: &[(MissionId, Ajustement)]) -> Vec<(MissionId, Ajustement)> {
    let demande = |id: MissionId, x: Option<Ajustement>| x.is_some_and(|x| a.contains(&(id, x)));
    let fait = crate::autotest::reglage::ajuster_retenus_dans(
        lu.dossier,
        lu.aujourd_hui,
        lu.mesures,
        lu.delai_du_code,
        &crate::autotest::reglage::Retenus {
            montee: &|m| demande(MissionId::Reglage, missions::de_montee(m)),
            pas: &|r| demande(MissionId::Cache, missions::de_raccourcie(r)),
            rallongee: &|r| demande(MissionId::Cache, missions::de_rallongee(r)),
            coupure: &|c| demande(MissionId::Cache, missions::de_coupure(c)),
        },
    );
    // Les seconds essais demandés, vérifiés : l'auto-réglage les note (`reglage.json`), le bilan suivant les lit.
    let relances: Vec<_> = a
        .iter()
        .filter_map(|(id, x)| match x.levier {
            Levier::SecondEssai {
                regle,
                passageres,
                reprises,
            } if *id == MissionId::Reglage => {
                Some((regle.texte().to_owned(), u32::from(passageres), u32::from(reprises)))
            }
            _ => None,
        })
        .collect();
    let donnees = crate::autotest::reglage::relancer_dans(lu.dossier, lu.aujourd_hui, &relances);
    let reglage = fait
        .montees
        .iter()
        .filter_map(missions::de_montee)
        .chain(donnees.iter().filter_map(missions::de_relance))
        .map(|x| (MissionId::Reglage, x));
    let cache = fait
        .coupures
        .iter()
        .filter_map(missions::de_coupure)
        .chain(fait.raccourcies.iter().filter_map(missions::de_raccourcie))
        .chain(fait.rallongees.iter().filter_map(missions::de_rallongee))
        .map(|x| (MissionId::Cache, x));
    reglage.chain(cache).collect()
}

/// Un jeu tourne-t-il (GameMode, sous Linux) ? Ailleurs, rien ne le dit : non.
fn en_jeu() -> bool {
    #[cfg(all(target_os = "linux", not(test)))]
    {
        crate::machine::linux::dbus::gamemode_actif() == Some(true)
    }
    #[cfg(not(all(target_os = "linux", not(test))))]
    {
        false
    }
}

/// L'attente d'un geste de Paramètres derrière un tour : un tour prend d'ordinaire quelques millisecondes, et son
/// budget dix secondes par mission au plus. Au-delà, le geste échoue et le dit, plutôt que de figer Paramètres.
const ATTENTE_GESTE: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_secs(1)
} else {
    std::time::Duration::from_secs(10)
};

/// Le verrou de l'agent, tenu par un geste de Paramètres qui change ce qu'un tour lit ou écrit (`reglage.json`, les
/// états, le journal). Sans lui, un tour qui a lu le journal avant le geste le réécrivait après, avec ses anciennes
/// lignes : la ligne « tout remettre » se perdait, ou ses compteurs survivaient à la remise à zéro.
pub(crate) struct Geste {
    _verrou: crate::socle::Verrou,
}

/// Prend le verrou de l'agent pour un geste (voir `Geste`), en attendant la fin d'un tour en cours.
pub(crate) fn geste_dans(dossier: &Path) -> std::io::Result<Geste> {
    crate::socle::Verrou::prendre(dossier, "agent.lock", false, ATTENTE_GESTE)
        .map(|v| Geste { _verrou: v })
        .map_err(|_| {
            std::io::Error::other(crate::tr!(
                "l'Agent Vanguard (sans IA) est en plein tour : réessayez dans un moment",
                "the Vanguard Agent (no AI) is busy: try again in a moment"
            ))
        })
}

/// « Tout remettre » (Paramètres), sous le verrou d'un geste : les états des missions et leurs interrupteurs
/// reviennent à l'origine, et l'agent repart d'un journal neuf, scellé, dont la première ligne le note. Un journal
/// douteux (changé hors de Vanguard, ou à moitié écrit) arrêtait sinon l'agent pour toujours : c'est sa seule issue.
pub(crate) fn tout_remettre_dans(dossier: &Path, quand: i64, _geste: &Geste) -> std::io::Result<()> {
    for id in MissionId::TOUTES {
        etat::ecrire_dans(dossier, etat::nom_etat(id), &Compteurs::default())?;
    }
    etat::ecrire_dans(dossier, etat::AGENT, &etat::Interrupteurs::default())?;
    let o = journal::ajouter(Vec::new(), &[journal::Fait::ToutRemis], quand, empreinte);
    crate::sceau::ecrire_dans(dossier, journal::JOURNAL, &o)
}

/// La mission `id` est-elle coupée dans `dossier` : son interrupteur à « non », ou le fichier des interrupteurs
/// douteux (seule une détection continue alors, comme au tour).
pub(crate) fn mission_coupee_dans(dossier: &Path, id: MissionId) -> bool {
    match etat::lire_dans::<etat::Interrupteurs>(dossier, etat::AGENT).utilisable() {
        Some(i) => i.coupees.contains(&id),
        None => missions().iter().any(|m| m.id() == id && m.genre() != Genre::Detection),
    }
}

/// Coupe (`coupee`) ou remet en marche la mission `id` (Paramètres), sous le verrou d'un geste ; rend vrai si
/// l'interrupteur a changé. Un fichier douteux repart de ce qui vaut pendant le doute : toutes coupées, sauf les
/// détections ; seul ce geste-là en remet une en marche. Rien d'autre ne change : ni l'état de la mission, ni le
/// journal, ni ce qu'elle a déjà réglé (qui s'annule dans Paramètres).
pub(crate) fn couper_dans(dossier: &Path, id: MissionId, coupee: bool, _geste: &Geste) -> std::io::Result<bool> {
    let lu = etat::lire_dans::<etat::Interrupteurs>(dossier, etat::AGENT);
    let douteux = matches!(lu, etat::Lu::Douteux);
    let mut i = lu.utilisable().unwrap_or_else(|| etat::Interrupteurs {
        v: 1,
        coupees: missions()
            .iter()
            .filter(|m| m.genre() != Genre::Detection)
            .map(|m| m.id())
            .collect::<BTreeSet<_>>(),
    });
    let change = if coupee {
        i.coupees.insert(id)
    } else {
        i.coupees.remove(&id)
    };
    if !change && !douteux {
        return Ok(false);
    }
    etat::ecrire_dans(dossier, etat::AGENT, &i)?;
    Ok(change)
}

#[cfg(test)]
mod tests;
