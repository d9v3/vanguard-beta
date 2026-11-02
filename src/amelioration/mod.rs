//! L'auto-amélioration (plan des lots A1 à A8) : ce que Vanguard apprend de ses propres erreurs, sur l'ordinateur où
//! il tourne, sans qu'aucun secret ni rien de personnel n'en sorte. A1 en pose la voie ouverte (les textes, noms et
//! versions venus de l'ordinateur, nettoyés par `texte`) ; A2, le relevé local (`releve`, `materiel`, et ce module).
//!
//! Le relevé note, dans la mémoire du programme, ce qui arrive au fil de l'eau (bilans, causes du journal,
//! corrections, choix, outils), en comptes agrégés par clé, jamais un événement brut ; la mission du relevé de l'Agent
//! Vanguard (`agent::missions::Releve`) le verse ensuite, verrou de l'agent tenu, dans le fichier du jour
//! (`amelioration/jours/AAAA-MM-JJ.json`, scellé). Rien n'en sort : ni réseau, ni commande, ni élévation ; le lot
//! d'un jour (`lot_du_jour`) n'est que construit, son envoi est à A4.
//!
//! Jamais relevé : sous les essais (`cfg(test)`), sous Wine, dans la CI, avec `VANGUARD_ENVOI=0` (qui l'emporte
//! toujours), ni depuis une clé VANGUARD (son programme sert sur des ordinateurs qui ne sont pas les siens).

pub(crate) mod materiel;
pub(crate) mod releve;
pub(crate) mod texte;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::compte_rendu::champs::{Code, Contexte, Regle};
use crate::compte_rendu::envoi::{
    CacheRegle, CauseEnvoyee, Compte, Etat, Levier, Lot, MS_MAX, Materiel, NomOutil, Nombre, ObjetEnvoye, Origine,
    Reglage, Sorte,
};
use crate::compte_rendu::journal::Champs;
use crate::machine::Constat;
use releve::{Brouillon, Durees, OutilJour, RegleJour, TexteJour};

pub(crate) use texte::{NomLogiciel, Rejet, TexteNettoye, VersionTierce};

/// Le suivi d'un jour à l'autre : les corrections réussies à revoir au bilan suivant, et la base des compteurs
/// cumulés de la cache (`mesures.json`), pour n'en relever que ce qui a changé.
pub(crate) const SUIVI: &str = "amelioration/suivi.json";
/// Le matériel, relu une fois par semaine.
pub(crate) const MATERIEL: &str = "amelioration/materiel.json";
/// Les fichiers des jours, chacun scellé sous son nom (« amelioration/jours/2026-11-02.json »).
pub(crate) const JOURS: &str = "amelioration/jours";

/// Une correction réussie se revoit au plus 7 jours ; au-delà, son retour ne se lie plus à elle.
const SUIVI_JOURS: i64 = 7;
/// Corrections suivies au plus, et bilans gardés en mémoire entre deux relevés.
const SUIVIES_MAX: usize = 100;
const BILANS_MAX: usize = 4;
/// Le matériel est relu au bout de 7 jours.
const MATERIEL_JOURS: i64 = 7;
/// Le suivi n'a pas de raison de dépasser quelques Kio.
const SUIVI_MAX: usize = 64 << 10;

// --- Où le relevé a droit de cité --------------------------------------------------------------------------------

/// Ce qui décide si ce processus relève : chaque cas qui l'empêche, pris un à un.
#[allow(clippy::struct_excessive_bools)] // un empêchement par champ, chacun pour lui-même
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Lieu {
    pub(crate) essai: bool,
    pub(crate) wine: bool,
    pub(crate) ci: bool,
    pub(crate) envoi_coupe: bool,
    pub(crate) depuis_une_cle: bool,
    /// Lancé en root (sudo, ou root d'un espace de noms) : le dossier serait celui de root, pas celui du compte qui
    /// se sert de l'ordinateur, et le programme n'y écrit déjà rien d'autre qu'il puisse éviter.
    pub(crate) en_root: bool,
}

/// Le relevé n'a lieu que si rien ne l'empêche.
pub(crate) fn permis(l: Lieu) -> bool {
    !(l.essai || l.wine || l.ci || l.envoi_coupe || l.depuis_une_cle || l.en_root)
}

/// Le lieu de ce processus, lu une fois.
fn lieu() -> Lieu {
    #[cfg(windows)]
    let wine = crate::commande::sous_wine();
    #[cfg(not(windows))]
    let wine = false;
    Lieu {
        essai: cfg!(test),
        wine,
        ci: std::env::var_os("CI").is_some_and(|v| !v.is_empty()),
        envoi_coupe: std::env::var("VANGUARD_ENVOI").is_ok_and(|v| v.trim() == "0"),
        // Sous les essais, on ne cherche même pas la clé : `permis` dit déjà non.
        depuis_une_cle: !cfg!(test) && crate::reseau::cle_du_programme().is_some(),
        #[cfg(unix)]
        en_root: crate::socle::euid() == 0,
        #[cfg(not(unix))]
        en_root: false,
    }
}

/// « Ne pas partager » : arrêté pour ce processus, quoi qu'il arrive ensuite.
static ARRETE: AtomicBool = AtomicBool::new(false);

/// Ce processus relève-t-il ?
pub(crate) fn actif() -> bool {
    static PERMIS: OnceLock<bool> = OnceLock::new();
    !ARRETE.load(Ordering::Relaxed) && *PERMIS.get_or_init(|| permis(lieu()))
}

// --- La mémoire du programme -------------------------------------------------------------------------------------

/// Une correction réussie, par sa règle et l'empreinte de sa clé (jamais la clé elle-même : l'objet peut être un
/// chemin), et quand (ms depuis 1970).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Corrigee {
    pub(crate) regle: Regle,
    pub(crate) empreinte: u64,
    pub(crate) quand: i64,
}

/// Un bilan : les règles qui y ont rendu un constat, et les empreintes de ses problèmes.
#[derive(Clone, Debug, Default)]
pub(crate) struct Bilan {
    pub(crate) quand: i64,
    pub(crate) regles: BTreeSet<Regle>,
    pub(crate) problemes: BTreeSet<u64>,
}

/// Ce que ce processus a noté depuis son dernier relevé.
#[derive(Default)]
pub(crate) struct Memoire {
    pub(crate) brouillon: Brouillon,
    pub(crate) corrigees: Vec<Corrigee>,
    pub(crate) bilans: Vec<Bilan>,
}

impl Memoire {
    fn est_vide(&self) -> bool {
        self.brouillon.est_vide() && self.corrigees.is_empty() && self.bilans.is_empty()
    }

    /// Reprend ce qu'un relevé manqué n'a pas pu écrire.
    fn reprendre(&mut self, m: Memoire) {
        self.brouillon.fusionner(&m.brouillon);
        let mut corrigees = m.corrigees;
        corrigees.append(&mut self.corrigees);
        corrigees.truncate(SUIVIES_MAX);
        self.corrigees = corrigees;
        let mut bilans = m.bilans;
        bilans.append(&mut self.bilans);
        bilans.truncate(BILANS_MAX);
        self.bilans = bilans;
    }
}

static MEMOIRE: LazyLock<Mutex<Memoire>> = LazyLock::new(|| Mutex::new(Memoire::default()));
/// Les refus du nettoyage (`texte::refus_locaux`, cumulés depuis le début du processus) déjà versés au relevé.
static REFUS_VERSES: AtomicU64 = AtomicU64::new(0);

/// Note dans la mémoire, sans jamais attendre : la mémoire prise (un relevé en cours, un autre fil), l'événement est
/// perdu plutôt que de faire attendre le programme.
fn noter(f: impl FnOnce(&mut Memoire)) {
    if !actif() {
        return;
    }
    if let Ok(mut m) = MEMOIRE.try_lock() {
        f(&mut m);
    }
}

/// Y a-t-il quelque chose à verser ? À la sortie, le tour de l'agent n'est payé que dans ce cas.
pub(crate) fn a_noter() -> bool {
    actif()
        && (texte::refus_locaux() != REFUS_VERSES.load(Ordering::Relaxed)
            || MEMOIRE.try_lock().map_or(true, |m| !m.est_vide()))
}

fn maintenant_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// L'empreinte d'une clé de constat : BLAKE3 à clé dérivée propre, 8 octets ; elle reconnaît le même problème d'un
/// bilan à l'autre sans rien garder de lisible.
pub(crate) fn empreinte(cle: &crate::modele::Cle) -> u64 {
    let h = blake3::derive_key(
        "vanguard releve suivi 1",
        format!("{}\0{}", cle.regle, cle.objet).as_bytes(),
    );
    let mut o = [0u8; 8];
    o.copy_from_slice(h.get(..8).unwrap_or(&[0; 8]));
    u64::from_le_bytes(o)
}

/// Un compte de 1.
fn un<const M: u32>() -> Compte<M> {
    Compte::new(1)
}

/// Ajoute à une table du brouillon, et compte ce qui n'y tient pas.
macro_rules! ajouter {
    ($b:expr, $table:ident, $e:expr) => {
        if !$b.$table.ajouter($e) {
            $b.retires.$table.ajouter(1);
        }
    };
}

// --- Les événements ----------------------------------------------------------------------------------------------

/// La sorte d'un objet, d'après le genre de sa clé (« paquet:openssl ») ; les autres genres (chemin, port, adresse…)
/// ne sont jamais des noms à garder.
fn sorte_de(genre: &str) -> Option<Sorte> {
    Some(match genre {
        "programme" => Sorte::Programme,
        "service" => Sorte::Service,
        "pilote" => Sorte::Pilote,
        "paquet" => Sorte::Paquet,
        "unite" => Sorte::Unite,
        "flatpak" => Sorte::Flatpak,
        "module" => Sorte::Module,
        _ => return None,
    })
}

/// Un bilan vient de finir. `nom_garde` dit, par identifiant, les règles qui gardent le nom de leur objet
/// (`machine::regles::Partage::Nom`) ; `manuel` : demandé, pas la passe horaire.
pub(crate) fn noter_bilan(constats: &[Constat], nom_garde: &dyn Fn(&str) -> bool, manuel: bool) {
    // L'autotest rejoue des bilans en lecture seule : ce ne sont pas ceux de la personne.
    if !actif() || crate::autotest::lecture_seule::active() {
        return;
    }
    // Le nettoyage des noms et des textes coûte : fait hors de la mémoire, qui n'est prise qu'à la fin.
    let mut m = Memoire::default();
    noter_bilan_dans(&mut m, constats, nom_garde, manuel, maintenant_ms());
    noter(|x| x.reprendre(m));
}

pub(crate) fn noter_bilan_dans(
    m: &mut Memoire,
    constats: &[Constat],
    nom_garde: &dyn Fn(&str) -> bool,
    manuel: bool,
    quand: i64,
) {
    use crate::modele::{Etat as Vu, Objet, Raison};
    let b = &mut m.brouillon;
    let mut bilan = Bilan {
        quand,
        ..Bilan::default()
    };
    for c in constats {
        let Some(regle) = Regle::new(c.regle) else {
            continue;
        };
        let mut r = RegleJour::new(regle.clone());
        let etat = match c.etat() {
            Vu::Sain => {
                r.sains = un();
                Etat::Sain
            }
            Vu::Probleme { .. } => {
                r.problemes = un();
                if let Some(k) = c.cle() {
                    bilan.problemes.insert(empreinte(&k));
                }
                Etat::Probleme
            }
            Vu::NonVerifie(raison) => {
                r.non_verifies = un();
                if raison == Raison::Delai {
                    r.hors_delai = un();
                }
                if let Some(code) = Code::new(raison.code()) {
                    r.raisons = releve::code_plus(&r.raisons, code);
                }
                match &raison {
                    // Le nom de l'outil qui manque, écrit par le code de la règle.
                    Raison::Absente(outil) => {
                        if let (Ok(nom), Some(n)) = (nom(outil), Nombre::new(1)) {
                            ajouter!(
                                b,
                                objets,
                                ObjetEnvoye {
                                    regle: regle.clone(),
                                    sorte: Sorte::Programme,
                                    nom,
                                    version: None,
                                    etat: Etat::NonVerifie,
                                    n,
                                }
                            );
                        }
                    }
                    // Le pourquoi du système : la voie ouverte, nettoyée.
                    Raison::Illisible(t) => {
                        if let (Ok(texte), Some(n)) = (texte(t), Nombre::new(1)) {
                            ajouter!(
                                b,
                                textes,
                                TexteJour {
                                    texte,
                                    contexte: Contexte::VerificationImpossible,
                                    regle: Some(regle.clone()),
                                    n,
                                }
                            );
                        }
                    }
                    _ => {}
                }
                Etat::NonVerifie
            }
            Vu::SansObjet(_) => continue,
        };
        bilan.regles.insert(regle.clone());
        ajouter!(b, regles, r);
        if nom_garde(c.regle)
            && let Objet::De(o) = &c.objet
            && let Some((genre, valeur)) = o.split_once(':')
            && let Some(sorte) = sorte_de(genre)
            && let (Ok(nom), Some(n)) = (nom(valeur), Nombre::new(1))
        {
            ajouter!(
                b,
                objets,
                ObjetEnvoye {
                    regle,
                    sorte,
                    nom,
                    version: None,
                    etat,
                    n,
                }
            );
        }
    }
    if manuel {
        b.bilans_manuels = b.bilans_manuels.saturating_add(1);
    } else {
        b.passes_horaires = b.passes_horaires.saturating_add(1);
    }
    if m.bilans.len() < BILANS_MAX {
        m.bilans.push(bilan);
    }
}

/// Ce qu'il advient d'une correction proposée.
#[derive(Clone, Debug)]
pub(crate) enum Issue {
    Proposee,
    Acceptee,
    Refusee,
    /// Avec la clé du constat corrigé, pour voir au bilan suivant s'il revient.
    Reussie(Option<crate::modele::Cle>),
    Echouee,
}

pub(crate) fn noter_correction(regle: &str, issue: Issue) {
    let quand = maintenant_ms();
    noter(|m| noter_correction_dans(m, regle, issue, quand));
}

pub(crate) fn noter_correction_dans(m: &mut Memoire, regle: &str, issue: Issue, quand: i64) {
    let Some(r) = Regle::new(regle) else {
        return;
    };
    let mut c = releve::correction(r.clone());
    match issue {
        Issue::Proposee => c.proposees = un(),
        Issue::Acceptee => c.acceptees = un(),
        Issue::Refusee => c.refusees = un(),
        Issue::Echouee => c.echouees = un(),
        Issue::Reussie(cle) => {
            c.reussies = un();
            if let Some(k) = cle
                && m.corrigees.len() < SUIVIES_MAX
            {
                m.corrigees.push(Corrigee {
                    regle: r,
                    empreinte: empreinte(&k),
                    quand,
                });
            }
        }
    }
    ajouter!(m.brouillon, corrections, c);
}

/// Un choix de la personne sur une règle.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Choisi {
    /// « C'est normal chez moi ».
    Normale,
    /// Ce choix oublié (Paramètres, « Ce que Vanguard a appris »).
    Oubli,
    /// Une correction refusée.
    Refus,
}

pub(crate) fn noter_choix(regle: &str, choisi: Choisi) {
    noter(|m| noter_choix_dans(m, regle, choisi));
}

pub(crate) fn noter_choix_dans(m: &mut Memoire, regle: &str, choisi: Choisi) {
    let Some(r) = Regle::new(regle) else {
        return;
    };
    let mut c = releve::choix(r);
    match choisi {
        Choisi::Normale => c.normales = un(),
        Choisi::Oubli => c.oublis = un(),
        Choisi::Refus => c.refus = un(),
    }
    ajouter!(m.brouillon, choix, c);
}

/// Un outil lancé (par le nom de sa sous-commande, jamais ses arguments).
pub(crate) fn outil_lance(commande: &str, origine: Origine) {
    noter(|m| outil_dans(m, commande, origine, None));
}

/// L'outil lancé en ligne de commande et son départ : sa fin se note une fois, en fin de `main` comme dans
/// `machine::quitter` (un code de retour), sans quoi un outil qui rend un code ressemblerait à un plantage.
static EN_LIGNE: Mutex<Option<(&'static str, std::time::Instant)>> = Mutex::new(None);

pub(crate) fn ligne_lancee(commande: &'static str) {
    outil_lance(commande, Origine::Ligne);
    if let Ok(mut l) = EN_LIGNE.lock() {
        *l = Some((commande, std::time::Instant::now()));
    }
}

/// La fin de l'outil lancé en ligne, s'il y en a un et qu'elle n'est pas déjà notée.
pub(crate) fn ligne_finie() {
    let pris = EN_LIGNE.lock().ok().and_then(|mut l| l.take());
    if let Some((commande, debut)) = pris {
        outil_fini(commande, Origine::Ligne, false, debut.elapsed());
    }
}

/// Un outil fini, ou laissé (« revenir »), et sa durée.
pub(crate) fn outil_fini(commande: &str, origine: Origine, abandonne: bool, duree: std::time::Duration) {
    noter(|m| outil_dans(m, commande, origine, Some((abandonne, duree))));
}

pub(crate) fn outil_dans(m: &mut Memoire, commande: &str, origine: Origine, fin: Option<(bool, std::time::Duration)>) {
    let Some(outil) = NomOutil::new(commande) else {
        return;
    };
    let mut o = OutilJour::new(outil, origine);
    match fin {
        None => o.lances = un(),
        Some((true, _)) => o.abandonnes = un(),
        Some((false, d)) => {
            o.finis = un();
            o.durees
                .push(u32::try_from(d.as_millis()).unwrap_or(MS_MAX).min(MS_MAX));
        }
    }
    ajouter!(m.brouillon, outils, o);
}

/// Une entrée du journal des erreurs : ses champs fermés, et le gabarit de son détail (jamais le détail).
pub(crate) fn noter_cause(champs: &Champs, detail: &str) {
    if !actif() {
        return;
    }
    let cause = cause(champs, detail);
    noter(|m| ajouter!(m.brouillon, causes, cause));
}

pub(crate) fn cause(champs: &Champs, detail: &str) -> CauseEnvoyee {
    CauseEnvoyee {
        genre: champs.genre,
        contexte: champs.contexte,
        regle: champs.regle.clone(),
        lieu: champs.lieu.clone(),
        code: champs.code.clone(),
        n: Nombre::new(1).unwrap_or_else(|| unreachable!("1 > 0")),
        duree_ms: Compte::default(),
        en_plus: Compte::default(),
        en_moins: Compte::default(),
        differents: Compte::default(),
        gabarit: texte(detail).ok().map(|t| texte::Gabarit::de(&t)),
    }
}

// --- Le relevé : la mémoire versée dans le fichier du jour -------------------------------------------------------

/// Le nom du fichier d'un jour.
pub(crate) fn nom_jour(jour: chrono::NaiveDate) -> String {
    format!("{JOURS}/{}.json", jour.format("%Y-%m-%d"))
}

/// La base des compteurs cumulés de la cache d'une règle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Base {
    repris: u64,
    a_neuf: u64,
    age_total_s: u64,
    gagne_ms: u64,
    comparees: u64,
    ecarts: u64,
}

impl Base {
    fn de(c: &crate::autotest::mesures::Cache) -> Base {
        Base {
            repris: u64::from(c.repris),
            a_neuf: u64::from(c.a_neuf),
            age_total_s: c.age_total_s,
            gagne_ms: c.gagne_ms,
            comparees: u64::from(c.comparees),
            ecarts: u64::from(c.ecarts),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Suivi {
    #[serde(default)]
    pub(crate) corrigees: Vec<Corrigee>,
    #[serde(default)]
    pub(crate) cache: BTreeMap<Regle, Base>,
    /// Le jour (« AAAA-MM-JJ ») où le matériel a été lu.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) materiel_le: Option<String>,
}

/// Relit le suivi : douteux, trop gros ou hors forme, il repart de zéro (une base neuve ne relève rien de faux : les
/// compteurs de la cache repartent de la valeur vue).
fn suivi_dans(dossier: &Path) -> Suivi {
    crate::sceau::juge_dans(dossier, SUIVI)
        .cru()
        .filter(|o| o.len() <= SUIVI_MAX)
        .and_then(|o| serde_json::from_slice::<Suivi>(&o).ok())
        .filter(|s| s.corrigees.len() <= SUIVIES_MAX && s.cache.len() <= crate::compte_rendu::envoi::CACHE_MAX)
        .unwrap_or_default()
}

/// Le matériel écrit, et le jour où il a été lu.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MaterielLu {
    /// « AAAA-MM-JJ ».
    pub(crate) jour: String,
    pub(crate) materiel: Materiel,
}

fn materiel_dans(dossier: &Path) -> Option<MaterielLu> {
    crate::sceau::juge_dans(dossier, MATERIEL)
        .cru()
        .filter(|o| o.len() <= materiel::MATERIEL_MAX)
        .and_then(|o| serde_json::from_slice(&o).ok())
}

/// Les retours : une correction réussie dont le problème est encore là au premier bilan qui passe sa règle ensuite.
/// Revu ce bilan-là, le suivi l'oublie, revenu ou non ; sans bilan de sa règle en 7 jours, aussi.
pub(crate) fn revenues(corrigees: &mut Vec<Corrigee>, bilans: &[Bilan], maintenant: i64) -> Vec<Regle> {
    let mut revenues = Vec::new();
    corrigees.retain(|c| {
        let bilan = bilans.iter().find(|b| b.quand > c.quand && b.regles.contains(&c.regle));
        if let Some(b) = bilan {
            if b.problemes.contains(&c.empreinte) {
                revenues.push(c.regle.clone());
            }
            return false;
        }
        // Une date à venir (suivi trafiqué, horloge reculée) n'est pas gardée : elle ne s'expirerait jamais.
        c.quand <= maintenant && maintenant.saturating_sub(c.quand) < SUIVI_JOURS.saturating_mul(86_400_000)
    });
    revenues
}

/// Ce que la cache a fait depuis la base, par règle ; la base suit. Une règle vue pour la première fois, ou dont les
/// compteurs ont reculé (mesures remises à zéro), repart de ce qu'on voit sans rien relever.
fn cache_depuis(base: &mut BTreeMap<Regle, Base>, mesures: &crate::autotest::mesures::Mesures) -> Vec<CacheRegle> {
    let mut v = Vec::new();
    for (id, c) in &mesures.cache {
        let Some(regle) = Regle::new(id) else {
            continue;
        };
        let maintenant = Base::de(c);
        let avant = base.insert(regle.clone(), maintenant);
        let Some(a) = avant else {
            continue;
        };
        let d = |n: u64, a: u64| n.checked_sub(a);
        let (Some(repris), Some(a_neuf), Some(age), Some(gagne), Some(comparees), Some(ecarts)) = (
            d(maintenant.repris, a.repris),
            d(maintenant.a_neuf, a.a_neuf),
            d(maintenant.age_total_s, a.age_total_s),
            d(maintenant.gagne_ms, a.gagne_ms),
            d(maintenant.comparees, a.comparees),
            d(maintenant.ecarts, a.ecarts),
        ) else {
            continue;
        };
        if repris == 0 && a_neuf == 0 && comparees == 0 {
            continue;
        }
        v.push(CacheRegle {
            regle,
            repris: Compte::new(repris),
            a_neuf: Compte::new(a_neuf),
            age_total_s: Compte::new(age),
            gagne_ms: Compte::new(gagne),
            comparees: Compte::new(comparees),
            ecarts: Compte::new(ecarts),
        });
    }
    // Les règles qui ne sont plus dans les mesures ne gardent pas leur base.
    base.retain(|r, _| mesures.cache.contains_key(r.as_str()));
    v
}

/// Les jours écrits : (« AAAA-MM-JJ », taille).
fn jours_dans(dossier: &Path) -> Vec<(String, u64)> {
    let Ok(d) = std::fs::read_dir(dossier.join(JOURS)) else {
        return Vec::new();
    };
    d.flatten()
        .filter_map(|e| {
            let nom = e.file_name().into_string().ok()?;
            let jour = nom.strip_suffix(".json")?;
            chrono::NaiveDate::parse_from_str(jour, "%Y-%m-%d").ok()?;
            let m = e.metadata().ok()?;
            m.is_file().then(|| (jour.to_string(), m.len()))
        })
        .collect()
}

fn taille(dossier: &Path, nom: &str) -> u64 {
    std::fs::symlink_metadata(dossier.join(nom)).map_or(0, |m| m.len())
}

/// Le relevé, appelé par la mission du relevé (`agent::Contexte::relever`), verrou de l'agent tenu.
pub(crate) fn relever(
    dossier: &Path,
    jour: chrono::NaiveDate,
    mesures: &crate::autotest::mesures::Mesures,
    moment: crate::agent::Moment,
) {
    if !actif() {
        return;
    }
    let Ok(mut m) = MEMOIRE.try_lock() else {
        return;
    };
    let mut pris = std::mem::take(&mut *m);
    drop(m);
    let refus = texte::refus_locaux();
    let deja = REFUS_VERSES.swap(refus, Ordering::Relaxed);
    pris.brouillon.refus_locaux = pris.brouillon.refus_locaux.saturating_add(refus.saturating_sub(deja));
    // La sortie d'une commande courte ne paie pas WMI : le matériel attend un autre moment.
    let lire: &dyn Fn() -> Option<Materiel> = &materiel::lire;
    let materiel = (moment != crate::agent::Moment::Sortie).then_some(lire);
    if relever_dans(dossier, jour, mesures, maintenant_ms(), &mut pris, materiel).is_err()
        && !ARRETE.load(Ordering::Relaxed)
        && let Ok(mut m) = MEMOIRE.try_lock()
    {
        m.reprendre(pris);
    }
}

/// Écrit `octets` sous `nom`, sauf si « Ne pas partager » est arrivé pendant le relevé : rien ne se réécrit après
/// l'effacement.
fn ecrire_si_permis(dossier: &Path, nom: &str, octets: &[u8]) -> std::io::Result<()> {
    if ARRETE.load(Ordering::Relaxed) {
        return Err(std::io::Error::other("relevé arrêté"));
    }
    crate::sceau::ecrire_dans(dossier, nom, octets)
}

/// Le relevé dans `dossier` : le suivi d'abord (retours, base de la cache), puis le jour relu, la mémoire ajoutée,
/// le tout écrit (scellé, 96 Kio au plus) ; ensuite, chaque semaine, le matériel, et la purge (90 jours, 10 Mo). Le
/// suivi passe avant le jour : si le jour ne s'écrit pas, la mémoire rendue à l'appelant porte les retours et les
/// écarts de la cache une seule fois, et le relevé suivant ne les recalcule pas (au pire un compte de moins, jamais
/// un de trop). Si le suivi ne s'écrit pas, rien n'a bougé.
pub(crate) fn relever_dans(
    dossier: &Path,
    jour: chrono::NaiveDate,
    mesures: &crate::autotest::mesures::Mesures,
    quand: i64,
    m: &mut Memoire,
    materiel: Option<&dyn Fn() -> Option<Materiel>>,
) -> std::io::Result<()> {
    let nom = nom_jour(jour);
    let mut suivi = suivi_dans(dossier);
    // Les corrections d'avant d'abord : la plus ancienne se revoit la première.
    let mut corrigees = std::mem::take(&mut suivi.corrigees);
    corrigees.extend(m.corrigees.iter().cloned());
    let trop = corrigees.len().saturating_sub(SUIVIES_MAX);
    corrigees.drain(..trop);
    let revenues = revenues(&mut corrigees, &m.bilans, quand);
    let mut base = std::mem::take(&mut suivi.cache);
    let ecarts = cache_depuis(&mut base, mesures);
    suivi.corrigees = corrigees;
    suivi.cache = base;
    ecrire_si_permis(dossier, SUIVI, &serde_json::to_vec(&suivi).unwrap_or_default())?;
    // Le suivi tient les corrections et les bilans : la mémoire ne les porte plus, elle porte ce qu'ils ont donné.
    m.corrigees.clear();
    m.bilans.clear();
    for regle in revenues {
        let mut c = releve::correction(regle);
        c.revenues = un();
        ajouter!(m.brouillon, corrections, c);
    }
    for c in ecarts {
        ajouter!(m.brouillon, cache, c);
    }
    let mut b = crate::sceau::juge_dans(dossier, &nom)
        .cru()
        .map(|o| Brouillon::de(&releve::lire(&o)))
        .unwrap_or_default();
    b.fusionner(&m.brouillon);
    if !m.brouillon.est_vide() || crate::sceau::juge_dans(dossier, &nom) == crate::sceau::Juge::Absent {
        ecrire_si_permis(dossier, &nom, &b.ecrire())?;
    }
    // Le jour est écrit : la mémoire est versée.
    *m = Memoire::default();
    let lu_le = suivi
        .materiel_le
        .as_deref()
        .and_then(|le| chrono::NaiveDate::parse_from_str(le, "%Y-%m-%d").ok());
    if let Some(lire) = materiel
        && lu_le.is_none_or(|le| jour.signed_duration_since(le).num_days() >= MATERIEL_JOURS || le > jour)
    {
        // Lu ou non, on ne réessaie pas avant la semaine suivante : une lecture qui échoue ne se paie pas à chaque
        // passe.
        let texte_jour = jour.format("%Y-%m-%d").to_string();
        suivi.materiel_le = Some(texte_jour.clone());
        if let Some(materiel) = lire() {
            let o = serde_json::to_vec(&MaterielLu {
                jour: texte_jour,
                materiel,
            })
            .unwrap_or_default();
            if o.len() <= materiel::MATERIEL_MAX {
                ecrire_si_permis(dossier, MATERIEL, &o)?;
            }
        }
        ecrire_si_permis(dossier, SUIVI, &serde_json::to_vec(&suivi).unwrap_or_default())?;
    }
    purger_dans(dossier, jour)
}

/// Les jours de plus de 90 jours, puis les plus anciens tant que `amelioration/` dépasse 10 Mo.
pub(crate) fn purger_dans(dossier: &Path, jour: chrono::NaiveDate) -> std::io::Result<()> {
    let limite = (jour - chrono::Duration::days(releve::JOURS_GARDES))
        .format("%Y-%m-%d")
        .to_string();
    let garde = jour.format("%Y-%m-%d").to_string();
    let autres = taille(dossier, SUIVI).saturating_add(taille(dossier, MATERIEL));
    for j in releve::a_purger(&jours_dans(dossier), &limite, &garde, autres) {
        crate::sceau::effacer_dans(dossier, &format!("{JOURS}/{j}.json"))?;
    }
    Ok(())
}

/// Efface tout le relevé de `dossier` : les jours, le suivi, le matériel (« Ne pas partager », A5).
/// Un fichier qui résiste (verrouillé par un antivirus) n'arrête pas les autres : la première erreur est rendue à
/// la fin.
pub(crate) fn effacer_dans(dossier: &Path) -> std::io::Result<()> {
    let mut noms: Vec<String> = jours_dans(dossier)
        .into_iter()
        .map(|(j, _)| format!("{JOURS}/{j}.json"))
        .collect();
    noms.extend([SUIVI.to_string(), MATERIEL.to_string()]);
    let mut premiere = Ok(());
    for nom in noms {
        if let Err(e) = crate::sceau::effacer_dans(dossier, &nom)
            && premiere.is_ok()
        {
            premiere = Err(e);
        }
    }
    // Les dossiers vides seulement : un fichier qui n'est pas du relevé reste où il est.
    let _ = std::fs::remove_dir(dossier.join(JOURS));
    let _ = std::fs::remove_dir(dossier.join("amelioration"));
    premiere
}

/// Où « Ne pas partager » efface : partout où ce dossier est celui de la personne, même là où ce processus ne relève
/// pas (`VANGUARD_ENVOI=0` posé après coup laisse les jours d'avant, un second clic réessaie). Jamais sous les
/// essais, Wine ou la CI (un dossier qui n'est pas le sien), ni depuis la clé de quelqu'un d'autre (les jours de
/// l'ordinateur sont à son propriétaire, pas à qui passe) ni en root (le dossier de root, où rien ne s'écrit).
pub(crate) fn peut_effacer(l: Lieu) -> bool {
    !(l.essai || l.wine || l.ci || l.depuis_une_cle || l.en_root)
}

/// « Ne pas partager » (A5) : le relevé s'arrête pour ce processus, sa mémoire est vidée, et ce qui a été écrit est
/// effacé (`peut_effacer`). Un relevé en cours ne réécrit rien après (`ecrire_si_permis`) ; un autre processus
/// Vanguard déjà lancé, lui, ne le sait pas : l'interrupteur gardé sur le disque est à A5.
#[allow(dead_code)] // branché par A5 (Paramètres) ; jamais appelé des essais, il arrêterait tout le processus
pub(crate) fn arreter_et_effacer() -> std::io::Result<()> {
    ARRETE.store(true, Ordering::Relaxed);
    if let Ok(mut m) = MEMOIRE.lock() {
        *m = Memoire::default();
    }
    if !peut_effacer(lieu()) {
        return Ok(());
    }
    effacer_dans(&crate::socle::dossier_local())
}

// --- Le lot d'un jour (pour A4) ----------------------------------------------------------------------------------

/// Les durées des règles un jour donné, d'après `mesures.json` : brutes pour le jour en cours, résumées (le 90e
/// centile y est le maximum, seul gardé) pour un jour clos.
pub(crate) fn durees_du(mesures: &crate::autotest::mesures::Mesures, jour: &str) -> BTreeMap<Regle, Durees> {
    let mut v = BTreeMap::new();
    if mesures.jour == jour {
        for (id, d) in &mesures.en_cours {
            let (Some(regle), false) = (Regle::new(id), d.is_empty()) else {
                continue;
            };
            let mut t = d.clone();
            t.sort_unstable();
            let rang = |q: usize| {
                t.get(t.len().saturating_sub(1).saturating_mul(q) / 100)
                    .copied()
                    .unwrap_or(0)
            };
            v.insert(
                regle,
                Durees {
                    n: u64::try_from(t.len()).unwrap_or(u64::MAX),
                    med_ms: rang(50),
                    p90_ms: rang(90),
                },
            );
        }
    } else if let Some(j) = mesures.jours.get(jour) {
        for (id, r) in j {
            if let Some(regle) = Regle::new(id) {
                v.insert(
                    regle,
                    Durees {
                        n: u64::from(r.n),
                        med_ms: r.med,
                        p90_ms: r.max,
                    },
                );
            }
        }
    }
    v
}

/// Les réglages de l'auto-réglage un jour donné : les montées et raccourcis de ce jour, et ceux que la personne a
/// annulés (sans date : redits chaque jour).
pub(crate) fn reglages_du(etat: &crate::autotest::reglage::Etat, jour: &str) -> Vec<Reglage> {
    let mut v: Vec<Reglage> = Vec::new();
    let mut pousser = |levier, regle: &str, avant: u64, apres: u64, annule| {
        let Some(regle) = Regle::new(regle) else {
            return;
        };
        let r = Reglage {
            levier,
            regle: Some(regle),
            avant: Compte::new(avant),
            apres: Compte::new(apres),
            annule,
        };
        if !v.iter().any(|x| x.levier == r.levier && x.regle == r.regle) {
            v.push(r);
        }
    };
    for m in etat.montees.iter().filter(|m| m.quand == jour) {
        pousser(Levier::Delai, &m.regle, m.avant_s, m.apres_s, false);
    }
    for r in etat.raccourcies.iter().filter(|r| r.quand == jour) {
        pousser(
            Levier::DureeCache,
            &r.regle,
            u64::from(r.avant_min),
            u64::from(r.apres_min),
            false,
        );
    }
    for r in &etat.refusees {
        pousser(Levier::Delai, r, 0, 0, true);
    }
    for r in &etat.gardees {
        pousser(Levier::DureeCache, r, 0, 0, true);
    }
    v
}

/// Le lot du jour `jour`, sur la base `lot` (version, plateforme, activité posées par A4) ; `None` sans fichier du
/// jour qu'on puisse croire. Le lot rendu passe toujours `envoi::lire` (essai) : c'est à A4 de l'envoyer, ou non.
#[cfg_attr(not(test), allow(dead_code))] // branché par A4 (l'envoi)
pub(crate) fn lot_du_jour(
    dossier: &Path,
    jour: chrono::NaiveDate,
    mut lot: Lot,
    mesures: &crate::autotest::mesures::Mesures,
    delai_s: impl Fn(&Regle) -> Option<u64>,
) -> Option<Lot> {
    let o = crate::sceau::juge_dans(dossier, &nom_jour(jour)).cru()?;
    let b = Brouillon::de(&releve::lire(&o));
    let texte_jour = jour.format("%Y-%m-%d").to_string();
    let reglages = match crate::autotest::reglage::lire_dans(dossier) {
        crate::autotest::reglage::Lu::Cru(e) => reglages_du(&e, &texte_jour),
        _ => Vec::new(),
    };
    // Le matériel n'entre que dans le lot du jour où il a été lu : une fois par semaine.
    lot.materiel = materiel_dans(dossier)
        .filter(|m| m.jour == texte_jour)
        .map(|m| m.materiel);
    Some(releve::vers_lot(
        &b,
        lot,
        &durees_du(mesures, &texte_jour),
        delai_s,
        &reglages,
    ))
}

// --- Les portes de la voie ouverte (A1) --------------------------------------------------------------------------

/// Un texte d'erreur brut, tel que l'ordinateur le donne : noms de la personne, de la machine et du réseau retirés
/// d'abord (`journal::anonymiser`, qui connaît le dossier personnel et la base des appareils), puis nettoyé. Les
/// chevrons du brut sont retirés avant : seuls l'anonymisation et le nettoyage posent des marqueurs. C'est la porte
/// d'entrée à prendre ; `TexteNettoye::nettoyer` seul laisserait passer un faux marqueur écrit dans le brut.
pub(crate) fn texte(brut: &str) -> Result<TexteNettoye, Rejet> {
    TexteNettoye::nettoyer(&crate::journal::anonymiser(&texte::sans_chevrons(brut)))
}

/// Le nom d'un logiciel, d'un service ou d'un pilote, nettoyé de la même façon.
pub(crate) fn nom(brut: &str) -> Result<NomLogiciel, Rejet> {
    NomLogiciel::nettoyer(&crate::journal::anonymiser(&texte::sans_chevrons(brut)))
}

/// La version d'un logiciel tiers. Une version que l'anonymisation changerait porte autre chose qu'une version (un
/// nom, une adresse) : refusée plutôt que réparée.
pub(crate) fn version(brut: &str) -> Result<VersionTierce, Rejet> {
    if crate::journal::anonymiser(brut) != brut {
        return Err(texte::compter(Rejet::Forme));
    }
    VersionTierce::nettoyer(brut)
}

#[cfg(test)]
mod tests;
