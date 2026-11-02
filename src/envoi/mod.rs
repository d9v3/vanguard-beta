//! L'envoi des lots de l'auto-amélioration (A4) : le lot de chaque jour clos du relevé local (`amelioration`) est mis
//! en file (`envoi/file/AAAA-MM-JJ.json`, 7 jours au plus), puis posté au relais, au plus 3 essais par jour.
//!
//! **Le relais n'existe pas encore : `RELAIS` vaut `None`, et rien ne part.** Tant qu'il en est ainsi, rien n'est
//! même préparé : ni fichier écrit, ni fil lancé, ni connexion (essai, par un compteur de connexions).
//!
//! Jamais rien ne part : sous les essais, sous Wine, dans la CI, avec `VANGUARD_ENVOI=0`, depuis une clé, en root
//! (les mêmes garde-fous que le relevé, `amelioration::actif`), dans une compilation de développement, sans
//! Internet (`hors_ligne`), sans l'accord de la personne (A5 : l'avis montré, et pas « Ne pas partager »), ni après
//! « Ne pas partager » dans ce processus. Le lot posté est celui que la lecture stricte du schéma 2 vient de relire ;
//! de la réponse, seul le code est lu (`http::poster_sans_lire`).

mod file;
mod plateforme;
#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::NaiveDate;

use crate::compte_rendu::champs::{Regle, Version};
use crate::compte_rendu::envoi::{Activite, Anciennete, IdInstallation, Lot, Plateforme};
use file::{Echec, Essais, Etat, Installation, Raison, SuiviVersion};

/// L'adresse entière du POST des lots (« https://<hôte du relais>/v1/lot »), quand le relais sera déployé. Le jour
/// où elle est posée, son hôte entre aussi dans `http::HOTES` et dans MODELE-DE-MENACE.md et .en.md (« Ce qui sort
/// de l'ordinateur ») : sans cela, `http::poster_sans_lire` la refuse avant toute connexion, et le test `envois`
/// échoue. Un essai vérifie qu'elle vaut `None`, pour qu'elle ne change pas sans qu'on le voie.
pub(crate) const RELAIS: Option<&str> = None;

pub(crate) use file::{ETAT, FILE};

/// Trois essais par jour au plus, toutes tentatives comprises.
const ESSAIS_PAR_JOUR: u32 = 3;
/// Un lot attend 7 jours au plus ; après, il est jeté sans être parti.
const JOURS_GARDES: i64 = 7;
/// Après un 429 ou un 503 : rien avant 24 h.
const ATTENTE_S: i64 = 86_400;
/// L'identifiant d'installation est retiré tous les 90 jours (P1) : un profil ne s'étend pas au-delà.
const ID_JOURS: i64 = 90;
/// La version d'avant accompagne les lots des 7 jours qui suivent une mise à jour.
const VERSION_AVANT_JOURS: i64 = 7;
/// Le POST : 5 s pour se connecter, 10 s en tout jusqu'au code.
const CONNEXION: Duration = Duration::from_secs(5);
const DELAI: Duration = Duration::from_secs(10);

// --- Les garde-fous ----------------------------------------------------------------------------------------------

/// Ce qui permet, ou non, de préparer puis d'envoyer : chaque cas pris un à un (essais).
#[allow(clippy::struct_excessive_bools)] // un garde-fou par champ, chacun pour lui-même
#[derive(Clone, Copy, Debug)]
pub(crate) struct Garde {
    /// Le relevé a droit de cité (`amelioration::actif`) : ni essais, ni Wine, ni CI, ni `VANGUARD_ENVOI=0`, ni clé,
    /// ni root, ni « Ne pas partager ».
    pub(crate) releve: bool,
    /// Compilation de développement (`debug_assertions`) : un `cargo run` ne poste rien.
    pub(crate) developpement: bool,
    /// Sans Internet : la file attend.
    pub(crate) hors_ligne: bool,
    /// L'accord de la personne (A5).
    pub(crate) accord: bool,
    /// « Ne pas partager » dans ce processus.
    pub(crate) arrete: bool,
}

impl Garde {
    fn de_ce_processus() -> Garde {
        Garde {
            releve: crate::amelioration::actif(),
            developpement: cfg!(debug_assertions),
            hors_ligne: crate::parametres::hors_ligne(),
            accord: accord(),
            arrete: ARRETE.load(Ordering::SeqCst),
        }
    }

    pub(crate) fn peut_preparer(self) -> bool {
        self.releve && !self.developpement && self.accord && !self.arrete
    }

    pub(crate) fn peut_envoyer(self) -> bool {
        self.peut_preparer() && !self.hors_ligne
    }
}

/// L'accord de la personne : l'avis du partage montré (E8) et pas « Ne pas partager ». A5 le pose ; d'ici là,
/// fermé.
fn accord() -> bool {
    false
}

/// « Ne pas partager » : plus rien pour ce processus, quoi qu'il arrive ensuite.
static ARRETE: AtomicBool = AtomicBool::new(false);

/// Un seul envoi à la fois dans ce processus (le verrou `envoi.lock` le fait entre deux processus).
static EN_COURS: AtomicBool = AtomicBool::new(false);

/// Le fil de l'envoi, attendu à la fin de la passe horaire.
static FIL: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);

// --- La passe ----------------------------------------------------------------------------------------------------

/// Ce qu'une passe a fait, pour les essais.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Bilan {
    pub(crate) mis: usize,
    pub(crate) postes: usize,
    pub(crate) recus: usize,
    pub(crate) jetes: usize,
}

/// Le cadre d'une passe : où, quand, sous quels garde-fous, vers quelle adresse, de quelle version.
pub(crate) struct Cadre<'a> {
    pub(crate) dossier: &'a Path,
    /// Le jour local : celui des fichiers du relevé.
    pub(crate) aujourd_hui: NaiveDate,
    /// Secondes depuis 1970 (UTC), pour l'attente de 24 h.
    pub(crate) maintenant: i64,
    pub(crate) garde: Garde,
    pub(crate) relais: Option<&'a str>,
    pub(crate) version: Version,
}

/// Ce dont la passe a besoin du reste du programme, donné par l'appelant (essais : sans rien lire de l'ordinateur).
pub(crate) struct Sources<P, J, E>
where
    P: FnOnce() -> Option<(Plateforme, Activite)>,
    J: Fn(NaiveDate, Lot) -> Option<Lot>,
    E: FnMut(&str, Vec<u8>) -> Option<u16>,
{
    /// La plateforme et l'activité : lues une fois, seulement s'il y a un lot à faire.
    pub(crate) plateforme: P,
    /// Le lot d'un jour sur une base (`amelioration::lot_du_jour`).
    pub(crate) du_jour: J,
    /// Le POST, qui rend le code de réponse (`http::poster_sans_lire`).
    pub(crate) poster: E,
}

/// Une passe : la file remplie des jours clos, purgée, puis envoyée du plus vieux lot au plus récent.
pub(crate) fn passe_dans<P, J, E>(c: &Cadre, s: Sources<P, J, E>) -> Bilan
where
    P: FnOnce() -> Option<(Plateforme, Activite)>,
    J: Fn(NaiveDate, Lot) -> Option<Lot>,
    E: FnMut(&str, Vec<u8>) -> Option<u16>,
{
    let mut bilan = Bilan::default();
    // L'adresse d'abord : sans relais, rien n'est touché, ni lu ni écrit.
    let Some(adresse) = c.relais else {
        return bilan;
    };
    if !c.garde.peut_preparer() || !file::dossiers_surs(c.dossier) {
        return bilan;
    }
    // Un autre Vanguard envoie déjà : il fera tout, celui-ci ne fait rien.
    let Ok(_verrou) = crate::socle::Verrou::prendre(c.dossier, "envoi.lock", false, Duration::ZERO) else {
        return bilan;
    };
    let mut etat = file::lire_etat(c.dossier);
    tenir(&mut etat, c);
    bilan.mis = remplir(&mut etat, c, s.plateforme, &s.du_jour);
    let debut = c.aujourd_hui - chrono::Duration::days(JOURS_GARDES);
    file::purger(c.dossier, |d| d >= debut && d < c.aujourd_hui);
    if arrete() || file::ecrire_etat(c.dossier, &etat).is_err() || !c.garde.peut_envoyer() {
        return bilan;
    }
    envoyer(&mut etat, c, adresse, s.poster, &mut bilan);
    bilan
}

/// L'état ramené à ce jour : premier jour, identifiant tiré ou renouvelé, version suivie, attente bornée. Une date
/// du futur (horloge reculée, état forgé) se ramène à aujourd'hui : elle ne bloque rien pour toujours.
fn tenir(etat: &mut Etat, c: &Cadre) {
    let aujourd_hui = file::jour(c.aujourd_hui);
    let futur = |j: &crate::compte_rendu::champs::Jour| file::date(j).is_none_or(|d| d > c.aujourd_hui);
    if etat.premier_jour.as_ref().is_none_or(futur) {
        etat.premier_jour = Some(aujourd_hui.clone());
    }
    let id_vieux = etat.installation.as_ref().is_none_or(|i| {
        futur(&i.depuis) || file::date(&i.depuis).is_none_or(|d| (c.aujourd_hui - d).num_days() >= ID_JOURS)
    });
    if id_vieux {
        let mut octets = [0u8; 8];
        etat.installation = getrandom::fill(&mut octets).ok().map(|()| Installation {
            id: IdInstallation::de_octets(octets),
            depuis: aujourd_hui.clone(),
        });
    }
    match &etat.version {
        Some(v) if v.version == c.version && !futur(&v.depuis) => {}
        Some(v) if !futur(&v.depuis) => {
            etat.version = Some(SuiviVersion {
                avant: Some(v.version.clone()),
                version: c.version.clone(),
                depuis: aujourd_hui.clone(),
            });
        }
        _ => {
            etat.version = Some(SuiviVersion {
                version: c.version.clone(),
                avant: None,
                depuis: aujourd_hui.clone(),
            });
        }
    }
    if etat.dernier_mis.as_ref().is_some_and(futur) {
        // Un jour « déjà mis » du futur arrêterait la file jusqu'à lui : il revient à hier, sans refaire un jour
        // envoyé (au pire, ceux de la fenêtre qui ont encore leur relevé).
        etat.dernier_mis = Some(file::jour(c.aujourd_hui - chrono::Duration::days(1)));
    }
    if etat.essais.as_ref().is_some_and(|e| futur(&e.jour)) {
        etat.essais = None;
    }
    if let Some(t) = etat.attendre_jusqu_a {
        etat.attendre_jusqu_a = (t > c.maintenant).then(|| t.min(c.maintenant.saturating_add(ATTENTE_S)));
    }
}

/// Met en file le lot de chaque jour clos de la fenêtre qui n'y est pas encore passé. Un jour sans relevé n'a pas de
/// lot ; il compte comme passé.
fn remplir<P, J>(etat: &mut Etat, c: &Cadre, plateforme: P, du_jour: &J) -> usize
where
    P: FnOnce() -> Option<(Plateforme, Activite)>,
    J: Fn(NaiveDate, Lot) -> Option<Lot>,
{
    let hier = c.aujourd_hui - chrono::Duration::days(1);
    let mut d = c.aujourd_hui - chrono::Duration::days(JOURS_GARDES);
    if let Some(apres) = etat.dernier_mis.as_ref().and_then(file::date) {
        d = d.max(apres + chrono::Duration::days(1));
    }
    if d > hier {
        return 0;
    }
    let Some((plateforme, activite)) = plateforme() else {
        return 0;
    };
    let premier = etat.premier_jour.as_ref().and_then(file::date).unwrap_or(c.aujourd_hui);
    let mut mis = 0;
    while d <= hier {
        if arrete() {
            return mis;
        }
        let jours = u64::try_from((d - premier).num_days()).unwrap_or(0);
        let mut base = Lot::new(
            c.version.clone(),
            file::jour(d),
            Anciennete::de_jours(jours),
            plateforme.clone(),
            activite.clone(),
        );
        base.installation = etat.installation.as_ref().map(|i| i.id.clone());
        base.version_avant = etat.version.as_ref().and_then(|v| {
            let depuis = file::date(&v.depuis)?;
            let ecart = (d - depuis).num_days();
            (0..VERSION_AVANT_JOURS)
                .contains(&ecart)
                .then(|| v.avant.clone())
                .flatten()
        });
        // Un jour qui ne s'écrit pas (disque plein) reste à faire : la passe suivante le reprendra.
        if !file::chemin(c.dossier, d).exists()
            && let Some(lot) = du_jour(d, base)
        {
            if file::mettre(c.dossier, d, lot).is_err() {
                return mis;
            }
            mis += 1;
        }
        etat.dernier_mis = Some(file::jour(d));
        d += chrono::Duration::days(1);
    }
    mis
}

/// Poste les lots en file, du plus vieux au plus récent, tant que le jour a des essais et que le relais répond.
/// Chaque essai est noté avant de partir : un processus tué pendant le POST l'a déjà compté.
fn envoyer<E>(etat: &mut Etat, c: &Cadre, adresse: &str, mut poster: E, bilan: &mut Bilan)
where
    E: FnMut(&str, Vec<u8>) -> Option<u16>,
{
    let aujourd_hui = file::jour(c.aujourd_hui);
    if etat.attendre_jusqu_a.is_some() {
        return;
    }
    for d in file::jours_en_file(c.dossier) {
        let lot = match file::relire(c.dossier, d) {
            Ok(Some(lot)) => lot,
            Ok(None) => continue,
            Err(()) => {
                file::retirer(c.dossier, d);
                bilan.jetes += 1;
                noter(etat, &aujourd_hui, Raison::Illisible, None);
                continue;
            }
        };
        let essais = etat
            .essais
            .as_ref()
            .filter(|e| e.jour == aujourd_hui)
            .map_or(0, |e| e.n);
        if essais >= ESSAIS_PAR_JOUR || arrete() {
            break;
        }
        etat.essais = Some(Essais {
            jour: aujourd_hui.clone(),
            n: essais + 1,
        });
        // Sans l'essai noté sur le disque, rien ne part : le plafond du jour ne tiendrait plus d'un processus à
        // l'autre.
        if file::ecrire_etat(c.dossier, etat).is_err() {
            return;
        }
        bilan.postes += 1;
        let code = poster(adresse, lot.ecrire());
        match code {
            Some(200..=299) => {
                file::retirer(c.dossier, d);
                bilan.recus += 1;
                etat.dernier_succes = Some(aujourd_hui.clone());
            }
            Some(429 | 503) => {
                let raison = if code == Some(429) {
                    Raison::Limite
                } else {
                    Raison::Indisponible
                };
                noter(etat, &aujourd_hui, raison, code);
                etat.attendre_jusqu_a = Some(c.maintenant.saturating_add(ATTENTE_S));
                break;
            }
            Some(400..=499) => {
                file::retirer(c.dossier, d);
                bilan.jetes += 1;
                noter(etat, &aujourd_hui, Raison::Refuse, code);
            }
            Some(_) => {
                noter(etat, &aujourd_hui, Raison::Autre, code);
                break;
            }
            None => {
                noter(etat, &aujourd_hui, Raison::SansReponse, None);
                break;
            }
        }
    }
    if !arrete() {
        let _ = file::ecrire_etat(c.dossier, etat);
    }
}

fn noter(etat: &mut Etat, jour: &crate::compte_rendu::champs::Jour, raison: Raison, code: Option<u16>) {
    etat.dernier_echec = Some(Echec {
        jour: jour.clone(),
        raison,
        code,
    });
}

fn arrete() -> bool {
    ARRETE.load(Ordering::SeqCst)
}

// --- Les points d'entrée ------------------------------------------------------------------------------------------

/// Le délai appliqué de chaque règle (celui du code, ou monté par l'auto-réglage), en secondes.
fn delais() -> impl Fn(&Regle) -> Option<u64> {
    let longs = crate::autotest::reglage::delais_longs();
    let regles = crate::machine::regles::regles(crate::machine::regles::Os::actuel());
    move |id: &Regle| {
        regles
            .iter()
            .find(|r| r.id == id.as_str())
            .map(|r| r.delai_avec(&longs).as_secs())
    }
}

/// Une passe de ce processus, sur son dossier.
fn passe(en_passe_horaire: bool) {
    let dossier = crate::socle::dossier_local();
    let maintenant = chrono::Utc::now().timestamp();
    let cadre = Cadre {
        dossier: &dossier,
        aujourd_hui: chrono::Local::now().date_naive(),
        maintenant,
        garde: Garde::de_ce_processus(),
        relais: RELAIS,
        version: Version::du_programme(),
    };
    // Lus seulement s'il y a un jour à mettre en file : une fois par jour, pas à chaque passe.
    let mesures = std::sync::LazyLock::new(crate::autotest::mesures::lues);
    let delai_s = std::sync::LazyLock::new(delais);
    let sources = Sources {
        plateforme: || {
            let activite = Activite {
                bilans_manuels: crate::compte_rendu::envoi::Compte::default(),
                passes_horaires: crate::compte_rendu::envoi::Compte::default(),
                surveillance: en_passe_horaire || crate::reseau::surveillance::installee(),
                #[cfg(target_os = "linux")]
                veilleur: crate::machine::linux::veilleur::voulu(),
                #[cfg(not(target_os = "linux"))]
                veilleur: false,
                // Depuis une clé, rien n'est relevé ni envoyé (`Garde::releve`).
                cle: false,
            };
            Some((plateforme::plateforme()?, activite))
        },
        du_jour: |d, base| crate::amelioration::lot_du_jour(&dossier, d, base, &mesures, &*delai_s),
        poster: |adresse: &str, corps| crate::http::poster_sans_lire(adresse, corps, CONNEXION, DELAI),
    };
    passe_dans(&cadre, sources);
}

/// L'envoi en fond, dans un fil à lui : la passe horaire l'attend à sa fin (`attendre`), le lancement jamais (le
/// fil part avec le programme). Sans relais ou sans droit d'envoyer, aucun fil n'est lancé.
pub(crate) fn en_fond(en_passe_horaire: bool) {
    if RELAIS.is_none() || !Garde::de_ce_processus().peut_preparer() {
        return;
    }
    if EN_COURS.swap(true, Ordering::SeqCst) {
        return;
    }
    let fil = std::thread::Builder::new().name("envoi".into()).spawn(move || {
        passe(en_passe_horaire);
        EN_COURS.store(false, Ordering::SeqCst);
    });
    // Gardé dans les deux cas : la passe horaire est aussi un lancement, et elle attend le fil qui a pris l'envoi.
    match fil {
        Ok(f) => *FIL.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(f),
        Err(_) => EN_COURS.store(false, Ordering::SeqCst),
    }
}

/// La fin de l'envoi de la passe horaire : ses délais la bornent (3 essais de 10 s au plus).
pub(crate) fn attendre() {
    let fil = FIL.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
    if let Some(f) = fil {
        let _ = f.join();
    }
}

/// « Ne pas partager » (A5) : plus rien ne part de ce processus, et la file et l'état (avec l'identifiant
/// d'installation) sont effacés, là où « Ne pas partager » efface le relevé (`amelioration::effacement_permis`).
#[allow(dead_code)] // branché par A5 (Paramètres) ; jamais appelé des essais, il arrêterait tout le processus
pub(crate) fn arreter_et_vider() -> std::io::Result<()> {
    ARRETE.store(true, Ordering::SeqCst);
    if !crate::amelioration::effacement_permis() {
        return Ok(());
    }
    let dossier = crate::socle::dossier_local();
    // Un envoi en cours finit son POST (déjà parti) mais ne réécrit rien : il voit `ARRETE`. Le verrou attendu ici
    // le laisse finir avant d'effacer, pour que rien ne revienne après.
    let _verrou = crate::socle::Verrou::prendre(&dossier, "envoi.lock", false, DELAI + CONNEXION);
    file::vider(&dossier)
}
