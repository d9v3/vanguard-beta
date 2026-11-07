//! La réception chez l'auteur (lot A8) : les relèves du relais, posées brutes par `outils/veille/releve-envois.sh`
//! dans `retours/envois/AAAA-MM-JJ.jsonl`, relues ici et agrégées par version (`veille/etat/flotte/<version>.json`)
//! pour la veille de nuit (`vanguard compte-rendu flotte`), ou seulement comptées (`vanguard compte-rendu envois`).
//!
//! Pourquoi si méfiant : chaque lot vient d'un ordinateur qu'on ne connaît pas. Le relais a déjà tout vérifié, mais la
//! relève est relue comme si elle venait de n'importe qui :
//! - chaque lot repasse par `envoi::lire`, la même lecture stricte que le relais et que le banc de fuzzing ;
//! - une version jamais publiée (aucune étiquette `vX.Y.Z` de l'arbre de la veille), trop ancienne, ou dont le lot
//!   dit un jour d'avant sa publication est refusée ; une règle absente de l'arbre de sa version, un outil qui n'est
//!   pas une `Outil.commande` de cette version, un emplacement dans un fichier qu'elle n'a pas, aussi ;
//! - un lot où le détecteur de secrets sonne, sur n'importe quelle chaîne ou clé, va en quarantaine : compté, jamais
//!   lu plus loin, jamais recopié (il reste dans la relève brute, que rien d'autre ne lit) ;
//! - l'état écrit ne garde que des listes fermées, des nombres et des empreintes : aucun texte venu d'un lot.
//!
//! Une voix par source et par jour : la source est l'empreinte du préfixe de l'adresse que le relais calcule avec le
//! sel du jour. Mille lots d'une même source un même jour comptent comme un seul : chaque nombre est pris à son
//! maximum sur les lots de la source, puis sommé d'une source à l'autre. Tout passe par des maximums, des unions et
//! des sommes : l'agrégat ne dépend ni de l'ordre des lignes ni de celui des fichiers.
//!
//! Les jours reçus depuis 30 jours (`FENETRE`) sont recalculés chaque nuit depuis la relève brute, gardée 90 jours :
//! relire deux fois la même relève ne compte rien deux fois. Les jours plus anciens sont figés dans l'état.
//!
//! Les signaux (lot A9) sont tirés de ces comptes par `signaux` : en Rust, sans IA, sur les états de la nuit.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
#![forbid(unsafe_code)]

pub(crate) mod signaux;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use chrono::{Days, NaiveDate};
use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::envoi::{self, Lot, Virtuelle};
use super::{Jour, Regle, Version, version_cle};
use crate::amelioration::texte;
use crate::modele::Echec;
use crate::ui::{tr, trf};

/// Le contexte des échecs (`champs::CONTEXTES_ECHEC`) : celui des lectures des comptes rendus, sans en ajouter un
/// (le schéma du compte rendu et le relais en ont une copie).
const LIRE: &str = "compte-rendu/lire";
/// Une relève du jour : 8 Mio au plus par `releve-envois.sh`, un peu de marge pour une ligne coupée.
const FICHIER_MAX: u64 = 9 * 1024 * 1024;
/// Une réponse du relais : 4 Mio de lots au plus, plus l'enveloppe.
const LIGNE_MAX: usize = 5 * 1024 * 1024;
/// Lots par réponse (`RELEVE_LOTS` du relais).
const LOTS_MAX: usize = 1000;
/// Lignes de refus par réponse : 11 raisons sur 15 jours au plus chez le relais.
const REFUS_LIGNES_MAX: usize = 1000;
/// Un compteur de refus du relais ne monte pas au-delà (`REFUS_MAX`).
const REFUS_N_MAX: u64 = 10_000;
/// Les raisons de refus du relais ; une autre est comptée « inconnue » (un relais plus récent).
const RAISONS_RELAIS: &[&str] = &[
    "type", "taille", "limite", "json", "schema", "secret", "jour", "plafond", "quota", "releve", "doublon",
];
/// Un fichier de références (liste de règles, d'outils ou de fichiers d'une version).
const REFERENCE_MAX: u64 = 1024 * 1024;
/// L'état d'une version : 2 Mio au plus, élagué au-delà.
pub(crate) const ETAT_MAX: usize = 2 * 1024 * 1024;
/// Le résumé des relèves.
const RELEVE_MAX: u64 = 1024 * 1024;
/// Les jours reçus depuis autant de jours sont recalculés ; les autres sont figés.
const FENETRE: u64 = 29;
/// Les fichiers de relève lus : depuis autant de jours (un lot reste 14 jours au plus chez le relais).
const FICHIERS_AVANT: u64 = FENETRE + 1;
/// Un lot relevé le jour F a été reçu au plus tôt F − 15 (garde du relais : 14 jours).
const RECU_AVANT: u64 = 15;
/// Le jour d'un lot, autour du jour de réception (`LOT_JOURS_AVANT` et `LOT_JOURS_APRES` du relais).
const LOT_AVANT: u64 = 12;
const LOT_APRES: u64 = 1;
/// Les versions agrégées : celles des trois mineures publiées les plus récentes (la courante et les deux d'avant).
const MINEURES: usize = 3;
/// Le résumé des relèves garde autant de jours.
const RELEVE_GARDE: u64 = 120;
/// Une clé de l'état : longueur et caractères permis (rien qui ressemble à du texte ou à du Markdown).
const CLE_MAX: usize = 256;
/// Le format de l'état.
const ETAT_SCHEMA: u8 = 1;

/// Pourquoi un lot n'est pas compté. L'ordre est celui des vérifications.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Rejet {
    /// Jour, source ou réseau large hors motif, ou jour de réception hors de la fenêtre du fichier.
    Enveloppe,
    /// Plus de `envoi::LOT_MAX` octets : refusé avant tout balayage (rien à gagner à lire 5 Mio pour les refuser).
    TropGros,
    /// Le détecteur de secrets sonne : compté, jamais lu plus loin.
    Quarantaine,
    HorsSchema,
    VersionNonPubliee,
    /// Hors des trois dernières mineures publiées.
    VersionAncienne,
    /// `version_avant` non publiée ou pas plus ancienne.
    VersionAvant,
    /// Le jour du lot trop loin du jour de réception.
    Jour,
    /// Un jour d'avant la publication de sa version.
    Futur,
    /// L'arbre de cette version n'a pas été lu (références absentes).
    SansReference,
    RegleInconnue,
    OutilInconnu,
    LieuInconnu,
    /// Le même lot, de la même source, reçu le même jour.
    Doublon,
    /// Reçu un jour figé (plus de 29 jours) : pas recompté.
    JourFige,
}

impl Rejet {
    pub(crate) const TOUS: [Rejet; 15] = [
        Rejet::Enveloppe,
        Rejet::TropGros,
        Rejet::Quarantaine,
        Rejet::HorsSchema,
        Rejet::VersionNonPubliee,
        Rejet::VersionAncienne,
        Rejet::VersionAvant,
        Rejet::Jour,
        Rejet::Futur,
        Rejet::SansReference,
        Rejet::RegleInconnue,
        Rejet::OutilInconnu,
        Rejet::LieuInconnu,
        Rejet::Doublon,
        Rejet::JourFige,
    ];

    pub(crate) fn id(self) -> &'static str {
        match self {
            Rejet::Enveloppe => "enveloppe",
            Rejet::Quarantaine => "quarantaine",
            Rejet::TropGros => "trop-gros",
            Rejet::HorsSchema => "hors-schema",
            Rejet::VersionNonPubliee => "version-non-publiee",
            Rejet::VersionAncienne => "version-ancienne",
            Rejet::VersionAvant => "version-avant",
            Rejet::Jour => "jour",
            Rejet::Futur => "futur",
            Rejet::SansReference => "sans-reference",
            Rejet::RegleInconnue => "regle-inconnue",
            Rejet::OutilInconnu => "outil-inconnu",
            Rejet::LieuInconnu => "lieu-inconnu",
            Rejet::Doublon => "doublon",
            Rejet::JourFige => "jour-fige",
        }
    }

    /// Les trois comptés à part dans la ligne : ni refus du lot ni faute de son auteur.
    fn a_part(self) -> bool {
        matches!(self, Rejet::Quarantaine | Rejet::Doublon | Rejet::JourFige)
    }
}

// --- Les références : ce que chaque version publiée contient ------------------------------------------------------

/// Ce que l'arbre d'une version contient : ses règles non retirées, ses commandes d'outils, ses fichiers `src/`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Arbre {
    pub(crate) regles: BTreeSet<String>,
    pub(crate) outils: BTreeSet<String>,
    pub(crate) fichiers: BTreeSet<String>,
}

/// Les versions publiées (étiquettes de l'arbre de la veille, posées par `outils/veille/references-flotte.sh`) et
/// l'arbre de chacune des mineures récentes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct References {
    publiees: BTreeMap<Version, NaiveDate>,
    recentes: BTreeSet<(u16, u16)>,
    arbres: BTreeMap<Version, Arbre>,
}

fn mineure(v: &Version) -> (u16, u16) {
    let (a, b, _) = version_cle(v);
    (a, b)
}

fn date(j: &Jour) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(j.as_str(), "%Y-%m-%d").ok()
}

fn jour_de(d: NaiveDate) -> Option<Jour> {
    Jour::new(&d.format("%Y-%m-%d").to_string())
}

fn moins(d: NaiveDate, n: u64) -> NaiveDate {
    d.checked_sub_days(Days::new(n)).unwrap_or(NaiveDate::MIN)
}

fn plus(d: NaiveDate, n: u64) -> NaiveDate {
    d.checked_add_days(Days::new(n)).unwrap_or(NaiveDate::MAX)
}

impl References {
    /// Des références données ; sans aucune version publiée, refusé (rien ne serait gardé, tout l'état partirait).
    pub(crate) fn de(
        publiees: BTreeMap<Version, NaiveDate>,
        arbres: BTreeMap<Version, Arbre>,
    ) -> Result<References, Echec> {
        let mut mineures: Vec<(u16, u16)> = publiees.keys().map(mineure).collect();
        mineures.sort_unstable();
        mineures.dedup();
        let recentes: BTreeSet<(u16, u16)> = mineures.into_iter().rev().take(MINEURES).collect();
        if recentes.is_empty() {
            return Err(Echec::refuse(
                LIRE,
                tr!(
                    "aucune version publiée dans les références",
                    "no published version in the references"
                )
                .to_string(),
            ));
        }
        let arbres = arbres
            .into_iter()
            .filter(|(v, _)| publiees.contains_key(v) && recentes.contains(&mineure(v)))
            .collect();
        Ok(References {
            publiees,
            recentes,
            arbres,
        })
    }

    /// Lit `versions.tsv` (`X.Y.Z<tab>AAAA-MM-JJ` par ligne) et, pour chaque version récente, `<version>/regles.txt`,
    /// `outils.txt` et `fichiers.txt`. Une ligne hors motif refuse tout : ces fichiers viennent de la veille elle-même.
    pub(crate) fn lire(dossier: &Path) -> Result<References, Echec> {
        let Some(octets) = lire_borne(&dossier.join("versions.tsv"), REFERENCE_MAX)? else {
            return Err(Echec::refuse(
                LIRE,
                tr!(
                    "versions.tsv absent des références",
                    "versions.tsv missing from the references"
                )
                .to_string(),
            ));
        };
        let mut publiees = BTreeMap::new();
        for ligne in lignes(&octets)? {
            let lue = ligne
                .split_once('\t')
                .and_then(|(v, j)| Some((Version::new(v)?, date(&Jour::new(j)?)?)));
            let Some((v, d)) = lue else {
                return Err(reference_refusee("versions.tsv"));
            };
            publiees.insert(v, d);
        }
        let provisoires = References::de(publiees, BTreeMap::new())?;
        let mut arbres = BTreeMap::new();
        for v in provisoires
            .publiees
            .keys()
            .filter(|v| provisoires.recentes.contains(&mineure(v)))
        {
            // Le nom vient d'une version validée : des chiffres et des points seulement.
            let ici = dossier.join(v.as_str());
            if !ici.is_dir() {
                continue;
            }
            let liste = |nom: &str, valide: fn(&str) -> bool| -> Result<BTreeSet<String>, Echec> {
                let o = lire_borne(&ici.join(nom), REFERENCE_MAX)?.ok_or_else(|| reference_refusee(nom))?;
                let mut s = BTreeSet::new();
                for l in lignes(&o)? {
                    if !valide(l) {
                        return Err(reference_refusee(nom));
                    }
                    s.insert(l.to_string());
                }
                Ok(s)
            };
            arbres.insert(
                v.clone(),
                Arbre {
                    regles: liste("regles.txt", |l| Regle::new(l).is_some())?,
                    outils: liste("outils.txt", |l| envoi::NomOutil::new(l).is_some())?,
                    fichiers: liste("fichiers.txt", est_fichier)?,
                },
            );
        }
        References::de(provisoires.publiees, arbres)
    }
}

/// Un fichier de l'arbre : `src/…`, ASCII visible, borné.
fn est_fichier(s: &str) -> bool {
    s.starts_with("src/") && s.len() <= 300 && s.bytes().all(|o| o.is_ascii_graphic())
}

fn reference_refusee(nom: &str) -> Echec {
    Echec::refuse(
        LIRE,
        trf!(
            "références illisibles : {} hors motif",
            "unreadable references: {} out of pattern",
            nom
        ),
    )
}

/// Les lignes non vides d'un fichier de la veille, en UTF-8.
fn lignes(octets: &[u8]) -> Result<impl Iterator<Item = &str>, Echec> {
    let t = std::str::from_utf8(octets).map_err(|_| reference_refusee("UTF-8"))?;
    Ok(t.lines().filter(|l| !l.is_empty()))
}

/// Un fichier lu en entier, borné ; absent : rien.
fn lire_borne(chemin: &Path, max: u64) -> Result<Option<Vec<u8>>, Echec> {
    // Ni lien suivi, ni tube nommé (il figerait la nuit dans open()), jugé sur ce qui est ouvert : socle.
    match crate::socle::lire_ordinaire(chemin, max) {
        Ok(o) => Ok(Some(o)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Echec::refuse(LIRE, format!("{}: {e}", chemin.display()))),
    }
}

// --- La relève : l'enveloppe du relais ---------------------------------------------------------------------------

/// Une réponse de `GET /v1/releve` (`relais/worker.js`, `relever`), une par ligne de la relève brute.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reponse<'a> {
    releve: u8,
    #[serde(borrow)]
    lots: Vec<LotRecu<'a>>,
    refus: Vec<RefusRelais>,
    #[serde(rename = "reste")]
    _reste: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LotRecu<'a> {
    #[serde(rename = "id")]
    _id: u64,
    jour: String,
    source: String,
    source_large: String,
    /// Le lot tel que le relais l'a gardé : ses octets exacts repassent par `envoi::lire`.
    #[serde(borrow)]
    lot: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusRelais {
    jour: String,
    raison: String,
    n: u64,
}

/// 32 chiffres hexadécimaux minuscules (empreinte de source du relais).
fn est_empreinte(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|o| o.is_ascii_digit() || (b'a'..=b'f').contains(&o))
}

/// Le nombre d'alertes du détecteur de secrets sur chaque chaîne et chaque clé d'un JSON, sans rien garder : une clé
/// en double est vue deux fois (une `Value` n'en garderait qu'une), un échappement `\u` est déjà décodé.
struct Balayage(u32);

impl<'de> Deserialize<'de> for Balayage {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Balayage, D::Error> {
        d.deserialize_any(Balayeur)
    }
}

struct Balayeur;

impl<'de> Visitor<'de> for Balayeur {
    type Value = Balayage;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("du JSON")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Balayage, E> {
        Ok(Balayage(0))
    }

    fn visit_i64<E>(self, _: i64) -> Result<Balayage, E> {
        Ok(Balayage(0))
    }

    fn visit_u64<E>(self, _: u64) -> Result<Balayage, E> {
        Ok(Balayage(0))
    }

    fn visit_f64<E>(self, _: f64) -> Result<Balayage, E> {
        Ok(Balayage(0))
    }

    fn visit_unit<E>(self) -> Result<Balayage, E> {
        Ok(Balayage(0))
    }

    fn visit_str<E>(self, s: &str) -> Result<Balayage, E> {
        Ok(Balayage(texte::alertes(s)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Balayage, A::Error> {
        let mut n = 0u32;
        while let Some(Balayage(x)) = a.next_element()? {
            n = n.saturating_add(x);
        }
        Ok(Balayage(n))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Balayage, A::Error> {
        let mut n = 0u32;
        while let Some(Balayage(k)) = a.next_key()? {
            let Balayage(v) = a.next_value()?;
            n = n.saturating_add(k).saturating_add(v);
        }
        Ok(Balayage(n))
    }
}

// --- Les comptes d'un lot ----------------------------------------------------------------------------------------

/// Les nombres d'un lot, à plat : une clé de listes fermées, d'identifiants validés et d'empreintes, un nombre.
#[derive(Default)]
struct Stats(BTreeMap<String, u64>);

impl Stats {
    fn n(&mut self, cle: String, v: u64) {
        if v > 0 {
            let e = self.0.entry(cle).or_insert(0);
            *e = e.saturating_add(v);
        }
    }

    fn oui(&mut self, cle: String, b: bool) {
        self.n(cle, u64::from(b));
    }

    /// L'ordre de grandeur d'une durée ou d'un âge (nombre de bits) : la valeur exacte ne sert à aucun signal.
    fn ordre(&mut self, cle: &str, v: u64) {
        if v > 0 {
            self.n(format!("{cle}|b{}", u64::BITS.saturating_sub(v.leading_zeros())), 1);
        }
    }
}

/// L'empreinte d'un texte de la voie ouverte (nom de logiciel, modèle, version tierce) : « # » et 16 chiffres
/// hexadécimaux. L'IA de nuit peut compter les mêmes, jamais lire le texte.
fn empreinte(domaine: &str, s: &str) -> String {
    let mut h = blake3::Hasher::new_derive_key("vanguard flotte empreinte 1");
    h.update(domaine.as_bytes());
    h.update(&[0]);
    h.update(s.as_bytes());
    let hex = h.finalize().to_hex();
    format!("#{}", &hex[..16])
}

fn est_cle(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= CLE_MAX
        && s.bytes()
            .all(|o| o.is_ascii_alphanumeric() || b"_.:/|#=+-".contains(&o))
}

/// Un morceau de clé : tel quel s'il est sûr, sinon son empreinte (aucun cas connu ; une liste fermée qui grandirait).
fn morceau(s: &str) -> String {
    if s.len() <= 120 && !s.contains('|') && est_cle(s) {
        s.to_string()
    } else {
        empreinte("morceau", s)
    }
}

fn ou_tiret(r: Option<&Regle>) -> &str {
    r.map_or("-", Regle::as_str)
}

/// La classe de machine : physique ou virtuelle, disque, fils par paliers ; « inconnue » sans matériel.
fn classe(lot: &Lot) -> String {
    let Some(m) = &lot.materiel else {
        return "inconnue".to_string();
    };
    let sorte = if m.virtuelle == Virtuelle::Aucune {
        "physique"
    } else {
        "virtuelle"
    };
    let fils = match m.fils.get() {
        0..=2 => "f1-2",
        3..=4 => "f3-4",
        5..=8 => "f5-8",
        9..=16 => "f9-16",
        _ => "f17+",
    };
    format!("{sorte}-{}-{fils}", m.disque.id())
}

/// Le groupe : famille fine du système et classe de machine.
fn groupe(lot: &Lot) -> String {
    format!("{}|{}", lot.plateforme.famille.id(), classe(lot))
}

#[allow(clippy::too_many_lines)]
fn stats(lot: &Lot) -> BTreeMap<String, u64> {
    let mut s = Stats::default();
    let p = &lot.plateforme;
    s.n(format!("anciennete|{}", lot.anciennete.id()), 1);
    s.n(format!("systeme|{}", morceau(p.systeme_version.as_str())), 1);
    s.n(format!("arch|{}", p.arch.id()), 1);
    s.n(format!("langue|{}", p.langue.id()), 1);
    if let Some(e) = p.edition {
        s.n(format!("edition|{}", e.id()), 1);
    }
    s.oui("administrateur".into(), p.administrateur);
    if let Some(v) = &lot.version_avant {
        s.n(format!("version-avant|{}", v.as_str()), 1);
    }
    let a = &lot.activite;
    s.n("activite|bilans_manuels".into(), u64::from(a.bilans_manuels.get()));
    s.n("activite|passes_horaires".into(), u64::from(a.passes_horaires.get()));
    s.oui("activite|surveillance".into(), a.surveillance);
    s.oui("activite|veilleur".into(), a.veilleur);
    s.oui("activite|cle".into(), a.cle);
    if let Some(m) = &lot.materiel {
        s.n(format!("materiel|processeur|{}", m.processeur.id()), 1);
        s.ordre("materiel|coeurs", u64::from(m.coeurs.get()));
        s.ordre("materiel|fils", u64::from(m.fils.get()));
        s.n(format!("materiel|memoire|{}", m.memoire_go.get()), 1);
        s.n(format!("materiel|disque|{}", m.disque.id()), 1);
        s.n(format!("materiel|virtuelle|{}", m.virtuelle.id()), 1);
        s.oui("materiel|portable".into(), m.portable);
        s.n(format!("materiel|tpm|{}", m.tpm.id()), 1);
        s.n(format!("materiel|demarrage_securise|{}", m.demarrage_securise.id()), 1);
        s.n(format!("materiel|graphique|{}", m.graphique.id()), 1);
        if let Some(x) = &m.modele_processeur {
            s.n(
                format!("materiel|modele_processeur|{}", empreinte("modele", x.as_str())),
                1,
            );
        }
        if let Some(x) = &m.modele_graphique {
            s.n(
                format!("materiel|modele_graphique|{}", empreinte("modele", x.as_str())),
                1,
            );
        }
    }
    // Les taux de la régression par version (A9) : une source compte si un de ses lots a eu un plantage, une cause.
    s.oui(
        "taux|plantage".into(),
        lot.causes.entrees().iter().any(|c| c.genre.id() == "plantage"),
    );
    s.oui("taux|cause".into(), !lot.causes.est_vide());
    for r in lot.regles.entrees() {
        let k = format!("regle|{}", r.id.as_str());
        // Un constat instable (plan, §1) : problème et sain dans la même période sans correction réussie qui
        // expliquerait le passage de l'un à l'autre.
        let corrigee = lot
            .corrections
            .entrees()
            .iter()
            .any(|c| c.regle == r.id && !c.reussies.est_nul());
        s.oui(
            format!("instable|{}", r.id.as_str()),
            !r.problemes.est_nul() && !r.sains.est_nul() && !corrigee,
        );
        s.n(format!("{k}|vue"), 1);
        s.n(format!("{k}|n"), u64::from(r.n.get()));
        s.n(format!("{k}|problemes"), u64::from(r.problemes.get()));
        s.n(format!("{k}|sains"), u64::from(r.sains.get()));
        s.n(format!("{k}|non_verifies"), u64::from(r.non_verifies.get()));
        s.n(format!("{k}|hors_delai"), u64::from(r.hors_delai.get()));
        let frole = r.p90_ms.get() > 0
            && u64::from(r.p90_ms.get()).saturating_mul(2) >= u64::from(r.delai_s.get()).saturating_mul(1000);
        s.oui(format!("{k}|frole"), frole);
        s.ordre(&format!("{k}|med_ms"), u64::from(r.med_ms.get()));
        s.ordre(&format!("{k}|p90_ms"), u64::from(r.p90_ms.get()));
        for x in r.raisons.entrees() {
            s.n(format!("{k}|raison|{}", morceau(x.code.as_str())), u64::from(x.n.get()));
        }
    }
    for c in lot.causes.entrees() {
        let k = format!(
            "cause|{}|{}|{}|{}|{}",
            morceau(c.genre.id()),
            morceau(c.contexte.id()),
            ou_tiret(c.regle.as_ref()),
            c.lieu
                .as_ref()
                .map_or_else(|| "-".to_string(), |l| morceau(l.sans_colonne())),
            c.code.as_ref().map_or_else(|| "-".to_string(), |x| morceau(x.as_str())),
        );
        s.n(format!("{k}|n"), u64::from(c.n.get()));
        s.ordre(&format!("{k}|duree_ms"), u64::from(c.duree_ms.get()));
        s.n(format!("{k}|en_plus"), u64::from(c.en_plus.get()));
        s.n(format!("{k}|en_moins"), u64::from(c.en_moins.get()));
        s.n(format!("{k}|differents"), u64::from(c.differents.get()));
        if let Some(g) = &c.gabarit {
            s.n(
                format!(
                    "gabarit|{}|{}|{}",
                    g.as_str(),
                    morceau(c.genre.id()),
                    morceau(c.contexte.id())
                ),
                u64::from(c.n.get()),
            );
        }
    }
    for o in lot.objets.entrees() {
        let nom = empreinte("nom", o.nom.as_str());
        s.n(
            format!("objet|{}|{}|{}|{nom}", o.regle.as_str(), o.sorte.id(), o.etat.id()),
            u64::from(o.n.get()),
        );
        if let Some(v) = &o.version {
            s.n(
                format!(
                    "objet-version|{}|{nom}|{}",
                    o.regle.as_str(),
                    empreinte("version", v.as_str())
                ),
                u64::from(o.n.get()),
            );
        }
    }
    for t in lot.textes.entrees() {
        s.n(
            format!(
                "texte|{}|{}|{}",
                t.gabarit().as_str(),
                morceau(t.contexte().id()),
                ou_tiret(t.regle())
            ),
            u64::from(t.n().get()),
        );
    }
    for c in lot.corrections.entrees() {
        let k = format!("correction|{}", c.regle.as_str());
        for (nom, v) in [
            ("proposees", c.proposees.get()),
            ("acceptees", c.acceptees.get()),
            ("refusees", c.refusees.get()),
            ("reussies", c.reussies.get()),
            ("echouees", c.echouees.get()),
            ("annulees", c.annulees.get()),
            ("revenues", c.revenues.get()),
        ] {
            s.n(format!("{k}|{nom}"), u64::from(v));
        }
        // Le dénominateur de l'échec d'une correction : celles qui ont été appliquées (réussies ou échouées).
        s.n(
            format!("{k}|appliquees"),
            u64::from(c.reussies.get()).saturating_add(u64::from(c.echouees.get())),
        );
        for x in c.codes.entrees() {
            s.n(format!("{k}|code|{}", morceau(x.code.as_str())), u64::from(x.n.get()));
        }
    }
    for c in lot.choix.entrees() {
        let k = format!("choix|{}", c.regle.as_str());
        for (nom, v) in [
            ("normales", c.normales.get()),
            ("oublis", c.oublis.get()),
            ("refus", c.refus.get()),
            ("echap", c.echap.get()),
        ] {
            s.n(format!("{k}|{nom}"), u64::from(v));
        }
    }
    for o in lot.outils.entrees() {
        let k = format!("outil|{}|{}", o.outil.as_str(), o.origine.id());
        for (nom, v) in [
            ("lances", o.lances.get()),
            ("finis", o.finis.get()),
            ("abandonnes", o.abandonnes.get()),
            ("plantes", o.plantes.get()),
        ] {
            s.n(format!("{k}|{nom}"), u64::from(v));
        }
        s.ordre(&format!("{k}|med_ms"), u64::from(o.med_ms.get()));
    }
    for c in lot.cache.entrees() {
        let k = format!("cache|{}", c.regle.as_str());
        for (nom, v) in [
            ("repris", c.repris.get()),
            ("a_neuf", c.a_neuf.get()),
            ("comparees", c.comparees.get()),
            ("ecarts", c.ecarts.get()),
        ] {
            s.n(format!("{k}|{nom}"), u64::from(v));
        }
        s.ordre(&format!("{k}|age_total_s"), u64::from(c.age_total_s.get()));
        s.ordre(&format!("{k}|gagne_ms"), u64::from(c.gagne_ms.get()));
    }
    for r in lot.reglages.entrees() {
        let k = format!("reglage|{}|{}", r.levier.id(), ou_tiret(r.regle.as_ref()));
        s.n(format!("{k}|vu"), 1);
        s.oui(format!("{k}|annule"), r.annule);
        s.ordre(&format!("{k}|avant"), u64::from(r.avant.get()));
        s.ordre(&format!("{k}|apres"), u64::from(r.apres.get()));
    }
    let r = &lot.retires;
    for (nom, v) in [
        ("regles", r.regles.get()),
        ("textes", r.textes.get()),
        ("objets", r.objets.get()),
        ("cache", r.cache.get()),
        ("outils", r.outils.get()),
        ("choix", r.choix.get()),
        ("corrections", r.corrections.get()),
        ("reglages", r.reglages.get()),
        ("causes", r.causes.get()),
    ] {
        s.n(format!("retires|{nom}"), u64::from(v));
    }
    s.n("refus_locaux".into(), u64::from(lot.refus_locaux.get()));
    // Une clé qui sortirait du motif (aucune connue) n'est pas gardée : l'état relu la refuserait.
    s.0.retain(|k, _| est_cle(k));
    s.0
}

/// Chaque règle nommée par un lot, où qu'elle soit.
fn regles(lot: &Lot) -> impl Iterator<Item = &Regle> {
    let causes = lot.causes.entrees().iter().filter_map(|c| c.regle.as_ref());
    let regles = lot.regles.entrees().iter().map(|r| &r.id);
    let objets = lot.objets.entrees().iter().map(|o| &o.regle);
    let textes = lot.textes.entrees().iter().filter_map(|t| t.regle());
    let corrections = lot.corrections.entrees().iter().map(|c| &c.regle);
    let choix = lot.choix.entrees().iter().map(|c| &c.regle);
    let cache = lot.cache.entrees().iter().map(|c| &c.regle);
    let reglages = lot.reglages.entrees().iter().filter_map(|r| r.regle.as_ref());
    causes
        .chain(regles)
        .chain(objets)
        .chain(textes)
        .chain(corrections)
        .chain(choix)
        .chain(cache)
        .chain(reglages)
}

// --- L'agrégat ---------------------------------------------------------------------------------------------------

/// Les clés gardées par voix : une source qui envoie des milliers de lots aux noms tous différents ne fait pas
/// grossir la nuit sans fin.
const CLES_VOIX_MAX: usize = 2000;
/// Les installations gardées par voix : un foyer derrière une même adresse en a quelques-unes ; une source ne peut
/// pas en déclarer mille pour gonfler le compte des installations distinctes.
const INSTALLATIONS_VOIX_MAX: usize = 8;

/// Ce qu'une source a dit un jour, sur tous ses lots : chaque nombre à son maximum. Bornée en gardant les plus
/// petites clés (et installations) dans l'ordre du texte : une clé écartée avait déjà assez de plus petites qu'elle
/// et en aura toujours ; le résultat ne dépend donc pas de l'ordre des lots.
#[derive(Default)]
struct Voix {
    larges: BTreeSet<String>,
    lots: u64,
    installations: BTreeSet<String>,
    stats: BTreeMap<String, u64>,
}

impl Voix {
    fn ajouter(&mut self, large: &str, installation: Option<&str>, stats: &BTreeMap<String, u64>) {
        self.larges.insert(large.to_string());
        self.lots = self.lots.saturating_add(1);
        if let Some(i) = installation {
            self.installations.insert(i.to_string());
            while self.installations.len() > INSTALLATIONS_VOIX_MAX {
                self.installations.pop_last();
            }
        }
        for (k, v) in stats {
            let e = self.stats.entry(k.clone()).or_insert(0);
            *e = (*e).max(*v);
        }
        while self.stats.len() > CLES_VOIX_MAX {
            self.stats.pop_last();
        }
    }
}

/// Les comptes d'un jour ou d'un groupe : sources distinctes, réseaux larges distincts, lots, installations
/// distinctes, et pour chaque clé `[sources, réseaux larges, somme des maximums par source]`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Agregat {
    pub(crate) sources: u64,
    pub(crate) larges: u64,
    pub(crate) lots: u64,
    pub(crate) installations: u64,
    pub(crate) stats: BTreeMap<String, [u64; 3]>,
}

fn compter(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl Agregat {
    fn de(voix: &BTreeMap<String, Voix>) -> Agregat {
        let mut larges = BTreeSet::new();
        let mut installations = BTreeSet::new();
        let mut lots = 0u64;
        let mut par_cle: BTreeMap<&str, (u64, BTreeSet<&str>, u64)> = BTreeMap::new();
        for v in voix.values() {
            larges.extend(v.larges.iter().map(String::as_str));
            installations.extend(v.installations.iter().map(String::as_str));
            lots = lots.saturating_add(v.lots);
            for (k, n) in &v.stats {
                let e = par_cle.entry(k).or_default();
                e.0 = e.0.saturating_add(1);
                e.1.extend(v.larges.iter().map(String::as_str));
                e.2 = e.2.saturating_add(*n);
            }
        }
        Agregat {
            sources: compter(voix.len()),
            larges: compter(larges.len()),
            lots,
            installations: compter(installations.len()),
            stats: par_cle
                .into_iter()
                .map(|(k, (s, l, n))| (k.to_string(), [s, compter(l.len()), n]))
                .collect(),
        }
    }

    fn valide(&self) -> bool {
        self.stats.keys().all(|k| est_cle(k))
    }
}

/// Un jour de réception : tout ensemble (une voix par source), puis par groupe (famille et classe de machine), puis
/// par famille seule (A9 : les taux du plan se comparent « même famille »). `familles` manque aux états écrits avant
/// A9 : relu vide, sans changer de format (un champ en plus, facultatif ; l'ancien lecteur n'est plus là pour le
/// refuser).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JourFlotte {
    pub(crate) tous: Agregat,
    pub(crate) groupes: BTreeMap<String, Agregat>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) familles: BTreeMap<String, Agregat>,
}

/// L'état d'une version (`etat/flotte/<version>.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EtatVersion {
    pub(crate) schema: u8,
    pub(crate) version: Version,
    pub(crate) jours: BTreeMap<Jour, JourFlotte>,
}

impl EtatVersion {
    /// Relu : même format, même version que le nom du fichier, clés dans leur motif ; sinon rien (compté).
    fn lire(octets: &[u8], version: &Version) -> Option<EtatVersion> {
        let e: EtatVersion = serde_json::from_slice(octets).ok()?;
        let bon = e.schema == ETAT_SCHEMA
            && e.version == *version
            && e.jours.values().all(|j| {
                j.tous.valide()
                    && j.groupes.iter().all(|(g, a)| est_cle(g) && a.valide())
                    && j.familles
                        .iter()
                        .all(|(f, a)| envoi::FamilleFine::TOUS.iter().any(|x| x.id() == f) && a.valide())
            });
        bon.then_some(e)
    }
}

/// Le résumé d'un fichier de relève (`etat/flotte/releve.json`) : lignes, lots, refus, et les refus du relais.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleveJour {
    pub(crate) lignes: u64,
    pub(crate) illisibles: u64,
    pub(crate) lots: u64,
    pub(crate) acceptes: u64,
    pub(crate) rejets: BTreeMap<String, u64>,
    pub(crate) relais: BTreeMap<Jour, BTreeMap<String, u64>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EtatReleve {
    schema: u8,
    fichiers: BTreeMap<Jour, ReleveJour>,
}

impl EtatReleve {
    fn lire(octets: &[u8]) -> Option<EtatReleve> {
        let e: EtatReleve = serde_json::from_slice(octets).ok()?;
        let bon = e.schema == ETAT_SCHEMA
            && e.fichiers.values().all(|f| {
                f.rejets.keys().all(|k| Rejet::TOUS.iter().any(|r| r.id() == k))
                    && f.relais.values().all(|m| {
                        m.keys()
                            .all(|k| k == "inconnue" || RAISONS_RELAIS.contains(&k.as_str()))
                    })
            });
        bon.then_some(e)
    }
}

// --- La lecture d'une nuit ---------------------------------------------------------------------------------------

/// Les comptes d'une lecture : des nombres seulement, jamais rien d'un lot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Comptes {
    pub(crate) fichiers: u64,
    /// Fichiers de la fenêtre écartés : lien, trop gros, illisibles.
    pub(crate) fichiers_ignores: u64,
    pub(crate) lignes: u64,
    pub(crate) illisibles: u64,
    pub(crate) lots: u64,
    pub(crate) acceptes: u64,
    /// Voix comptées : une par version, jour de réception et source.
    pub(crate) votes: u64,
    pub(crate) relais_refus: u64,
    /// Dont les refus du relais pour quota ou plafond atteints (le rapport du matin les dit).
    pub(crate) relais_quota: u64,
    /// États de version écrits.
    pub(crate) versions: u64,
    /// Clés ou jours retirés pour tenir dans `ETAT_MAX`.
    pub(crate) elagues: u64,
    pub(crate) etats_illisibles: u64,
    /// Un fichier de la fenêtre écarté : l'état n'est pas récrit cette nuit (il perdrait les jours de ce fichier, pour
    /// de bon s'ils se figeaient avant qu'il redevienne lisible) ; la commande échoue pour que l'auteur le sache.
    pub(crate) etat_retenu: bool,
    pub(crate) rejets: BTreeMap<Rejet, u64>,
    /// Les signaux tirés des états (A9) et les tickets écrits cette nuit ; 0 sans `--signaux`.
    pub(crate) signaux: u64,
    pub(crate) tickets: u64,
}

impl Comptes {
    pub(crate) fn rejet(&self, r: Rejet) -> u64 {
        self.rejets.get(&r).copied().unwrap_or(0)
    }

    /// Les refus du lot lui-même (ni quarantaine, ni doublon, ni jour figé).
    pub(crate) fn refuses(&self) -> u64 {
        self.rejets
            .iter()
            .filter(|(r, _)| !r.a_part())
            .fold(0u64, |a, (_, n)| a.saturating_add(*n))
    }

    /// La ligne de comptes lue par la veille.
    pub(crate) fn ligne(&self) -> String {
        let mut l = format!(
            "fichiers={} fichiers-ignores={} lignes={} illisibles={} lots={} acceptes={} votes={} quarantaine={} \
             doublons={} figes={} refuses={} relais-refus={} versions={} elagues={} etats-illisibles={} etat-retenu={}",
            self.fichiers,
            self.fichiers_ignores,
            self.lignes,
            self.illisibles,
            self.lots,
            self.acceptes,
            self.votes,
            self.rejet(Rejet::Quarantaine),
            self.rejet(Rejet::Doublon),
            self.rejet(Rejet::JourFige),
            self.refuses(),
            self.relais_refus,
            self.versions,
            self.elagues,
            self.etats_illisibles,
            u8::from(self.etat_retenu),
        );
        for r in Rejet::TOUS.iter().filter(|r| !r.a_part()) {
            let _ = write!(l, " refus-{}={}", r.id(), self.rejet(*r));
        }
        // À la fin : la veille lit les champs d'avant par leur place.
        let _ = write!(
            l,
            " relais-quota={} signaux={} tickets={}",
            self.relais_quota, self.signaux, self.tickets
        );
        l
    }
}

/// Ce que demande `vanguard compte-rendu envois|flotte`.
pub(crate) struct Demande<'a> {
    /// `retours/envois`.
    pub(crate) dossier: &'a Path,
    /// Les références tirées de l'arbre (`references-flotte.sh`).
    pub(crate) references: &'a References,
    /// `veille/etat/flotte` ; sans lui (`envois`), rien n'est écrit.
    pub(crate) etat: Option<&'a Path>,
    pub(crate) aujourdhui: NaiveDate,
    /// La borne de l'état d'une version (`ETAT_MAX` ; plus petite dans les essais).
    pub(crate) etat_max: usize,
}

/// Les voix d'un jour : tout ensemble, par groupe, par famille ; chacune par source.
#[derive(Default)]
struct VoixJour {
    tous: BTreeMap<String, Voix>,
    groupes: BTreeMap<String, BTreeMap<String, Voix>>,
    familles: BTreeMap<String, BTreeMap<String, Voix>>,
}

/// Les voix d'une nuit : version → jour de réception → voix du jour.
type Voix3 = BTreeMap<Version, BTreeMap<Jour, VoixJour>>;

/// Installations gardées dans l'histoire de la nuit (P1) : bien plus que la flotte attendue ; au-delà, les plus
/// petits identifiants (même raison que `Voix` : le résultat ne dépend pas de l'ordre des lots). L'histoire ne
/// vient que des voix déjà bornées, et au plus `INSTALLATIONS_VOIX_MAX` installations par source : une seule
/// adresse qui déclare des milliers de petits identifiants ne peut pas en chasser les vraies installations.
const HISTOIRE_MAX: usize = 100_000;

/// Ce qu'une source a dit un jour, installation par installation (P1), pour les seules clés des taux : de quoi
/// refaire un taux sur un sous-ensemble d'installations (anciennes, vues sur les deux versions). En mémoire
/// seulement, le temps de la nuit : l'identifiant d'installation n'est jamais écrit.
#[derive(Default)]
pub(crate) struct VoixP1 {
    larges: BTreeSet<String>,
    installations: BTreeMap<String, BTreeMap<String, u64>>,
}

impl VoixP1 {
    fn ajouter(&mut self, large: &str, installation: &str, stats: &BTreeMap<String, u64>) {
        self.larges.insert(large.to_string());
        let st = self.installations.entry(installation.to_string()).or_default();
        for (k, v) in stats.iter().filter(|(k, _)| cle_p1(k)) {
            let e = st.entry(k.clone()).or_insert(0);
            *e = (*e).max(*v);
        }
        while st.len() > CLES_VOIX_MAX {
            st.pop_last();
        }
        while self.installations.len() > INSTALLATIONS_VOIX_MAX {
            self.installations.pop_last();
        }
    }
}

/// Les clés qu'un signal compare sur les mêmes installations : numérateurs et dénominateurs des taux, rien d'autre.
fn cle_p1(k: &str) -> bool {
    let m: Vec<&str> = k.split('|').collect();
    match m.as_slice() {
        ["taux" | "instable", _] => true,
        ["regle", _, x] => matches!(*x, "vue" | "problemes" | "hors_delai" | "non_verifies"),
        ["choix", _, x] => *x == "normales",
        ["correction", _, x] => matches!(*x, "proposees" | "refusees" | "appliquees" | "echouees"),
        ["outil", _, _, x] => matches!(*x, "lances" | "abandonnes"),
        _ => false,
    }
}

/// Une voix P1 : version, jour de réception, famille.
pub(crate) type CleP1 = (Version, Jour, String);

/// Les données P1 de la nuit : les voix par installation et, pour chaque installation, le premier jour où elle a été
/// vue sur chaque version (fenêtre de la relève).
#[derive(Default)]
pub(crate) struct P1 {
    voix: BTreeMap<CleP1, BTreeMap<String, VoixP1>>,
    histoire: BTreeMap<String, BTreeMap<Version, NaiveDate>>,
}

impl P1 {
    /// L'histoire tirée des voix de la nuit, une fois tous les lots lus : par source, ses plus petits identifiants
    /// seulement (sur toutes ses voix), notés au premier jour de réception où elle les a dits sur chaque version.
    fn histoire_des_voix(&mut self) {
        let mut par_source: BTreeMap<&str, BTreeMap<&str, BTreeMap<&Version, NaiveDate>>> = BTreeMap::new();
        for ((version, jour, _), sources) in &self.voix {
            let Some(d) = date(jour) else {
                continue;
            };
            for (source, v) in sources {
                let s = par_source.entry(source.as_str()).or_default();
                for i in v.installations.keys() {
                    let e = s.entry(i.as_str()).or_default().entry(version).or_insert(d);
                    *e = (*e).min(d);
                }
                while s.len() > INSTALLATIONS_VOIX_MAX {
                    s.pop_last();
                }
            }
        }
        let notes: Vec<(String, Version, NaiveDate)> = par_source
            .values()
            .flat_map(|s| s.iter())
            .flat_map(|(i, m)| m.iter().map(move |(v, d)| ((*i).to_string(), (*v).clone(), *d)))
            .collect();
        for (i, v, d) in notes {
            self.noter(&i, &v, d);
        }
    }

    fn noter(&mut self, installation: &str, version: &Version, jour: NaiveDate) {
        let e = self
            .histoire
            .entry(installation.to_string())
            .or_default()
            .entry(version.clone())
            .or_insert(jour);
        *e = (*e).min(jour);
        while self.histoire.len() > HISTOIRE_MAX {
            self.histoire.pop_last();
        }
    }
}

/// Entrées ouvertes gardées par clé (règle ou gabarit), sources par entrée, clés : bornes de la nuit, plus petites
/// valeurs gardées (même raison que `Voix`).
const OUVERTES_CLES_MAX: usize = 2000;
const OUVERTES_ENTREES_MAX: usize = 200;
const OUVERTES_SOURCES_MAX: usize = 8;
/// Entrées ouvertes gardées en tout, toutes clés confondues : 2000 clés × 200 entrées feraient sinon des centaines
/// de Mo dans la nuit. Au-delà, les plus grandes paires (clé, entrée) partent, les gabarits d'abord (`a_retirer`) :
/// le même choix quel que soit l'ordre des lots (une paire écartée est toujours après toutes les gardées).
const OUVERTES_TOTAL_MAX: usize = 20_000;

/// Une donnée de la voie ouverte, pour les tickets de l'auteur seulement : un objet (nom, et « sorte version état »)
/// ou un texte nettoyé (texte, contexte). Déjà passés par le nettoyage de l'ordinateur et revérifiés par
/// `envoi::lire` ; jamais écrits dans l'état, jamais vus par l'IA sauf un nom approuvé par l'auteur.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Ouverte {
    Objet { nom: String, detail: String },
    Texte { texte: String, contexte: String },
}

/// Les données ouvertes de la nuit : clé (`regle|ID`, `gabarit|G`) → donnée → sources ; et le nombre d'entrées en
/// tout.
#[derive(Default)]
pub(crate) struct Ouvertes(BTreeMap<String, BTreeMap<Ouverte, BTreeSet<String>>>, usize);

impl Ouvertes {
    fn ajouter(&mut self, cle: String, donnee: Ouverte, source: &str) {
        let entrees = self.0.entry(cle).or_default();
        let avant = entrees.len();
        let sources = entrees.entry(donnee).or_default();
        sources.insert(source.to_string());
        while sources.len() > OUVERTES_SOURCES_MAX {
            sources.pop_last();
        }
        while entrees.len() > OUVERTES_ENTREES_MAX {
            entrees.pop_last();
        }
        self.1 = self.1.saturating_add(entrees.len()).saturating_sub(avant);
        while self.0.len() > OUVERTES_CLES_MAX {
            let Some(k) = self.a_retirer() else { break };
            if let Some(e) = self.0.remove(&k) {
                self.1 = self.1.saturating_sub(e.len());
            }
        }
        while self.1 > OUVERTES_TOTAL_MAX {
            let Some(k) = self.a_retirer() else { break };
            let Some(entrees) = self.0.get_mut(&k) else { break };
            if entrees.pop_last().is_some() {
                self.1 = self.1.saturating_sub(1);
            }
            if entrees.is_empty() {
                self.0.remove(&k);
            }
        }
    }

    /// La clé qui perd en premier : le plus grand gabarit (n'importe qui peut en inventer), puis seulement la plus
    /// grande clé (les règles sont celles du programme, en nombre fini). Sans cela, « gabarit| » se rangeant avant
    /// « regle| », une inondation de gabarits chasserait les données des règles.
    fn a_retirer(&self) -> Option<String> {
        self.0
            .range::<str, _>((
                std::ops::Bound::Included("gabarit|"),
                std::ops::Bound::Excluded("gabarit}"),
            ))
            .next_back()
            .or_else(|| self.0.iter().next_back())
            .map(|(k, _)| k.clone())
    }

    fn lot(&mut self, lot: &Lot, source: &str) {
        for o in lot.objets.entrees() {
            let detail = format!(
                "{} {} {}",
                o.sorte.id(),
                o.version.as_ref().map_or("-", |v| v.as_str()),
                o.etat.id()
            );
            let donnee = Ouverte::Objet {
                nom: o.nom.as_str().to_string(),
                detail,
            };
            self.ajouter(format!("regle|{}", o.regle.as_str()), donnee, source);
        }
        for t in lot.textes.entrees() {
            let donnee = Ouverte::Texte {
                texte: t.texte().as_str().to_string(),
                contexte: t.contexte().id().to_string(),
            };
            if let Some(r) = t.regle() {
                self.ajouter(format!("regle|{}", r.as_str()), donnee.clone(), source);
            }
            self.ajouter(format!("gabarit|{}", t.gabarit().as_str()), donnee, source);
        }
    }

    /// Les données d'une clé vues d'au moins deux sources (une seule source ne fait pas une donnée de la flotte),
    /// les plus vues d'abord, puis dans l'ordre du texte.
    pub(crate) fn de(&self, cle: &str, max: usize) -> Vec<(&Ouverte, usize)> {
        let Some(entrees) = self.0.get(cle) else {
            return Vec::new();
        };
        let mut v: Vec<(&Ouverte, usize)> = entrees
            .iter()
            .map(|(d, s)| (d, s.len()))
            .filter(|(_, n)| *n >= 2)
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        v.truncate(max);
        v
    }
}

/// Ce que les signaux lisent après une nuit : les états de chaque version (avant élagage : tout ce que la nuit sait),
/// les voix P1, les données ouvertes.
pub(crate) struct Analyse {
    pub(crate) aujourdhui: NaiveDate,
    pub(crate) etats: BTreeMap<Version, EtatVersion>,
    pub(crate) p1: P1,
    pub(crate) ouvertes: Ouvertes,
}

struct Lecture<'a> {
    d: &'a Demande<'a>,
    comptes: Comptes,
    voix: Voix3,
    vus: BTreeSet<(Jour, String, [u8; 32])>,
    releve: BTreeMap<Jour, ReleveJour>,
    p1: P1,
    ouvertes: Ouvertes,
}

impl Lecture<'_> {
    /// Les fichiers de la fenêtre, triés par jour.
    fn fichiers(&mut self) -> Result<BTreeMap<NaiveDate, PathBuf>, Echec> {
        let mut f = BTreeMap::new();
        let lus = match std::fs::read_dir(self.d.dossier) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(f),
            Err(e) => return Err(Echec::io(LIRE, &e)),
        };
        let t = self.d.aujourdhui;
        for entree in lus {
            let entree = entree.map_err(|e| Echec::io(LIRE, &e))?;
            let nom = entree.file_name();
            let Some(jour) = nom
                .to_str()
                .and_then(|n| n.strip_suffix(".jsonl"))
                .and_then(Jour::new)
                .and_then(|j| date(&j))
            else {
                continue;
            };
            if jour < moins(t, FICHIERS_AVANT) || jour > plus(t, 1) {
                continue;
            }
            // Ni lien (il ferait lire un autre fichier), ni fichier trop gros : écarté, compté.
            let bon = std::fs::symlink_metadata(entree.path()).is_ok_and(|m| m.is_file() && m.len() <= FICHIER_MAX);
            if bon {
                f.insert(jour, entree.path());
            } else {
                self.comptes.fichiers_ignores = self.comptes.fichiers_ignores.saturating_add(1);
            }
        }
        Ok(f)
    }

    fn rejeter(&mut self, resume: &mut ReleveJour, r: Rejet) {
        let e = self.comptes.rejets.entry(r).or_insert(0);
        *e = e.saturating_add(1);
        let e = resume.rejets.entry(r.id().to_string()).or_insert(0);
        *e = e.saturating_add(1);
    }

    fn fichier(&mut self, f: NaiveDate, chemin: &Path) {
        let Some(jour_f) = jour_de(f) else { return };
        let Some(octets) = lire_borne(chemin, FICHIER_MAX).ok().flatten() else {
            self.comptes.fichiers_ignores = self.comptes.fichiers_ignores.saturating_add(1);
            return;
        };
        self.comptes.fichiers = self.comptes.fichiers.saturating_add(1);
        let mut resume = ReleveJour::default();
        for ligne in octets
            .split(|o| *o == b'\n')
            .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
        {
            resume.lignes = resume.lignes.saturating_add(1);
            self.comptes.lignes = self.comptes.lignes.saturating_add(1);
            if !self.ligne(f, ligne, &mut resume) {
                resume.illisibles = resume.illisibles.saturating_add(1);
                self.comptes.illisibles = self.comptes.illisibles.saturating_add(1);
            }
        }
        self.releve.insert(jour_f, resume);
    }

    /// Une réponse du relais ; faux si elle est illisible (rien n'en est compté alors).
    fn ligne(&mut self, f: NaiveDate, ligne: &[u8], resume: &mut ReleveJour) -> bool {
        if ligne.len() > LIGNE_MAX {
            return false;
        }
        let Ok(texte) = std::str::from_utf8(ligne) else {
            return false;
        };
        let Ok(r) = serde_json::from_str::<Reponse<'_>>(texte) else {
            return false;
        };
        if r.releve != 1 || r.lots.len() > LOTS_MAX || r.refus.len() > REFUS_LIGNES_MAX {
            return false;
        }
        let mut relais = Vec::with_capacity(r.refus.len());
        for x in &r.refus {
            // Le jour borné comme la réception d'un lot (le relais ne garde que 14 jours) : sinon mille jours
            // distincts par ligne feraient grossir releve.json sans limite.
            let Some(j) = Jour::new(&x.jour) else { return false };
            if x.n > REFUS_N_MAX || date(&j).is_none_or(|d| d < moins(f, RECU_AVANT) || d > plus(f, 1)) {
                return false;
            }
            let raison = if RAISONS_RELAIS.contains(&x.raison.as_str()) {
                x.raison.clone()
            } else {
                "inconnue".to_string()
            };
            relais.push((j, raison, x.n));
        }
        for (j, raison, n) in relais {
            if raison == "quota" || raison == "plafond" {
                self.comptes.relais_quota = self.comptes.relais_quota.saturating_add(n);
            }
            let e = resume.relais.entry(j).or_default().entry(raison).or_insert(0);
            *e = e.saturating_add(n);
            self.comptes.relais_refus = self.comptes.relais_refus.saturating_add(n);
        }
        for recu in &r.lots {
            resume.lots = resume.lots.saturating_add(1);
            self.comptes.lots = self.comptes.lots.saturating_add(1);
            match self.lot(f, recu) {
                Ok(()) => {
                    resume.acceptes = resume.acceptes.saturating_add(1);
                    self.comptes.acceptes = self.comptes.acceptes.saturating_add(1);
                }
                Err(rejet) => self.rejeter(resume, rejet),
            }
        }
        true
    }

    /// Un lot : vérifié dans l'ordre de `Rejet`, puis compté dans la voix de sa source.
    fn lot(&mut self, f: NaiveDate, recu: &LotRecu<'_>) -> Result<(), Rejet> {
        let t = self.d.aujourdhui;
        let (Some(jour_r), true, true) = (
            Jour::new(&recu.jour),
            est_empreinte(&recu.source),
            est_empreinte(&recu.source_large),
        ) else {
            return Err(Rejet::Enveloppe);
        };
        let r = date(&jour_r).ok_or(Rejet::Enveloppe)?;
        if r < moins(f, RECU_AVANT) || r > plus(f, 1) || r > plus(t, 1) {
            return Err(Rejet::Enveloppe);
        }
        let brut = recu.lot.get();
        if brut.len() > envoi::LOT_MAX {
            return Err(Rejet::TropGros);
        }
        match serde_json::from_str::<Balayage>(brut) {
            Ok(Balayage(0)) => {}
            Ok(_) => return Err(Rejet::Quarantaine),
            Err(_) => return Err(Rejet::HorsSchema),
        }
        let lot = envoi::lire(brut.as_bytes()).map_err(|e| match e {
            envoi::Refus::TropGros => Rejet::TropGros,
            envoi::Refus::HorsSchema => Rejet::HorsSchema,
        })?;
        let refs = self.d.references;
        let publiee = *refs.publiees.get(&lot.version).ok_or(Rejet::VersionNonPubliee)?;
        if !refs.recentes.contains(&mineure(&lot.version)) {
            return Err(Rejet::VersionAncienne);
        }
        if let Some(avant) = &lot.version_avant
            && (!refs.publiees.contains_key(avant) || version_cle(avant) >= version_cle(&lot.version))
        {
            return Err(Rejet::VersionAvant);
        }
        let jour_lot = date(&lot.jour).ok_or(Rejet::HorsSchema)?;
        if jour_lot < moins(r, LOT_AVANT) || jour_lot > plus(r, LOT_APRES) {
            return Err(Rejet::Jour);
        }
        // Un jour (du lot ou de sa réception) d'avant la publication de sa version, à un jour près (fuseaux).
        if publiee > plus(jour_lot.min(r), 1) {
            return Err(Rejet::Futur);
        }
        let arbre = refs.arbres.get(&lot.version).ok_or(Rejet::SansReference)?;
        if !regles(&lot).all(|x| arbre.regles.contains(x.as_str())) {
            return Err(Rejet::RegleInconnue);
        }
        if !lot
            .outils
            .entrees()
            .iter()
            .all(|o| arbre.outils.contains(o.outil.as_str()))
        {
            return Err(Rejet::OutilInconnu);
        }
        let lieux = lot.causes.entrees().iter().filter_map(|c| c.lieu.as_ref());
        if !lieux.into_iter().all(|l| {
            l.as_str()
                .split_once(':')
                .is_some_and(|(fichier, _)| arbre.fichiers.contains(fichier))
        }) {
            return Err(Rejet::LieuInconnu);
        }
        if !self.vus.insert((
            jour_r.clone(),
            recu.source.clone(),
            *blake3::hash(brut.as_bytes()).as_bytes(),
        )) {
            return Err(Rejet::Doublon);
        }
        if r < moins(t, FENETRE) {
            return Err(Rejet::JourFige);
        }
        let st = stats(&lot);
        let installation = lot.installation.as_ref().map(envoi::IdInstallation::as_str);
        let famille = lot.plateforme.famille.id().to_string();
        if let Some(i) = installation {
            self.p1
                .voix
                .entry((lot.version.clone(), jour_r.clone(), famille.clone()))
                .or_default()
                .entry(recu.source.clone())
                .or_default()
                .ajouter(&recu.source_large, i, &st);
        }
        self.ouvertes.lot(&lot, &recu.source);
        let vj = self
            .voix
            .entry(lot.version.clone())
            .or_default()
            .entry(jour_r)
            .or_default();
        vj.tous
            .entry(recu.source.clone())
            .or_default()
            .ajouter(&recu.source_large, installation, &st);
        vj.groupes
            .entry(groupe(&lot))
            .or_default()
            .entry(recu.source.clone())
            .or_default()
            .ajouter(&recu.source_large, installation, &st);
        vj.familles
            .entry(famille)
            .or_default()
            .entry(recu.source.clone())
            .or_default()
            .ajouter(&recu.source_large, installation, &st);
        Ok(())
    }
}

/// Les jours de la nuit, agrégés.
fn agreger(voix: &Voix3) -> BTreeMap<Version, BTreeMap<Jour, JourFlotte>> {
    voix.iter()
        .map(|(v, jours)| {
            let jours = jours
                .iter()
                .map(|(j, vj)| {
                    (
                        j.clone(),
                        JourFlotte {
                            tous: Agregat::de(&vj.tous),
                            groupes: vj.groupes.iter().map(|(g, x)| (g.clone(), Agregat::de(x))).collect(),
                            familles: vj.familles.iter().map(|(f, x)| (f.clone(), Agregat::de(x))).collect(),
                        },
                    )
                })
                .collect();
            (v.clone(), jours)
        })
        .collect()
}

fn taille(e: &EtatVersion) -> usize {
    serde_json::to_vec(e).map_or(usize::MAX, |v| v.len())
}

/// Tient l'état sous `max` octets : d'abord les clés vues d'une seule source dans les groupes et les familles, puis
/// les groupes, puis les clés d'une seule source du tout, puis les jours les plus anciens (il en reste toujours un),
/// puis les clés les moins vues par seuils doublés (tout et familles), puis les familles. Rend le nombre de clés et
/// de jours retirés. Les signaux de la nuit sont tirés avant l'élagage : il ne touche que ce qui est gardé.
fn borner(e: &mut EtatVersion, max: usize) -> Result<u64, Echec> {
    fn retirer(stats: &mut BTreeMap<String, [u64; 3]>, seuil: u64) -> u64 {
        let avant = stats.len();
        stats.retain(|_, x| x[0] > seuil);
        compter(avant.saturating_sub(stats.len()))
    }
    let mut retires = 0u64;
    if taille(e) > max {
        for j in e.jours.values_mut() {
            for a in j.groupes.values_mut().chain(j.familles.values_mut()) {
                retires = retires.saturating_add(retirer(&mut a.stats, 1));
            }
        }
    }
    if taille(e) > max {
        for j in e.jours.values_mut() {
            for a in std::mem::take(&mut j.groupes).values_mut() {
                retires = retires.saturating_add(retirer(&mut a.stats, u64::MAX));
            }
        }
    }
    if taille(e) > max {
        for j in e.jours.values_mut() {
            retires = retires.saturating_add(retirer(&mut j.tous.stats, 1));
        }
    }
    while taille(e) > max && e.jours.len() > 1 {
        if let Some((_, mut j)) = e.jours.pop_first() {
            retires = retires
                .saturating_add(retirer(&mut j.tous.stats, u64::MAX))
                .saturating_add(1);
            for a in j.familles.values_mut() {
                retires = retires.saturating_add(retirer(&mut a.stats, u64::MAX));
            }
        }
    }
    let mut seuil = 2u64;
    while taille(e) > max
        && e.jours
            .values()
            .any(|j| !j.tous.stats.is_empty() || j.familles.values().any(|a| !a.stats.is_empty()))
    {
        for j in e.jours.values_mut() {
            retires = retires.saturating_add(retirer(&mut j.tous.stats, seuil));
            for a in j.familles.values_mut() {
                retires = retires.saturating_add(retirer(&mut a.stats, seuil));
            }
        }
        seuil = seuil.saturating_mul(2);
    }
    if taille(e) > max {
        for j in e.jours.values_mut() {
            j.familles.clear();
        }
    }
    if taille(e) > max {
        return Err(Echec::refuse(
            LIRE,
            trf!(
                "état de la flotte au-delà de {} octets même élagué",
                "fleet state over {} bytes even pruned",
                max
            ),
        ));
    }
    Ok(retires)
}

fn ecrire(chemin: &Path, contenu: &[u8]) -> Result<(), Echec> {
    crate::socle::ecrire_atomique(chemin, contenu).map_err(|e| Echec::ecriture(LIRE, &e))
}

fn json<T: Serialize>(t: &T) -> Result<Vec<u8>, Echec> {
    serde_json::to_vec(t).map_err(|e| {
        Echec::refuse(
            LIRE,
            trf!("état impossible à écrire : {e}", "state could not be written: {e}"),
        )
    })
}

/// La version d'un fichier d'état `<X.Y.Z>.json`, nom strict.
fn version_du_fichier(nom: &std::ffi::OsStr) -> Option<Version> {
    nom.to_str()?.strip_suffix(".json").and_then(Version::new)
}

/// Une nuit : lit la relève de la fenêtre et, avec un dossier d'état, écrit l'état de chaque version récente (les
/// essais ; la commande passe par `executer_analyse`).
#[cfg(test)]
pub(crate) fn executer(d: &Demande<'_>) -> Result<Comptes, Echec> {
    executer_analyse(d).map(|x| x.0)
}

/// La même nuit, avec ce que les signaux lisent : rien sans dossier d'état, ni quand l'état est retenu (un fichier
/// écarté : des voix manqueraient, un signal pourrait naître ou se cacher de ce seul fait).
pub(crate) fn executer_analyse(d: &Demande<'_>) -> Result<(Comptes, Option<Analyse>), Echec> {
    let mut lu = Lecture {
        d,
        comptes: Comptes::default(),
        voix: BTreeMap::new(),
        vus: BTreeSet::new(),
        releve: BTreeMap::new(),
        p1: P1::default(),
        ouvertes: Ouvertes::default(),
    };
    for (f, chemin) in lu.fichiers()? {
        lu.fichier(f, &chemin);
    }
    let neufs = agreger(&lu.voix);
    lu.comptes.votes = neufs
        .values()
        .flat_map(BTreeMap::values)
        .fold(0u64, |a, j| a.saturating_add(j.tous.sources));
    let Some(dossier) = d.etat else {
        return Ok((lu.comptes, None));
    };
    if lu.comptes.fichiers_ignores > 0 {
        lu.comptes.etat_retenu = true;
        return Ok((lu.comptes, None));
    }
    let mut etats = BTreeMap::new();
    std::fs::create_dir_all(dossier).map_err(|e| Echec::ecriture(LIRE, &e))?;
    let t = d.aujourdhui;
    let fige = |j: &Jour| date(j).is_some_and(|x| x < moins(t, FENETRE));
    // Les versions à écrire : celles de la nuit et celles d'un état déjà là ; un état d'une mineure sortie part.
    let mut versions: BTreeSet<Version> = neufs.keys().cloned().collect();
    for entree in std::fs::read_dir(dossier).map_err(|e| Echec::io(LIRE, &e))? {
        let entree = entree.map_err(|e| Echec::io(LIRE, &e))?;
        let Some(v) = version_du_fichier(&entree.file_name()) else {
            continue;
        };
        if d.references.recentes.contains(&mineure(&v)) {
            versions.insert(v);
        } else {
            std::fs::remove_file(entree.path()).map_err(|e| Echec::ecriture(LIRE, &e))?;
        }
    }
    for v in versions {
        let chemin = dossier.join(format!("{}.json", v.as_str()));
        let ancien = match lire_borne(&chemin, u64::try_from(d.etat_max).unwrap_or(u64::MAX)) {
            Ok(Some(octets)) => {
                let relu = EtatVersion::lire(&octets, &v);
                if relu.is_none() {
                    lu.comptes.etats_illisibles = lu.comptes.etats_illisibles.saturating_add(1);
                }
                relu
            }
            Ok(None) => None,
            Err(_) => {
                lu.comptes.etats_illisibles = lu.comptes.etats_illisibles.saturating_add(1);
                None
            }
        };
        let mut jours: BTreeMap<Jour, JourFlotte> = ancien
            .map(|e| e.jours.into_iter().filter(|(j, _)| fige(j)).collect())
            .unwrap_or_default();
        if let Some(n) = neufs.get(&v) {
            jours.extend(n.iter().filter(|(j, _)| !fige(j)).map(|(j, x)| (j.clone(), x.clone())));
        }
        if jours.is_empty() {
            match std::fs::remove_file(&chemin) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Echec::ecriture(LIRE, &e)),
            }
            continue;
        }
        let mut etat = EtatVersion {
            schema: ETAT_SCHEMA,
            version: v.clone(),
            jours,
        };
        etats.insert(v, etat.clone());
        lu.comptes.elagues = lu.comptes.elagues.saturating_add(borner(&mut etat, d.etat_max)?);
        ecrire(&chemin, &json(&etat)?)?;
        lu.comptes.versions = lu.comptes.versions.saturating_add(1);
    }
    ecrire_releve(dossier, t, lu.releve, &mut lu.comptes)?;
    lu.p1.histoire_des_voix();
    let analyse = Analyse {
        aujourdhui: t,
        etats,
        p1: lu.p1,
        ouvertes: lu.ouvertes,
    };
    Ok((lu.comptes, Some(analyse)))
}

/// Le résumé des relèves : les fichiers lus cette nuit remplacent les leurs, les plus vieux que `RELEVE_GARDE`
/// partent.
fn ecrire_releve(
    dossier: &Path,
    t: NaiveDate,
    neufs: BTreeMap<Jour, ReleveJour>,
    comptes: &mut Comptes,
) -> Result<(), Echec> {
    let chemin = dossier.join("releve.json");
    let ancien = match lire_borne(&chemin, RELEVE_MAX) {
        Ok(Some(o)) => EtatReleve::lire(&o).or_else(|| {
            comptes.etats_illisibles = comptes.etats_illisibles.saturating_add(1);
            None
        }),
        Ok(None) => None,
        Err(_) => {
            comptes.etats_illisibles = comptes.etats_illisibles.saturating_add(1);
            None
        }
    };
    let mut fichiers: BTreeMap<Jour, ReleveJour> = ancien
        .map(|e| e.fichiers)
        .unwrap_or_default()
        .into_iter()
        .filter(|(j, _)| date(j).is_some_and(|x| x >= moins(t, RELEVE_GARDE) && x < moins(t, FICHIERS_AVANT)))
        .collect();
    fichiers.extend(neufs);
    ecrire(
        &chemin,
        &json(&EtatReleve {
            schema: ETAT_SCHEMA,
            fichiers,
        })?,
    )
}

/// Le jour de la nuit : donné (la veille, les essais), sinon aujourd'hui (UTC).
pub(crate) fn aujourdhui(donne: Option<&str>) -> Result<NaiveDate, Echec> {
    let j = match donne {
        Some(s) => Jour::new(s).ok_or_else(|| {
            Echec::refuse(
                LIRE,
                tr!("--aujourdhui : un jour AAAA-MM-JJ", "--aujourdhui: a day YYYY-MM-DD").to_string(),
            )
        })?,
        None => Jour::aujourdhui(),
    };
    date(&j).ok_or_else(|| Echec::refuse(LIRE, tr!("jour illisible", "unreadable day").to_string()))
}

/// La phrase pour l'auteur (sortie d'erreur ; la veille lit la ligne de comptes).
pub(crate) fn phrase(c: &Comptes) -> String {
    trf!(
        "{} lot(s) relu(s) : {} compté(s) en {} voix, {} refusé(s), {} en quarantaine, {} doublon(s) ; {} ligne(s) \
         illisible(s).",
        "{} batch(es) read: {} counted as {} vote(s), {} refused, {} quarantined, {} duplicate(s); {} unreadable \
         line(s).",
        c.lots,
        c.acceptes,
        c.votes,
        c.refuses(),
        c.rejet(Rejet::Quarantaine),
        c.rejet(Rejet::Doublon),
        c.illisibles
    )
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::as_conversions)]
mod tests;
