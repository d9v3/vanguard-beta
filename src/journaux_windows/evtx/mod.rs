//! Lecteur des journaux d'événements de Windows (.evtx), écrit pour Vanguard d'après les sources premières, sans
//! code d'un autre lecteur :
//!
//! - [MS-EVEN6] « EventLog Remoting Protocol Version 6.0 », Microsoft : 2.2.12 BinXml (grammaire, jetons, types de
//!   valeurs), 2.2.12.1 à 2.2.12.12 (règles de rendu), 3.1.4.7 et 3.1.4.7.1 à 3.1.4.7.6 (gabarits, substitutions
//!   optionnelles, système de types, type BinXml, tableaux).
//!   <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/c73573ae-1c90-43a2-a65f-ad7501155956>
//!   <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/e6fc7c72-b8c0-475b-aef7-25eaf1a64530>
//! - [MS-DTYP] « Windows Data Types », Microsoft : FILETIME, SYSTEMTIME, GUID, SID.
//!   <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/cca27429-5689-4a16-b2b4-9325d93e4ba2>
//! - `[libyal]` « Windows XML Event Log (EVTX) format », J. Metz (documentation du format, prose et tableaux, GFDL) :
//!   en-tête du fichier, morceaux, enregistrements, CRC32, et ce que le fichier change au BinXml de [MS-EVEN6]
//!   (noms et gabarits désignés par leur position dans le morceau).
//!   <https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc>
//! - RFC 1952 (§ 8) pour le CRC32. <https://www.rfc-editor.org/rfc/rfc1952>
//!
//! Le fichier : un en-tête de 4 096 octets (« ElfFile\0 », CRC32 de ses 120 premiers octets à 124), puis des
//! morceaux de 64 Kio (« ElfChnk\0 », CRC32 de l'en-tête du morceau : octets 0 à 120 et 128 à 512, à 124 ; CRC32
//! des enregistrements : de 512 à la place libre annoncée à 48, à 52), chacun suivi de ses enregistrements
//! (« **\0\0 », taille, numéro, date d'écriture, BinXml, copie de la taille).
//!
//! Le fichier vient d'ailleurs, parfois d'un Windows piraté : tout est borné (`Bornes`), rien n'est alloué d'après un
//! champ du fichier sans borne, aucune récursion sans limite, aucune panique. Chaque morceau se lit seul : un morceau
//! au CRC faux est écarté et compté, un enregistrement illisible est compté et sauté, la lecture continue ; le
//! `Bilan` dit toujours ce qui n'a pas pu être lu. Module autonome (aucun `crate::`) : le banc de fuzzing l'inclut
//! par son chemin (fuzz/fuzz_targets/evtx_fichier.rs, binxml.rs) ; les textes pour l'utilisateur viendront avec
//! son appelant (E2).

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

mod binxml;
mod valeurs;

// Ses fabriques de fichiers servent aussi aux essais de la suite des numéros (journaux_windows::trous).
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
pub(crate) mod tests;

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};

pub(crate) use binxml::ErreurBinxml;

/// Taille de l'en-tête du fichier, et place du premier morceau.
const EN_TETE: usize = 4096;
/// Taille d'un morceau.
const MORCEAU: usize = 65_536;
/// Taille de l'en-tête d'un morceau (tables de chaînes et de gabarits comprises) : les enregistrements suivent.
const EN_TETE_MORCEAU: usize = 512;
/// Signature, taille, numéro, date (24 octets), puis la copie de la taille (4) : le plus petit enregistrement.
const ENREGISTREMENT_MIN: usize = 28;
const EN_TETE_U64: u64 = 4096;
const MORCEAU_U64: u64 = 65_536;
const EN_TETE_MORCEAU_U64: u64 = 512;
const ENREGISTREMENT_MIN_U64: u64 = 28;
/// Le plus d'enregistrements minimaux que tiennent 64 Kio : au-delà, une plage annoncée ne se tient pas.
const ENREGISTREMENTS_PAR_MORCEAU: u64 = MORCEAU_U64 / ENREGISTREMENT_MIN_U64;

/// Les bornes d'une lecture. Les valeurs par défaut laissent passer tout vrai journal d'une maison ou d'une petite
/// entreprise (Security.evtx fait 20 Mo d'origine, quelques dizaines de milliers d'événements) et arrêtent ce qu'un
/// fichier fabriqué ferait durer ou grossir sans fin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bornes {
    /// Octets du fichier lus au plus ; les morceaux au-delà sont comptés, pas lus. 1 Gio : cinquante fois la taille
    /// d'origine du plus gros journal de Windows, et la lecture va morceau par morceau (64 Kio en mémoire).
    pub taille_fichier: u64,
    /// Événements rendus au plus ; les suivants sont comptés, pas rendus. Un événement de sécurité rendu pèse
    /// environ 6 Kio, arbre compris (mesuré : 62 031 événements, 380 Mo) : 200 000 font 1,2 Gio au plus pour
    /// `lire_fichier`, qui les garde tous, et rien pour `parcourir`, qui les donne un à un. Un journal d'origine
    /// (20 Mo) en a quelques dizaines de milliers.
    pub enregistrements: usize,
    /// Valeurs d'une instance de gabarit ; un vrai événement en a moins de cent (4624 : une trentaine).
    pub substitutions: usize,
    /// Éléments, instances et valeurs BinXml imbriqués ; un vrai événement descend à moins de dix.
    pub profondeur: usize,
    /// Caractères d'une valeur : une chaîne de 64 Kio (le plus qu'une valeur peut porter) n'est jamais coupée, un
    /// binaire en hexadécimal peut l'être.
    pub texte: usize,
    /// Octets de texte rendus pour un enregistrement : une valeur substituée mille fois s'arrête là.
    pub texte_enregistrement: usize,
    /// Éléments rendus pour un enregistrement.
    pub noeuds: usize,
    /// Pas de rendu pour un enregistrement (contenus, attributs) : le coût d'un gabarit démultiplié s'arrête là.
    pub travail: usize,
    /// Lectures d'octets du BinXml pour tout un morceau, gabarits et noms désignés compris. Un vrai morceau en fait
    /// quelques centaines de milliers (chaque jeton lu une fois, chaque gabarit et chaque nom une fois, les noms
    /// étant lus à part dans la limite de 256 caractères) ; des gabarits désignés à des positions qui se chevauchent
    /// feraient sinon relire le morceau presque autant de fois qu'il a d'octets. Le budget vaut pour tout le
    /// morceau : épuisé par un enregistrement fabriqué, il rend illisibles (et comptés) tous ceux qui suivent dans
    /// ce morceau, jamais ceux des morceaux suivants.
    pub lecture_morceau: usize,
}

impl Default for Bornes {
    fn default() -> Self {
        Self {
            taille_fichier: 1 << 30,
            enregistrements: 200_000,
            substitutions: 1024,
            profondeur: 48,
            texte: 32_768,
            texte_enregistrement: 1 << 20,
            noeuds: 4096,
            travail: 200_000,
            lecture_morceau: 1 << 21,
        }
    }
}

/// Un élément XML rendu : son nom, ses attributs (nom, valeur), son texte (tous ses morceaux de texte mis bout à
/// bout) et ses éléments enfants, dans l'ordre. Les noms sont partagés (`Arc`) entre tous les événements d'un même
/// morceau : un événement de sécurité en compte une soixantaine, chacun alloué à part doublait sa taille en mémoire. Les textes gardent leurs caractères tels quels : le nettoyage des
/// caractères piégés (contrôles, direction du texte) se fait à l'affichage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Noeud {
    pub nom: Arc<str>,
    pub attributs: Vec<(Arc<str>, String)>,
    pub texte: String,
    pub enfants: Vec<Noeud>,
}

impl Noeud {
    /// Le premier enfant de ce nom.
    pub(crate) fn enfant(&self, nom: &str) -> Option<&Noeud> {
        self.enfants.iter().find(|e| &*e.nom == nom)
    }

    /// La valeur du premier attribut de ce nom.
    pub(crate) fn attribut(&self, nom: &str) -> Option<&str> {
        self.attributs
            .iter()
            .find(|(n, _)| &**n == nom)
            .map(|(_, v)| v.as_str())
    }
}

/// Un événement lu dans le fichier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Enregistrement {
    /// Le numéro d'enregistrement (EventRecordID) de l'en-tête de l'enregistrement.
    pub numero: u64,
    /// Le rang dans le fichier du morceau qui le porte (0 : le premier après l'en-tête) : la suite des numéros se
    /// juge morceau par morceau (`RecapMorceau`).
    pub morceau: u64,
    /// Faux s'il vient d'un morceau au CRC faux (en-tête ou données), relu enregistrement par enregistrement : sa
    /// structure et son BinXml se tiennent, mais rien ne prouve que ce soit ce que Windows a écrit (une page à moitié
    /// recopiée, un morceau retouché). Un événement non vérifié peut servir d'indice, jamais à lui seul de preuve
    /// que tout va bien.
    pub verifie: bool,
    /// La date d'écriture de l'en-tête de l'enregistrement (FILETIME, UTC) ; rien si elle est hors des dates
    /// représentables.
    pub date: Option<DateTime<Utc>>,
    /// System/Provider, attribut Name (à défaut EventSourceName).
    pub fournisseur: String,
    /// System/EventID.
    pub id: Option<u32>,
    /// System/Level.
    pub niveau: Option<u8>,
    /// System/TimeCreated, attribut SystemTime.
    pub cree: Option<DateTime<Utc>>,
    /// System/EventRecordID, tel que le BinXml le donne (d'ordinaire égal à `numero`).
    pub numero_systeme: Option<u64>,
    /// System/Channel.
    pub canal: String,
    /// System/Computer.
    pub ordinateur: String,
    /// Les champs de EventData (Data : attribut Name, texte ; un Data sans Name a un nom vide, son rang est celui
    /// de la liste ; un autre élément, Binary par exemple, a son propre nom) ou, à défaut, de UserData (les
    /// feuilles sous son premier élément, nommées par leur chemin « a/b »).
    pub champs: Vec<(String, String)>,
    /// L'élément Event entier.
    pub evenement: Noeud,
}

/// Ce que la lecture a pu faire ou non : rien n'est jamais dit « tout lu » sans que ce soit vrai.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Bilan {
    /// Le CRC de l'en-tête du fichier est faux : ses champs (nombre de morceaux, drapeaux) ne sont pas crus ; les
    /// morceaux sont lus quand même, chacun vérifié par le sien.
    pub en_tete_abime: bool,
    /// Le fichier se dit « sale » (fermé pendant une écriture, ou copié ouvert).
    pub sale: bool,
    pub morceaux_lus: u64,
    /// Morceaux vides (place réservée jamais écrite, ou morceau préparé sans enregistrement) : rien de perdu.
    pub morceaux_vides: u64,
    /// Morceaux écartés : signature inconnue, morceau coupé en fin de fichier.
    pub morceaux_illisibles: u64,
    /// Morceaux à la signature juste mais au CRC faux (en-tête ou données) ou à la place libre impossible, relus
    /// quand même : ce qui s'y relit entier est rendu, marqué non vérifié (`Enregistrement::verifie`), le reste
    /// compté illisible.
    pub morceaux_non_verifies: u64,
    /// Événements rendus depuis un morceau non vérifié (compris dans `enregistrements_lus`).
    pub enregistrements_non_verifies: u64,
    /// Morceaux au-delà de `Bornes::taille_fichier` ou après `Bornes::enregistrements` : pas lus.
    pub morceaux_hors_borne: u64,
    pub enregistrements_lus: u64,
    /// Enregistrements sautés : signature, taille ou copie de la taille fausses, BinXml illisible.
    pub enregistrements_illisibles: u64,
    /// Enregistrements d'un morceau lu, laissés au-delà de `Bornes::enregistrements`.
    pub enregistrements_hors_borne: u64,
    /// Enregistrements entiers (signature, taille et copie justes) trouvés après la place libre d'un morceau lu, donc
    /// pas lus, comme Windows ne les lit pas : d'ordinaire d'anciennes versions d'enregistrements (`[libyal]`
    /// « Recovery » ; 1 051 dans les 28 échantillons publics de la crate evtx), mais aussi ce qu'une place libre
    /// reculée à la main cacherait. Dits, sans compter dans `complet` : ce n'est pas une perte de lecture.
    pub enregistrements_apres_place_libre: u64,
    /// Enregistrements qu'un morceau lu annonce (premier et dernier numéros de son en-tête) et qui n'y ont pas été
    /// trouvés, même illisibles : une place libre avancée à la main ferait sinon taire la fin du morceau.
    pub enregistrements_absents: u64,
    /// Valeurs de substitution d'un type inconnu ou d'une taille impossible, rendues « inconnu ».
    pub valeurs_inconnues: u64,
    /// Chaînes coupées à `Bornes::texte` caractères.
    pub chaines_tronquees: u64,
    /// Substitutions sans valeur dans leur instance, rendues vides.
    pub substitutions_manquantes: u64,
    /// Ce que chaque morceau lu, vide ou écarté annonce et a donné, dans l'ordre du fichier, au plus `MAX_RECAPS` :
    /// de quoi dire d'un trou dans la suite des numéros s'il tombe dans un morceau intact (des enregistrements
    /// retirés) ou dans ce que la lecture a perdu (journaux_windows::trous).
    pub morceaux: Vec<RecapMorceau>,
    /// Morceaux au-delà de `MAX_RECAPS`, sans récapitulatif.
    pub morceaux_sans_recap: u64,
    /// Le prochain numéro d'enregistrement qu'annonce l'en-tête du fichier (octet 24, `[libyal]` « Next record
    /// identifier »), quand cet en-tête est juste. Dans un fichier fermé proprement, c'est le plus grand numéro plus
    /// un (vu sur chaque échantillon public propre) : les derniers enregistrements ôtés s'y voient. Dans un fichier
    /// sale, il retarde.
    pub prochain_numero: Option<u64>,
    /// Le nombre de morceaux qu'annonce l'en-tête du fichier (octet 42), quand cet en-tête est juste. Dans un fichier
    /// fermé proprement, c'est le nombre de morceaux écrits : un bloc au-delà n'a rien pu porter.
    pub nombre_morceaux: Option<u16>,
    /// Les numéros (et le rang du morceau) des enregistrements entiers (signature, taille et copie justes) qui n'ont
    /// pas été rendus : BinXml illisible, ou au-delà de `Bornes::enregistrements`. Ils existent : leur numéro n'est
    /// pas un trou. Au plus `MAX_NON_RENDUS` ; les suivants comptent dans `RecapMorceau::non_rendus`.
    pub numeros_non_rendus: Vec<(u64, u64)>,
}

/// Les numéros d'enregistrements non rendus gardés au plus.
pub(crate) const MAX_NON_RENDUS: usize = 1 << 18;

/// Les récapitulatifs de morceaux gardés au plus : 4 Gio de morceaux, quatre fois la borne de taille par défaut ;
/// une borne choisie démesurée ne fait pas grossir le bilan sans fin.
pub(crate) const MAX_RECAPS: usize = 1 << 16;

/// Ce qu'est devenu un morceau.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EtatMorceau {
    /// Ses deux CRC justes : ses enregistrements lus.
    Lu,
    /// Tout à zéro : jamais écrit (ou remis à zéro).
    Vide,
    /// Préparé sans enregistrement (signature et en-tête justes, place libre au début) : ce que laisse un journal
    /// vidé par Windows (wevtutil cl, Clear-EventLog).
    Prepare,
    /// Écarté (signature inconnue), ou coupé en fin de fichier.
    Ecarte,
    /// Signature juste, CRC faux ou place libre impossible : relu, ses événements non vérifiés.
    NonVerifie,
}

/// Le plus d'enregistrements qu'un morceau peut porter : ce qui suit son en-tête, en enregistrements minimaux.
pub(crate) const CAPACITE_MORCEAU: u64 = (MORCEAU_U64 - EN_TETE_MORCEAU_U64) / ENREGISTREMENT_MIN_U64;

/// Un morceau tel que la lecture l'a vu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecapMorceau {
    /// Son rang dans le fichier (0 : le premier après l'en-tête).
    pub rang: u64,
    pub etat: EtatMorceau,
    /// Le premier et le dernier numéro d'enregistrement (identifiants, octets 24 et 32) qu'annonce son en-tête,
    /// quand cet en-tête est juste (signature, CRC) et se tient (dernier après le premier, pas plus qu'un morceau ne
    /// peut en contenir) ; rien sinon.
    pub annonce: Option<(u64, u64)>,
    /// Ce que ce morceau lu peut cacher sans numéro connu : les passages abîmés (signature, taille ou copie fausses),
    /// à un enregistrement par 28 octets sautés au plus, et les non-rendus au-delà de `MAX_NON_RENDUS`. Les
    /// enregistrements entiers non rendus ont leur numéro dans `Bilan::numeros_non_rendus`, pas ici.
    pub non_rendus: u64,
    /// Morceau lu dont l'en-tête ne se tient pas : rien d'annoncé, des numéros (octets 8 et 16) qui ne comptent pas
    /// autant d'enregistrements que les identifiants (24 et 32), ou un enregistrement hors de la plage annoncée.
    /// Windows ne l'écrit pas ainsi : un morceau réécrit.
    pub incoherent: bool,
    /// Le plus d'enregistrements qu'il pouvait porter (`CAPACITE_MORCEAU`, moins pour un morceau coupé en fin de
    /// fichier) : ce qu'un morceau écarté sans plage connue peut cacher.
    pub capacite: u64,
}

impl Bilan {
    // Pour les tests (le programme juge par `fichiers::BilanFichier`).
    /// Tout ce que le fichier contenait a été lu et rendu exactement (les morceaux vides ne contiennent rien). Les
    /// enregistrements laissés après la place libre (`enregistrements_apres_place_libre`) n'y comptent pas, comme
    /// Windows ne les lit pas : un appelant qui juge un journal doit les regarder à part (une place libre reculée à
    /// la main, CRC recalculés, laisse `complet` vrai et ne se voit que là).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn complet(&self) -> bool {
        !self.en_tete_abime
            && self.morceaux_illisibles == 0
            && self.morceaux_non_verifies == 0
            && self.morceaux_hors_borne == 0
            && self.enregistrements_illisibles == 0
            && self.enregistrements_hors_borne == 0
            && self.enregistrements_absents == 0
            && self.valeurs_inconnues == 0
            && self.chaines_tronquees == 0
            && self.substitutions_manquantes == 0
    }
}

// Pour les tests et le banc de fuzzing, comme `lire_fichier` et `lire_octets`.
/// Les événements d'un fichier et le bilan de sa lecture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct Lecture {
    pub enregistrements: Vec<Enregistrement>,
    pub bilan: Bilan,
}

/// Ce qui empêche de lire le fichier du tout.
#[derive(Debug)]
pub(crate) enum Erreur {
    /// Le fichier n'a pas pu être ouvert ou lu.
    Lecture(std::io::Error),
    /// Pas d'en-tête « ElfFile » : ce n'est pas un journal .evtx (ou il est coupé avant la fin de son en-tête).
    PasUnEvtx,
}

impl From<std::io::Error> for Erreur {
    fn from(e: std::io::Error) -> Self {
        Self::Lecture(e)
    }
}

/// Lit un fichier .evtx.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn lire_fichier(chemin: &Path, bornes: &Bornes) -> Result<Lecture, Erreur> {
    let fichier = std::fs::File::open(chemin)?;
    lire(std::io::BufReader::new(fichier), bornes)
}

/// Lit un journal .evtx déjà en mémoire.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn lire_octets(octets: &[u8], bornes: &Bornes) -> Result<Lecture, Erreur> {
    lire(std::io::Cursor::new(octets), bornes)
}

#[cfg_attr(not(test), allow(dead_code))]
fn lire<R: Read + Seek>(source: R, bornes: &Bornes) -> Result<Lecture, Erreur> {
    let mut enregistrements = Vec::new();
    let bilan = parcourir(source, bornes, |e| enregistrements.push(e))?;
    Ok(Lecture { enregistrements, bilan })
}

/// Lit un journal morceau par morceau (64 Kio en mémoire à la fois) et donne chaque événement à `recevoir`, dans
/// l'ordre du fichier, au plus `Bornes::enregistrements`.
pub(crate) fn parcourir<R: Read + Seek>(
    mut source: R,
    bornes: &Bornes,
    mut recevoir: impl FnMut(Enregistrement),
) -> Result<Bilan, Erreur> {
    let taille = source.seek(SeekFrom::End(0))?;
    source.seek(SeekFrom::Start(0))?;
    // Un tableau de taille fixe : les champs de l'en-tête se lisent à des places connues, sans index à vérifier.
    let mut en_tete = [0u8; EN_TETE];
    if lire_au_plus(&mut source, &mut en_tete)? < EN_TETE || !en_tete.starts_with(b"ElfFile\0") {
        return Err(Erreur::PasUnEvtx);
    }
    let mut bilan = Bilan {
        en_tete_abime: crc32(&[&en_tete[..120]]) != u32_a(&en_tete, 124).unwrap_or(0),
        ..Bilan::default()
    };
    bilan.sale = !bilan.en_tete_abime && u32_a(&en_tete, 120).is_some_and(|d| d & 1 != 0);
    if !bilan.en_tete_abime {
        bilan.prochain_numero = u64_a(&en_tete, 24);
        bilan.nombre_morceaux = Some(u16::from_le_bytes([en_tete[42], en_tete[43]]));
    }

    // Le nombre de morceaux de l'en-tête n'est pas cru (un fichier sale en annonce moins qu'il n'en a, [libyal]
    // « Dirty file with invalid number of chunks ») : c'est la taille du fichier qui compte, bornée.
    let blocs = taille.saturating_sub(EN_TETE_U64).div_ceil(MORCEAU_U64);
    let blocs_permis = bornes.taille_fichier.saturating_sub(EN_TETE_U64) / MORCEAU_U64;
    let blocs_lus = blocs.min(blocs_permis);
    bilan.morceaux_hors_borne = blocs.saturating_sub(blocs_lus);

    let mut morceau = vec![0u8; MORCEAU];
    let mut restant = bornes.enregistrements;
    for i in 0..blocs_lus {
        if restant == 0 {
            ajouter(&mut bilan.morceaux_hors_borne, blocs_lus.saturating_sub(i));
            break;
        }
        // `i` reste sous la borne de taille, mais une borne choisie démesurée ne doit pas faire déborder le calcul.
        let Some(debut) = i.checked_mul(MORCEAU_U64).and_then(|d| d.checked_add(EN_TETE_U64)) else {
            ajouter(&mut bilan.morceaux_hors_borne, blocs_lus.saturating_sub(i));
            break;
        };
        source.seek(SeekFrom::Start(debut))?;
        if lire_au_plus(&mut source, &mut morceau)? < MORCEAU {
            // Coupé en fin de fichier : son CRC ne peut pas être vérifié. Il ne peut cacher que ce que ses octets
            // portent (rien sous 540 octets).
            ajouter(&mut bilan.morceaux_illisibles, 1);
            let octets = taille.saturating_sub(debut).min(MORCEAU_U64);
            let capacite = octets.saturating_sub(EN_TETE_MORCEAU_U64) / ENREGISTREMENT_MIN_U64;
            recapituler(&mut bilan, i, EtatMorceau::Ecarte, None, 0, false, capacite);
            break;
        }
        lire_morceau(&morceau, i, bornes, &mut bilan, &mut restant, &mut recevoir);
    }
    Ok(bilan)
}

/// Remplit `tampon` autant que la source le permet ; rend le nombre d'octets lus.
fn lire_au_plus<R: Read>(source: &mut R, tampon: &mut [u8]) -> std::io::Result<usize> {
    let mut lu = 0;
    while let Some(reste) = tampon.get_mut(lu..).filter(|r| !r.is_empty()) {
        match source.read(reste) {
            Ok(0) => break,
            // Read::read rend au plus `reste.len()` octets ; un lecteur fautif qui en dirait plus arrête la boucle
            // (plus rien à remplir) sans faire déborder le compte.
            Ok(n) => lu = lu.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(lu)
}

/// Ce qu'un morceau donne à lire.
enum Etat {
    /// Les deux CRC justes : les enregistrements vont jusqu'à cette place libre.
    Lisible(usize),
    /// Jamais écrit (tout à zéro), ou préparé sans aucun enregistrement (place libre au début, en-tête juste) : rien
    /// de perdu ; la place libre, s'il y en a une, pour y chercher ce qui y resterait.
    Vide(Option<usize>),
    /// Signature juste, mais un CRC faux ou une place libre impossible : à relire sans rien croire. `en_tete_juste` :
    /// seul le CRC des enregistrements (ou la place libre) ne va pas, la plage de numéros qu'il annonce reste crue ;
    /// `libre` : la place libre, si elle se tient (sinon tout le morceau est relu).
    NonVerifie { en_tete_juste: bool, libre: Option<usize> },
    /// Écarté : pas la signature d'un morceau (et pas tout à zéro).
    Illisible,
}

/// Le morceau vérifié : signature, CRC de l'en-tête, place libre plausible, CRC des enregistrements.
fn verifier_morceau(morceau: &[u8]) -> Etat {
    // Vu comme un tableau de 64 Kio : l'en-tête se découpe à des places fixes, sans index à vérifier.
    let Ok(morceau) = <&[u8; MORCEAU]>::try_from(morceau) else {
        return Etat::Illisible;
    };
    if !morceau.starts_with(b"ElfChnk\0") {
        return if morceau.iter().all(|&b| b == 0) {
            Etat::Vide(None)
        } else {
            Etat::Illisible
        };
    }
    let libre = u32_a(morceau, 48)
        .and_then(|l| usize::try_from(l).ok())
        .filter(|l| (EN_TETE_MORCEAU..=MORCEAU).contains(l));
    let annonce = u32_a(morceau, 124);
    if annonce != Some(crc32(&[&morceau[..120], &morceau[128..EN_TETE_MORCEAU]])) {
        return Etat::NonVerifie {
            en_tete_juste: false,
            libre,
        };
    }
    let Some(libre) = libre else {
        return Etat::NonVerifie {
            en_tete_juste: true,
            libre: None,
        };
    };
    // Préparé sans aucun enregistrement : son CRC des enregistrements reste celui d'avant, mais il n'y a rien à lire.
    if libre == EN_TETE_MORCEAU {
        return Etat::Vide(Some(libre));
    }
    if u32_a(morceau, 52) != morceau.get(EN_TETE_MORCEAU..libre).map(|z| crc32(&[z])) {
        return Etat::NonVerifie {
            en_tete_juste: true,
            libre: Some(libre),
        };
    }
    Etat::Lisible(libre)
}

/// Les enregistrements entiers rangés après la place libre, comptés sans être lus. La recherche avance toujours :
/// d'un enregistrement entier à sa fin, sinon d'un octet.
fn apres_place_libre(morceau: &[u8], libre: usize) -> u64 {
    let mut n = 0;
    let mut pos = libre;
    while let Some(trouve) = chercher_signature(morceau, pos, MORCEAU) {
        match fin_enregistrement(morceau, trouve, MORCEAU) {
            Some(fin) => {
                ajouter(&mut n, 1);
                pos = fin;
            }
            None => pos = apres(trouve),
        }
    }
    n
}

/// Note ce qu'un morceau a donné, dans la limite de `MAX_RECAPS`.
fn recapituler(
    bilan: &mut Bilan,
    rang: u64,
    etat: EtatMorceau,
    annonce: Option<(u64, u64)>,
    non_rendus: u64,
    incoherent: bool,
    capacite: u64,
) {
    if bilan.morceaux.len() < MAX_RECAPS {
        bilan.morceaux.push(RecapMorceau {
            rang,
            etat,
            annonce,
            non_rendus,
            incoherent,
            capacite,
        });
    } else {
        ajouter(&mut bilan.morceaux_sans_recap, 1);
    }
}

/// Les enregistrements d'un morceau de 64 Kio, après vérification de ses deux CRC.
fn lire_morceau(
    morceau: &[u8],
    rang: u64,
    bornes: &Bornes,
    bilan: &mut Bilan,
    restant: &mut usize,
    recevoir: &mut impl FnMut(Enregistrement),
) {
    // `verifie` : les deux CRC justes. Sinon le morceau est relu enregistrement par enregistrement, avec les mêmes
    // bornes et le même budget de lecture, ses événements marqués non vérifiés ; sa plage annoncée n'est crue que
    // si son en-tête est juste.
    let (libre, verifie, en_tete_juste) = match verifier_morceau(morceau) {
        Etat::Lisible(libre) => (libre, true, true),
        // En-tête faux : sa place libre n'est pas crue, tout le morceau est relu (jusqu'aux zéros).
        Etat::NonVerifie { en_tete_juste, libre } => {
            let libre = if en_tete_juste {
                libre.unwrap_or(MORCEAU)
            } else {
                MORCEAU
            };
            (libre, false, en_tete_juste)
        }
        Etat::Vide(libre) => {
            ajouter(&mut bilan.morceaux_vides, 1);
            let apres = libre.map_or(0, |l| apres_place_libre(morceau, l));
            ajouter(&mut bilan.enregistrements_apres_place_libre, apres);
            let etat = if libre.is_some() {
                EtatMorceau::Prepare
            } else {
                EtatMorceau::Vide
            };
            recapituler(bilan, rang, etat, None, 0, false, 0);
            return;
        }
        Etat::Illisible => {
            ajouter(&mut bilan.morceaux_illisibles, 1);
            recapituler(bilan, rang, EtatMorceau::Ecarte, None, 0, false, CAPACITE_MORCEAU);
            return;
        }
    };
    let annonce = if en_tete_juste { plage_annoncee(morceau) } else { None };
    // Un numéro d'enregistrement hors de la plage annoncée (ou rien d'annoncé) : l'en-tête ne se tient pas.
    let mut hors_annonce = annonce.is_none();
    let mut voir_numero = |n: Option<u64>| {
        if let (Some(n), Some((p, d))) = (n, annonce)
            && !(p..=d).contains(&n)
        {
            hors_annonce = true;
        }
    };
    if verifie {
        ajouter(&mut bilan.morceaux_lus, 1);
        ajouter(
            &mut bilan.enregistrements_apres_place_libre,
            apres_place_libre(morceau, libre),
        );
    } else {
        ajouter(&mut bilan.morceaux_non_verifies, 1);
        // Ce qui suit la place libre d'un en-tête juste, au CRC des données faux : compté, comme pour un morceau lu.
        if libre < MORCEAU {
            ajouter(
                &mut bilan.enregistrements_apres_place_libre,
                apres_place_libre(morceau, libre),
            );
        }
    }
    let mut lecteur = binxml::Morceau::new(morceau, bornes);
    // Les enregistrements trouvés dans ce morceau : la somme des trois compteurs, avant et après.
    let vus = |b: &Bilan| {
        b.enregistrements_lus
            .saturating_add(b.enregistrements_illisibles)
            .saturating_add(b.enregistrements_hors_borne)
    };
    let avant = vus(bilan);
    // Ce que le morceau peut cacher sans numéro connu (voir `RecapMorceau::non_rendus`).
    let mut non_rendus = 0u64;
    let noter_non_rendu = |bilan: &mut Bilan, numero: Option<u64>, non_rendus: &mut u64| match numero {
        Some(n) if bilan.numeros_non_rendus.len() < MAX_NON_RENDUS => bilan.numeros_non_rendus.push((n, rang)),
        _ => ajouter(non_rendus, 1),
    };
    let mut pos = EN_TETE_MORCEAU;
    // `pos` ne dépasse jamais `libre` (au plus 64 Kio) : il ne va que d'une signature trouvée avant `libre` à une
    // autre, ou à la fin d'un enregistrement entier, qui tient avant `libre`.
    while pos.checked_add(ENREGISTREMENT_MIN).is_some_and(|f| f <= libre) {
        let Some(fin) = fin_enregistrement(morceau, pos, libre) else {
            // Le reste est à zéro : la fin des enregistrements, pas une perte.
            if morceau.get(pos..libre).is_some_and(|z| z.iter().all(|&b| b == 0)) {
                break;
            }
            // Signature, taille ou copie fausses : compté, puis la suite cherchée à la signature suivante
            // ([libyal] « Corrupt event record »), sans jamais revenir en arrière.
            // Le passage sauté ne peut avoir porté qu'un enregistrement par 28 octets : une fausse signature de
            // quelques octets ne couvre rien.
            ajouter(&mut bilan.enregistrements_illisibles, 1);
            let suivant = chercher_signature(morceau, apres(pos), libre);
            let saute = suivant.unwrap_or(libre).saturating_sub(pos);
            ajouter(
                &mut non_rendus,
                u64::try_from(saute).unwrap_or(u64::MAX) / ENREGISTREMENT_MIN_U64,
            );
            match suivant {
                Some(suivant) => {
                    pos = suivant;
                    continue;
                }
                None => break,
            }
        };
        // L'enregistrement entier : signature, taille (4), numéro (8), date (16), BinXml (24), copie de la taille.
        let entier = morceau.get(pos..fin).unwrap_or_default();
        let numero = u64_a(entier, 8);
        voir_numero(numero);
        if *restant == 0 {
            ajouter(&mut bilan.enregistrements_hors_borne, 1);
            noter_non_rendu(bilan, numero, &mut non_rendus);
            pos = fin;
            continue;
        }
        // Le BinXml va de l'octet 24 à la copie de la taille (enregistrement de 28 octets au moins).
        let binxml = pos.checked_add(24).zip(fin.checked_sub(4));
        if let Some((debut_binxml, fin_binxml)) = binxml
            && let Ok(evenement) = lecteur.rendre(debut_binxml, fin_binxml)
        {
            let numero = numero.unwrap_or(0);
            let date = u64_a(entier, 16).and_then(valeurs::filetime);
            let mut e = enregistrement(numero, date, evenement);
            e.morceau = rang;
            e.verifie = verifie;
            recevoir(e);
            ajouter(&mut bilan.enregistrements_lus, 1);
            ajouter(&mut bilan.enregistrements_non_verifies, u64::from(!verifie));
            *restant = restant.saturating_sub(1);
        } else {
            ajouter(&mut bilan.enregistrements_illisibles, 1);
            noter_non_rendu(bilan, numero, &mut non_rendus);
        }
        pos = fin;
    }
    let trouves = vus(bilan).saturating_sub(avant);
    if en_tete_juste {
        ajouter(
            &mut bilan.enregistrements_absents,
            annonces(morceau).saturating_sub(trouves),
        );
    }
    // Les numéros (8, 16) et les identifiants (24, 32) d'un même morceau comptent autant d'enregistrements.
    let compte = |a: usize, b: usize| u64_a(morceau, b)?.checked_sub(u64_a(morceau, a)?);
    // Un morceau non vérifié ne se juge pas à son en-tête : il n'est pas cru.
    let incoherent = verifie && (hors_annonce || compte(8, 16) != compte(24, 32));
    let etat = if verifie {
        EtatMorceau::Lu
    } else {
        EtatMorceau::NonVerifie
    };
    recapituler(bilan, rang, etat, annonce, non_rendus, incoherent, CAPACITE_MORCEAU);
    ajouter(&mut bilan.valeurs_inconnues, lecteur.compteurs.valeurs_inconnues);
    ajouter(&mut bilan.chaines_tronquees, lecteur.compteurs.chaines_tronquees);
    ajouter(
        &mut bilan.substitutions_manquantes,
        lecteur.compteurs.substitutions_manquantes,
    );
}

/// Ajoute à un compteur du bilan. Chacun compte au plus un par octet lu et ne peut pas approcher `u64::MAX` ; il
/// sature quand même, plutôt que de paniquer si une erreur de calcul l'y menait.
fn ajouter(compteur: &mut u64, n: u64) {
    *compteur = compteur.saturating_add(n);
}

/// La place qui suit `pos`, une place dans un morceau (64 Kio) : l'octet suivant.
fn apres(pos: usize) -> usize {
    pos.saturating_add(1)
}

/// Le nombre d'enregistrements que l'en-tête du morceau annonce : dernier numéro moins premier, plus un (`[libyal]`
/// « Normal behavior »). Rien si l'en-tête ne se tient pas (dernier avant le premier, ou plus qu'un morceau ne peut
/// en contenir) : il ne servirait qu'à inventer des pertes.
fn annonces(morceau: &[u8]) -> u64 {
    let (Some(premier), Some(dernier)) = (u64_a(morceau, 8), u64_a(morceau, 16)) else {
        return 0;
    };
    match dernier.checked_sub(premier) {
        Some(n) if n < ENREGISTREMENTS_PAR_MORCEAU => n.saturating_add(1),
        _ => 0,
    }
}

/// La plage d'identifiants d'enregistrements (premier, dernier) qu'annonce l'en-tête du morceau (octets 24 et 32,
/// `[libyal]` « First / Last event record identifier » : les numéros que portent les enregistrements eux-mêmes ;
/// ceux des octets 8 et 16 repartent de 1 après un effacement). Rien si elle ne se tient pas, comme `annonces`.
fn plage_annoncee(morceau: &[u8]) -> Option<(u64, u64)> {
    let (premier, dernier) = (u64_a(morceau, 24)?, u64_a(morceau, 32)?);
    let n = dernier.checked_sub(premier)?;
    (n < ENREGISTREMENTS_PAR_MORCEAU).then_some((premier, dernier))
}

/// La fin (place qui suit son dernier octet) de l'enregistrement qui commence à `pos`, s'il est entier : signature,
/// taille plausible qui tient avant la place libre, copie de la taille à sa fin.
fn fin_enregistrement(morceau: &[u8], pos: usize, libre: usize) -> Option<usize> {
    let apres_signature = pos.checked_add(4)?;
    if morceau.get(pos..apres_signature)? != b"**\0\0" {
        return None;
    }
    let annoncee = u32_a(morceau, apres_signature)?;
    let taille = usize::try_from(annoncee).ok()?;
    let fin = pos.checked_add(taille)?;
    if taille < ENREGISTREMENT_MIN || fin > libre {
        return None;
    }
    (u32_a(morceau, fin.checked_sub(4)?)? == annoncee).then_some(fin)
}

fn chercher_signature(morceau: &[u8], depuis: usize, libre: usize) -> Option<usize> {
    let zone = morceau.get(depuis..libre)?;
    zone.windows(4)
        .position(|f| f == b"**\0\0")
        .and_then(|i| depuis.checked_add(i))
}

/// Les champs utiles tirés de l'arbre rendu. Sert aussi à l'arbre lu dans le XML que rend Windows (source vivante,
/// journaux_windows::xml) : les deux sources tirent leurs champs de la même façon.
pub(crate) fn enregistrement(numero: u64, date: Option<DateTime<Utc>>, evenement: Noeud) -> Enregistrement {
    let systeme = evenement.enfant("System");
    let texte = |nom: &str| systeme.and_then(|s| s.enfant(nom)).map(|e| e.texte.trim().to_string());
    let fournisseur = systeme.and_then(|s| s.enfant("Provider")).map(|p| {
        p.attribut("Name")
            .filter(|n| !n.is_empty())
            .or_else(|| p.attribut("EventSourceName"))
            .unwrap_or_default()
            .to_string()
    });
    let cree = systeme
        .and_then(|s| s.enfant("TimeCreated"))
        .and_then(|t| t.attribut("SystemTime"))
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|d| d.with_timezone(&Utc));
    Enregistrement {
        numero,
        morceau: 0,
        verifie: true,
        date,
        fournisseur: fournisseur.unwrap_or_default(),
        id: texte("EventID").and_then(|t| t.parse().ok()),
        niveau: texte("Level").and_then(|t| t.parse().ok()),
        cree,
        numero_systeme: texte("EventRecordID").and_then(|t| t.parse().ok()),
        canal: texte("Channel").unwrap_or_default(),
        ordinateur: texte("Computer").unwrap_or_default(),
        champs: champs(&evenement),
        evenement,
    }
}

fn champs(evenement: &Noeud) -> Vec<(String, String)> {
    let mut sortie = Vec::new();
    if let Some(donnees) = evenement.enfant("EventData") {
        for d in &donnees.enfants {
            let nom = if &*d.nom == "Data" {
                d.attribut("Name").unwrap_or_default().to_string()
            } else {
                d.nom.to_string()
            };
            sortie.push((nom, d.texte.clone()));
        }
    } else if let Some(racine) = evenement.enfant("UserData").and_then(|u| u.enfants.first()) {
        let mut chemin = Vec::new();
        feuilles(racine, &mut chemin, &mut sortie);
    }
    sortie
}

/// Les feuilles d'un arbre UserData, nommées par leur chemin depuis son premier élément. La profondeur est celle de
/// l'arbre rendu, déjà bornée.
fn feuilles<'n>(noeud: &'n Noeud, chemin: &mut Vec<&'n str>, sortie: &mut Vec<(String, String)>) {
    for e in &noeud.enfants {
        chemin.push(&e.nom);
        if e.enfants.is_empty() {
            sortie.push((chemin.join("/"), e.texte.clone()));
        } else {
            feuilles(e, chemin, sortie);
        }
        chemin.pop();
    }
}

/// Le BinXml d'un enregistrement rangé dans `morceau` à partir de `debut`, rendu seul : pour le banc de fuzzing,
/// qui veut atteindre le BinXml sans passer par les CRC.
#[cfg_attr(not(fuzzing), allow(dead_code))]
pub(crate) fn rendre_binxml(morceau: &[u8], debut: usize, bornes: &Bornes) -> Result<Noeud, ErreurBinxml> {
    binxml::Morceau::new(morceau, bornes).rendre(debut, morceau.len())
}

fn u32_a(octets: &[u8], pos: usize) -> Option<u32> {
    let b = octets.get(pos..pos.checked_add(4)?)?;
    Some(u32::from_le_bytes(b.try_into().ok()?))
}

fn u64_a(octets: &[u8], pos: usize) -> Option<u64> {
    let b = octets.get(pos..pos.checked_add(8)?)?;
    Some(u64::from_le_bytes(b.try_into().ok()?))
}

/// La table du CRC32 de RFC 1952 (polynôme 0xEDB88320, bits retournés), calculée à la compilation.
const TABLE_CRC: [u32; 256] = {
    let mut table = [0u32; 256];
    // `i` range l'entrée, `c` est sa valeur en u32 : deux compteurs qui avancent ensemble, sans conversion.
    let mut i = 0usize;
    let mut c = 0u32;
    while i < 256 {
        let mut v = c;
        let mut k = 0;
        while k < 8 {
            v = if v & 1 != 0 { 0xEDB8_8320 ^ (v >> 1) } else { v >> 1 };
            k += 1;
        }
        #[expect(
            clippy::indexing_slicing,
            reason = "i < 256 par la boucle, table de 256 ; calculé à la compilation"
        )]
        {
            table[i] = v;
        }
        i += 1;
        c += 1;
    }
    table
};

/// Le CRC32 de RFC 1952 de plusieurs zones mises bout à bout (l'en-tête d'un morceau saute ses octets 120 à 128).
pub(crate) fn crc32(zones: &[&[u8]]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for zone in zones {
        for &b in *zone {
            #[expect(clippy::indexing_slicing, reason = "un octet indexe une table de 256 entrées")]
            let entree = TABLE_CRC[usize::from(c.to_le_bytes()[0] ^ b)];
            c = entree ^ (c >> 8);
        }
    }
    c ^ 0xFFFF_FFFF
}

/// Recalcule les CRC d'un fichier (en-tête, puis chaque morceau entier qui porte sa signature) : les tests et le
/// banc de fuzzing fabriquent ou abîment un fichier, puis le rendent cohérent pour atteindre ce qui suit les CRC.
#[cfg(any(test, fuzzing))]
pub(crate) fn recalculer_crc(fichier: &mut [u8]) {
    // En tableaux de taille fixe : les champs se découpent à des places connues, sans index à vérifier.
    let Some((en_tete, suite)) = fichier.split_first_chunk_mut::<EN_TETE>() else {
        return;
    };
    let crc = crc32(&[&en_tete[..120]]);
    en_tete[124..128].copy_from_slice(&crc.to_le_bytes());
    for morceau in suite.as_chunks_mut::<MORCEAU>().0 {
        if morceau.starts_with(b"ElfChnk\0") {
            let libre = u32_a(morceau, 48)
                .and_then(|l| usize::try_from(l).ok())
                .filter(|l| (EN_TETE_MORCEAU..=MORCEAU).contains(l));
            if let Some(crc) = libre.and_then(|l| morceau.get(EN_TETE_MORCEAU..l)).map(|z| crc32(&[z])) {
                morceau[52..56].copy_from_slice(&crc.to_le_bytes());
            }
            let crc = crc32(&[&morceau[..120], &morceau[128..EN_TETE_MORCEAU]]);
            morceau[124..128].copy_from_slice(&crc.to_le_bytes());
        }
    }
}
