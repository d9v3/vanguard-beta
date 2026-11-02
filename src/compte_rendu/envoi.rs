//! Le lot de schéma 2 (plan de l'auto-amélioration, §3) : ce qu'un ordinateur enverra une fois par jour au relais,
//! en mémoire et en JSON. Ce module n'envoie rien et n'ouvre aucune connexion : il construit, borne, tronque, écrit
//! et relit. L'envoi (A4) et le relais (A7) viennent après.
//!
//! Pourquoi si fermé : le lot part d'un ordinateur qu'on ne connaît pas vers un relais public, puis vers la veille de
//! nuit (une IA) et vers l'auteur. Un champ libre serait une porte pour un secret, un nom, ou une consigne écrite pour
//! piloter l'IA. Donc :
//! - aucun `String` nu : chaque texte est un type validé à la construction comme à la lecture, soit par un motif ou
//!   une liste fermée (voie fermée, que l'IA de nuit peut lire), soit par le nettoyage de `amelioration::texte`
//!   (voie ouverte : `TexteNettoye`, `NomLogiciel`, `VersionTierce`, lus seulement par l'auteur ou une session qu'il
//!   lance, toujours présentés comme des données, jamais rendus en Markdown) ;
//! - tout champ inconnu, tout nombre hors bornes, tout tableau trop long ou en double refuse le lot entier ;
//! - les champs à zéro, les listes vides et les facultatifs absents ne sont pas écrits, et un zéro ou un `null` écrit
//!   est refusé : un lot n'a qu'une seule écriture, `lire(ecrire(lot)) == lot`.
//!
//! Exclu par construction (aucun type ici ne peut le porter) : contenu de fichier, arguments de commande (seul le
//! nom d'un outil voyage), navigateur, texte tapé, fichiers, comptes, réseaux, appareils, l'inventaire des logiciels.
//!
//! `outils/veille/schema-envoi.json` décrit le même lot pour le relais et les outils de nuit ; un essai prouve que
//! les deux disent la même chose (noms, types, motifs, bornes).
//!
//! Module pur : le banc de fuzz l'inclut par son chemin (cible `envoi_lot`), avec `champs` et `amelioration::texte`.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;
use std::marker::PhantomData;

use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::amelioration::texte::{Gabarit, NomLogiciel, TexteNettoye, VersionTierce};
use crate::compte_rendu::champs::{Code, Contexte, Genre, Jour, Lieu, Regle, Version};

/// La version du format, seule valeur permise du champ `schema`.
pub(crate) const SCHEMA: u8 = 2;
/// Un lot écrit fait au plus 96 Kio (plan, P4) : `tronquer` l'y ramène, `lire` refuse au-delà.
pub(crate) const LOT_MAX: usize = 98_304;
/// Le relais refuse un corps de requête plus gros (plan, §3, point 2) : la marge couvre l'enveloppe d'A4.
pub(crate) const CORPS_MAX: usize = 131_072;

/// Un nombre d'événements par jour (passages, refus, oublis…) : au-delà, ce n'est plus une mesure mais un lot forgé.
pub(crate) const N_MAX: u32 = 1_000_000;
/// Une cause du journal compte au plus mille occurrences par jour (plan de l'envoi, §3).
pub(crate) const CAUSE_N_MAX: u32 = 1000;
/// Une durée en millisecondes : une journée au plus.
pub(crate) const MS_MAX: u32 = 86_400_000;
/// Un délai de règle en secondes : une journée au plus.
pub(crate) const DELAI_MAX: u32 = 86_400;
/// Une somme sur la journée (âges cumulés du cache en secondes, temps gagné en millisecondes) : sous 2³² et sous les
/// 2⁵³ que JavaScript lit sans perte.
pub(crate) const TOTAL_MAX: u32 = 4_000_000_000;
/// Une valeur d'auto-réglage avant ou après (secondes, minutes ou nombre de fils selon le levier).
pub(crate) const VALEUR_MAX: u32 = 1_000_000;
/// Le matériel : cœurs, fils et mémoire (en Go, puissance de 2).
pub(crate) const COEURS_MAX: u32 = 1024;
pub(crate) const FILS_MAX: u32 = 4096;
pub(crate) const MEMOIRE_MAX: u32 = 4096;

/// Les bornes des tableaux (plan, §3).
pub(crate) const CAUSES_MAX: usize = 50;
pub(crate) const REGLES_MAX: usize = 400;
pub(crate) const RAISONS_MAX: usize = 4;
pub(crate) const OBJETS_MAX: usize = 100;
pub(crate) const TEXTES_MAX: usize = 30;
pub(crate) const CORRECTIONS_MAX: usize = 100;
pub(crate) const CHOIX_MAX: usize = 100;
pub(crate) const OUTILS_MAX: usize = 80;
pub(crate) const CACHE_MAX: usize = 200;
pub(crate) const REGLAGES_MAX: usize = 50;

// --- Briques : nombres bornés, listes bornées, textes à motif, listes fermées ------------------------------------

/// Un compte facultatif de 1 à `MAX` : zéro en mémoire veut dire « rien », jamais écrit (`skip_serializing_if`), et
/// refusé s'il est écrit quand même. La construction plafonne au lieu d'échouer : un compte qui déborde reste vrai.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Compte<const MAX: u32>(u32);

// Construit par A2 ; ici, par les essais et le banc.
#[allow(dead_code)]
impl<const MAX: u32> Compte<MAX> {
    pub(crate) fn new(n: u64) -> Compte<MAX> {
        Compte(u32::try_from(n.min(u64::from(MAX))).unwrap_or(MAX))
    }

    pub(crate) fn get(self) -> u32 {
        self.0
    }

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "skip_serializing_if de serde passe une référence"
    )]
    pub(crate) fn est_nul(&self) -> bool {
        self.0 == 0
    }

    /// Ajoute `n`, plafonné à `MAX`.
    pub(crate) fn ajouter(&mut self, n: u64) {
        *self = Compte::new(u64::from(self.0).saturating_add(n));
    }
}

impl<const MAX: u32> Serialize for Compte<MAX> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.0)
    }
}

impl<'de, const MAX: u32> Deserialize<'de> for Compte<MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Compte<MAX>, D::Error> {
        borne(d, MAX).map(Compte)
    }
}

/// Un nombre obligatoire de 1 à `MAX` (le `n` d'une entrée, un délai) : jamais nul, en mémoire comme écrit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Nombre<const MAX: u32>(u32);

#[allow(dead_code)]
impl<const MAX: u32> Nombre<MAX> {
    /// Rien pour zéro (une entrée sans occurrence n'existe pas) ; plafonné à `MAX` au-delà.
    pub(crate) fn new(n: u64) -> Option<Nombre<MAX>> {
        (n > 0).then(|| Nombre(u32::try_from(n.min(u64::from(MAX))).unwrap_or(MAX)))
    }

    pub(crate) fn get(self) -> u32 {
        self.0
    }
}

impl<const MAX: u32> Serialize for Nombre<MAX> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.0)
    }
}

impl<'de, const MAX: u32> Deserialize<'de> for Nombre<MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Nombre<MAX>, D::Error> {
        borne(d, MAX).map(Nombre)
    }
}

/// Un entier JSON de 1 à `max`. `u32` refuse déjà un nombre écrit avec une virgule (`1.0`), un négatif et ce qui
/// dépasse 2³² : seul l'entier sans décimale passe.
fn borne<'de, D: Deserializer<'de>>(d: D, max: u32) -> Result<u32, D::Error> {
    let n = u32::deserialize(d)?;
    if (1..=max).contains(&n) {
        Ok(n)
    } else {
        Err(D::Error::custom("nombre hors bornes"))
    }
}

/// Une entrée de tableau : sa clé (deux entrées de même clé dans un tableau refusent le lot ; l'agrégation se fait
/// avant, chez A2) et son intérêt (le moins intéressant part le premier quand le lot est trop gros).
pub(crate) trait Entree {
    type Clef: Ord;
    fn clef(&self) -> Self::Clef;
    fn interet(&self) -> u64;
}

/// Un tableau de 1 à `MAX` entrées de clés distinctes. Vide en mémoire, il n'est pas écrit ; écrit vide (`[]`), trop
/// long ou avec un doublon, il est refusé dès la lecture, sans tout allouer d'abord.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Liste<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> Default for Liste<T, MAX> {
    fn default() -> Liste<T, MAX> {
        Liste(Vec::new())
    }
}

#[allow(dead_code)]
impl<T: Entree, const MAX: usize> Liste<T, MAX> {
    /// Ajoute une entrée ; la rend si la liste est pleine ou si sa clé y est déjà.
    pub(crate) fn pousser(&mut self, t: T) -> Result<(), T> {
        let clef = t.clef();
        if self.0.len() >= MAX || self.0.iter().any(|x| x.clef() == clef) {
            return Err(t);
        }
        self.0.push(t);
        Ok(())
    }

    pub(crate) fn entrees(&self) -> &[T] {
        &self.0
    }

    pub(crate) fn est_vide(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T: Serialize, const MAX: usize> Serialize for Liste<T, MAX> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de, T: Deserialize<'de> + Entree, const MAX: usize> Deserialize<'de> for Liste<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Liste<T, MAX>, D::Error> {
        d.deserialize_seq(Visiteur::<T, MAX>(PhantomData))
    }
}

struct Visiteur<T, const MAX: usize>(PhantomData<T>);

impl<'de, T: Deserialize<'de> + Entree, const MAX: usize> Visitor<'de> for Visiteur<T, MAX> {
    type Value = Liste<T, MAX>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "un tableau de 1 à {MAX} entrées distinctes")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Liste<T, MAX>, A::Error> {
        let mut v = Vec::new();
        let mut clefs = BTreeSet::new();
        while let Some(t) = a.next_element::<T>()? {
            if v.len() >= MAX {
                return Err(A::Error::custom("tableau trop long"));
            }
            if !clefs.insert(t.clef()) {
                return Err(A::Error::custom("entrée en double"));
            }
            v.push(t);
        }
        if v.is_empty() {
            return Err(A::Error::custom("tableau vide écrit"));
        }
        Ok(Liste(v))
    }
}

/// Un facultatif écrit est lu comme sa valeur : `null` est refusé (un absent ne s'écrit pas).
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// Un texte de la voie fermée validé par son motif (même porte à la construction et à la lecture).
macro_rules! motif {
    ($(#[$m:meta])* $nom:ident, $valide:path) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub(crate) struct $nom(String);

        #[allow(dead_code)]
        impl $nom {
            pub(crate) fn new(s: &str) -> Option<$nom> {
                $valide(s).then(|| $nom(s.to_owned()))
            }

            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $nom {
            type Error = &'static str;

            fn try_from(s: String) -> Result<$nom, &'static str> {
                if $valide(&s) { Ok($nom(s)) } else { Err(concat!(stringify!($nom), " hors motif")) }
            }
        }

        impl From<$nom> for String {
            fn from(c: $nom) -> String {
                c.0
            }
        }
    };
}

/// Une liste fermée : seul l'identifiant ASCII est écrit et relu.
macro_rules! fermee {
    ($(#[$m:meta])* $nom:ident { $($v:ident = $id:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub(crate) enum $nom {
            $(#[serde(rename = $id)] $v),+
        }

        #[allow(dead_code)]
        impl $nom {
            pub(crate) const TOUS: &[$nom] = &[$($nom::$v),+];

            pub(crate) fn id(self) -> &'static str {
                match self {
                    $($nom::$v => $id),+
                }
            }
        }
    };
}

/// L'identifiant d'installation (plan, P1) : 16 chiffres hexadécimaux minuscules, tirés au hasard (A4) et
/// renouvelés tous les 90 jours. Il ne dit rien de la machine.
fn est_id_installation(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|o| o.is_ascii_digit() || (b'a'..=b'f').contains(&o))
}

/// La version du système, réduite (plan de l'envoi, §3) : build de Windows, majeure de macOS, majeur.mineur du noyau
/// Linux. Jamais la chaîne entière (« 6.17.2-1-maison » trahirait un noyau compilé à la main).
fn est_systeme_version(s: &str) -> bool {
    let (majeur, mineur) = s.split_once('.').map_or((s, None), |(a, b)| (a, Some(b)));
    chiffres(majeur, 6) && mineur.is_none_or(|m| chiffres(m, 3))
}

/// Le nom d'un outil de Vanguard ou d'une sous-commande (`Outil.commande`, nom clap) : jamais ses arguments.
/// Minuscules, chiffres et traits d'union, 32 caractères au plus ; la liste fermée elle-même est vérifiée chez
/// l'auteur (A8), le relais ne la connaît pas.
fn est_outil(s: &str) -> bool {
    let o = s.as_bytes();
    let (Some(premier), Some(dernier)) = (o.first(), o.last()) else {
        return false;
    };
    o.len() <= 32
        && premier.is_ascii_lowercase()
        && (dernier.is_ascii_lowercase() || dernier.is_ascii_digit())
        && o.iter()
            .all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || *x == b'-')
}

/// De 1 à `max` chiffres ASCII.
fn chiffres(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|o| o.is_ascii_digit())
}

motif!(
    /// L'identifiant d'installation (`est_id_installation`).
    IdInstallation,
    est_id_installation
);
motif!(
    /// La version réduite du système (`est_systeme_version`).
    SystemeVersion,
    est_systeme_version
);
motif!(
    /// Le nom d'un outil ou d'une sous-commande (`est_outil`).
    NomOutil,
    est_outil
);

impl IdInstallation {
    /// L'identifiant de 8 octets tirés au hasard (le tirage est à A4, qui a l'aléa du système).
    #[allow(dead_code)]
    pub(crate) fn de_octets(octets: [u8; 8]) -> IdInstallation {
        IdInstallation(octets.iter().fold(String::with_capacity(16), |mut s, o| {
            let _ = write!(s, "{o:02x}");
            s
        }))
    }
}

/// `schema`, toujours 2 : un lot d'un autre format est refusé, pas deviné.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Schema;

impl Serialize for Schema {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(SCHEMA)
    }
}

impl<'de> Deserialize<'de> for Schema {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Schema, D::Error> {
        if u8::deserialize(d)? == SCHEMA {
            Ok(Schema)
        } else {
            Err(D::Error::custom("schéma inconnu"))
        }
    }
}

/// La mémoire en Go, arrondie à une puissance de 2 (plan, §1) : 12 Go et 16 Go se confondent, c'est voulu.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MemoireGo(u32);

impl MemoireGo {
    /// La puissance de 2 la plus proche par en dessous, de 1 à `MEMOIRE_MAX`.
    #[allow(dead_code)]
    pub(crate) fn arrondie(go: u64) -> MemoireGo {
        let go = u32::try_from(go.clamp(1, u64::from(MEMOIRE_MAX))).unwrap_or(MEMOIRE_MAX);
        MemoireGo(1u32.checked_shl(go.ilog2()).unwrap_or(MEMOIRE_MAX))
    }

    /// Les valeurs permises, de 1 à `MEMOIRE_MAX`.
    pub(crate) fn permises() -> impl Iterator<Item = u32> {
        (0..u32::BITS)
            .filter_map(|p| 1u32.checked_shl(p))
            .take_while(|v| *v <= MEMOIRE_MAX)
    }
}

impl Serialize for MemoireGo {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for MemoireGo {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<MemoireGo, D::Error> {
        let n = u32::deserialize(d)?;
        if MemoireGo::permises().any(|v| v == n) {
            Ok(MemoireGo(n))
        } else {
            Err(D::Error::custom("mémoire hors liste"))
        }
    }
}

fermee!(
    /// Depuis combien de temps Vanguard est installé : quatre classes, jamais la date.
    Anciennete {
        Moins7 = "moins-7-jours",
        Moins30 = "moins-30-jours",
        Moins90 = "moins-90-jours",
        Plus90 = "90-jours-et-plus",
    }
);

impl Anciennete {
    #[allow(dead_code)]
    pub(crate) fn de_jours(jours: u64) -> Anciennete {
        match jours {
            0..7 => Anciennete::Moins7,
            7..30 => Anciennete::Moins30,
            30..90 => Anciennete::Moins90,
            _ => Anciennete::Plus90,
        }
    }
}

fermee!(
    /// La famille fine du système (plan de l'envoi, §3) : jamais le nom écrit dans os-release.
    FamilleFine {
        Windows10 = "windows-10",
        Windows11 = "windows-11",
        Macos = "macos",
        Arch = "arch",
        Debian = "debian",
        Ubuntu = "ubuntu",
        Fedora = "fedora",
        Opensuse = "opensuse",
        Mint = "mint",
        LinuxAutre = "linux-autre",
    }
);

fermee!(
    Arch {
        X86_64 = "x86_64",
        Aarch64 = "aarch64",
    }
);

fermee!(
    Langue {
        Fr = "fr",
        En = "en",
    }
);

fermee!(
    /// L'édition du système, quand elle a un sens (Windows surtout).
    Edition {
        Home = "home",
        Pro = "pro",
        Entreprise = "entreprise",
        Serveur = "serveur",
    }
);

fermee!(
    /// Le fabricant du processeur.
    Processeur {
        Intel = "intel",
        Amd = "amd",
        Apple = "apple",
        Qualcomm = "qualcomm",
        Autre = "autre",
    }
);

fermee!(
    /// Le disque du système.
    Disque {
        Nvme = "nvme",
        Ssd = "ssd",
        Hdd = "hdd",
        Inconnu = "inconnu",
    }
);

fermee!(
    /// La machine virtuelle sous laquelle Vanguard tourne, s'il y en a une.
    Virtuelle {
        Aucune = "aucune",
        Hyperv = "hyperv",
        Kvm = "kvm",
        Vmware = "vmware",
        Virtualbox = "virtualbox",
        Parallels = "parallels",
        Wsl = "wsl",
        Autre = "autre",
    }
);

fermee!(
    /// Un état matériel lu ou non (TPM, démarrage sécurisé) : ce qui n'a pas pu être lu le dit.
    TroisEtats {
        Oui = "oui",
        Non = "non",
        Inconnu = "inconnu",
    }
);

fermee!(
    /// Le fabricant de la carte graphique.
    Graphique {
        Nvidia = "nvidia",
        Amd = "amd",
        Intel = "intel",
        Apple = "apple",
        Qualcomm = "qualcomm",
        Autre = "autre",
        Aucune = "aucune",
    }
);

fermee!(
    /// La sorte d'un objet en cause (plan, §1). Ni fichier, ni compte, ni réseau, ni appareil, ni site : ces sortes
    /// n'existent pas ici (un essai le vérifie contre les sources exclues).
    Sorte {
        Programme = "programme",
        Service = "service",
        Pilote = "pilote",
        Paquet = "paquet",
        Unite = "unite",
        Flatpak = "flatpak",
        Module = "module",
    }
);

fermee!(
    /// L'état d'un objet au bilan.
    Etat {
        Probleme = "probleme",
        Sain = "sain",
        NonVerifie = "non-verifie",
    }
);

fermee!(
    /// D'où un outil a été lancé : le menu, ou la ligne de commande (nom de la sous-commande seulement).
    Origine {
        Menu = "menu",
        Ligne = "ligne",
    }
);

fermee!(
    /// Ce que l'auto-réglage a changé (L6).
    Levier {
        Delai = "delai",
        DureeCache = "duree-cache",
        CacheCoupe = "cache-coupe",
        SecondEssai = "second-essai",
        ReserveFils = "reserve-fils",
        CorrectionFragile = "correction-fragile",
    }
);

// --- Le lot ------------------------------------------------------------------------------------------------------

/// Le lot d'une journée. Les champs sont ceux de `outils/veille/schema-envoi.json`, ni plus ni moins (essai).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lot {
    pub(crate) schema: Schema,
    pub(crate) version: Version,
    /// La version d'avant, dans les 7 jours d'une mise à jour.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) version_avant: Option<Version>,
    pub(crate) jour: Jour,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) installation: Option<IdInstallation>,
    pub(crate) anciennete: Anciennete,
    pub(crate) plateforme: Plateforme,
    /// Une fois par semaine.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) materiel: Option<Materiel>,
    pub(crate) activite: Activite,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) causes: Liste<CauseEnvoyee, CAUSES_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) regles: Liste<RegleEnvoyee, REGLES_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) objets: Liste<ObjetEnvoye, OBJETS_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) textes: Liste<TexteEnvoye, TEXTES_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) corrections: Liste<Correction, CORRECTIONS_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) choix: Liste<Choix, CHOIX_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) outils: Liste<OutilEnvoye, OUTILS_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) cache: Liste<CacheRegle, CACHE_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) reglages: Liste<Reglage, REGLAGES_MAX>,
    /// Les textes, noms et versions jetés par le nettoyage (`texte::refus_locaux`) : le seul signe d'un refus.
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) refus_locaux: Compte<N_MAX>,
    /// Ce que `tronquer` a retiré pour tenir dans 96 Kio, par tableau.
    #[serde(
        default,
        skip_serializing_if = "Retires::est_vide",
        deserialize_with = "retires_ecrits"
    )]
    pub(crate) retires: Retires,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plateforme {
    pub(crate) famille: FamilleFine,
    pub(crate) systeme_version: SystemeVersion,
    pub(crate) arch: Arch,
    pub(crate) langue: Langue,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) edition: Option<Edition>,
    pub(crate) administrateur: bool,
}

/// Le matériel (plan, §1). Jamais de numéro de série ; seuls les deux modèles sont en voie ouverte.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Materiel {
    pub(crate) processeur: Processeur,
    pub(crate) coeurs: Nombre<COEURS_MAX>,
    pub(crate) fils: Nombre<FILS_MAX>,
    pub(crate) memoire_go: MemoireGo,
    pub(crate) disque: Disque,
    pub(crate) virtuelle: Virtuelle,
    pub(crate) portable: bool,
    pub(crate) tpm: TroisEtats,
    pub(crate) demarrage_securise: TroisEtats,
    pub(crate) graphique: Graphique,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) modele_processeur: Option<NomLogiciel>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) modele_graphique: Option<NomLogiciel>,
}

/// Comment Vanguard a tourné ce jour-là.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Activite {
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) bilans_manuels: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) passes_horaires: Compte<N_MAX>,
    pub(crate) surveillance: bool,
    pub(crate) veilleur: bool,
    pub(crate) cle: bool,
}

/// Une cause du journal (L2/L3) : jamais le détail, seulement ses champs fermés et le gabarit de son texte.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CauseEnvoyee {
    pub(crate) genre: Genre,
    pub(crate) contexte: Contexte,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) regle: Option<Regle>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) lieu: Option<Lieu>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) code: Option<Code>,
    pub(crate) n: Nombre<CAUSE_N_MAX>,
    /// Arrondie à deux chiffres significatifs (`arrondir_ms`).
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) duree_ms: Compte<MS_MAX>,
    /// Les trois nombres d'un écart de l'autotest.
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) en_plus: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) en_moins: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) differents: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) gabarit: Option<Gabarit>,
}

/// Une durée arrondie à deux chiffres significatifs, par en dessous (1 234 ms → 1 200) : assez pour voir une
/// lenteur, trop peu pour reconnaître une machine à sa durée exacte.
#[allow(dead_code)]
pub(crate) fn arrondir_ms(ms: u64) -> u64 {
    let mut pas = 1u64;
    while ms.checked_div(pas).is_some_and(|q| q >= 100) {
        pas = pas.saturating_mul(10);
    }
    ms.checked_div(pas).map_or(ms, |q| q.saturating_mul(pas))
}

/// Les durées et résultats d'une règle (mesures de l'autotest et bilans).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegleEnvoyee {
    pub(crate) id: Regle,
    pub(crate) n: Nombre<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) med_ms: Compte<MS_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) p90_ms: Compte<MS_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) hors_delai: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) problemes: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) sains: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) non_verifies: Compte<N_MAX>,
    /// Pourquoi elle n'a pas conclu : le code de `Raison`, et combien de fois.
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) raisons: Liste<RaisonNombre, RAISONS_MAX>,
    pub(crate) delai_s: Nombre<DELAI_MAX>,
}

impl RegleEnvoyee {
    /// Ce qui mérite d'être gardé quand le lot est trop gros : un dépassement, une règle qui n'a pas conclu, ou qui
    /// frôle son délai (90e centile à la moitié ou plus).
    pub(crate) fn notable(&self) -> bool {
        let frole =
            u64::from(self.p90_ms.get()).saturating_mul(2) >= u64::from(self.delai_s.get()).saturating_mul(1000);
        !self.hors_delai.est_nul() || !self.non_verifies.est_nul() || !self.raisons.est_vide() || frole
    }
}

/// Un code et son nombre (raisons d'une règle qui n'a pas conclu, codes d'une correction échouée).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RaisonNombre {
    pub(crate) code: Code,
    pub(crate) n: Nombre<N_MAX>,
}

/// Un objet en cause dans une règle : sorte fermée, nom et version en voie ouverte.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObjetEnvoye {
    pub(crate) regle: Regle,
    pub(crate) sorte: Sorte,
    pub(crate) nom: NomLogiciel,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) version: Option<VersionTierce>,
    pub(crate) etat: Etat,
    pub(crate) n: Nombre<N_MAX>,
}

/// Un texte d'erreur nettoyé (voie ouverte) et son gabarit (voie fermée). Le gabarit est toujours celui du texte :
/// calculé ici, revérifié à la lecture, jamais fourni à part.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TexteLu")]
pub(crate) struct TexteEnvoye {
    gabarit: Gabarit,
    texte: TexteNettoye,
    contexte: Contexte,
    #[serde(skip_serializing_if = "Option::is_none")]
    regle: Option<Regle>,
    n: Nombre<N_MAX>,
}

/// La forme lue d'un `TexteEnvoye`, avant la vérification du gabarit.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TexteLu {
    gabarit: Gabarit,
    texte: TexteNettoye,
    contexte: Contexte,
    #[serde(default, deserialize_with = "present")]
    regle: Option<Regle>,
    n: Nombre<N_MAX>,
}

impl TryFrom<TexteLu> for TexteEnvoye {
    type Error = &'static str;

    fn try_from(t: TexteLu) -> Result<TexteEnvoye, &'static str> {
        if Gabarit::de(&t.texte) != t.gabarit {
            return Err("gabarit d'un autre texte");
        }
        Ok(TexteEnvoye {
            gabarit: t.gabarit,
            texte: t.texte,
            contexte: t.contexte,
            regle: t.regle,
            n: t.n,
        })
    }
}

#[allow(dead_code)]
impl TexteEnvoye {
    pub(crate) fn new(texte: TexteNettoye, contexte: Contexte, regle: Option<Regle>, n: Nombre<N_MAX>) -> TexteEnvoye {
        TexteEnvoye {
            gabarit: Gabarit::de(&texte),
            texte,
            contexte,
            regle,
            n,
        }
    }

    pub(crate) fn texte(&self) -> &TexteNettoye {
        &self.texte
    }

    pub(crate) fn gabarit(&self) -> &Gabarit {
        &self.gabarit
    }
}

/// Les corrections d'une règle (plan, §1) : proposées, acceptées, refusées, réussies, échouées (et leurs codes),
/// annulées, revenues (le constat réapparaît au bilan suivant).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Correction {
    pub(crate) regle: Regle,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) proposees: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) acceptees: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) refusees: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) reussies: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) echouees: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) annulees: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) revenues: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Liste::est_vide")]
    pub(crate) codes: Liste<RaisonNombre, RAISONS_MAX>,
}

/// Les choix de la personne sur une règle : « c'est normal », oubli de ce choix, refus d'une correction, Échap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Choix {
    pub(crate) regle: Regle,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) normales: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) oublis: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) refus: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) echap: Compte<N_MAX>,
}

/// Un outil lancé : par son nom seul, jamais ses arguments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutilEnvoye {
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
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) med_ms: Compte<MS_MAX>,
}

/// Le cache d'une règle (L6c, `mesures.json`), lu seulement : repris, refait à neuf, âges cumulés, temps gagné,
/// comparaisons du cache au neuf et écarts trouvés.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CacheRegle {
    pub(crate) regle: Regle,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) repris: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) a_neuf: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) age_total_s: Compte<TOTAL_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) gagne_ms: Compte<TOTAL_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) comparees: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) ecarts: Compte<N_MAX>,
}

/// Un ajustement de l'auto-réglage (`reglage.json`), et s'il a été annulé par la personne.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reglage {
    pub(crate) levier: Levier,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(crate) regle: Option<Regle>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) avant: Compte<VALEUR_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) apres: Compte<VALEUR_MAX>,
    pub(crate) annule: bool,
}

/// Ce que la troncature a retiré, par tableau. Absent s'il n'y a rien ; écrit, il compte au moins une entrée.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Retires {
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) regles: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) textes: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) objets: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) cache: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) outils: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) choix: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) corrections: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) reglages: Compte<N_MAX>,
    #[serde(default, skip_serializing_if = "Compte::est_nul")]
    pub(crate) causes: Compte<N_MAX>,
}

impl Retires {
    pub(crate) fn est_vide(&self) -> bool {
        *self == Retires::default()
    }
}

/// `retires` écrit sans rien dedans (`{}`) n'a qu'une écriture permise : l'absence.
fn retires_ecrits<'de, D: Deserializer<'de>>(d: D) -> Result<Retires, D::Error> {
    let r = Retires::deserialize(d)?;
    if r.est_vide() {
        Err(D::Error::custom("retires vide écrit"))
    } else {
        Ok(r)
    }
}

// --- Clés et intérêt des entrées ---------------------------------------------------------------------------------

/// Deux causes de même genre, contexte, règle, lieu, code et gabarit sont la même : A2 les additionne.
type ClefCause = (
    Genre,
    Contexte,
    Option<Regle>,
    Option<Lieu>,
    Option<Code>,
    Option<Gabarit>,
);

impl Entree for CauseEnvoyee {
    type Clef = ClefCause;
    fn clef(&self) -> ClefCause {
        (
            self.genre,
            self.contexte,
            self.regle.clone(),
            self.lieu.clone(),
            self.code.clone(),
            self.gabarit.clone(),
        )
    }
    fn interet(&self) -> u64 {
        u64::from(self.n.get())
    }
}

impl Entree for RegleEnvoyee {
    type Clef = Regle;
    fn clef(&self) -> Regle {
        self.id.clone()
    }
    fn interet(&self) -> u64 {
        u64::from(self.n.get())
    }
}

impl Entree for RaisonNombre {
    type Clef = Code;
    fn clef(&self) -> Code {
        self.code.clone()
    }
    fn interet(&self) -> u64 {
        u64::from(self.n.get())
    }
}

impl Entree for ObjetEnvoye {
    type Clef = (Regle, Sorte, NomLogiciel, Option<VersionTierce>);
    fn clef(&self) -> Self::Clef {
        (self.regle.clone(), self.sorte, self.nom.clone(), self.version.clone())
    }
    fn interet(&self) -> u64 {
        u64::from(self.n.get())
    }
}

impl Entree for TexteEnvoye {
    type Clef = (Gabarit, Contexte, Option<Regle>);
    fn clef(&self) -> Self::Clef {
        (self.gabarit.clone(), self.contexte, self.regle.clone())
    }
    fn interet(&self) -> u64 {
        u64::from(self.n.get())
    }
}

/// La somme de comptes, pour l'intérêt d'une entrée sans `n`.
fn somme<const M: u32>(comptes: &[Compte<M>]) -> u64 {
    comptes.iter().fold(0u64, |s, c| s.saturating_add(u64::from(c.get())))
}

impl Entree for Correction {
    type Clef = Regle;
    fn clef(&self) -> Regle {
        self.regle.clone()
    }
    fn interet(&self) -> u64 {
        somme(&[
            self.proposees,
            self.acceptees,
            self.refusees,
            self.echouees,
            self.revenues,
        ])
    }
}

impl Entree for Choix {
    type Clef = Regle;
    fn clef(&self) -> Regle {
        self.regle.clone()
    }
    fn interet(&self) -> u64 {
        somme(&[self.normales, self.oublis, self.refus, self.echap])
    }
}

impl Entree for OutilEnvoye {
    type Clef = (NomOutil, Origine);
    fn clef(&self) -> Self::Clef {
        (self.outil.clone(), self.origine)
    }
    fn interet(&self) -> u64 {
        somme(&[self.lances, self.abandonnes, self.plantes])
    }
}

impl Entree for CacheRegle {
    type Clef = Regle;
    fn clef(&self) -> Regle {
        self.regle.clone()
    }
    fn interet(&self) -> u64 {
        somme(&[self.repris, self.a_neuf, self.ecarts])
    }
}

impl Entree for Reglage {
    type Clef = (Levier, Option<Regle>);
    fn clef(&self) -> Self::Clef {
        (self.levier, self.regle.clone())
    }
    fn interet(&self) -> u64 {
        u64::from(self.annule)
    }
}

// --- Écrire, tronquer, relire ------------------------------------------------------------------------------------

/// Pourquoi un lot est refusé. Jamais l'erreur de serde, qui recopierait un nom de champ ou une valeur venue du lot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refus {
    /// Plus de `LOT_MAX` octets.
    TropGros,
    /// Pas du JSON, ou pas exactement ce que le schéma 2 permet.
    HorsSchema,
}

impl fmt::Display for Refus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refus::TropGros => "lot de plus de 96 Kio",
            Refus::HorsSchema => "lot hors du schéma 2",
        })
    }
}

/// Relit un lot : tout ou rien.
pub(crate) fn lire(octets: &[u8]) -> Result<Lot, Refus> {
    if octets.len() > LOT_MAX {
        return Err(Refus::TropGros);
    }
    serde_json::from_slice(octets).map_err(|_| Refus::HorsSchema)
}

#[allow(dead_code)]
impl Lot {
    /// Un lot sans tableau ni facultatif : A2 le remplit.
    pub(crate) fn new(
        version: Version,
        jour: Jour,
        anciennete: Anciennete,
        plateforme: Plateforme,
        activite: Activite,
    ) -> Lot {
        Lot {
            schema: Schema,
            version,
            version_avant: None,
            jour,
            installation: None,
            anciennete,
            plateforme,
            materiel: None,
            activite,
            causes: Liste::default(),
            regles: Liste::default(),
            objets: Liste::default(),
            textes: Liste::default(),
            corrections: Liste::default(),
            choix: Liste::default(),
            outils: Liste::default(),
            cache: Liste::default(),
            reglages: Liste::default(),
            refus_locaux: Compte::default(),
            retires: Retires::default(),
        }
    }

    /// Le lot en JSON compact. Aucun de ses types ne peut faire échouer serde (pas de table à clé non textuelle) :
    /// le vide de repli ne sert jamais, et `lire` le refuserait.
    pub(crate) fn ecrire(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Ramène le lot écrit à `LOT_MAX` octets au plus, dans cet ordre (plan, §3) : les règles sans rien de notable,
    /// puis les textes, puis les objets ; au-delà (un lot plein partout), les règles notables, le cache, les outils,
    /// les choix, les corrections, les réglages et enfin les causes. Dans chaque tableau, l'entrée de moindre intérêt
    /// part la première (à égalité, la dernière). Chaque retrait est compté dans `retires`.
    pub(crate) fn tronquer(&mut self) {
        loop {
            let taille = self.ecrire().len();
            let exces = taille.saturating_sub(LOT_MAX);
            if exces == 0 {
                return;
            }
            let r = retirer(&mut self.regles, |r| !r.notable(), exces);
            if r > 0 {
                self.retires.regles.ajouter(r);
                continue;
            }
            macro_rules! puis {
                ($($champ:ident),+) => {
                    $(
                        let r = retirer(&mut self.$champ, |_| true, exces);
                        if r > 0 {
                            self.retires.$champ.ajouter(r);
                            continue;
                        }
                    )+
                };
            }
            puis!(
                textes,
                objets,
                regles,
                cache,
                outils,
                choix,
                corrections,
                reglages,
                causes
            );
            // Plus rien à retirer : le reste (plateforme, matériel, activité) tient bien sous 96 Kio.
            return;
        }
    }
}

/// Retire de `liste` les entrées `retirable` de moindre intérêt, jusqu'à couvrir `exces` octets (taille écrite de
/// chacune, virgule comprise) ; rend le nombre retiré, 0 s'il n'y avait aucune candidate. La taille exacte est
/// remesurée par l'appelant : le compte de `retires` ajoute quelques octets, et un tableau vidé en retire.
fn retirer<T: Entree + Serialize, const M: usize>(
    liste: &mut Liste<T, M>,
    retirable: impl Fn(&T) -> bool,
    exces: usize,
) -> u64 {
    let mut candidates: Vec<(u64, Reverse<usize>)> = liste
        .0
        .iter()
        .enumerate()
        .filter(|(_, t)| retirable(t))
        .map(|(i, t)| (t.interet(), Reverse(i)))
        .collect();
    candidates.sort_unstable();
    let mut partantes = BTreeSet::new();
    let mut reste = exces;
    for (_, Reverse(i)) in candidates {
        if reste == 0 {
            break;
        }
        let taille = liste
            .0
            .get(i)
            .and_then(|t| serde_json::to_vec(t).ok())
            .map_or(1, |o| o.len().saturating_add(1));
        reste = reste.saturating_sub(taille);
        partantes.insert(i);
    }
    liste.0 = std::mem::take(&mut liste.0)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !partantes.contains(i))
        .map(|(_, t)| t)
        .collect();
    u64::try_from(partantes.len()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::as_conversions)]
mod tests;
