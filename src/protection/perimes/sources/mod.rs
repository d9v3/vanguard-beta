//! Les fichiers fixes qui disent la dernière version des logiciels suivis : une table fermée, la même pour tous les
//! ordinateurs d'un même système, qui ne dépend jamais de ce qui est installé. Chaque fichier est téléchargé en
//! entier, sans paramètre de version ni adresse par logiciel : la liste des logiciels de l'ordinateur ne sort jamais.
//! Le modèle est celui du catalogue de la CISA (`kev`) : gardé un jour dans le dossier de Vanguard, la copie d'avant
//! sert hors ligne. Le réglage « Versions des logiciels » (Paramètres) et le travail sans Internet coupent tout
//! téléchargement ; les copies déjà gardées servent alors seules, et c'est dit.
//!
//! Une réponse qui n'a pas la forme attendue (page d'un portail Wi-Fi, format changé) ne remplace jamais la bonne
//! copie (`crate::socle::cache::liste_validee`). Un fichier gzip est gardé tel que reçu, et relu par `degzip_controle` (CRC et
//! taille vérifiés) : un téléchargement coupé ne passe pas pour un fichier entier.

pub(crate) mod editeurs;
pub(crate) mod eol;
pub(crate) mod homebrew;

use std::time::Duration;

use std::fmt;
use std::marker::PhantomData;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::{tr, trf};

/// Au-delà, la copie est redemandée.
pub(crate) const FRAICHE: Duration = Duration::from_hours(24);
/// Au-delà, une copie ne suffit plus pour dire « à jour » : le logiciel est « non vérifié ».
pub(crate) const A_JOUR_MAX: Duration = Duration::from_hours(72);
/// Au-delà, la source ne sert plus du tout : une copie aussi vieille n'est plus suivie.
pub(crate) const DEPASSEE_MAX: Duration = Duration::from_hours(30 * 24);
/// Le sous-dossier des copies, dans le dossier de Vanguard.
const SOUS_DOSSIER: &str = "versions";

/// Les systèmes dont les logiciels sont suivis (sous Linux, le gestionnaire de paquets tient les versions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Systeme {
    Windows,
    MacOs,
}

impl Systeme {
    /// Le système qui tourne ; `None` sous Linux.
    #[cfg(test)]
    pub(crate) fn courant() -> Option<Systeme> {
        if cfg!(windows) {
            Some(Systeme::Windows)
        } else if cfg!(target_os = "macos") {
            Some(Systeme::MacOs)
        } else {
            None
        }
    }
}

/// Comment un fichier se lit (et se valide : une réponse que son lecteur refuse ne remplace pas la copie d'avant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lecteur {
    Firefox,
    /// Plateforme et canal de versionhistory.
    Chrome(&'static str, &'static str),
    Edge,
    Office,
    /// L'identifiant d'application du manifeste de Microsoft AutoUpdate.
    Mau(&'static str),
    Adobe,
    Brave,
    Eol,
    Cask,
    /// `formula.json` de Homebrew : 7-Zip et PuTTY, dont les formules suivent l'amont.
    Formules,
    /// La plateforme que la réponse de Slack doit nommer (« win32 », « darwin »).
    Slack(&'static str),
    /// L'archive des avis de sécurité de Mozilla (tar en gzip).
    Mfsa,
}

/// Une ligne de la table : un fichier fixe.
#[derive(Debug)]
pub(crate) struct Source {
    /// Aussi le nom de la copie gardée.
    pub id: &'static str,
    pub adresse: &'static str,
    pub lecteur: Lecteur,
    pub systemes: &'static [Systeme],
    /// Octets reçus au plus (compressés, quand le serveur compresse).
    pub taille_max: u64,
    /// `Some(n)` : demandé en gzip (`Accept-Encoding`), au plus `n` octets une fois décompressé.
    pub gzip: Option<usize>,
    /// Délai de la demande, en secondes.
    pub delai: u64,
}

const W: &[Systeme] = &[Systeme::Windows];
const M: &[Systeme] = &[Systeme::MacOs];
const WM: &[Systeme] = &[Systeme::Windows, Systeme::MacOs];

/// Une source de versionhistory (Chrome) : une adresse par plateforme et par canal, toutes prises.
macro_rules! chrome {
    ($p:literal, $c:literal, $s:expr) => {
        Source {
            id: concat!("chrome-", $p, "-", $c),
            adresse: concat!(
                "https://versionhistory.googleapis.com/v1/chrome/platforms/",
                $p,
                "/channels/",
                $c,
                "/versions/all/releases?filter=endtime=none"
            ),
            lecteur: Lecteur::Chrome($p, $c),
            systemes: $s,
            taille_max: 256 << 10,
            gzip: None,
            delai: 30,
        }
    };
}

/// Un manifeste de Microsoft AutoUpdate (Office pour Mac) : un par application, tous pris.
macro_rules! mau {
    ($id:literal) => {
        Source {
            id: concat!("mau-", $id),
            adresse: concat!(
                "https://res.public.onecdn.static.microsoft/mro1cdnstorage/C1297A47-86C4-4C1F-97FA-950631F94777/MacAutoupdate/0409",
                $id,
                "-chk.xml"
            ),
            lecteur: Lecteur::Mau($id),
            systemes: M,
            taille_max: 64 << 10,
            gzip: None,
            delai: 30,
        }
    };
}

/// Un petit fichier texte d'un éditeur (Adobe, Brave).
macro_rules! texte {
    ($id:literal, $adresse:literal, $lecteur:expr, $s:expr) => {
        Source {
            id: $id,
            adresse: $adresse,
            lecteur: $lecteur,
            systemes: $s,
            taille_max: 1 << 10,
            gzip: None,
            delai: 30,
        }
    };
}

/// La table : 17 fichiers sous Windows, 21 sous macOS (adresses finales, mesurées le 23 oct. 2026 : aucune
/// redirection, qu'un en-tête interdirait de suivre vers un autre hôte, voir `http::envoyer`). Le catalogue de la
/// CISA s'y ajoute, par `kev::catalogue`.
pub(crate) const SOURCES: &[Source] = &[
    Source {
        id: "mozilla",
        adresse: "https://product-details.mozilla.org/1.0/firefox_versions.json",
        lecteur: Lecteur::Firefox,
        systemes: WM,
        taille_max: 64 << 10,
        gzip: None,
        delai: 30,
    },
    chrome!("win", "stable", W),
    chrome!("win", "extended", W),
    chrome!("win64", "stable", W),
    chrome!("win64", "extended", W),
    chrome!("win_arm64", "stable", W),
    chrome!("win_arm64", "extended", W),
    chrome!("mac", "stable", M),
    chrome!("mac", "extended", M),
    chrome!("mac_arm64", "stable", M),
    chrome!("mac_arm64", "extended", M),
    Source {
        id: "edge",
        adresse: "https://edgeupdates.microsoft.com/api/products",
        lecteur: Lecteur::Edge,
        systemes: WM,
        taille_max: 1 << 20,
        gzip: None,
        delai: 30,
    },
    Source {
        id: "office",
        adresse: "https://clients.config.office.net/releases/v1.0/OfficeReleases",
        lecteur: Lecteur::Office,
        systemes: W,
        taille_max: 1 << 20,
        gzip: None,
        delai: 30,
    },
    mau!("MSWD2019"),
    mau!("XCEL2019"),
    mau!("PPT32019"),
    mau!("OPIM2019"),
    mau!("ONMC2019"),
    mau!("MSau04"),
    // Seul le chemin « mac/ » existe chez Adobe (« win/ » répond 404) ; la piste Continuous porte le même numéro.
    texte!(
        "adobe-reader",
        "https://armmf.adobe.com/arm-manifests/mac/AcrobatDC/reader/current_version.txt",
        Lecteur::Adobe,
        WM
    ),
    texte!(
        "adobe-acrobat",
        "https://armmf.adobe.com/arm-manifests/mac/AcrobatDC/acrobat/current_version.txt",
        Lecteur::Adobe,
        WM
    ),
    texte!(
        "brave-windows-x64",
        "https://versions.brave.com/latest/release-windows-x64.version",
        Lecteur::Brave,
        W
    ),
    texte!(
        "brave-windows-arm64",
        "https://versions.brave.com/latest/release-windows-arm64.version",
        Lecteur::Brave,
        W
    ),
    texte!(
        "brave-macos-arm64",
        "https://versions.brave.com/latest/release-macos-arm64.version",
        Lecteur::Brave,
        M
    ),
    texte!(
        "brave-macos-x64",
        "https://versions.brave.com/latest/release-macos-x64.version",
        Lecteur::Brave,
        M
    ),
    Source {
        id: "eol",
        adresse: "https://endoflife.date/api/v1/products/full",
        lecteur: Lecteur::Eol,
        systemes: WM,
        taille_max: 8 << 20,
        gzip: Some(16 << 20),
        delai: 30,
    },
    // L'archive entière du dépôt des avis (codeload, adresse finale de GitHub, sans redirection) : 600 Kio en gzip,
    // 5 Mio une fois décompressée le 23 oct. 2026.
    Source {
        id: "mfsa",
        adresse: "https://codeload.github.com/mozilla/foundation-security-advisories/tar.gz/main",
        lecteur: Lecteur::Mfsa,
        systemes: WM,
        taille_max: 8 << 20,
        gzip: Some(64 << 20),
        delai: 60,
    },
    // Slack : une adresse fixe par système, la même pour tous (API non documentée, mesurée le 23 oct. 2026 :
    // « variant=msi » est l'installation par machine, sans mise à jour automatique ; « universal » sert les deux
    // architectures du Mac). « redirect=false » : la réponse est le JSON, pas un renvoi vers le fichier à installer.
    Source {
        id: "slack-windows",
        adresse: "https://slack.com/api/desktop.latestRelease?arch=x64&variant=msi&redirect=false",
        lecteur: Lecteur::Slack("win32"),
        systemes: W,
        taille_max: 4 << 10,
        gzip: None,
        delai: 30,
    },
    Source {
        id: "slack-macos",
        adresse: "https://slack.com/api/desktop.latestRelease?arch=universal&variant=dmg&redirect=false",
        lecteur: Lecteur::Slack("darwin"),
        systemes: M,
        taille_max: 4 << 10,
        gzip: None,
        delai: 30,
    },
    // Les formules de Homebrew, prises sous Windows aussi : 7-Zip et PuTTY y suivent l'amont, et n'ont aucun autre
    // fichier fixe. 5 Mio en gzip, 32 Mio une fois décompressé le 23 oct. 2026 ; pris par tous ou par personne,
    // jamais selon que Homebrew est installé.
    Source {
        id: "formules",
        adresse: "https://formulae.brew.sh/api/formula.json",
        lecteur: Lecteur::Formules,
        systemes: WM,
        taille_max: 24 << 20,
        gzip: Some(96 << 20),
        delai: 60,
    },
    // HTTPS seulement, sans vérifier la signature (cask.jws.json) : décision de l'auteur, pour ne pas prendre ring
    // en direct.
    Source {
        id: "cask",
        adresse: "https://formulae.brew.sh/api/cask.json",
        lecteur: Lecteur::Cask,
        systemes: M,
        taille_max: 40 << 20,
        gzip: Some(64 << 20),
        delai: 60,
    },
];

/// Les sources d'un système : ne dépend que de lui.
pub(crate) fn du_systeme(systeme: Systeme) -> impl Iterator<Item = &'static Source> {
    SOURCES.iter().filter(move |s| s.systemes.contains(&systeme))
}

/// Une source sert si un logiciel de la table s'en sert : les autres ne sont pas téléchargées (cask.json attend la
/// longue traîne de macOS ; le manifeste de Microsoft AutoUpdate lui-même n'est pas jugé). Ne dépend que des deux
/// tables fixes, jamais de ce qui est installé.
pub(crate) fn sert(source: &Source) -> bool {
    super::produits::FICHES.iter().any(|f| f.sources.contains(&source.id))
}

/// Pourquoi rien ne doit être téléchargé (tests, réglage coupé, travail sans Internet) ; `None` : permis.
pub(crate) fn coupure() -> Option<String> {
    if cfg!(test) {
        Some(tr!("tests : rien n'est téléchargé", "tests: nothing is downloaded").to_string())
    } else if !crate::parametres::versions_logiciels() {
        Some(
            tr!(
                "téléchargement coupé (Paramètres › Versions des logiciels)",
                "download turned off (Settings › Software versions)"
            )
            .to_string(),
        )
    } else if crate::parametres::hors_ligne() {
        Some(tr!("travail sans Internet", "working without the Internet").to_string())
    } else {
        None
    }
}

/// Une valeur JSON dont le type peut changer sans tout rendre illisible : gardée si elle a la forme attendue
/// (`Forme`), ignorée sinon (un champ d'un autre produit qui change de forme ne fait pas tomber la lecture des
/// autres). Lue en flux : une valeur d'une autre forme est parcourue puis oubliée, jamais copiée en mémoire. Un
/// `#[serde(untagged)]` la copierait en entier avant de l'essayer, soit des centaines de Mo pour un tableau démesuré
/// qui pèse quelques centaines de Kio en gzip.
pub(crate) enum Souple<T> {
    Bon(T),
    Autre,
}

impl<T> Souple<T> {
    pub(crate) fn bon(self) -> Option<T> {
        match self {
            Souple::Bon(v) => Some(v),
            Souple::Autre => None,
        }
    }

    fn de(valeur: Option<T>) -> Self {
        valeur.map_or(Souple::Autre, Souple::Bon)
    }
}

/// Les formes qu'une valeur JSON peut prendre pour un type lu par `Souple` : `None` quand ce n'est pas la sienne.
/// Par défaut, aucune ; un tableau ou un objet refusé est parcouru jusqu'au bout sans rien garder.
pub(crate) trait Forme: Sized {
    fn texte(_: &str) -> Option<Self> {
        None
    }

    fn booleen(_: bool) -> Option<Self> {
        None
    }

    /// Un nombre ou `null`.
    fn autre() -> Option<Self> {
        None
    }

    fn suite<'de, A: SeqAccess<'de>>(mut suite: A) -> Result<Option<Self>, A::Error> {
        while suite.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }

    fn table<'de, A: MapAccess<'de>>(mut table: A) -> Result<Option<Self>, A::Error> {
        while table.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
}

impl Forme for String {
    fn texte(t: &str) -> Option<Self> {
        Some(t.to_owned())
    }
}

impl Forme for bool {
    fn booleen(b: bool) -> Option<Self> {
        Some(b)
    }
}

/// Un élément souple d'un tableau : toujours accepté, gardé ou non selon sa propre forme.
impl<E: Forme> Forme for Souple<E> {
    fn texte(t: &str) -> Option<Self> {
        Some(Souple::de(E::texte(t)))
    }

    fn booleen(b: bool) -> Option<Self> {
        Some(Souple::de(E::booleen(b)))
    }

    fn autre() -> Option<Self> {
        Some(Souple::de(E::autre()))
    }

    fn suite<'de, A: SeqAccess<'de>>(suite: A) -> Result<Option<Self>, A::Error> {
        E::suite(suite).map(|e| Some(Souple::de(e)))
    }

    fn table<'de, A: MapAccess<'de>>(table: A) -> Result<Option<Self>, A::Error> {
        E::table(table).map(|e| Some(Souple::de(e)))
    }
}

/// Les entrées d'un tableau lu, au plus. Les vrais fichiers en ont au plus quelques milliers (8 667 formules et
/// 7 803 casks le 23 oct. 2026) ; sans plafond, 100 Kio de `{},` en gzip, décompressés jusqu'à leur limite, faisaient
/// allouer des Gio d'entrées vides, et le programme s'arrêtait faute de mémoire.
pub(crate) const ENTREES_MAX: usize = 50_000;

/// Les éléments d'un tableau dans une entrée (branches d'un produit, CVE d'un avis, autres noms), au plus : quelques
/// centaines dans les vrais fichiers.
pub(crate) const SOUS_ENTREES_MAX: usize = 2_000;

/// Un tableau dont un seul élément n'a pas la forme attendue, ou qui dépasse `SOUS_ENTREES_MAX`, est refusé en
/// entier ; la suite est parcourue sans rien garder.
impl<E: Forme> Forme for Vec<E> {
    fn suite<'de, A: SeqAccess<'de>>(mut suite: A) -> Result<Option<Self>, A::Error> {
        let mut garde = Some(Vec::new());
        let mut n = 0usize;
        while let Some(e) = suite.next_element::<Souple<E>>()? {
            n += 1;
            match (e.bon(), garde.as_mut()) {
                (Some(e), Some(v)) if n <= SOUS_ENTREES_MAX => v.push(e),
                _ => garde = None,
            }
        }
        Ok(garde)
    }
}

/// Ce qu'on garde d'une entrée d'un tableau lu en flux (`Choisis`) : les autres sont oubliées dès qu'elles sont lues.
pub(crate) trait Choix {
    fn garder(&self) -> bool;
}

/// Un tableau JSON lu en flux : chaque entrée est lue, gardée si elle est choisie (`Choix`), oubliée sinon ; jamais le
/// tableau entier en mémoire avant le tri. Au-delà de `ENTREES_MAX` entrées, c'est une erreur : le fichier est
/// refusé, pas tronqué. Le second champ : le nombre d'entrées lues, gardées ou non.
pub(crate) struct Choisis<T>(pub Vec<T>, pub usize);

impl<'de, T: Deserialize<'de> + Choix> Deserialize<'de> for Choisis<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de> + Choix> Visitor<'de> for V<T> {
            type Value = Choisis<T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("un tableau JSON")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut suite: A) -> Result<Self::Value, A::Error> {
                let mut gardes = Vec::new();
                let mut n = 0usize;
                while let Some(e) = suite.next_element::<T>()? {
                    n += 1;
                    if n > ENTREES_MAX {
                        return Err(de::Error::custom("trop d'entrées"));
                    }
                    if e.garder() {
                        gardes.push(e);
                    }
                }
                Ok(Choisis(gardes, n))
            }
        }
        d.deserialize_seq(V(PhantomData))
    }
}

/// Une structure lue par `serde` à partir d'un objet JSON. Ses champs doivent tous être facultatifs et souples : un
/// champ manquant ou d'une autre forme ne doit pas être une erreur, qui rendrait tout le fichier illisible.
macro_rules! forme_objet {
    ($($t:ty),+ $(,)?) => {
        $(impl $crate::protection::perimes::sources::Forme for $t {
            fn table<'de, A: serde::de::MapAccess<'de>>(table: A) -> Result<Option<Self>, A::Error> {
                <$t as serde::Deserialize>::deserialize(serde::de::value::MapAccessDeserializer::new(table)).map(Some)
            }
        })+
    };
}
pub(crate) use forme_objet;

impl<'de, T: Forme> Deserialize<'de> for Souple<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(VisiteurSouple(PhantomData))
    }
}

struct VisiteurSouple<T>(PhantomData<T>);

impl<'de, T: Forme> Visitor<'de> for VisiteurSouple<T> {
    type Value = Souple<T>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("une valeur JSON")
    }

    fn visit_str<E: de::Error>(self, t: &str) -> Result<Self::Value, E> {
        Ok(Souple::de(T::texte(t)))
    }

    fn visit_bool<E: de::Error>(self, b: bool) -> Result<Self::Value, E> {
        Ok(Souple::de(T::booleen(b)))
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(Souple::de(T::autre()))
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(Souple::de(T::autre()))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(Souple::de(T::autre()))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Souple::de(T::autre()))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Souple::de(T::autre()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, suite: A) -> Result<Self::Value, A::Error> {
        T::suite(suite).map(Souple::de)
    }

    fn visit_map<A: MapAccess<'de>>(self, table: A) -> Result<Self::Value, A::Error> {
        T::table(table).map(Souple::de)
    }
}

/// Une copie utilisable : son contenu (décompressé), son âge, et pourquoi elle n'a pas été rafraîchie quand elle
/// aurait dû l'être.
#[derive(Debug)]
pub(crate) struct Copie {
    pub octets: Vec<u8>,
    pub age: Duration,
    pub manque: Option<String>,
}

/// Ce que chaque source du système a donné : sa copie, ou pourquoi il n'y en a pas.
pub(crate) struct Releve {
    pub sources: Vec<(&'static Source, Result<Copie, String>)>,
}

impl Releve {
    /// La copie de la source `id` ; `Err` : pourquoi elle manque.
    pub(crate) fn copie(&self, id: &str) -> Result<&Copie, String> {
        match self.sources.iter().find(|(s, _)| s.id == id) {
            Some((_, Ok(c))) => Ok(c),
            Some((_, Err(raison))) => Err(raison.clone()),
            None => Err(tr!("source inconnue", "unknown source").to_string()),
        }
    }
}

/// Télécharger, ou seulement relire les copies gardées (avec la raison à dire quand une copie aurait dû être
/// rafraîchie).
enum Mode {
    Telecharger,
    CopieSeule(String),
}

/// Ce que chaque source de `systeme` donne : téléchargées en parallèle (une minute au pire), sauf si le réglage les
/// coupe, sans Internet, ou dans les tests ; les copies gardées servent alors seules.
pub(crate) fn rafraichir(systeme: Systeme) -> Releve {
    let mode = coupure().map_or(Mode::Telecharger, Mode::CopieSeule);
    let sources: Vec<&'static Source> = du_systeme(systeme).filter(|s| sert(s)).collect();
    let resultats = std::thread::scope(|portee| {
        let fils: Vec<_> = sources
            .iter()
            .map(|&s| {
                let mode = &mode;
                portee.spawn(move || obtenir(s, s.adresse, mode))
            })
            .collect();
        fils.into_iter()
            .map(|f| {
                f.join()
                    .unwrap_or_else(|_| Err(tr!("lecture interrompue", "reading interrupted").to_string()))
            })
            .collect::<Vec<_>>()
    });
    Releve {
        sources: sources.into_iter().zip(resultats).collect(),
    }
}

/// La copie d'une source, demandée à `adresse` (un serveur local dans les tests) quand il faut la rafraîchir.
fn obtenir(source: &Source, adresse: &str, mode: &Mode) -> Result<Copie, String> {
    let lieu = (SOUS_DOSSIER, source.id);
    let (brut, age, manque) = match mode {
        Mode::Telecharger => {
            let liste = crate::socle::cache::liste_validee(demande(source, adresse), lieu, FRAICHE, &|o| {
                contenu(source, o).is_some()
            });
            let manque = liste.manque.map(raison);
            let (brut, age) = liste.resultat(false).map_err(raison)?;
            (brut, age, manque)
        }
        Mode::CopieSeule(pourquoi) => {
            // Âge et contenu d'après le sceau de la copie : changée ou datée dans le futur, elle ne sert pas.
            let (brut, age) = crate::socle::cache::gardee(lieu, crate::socle::cache::LISTE_MAX)
                .map_err(|refus| trf!("{pourquoi} ; {}", "{pourquoi}; {}", refus.texte()))?
                .ok_or_else(|| pourquoi.clone())?;
            let manque = (age >= FRAICHE).then(|| pourquoi.clone());
            (brut, age, manque)
        }
    };
    if age > DEPASSEE_MAX {
        return Err(trf!(
            "copie de {} jours, plus suivie",
            "{}-day-old copy, no longer followed",
            age.as_secs() / 86_400
        ));
    }
    let octets = contenu(source, &brut).ok_or_else(|| {
        tr!(
            "copie gardée illisible (format changé ?)",
            "kept copy unreadable (format changed?)"
        )
        .to_string()
    })?;
    Ok(Copie { octets, age, manque })
}

/// La demande d'une source, envoyée à `adresse` (un serveur local dans les tests) : la même pour le programme et pour
/// les canaris de la veille de nuit (`canaris`), qui doivent voir ce que le programme verrait.
pub(crate) fn demande<'a>(source: &Source, adresse: &'a str) -> crate::http::Demande<'a> {
    let mut demande = crate::http::Demande {
        taille_max: source.taille_max,
        ..crate::http::Demande::get(adresse, Duration::from_secs(source.delai))
    };
    if source.gzip.is_some() {
        demande.entetes.push(("Accept-Encoding", "gzip".to_string()));
    }
    demande
}

/// Le contenu d'une réponse ou d'une copie, décompressé s'il le faut, et seulement s'il a la forme attendue.
pub(crate) fn contenu(source: &Source, brut: &[u8]) -> Option<Vec<u8>> {
    let octets = match source.gzip {
        Some(limite) if crate::archives::gzip::est_gzip(brut) => crate::archives::gzip::degzip_controle(brut, limite)?,
        _ => brut.to_vec(),
    };
    lisible(source.lecteur, &octets).then_some(octets)
}

/// Le fichier se lit-il comme son lecteur l'attend ?
fn lisible(lecteur: Lecteur, octets: &[u8]) -> bool {
    match lecteur {
        Lecteur::Firefox => editeurs::firefox(octets).is_some(),
        Lecteur::Chrome(plateforme, canal) => editeurs::chrome(octets, plateforme, canal).is_some(),
        Lecteur::Edge => editeurs::edge(octets).is_some(),
        Lecteur::Office => editeurs::office(octets).is_some(),
        Lecteur::Mau(id) => editeurs::mau(octets, id).is_some(),
        Lecteur::Adobe => editeurs::adobe(octets).is_some(),
        Lecteur::Brave => editeurs::brave(octets).is_some(),
        Lecteur::Eol => eol::lire(octets).is_some(),
        Lecteur::Cask => homebrew::casks(octets).is_some(),
        Lecteur::Formules => homebrew::formules(octets).is_some(),
        Lecteur::Slack(plateforme) => editeurs::slack(octets, plateforme).is_some(),
        Lecteur::Mfsa => super::avis_de_l_archive(octets).is_some(),
    }
}

/// La raison d'une copie manquée, dite sans l'adresse.
fn raison(echec: crate::protection::abuse_ch::Echec) -> String {
    use crate::protection::abuse_ch::Echec;
    match echec {
        Echec::Reponse(code) => trf!("le serveur a répondu {code}", "the server answered {code}"),
        Echec::SansReponse => tr!("pas d'Internet ?", "no Internet?").to_string(),
        autre => autre.raison(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::io::{Read, Write};

    /// L'allocateur des essais : celui du système, qui compte les octets alloués par chaque fil. Il sert à vérifier
    /// qu'une lecture ne copie pas en mémoire ce qu'elle ignore (`allocations`).
    #[cfg_attr(all(miri, windows), allow(dead_code))]
    struct Compteur;

    thread_local! {
        static ALLOUE: Cell<usize> = const { Cell::new(0) };
    }

    // SAFETY: tout est délégué à l'allocateur du système ; le compte (un `Cell` sans destructeur, initialisé à la
    // compilation) n'alloue rien lui-même.
    // `unsafe impl GlobalAlloc` : l'allocateur compteur des essais.
    #[allow(unsafe_code)]
    unsafe impl GlobalAlloc for Compteur {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let _ = ALLOUE.try_with(|c| c.set(c.get().saturating_add(l.size())));
            // SAFETY: les conditions de `GlobalAlloc::alloc` (taille non nulle) sont celles de l'appelant, transmises telles quelles.
            unsafe { System.alloc(l) }
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            // SAFETY: `p` vient de cet allocateur, donc du système, avec ce même `l` : l'appelant le garantit.
            unsafe { System.dealloc(p, l) }
        }
        unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
            let _ = ALLOUE.try_with(|c| c.set(c.get().saturating_add(l.size())));
            // SAFETY: mêmes conditions que `alloc`, transmises telles quelles par l'appelant.
            unsafe { System.alloc_zeroed(l) }
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, taille: usize) -> *mut u8 {
            let _ = ALLOUE.try_with(|c| c.set(c.get().saturating_add(taille)));
            // SAFETY: `p` vient du système avec `l`, et `taille` est valide : l'appelant le garantit.
            unsafe { System.realloc(p, l, taille) }
        }
    }

    // Pas sous Miri pour Windows : l'allocateur du système de std y relit son en-tête (allocations alignées sur plus
    // de 16 octets) par un pointeur que Miri juge sans droit sur lui, ce qui se reproduit sans Vanguard, avec `System`
    // seul. Miri y garde son allocateur ; le compteur est vérifié sous Miri pour Linux (outils/preuves.sh).
    #[cfg(not(all(miri, windows)))]
    #[global_allocator]
    static COMPTEUR: Compteur = Compteur;

    /// Ce que rend `f`, et les octets alloués par ce fil pendant qu'il tournait.
    #[cfg(not(all(miri, windows)))]
    pub(crate) fn allocations<T>(f: impl FnOnce() -> T) -> (T, usize) {
        let avant = ALLOUE.with(Cell::get);
        let r = f();
        (r, ALLOUE.with(Cell::get) - avant)
    }

    /// Sans le compteur (Miri pour Windows) : refuse plutôt que de rendre zéro, pour qu'un essai « ne copie pas » n'y
    /// passe jamais à vide.
    #[cfg(all(miri, windows))]
    pub(crate) fn allocations<T>(_: impl FnOnce() -> T) -> (T, usize) {
        panic!("allocations : pas de compteur sous Miri pour Windows (voir COMPTEUR)")
    }

    /// Le compteur lui-même : chaque méthode de l'allocateur (allocation, à zéro, agrandie, libérée) passe au système
    /// et compte ce qu'elle demande. Lancé sous Miri (outils/preuves.sh), qui y vérifie les quatre délégations.
    #[test]
    #[cfg_attr(
        all(miri, windows),
        ignore = "sans le compteur sous Miri pour Windows (voir COMPTEUR)"
    )]
    fn compteur_delegue_et_compte() {
        let (v, alloue) = allocations(|| {
            let mut v = vec![0u8; 16];
            v.extend_from_slice(&[7; 100]);
            v.push(1);
            v
        });
        assert_eq!(v.len(), 117);
        assert!(v[..16].iter().all(|&o| o == 0) && v[16..116].iter().all(|&o| o == 7));
        assert!(alloue >= 117, "{alloue}");
        drop(v);
    }

    /// Un serveur HTTP local qui répond `reponse` à une demande et rend les en-têtes reçus.
    fn serveur(reponse: Vec<u8>) -> (String, std::thread::JoinHandle<String>) {
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = format!("http://{}/api/products/full", ecoute.local_addr().unwrap());
        let fil = std::thread::spawn(move || {
            let (mut prise, _) = ecoute.accept().unwrap();
            prise.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut recu = vec![0u8; 65_536];
            let n = prise.read(&mut recu).unwrap_or(0);
            let _ = prise.write_all(&reponse);
            String::from_utf8_lossy(&recu[..n]).into_owned()
        });
        (adresse, fil)
    }

    fn reponse(corps: &[u8]) -> Vec<u8> {
        let mut r = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            corps.len()
        )
        .into_bytes();
        r.extend(corps);
        r
    }

    fn gzip(contenu: &[u8]) -> Vec<u8> {
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        gz.extend(miniz_oxide::deflate::compress_to_vec(contenu, 6));
        let crc = {
            // Le CRC du lecteur, recalculé ici par la définition (bit à bit) : les deux doivent s'accorder.
            let mut c = !0u32;
            for &o in contenu {
                c ^= u32::from(o);
                for _ in 0..8 {
                    c = if c & 1 == 1 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                }
            }
            !c
        };
        gz.extend(crc.to_le_bytes());
        gz.extend(u32::try_from(contenu.len()).unwrap().to_le_bytes());
        gz
    }

    /// Une source d'essai, pour la copie « essai-eol » (lecteur d'endoflife.date).
    const ESSAI: Source = Source {
        id: "essai-eol",
        adresse: "https://endoflife.date/api/v1/products/full",
        lecteur: Lecteur::Eol,
        systemes: WM,
        taille_max: 1 << 20,
        gzip: Some(1 << 20),
        delai: 5,
    };

    const EOL: &[u8] = include_bytes!("../../../../assets/essais/eol-extrait.json");

    /// La table : les mêmes fichiers pour tous les ordinateurs d'un système, en HTTPS, sans rien de variable dans
    /// l'adresse, jamais l'adresse d'un logiciel en particulier (cask par cask) ni winget.
    #[test]
    fn table_fermee_et_fixe() {
        let mut ids: Vec<&str> = SOURCES.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), SOURCES.len(), "identifiants en double");
        assert_eq!(du_systeme(Systeme::Windows).count(), 17);
        assert_eq!(du_systeme(Systeme::MacOs).count(), 21);
        // Toutes servent, sauf celles qu'aucun logiciel jugé n'utilise encore (Microsoft AutoUpdate lui-même, la
        // longue traîne de macOS par cask.json) : pas téléchargées pour rien.
        let inutiles: Vec<&str> = SOURCES.iter().filter(|s| !sert(s)).map(|s| s.id).collect();
        assert_eq!(inutiles, ["mau-MSau04", "cask"]);
        for s in SOURCES {
            assert!(s.adresse.starts_with("https://"), "{}", s.adresse);
            assert!(
                !s.adresse.contains('{') && !s.adresse.contains("api/cask/"),
                "{}",
                s.adresse
            );
            assert!(
                !s.adresse.contains("winget") && !s.adresse.contains("version=") && !s.adresse.contains("api/formula/"),
                "{}",
                s.adresse
            );
            // Un paramètre d'adresse est une constante de la table, jamais ce qui est installé : aucun n'est fait
            // au moment de demander (l'adresse est `&'static str`), et seuls ceux-ci existent.
            if let Some((_, requete)) = s.adresse.split_once('?') {
                for p in requete.split('&') {
                    assert!(
                        [
                            "filter=endtime=none",
                            "arch=x64",
                            "arch=universal",
                            "variant=msi",
                            "variant=dmg",
                            "redirect=false"
                        ]
                        .contains(&p),
                        "{} : {p}",
                        s.adresse
                    );
                }
            }
            assert!(!s.systemes.is_empty() && s.taille_max > 0 && (5..=60).contains(&s.delai));
            assert!(
                s.id.bytes()
                    .all(|o| o.is_ascii_alphanumeric() || o == b'-' || o == b'_'),
                "{}",
                s.id
            );
            if let Lecteur::Chrome(p, c) = s.lecteur {
                assert!(
                    s.adresse.contains(&format!("/platforms/{p}/channels/{c}/")),
                    "{}",
                    s.adresse
                );
            }
        }
        // formula.json pour tous, sous les deux systèmes (jamais selon que Homebrew est là) ; Slack, une adresse par
        // système.
        for systeme in [Systeme::Windows, Systeme::MacOs] {
            assert!(du_systeme(systeme).any(|s| s.id == "formules"), "{systeme:?}");
            assert_eq!(
                du_systeme(systeme)
                    .filter(|s| matches!(s.lecteur, Lecteur::Slack(_)))
                    .count(),
                1,
                "{systeme:?}"
            );
        }
        // Chaque plateforme de Chrome a ses deux canaux (sans extended, un Chrome d'entreprise serait dit dépassé).
        for p in ["win", "win64", "win_arm64", "mac", "mac_arm64"] {
            for c in ["stable", "extended"] {
                assert!(SOURCES.iter().any(|s| s.lecteur == Lecteur::Chrome(p, c)), "{p} {c}");
            }
        }
    }

    /// Téléchargée en gzip (l'en-tête est envoyé), gardée telle quelle, relue décompressée ; une page de portail ensuite
    /// ne chasse pas la bonne copie, et c'est dit.
    #[test]
    fn gzip_garde_et_portail_refuse() {
        let dossier = crate::socle::dossier_local().join(SOUS_DOSSIER);
        let _ = std::fs::remove_file(dossier.join(ESSAI.id));
        let (adresse, fil) = serveur(reponse(&gzip(EOL)));
        let copie = obtenir(&ESSAI, &adresse, &Mode::Telecharger).unwrap();
        let recu = fil.join().unwrap().to_lowercase();
        assert!(recu.contains("accept-encoding: gzip"), "{recu}");
        assert!(recu.contains("user-agent: vanguard\r\n"), "{recu}");
        assert_eq!(copie.octets, EOL);
        assert!(copie.manque.is_none());
        assert!(crate::archives::gzip::est_gzip(
            &std::fs::read(dossier.join(ESSAI.id)).unwrap()
        ));
        // Une copie de moins d'un jour n'est pas redemandée : vieillie pour que la suite le soit.
        // L'âge vient du sceau de la copie : c'est lui qui est vieilli.
        let vieillir = |jours: u64| {
            crate::socle::cache::vieillir_pour_essai((SOUS_DOSSIER, ESSAI.id), Duration::from_hours(24 * jours));
        };
        vieillir(2);
        // Une page de portail Wi-Fi : la copie d'avant sert, le manque est dit.
        let (adresse, fil) = serveur(reponse(b"<html>Connexion requise</html>"));
        let copie = obtenir(&ESSAI, &adresse, &Mode::Telecharger).unwrap();
        fil.join().unwrap();
        assert_eq!(copie.octets, EOL);
        assert!(
            copie
                .manque
                .is_some_and(|m| m.contains("portail") || m.contains("portal"))
        );
        // Un gzip coupé ou abîmé non plus.
        vieillir(2);
        let mut abime = gzip(EOL);
        let n = abime.len();
        abime[n - 6] ^= 0xff;
        let (adresse, fil) = serveur(reponse(&abime));
        let copie = obtenir(&ESSAI, &adresse, &Mode::Telecharger).unwrap();
        fil.join().unwrap();
        assert_eq!(copie.octets, EOL);
        assert!(copie.manque.is_some());
        // Sans téléchargement : la copie seule, et pourquoi elle n'est pas rafraîchie quand elle est vieille.
        vieillir(0);
        let copie = obtenir(&ESSAI, &adresse, &Mode::CopieSeule("coupé".into())).unwrap();
        assert_eq!((copie.octets.as_slice(), copie.manque), (EOL, None));
        vieillir(2);
        let copie = obtenir(&ESSAI, &adresse, &Mode::CopieSeule("coupé".into())).unwrap();
        assert_eq!(copie.manque.as_deref(), Some("coupé"));
        assert!(copie.age > A_JOUR_MAX / 2);
        // Plus de 30 jours : plus suivie.
        vieillir(31);
        let refus = obtenir(&ESSAI, &adresse, &Mode::CopieSeule("coupé".into())).unwrap_err();
        assert!(refus.contains("31"), "{refus}");
        // Effacée sous son sceau : refusée, et dit.
        std::fs::remove_file(dossier.join(ESSAI.id)).unwrap();
        let refus = obtenir(&ESSAI, &adresse, &Mode::CopieSeule("coupé".into())).unwrap_err();
        assert!(refus.contains(crate::socle::cache::Refus::Effacee.raison()), "{refus}");
        // Oubliée par Vanguard (copie et sceau) : aucune copie, la raison de la coupure.
        crate::socle::cache::oublier((SOUS_DOSSIER, ESSAI.id)).unwrap();
        assert_eq!(
            obtenir(&ESSAI, &adresse, &Mode::CopieSeule("coupé".into())).unwrap_err(),
            "coupé"
        );
    }

    /// Sans copie et sans réponse : la raison, jamais une copie vide ; une réponse refusée sans copie d'avant dit la
    /// forme, pas le code.
    #[test]
    fn sans_copie_la_raison() {
        let source = Source {
            id: "essai-sans-copie",
            ..ESSAI
        };
        let _ = std::fs::remove_file(crate::socle::dossier_local().join(SOUS_DOSSIER).join(source.id));
        let libre = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let adresse = format!("http://{libre}/full");
        assert_eq!(
            obtenir(&source, &adresse, &Mode::Telecharger).unwrap_err(),
            tr!("pas d'Internet ?", "no Internet?")
        );
        let (adresse, fil) = serveur(reponse(b"{\"total\": 3, \"result\": []}"));
        let refus = obtenir(&source, &adresse, &Mode::Telecharger).unwrap_err();
        fil.join().unwrap();
        assert!(refus.contains("portail") || refus.contains("portal"), "{refus}");
        let (adresse, fil) =
            serveur(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec());
        let refus = obtenir(&source, &adresse, &Mode::Telecharger).unwrap_err();
        fil.join().unwrap();
        assert!(refus.contains("503"), "{refus}");
    }

    /// Dans les tests, rien ne part : chaque source du système dit pourquoi elle n'a pas de copie.
    #[test]
    fn rien_ne_part_dans_les_tests() {
        // Sous Linux, aucun système suivi : le gestionnaire de paquets tient les versions.
        assert_eq!(Systeme::courant().is_none(), cfg!(target_os = "linux"));
        for systeme in [Systeme::Windows, Systeme::MacOs] {
            let releve = rafraichir(systeme);
            assert_eq!(releve.sources.len(), du_systeme(systeme).filter(|s| sert(s)).count());
            for (s, r) in &releve.sources {
                if let Err(raison) = r {
                    assert!(raison.contains("test"), "{} : {raison}", s.id);
                }
            }
            assert!(releve.copie("absente").is_err());
        }
    }
}
