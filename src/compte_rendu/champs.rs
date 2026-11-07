//! Les champs d'un compte rendu pour Claude, un par un : chaque texte a son motif ou sa liste fermée, vérifié à la
//! construction comme à la lecture. Aucun `String` libre : ce qui ne passe pas n'existe pas.
//!
//! Pourquoi si strict : le journal des erreurs s'écrit sur n'importe quel ordinateur (VANGUARDLOG, dossier du compte)
//! et peut être forgé pour glisser des consignes à l'IA de la veille. Ces types sont la première barrière (en Rust,
//! fuzzée) ; `sur()` de `outils/veille/rapport.py` refiltre derrière, hors de portée de l'IA.
//!
//! Module pur, sans `crate::` ni `unsafe` : le banc de fuzz l'inclut par son chemin (cible `journal_entrees`).

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Un champ refusé par son motif : le message ne nomme que le champ, jamais la valeur, qui peut venir d'un fichier
/// forgé.
#[derive(Debug)]
pub(crate) struct HorsMotif(&'static str);

impl std::fmt::Display for HorsMotif {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} hors motif", self.0)
    }
}

impl std::error::Error for HorsMotif {}

/// Un champ texte validé par son motif : `new` le refuse s'il n'a pas exactement la forme permise, et la lecture
/// (serde) passe par la même porte.
macro_rules! champ {
    ($(#[$m:meta])* $nom:ident, $valide:path) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub(crate) struct $nom(String);

        // Chaque champ ne sert pas ses deux méthodes partout : certains ne sont que lus (serde), d'autres que
        // construits ; la macro les donne toutes pour que le banc de fuzzing et les essais s'en servent.
        #[allow(dead_code)]
        impl $nom {
            /// La valeur, si elle a exactement la forme permise.
            pub(crate) fn new(s: &str) -> Option<$nom> {
                $valide(s).then(|| $nom(s.to_string()))
            }

            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $nom {
            type Error = HorsMotif;

            fn try_from(s: String) -> Result<$nom, HorsMotif> {
                if $valide(&s) { Ok($nom(s)) } else { Err(HorsMotif(stringify!($nom))) }
            }
        }

        impl From<$nom> for String {
            fn from(c: $nom) -> String {
                c.0
            }
        }

        impl std::fmt::Display for $nom {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

/// `n` chiffres ASCII, de `min` à `max`.
fn chiffres(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

/// Un identifiant de règle ou d'outil : `[A-Z]{3}-[A-Z]{3}-\d{3}` (« LNX-MAJ-001 »).
pub(crate) fn est_regle(s: &str) -> bool {
    let [l1, l2, l3, b'-', l4, l5, l6, b'-', c1, c2, c3] = s.as_bytes() else {
        return false;
    };
    [l1, l2, l3, l4, l5, l6].iter().all(|x| x.is_ascii_uppercase()) && [c1, c2, c3].iter().all(|x| x.is_ascii_digit())
}

/// Un emplacement dans le code de Vanguard : `src/…\.rs:L:C` (`[a-z0-9_]` par segment, 120 caractères au plus pour
/// le chemin ; ligne de 1 à 6 chiffres, colonne de 1 à 5).
pub(crate) fn est_lieu(s: &str) -> bool {
    let mut parties = s.rsplitn(3, ':');
    let (Some(colonne), Some(ligne), Some(chemin)) = (parties.next(), parties.next(), parties.next()) else {
        return false;
    };
    let Some(milieu) = chemin.strip_prefix("src/").and_then(|c| c.strip_suffix(".rs")) else {
        return false;
    };
    chiffres(ligne, 1, 6)
        && chiffres(colonne, 1, 5)
        && chemin.len() <= 120
        && milieu.split('/').all(|seg| {
            !seg.is_empty()
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

/// Une version de Vanguard : `\d{1,3}\.\d{1,3}\.\d{1,3}`, sans suffixe (un suffixe libre serait du texte).
pub(crate) fn est_version(s: &str) -> bool {
    let p: Vec<&str> = s.split('.').collect();
    p.len() == 3 && p.iter().all(|x| chiffres(x, 1, 3))
}

/// Un jour `AAAA-MM-JJ` qui existe au calendrier.
pub(crate) fn est_jour(s: &str) -> bool {
    // La forme d'abord, octet par octet : chrono lit `%Y` avec un signe (« +202-11-01 » passerait), et le motif du
    // schéma d'envoi, que le relais reproduit, n'a que des chiffres.
    let forme = s.len() == 10
        && s.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        });
    forme && chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
}

/// Une clé de cause : 16 chiffres hexadécimaux minuscules.
pub(crate) fn est_cle(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Un commit git complet : 40 chiffres hexadécimaux minuscules.
pub(crate) fn est_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Les codes nommés qu'une cause peut porter, et seulement eux : ceux de `modele::Raison` (« muette »), des
/// invariants de l'autotest (« message-vide ») et des écarts des lectures croisées (« absent-natif »). Un essai
/// vérifie que chaque code du programme y est.
pub(crate) const CODES: &[&str] = &[
    // modele::Raison
    "droits",
    "absente",
    "illisible",
    "muette",
    "panique",
    "delai",
    "version-ancienne",
    "non-precisee",
    "introuvable",
    "falsifie",
    "refuse",
    "echoue",
    // invariants de l'autotest
    "sans-regle",
    "etat-incoherent",
    "message-vide",
    // écarts des lectures croisées (autotest::croisees::Ecart)
    "absent-natif",
    "en-trop-natif",
    "valeur-differente",
    "champ-illisible",
    "sortie-inattendue",
];

/// Un code : un entier (code de sortie, 1 à 10 chiffres, signe moins permis) ou un code nommé de `CODES`.
pub(crate) fn est_code(s: &str) -> bool {
    CODES.contains(&s) || chiffres(s.strip_prefix('-').unwrap_or(s), 1, 10)
}

champ!(
    /// Un identifiant de règle ou d'outil (`est_regle`).
    Regle,
    est_regle
);
champ!(
    /// Un emplacement dans le code (`est_lieu`).
    Lieu,
    est_lieu
);
champ!(
    /// Une version de Vanguard (`est_version`).
    Version,
    est_version
);
champ!(
    /// Un jour (`est_jour`).
    Jour,
    est_jour
);
champ!(
    /// La clé d'une cause (`est_cle`).
    Cle,
    est_cle
);
champ!(
    /// Un commit git (`est_sha`).
    Sha,
    est_sha
);
champ!(
    /// Un code (`est_code`).
    Code,
    est_code
);

impl Version {
    /// La version de ce programme (Cargo.toml) ; « 0.0.0 » si elle sortait du motif, ce qu'un essai refuse.
    pub(crate) fn du_programme() -> Version {
        Version::new(env!("CARGO_PKG_VERSION")).unwrap_or_else(|| Version("0.0.0".to_string()))
    }
}

impl Jour {
    /// Aujourd'hui (UTC), toujours dans le motif.
    pub(crate) fn aujourdhui() -> Jour {
        Jour(chrono::Utc::now().format("%Y-%m-%d").to_string())
    }
}

impl Cle {
    /// La clé tirée des 8 premiers octets d'un hachage, en hexadécimal minuscule.
    pub(crate) fn de_hachage(h: &[u8; 32]) -> Cle {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(16);
        for o in h.iter().take(8) {
            let _ = write!(hex, "{o:02x}");
        }
        Cle(hex)
    }
}

impl Lieu {
    /// Le fichier et la ligne, sans la colonne : la clé d'une cause ne change pas pour une colonne qui bouge.
    pub(crate) fn sans_colonne(&self) -> &str {
        self.0.rsplit_once(':').map_or(&self.0, |(a, _)| a)
    }
}

/// Une liste fermée : chaque valeur a un identifiant ASCII stable, seul écrit et seul relu.
macro_rules! liste {
    ($(#[$m:meta])* $nom:ident { $($(#[$mv:meta])* $v:ident = $id:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub(crate) enum $nom {
            $($(#[$mv])* #[serde(rename = $id)] $v),+
        }

        // Générées pour chaque liste : chacune n'emploie pas tout.
        #[allow(dead_code)]
        impl $nom {
            /// Toutes les valeurs, dans l'ordre de leur déclaration.
            pub(crate) const TOUS: &[$nom] = &[$($nom::$v),+];

            /// L'identifiant écrit.
            pub(crate) fn id(self) -> &'static str {
                match self {
                    $($nom::$v => $id),+
                }
            }

            /// La valeur d'un identifiant de la liste, sinon rien.
            pub(crate) fn de_id(s: &str) -> Option<$nom> {
                match s {
                    $($id => Some($nom::$v),)+
                    _ => None,
                }
            }
        }
    };
}

liste!(
    /// Le genre d'une cause.
    Genre {
        /// Une panique qui a arrêté Vanguard.
        Plantage = "plantage",
        /// Une panique rattrapée (une règle plantée sous sa garde, une erreur interne).
        Rattrapee = "rattrapee",
        /// Une vérification impossible (`machine`).
        Impossible = "impossible",
        /// Un échec typé noté par `modele::Echec`.
        Echec = "echec",
        /// Une autre erreur notée au journal (PowerShell, WMI, scan du réseau…).
        Erreur = "erreur",
        /// Une lecture native contredite par l'outil du système (autotest).
        Contredite = "contredite",
        /// Un constat qui ne tient pas un invariant du modèle commun (autotest).
        Invariant = "invariant",
        /// Un fichier de Vanguard changé pendant l'autotest, qui ne doit rien écrire.
        Ecriture = "ecriture",
        /// Une règle qui a dépassé son délai pendant l'autotest.
        HorsDelai = "hors-delai",
        /// Une règle qui n'a rien rendu pendant l'autotest.
        Muette = "muette",
        /// Une règle plus lente que les semaines d'avant (mesures de l'autotest).
        Lente = "lente",
        /// Une règle qui frôle son délai (mesures de l'autotest).
        FroleDelai = "frole-delai",
        /// Un bilan ou une règle plus lent que les nuits d'avant (veille).
        Lenteur = "lenteur",
    }
);

liste!(
    /// La famille du système : rien de plus fin (ni version, ni nom d'ordinateur).
    Famille {
        Windows = "windows",
        Macos = "macos",
        Linux = "linux",
    }
);

liste!(
    /// D'où vient une entrée : posé par `outils/deployer.sh` au rapatriement, jamais lu dans l'entrée.
    Provenance {
        /// Le journal de l'ordinateur de l'auteur.
        CetOrdinateur = "cet-ordinateur",
        /// Le journal rapporté par la clé, écrit sur un autre ordinateur.
        Cle = "cle",
    }
);

liste!(
    /// Ce qui a produit le compte rendu (« campagne » est réservé aux campagnes d'attaque, pas encore là).
    Source {
        Autotest = "autotest",
        Journal = "journal",
        Lenteur = "lenteur",
    }
);

liste!(
    /// La commande qui rejoue une cause, fixe : jamais un texte venu de l'entrée.
    Reproduction {
        Autotest = "vanguard autotest",
        AutotestInternet = "vanguard autotest --internet",
    }
);

/// Les contextes des échecs typés (`modele::Echec`) que le journal peut porter : chaque contexte écrit dans `src/`
/// y est (essai-garde `contextes_d_echec_connus`). Un contexte hors liste s'écrit « echec/autre ».
pub(crate) const CONTEXTES_ECHEC: &[&str] = &[
    "annulation/remettre",
    "audit/pq-box",
    "audit/tls-pq",
    "autotest/cache",
    "autotest/dernier",
    "bilan/pqc-ssh",
    "bilan/pqc-sshd",
    "bilan/sshd-config",
    "blocage/pare-feu",
    "blocage/preparer",
    "blocage/regler",
    "canaux/lire",
    "certificats/retirer",
    "compte-rendu/lire",
    "compte-rendu/trier",
    "changements/noter",
    "dbus/actions",
    "dbus/etat_d_activite",
    "dbus/systeme",
    "dns/resolved",
    "docker",
    "droits/poser",
    "eleve/hosts",
    "eleve/montrer",
    "entretien/etat",
    "essai",
    "essai/lecture",
    "evenements/noter",
    "evenements/perdus",
    "evenements/version",
    "examens/ecrire",
    "http_unix",
    "http_unix/connexion",
    "machine/ports-bloques",
    "maj/fwupd",
    "manifeste/image",
    "manifeste/relire",
    "mise_a_jour/historique",
    "mise_a_jour/remise",
    "networkmanager",
    "partages/retirer",
    "plateforme/fwupd",
    "plugins/ecrire",
    "plugins/reglages",
    "plugins/sceau",
    "programmes_poses/noter",
    "quarantaine/creer",
    "quarantaine/deposer",
    "quarantaine/dossier",
    "quarantaine/droits",
    "quarantaine/lire",
    "quarantaine/remettre",
    "quarantaine/retirer",
    "quarantaine/supprimer",
    "quarantaine/traces",
    "reseau/appareils",
    "reseau/carnet",
    "reseau/dns-poser",
    "reseau/dns-registre",
    "reseau/hosts",
    "reseau/hosts-lire",
    "reseau/hosts-remplacer",
    "reseau/resolved",
    "sceau/adopter",
    "sceau/ecrire",
    "sceau/temoin",
    "signaler/controle",
    "signaler/dossier",
    "signaler/droits",
    "signaler/ecrire",
    "signaler/effacer",
    "signaler/incident",
    "signaler/langue",
    "signaler/outil",
    "signaler/programme",
    "sites_bloques/preparer",
    "ssh/ecriture",
    "ssh/noter",
    "systemd",
    "veilleur/oublier",
    "voulues/noter",
    "wifi/networkmanager",
];

/// Où une erreur a été notée : une liste fermée, écrite par le code (jamais un texte de l'erreur). L'identifiant
/// ASCII va dans la ligne de champs du journal ; le libellé français de la ligne `[contexte]` reste celui d'avant,
/// pour les tickets déjà ouverts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Contexte {
    MesOrdinateurs,
    ErreurInterne,
    Plantage,
    Autotest,
    VerificationImpossible,
    ScanReseau,
    AuditReseau,
    ProtectionRelro,
    ScanReseauNonVerifie,
    VanguardAdministrateur,
    CorrectionElevee,
    PowerShell,
    Wmi,
    OrigineProgramme,
    ProtectionCle,
    WindowsUpdate,
    TachesPlanifiees,
    BitLocker,
    PareFeuWindows,
    Reseaux,
    /// Un échec typé, par son contexte de `CONTEXTES_ECHEC` (toujours pris dans la liste).
    Echec(&'static str),
    /// Un échec typé dont le contexte n'est pas dans la liste.
    EchecAutre,
}

/// Les contextes sans paramètre, avec leur identifiant et leur libellé d'avant.
const CONTEXTES: &[(Contexte, &str, &str)] = &[
    (Contexte::MesOrdinateurs, "mes-ordinateurs", "mes ordinateurs"),
    (Contexte::ErreurInterne, "erreur-interne", "erreur interne rattrapée"),
    (Contexte::Plantage, "plantage", "plantage"),
    (Contexte::Autotest, "autotest", "autotest"),
    (
        Contexte::VerificationImpossible,
        "verification-impossible",
        "vérification impossible",
    ),
    (Contexte::ScanReseau, "scan-reseau", "scan réseau"),
    (Contexte::AuditReseau, "audit-reseau", "audit du réseau"),
    (Contexte::ProtectionRelro, "protection-relro", "protection RELRO"),
    (
        Contexte::ScanReseauNonVerifie,
        "scan-reseau-non-verifie",
        "scan du réseau non vérifié",
    ),
    (
        Contexte::VanguardAdministrateur,
        "vanguard-administrateur",
        "Vanguard administrateur",
    ),
    (Contexte::CorrectionElevee, "correction-elevee", "Correction élevée"),
    (Contexte::PowerShell, "powershell", "PowerShell"),
    (Contexte::Wmi, "wmi", "WMI"),
    (Contexte::OrigineProgramme, "origine-programme", "origine du programme"),
    (Contexte::ProtectionCle, "protection-cle", "protection de la clé"),
    (Contexte::WindowsUpdate, "windows-update", "Windows Update"),
    (Contexte::TachesPlanifiees, "taches-planifiees", "Tâches planifiées"),
    (Contexte::BitLocker, "bitlocker", "BitLocker"),
    (Contexte::PareFeuWindows, "pare-feu-windows", "Pare-feu Windows"),
    (Contexte::Reseaux, "reseaux", "Réseaux"),
    (Contexte::EchecAutre, "echec/autre", "echec/autre"),
];

impl Contexte {
    /// Le contexte d'un échec typé : le sien s'il est dans la liste, sinon « autre ».
    pub(crate) fn echec(contexte: &str) -> Contexte {
        CONTEXTES_ECHEC
            .iter()
            .copied()
            .find(|c| *c == contexte)
            .map_or(Contexte::EchecAutre, Contexte::Echec)
    }

    /// L'identifiant écrit dans la ligne de champs et dans le compte rendu.
    pub(crate) fn id(self) -> &'static str {
        match self {
            Contexte::Echec(c) => c,
            _ => CONTEXTES
                .iter()
                .find(|(x, ..)| *x == self)
                .map_or("echec/autre", |(_, id, _)| id),
        }
    }

    /// Le libellé français de la ligne `[contexte]`, inchangé depuis les versions d'avant.
    pub(crate) fn libelle(self) -> &'static str {
        match self {
            Contexte::Echec(c) => c,
            _ => CONTEXTES
                .iter()
                .find(|(x, ..)| *x == self)
                .map_or("echec/autre", |(.., l)| l),
        }
    }

    /// Le contexte d'un identifiant de la liste fermée, sinon rien.
    pub(crate) fn de_id(s: &str) -> Option<Contexte> {
        CONTEXTES
            .iter()
            .find(|(_, id, _)| *id == s)
            .map(|(c, ..)| *c)
            .or_else(|| CONTEXTES_ECHEC.iter().copied().find(|c| *c == s).map(Contexte::Echec))
    }

    /// Le contexte d'un libellé français d'avant (entrée écrite avant la ligne de champs), sinon rien : un contexte
    /// d'autotest (« autotest LNX-MAJ-001 ») se reconnaît à son début.
    #[cfg_attr(not(test), allow(dead_code))] // lu par le lecteur du journal (L2)
    pub(crate) fn de_libelle(s: &str) -> Option<Contexte> {
        if s.strip_prefix("autotest ").is_some_and(est_regle) {
            return Some(Contexte::Autotest);
        }
        CONTEXTES
            .iter()
            .find(|(_, _, l)| *l == s)
            .map(|(c, ..)| *c)
            .or_else(|| CONTEXTES_ECHEC.iter().copied().find(|c| *c == s).map(Contexte::Echec))
    }

    /// Tous les identifiants, pour le schéma et les essais.
    #[cfg(test)]
    pub(crate) fn tous_les_id() -> impl Iterator<Item = &'static str> {
        CONTEXTES
            .iter()
            .map(|(_, id, _)| *id)
            .chain(CONTEXTES_ECHEC.iter().copied())
    }
}

impl Serialize for Contexte {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.id())
    }
}

impl<'de> Deserialize<'de> for Contexte {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Contexte, D::Error> {
        let s = String::deserialize(d)?;
        Contexte::de_id(&s).ok_or_else(|| serde::de::Error::custom("contexte hors liste"))
    }
}
